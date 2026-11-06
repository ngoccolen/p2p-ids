import argparse
import asyncio
import logging
import os
import uvicorn
import yaml

from common.bus import Bus
from common.lamport import LamportClock
from common.models import Alert
from storage.db import Database
from p2p.peer_manager import PeerManager
from p2p.node import P2PNode
from p2p.gossip import Gossip
from collector.flow_table import FlowTable
from collector.sniffer import Collector
from aggregator.correlator import AlertCorrelator
from response.blocker import IPBlocker
from api.server import create_app, ui_broadcaster_loop

# Tự động nạp DetectionEngine của Linh nếu đã có trên repo
try:
    from detection.engine import DetectionEngine
except ImportError:
    DetectionEngine = None

log = logging.getLogger("main")


async def collector_loop(ft: FlowTable, bus: Bus, blocker: IPBlocker):
    """Mỗi giây đóng các Flow hết hạn, đẩy thống kê lưu lượng và dọn các IP hết hạn chặn."""
    while True:
        await asyncio.sleep(1)
        flows, stats = ft.tick()
        for f in flows:
            if not bus.flows.full():
                bus.flows.put_nowait(f)
        if not bus.stats.full():
            bus.stats.put_nowait(stats)
        bus.ui_nowait("traffic", {
            "ts": stats.ts,
            "pps": stats.total_packets,
            "bps": stats.total_bytes
        })
        blocker.cleanup_expired()


async def fallback_flow_saver(bus: Bus, db: Database):
    """Chế độ dự phòng khi chưa có DetectionEngine: vẫn lưu Flow vào SQLite và xả hàng đợi stats."""
    log.warning("Chưa tìm thấy detection/engine.py -> Chạy chế độ dự phòng (vẫn lưu Flow vào SQLite bình thường).")
    while True:
        await asyncio.sleep(0.5)
        while not bus.stats.empty():
            bus.stats.get_nowait()
        while not bus.flows.empty():
            flow = bus.flows.get_nowait()
            db.insert_flow(flow)


async def alert_router(bus: Bus, gossip: Gossip, db: Database, correlator: AlertCorrelator, blocker: IPBlocker):
    """Xử lý cảnh báo cục bộ: lưu DB, đẩy UI, phát tán Gossip, chạy Correlator và kích hoạt IPS chặn IP."""
    while True:
        alert: Alert = await bus.alerts.get()
        log.warning(f"LOCAL ALERT: [{alert.severity}] {alert.type} từ {alert.src_ip} - {alert.description}")
        db.insert_alert(alert, is_local=1)
        bus.ui_nowait("alert", alert.to_dict())
        await gossip.publish("ALERT", alert.to_dict())

        # Tự động chặn IP và phát tán lệnh BLOCK sang toàn mạng nếu mức độ cao
        if blocker.should_auto_block(alert.severity):
            if blocker.block_ip(alert.src_ip, reason=f"{alert.type} ({alert.severity})", source_peer=alert.origin_peer):
                await gossip.publish("BLOCK", {
                    "ip": alert.src_ip,
                    "reason": f"Auto-IPS: {alert.type}",
                    "origin_peer": alert.origin_peer
                })

        # Kiểm tra tương quan đa Peer
        corr_alert = correlator.observe(alert)
        if corr_alert:
            db.insert_alert(corr_alert, is_local=1)
            bus.ui_nowait("alert", corr_alert.to_dict())
            await gossip.publish("ALERT", corr_alert.to_dict())


async def main(cfg: dict):
    os.makedirs(os.path.dirname(cfg["db_path"]), exist_ok=True)
    os.makedirs(os.path.dirname(cfg["model_path"]), exist_ok=True)

    db = Database(cfg["db_path"])
    db.init()

    bus = Bus()
    clock = LamportClock()
    peers = PeerManager(db, bus)
    node = P2PNode(cfg, peers, clock)
    gossip = Gossip(cfg, node, clock)
    correlator = AlertCorrelator(cfg, cfg["peer_id"], peers, clock)
    blocker = IPBlocker(cfg, bus)

    # 1. Callback khi nhận ALERT từ peer khác qua P2P Gossip
    async def on_remote_alert(payload: dict, sender: str):
        remote_alert = Alert(**payload)
        log.warning(f"REMOTE ALERT từ {sender}: [{remote_alert.severity}] {remote_alert.type} từ {remote_alert.src_ip}")
        db.insert_alert(remote_alert, is_local=0, received_from=sender)
        bus.ui_nowait("alert", remote_alert.to_dict())

        if blocker.should_auto_block(remote_alert.severity):
            blocker.block_ip(
                remote_alert.src_ip,
                reason=f"P2P Alert ({remote_alert.origin_peer}): {remote_alert.type}",
                source_peer=remote_alert.origin_peer
            )

        corr_alert = correlator.observe(remote_alert)
        if corr_alert:
            db.insert_alert(corr_alert, is_local=1)
            bus.ui_nowait("alert", corr_alert.to_dict())
            await gossip.publish("ALERT", corr_alert.to_dict())

    # 2. Callback khi nhận lệnh BLOCK / UNBLOCK từ peer khác
    async def on_remote_block(payload: dict, sender: str):
        ip = payload.get("ip")
        reason = payload.get("reason", f"Đồng bộ chặn từ {sender}")
        origin = payload.get("origin_peer", sender)
        blocker.block_ip(ip, reason=reason, source_peer=origin)

    async def on_remote_unblock(payload: dict, sender: str):
        ip = payload.get("ip")
        blocker.unblock_ip(ip)

    gossip.on_deliver("ALERT", on_remote_alert)
    gossip.on_deliver("BLOCK", on_remote_block)
    gossip.on_deliver("UNBLOCK", on_remote_unblock)

    # 3. Khởi động bộ bắt gói Scapy
    ft = FlowTable(cfg)
    collector = Collector(cfg, ft)
    try:
        collector.start()
    except Exception as e:
        log.error(f"Không thể bật Scapy Sniffer trên card '{cfg['iface']}' ({e}). Kiểm tra quyền sudo hoặc tên card mạng!")

    # 4. Khởi động DetectionEngine (nếu Linh đã push) hoặc chế độ lưu Flow dự phòng
    if DetectionEngine is not None:
        engine = DetectionEngine(cfg, db, bus, clock)
        detection_task = engine.run()
    else:
        detection_task = fallback_flow_saver(bus, db)

    # 5. Khởi động FastAPI + WebSocket trên cổng api_port (mặc định 8000)
    app, ws_mgr, live_metrics = create_app(cfg, db, bus, clock, node, gossip, blocker)
    api_port = cfg.get("api_port", 8000)
    uvi_cfg = uvicorn.Config(app, host="0.0.0.0", port=api_port, log_level="warning")
    uvi_server = uvicorn.Server(uvi_cfg)
    log.info(f"🌐 Web SOC Dashboard sẵn sàng tại: http://{cfg['host']}:{api_port}")

    await asyncio.gather(
        node.start(),
        gossip.run(),
        collector_loop(ft, bus, blocker),
        detection_task,
        alert_router(bus, gossip, db, correlator, blocker),
        ui_broadcaster_loop(bus, ws_mgr, live_metrics),
        uvi_server.serve()
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, help="Đường dẫn file config yaml")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    with open(args.config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    try:
        asyncio.run(main(config))
    except KeyboardInterrupt:
        log.info("Đã dừng hệ thống P2P-IDS an toàn.")
