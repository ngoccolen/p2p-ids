import os
import time
import asyncio
import logging
from typing import Optional, Set
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from common.models import Alert

log = logging.getLogger("api.server")


class StatusPatch(BaseModel):
    status: str  # NEW | ACKNOWLEDGED | RESOLVED | FALSE_POSITIVE


class BlockRequest(BaseModel):
    ip: str
    reason: str = "Chặn thủ công từ SOC Dashboard"


class SimulateAlertRequest(BaseModel):
    type: str = "PORT_SCAN"
    severity: str = "HIGH"
    src_ip: str = "203.0.113.50"
    description: str = "Giả lập tấn công quét 45 cổng TCP để kiểm thử P2P Gossip"


class WSManager:
    def __init__(self):
        self.clients: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket):
        self.clients.discard(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)


def create_app(cfg: dict, db, bus, clock, node, gossip, blocker) -> tuple[FastAPI, WSManager, dict]:
    app = FastAPI(title=f"P2P-IDS API ({cfg['peer_id']})", version="1.0.0")
    ws_mgr = WSManager()
    live_metrics = {"pps": 0, "bps": 0, "ts": time.time()}

    @app.get("/api/stats")
    def get_stats():
        peers = db.list_peers()
        online_peers = sum(1 for p in peers if p.get("status") == "ONLINE")

        sev_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        total_alerts = 0
        total_flows = 0
        anomaly_flows = 0

        with db._get_conn() as conn:
            for row in conn.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"):
                sev = row["severity"]
                cnt = row["cnt"]
                total_alerts += cnt
                if sev in sev_counts:
                    sev_counts[sev] = cnt
            total_flows = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
            anomaly_flows = conn.execute("SELECT COUNT(*) FROM flows WHERE is_anomaly = 1").fetchone()[0]

        return {
            "peer_id": cfg["peer_id"],
            "host": cfg["host"],
            "lamport": clock.value,
            "online_peers": online_peers,
            "total_peers": len(peers),
            "total_alerts": total_alerts,
            "severity_counts": sev_counts,
            "total_flows": total_flows,
            "anomaly_flows": anomaly_flows,
            "blocked_count": len(blocker.blocked),
            "pps": live_metrics["pps"],
            "bps": live_metrics["bps"]
        }

    @app.get("/api/peers")
    def get_peers():
        return {"self": node.info(), "peers": db.list_peers()}

    @app.get("/api/alerts")
    def get_alerts(
        type: Optional[str] = None,
        severity: Optional[str] = None,
        src_ip: Optional[str] = None,
        status: Optional[str] = None,
        order: str = "lamport",
        page: int = 1,
        size: int = 25
    ):
        return db.query_alerts(type=type, severity=severity, src_ip=src_ip, status=status, order=order, page=page, size=size)

    @app.patch("/api/alerts/{alert_id}")
    def update_alert_status(alert_id: str, body: StatusPatch):
        allowed = {"NEW", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"}
        if body.status not in allowed:
            raise HTTPException(status_code=400, detail=f"Trạng thái phải thuộc {allowed}")
        with db._get_conn() as conn:
            cur = conn.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (body.status, alert_id))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Không tìm thấy alert_id")
        return {"ok": True, "alert_id": alert_id, "status": body.status}

    @app.get("/api/flows")
    def get_flows(
        src_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        anomaly: Optional[int] = None,
        page: int = 1,
        size: int = 30
    ):
        return db.query_flows(src_ip=src_ip, protocol=protocol, anomaly=anomaly, page=page, size=size)

    @app.get("/api/blocked")
    def get_blocked():
        return {"items": blocker.list_blocked(), "whitelist": sorted(blocker.whitelist)}

    @app.post("/api/block")
    async def manual_block(req: BlockRequest):
        changed = blocker.block_ip(req.ip, reason=req.reason, source_peer=cfg["peer_id"])
        await gossip.publish("BLOCK", {"ip": req.ip, "reason": req.reason, "origin_peer": cfg["peer_id"]})
        return {"ok": True, "blocked_locally": changed, "ip": req.ip}

    @app.post("/api/unblock")
    async def manual_unblock(req: BlockRequest):
        changed = blocker.unblock_ip(req.ip)
        await gossip.publish("UNBLOCK", {"ip": req.ip, "origin_peer": cfg["peer_id"]})
        return {"ok": True, "unblocked_locally": changed, "ip": req.ip}

    @app.post("/api/simulate-alert")
    async def simulate_alert(req: SimulateAlertRequest):
        """Tạo 1 Alert kiểm thử đẩy thẳng vào Bus để test Gossip, Correlator, Iptables và UI."""
        alert = Alert(
            type=req.type,
            source="RULE",
            severity=req.severity,
            src_ip=req.src_ip,
            dst_ip=cfg["host"],
            description=req.description,
            origin_peer=cfg["peer_id"],
            lamport=clock.tick(),
            score=0.88 if req.severity in ("HIGH", "CRITICAL") else 0.55,
            evidence={"simulated": True, "triggered_by": cfg["peer_id"]}
        )
        await bus.alerts.put(alert)
        return {"ok": True, "alert": alert.to_dict()}

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        await ws_mgr.connect(ws)
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            ws_mgr.disconnect(ws)
        except Exception:
            ws_mgr.disconnect(ws)

    # Phục vụ giao diện Web tĩnh tại thư mục web/
    os.makedirs("web", exist_ok=True)

    @app.get("/")
    def index_page():
        index_file = os.path.join("web", "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "P2P-IDS API đang chạy. Hãy tạo file web/index.html để xem Dashboard."}

    app.mount("/static", StaticFiles(directory="web"), name="static")
    return app, ws_mgr, live_metrics


async def ui_broadcaster_loop(bus, ws_mgr: WSManager, live_metrics: dict):
    """Tiêu thụ sự kiện từ bus.ui liên tục và đẩy xuống mọi trình duyệt qua WebSocket."""
    while True:
        item = await bus.ui.get()
        if item.get("event") == "traffic":
            d = item.get("data", {})
            live_metrics["pps"] = d.get("pps", 0)
            live_metrics["bps"] = d.get("bps", 0)
            live_metrics["ts"] = d.get("ts", time.time())
        await ws_mgr.broadcast(item)
