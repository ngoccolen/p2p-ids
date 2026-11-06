import asyncio
import time
import logging
from collections import defaultdict
from .protocol import make_msg

log = logging.getLogger("p2p.gossip")
RELIABLE_TYPES = ("ALERT", "BLOCK", "UNBLOCK")


class Gossip:
    def __init__(self, cfg: dict, node, clock):
        self.node = node
        self.clock = clock
        p = cfg.get("p2p", {})
        self.ttl = p.get("alert_ttl", 3)
        self.ack_timeout = p.get("ack_timeout", 3)
        self.max_retry = p.get("max_retry", 3)

        self.seen: dict[str, float] = {}
        self.pending: dict[tuple, list] = {}
        self.outbox: dict[str, list] = defaultdict(list)
        self.deliver = {}

        for t in RELIABLE_TYPES:
            self.node.on(t, self._on_reliable_msg)
        self.node.on("ACK", self._on_ack)
        self.node.on_peer_online.append(self._flush_outbox)

    def on_deliver(self, type_: str, cb):
        self.deliver[type_] = cb

    async def publish(self, type_: str, payload: dict):
        """Phát tán tin cậy tới mọi peer đang online, và xếp hàng outbox cho peer đang tạm offline."""
        msg = make_msg(type_, self.node.id, self.clock.tick(), payload, origin=self.node.id, ttl=self.ttl)
        self.seen[msg["msg_id"]] = time.time()

        known_ids = set(self.node.conns.keys()) | set(self.node.peers.peers.keys())
        known_ids.discard(self.node.id)

        for pid in known_ids:
            if pid in self.node.conns:
                await self._send(pid, msg, 1)
            else:
                if len(self.outbox[pid]) < 500:
                    self.outbox[pid].append(msg)

    async def _send(self, pid: str, msg: dict, tries: int):
        await self.node.send_to(pid, msg)
        self.pending[(msg["msg_id"], pid)] = [msg, tries, time.time()]

    async def _on_reliable_msg(self, conn, msg: dict):
        # 1. Phản hồi ACK ngay lập tức cho bên gửi
        await conn.send(make_msg("ACK", self.node.id, self.clock.tick(), {"ack": msg["msg_id"]}))

        # 2. Chống lặp: nếu đã nhận msg_id này rồi thì bỏ qua
        if msg["msg_id"] in self.seen:
            return
        self.seen[msg["msg_id"]] = time.time()

        # 3. Đưa tin nhắn lên tầng ứng dụng xử lý
        cb = self.deliver.get(msg["type"])
        if cb:
            await cb(msg["payload"], msg["sender"])

        # 4. Chuyển tiếp (Flooding) nếu TTL > 1
        current_ttl = msg.get("ttl", 1)
        if current_ttl > 1:
            forward_msg = {
                **msg,
                "ttl": current_ttl - 1,
                "sender": self.node.id,
                "lamport": self.clock.tick()
            }
            for pid in list(self.node.conns.keys()):
                if pid != conn.peer_id:
                    await self._send(pid, forward_msg, 1)

    async def _on_ack(self, conn, msg: dict):
        acked_id = msg["payload"].get("ack")
        self.pending.pop((acked_id, conn.peer_id), None)

    async def _flush_outbox(self, pid: str):
        pending_list = self.outbox.pop(pid, [])
        if pending_list:
            log.info(f"Đẩy bù {len(pending_list)} bản tin trong Outbox tới {pid} vừa ONLINE")
        for m in pending_list:
            await self._send(pid, m, 1)

    async def run(self):
        while True:
            await asyncio.sleep(1)
            now = time.time()

            for key, (msg, tries, last_sent) in list(self.pending.items()):
                if now - last_sent < self.ack_timeout:
                    continue
                mid, pid = key
                if tries >= self.max_retry or pid not in self.node.conns:
                    del self.pending[key]
                    if len(self.outbox[pid]) < 500:
                        self.outbox[pid].append(msg)
                else:
                    log.info(f"Gửi lại (Retry {tries + 1}) tin {mid[:8]} tới {pid}")
                    await self._send(pid, msg, tries + 1)

            for mid, ts in list(self.seen.items()):
                if now - ts > 600:
                    del self.seen[mid]
