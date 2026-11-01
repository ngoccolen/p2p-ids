# p2p/node.py
import asyncio
import logging
import time
from .protocol import make_msg, encode, decode

log = logging.getLogger("p2p.node")

class Connection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, outbound: bool):
        self.reader = reader
        self.writer = writer
        self.outbound = outbound
        self.peer_id: str | None = None
        self.addr: str | None = None
        self._lock = asyncio.Lock()

    async def send(self, msg: dict):
        async with self._lock:
            self.writer.write(encode(msg))
            await self.writer.drain()

    def close(self):
        try:
            self.writer.close()
        except Exception:
            pass

class P2PNode:
    def __init__(self, cfg: dict, peers, clock):
        self.cfg = cfg
        self.peers = peers
        self.clock = clock
        self.id = cfg["peer_id"]
        self.my_addr = f"{cfg['host']}:{cfg['p2p_port']}"
        self.conns: dict[str, Connection] = {}
        self.known = set(cfg.get("bootstrap_peers", []))
        self.handlers = {
            "PING": self._on_ping,
            "PONG": self._on_pong,
            "PEER_LIST": self._on_peer_list
        }
        self.on_peer_online = []

    def on(self, type_: str, fn):
        self.handlers[type_] = fn

    def info(self) -> dict:
        return {
            "peer_id": self.id,
            "host": self.cfg["host"],
            "p2p_port": self.cfg["p2p_port"],
            "api_port": self.cfg.get("api_port", 8000)
        }

    async def start(self):
        srv = await asyncio.start_server(
            lambda r, w: self._handle_conn(Connection(r, w, outbound=False)),
            "0.0.0.0", self.cfg["p2p_port"]
        )
        log.info(f"P2P Node đang lắng nghe tại {self.my_addr}")
        await asyncio.gather(srv.serve_forever(), self._dial_loop(), self._ping_loop())

    async def send_to(self, pid: str, msg: dict) -> bool:
        conn = self.conns.get(pid)
        if not conn: return False
        try:
            await conn.send(msg)
            return True
        except Exception:
            conn.close()
            return False

    async def broadcast(self, msg: dict, exclude: str = None):
        for pid in list(self.conns.keys()):
            if pid != exclude:
                await self.send_to(pid, msg)

    async def _dial_loop(self):
        """Vòng lặp tự động kết nối và reconnect qua IP Tailscale."""
        backoff = {}
        while True:
            connected = {c.addr for c in self.conns.values()}
            for addr in list(self.known - connected - {self.my_addr}):
                next_try, delay = backoff.get(addr, (0, 1))
                if time.time() < next_try:
                    continue
                try:
                    h, p = addr.split(":")
                    r, w = await asyncio.wait_for(asyncio.open_connection(h, int(p)), timeout=4.0)
                    backoff.pop(addr, None)
                    asyncio.create_task(self._handle_conn(Connection(r, w, outbound=True)))
                except Exception:
                    backoff[addr] = (time.time() + delay, min(delay * 2, 30))
            await asyncio.sleep(1)

    async def _handle_conn(self, conn: Connection):
        try:
            if conn.outbound:
                await conn.send(make_msg("HELLO", self.id, self.clock.tick(), self.info()))
            first_line = await asyncio.wait_for(conn.reader.readline(), timeout=5.0)
            first = decode(first_line)
            if first["type"] not in ("HELLO", "HELLO_ACK"):
                return

            self.clock.update(first["lamport"])
            info = first["payload"]
            conn.peer_id = info["peer_id"]
            conn.addr = f"{info['host']}:{info['p2p_port']}"

            if not self._register(conn):
                return

            if not conn.outbound:
                await conn.send(make_msg("HELLO_ACK", self.id, self.clock.tick(),
                                         {**self.info(), "peers": self.peers.addresses()}))

            self.known.add(conn.addr)
            self.known.update(info.get("peers", []))
            self.peers.set_online(info)
            log.info(f"Peer {conn.peer_id} đã KẾT NỐI ONLINE ({'Out' if conn.outbound else 'In'})")

            for cb in self.on_peer_online:
                asyncio.create_task(cb(conn.peer_id))

            await self.broadcast(make_msg("PEER_LIST", self.id, self.clock.tick(),
                                          {"peers": self.peers.addresses() + [self.my_addr]}))

            while line := await conn.reader.readline():
                msg = decode(line)
                self.clock.update(msg.get("lamport", 0))
                self.peers.touch(conn.peer_id)
                handler = self.handlers.get(msg["type"])
                if handler:
                    await handler(conn, msg)

        except Exception as e:
            log.debug(f"Kết nối với {conn.peer_id} kết thúc: {e}")
        finally:
            conn.close()
            if conn.peer_id and self.conns.get(conn.peer_id) is conn:
                del self.conns[conn.peer_id]
                self.peers.set_offline(conn.peer_id)
                log.warning(f"Peer {conn.peer_id} đã OFFLINE")

    def _register(self, conn: Connection) -> bool:
        if conn.peer_id == self.id: return False
        old = self.conns.get(conn.peer_id)
        if old:
            initiator = self.id if conn.outbound else conn.peer_id
            if initiator != min(self.id, conn.peer_id):
                return False
            old.close()
        self.conns[conn.peer_id] = conn
        return True

    async def _ping_loop(self):
        p_cfg = self.cfg.get("p2p", {})
        interval = p_cfg.get("ping_interval", 5)
        timeout = p_cfg.get("offline_timeout", 15)

        while True:
            await asyncio.sleep(interval)
            now = time.time()
            for pid, conn in list(self.conns.items()):
                if now - self.peers.last_seen(pid) > timeout:
                    conn.close()
                    continue
                await self.send_to(pid, make_msg("PING", self.id, self.clock.tick(), {"ts": now}))

    async def _on_ping(self, conn: Connection, msg: dict):
        await conn.send(make_msg("PONG", self.id, self.clock.tick(), {"ts": msg["payload"]["ts"]}))

    async def _on_pong(self, conn: Connection, msg: dict):
        rtt = (time.time() - msg["payload"]["ts"]) * 1000
        self.peers.touch(conn.peer_id, rtt_ms=rtt)

    async def _on_peer_list(self, conn: Connection, msg: dict):
        new_peers = msg["payload"].get("peers", [])
        self.known.update(new_peers)
