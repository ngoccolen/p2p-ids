# p2p/peer_manager.py
import time
from typing import Dict, Any, List

class PeerManager:
    def __init__(self, db, bus):
        self.db = db
        self.bus = bus
        self.peers: Dict[str, Dict[str, Any]] = {}

    def set_online(self, info: dict):
        p = self.peers.setdefault(info["peer_id"], {"rtt_ms": None})
        p.update(info)
        p["status"] = "ONLINE"
        p["last_seen"] = time.time()
        self._sync(p)

    def set_offline(self, pid: str):
        if pid in self.peers:
            self.peers[pid]["status"] = "OFFLINE"
            self._sync(self.peers[pid])

    def touch(self, pid: str, rtt_ms: float = None):
        p = self.peers.get(pid)
        if not p: return
        p["last_seen"] = time.time()
        if rtt_ms is not None:
            p["rtt_ms"] = round(rtt_ms, 2)
            self._sync(p)

    def last_seen(self, pid: str) -> float:
        return self.peers.get(pid, {}).get("last_seen", 0)

    def addresses(self) -> List[str]:
        return [f"{p['host']}:{p['p2p_port']}" for p in self.peers.values()]

    def _sync(self, p: dict):
        self.db.upsert_peer(p)
        self.bus.ui_nowait("peer_status", dict(p))
