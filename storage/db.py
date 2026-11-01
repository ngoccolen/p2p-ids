import sqlite3
import json
import time
from typing import List, Dict, Any, Optional
from common.models import Flow, Alert

class Database:
    """Lớp quản trị cơ sở dữ liệu SQLite cục bộ cho mỗi Peer (do Linh phụ trách)."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def init(self):
        with open("storage/schema.sql", "r", encoding="utf-8") as f:
            sql = f.read()
        with self._get_conn() as conn:
            conn.executescript(sql)

    def upsert_peer(self, p: Dict[str, Any]):
        sql = """
        INSERT INTO peers (peer_id, host, p2p_port, api_port, status, last_seen, rtt_ms)
        VALUES (:peer_id, :host, :p2p_port, :api_port, :status, :last_seen, :rtt_ms)
        ON CONFLICT(peer_id) DO UPDATE SET
            status=excluded.status,
            last_seen=excluded.last_seen,
            rtt_ms=coalesce(excluded.rtt_ms, peers.rtt_ms);
        """
        with self._get_conn() as conn:
            conn.execute(sql, {
                "peer_id": p["peer_id"], "host": p["host"], "p2p_port": p["p2p_port"],
                "api_port": p.get("api_port", 8000), "status": p["status"],
                "last_seen": p.get("last_seen", time.time()), "rtt_ms": p.get("rtt_ms")
            })

    def list_peers(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.execute("SELECT * FROM peers ORDER BY peer_id ASC")
            return [dict(r) for r in cur.fetchall()]

    def insert_flow(self, f: Flow, anomaly_score: float = 0.0, is_anomaly: int = 0):
        sql = """
        INSERT INTO flows (flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                           start_ts, end_ts, packets, bytes, fwd_packets, bwd_packets,
                           syn, ack, fin, rst, psh, urg, anomaly_score, is_anomaly)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self._get_conn() as conn:
            conn.execute(sql, (
                f.flow_id, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol,
                f.start_ts, f.end_ts, f.packets, f.bytes, f.fwd_packets, f.bwd_packets,
                f.syn, f.ack, f.fin, f.rst, f.psh, f.urg, anomaly_score, is_anomaly
            ))

    def query_flows(self, src_ip: Optional[str] = None, protocol: Optional[str] = None,
                    anomaly: Optional[int] = None, page: int = 1, size: int = 50) -> Dict[str, Any]:
        conditions, params = [], []
        if src_ip:
            conditions.append("src_ip = ?"); params.append(src_ip)
        if protocol:
            conditions.append("protocol = ?"); params.append(protocol.upper())
        if anomaly is not None:
            conditions.append("is_anomaly = ?"); params.append(anomaly)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        offset = (page - 1) * size

        with self._get_conn() as conn:
            count = conn.execute(f"SELECT COUNT(*) FROM flows {where}", params).fetchone()[0]
            cur = conn.execute(f"SELECT * FROM flows {where} ORDER BY start_ts DESC LIMIT ? OFFSET ?",
                               params + [size, offset])
            items = [dict(r) for r in cur.fetchall()]
            return {"items": items, "total": count, "page": page, "size": size}

    def insert_alert(self, a: Alert, is_local: int = 1, received_from: Optional[str] = None):
        sql = """
        INSERT OR IGNORE INTO alerts (alert_id, origin_peer, lamport, timestamp, type,
                                      source, severity, src_ip, dst_ip, score, description,
                                      evidence, status, is_local, received_from)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self._get_conn() as conn:
            conn.execute(sql, (
                a.alert_id, a.origin_peer, a.lamport, a.timestamp, a.type,
                a.source, a.severity, a.src_ip, a.dst_ip, a.score, a.description,
                json.dumps(a.evidence), a.status, is_local, received_from
            ))

    def query_alerts(self, type: Optional[str] = None, severity: Optional[str] = None,
                     src_ip: Optional[str] = None, status: Optional[str] = None,
                     order: str = "time", page: int = 1, size: int = 20) -> Dict[str, Any]:
        conditions, params = [], []
        if type:
            conditions.append("type = ?"); params.append(type)
        if severity:
            conditions.append("severity = ?"); params.append(severity)
        if src_ip:
            conditions.append("src_ip = ?"); params.append(src_ip)
        if status:
            conditions.append("status = ?"); params.append(status)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        order_col = "lamport DESC" if order == "lamport" else "timestamp DESC"
        offset = (page - 1) * size

        with self._get_conn() as conn:
            count = conn.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]
            cur = conn.execute(f"SELECT * FROM alerts {where} ORDER BY {order_col} LIMIT ? OFFSET ?",
                               params + [size, offset])
            items = []
            for r in cur.fetchall():
                d = dict(r)
                if d.get("evidence"):
                    try:
                        d["evidence"] = json.loads(d["evidence"])
                    except Exception:
                        pass
                items.append(d)
            return {"items": items, "total": count, "page": page, "size": size}
