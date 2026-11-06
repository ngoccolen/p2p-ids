import time
import logging
from collections import defaultdict, deque
from typing import Optional
from common.models import Alert, UPGRADE

log = logging.getLogger("aggregator.correlator")


class AlertCorrelator:
    """Gộp cảnh báo từ nhiều Peer để phát hiện tấn công phân tán (do Ngọc phụ trách)."""

    def __init__(self, cfg: dict, my_id: str, peers_mgr, clock, window_sec: float = 60.0, cooldown_sec: float = 60.0):
        self.my_id = my_id
        self.peers_mgr = peers_mgr
        self.clock = clock
        self.window = window_sec
        self.cooldown = cooldown_sec
        # src_ip -> deque[(ts, origin_peer, base_type, severity, score)]
        self.history = defaultdict(deque)
        self.last_corr_time: dict[tuple, float] = {}

    def _is_leader(self) -> bool:
        """Chỉ peer có ID nhỏ nhất trong các peer đang ONLINE mới sinh cảnh báo tổng hợp chống trùng."""
        online_ids = [
            pid for pid, p in self.peers_mgr.peers.items()
            if p.get("status") == "ONLINE"
        ]
        online_ids.append(self.my_id)
        return self.my_id == min(online_ids)

    def observe(self, alert: Alert) -> Optional[Alert]:
        """Ghi nhận 1 Alert (local hoặc remote). Trả về Alert DISTRIBUTED_* nếu phát hiện tấn công đa mục tiêu."""
        if alert.source == "AGGREGATED" or alert.type.startswith("DISTRIBUTED_"):
            return None

        now = time.time()
        q = self.history[alert.src_ip]
        q.append((now, alert.origin_peer, alert.type, alert.severity, alert.score))

        cutoff = now - self.window
        while q and q[0][0] < cutoff:
            q.popleft()

        distinct_peers = sorted({item[1] for item in q})
        if len(distinct_peers) < 2:
            return None

        if not self._is_leader():
            return None

        base_type = alert.type
        cd_key = (alert.src_ip, base_type)
        if now - self.last_corr_time.get(cd_key, 0) < self.cooldown:
            return None
        self.last_corr_time[cd_key] = now

        # Lấy mức độ nghiêm trọng cao nhất trong nhóm và nâng thêm 1 bậc
        sev_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        max_sev = max((item[3] for item in q), key=lambda s: sev_rank.get(s, 1))
        upgraded_sev = UPGRADE.get(max_sev, "CRITICAL")
        max_score = max((item[4] for item in q), default=0.0)

        corr_alert = Alert(
            type=f"DISTRIBUTED_{base_type}",
            source="AGGREGATED",
            severity=upgraded_sev,
            src_ip=alert.src_ip,
            description=(
                f"Tấn công phân tán: IP {alert.src_ip} bị phát hiện bởi "
                f"{len(distinct_peers)} nút ({', '.join(distinct_peers)}) trong {int(self.window)}s"
            ),
            origin_peer=self.my_id,
            lamport=self.clock.tick(),
            score=max_score,
            evidence={
                "reported_by_peers": distinct_peers,
                "event_count": len(q),
                "base_type": base_type,
                "window_sec": self.window
            }
        )
        log.warning(f"CORRELATED ALERT: [{corr_alert.severity}] {corr_alert.type} cho nguồn {corr_alert.src_ip}")
        return corr_alert
