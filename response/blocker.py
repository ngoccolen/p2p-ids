import os
import time
import shutil
import subprocess
import logging
from typing import Dict, Any, List

log = logging.getLogger("response.blocker")


class IPBlocker:
    """Quản lý chặn IP xâm nhập bằng Linux Iptables & đồng bộ P2P (do Ngọc phụ trách)."""

    def __init__(self, cfg: dict, bus):
        self.cfg = cfg
        self.bus = bus
        ips_cfg = cfg.get("ips", {})
        self.auto_block: bool = ips_cfg.get("auto_block", True)
        self.block_severities = set(ips_cfg.get("block_severities", ["HIGH", "CRITICAL"]))
        self.block_ttl: int = ips_cfg.get("block_ttl", 300)  # Tự gỡ chặn sau 5 phút (0 = vĩnh viễn)

        # Xây dựng tập Whitelist an toàn tuyệt đối (tránh tự khóa SSH / Tailscale)
        self.whitelist = set(cfg.get("whitelist", []))
        self.whitelist.update({"127.0.0.1", "0.0.0.0", "::1", cfg.get("host", "")})
        for bp in cfg.get("bootstrap_peers", []):
            self.whitelist.add(bp.split(":")[0])

        # Bảo vệ phiên SSH quản trị hiện tại (nếu đang SSH từ Windows Host vào VM)
        ssh_client = os.environ.get("SSH_CLIENT", "")
        if ssh_client:
            ssh_ip = ssh_client.split()[0]
            self.whitelist.add(ssh_ip)
            log.info(f"Đã tự động thêm IP phiên SSH quản trị ({ssh_ip}) vào Whitelist bảo vệ.")

        self.has_iptables = shutil.which("iptables") is not None and os.geteuid() == 0
        # ip -> {"ip": ip, "reason": str, "blocked_at": float, "expires_at": float | None, "enforced": bool}
        self.blocked: Dict[str, Dict[str, Any]] = {}

    def should_auto_block(self, severity: str) -> bool:
        return self.auto_block and (severity in self.block_severities)

    def block_ip(self, ip: str, reason: str = "IPS Auto-Block", source_peer: str = "local") -> bool:
        if not ip or ip in self.whitelist:
            log.info(f"Bỏ qua chặn IP {ip} (nằm trong danh sách Whitelist an toàn).")
            return False

        now = time.time()
        expires = (now + self.block_ttl) if self.block_ttl > 0 else None

        if ip in self.blocked:
            self.blocked[ip]["expires_at"] = expires
            return False

        enforced = False
        if self.has_iptables:
            try:
                chk = subprocess.run(
                    ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                if chk.returncode != 0:
                    subprocess.run(
                        ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                enforced = True
            except Exception as e:
                log.warning(f"Không thể thêm rule iptables cho {ip}: {e}")

        entry = {
            "ip": ip,
            "reason": reason,
            "source_peer": source_peer,
            "blocked_at": now,
            "expires_at": expires,
            "enforced": enforced
        }
        self.blocked[ip] = entry
        mode_str = "IPTABLES DROP" if enforced else "SIMULATED (chưa có root/iptables)"
        log.warning(f"🛡️ ĐÃ CHẶN IP {ip} [{mode_str}] - Lý do: {reason} (từ {source_peer})")
        self.bus.ui_nowait("block", {"action": "BLOCK", **entry})
        return True

    def unblock_ip(self, ip: str) -> bool:
        entry = self.blocked.pop(ip, None)
        if self.has_iptables:
            try:
                while True:
                    res = subprocess.run(
                        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    if res.returncode != 0:
                        break
            except Exception:
                pass

        if entry:
            log.info(f"🔓 Đã gỡ chặn IP {ip}")
            self.bus.ui_nowait("block", {"action": "UNBLOCK", "ip": ip})
            return True
        return False

    def cleanup_expired(self):
        """Gỡ chặn tự động các IP đã hết thời gian cách ly TTL."""
        now = time.time()
        for ip, info in list(self.blocked.items()):
            exp = info.get("expires_at")
            if exp and now >= exp:
                log.info(f"Hết hạn cách ly ({self.block_ttl}s), tự động gỡ chặn IP {ip}")
                self.unblock_ip(ip)

    def list_blocked(self) -> List[Dict[str, Any]]:
        return sorted(self.blocked.values(), key=lambda x: x["blocked_at"], reverse=True)
