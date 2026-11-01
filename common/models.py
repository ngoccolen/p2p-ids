# common/models.py
from dataclasses import dataclass, field, asdict
import time
import uuid

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
UPGRADE = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"}
BASE_TYPES = ["PORT_SCAN", "NETWORK_SCAN", "SSH_BRUTE_FORCE", "FLOOD", "ANOMALY"]

@dataclass
class Flow:
    """Do Ngọc tạo ra từ gói tin mạng -> Linh dùng để trích xuất đặc trưng AI."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str       # TCP | UDP | ICMP
    start_ts: float
    end_ts: float
    packets: int = 0
    bytes: int = 0
    fwd_packets: int = 0
    bwd_packets: int = 0
    syn: int = 0
    ack: int = 0
    fin: int = 0
    rst: int = 0
    psh: int = 0
    urg: int = 0

    @property
    def flow_id(self) -> str:
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"

    @property
    def duration(self) -> float:
        return max(self.end_ts - self.start_ts, 1e-3)

@dataclass
class SrcStats:
    """Thống kê trong 1 giây của 1 IP nguồn."""
    packets: int = 0
    bytes: int = 0
    syn: int = 0                              # Gói SYN không có ACK
    icmp_echo: int = 0
    arp_req: int = 0
    dst_hosts: set = field(default_factory=set)     # Danh sách host bị thăm dò
    dst_ports: dict = field(default_factory=dict)   # dst_ip -> set(ports)

@dataclass
class TrafficStats:
    """Ngọc xuất ra mỗi giây -> Linh nạp vào Rules để phát hiện Scan/Flood."""
    ts: float
    total_packets: int = 0
    total_bytes: int = 0
    by_src: dict = field(default_factory=dict)      # src_ip -> SrcStats

@dataclass
class RuleHit:
    """Kết quả phát hiện từ Rules."""
    type: str
    src_ip: str
    severity: str
    description: str
    dst_ip: str | None = None
    evidence: dict = field(default_factory=dict)

@dataclass
class Alert:
    """Cảnh báo an ninh chính thức. Linh tạo -> Ngọc phát tán qua P2P."""
    type: str               # PORT_SCAN | NETWORK_SCAN | SSH_BRUTE_FORCE | FLOOD | ANOMALY
    source: str             # RULE | AI | RULE+AI | AGGREGATED
    severity: str           # LOW | MEDIUM | HIGH | CRITICAL
    src_ip: str
    description: str
    origin_peer: str        # Peer phát hiện ban đầu (ví dụ: 'peer1')
    lamport: int            # Đồng hồ logic tại thời điểm tạo
    dst_ip: str | None = None
    score: float = 0.0      # Điểm bất thường từ AI hoặc mức tin cậy
    evidence: dict = field(default_factory=dict)
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    status: str = "NEW"     # NEW | ACKNOWLEDGED | RESOLVED | FALSE_POSITIVE

    def to_dict(self) -> dict:
        return asdict(self)
