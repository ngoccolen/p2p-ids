# collector/sniffer.py
from scapy.all import AsyncSniffer
import logging

log = logging.getLogger("collector")

class Collector:
    def __init__(self, cfg: dict, flow_table):
        self.cfg = cfg
        self.ft = flow_table
        self.sniffer = None

    def start(self):
        iface = self.cfg["iface"]
        p2p_port = self.cfg["p2p_port"]
        api_port = self.cfg.get("api_port", 8000)

        # Lọc bỏ lưu lượng P2P và API để không tự bắt gói của chính mình
        bpf = f"not (tcp port {p2p_port} or tcp port {api_port})"
        log.info(f"Bắt gói tin trên card [{iface}] với BPF: {bpf}")

        self.sniffer = AsyncSniffer(
            iface=iface,
            filter=bpf,
            prn=self.ft.process_packet,
            store=False
        )
        self.sniffer.start()
