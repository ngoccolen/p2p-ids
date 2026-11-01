# collector/flow_table.py
import threading
import time
from scapy.all import IP, TCP, UDP, ICMP, ARP
from common.models import Flow, SrcStats, TrafficStats

FLAGS = {"S": "syn", "A": "ack", "F": "fin", "R": "rst", "P": "psh", "U": "urg"}

class FlowTable:
    def __init__(self, cfg=None, idle_timeout=15, active_timeout=60):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.flows: dict[tuple, Flow] = {}
        self.lock = threading.Lock()
        self.stats = TrafficStats(ts=time.time())

    def _get_src(self, ip: str) -> SrcStats:
        return self.stats.by_src.setdefault(ip, SrcStats())

    def process_packet(self, pkt):
        now = time.time()
        with self.lock:
            # Bắt gói tin thăm dò ARP
            if ARP in pkt and pkt[ARP].op == 1:
                s = self._get_src(pkt[ARP].psrc)
                s.arp_req += 1
                s.dst_hosts.add(pkt[ARP].pdst)
                return

            if IP not in pkt:
                return

            ip = pkt[IP]
            size = len(pkt)
            sport = dport = 0
            flags = ""

            if TCP in pkt:
                proto = "TCP"
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                flags = str(pkt[TCP].flags)
            elif UDP in pkt:
                proto = "UDP"
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
            elif ICMP in pkt:
                proto = "ICMP"
            else:
                return

            self.stats.total_packets += 1
            self.stats.total_bytes += size
            s = self._get_src(ip.src)
            s.packets += 1
            s.bytes += size

            # Phát hiện dấu hiệu quét cổng SYN hoặc Ping quét mạng
            if proto == "TCP" and "S" in flags and "A" not in flags:
                s.syn += 1
                s.dst_hosts.add(ip.dst)
                s.dst_ports.setdefault(ip.dst, set()).add(dport)
            elif proto == "ICMP" and pkt[ICMP].type == 8:
                s.icmp_echo += 1
                s.dst_hosts.add(ip.dst)

            # Gom theo cặp xuôi/ngược của 5-tuple
            fkey = (ip.src, sport, ip.dst, dport, proto)
            bkey = (ip.dst, dport, ip.src, sport, proto)

            if fkey in self.flows:
                f = self.flows[fkey]
                f.fwd_packets += 1
            elif bkey in self.flows:
                f = self.flows[bkey]
                f.bwd_packets += 1
            else:
                f = Flow(ip.src, ip.dst, sport, dport, proto, start_ts=now, end_ts=now, fwd_packets=1)
                self.flows[fkey] = f

            f.packets += 1
            f.bytes += size
            f.end_ts = now

            for ch, name in FLAGS.items():
                if ch in flags:
                    setattr(f, name, getattr(f, name) + 1)

    def tick(self):
        """Được gọi mỗi giây để lấy ra các Flow đã đóng và bảng thống kê lưu lượng."""
        now = time.time()
        with self.lock:
            closed = []
            for k, f in list(self.flows.items()):
                if f.rst > 0 or (f.fin >= 2 and now - f.end_ts > 1.0) or \
                   (now - f.end_ts > self.idle_timeout) or (now - f.start_ts > self.active_timeout):
                    closed.append(self.flows.pop(k))

            current_stats = self.stats
            self.stats = TrafficStats(ts=now)

        return closed, current_stats
