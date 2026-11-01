# common/bus.py
import asyncio

class Bus:
    def __init__(self):
        self.flows = asyncio.Queue(maxsize=20000)   # Flow đã đóng: Collector -> Detection
        self.stats = asyncio.Queue(maxsize=600)     # Stats mỗi giây: Collector -> Rules
        self.alerts = asyncio.Queue()               # Alert cục bộ: Detection -> Gossip
        self.ui = asyncio.Queue(maxsize=2000)       # Sự kiện realtime gửi tới UI / WebSocket

    def ui_nowait(self, event: str, data: dict):
        """Gửi sự kiện realtime lên UI mà không làm nghẽn tiến trình nếu hàng đợi đầy"""
        try:
            self.ui.put_nowait({"event": event, "data": data})
        except asyncio.QueueFull:
            pass
