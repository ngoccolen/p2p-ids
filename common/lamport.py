# common/lamport.py
import threading

class LamportClock:
    def __init__(self):
        self._t = 0
        self._lock = threading.Lock()

    def tick(self) -> int:
        """Tăng đồng hồ lên 1 mỗi khi có sự kiện nội bộ hoặc trước khi gửi tin."""
        with self._lock:
            self._t += 1
            return self._t

    def update(self, received: int) -> int:
        """Cập nhật đồng hồ khi nhận được tin nhắn từ peer khác."""
        with self._lock:
            self._t = max(self._t, received) + 1
            return self._t

    @property
    def value(self) -> int:
        return self._t
