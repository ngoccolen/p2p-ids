# p2p/protocol.py
import json
import time
import uuid

def make_msg(type_: str, sender: str, lamport: int, payload: dict = None, **extra) -> dict:
    """Tạo một gói tin JSON chuẩn của hệ thống P2P."""
    m = {
        "type": type_,
        "msg_id": str(uuid.uuid4()),
        "sender": sender,
        "lamport": lamport,
        "ts": time.time(),
        "payload": payload or {}
    }
    m.update(extra)
    return m

def encode(msg: dict) -> bytes:
    """Chuyển dict thành chuỗi bytes kèm ký tự xuống dòng \n để gửi qua socket."""
    return (json.dumps(msg, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")

def decode(line: bytes) -> dict:
    """Giải mã dòng bytes nhận từ socket thành dict."""
    return json.loads(line.decode("utf-8"))
