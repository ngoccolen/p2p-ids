# test_p2p_week2.py
import argparse
import asyncio
import logging
import os
import yaml
from common.bus import Bus
from common.lamport import LamportClock
from storage.db import Database
from p2p.peer_manager import PeerManager
from p2p.node import P2PNode

log = logging.getLogger("test_p2p")

async def main(cfg: dict):
    os.makedirs(os.path.dirname(cfg["db_path"]), exist_ok=True)
    db = Database(cfg["db_path"])
    db.init()

    bus = Bus()
    clock = LamportClock()
    peers = PeerManager(db, bus)
    node = P2PNode(cfg, peers, clock)

    log.info(f"Khởi động thử nghiệm P2P Node cho {cfg['peer_id']}...")
    await node.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, help="Đường dẫn file config yaml")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    with open(args.config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    try:
        asyncio.run(main(config))
    except KeyboardInterrupt:
        log.info("Dừng thử nghiệm P2P.")
