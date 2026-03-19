#!/usr/bin/env python3
"""
SEAL Server Process
Hosts one or more Server (ORAM partition) instances and exposes them
over a local TCP socket using a simple JSON-RPC protocol.

Start before running client.py:
    python3 server.py [--host 127.0.0.1] [--port 65432]
"""

import json
import random
import socket
import threading
import argparse
import sys
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Server class  (unchanged ORAM storage logic)
# ---------------------------------------------------------------------------

class Server:
    """
    Server class - Dumb storage with NO ORAM logic.
    Just stores encrypted buckets and responds to read/write requests.

    Each Server instance represents a single ORAM tree partition.
    """

    def __init__(self, L: int, Z: int, partition_id: int):
        self.L = L
        self.Z = Z
        self.partition_id = partition_id
        self.total_buckets = 2 ** (L + 1) - 1

        self.tree: Dict[int, List[Tuple[int, int]]] = {}
        for bucket_id in range(self.total_buckets):
            dummy_blocks = []
            for _ in range(Z):
                dummy_id = -(random.randint(1_000_000, 9_999_999))
                dummy_blocks.append((dummy_id, 0))
            self.tree[bucket_id] = dummy_blocks

    def read_bucket(self, bucket_id: int) -> List[Tuple[int, int]]:
        if bucket_id < 0 or bucket_id >= self.total_buckets:
            raise ValueError(f"Invalid bucket_id: {bucket_id}")
        return self.tree[bucket_id].copy()

    def write_bucket(self, bucket_id: int, blocks: List[Tuple[int, int]]):
        if bucket_id < 0 or bucket_id >= self.total_buckets:
            raise ValueError(f"Invalid bucket_id: {bucket_id}")
        if len(blocks) != self.Z:
            raise ValueError(f"Must write exactly {self.Z} blocks, got {len(blocks)}")
        self.tree[bucket_id] = [tuple(b) for b in blocks]

    def get_tree_snapshot(self) -> Dict[int, List[Tuple[int, int]]]:
        return {bid: blocks.copy() for bid, blocks in self.tree.items()}


# ---------------------------------------------------------------------------
# RPC dispatcher
# ---------------------------------------------------------------------------

class PartitionStore:
    """Thread-safe store of Server partitions."""

    def __init__(self):
        self._partitions: Dict[int, Server] = {}
        self._lock = threading.Lock()

    def dispatch(self, request: dict) -> dict:
        """Dispatch a JSON-RPC-style request and return a response dict."""
        method = request.get("method")
        params = request.get("params", {})

        try:
            if method == "init_partition":
                return self._init_partition(**params)
            elif method == "read_bucket":
                return self._read_bucket(**params)
            elif method == "write_bucket":
                return self._write_bucket(**params)
            elif method == "get_tree_snapshot":
                return self._get_tree_snapshot(**params)
            elif method == "get_partition_meta":
                return self._get_partition_meta(**params)
            else:
                return {"error": f"Unknown method: {method}"}
        except Exception as exc:
            return {"error": str(exc)}

    # -- partition lifecycle --------------------------------------------------

    def _init_partition(self, partition_id: int, L: int, Z: int) -> dict:
        with self._lock:
            self._partitions[partition_id] = Server(L=L, Z=Z, partition_id=partition_id)
        return {"ok": True, "total_buckets": self._partitions[partition_id].total_buckets}

    def _get_partition_meta(self, partition_id: int) -> dict:
        with self._lock:
            srv = self._partitions[partition_id]
            return {"L": srv.L, "Z": srv.Z, "total_buckets": srv.total_buckets}

    # -- storage operations --------------------------------------------------

    def _read_bucket(self, partition_id: int, bucket_id: int) -> dict:
        with self._lock:
            srv = self._partitions[partition_id]
            blocks = srv.read_bucket(bucket_id)
        return {"blocks": blocks}

    def _write_bucket(self, partition_id: int, bucket_id: int,
                      blocks: list) -> dict:
        with self._lock:
            srv = self._partitions[partition_id]
            srv.write_bucket(bucket_id, [tuple(b) for b in blocks])
        return {"ok": True}

    def _get_tree_snapshot(self, partition_id: int) -> dict:
        with self._lock:
            srv = self._partitions[partition_id]
            snapshot = srv.get_tree_snapshot()
        # JSON keys must be strings
        return {"snapshot": {str(k): v for k, v in snapshot.items()},
                "total_buckets": srv.total_buckets}


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

def _recv_message(conn: socket.socket) -> dict:
    """Receive a length-prefixed JSON message."""
    raw_len = b""
    while len(raw_len) < 4:
        chunk = conn.recv(4 - len(raw_len))
        if not chunk:
            raise ConnectionResetError("Client disconnected")
        raw_len += chunk
    msg_len = int.from_bytes(raw_len, "big")
    data = b""
    while len(data) < msg_len:
        chunk = conn.recv(min(4096, msg_len - len(data)))
        if not chunk:
            raise ConnectionResetError("Client disconnected mid-message")
        data += chunk
    return json.loads(data.decode())


def _send_message(conn: socket.socket, obj: dict):
    """Send a length-prefixed JSON message."""
    data = json.dumps(obj).encode()
    conn.sendall(len(data).to_bytes(4, "big") + data)


def handle_client(conn: socket.socket, addr, store: PartitionStore):
    print(f"[server] Connection from {addr}")
    try:
        while True:
            request = _recv_message(conn)
            response = store.dispatch(request)
            _send_message(conn, response)
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as exc:
        print(f"[server] Error handling {addr}: {exc}")
    finally:
        conn.close()
        print(f"[server] Connection closed: {addr}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SEAL ORAM Server – hosts partition storage over TCP"
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=65432,
                        help="Bind port (default: 65432)")
    args = parser.parse_args()

    store = PartitionStore()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv_sock:
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind((args.host, args.port))
        srv_sock.listen()
        print(f"[server] Listening on {args.host}:{args.port}")

        try:
            while True:
                conn, addr = srv_sock.accept()
                t = threading.Thread(target=handle_client,
                                     args=(conn, addr, store),
                                     daemon=True)
                t.start()
        except KeyboardInterrupt:
            print("\n[server] Shutting down.")


if __name__ == "__main__":
    main()
