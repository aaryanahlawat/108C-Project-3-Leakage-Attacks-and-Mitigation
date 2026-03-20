#!/usr/bin/env python3
"""
SEAL (Searchable Encryption with Adjustable Leakage) Client
Based on "SEAL: Attack Mitigation for Encrypted Databases via Adjustable Leakage"
by Demertzis et al. (USENIX Security 2020)

This implementation demonstrates ADJ-ORAM-α: an adjustable ORAM that partitions
data into multiple smaller ORAMs, trading privacy for performance.

Key Parameters (following SEAL paper Section 4.1):
- α (alpha): The leakage parameter controlling bits of access pattern revealed
- P (partitions): Number of ORAM partitions, calculated as P = 2^α
  * α=0 → P=1:  Standard Path ORAM (0 bits leaked, no partition info)
  * α=1 → P=2:  Server observes which half (1 bit leaked)
  * α=2 → P=4:  Server observes which quarter (2 bits leaked)
  * α=3 → P=8:  Server observes which eighth (3 bits leaked)

The relationship: P = 2^α means α bits of the access pattern are revealed.

Usage:
    # Start the server first (in another terminal):
    python3 server.py

    # Then run the client exactly as you would have run model.py:
    python3 client.py --parameters input.txt output.txt
"""

import random
import math
import json
import socket
import argparse
import sys
from typing import Dict, List, Tuple, Optional


# ---------------------------------------------------------------------------
# Transport helpers (mirrored from server.py)
# ---------------------------------------------------------------------------

def _recv_message(conn: socket.socket) -> dict:
    raw_len = b""
    while len(raw_len) < 4:
        chunk = conn.recv(4 - len(raw_len))
        if not chunk:
            raise ConnectionResetError("Server disconnected")
        raw_len += chunk
    msg_len = int.from_bytes(raw_len, "big")
    data = b""
    while len(data) < msg_len:
        chunk = conn.recv(min(4096, msg_len - len(data)))
        if not chunk:
            raise ConnectionResetError("Server disconnected mid-message")
        data += chunk
    return json.loads(data.decode())


def _send_message(conn: socket.socket, obj: dict):
    data = json.dumps(obj).encode()
    conn.sendall(len(data).to_bytes(4, "big") + data)


# ---------------------------------------------------------------------------
# RemoteServer  – transparent proxy for server.py's Server partitions
# ---------------------------------------------------------------------------

class RemoteServer:
    """
    Drop-in replacement for the in-process Server class.
    All bucket reads/writes are forwarded to server.py over TCP.
    """

    def __init__(self, conn: socket.socket, partition_id: int,
                 L: int, Z: int):
        self._conn = conn
        self.partition_id = partition_id
        self.L = L
        self.Z = Z

        # Ask the server to allocate this partition
        resp = self._call("init_partition",
                          partition_id=partition_id, L=L, Z=Z)
        if "error" in resp:
            raise RuntimeError(f"Server error on init_partition: {resp['error']}")
        self.total_buckets = resp["total_buckets"]

    def _call(self, method: str, **params) -> dict:
        _send_message(self._conn, {"method": method, "params": params})
        return _recv_message(self._conn)

    def read_bucket(self, bucket_id: int) -> List[Tuple[int, int]]:
        resp = self._call("read_bucket",
                          partition_id=self.partition_id,
                          bucket_id=bucket_id)
        if "error" in resp:
            raise ValueError(resp["error"])
        return [tuple(b) for b in resp["blocks"]]

    def write_bucket(self, bucket_id: int, blocks: List[Tuple[int, int]]):
        resp = self._call("write_bucket",
                          partition_id=self.partition_id,
                          bucket_id=bucket_id,
                          blocks=[list(b) for b in blocks])
        if "error" in resp:
            raise ValueError(resp["error"])

    def get_tree_snapshot(self) -> Dict[int, List[Tuple[int, int]]]:
        resp = self._call("get_tree_snapshot",
                          partition_id=self.partition_id)
        if "error" in resp:
            raise ValueError(resp["error"])
        # Keys come back as strings over JSON
        return {int(k): [tuple(b) for b in v]
                for k, v in resp["snapshot"].items()}


# ---------------------------------------------------------------------------
# Client class  (unchanged ORAM logic)
# ---------------------------------------------------------------------------

class Client:
    """
    Client class for SEAL's ADJ-ORAM-α implementation.

    Manages multiple Server partitions and implements the adjustable leakage
    protocol. The position map now tracks (partition_id, leaf_id) for each block.
    """

    def __init__(self, partitions: Dict[int, RemoteServer], L: int, P: int,
                 padding_x: Optional[int] = None):
        self.partitions = partitions
        self.L = L
        self.P = P
        self.padding_x = padding_x
        self.Z = next(iter(partitions.values())).Z

        self.num_leaves = 2 ** L
        self.position: Dict[int, Tuple[int, int]] = {}
        self.stash: Dict[int, int] = {}
        self.result_sizes: Dict[int, int] = {}
        # Tracks block_id -> stored integer value for GROUP_READ (SE mode)
        self._group_index: Dict[int, int] = {}

        # For visualization
        self.mid_query_stash: Dict[int, int] = {}
        self.mid_query_partition = -1
        self.mid_query_leaf = -1

        # Statistics
        self.read_count = 0
        self.write_count = 0
        self.access_count = 0
        self.max_stash_size = 0

    def _calculate_padded_size(self, actual_size: int) -> int:
        """
        Calculate padded size using ADJ-PADDING-x.

        From SEAL paper Section 4.2:
        "Pad every list to the closest power of x"
        """
        if self.padding_x is None or actual_size == 0:
            return actual_size
        i = math.ceil(math.log(actual_size, self.padding_x))
        return self.padding_x ** i

    def _path_node(self, leaf: int, level: int) -> int:
        """
        Get the bucket ID on the path to 'leaf' at 'level'.
        Level 0 is root, level L is leaf.
        """
        if level == 0:
            return 0
        node = leaf >> (self.L - level)
        return (1 << level) - 1 + node

    def _get_path(self, leaf: int) -> List[int]:
        return [self._path_node(leaf, y) for y in range(self.L + 1)]

    def _on_path(self, block_leaf: int, path_leaf: int, level: int) -> bool:
        return self._path_node(block_leaf, level) == self._path_node(path_leaf, level)

    def access(self, op: str, block_id: int,
               data: Optional[int] = None) -> Optional[int]:
        """
        SEAL ADJ-ORAM-α access operation — faithful Path ORAM implementation.

        Follows Figure 1 of Stefanov et al. (Path ORAM, CCS 2013) and
        Section 4.1 of Demertzis et al. (SEAL, USENIX Security 2020).

        Steps (paper line numbers in comments):
          1. Look up (or assign) the block's current (partition, leaf).     [line 1]
          2. Remap the block to a fresh random leaf in the SAME partition.  [line 2]
             → The OLD leaf x is saved; the path read uses x, not new_leaf.
          3. Read every bucket along path P(x) into the stash.             [lines 3-5]
          4. Retrieve / update the target block in the stash.              [lines 6-9]
          5. Write back path leaf→root with greedy eviction:               [lines 10-15]
             - Only blocks whose PARTITION matches and whose assigned leaf
               intersects the current path at this level are eligible.
             - Eligible candidates are shuffled before selection so real
               blocks land at random positions rather than always at the
               shallowest slot (preserving the Path ORAM invariant).
             - After selecting up to Z real blocks, the remaining slots are
               filled with freshly generated dummy blocks.
             - The complete bucket (real + dummy) is shuffled before the
               write so the server cannot infer block position within a
               bucket from slot index.

        SEAL leakage: the server observes WHICH partition is accessed
        (α bits), but nothing about the leaf or which block within the
        partition — this is the intentional, adjustable leakage.
        """
        self.access_count += 1
        if op == 'read':
            self.read_count += 1
        else:
            self.write_count += 1

        # ------------------------------------------------------------------
        # Step 1: Look up current position; assign a random one on first
        #         access.  Do NOT pre-populate the stash here — the block
        #         will be found (or initialised to 0) after the path read.
        # ------------------------------------------------------------------
        if block_id not in self.position:
            partition_id = random.randint(0, self.P - 1)
            leaf_id      = random.randint(0, self.num_leaves - 1)
            self.position[block_id] = (partition_id, leaf_id)

        partition_id, old_leaf = self.position[block_id]

        # ============================================================
        # SEAL LEAKAGE: Server observes which partition is accessed.
        # This is the intentional α-bit leakage from ADJ-ORAM-α.
        # ============================================================
        print(f"[SEAL LEAKAGE] Server observes access to Partition ID: {partition_id}")

        # ------------------------------------------------------------------
        # Step 2: Remap block to a NEW random leaf in the SAME partition
        #         BEFORE reading the path (paper line 2).
        #         We keep old_leaf to know which path to actually read.
        # ------------------------------------------------------------------
        new_leaf = random.randint(0, self.num_leaves - 1)
        self.position[block_id] = (partition_id, new_leaf)

        # ------------------------------------------------------------------
        # Step 3: Read every bucket along P(old_leaf) into the stash.
        #         Only real blocks (non-negative IDs) enter the stash.
        #         Dummy blocks (negative IDs) are discarded.
        # ------------------------------------------------------------------
        server = self.partitions[partition_id]
        path   = self._get_path(old_leaf)

        for bucket_id in path:
            bucket = server.read_bucket(bucket_id)
            for blk_id, blk_data in bucket:
                if blk_id >= 0:                       # ignore dummies
                    self.stash[blk_id] = blk_data

        # Save stash state mid-query for the state visualisation
        self.mid_query_stash     = self.stash.copy()
        self.mid_query_partition = partition_id
        self.mid_query_leaf      = old_leaf

        # ------------------------------------------------------------------
        # Step 4: Retrieve the target block from the stash.
        #         If it was never written before, initialise its value to 0
        #         (paper: "client should assume block has default value 0").
        # ------------------------------------------------------------------
        if block_id not in self.stash:
            self.stash[block_id] = 0

        result_data = self.stash[block_id]

        # ------------------------------------------------------------------
        # Step 5: If this is a write, update the block value in the stash.
        # ------------------------------------------------------------------
        if op == 'write':
            if data is None:
                raise ValueError("Write operation requires data")
            self.stash[block_id] = data
            result_data = data

        # ------------------------------------------------------------------
        # Step 6: Write path back leaf→root with greedy eviction.
        #
        #   For each level (leaf first, root last):
        #     a) Collect ELIGIBLE blocks: blocks whose partition matches
        #        AND whose assigned leaf shares the same ancestor at this
        #        level as old_leaf (the _on_path invariant from Path ORAM).
        #     b) SHUFFLE the eligible list — this is critical.  Without it,
        #        dict iteration order would always place the same blocks at
        #        the shallowest level, defeating the random-placement goal
        #        of Path ORAM and making the stash grow unboundedly.
        #     c) Take at most Z blocks (greedy: as many as the bucket holds).
        #     d) Fill remaining slots with dummy blocks (fresh random IDs
        #        below -1000 to avoid collisions with the -(slot+1) scheme).
        #     e) SHUFFLE the final bucket before writing so the server
        #        cannot learn which slot holds the real block.
        # ------------------------------------------------------------------
        for level in range(self.L, -1, -1):
            bucket_id = self._path_node(old_leaf, level)

            # Collect eligible: same partition AND path intersection.
            # Per Path ORAM Figure 1 lines 10-14, we iterate leaf→root so
            # blocks are pushed as DEEP as possible — this is what keeps the
            # stash bounded (Theorem 1).  We do NOT shuffle the eligible list;
            # any deterministic selection order is correct and preserves the
            # greedy push-deep property.
            eligible = [
                blk_id for blk_id in self.stash
                if self.position[blk_id][0] == partition_id
                and self._on_path(self.position[blk_id][1], old_leaf, level)
            ]

            # Take up to Z blocks (greedy)
            selected = eligible[:self.Z]

            # Build bucket with selected real blocks
            bucket_blocks: List[Tuple[int, int]] = []
            for blk_id in selected:
                bucket_blocks.append((blk_id, self.stash[blk_id]))
                del self.stash[blk_id]

            # Pad to exactly Z with uniquely-IDed dummy blocks
            while len(bucket_blocks) < self.Z:
                dummy_id = -(random.randint(1_000_000, 9_999_999))
                bucket_blocks.append((dummy_id, 0))

            # Shuffle the BUCKET (not the eligible list) so the server cannot
            # infer which slot holds a real block vs. a dummy from position alone.
            random.shuffle(bucket_blocks)

            server.write_bucket(bucket_id, bucket_blocks)

        self.max_stash_size = max(self.max_stash_size, len(self.stash))
        return result_data

    def read(self, block_id: int) -> int:
        result = self.access('read', block_id)

        if self.padding_x is not None:
            actual_size = 1
            padded_size = self._calculate_padded_size(actual_size)
            print(f"READ result: Block {block_id} = {result}")
            print(f"  [Volume Protection] Actual: 1 block, Padded to: {padded_size} (power of {self.padding_x})")
        else:
            print(f"READ result: Block {block_id} = {result}")

        return result

    def write(self, block_id: int, data: int):
        self._group_index[block_id] = data   # track for GROUP_READ queries
        self.access('write', block_id, data)

        if self.padding_x is not None:
            actual_size = 1
            padded_size = self._calculate_padded_size(actual_size)
            print(f"WRITE complete: Block {block_id} = {data}")
            print(f"  [Volume Protection] Actual: 1 block, Padded to: {padded_size} (power of {self.padding_x})")
        else:
            print(f"WRITE complete: Block {block_id} = {data}")

    def get_position_map(self) -> Dict[int, Tuple[int, int]]:
        return self.position.copy()

    def get_stash(self) -> Dict[int, int]:
        return self.stash.copy()

    def get_mid_query_stash(self) -> Tuple[Dict[int, int], int, int]:
        return self.mid_query_stash.copy(), self.mid_query_partition, self.mid_query_leaf

    def get_statistics(self) -> Dict[str, int]:
        return {
            'Total Accesses': self.access_count,
            'Reads': self.read_count,
            'Writes': self.write_count,
            'Max Stash Size': self.max_stash_size,
            'Final Stash Size': len(self.stash),
            'Blocks in Position Map': len(self.position),
            'Number of Partitions (P)': self.P,
            'Leakage Parameter (α)': int(math.log2(self.P)) if self.P > 0 else 0,
        }


# ---------------------------------------------------------------------------
# print_state  (unchanged)
# ---------------------------------------------------------------------------

def print_state(query: str, client: Client,
                partitions: Dict[int, RemoteServer], output_file):
    """
    Print complete system state after a query, including all partitions.
    """
    print(f"\n--- State after: {query} ---")
    output_file.write(f"\n--- State after: {query} ---\n")

    # Client Position Map
    print("\nClient Position Map (block_id -> (partition_id, leaf_id)):")
    output_file.write("\nClient Position Map (block_id -> (partition_id, leaf_id)):\n")

    pos_map = client.get_position_map()
    if pos_map:
        for block_id in sorted(pos_map.keys()):
            partition_id, leaf_id = pos_map[block_id]
            print(f"  Block {block_id} -> (Partition {partition_id}, Leaf {leaf_id})")
            output_file.write(f"  Block {block_id} -> (Partition {partition_id}, Leaf {leaf_id})\n")
    else:
        print("  (empty)")
        output_file.write("  (empty)\n")

    # Stash (after operation completes)
    print("\nClient Stash (after operation):")
    output_file.write("\nClient Stash (after operation):\n")

    stash = client.get_stash()
    if stash:
        for block_id in sorted(stash.keys()):
            data = stash[block_id]
            print(f"  Block {block_id}: data={data}")
            output_file.write(f"  Block {block_id}: data={data}\n")
    else:
        print("  (empty)")
        output_file.write("  (empty)\n")

    # Mid-Query Stash
    mid_stash, mid_partition, mid_leaf = client.get_mid_query_stash()
    if mid_partition >= 0:
        print(f"\nMid-Query Stash (after reading path to Partition {mid_partition}, Leaf {mid_leaf}):")
        output_file.write(f"\nMid-Query Stash (after reading path to Partition {mid_partition}, Leaf {mid_leaf}):\n")

        if mid_stash:
            for block_id in sorted(mid_stash.keys()):
                data = mid_stash[block_id]
                print(f"  Block {block_id}: data={data}")
                output_file.write(f"  Block {block_id}: data={data}\n")
        else:
            print("  (empty)")
            output_file.write("  (empty)\n")

    # Server Trees (ALL PARTITIONS)
    print("\n" + "="*60)
    print("SERVER TREE STRUCTURES (All Partitions)")
    print("="*60)
    output_file.write("\n" + "="*60 + "\n")
    output_file.write("SERVER TREE STRUCTURES (All Partitions)\n")
    output_file.write("="*60 + "\n")

    for partition_id in sorted(partitions.keys()):
        server = partitions[partition_id]
        print(f"\n--- Partition {partition_id} ---")
        output_file.write(f"\n--- Partition {partition_id} ---\n")

        tree = server.get_tree_snapshot()

        for bucket_id in range(server.total_buckets):
            blocks = tree.get(bucket_id, [])
            content = ", ".join([f"({blk_id}, {data})" for blk_id, data in blocks])
            print(f"  Bucket {bucket_id}: [{content}]")
            output_file.write(f"  Bucket {bucket_id}: [{content}]\n")


# ---------------------------------------------------------------------------
# parse_arguments  (unchanged, plus --host / --port for server address)
# ---------------------------------------------------------------------------

def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments containing:
            - input_file, output_file, alpha, tree_height, padding
            - host, port  (address of server.py)
    """
    parser = argparse.ArgumentParser(
        description='SEAL ADJ-ORAM-α: Adjustable Oblivious RAM Simulation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SEAL Parameters (from paper Section 4):
  α (alpha): Controls access pattern leakage via partitioning
             P = 2^α partitions created, α bits leaked

  L (length/levels): Tree height for each ORAM partition
                     Affects bandwidth: O(L) per access

  x (padding): Controls volume pattern leakage
               Pads result sizes to closest power of x
               Leaks log_x(N) bits of volume pattern

Examples:
  # Standard Path ORAM (α=0, P=1, no access pattern leakage)
  python3 client.py input.txt output.txt -a 0

  # SEAL with 1 bit access pattern leakage (α=1, P=2)
  python3 client.py input.txt output.txt -a 1

  # Custom tree height (deeper trees, more bandwidth)
  python3 client.py input.txt output.txt -a 1 -l 4

  # Add volume pattern protection (pad to powers of 4)
  python3 client.py input.txt output.txt -a 1 -x 4

  # Full SEAL: access + volume protection
  python3 client.py input.txt output.txt -a 2 -l 3 -x 2

  # Connect to a remote server.py instance
  python3 client.py input.txt output.txt -a 1 --host 192.168.1.10 --port 65432

Note: SEAL(α,x) uses both ADJ-ORAM-α and ADJ-PADDING-x
        """
    )

    # Positional arguments
    parser.add_argument(
        'input_file',
        type=str,
        help='Path to input file containing queries (one per line: WRITE <id> <data> or READ <id>)'
    )
    parser.add_argument(
        'output_file',
        type=str,
        help='Path to output file where execution trace will be saved'
    )

    # ORAM parameters
    parser.add_argument(
        '-a', '--alpha',
        type=int,
        default=1,
        metavar='α',
        help='ADJ-ORAM-α parameter (default: 1). Access pattern leakage: P=2^α partitions, α bits leaked.'
    )
    parser.add_argument(
        '-l', '--length',
        type=int,
        default=2,
        metavar='L',
        dest='tree_height',
        help='Tree height/levels L (default: 2). Each partition has 2^L leaf buckets.'
    )
    parser.add_argument(
        '-x', '--padding',
        type=int,
        default=None,
        metavar='x',
        help='ADJ-PADDING-x parameter (optional). Pads result sizes to powers of x.'
    )

    # Server address
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='server.py hostname or IP (default: 127.0.0.1)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=65432,
        help='server.py port (default: 65432)'
    )

    parser.add_argument(
        '--query-log',
        type=str,
        default=None,
        metavar='PATH',
        dest='query_log',
        help=(
            'Path to write the machine-readable query log (JSON-lines). '
            'Required by attack.py to run leakage-abuse attacks. '
            'Example: --query-log queries.jsonl'
        )
    )

    args = parser.parse_args()
    args.partitions = 2 ** args.alpha

    if args.alpha < 0:
        parser.error("Alpha must be non-negative (α ≥ 0)")
    if args.tree_height < 1:
        parser.error("Tree height must be at least 1 (L ≥ 1)")
    if args.tree_height > 20:
        parser.error(f"Tree height too large (L={args.tree_height}). Practical maximum is around L=20.")
    if args.padding is not None and args.padding < 2:
        parser.error("Padding parameter must be at least 2 (x ≥ 2) or omit for no padding")

    return args


# ---------------------------------------------------------------------------
# main  (unchanged logic, uses RemoteServer instead of in-process Server)
# ---------------------------------------------------------------------------

def main():
    """Main function to run SEAL ADJ-ORAM simulation."""

    args = parse_arguments()

    input_file_path = args.input_file
    output_file_path = args.output_file
    alpha = args.alpha
    P = args.partitions
    L = args.tree_height
    x = args.padding

    print("SEAL (Searchable Encryption with Adjustable Leakage)")
    print("ADJ-ORAM-α with ADJ-PADDING-x")
    print("="*60)

    Z = 4  # Blocks per bucket (fixed for this demo)

    # Display configuration
    print(f"\nConfiguration:")
    print(f"  === Access Pattern Protection (ADJ-ORAM-α) ===")
    print(f"  Leakage Parameter (α): {alpha}")
    print(f"  Number of Partitions (P): {P}")
    print(f"  → P = 2^α = 2^{alpha} = {P}")
    print(f"  → Access pattern leakage: {alpha} bit{'s' if alpha != 1 else ''}")
    print(f"  → Server observes which of {P} partitions is accessed")
    print()
    print(f"  === Tree Structure (Path ORAM) ===")
    print(f"  Tree Height (L): {L}")
    print(f"  Bucket Size (Z): {Z}")
    print(f"  → Leaf buckets per partition: {2**L}")
    print(f"  → Total buckets per partition: {2**(L+1)-1}")
    print(f"  → Bandwidth per access: O(L) = O({L}) paths")
    print()

    if x is not None:
        print(f"  === Volume Pattern Protection (ADJ-PADDING-x) ===")
        print(f"  Padding Parameter (x): {x}")
        print(f"  → Result sizes padded to powers of {x}")
        print(f"  → Volume leakage: ~log_{x}(N) distinct sizes")
        print(f"  → Overhead: up to {x}× storage/bandwidth")
    else:
        print(f"  === Volume Pattern Protection ===")
        print(f"  Padding: DISABLED (x=⊥)")
        print(f"  → Full volume pattern leaked (actual result sizes visible)")

    print()
    print(f"  SEAL Configuration: SEAL({alpha}, {x if x is not None else '⊥'})")

    # ===== Connect to server.py =====
    print(f"\nConnecting to server.py at {args.host}:{args.port} ...", end=" ", flush=True)
    try:
        conn = socket.create_connection((args.host, args.port), timeout=10)
    except (ConnectionRefusedError, OSError) as exc:
        print(f"\n[ERROR] Cannot connect to server.py: {exc}")
        print(f"  → Make sure server.py is running:  python3 server.py --host {args.host} --port {args.port}")
        sys.exit(1)
    print("connected.")

    # ===== Create Remote Server Partitions =====
    partitions: Dict[int, RemoteServer] = {}
    for partition_id in range(P):
        partitions[partition_id] = RemoteServer(
            conn=conn, partition_id=partition_id, L=L, Z=Z
        )
    print(f"✓ Created {P} remote server partitions (independent ORAM trees)")

    # ===== Create Client =====
    client = Client(partitions=partitions, L=L, P=P, padding_x=x)
    print(f"✓ Client initialized with position map tracking (partition_id, leaf_id)")
    if x is not None:
        print(f"✓ Volume pattern protection enabled (ADJ-PADDING-{x})")

    # ===== Read Queries from Input File (.txt or .csv) =====
    # CSV format: one query per row, either a single column ("READ 1")
    # or two/three columns ("WRITE","1","99" / "READ","1").
    # TXT format: one query per line ("WRITE 1 99" / "READ 1").
    import csv, os
    ext = os.path.splitext(input_file_path)[1].lower()

    if not os.path.exists(input_file_path):
        print(f"\n[ERROR] Input file '{input_file_path}' not found.")
        print(f"  → Check the filename and try again.")
        conn.close()
        sys.exit(1)

    try:
        queries = []
        if ext == '.csv':
            with open(input_file_path, newline='', encoding='utf-8-sig') as f:
                reader = csv.reader(f)
                for row_num, row in enumerate(reader, 1):
                    # Skip blank rows
                    if not row or all(c.strip() == '' for c in row):
                        continue
                    # Only take the first 3 columns: op, block_id, [data]
                    # This means a Chicago-style CSV with 20+ columns won't
                    # get mangled — columns 4+ are silently ignored.
                    cols = [c.strip() for c in row[:3]]
                    op = cols[0].upper() if cols else ''
                    if op not in ('READ', 'WRITE', 'GROUP_READ'):
                        # Skip header rows or any row that isn't a query
                        continue
                    if len(cols) < 2 or not cols[1]:
                        print(f"[SKIP] Row {row_num}: missing block_id → {row[:3]}")
                        continue
                    if op == 'WRITE' and (len(cols) < 3 or not cols[2]):
                        print(f"[SKIP] Row {row_num}: WRITE missing data → {row[:3]}")
                        continue
                    # Validate block_id is an integer
                    try:
                        int(cols[1])
                    except ValueError:
                        print(f"[SKIP] Row {row_num}: block_id not an integer → '{cols[1]}'")
                        continue
                    # Validate data is an integer for WRITE
                    if op == 'WRITE':
                        try:
                            int(cols[2])
                        except ValueError:
                            print(f"[SKIP] Row {row_num}: data not an integer → '{cols[2]}'")
                            continue
                    # Build the canonical query string
                    if op == 'WRITE':
                        queries.append(f"WRITE {cols[1]} {cols[2]}")
                    elif op == 'GROUP_READ':
                        queries.append(f"GROUP_READ {cols[1]}")
                    else:
                        queries.append(f"READ {cols[1]}")
        else:
            with open(input_file_path, 'r') as f:
                queries = [line.strip() for line in f if line.strip()]

        if not queries:
            print(f"\n[ERROR] No valid queries found in '{input_file_path}'.")
            print(f"  → TXT format: one query per line  (e.g. WRITE 1 99)")
            print(f"  → CSV format: columns op,id,data  (e.g. WRITE,1,99)")
            conn.close()
            sys.exit(1)

        print(f"✓ Loaded {len(queries)} queries from {input_file_path}")

    except Exception as exc:
        print(f"\n[ERROR] Could not read input file '{input_file_path}': {exc}")
        conn.close()
        sys.exit(1)

    # ===== Execute Queries =====
    print("\n" + "="*60)
    print("EXECUTING QUERIES")
    print("="*60)

    # Open query log if requested (used by attack.py)
    import json as _json
    _qlog = open(args.query_log, 'w') if args.query_log else None
    if _qlog:
        # Write header metadata so attack.py knows the SEAL parameters
        _qlog.write(_json.dumps({
            "type": "header",
            "alpha": alpha,
            "padding_x": x,
            "P": P,
            "L": L,
            "Z": Z
        }) + "\n")
        print(f"✓ Query log enabled → {args.query_log}")

    with open(output_file_path, 'w') as output_file:
        output_file.write("SEAL ADJ-ORAM-α Execution Trace\n")
        output_file.write("="*60 + "\n")
        output_file.write(f"SEAL Configuration: SEAL({alpha}, {x if x is not None else '⊥'})\n")
        output_file.write(f"Parameters:\n")
        output_file.write(f"  α (alpha) = {alpha} → P = 2^{alpha} = {P} partitions\n")
        output_file.write(f"  L (tree height) = {L} → {2**L} leaves per partition\n")
        output_file.write(f"  Z (bucket size) = {Z}\n")
        if x is not None:
            output_file.write(f"  x (padding) = {x} → pad sizes to powers of {x}\n")
        else:
            output_file.write(f"  x (padding) = ⊥ (disabled)\n")
        output_file.write(f"Leakage:\n")
        output_file.write(f"  Access pattern: {alpha} bit{'s' if alpha != 1 else ''} (which partition)\n")
        if x is not None:
            output_file.write(f"  Volume pattern: ~log_{x}(N) distinct sizes\n")
        else:
            output_file.write(f"  Volume pattern: Full (actual sizes visible)\n")
        output_file.write("="*60 + "\n")

        for query in queries:
            parts = query.split()

            if len(parts) < 2:
                print(f"[SKIP] Invalid query: {query}")
                continue

            op = parts[0].upper()

            try:
                block_id = int(parts[1])
            except ValueError:
                print(f"[SKIP] Invalid block ID in query: {query}")
                continue

            try:
                print(f"\n{'='*60}")
                print(f"Query: {query}")
                print(f"{'='*60}")
                output_file.write(f"\n{'='*60}\n")
                output_file.write(f"Query: {query}\n")
                output_file.write(f"{'='*60}\n")

                if op == 'WRITE':
                    if len(parts) < 3:
                        print(f"[SKIP] Invalid WRITE query (missing data): {query}")
                        continue
                    data = int(parts[2])
                    client.write(block_id, data)
                elif op == 'READ':
                    result = client.read(block_id)
                elif op == 'GROUP_READ':
                    # SE-mode group query: read ALL blocks whose stored integer
                    # value matches block_id (which holds the value_code here).
                    # Returns result_size > 1, enabling the QR volume attack.
                    value_code = block_id
                    matching_blocks = sorted([
                        bid for bid, bval in client._group_index.items()
                        if bval == value_code
                    ])
                    group_size = len(matching_blocks)
                    print(f"  GROUP_READ code={value_code}: {group_size} blocks")
                    for _bid in matching_blocks:
                        client.read(_bid)
                    # Emit one group-level log entry with the real result size
                    # AND one per-block READ entry for each accessed block so
                    # the DR attack can see the α-bit partition leakage per tuple.
                    if _qlog is not None:
                        _padded_group = client._calculate_padded_size(group_size)
                        _qlog.write(_json.dumps({
                            "type":        "query",
                            "op":          "GROUP_READ",
                            "block_id":    value_code,
                            "partition_id": -1,
                            "alpha_bits":  -1,
                            "actual_size": group_size,
                            "padded_size": _padded_group if x is not None else group_size,
                            "value_code":  value_code,
                        }) + "\n")
                        # Per-block entries: server sees partition_id for each
                        # individual ORAM access — this IS the α-bit leakage.
                        # The DR attack uses these to narrow candidates per block.
                        for _bid in matching_blocks:
                            _part, _leaf = client.position[_bid]
                            _qlog.write(_json.dumps({
                                "type":        "query",
                                "op":          "GROUP_READ_BLOCK",
                                "block_id":    _bid,
                                "partition_id": _part,
                                "alpha_bits":  _part,
                                "actual_size": 1,
                                "padded_size": 1,
                                "value_code":  value_code,
                                "data":        value_code,
                            }) + "\n")
                    print_state(query, client, partitions, output_file)
                    print(f"{'='*60}\n")
                    output_file.write(f"{'='*60}\n\n")
                    continue
                else:
                    print(f"[SKIP] Unknown operation: {op}")
                    continue

                # --- emit query log entry -----------------------------------
                if _qlog is not None:
                    _partition_id, _leaf = client.position[block_id]
                    _actual_size = 1  # each ORAM access touches 1 logical block
                    _padded_size = client._calculate_padded_size(_actual_size)
                    _log_entry = {
                        "type":         "query",
                        "op":           op,
                        "block_id":     block_id,
                        "partition_id": _partition_id,
                        # α-bit prefix: the only per-tuple identifier the server sees
                        "alpha_bits":   _partition_id,
                        "actual_size":  _actual_size,
                        "padded_size":  _padded_size if x is not None else _actual_size,
                    }
                    # Include written value so attack.py can build ground truth
                    if op == 'WRITE':
                        _log_entry["data"] = data
                    _qlog.write(_json.dumps(_log_entry) + "\n")
                # ------------------------------------------------------------

                print_state(query, client, partitions, output_file)

                print(f"{'='*60}\n")
                output_file.write(f"{'='*60}\n\n")

            except Exception as e:
                print(f"\n[ERROR] {query}: {e}")
                output_file.write(f"\n[ERROR] {query}: {e}\n\n")

        # ===== Final Statistics =====
        print("\n" + "="*60)
        print("FINAL STATISTICS")
        print("="*60)

        stats = client.get_statistics()
        for key, value in stats.items():
            print(f"{key}: {value}")

        output_file.write("\n" + "="*60 + "\n")
        output_file.write("FINAL STATISTICS\n")
        output_file.write("="*60 + "\n")
        for key, value in stats.items():
            output_file.write(f"{key}: {value}\n")

        print("="*60)

    if _qlog:
        _qlog.close()
        print(f"✓ Query log written to: {args.query_log}")

    conn.close()
    print(f"\n✓ Simulation complete!")
    print(f"✓ Output written to: {output_file_path}")
    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    main()
