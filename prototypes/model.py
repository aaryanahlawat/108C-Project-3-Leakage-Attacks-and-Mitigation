#!/usr/bin/env python3
"""
SEAL (Searchable Encryption with Adjustable Leakage) Implementation
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
"""

import random
import math
import argparse
from typing import Dict, List, Tuple, Optional


class Server:
    """
    Server class - Dumb storage with NO ORAM logic.
    Just stores encrypted buckets and responds to read/write requests.
    
    Each Server instance represents a single ORAM tree partition.
    """
    
    def __init__(self, L: int, Z: int, partition_id: int):
        """
        Initialize server storage for a single partition.
        
        Args:
            L: Tree height (levels 0 to L)
            Z: Bucket size (number of blocks per bucket)
            partition_id: Identifier for this partition
        """
        self.L = L
        self.Z = Z
        self.partition_id = partition_id
        
        # Calculate total number of buckets in binary tree
        self.total_buckets = 2 ** (L + 1) - 1
        
        # Initialize tree with dummy blocks
        # tree[bucket_id] = list of (block_id, data) tuples
        self.tree: Dict[int, List[Tuple[int, int]]] = {}
        
        # Fill all buckets with dummy blocks (negative IDs)
        for bucket_id in range(self.total_buckets):
            dummy_blocks = []
            for i in range(Z):
                dummy_id = -(i + 1)
                dummy_data = -(i + 1)
                dummy_blocks.append((dummy_id, dummy_data))
            self.tree[bucket_id] = dummy_blocks
    
    def read_bucket(self, bucket_id: int) -> List[Tuple[int, int]]:
        """
        Read and return a bucket.
        
        Args:
            bucket_id: Index of bucket to read
            
        Returns:
            List of (block_id, data) tuples (always Z blocks)
        """
        if bucket_id < 0 or bucket_id >= self.total_buckets:
            raise ValueError(f"Invalid bucket_id: {bucket_id}")
        
        return self.tree[bucket_id].copy()
    
    def write_bucket(self, bucket_id: int, blocks: List[Tuple[int, int]]):
        """
        Write blocks to a bucket.
        
        Args:
            bucket_id: Index of bucket to write
            blocks: List of (block_id, data) tuples (must be exactly Z blocks)
        """
        if bucket_id < 0 or bucket_id >= self.total_buckets:
            raise ValueError(f"Invalid bucket_id: {bucket_id}")
        
        if len(blocks) != self.Z:
            raise ValueError(f"Must write exactly {self.Z} blocks, got {len(blocks)}")
        
        self.tree[bucket_id] = blocks.copy()
    
    def get_tree_snapshot(self) -> Dict[int, List[Tuple[int, int]]]:
        """Get complete tree state for visualization (debugging only)."""
        return {bucket_id: blocks.copy() for bucket_id, blocks in self.tree.items()}


class Client:
    """
    Client class for SEAL's ADJ-ORAM-α implementation.
    
    Manages multiple Server partitions and implements the adjustable leakage protocol.
    The position map now tracks (partition_id, leaf_id) for each block.
    """
    
    def __init__(self, partitions: Dict[int, Server], L: int, P: int, padding_x: Optional[int] = None):
        """
        Initialize client with multiple server partitions.
        
        Args:
            partitions: Dictionary of partition_id -> Server instance
            L: Tree height for each partition
            P: Number of partitions (controls leakage parameter alpha)
            padding_x: ADJ-PADDING-x parameter (None for no padding)
        """
        self.partitions = partitions
        self.L = L
        self.P = P
        self.padding_x = padding_x
        self.Z = next(iter(partitions.values())).Z  # All partitions have same Z
        
        # Calculate leaf parameters
        self.num_leaves = 2 ** L
        
        # Position map: block_id -> (partition_id, leaf_id)
        # This is the key difference from standard Path ORAM
        self.position: Dict[int, Tuple[int, int]] = {}
        
        # Stash: temporary storage for blocks during access
        self.stash: Dict[int, int] = {}
        
        # Track result sizes for padding (if enabled)
        self.result_sizes: Dict[int, int] = {}  # block_id -> actual result size
        
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
        
        Args:
            actual_size: Actual result size
            
        Returns:
            Padded size (power of x)
        """
        if self.padding_x is None or actual_size == 0:
            return actual_size
        
        # Find smallest i such that x^(i-1) < actual_size <= x^i
        import math
        i = math.ceil(math.log(actual_size, self.padding_x))
        padded = self.padding_x ** i
        
        return padded
    
    def _path_node(self, leaf: int, level: int) -> int:
        """
        Get the bucket ID on the path to 'leaf' at 'level'.
        Level 0 is root, level L is leaf.
        
        This is the core Path ORAM math - unchanged from standard Path ORAM.
        
        Args:
            leaf: Leaf index (0 to num_leaves-1)
            level: Level in tree (0 to L)
            
        Returns:
            Bucket ID at that level on the path
        """
        if level == 0:
            return 0  # Root
        
        # Shift right to get ancestor at this level
        node = leaf >> (self.L - level)
        # Add offset for this level
        return (1 << level) - 1 + node
    
    def _get_path(self, leaf: int) -> List[int]:
        """
        Get all bucket IDs from root to leaf.
        
        Args:
            leaf: Leaf index
            
        Returns:
            List of bucket IDs from root to leaf
        """
        return [self._path_node(leaf, y) for y in range(self.L + 1)]
    
    def _on_path(self, block_leaf: int, path_leaf: int, level: int) -> bool:
        """
        Check if block assigned to block_leaf can be placed at level on path to path_leaf.
        
        Args:
            block_leaf: Leaf where block is assigned
            path_leaf: Leaf of the path being written
            level: Level in the tree
            
        Returns:
            True if the paths intersect at this level
        """
        return self._path_node(block_leaf, level) == self._path_node(path_leaf, level)
    
    def access(self, op: str, block_id: int, data: Optional[int] = None) -> Optional[int]:
        """
        SEAL access operation with adjustable leakage.
        
        The key difference from standard Path ORAM:
        1. Position map stores (partition_id, leaf_id) instead of just leaf_id
        2. Access is routed to a specific partition based on position map
        3. Server observes which partition is accessed (this is the leakage!)
        
        Args:
            op: 'read' or 'write'
            block_id: ID of block to access (ANY positive integer allowed)
            data: Data to write (only for write operations)
            
        Returns:
            Data read from block (for read operations)
        """
        self.access_count += 1
        
        if op == 'read':
            self.read_count += 1
        else:
            self.write_count += 1
        
        # Step 1: Get current position (or assign random position if first access)
        if block_id not in self.position:
            # First access to this block - assign random partition AND random leaf
            partition_id = random.randint(0, self.P - 1)
            leaf_id = random.randint(0, self.num_leaves - 1)
            self.position[block_id] = (partition_id, leaf_id)
            # Initialize with default data (0) if reading for first time
            if op == 'read':
                self.stash[block_id] = 0
        
        partition_id, x = self.position[block_id]  # Current partition and leaf
        
        # ============================================================
        # SEAL LEAKAGE: Server observes which partition is accessed
        # This is the adjustable leakage - trading privacy for performance
        # ============================================================
        print(f"[SEAL LEAKAGE] Server observes access to Partition ID: {partition_id}")
        
        # Step 2: Remap to new random leaf in THE SAME PARTITION
        # Note: In this simplified SEAL implementation, partition_id stays fixed
        # The leaf_id is re-randomized after every access
        new_leaf_id = random.randint(0, self.num_leaves - 1)
        self.position[block_id] = (partition_id, new_leaf_id)
        
        # Step 3: Read path from the specific partition
        server = self.partitions[partition_id]
        path = self._get_path(x)
        
        for bucket_id in path:
            blocks = server.read_bucket(bucket_id)
            for blk_id, blk_data in blocks:
                # Only add real blocks to stash (ignore dummies with negative IDs)
                if blk_id >= 0:
                    self.stash[blk_id] = blk_data
        
        # Store mid-query stash for visualization
        self.mid_query_stash = self.stash.copy()
        self.mid_query_partition = partition_id
        self.mid_query_leaf = x
        
        # Step 4: Access the block
        if block_id not in self.stash:
            # Block doesn't exist yet, initialize with 0
            self.stash[block_id] = 0
        
        result_data = self.stash[block_id]
        
        # Step 5: If write, update the block in stash
        if op == 'write':
            if data is None:
                raise ValueError("Write operation requires data")
            self.stash[block_id] = data
            result_data = data
        
        # Step 6: Write back path (from leaf to root) with greedy eviction
        # This is identical to standard Path ORAM
        for level in range(self.L, -1, -1):
            bucket_id = self._path_node(x, level)
            
            # Select blocks that can go in this bucket
            eligible_blocks = []
            for blk_id in list(self.stash.keys()):
                blk_leaf = self.position[blk_id][1]  # Get leaf_id from (partition, leaf) tuple
                if self._on_path(blk_leaf, x, level):
                    eligible_blocks.append(blk_id)
            
            # Greedy selection: take min(Z, len(eligible)) blocks
            selected = eligible_blocks[:self.Z]
            
            # Build bucket: selected blocks + dummies to reach size Z
            bucket_blocks = []
            for blk_id in selected:
                bucket_blocks.append((blk_id, self.stash[blk_id]))
                del self.stash[blk_id]
            
            # Pad with dummies
            while len(bucket_blocks) < self.Z:
                dummy_id = -(len(bucket_blocks) + 1)
                dummy_data = -(len(bucket_blocks) + 1)
                bucket_blocks.append((dummy_id, dummy_data))
            
            # Write bucket to the specific partition
            server.write_bucket(bucket_id, bucket_blocks)
        
        # Update max stash size
        self.max_stash_size = max(self.max_stash_size, len(self.stash))
        
        return result_data
    
    def read(self, block_id: int) -> int:
        """Read operation wrapper."""
        result = self.access('read', block_id)
        
        if self.padding_x is not None:
            # Demonstrate volume pattern protection
            actual_size = 1  # Reading 1 block
            padded_size = self._calculate_padded_size(actual_size)
            print(f"READ result: Block {block_id} = {result}")
            print(f"  [Volume Protection] Actual: 1 block, Padded to: {padded_size} (power of {self.padding_x})")
        else:
            print(f"READ result: Block {block_id} = {result}")
        
        return result
    
    def write(self, block_id: int, data: int):
        """Write operation wrapper."""
        self.access('write', block_id, data)
        
        if self.padding_x is not None:
            actual_size = 1
            padded_size = self._calculate_padded_size(actual_size)
            print(f"WRITE complete: Block {block_id} = {data}")
            print(f"  [Volume Protection] Actual: 1 block, Padded to: {padded_size} (power of {self.padding_x})")
        else:
            print(f"WRITE complete: Block {block_id} = {data}")
    
    def get_position_map(self) -> Dict[int, Tuple[int, int]]:
        """Get position map for visualization."""
        return self.position.copy()
    
    def get_stash(self) -> Dict[int, int]:
        """Get stash for visualization."""
        return self.stash.copy()
    
    def get_mid_query_stash(self) -> Tuple[Dict[int, int], int, int]:
        """Get mid-query stash state (partition, leaf)."""
        return self.mid_query_stash.copy(), self.mid_query_partition, self.mid_query_leaf
    
    def get_statistics(self) -> Dict[str, int]:
        """Get client statistics."""
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


def print_state(query: str, client: Client, partitions: Dict[int, Server], output_file):
    """
    Print complete system state after a query, including all partitions.
    
    Args:
        query: The query that was just executed
        client: Client instance
        partitions: Dictionary of Server partitions
        output_file: File handle for output
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
            
            # Format all blocks in their actual order (real and dummy together)
            content = ", ".join([f"({blk_id}, {data})" for blk_id, data in blocks])
            
            print(f"  Bucket {bucket_id}: [{content}]")
            output_file.write(f"  Bucket {bucket_id}: [{content}]\n")


def parse_arguments():
    """
    Parse command-line arguments using argparse.
    
    Returns:
        argparse.Namespace: Parsed arguments containing:
            - input_file: Path to input query file
            - output_file: Path to output trace file
            - alpha: ADJ-ORAM-α leakage parameter (controls partitions)
            - tree_height: L parameter (tree height/levels)
            - padding: x parameter (ADJ-PADDING-x for volume pattern)
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
  python seal_oram.py input.txt output.txt -a 0
  
  # SEAL with 1 bit access pattern leakage (α=1, P=2)
  python seal_oram.py input.txt output.txt -a 1
  
  # Custom tree height (deeper trees, more bandwidth)
  python seal_oram.py input.txt output.txt -a 1 -l 4
  
  # Add volume pattern protection (pad to powers of 4)
  python seal_oram.py input.txt output.txt -a 1 -x 4
  
  # Full SEAL: access + volume protection
  python seal_oram.py input.txt output.txt -a 2 -l 3 -x 2

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
    
    # Optional arguments
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
        help='Tree height/levels L (default: 2). Each partition has 2^L leaf buckets. Higher L = more capacity but slower.'
    )
    
    parser.add_argument(
        '-x', '--padding',
        type=int,
        default=None,
        metavar='x',
        help='ADJ-PADDING-x parameter (optional). Pads result sizes to powers of x. Higher x = less volume leakage but more overhead. If not set, no padding applied (x=⊥).'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Calculate partitions from alpha
    args.partitions = 2 ** args.alpha
    
    # Validation
    if args.alpha < 0:
        parser.error("Alpha must be non-negative (α ≥ 0)")
    
    if args.tree_height < 1:
        parser.error("Tree height must be at least 1 (L ≥ 1)")
    
    if args.tree_height > 20:
        parser.error(f"Tree height too large (L={args.tree_height}). Practical maximum is around L=20. Use L≤10 for demonstrations.")
    
    if args.padding is not None:
        if args.padding < 2:
            parser.error("Padding parameter must be at least 2 (x ≥ 2) or omit for no padding")
    
    return args


def main():
    """Main function to run SEAL ADJ-ORAM simulation."""
    
    # ===== Parse Command Line Arguments =====
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
    
    # ===== Configuration =====
    Z = 4   # Blocks per bucket (fixed for this demo)
    
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
    
    # ===== Create Server Partitions =====
    partitions = {}
    for partition_id in range(P):
        partitions[partition_id] = Server(L=L, Z=Z, partition_id=partition_id)
    
    print(f"\n✓ Created {P} server partitions (independent ORAM trees)")
    
    # ===== Create Client =====
    client = Client(partitions=partitions, L=L, P=P, padding_x=x)
    print(f"✓ Client initialized with position map tracking (partition_id, leaf_id)")
    if x is not None:
        print(f"✓ Volume pattern protection enabled (ADJ-PADDING-{x})")
    
    # ===== Read Queries from Input File =====
    try:
        with open(input_file_path, 'r') as f:
            queries = [line.strip() for line in f if line.strip()]
        print(f"✓ Loaded {len(queries)} queries from {input_file_path}")
    except FileNotFoundError:
        print(f"\n[ERROR] Input file '{input_file_path}' not found!")
        print("\nCreating sample input file at 'sample_input.txt'...")
        with open('sample_input.txt', 'w') as f:
            f.write("WRITE 1 99\n")
            f.write("READ 1\n")
            f.write("WRITE 2 42\n")
            f.write("WRITE 3 77\n")
            f.write("READ 2\n")
            f.write("WRITE 100 500\n")
            f.write("READ 100\n")
            f.write("WRITE 1 100\n")
            f.write("READ 3\n")
        print("✓ Sample input file created at 'sample_input.txt'")
        print("\nPlease run again with: python seal_oram.py sample_input.txt output.txt")
        sys.exit(1)
    
    # ===== Execute Queries =====
    print("\n" + "="*60)
    print("EXECUTING QUERIES")
    print("="*60)
    
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
                # ===== QUERY START MARKER =====
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
                else:
                    print(f"[SKIP] Unknown operation: {op}")
                    continue
                
                # Print state after query
                print_state(query, client, partitions, output_file)
                
                # ===== QUERY END MARKER =====
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
    
    print(f"\n✓ Simulation complete!")
    print(f"✓ Output written to: {output_file_path}")
    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    main()
