#!/usr/bin/env python3
"""
PathORAM Implementation - Refactored with Strict Client-Server Separation
Based on "Path ORAM: An Extremely Simple Oblivious RAM Protocol" by Stefanov et al.

This version enforces proper memory separation between Server and Client.
"""

import random
import math
from typing import Dict, List, Tuple, Optional


class Server:
    """
    Server class - Dumb storage with NO ORAM logic.
    Just stores encrypted buckets and responds to read/write requests.
    """
    
    def __init__(self, L: int, Z: int):
        """
        Initialize server storage.
        
        Args:
            L: Tree height (levels 0 to L)
            Z: Bucket size (number of blocks per bucket)
        """
        self.L = L
        self.Z = Z
        
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
    Client class - Holds position map and stash, executes Path ORAM protocol.
    """
    
    def __init__(self, server: Server, L: int):
        """
        Initialize client.
        
        Args:
            server: Server instance to interact with
            L: Tree height
        """
        self.server = server
        self.L = L
        self.Z = server.Z
        
        # Calculate leaf parameters
        self.num_leaves = 2 ** L
        
        # Position map: block_id -> leaf_id (in range [0, num_leaves-1])
        self.position: Dict[int, int] = {}
        
        # Stash: temporary storage for blocks during access
        self.stash: Dict[int, int] = {}
        
        # Statistics
        self.read_count = 0
        self.write_count = 0
        self.access_count = 0
        self.max_stash_size = 0
    
    def _path_node(self, leaf: int, level: int) -> int:
        """
        Get the bucket ID on the path to 'leaf' at 'level'.
        Level 0 is root, level L is leaf.
        
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
        Access operation (read or write).
        
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
            # First access to this block - assign random leaf
            self.position[block_id] = random.randint(0, self.num_leaves - 1)
            # Initialize with default data (0) if reading for first time
            if op == 'read':
                self.stash[block_id] = 0
        
        x = self.position[block_id]  # Current leaf assignment
        
        # Step 2: Remap to new random leaf immediately
        self.position[block_id] = random.randint(0, self.num_leaves - 1)
        
        # Step 3: Read path from root to leaf x
        path = self._get_path(x)
        
        # Store mid-query stash for visualization (before reading from server)
        mid_query_stash_before_read = self.stash.copy()
        
        for bucket_id in path:
            blocks = self.server.read_bucket(bucket_id)
            for blk_id, blk_data in blocks:
                # Only add real blocks to stash (ignore dummies with negative IDs)
                if blk_id >= 0:
                    self.stash[blk_id] = blk_data
        
        # Store mid-query stash for display (after reading path)
        self.mid_query_stash = self.stash.copy()
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
        for level in range(self.L, -1, -1):
            bucket_id = self._path_node(x, level)
            
            # Select blocks that can go in this bucket
            eligible_blocks = []
            for blk_id, blk_data in self.stash.items():
                if self._on_path(self.position[blk_id], x, level):
                    eligible_blocks.append((blk_id, blk_data))
            
            # Take up to Z blocks
            selected = eligible_blocks[:self.Z]
            
            # Remove selected blocks from stash
            for blk_id, _ in selected:
                del self.stash[blk_id]
            
            # Pad with dummy blocks to reach Z blocks
            blocks_to_write = selected.copy()
            num_dummies_needed = self.Z - len(blocks_to_write)
            for i in range(num_dummies_needed):
                dummy_id = -(i + 1)
                dummy_data = -(i + 1)
                blocks_to_write.append((dummy_id, dummy_data))
            
            # Write bucket back to server
            self.server.write_bucket(bucket_id, blocks_to_write)
        
        # Update statistics
        self.max_stash_size = max(self.max_stash_size, len(self.stash))
        
        return result_data
    
    def read(self, block_id: int) -> int:
        """Read a block."""
        return self.access('read', block_id)
    
    def write(self, block_id: int, data: int):
        """Write a block."""
        self.access('write', block_id, data)
    
    def get_position_map(self) -> Dict[int, int]:
        """Get position map for visualization."""
        return self.position.copy()
    
    def get_stash(self) -> Dict[int, int]:
        """Get stash for visualization."""
        return self.stash.copy()
    
    def get_mid_query_stash(self) -> Tuple[Dict[int, int], int]:
        """Get mid-query stash (after reading path, before write-back)."""
        if hasattr(self, 'mid_query_stash'):
            return self.mid_query_stash.copy(), self.mid_query_leaf
        return {}, -1
    
    def get_statistics(self) -> Dict:
        """Get statistics."""
        return {
            'total_accesses': self.access_count,
            'total_reads': self.read_count,
            'total_writes': self.write_count,
            'max_stash_size': self.max_stash_size,
            'current_stash_size': len(self.stash),
            'tree_height': self.L,
            'num_leaves': self.num_leaves,
            'Z': self.Z
        }


def print_state(query: str, client: Client, server: Server, output_file):
    """Print current state after a query."""
    
    # Position Map
    print("\nClient Position Map (block_id -> leaf_id):")
    pos_map = client.get_position_map()
    if pos_map:
        for block_id in sorted(pos_map.keys()):
            leaf_id = pos_map[block_id]
            print(f"  Block {block_id} -> Leaf {leaf_id}")
    else:
        print("  (empty)")
    
    # Stash (after operation completes)
    print("\nClient Stash (after operation):")
    stash = client.get_stash()
    if stash:
        for block_id in sorted(stash.keys()):
            data = stash[block_id]
            print(f"  Block {block_id}: data={data}")
    else:
        print("  (empty)")
    
    # Mid-Query Stash (after reading path, before write-back)
    mid_stash, mid_leaf = client.get_mid_query_stash()
    if mid_leaf >= 0:
        print(f"\nMid-Query Stash (after reading path to leaf {mid_leaf}):")
        if mid_stash:
            for block_id in sorted(mid_stash.keys()):
                data = mid_stash[block_id]
                print(f"  Block {block_id}: data={data}")
        else:
            print("  (empty)")
    
    # Server Tree
    print("\nServer Tree Structure:")
    tree = server.get_tree_snapshot()
    
    for bucket_id in range(server.total_buckets):
        blocks = tree.get(bucket_id, [])
        
        # Separate real blocks from dummy blocks
        real_blocks = [(bid, data) for bid, data in blocks if bid >= 0]
        dummy_blocks = [(bid, data) for bid, data in blocks if bid < 0]
        
        # Format bucket contents
        if real_blocks:
            block_strs = [f"({blk_id},{data})" for blk_id, data in real_blocks]
            content = ", ".join(block_strs)
        else:
            content = ""
        
        # Add dummy blocks indicator
        if dummy_blocks:
            dummy_str = f"{len(dummy_blocks)} dummy blocks"
            if content:
                content += " + " + dummy_str
            else:
                content = dummy_str
        
        # Show what the dummies are (only if no real blocks)
        if dummy_blocks and len(real_blocks) == 0:
            dummy_details = ", ".join([f"({bid},{data})" for bid, data in dummy_blocks])
            content += f" [{dummy_details}]"
        
        print(f"  Bucket {bucket_id}: [{content}]")
    
    # Write to output file
    output_file.write("\nClient Position Map:\n")
    if pos_map:
        for block_id in sorted(pos_map.keys()):
            output_file.write(f"  Block {block_id} -> Leaf {pos_map[block_id]}\n")
    else:
        output_file.write("  (empty)\n")
    
    output_file.write("\nClient Stash:\n")
    if stash:
        for block_id in sorted(stash.keys()):
            output_file.write(f"  Block {block_id}: data={stash[block_id]}\n")
    else:
        output_file.write("  (empty)\n")
    
    # Mid-Query Stash
    mid_stash, mid_leaf = client.get_mid_query_stash()
    if mid_leaf >= 0:
        output_file.write(f"\nMid-Query Stash (after reading path to leaf {mid_leaf}):\n")
        if mid_stash:
            for block_id in sorted(mid_stash.keys()):
                output_file.write(f"  Block {block_id}: data={mid_stash[block_id]}\n")
        else:
            output_file.write("  (empty)\n")
    
    output_file.write("\nServer Tree:\n")
    for bucket_id in range(server.total_buckets):
        blocks = tree.get(bucket_id, [])
        
        real_blocks = [(bid, data) for bid, data in blocks if bid >= 0]
        dummy_blocks = [(bid, data) for bid, data in blocks if bid < 0]
        
        if real_blocks:
            block_strs = [f"({blk_id},{data})" for blk_id, data in real_blocks]
            content = ", ".join(block_strs)
        else:
            content = ""
        
        if dummy_blocks:
            dummy_str = f"{len(dummy_blocks)} dummy blocks"
            if content:
                content += " + " + dummy_str
            else:
                content = dummy_str
        
        if dummy_blocks and len(real_blocks) == 0:
            dummy_details = ", ".join([f"({bid},{data})" for bid, data in dummy_blocks])
            content += f" [{dummy_details}]"
        
        output_file.write(f"  Bucket {bucket_id}: [{content}]\n")


def main():
    """Main function to run PathORAM with strict Server/Client separation."""
    print("PathORAM Simulation - Strict Client-Server Separation")
    print("="*50)
    
    # Configuration - STRICT L=2
    L = 2   # Tree height (fixed)
    Z = 4   # Blocks per bucket
    
    # Create Server
    server = Server(L=L, Z=Z)
    
    # Create Client (linked to server)
    client = Client(server=server, L=L)
    
    print(f"Configuration:")
    print(f"  Server: Binary tree with L={L}, Z={Z}")
    print(f"  Total buckets: {server.total_buckets}")
    print(f"  Leaf buckets: {client.num_leaves} (indices {2**L - 1} to {server.total_buckets - 1})")
    print(f"  Client: Position map + Stash")
    print(f"  Block IDs: ANY positive integer allowed (no artificial limit)")
    
    # Read queries from input file
    try:
        with open('input.txt', 'r') as f:
            queries = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("\nNo input.txt found. Creating sample input file...")
        with open('input.txt', 'w') as f:
            f.write("WRITE 1 99\n")
            f.write("READ 1\n")
            f.write("WRITE 2 42\n")
            f.write("WRITE 3 77\n")
            f.write("READ 2\n")
            f.write("WRITE 100 500\n")  # High block ID - now allowed!
            f.write("READ 100\n")
            f.write("WRITE 1 100\n")
            f.write("READ 3\n")
        with open('input.txt', 'r') as f:
            queries = [line.strip() for line in f if line.strip()]
    
    # Open output file
    with open('output.txt', 'w') as output_file:
        output_file.write("PathORAM Execution Trace - Strict Client-Server Separation\n")
        output_file.write("="*50 + "\n")
        output_file.write(f"Configuration: L={L}, Z={Z}\n")
        output_file.write(f"Block IDs: ANY positive integer allowed\n")
        output_file.write("="*50 + "\n")
        
        # Execute each query
        for query in queries:
            parts = query.split()
            
            if len(parts) < 2:
                print(f"Invalid query: {query}")
                continue
            
            op = parts[0].upper()
            
            try:
                block_id = int(parts[1])
            except ValueError:
                print(f"Invalid block ID in query: {query}")
                continue
            
            try:
                # ===== QUERY START MARKER =====
                print(f"\n{'='*50}")
                print(f"Query: {query}")
                print(f"{'='*50}")
                output_file.write(f"\n{'='*50}\n")
                output_file.write(f"Query: {query}\n")
                output_file.write(f"{'='*50}\n")
                
                if op == 'WRITE':
                    if len(parts) < 3:
                        print(f"Invalid WRITE query (missing data): {query}")
                        continue
                    data = int(parts[2])
                    client.write(block_id, data)
                elif op == 'READ':
                    result = client.read(block_id)
                else:
                    print(f"Unknown operation: {op}")
                    continue
                
                # Print state after query
                print_state(query, client, server, output_file)
                
                # ===== QUERY END MARKER =====
                print(f"{'='*50}\n")
                output_file.write(f"{'='*50}\n\n")
                
            except Exception as e:
                print(f"\n[ERROR] {query}: {e}")
                output_file.write(f"\n[ERROR] {query}: {e}\n\n")
        
        # Print final statistics
        print("\n" + "="*50)
        stats = client.get_statistics()
        print("\n=== Client Statistics ===")
        for key, value in stats.items():
            print(f"{key}: {value}")
        print("="*50)
        
        output_file.write("\n" + "="*50 + "\n")
        output_file.write("Final Statistics:\n")
        for key, value in stats.items():
            output_file.write(f"  {key}: {value}\n")
    
    print(f"\n{'='*50}")
    print("Simulation complete. Output written to output.txt")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
