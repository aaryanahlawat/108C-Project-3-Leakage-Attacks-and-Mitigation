import random
import math
import csv
import json
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict

class PathORAM:
    def __init__(self, N: int, Z: int = 4, block_size: int = 256):
        """
        Initialize PathORAM structure.
        
        Args:
            N: Number of data blocks
            Z: Number of blocks per bucket (typically 4)
            block_size: Size of each block in bytes
        """
        self.N = N  # Number of blocks
        self.Z = Z  # Blocks per bucket
        self.block_size = block_size
        
        # Calculate tree height (L levels: 0 to L)
        self.L = math.ceil(math.log2(N)) if N > 0 else 0
        self.num_leaves = 2 ** self.L
        
        # Position map: maps block_id -> leaf_id
        self.position = {}
        
        # Stash: temporary storage for blocks
        # Format: {block_id: data}
        self.stash: Dict[int, bytes] = {}
        
        # Server storage: binary tree
        # Format: tree[bucket_id] = list of (block_id, data) tuples
        self.tree: Dict[int, List[Tuple[int, bytes]]] = defaultdict(list)
        
        # Statistics
        self.read_count = 0
        self.write_count = 0
        self.total_blocks_read = 0
        self.total_blocks_written = 0
        self.max_stash_size = 0
        
    def initialize_with_data(self, data_blocks: Dict[int, bytes]):
        """
        Initialize PathORAM with existing data blocks.
        
        Args:
            data_blocks: Dictionary mapping block_id -> data
        """
        print(f"Initializing PathORAM with {len(data_blocks)} blocks...")
        
        # Assign each block to a random leaf
        for block_id in data_blocks.keys():
            self.position[block_id] = random.randint(0, self.num_leaves - 1)
        
        # Place blocks in the tree
        for block_id, data in data_blocks.items():
            leaf = self.position[block_id]
            # Place at root initially
            bucket_id = self._path_node(leaf, 0)
            if len(self.tree[bucket_id]) < self.Z:
                self.tree[bucket_id].append((block_id, data))
            else:
                # If root is full, put in stash
                self.stash[block_id] = data
        
        print(f"Initialization complete. Tree height: {self.L}, Leaves: {self.num_leaves}")
        
    def _path_node(self, leaf: int, level: int) -> int:
        """
        Get the bucket ID on the path to 'leaf' at 'level'.
        Level 0 is root, level L is leaf.
        
        Bucket numbering: root = 0, left child = 1, right child = 2, etc.
        """
        if level == 0:
            return 0  # Root
        
        # Shift right to get ancestor at this level
        # At level y, we look at the top y bits of the leaf
        # The leaf number's bits tell you LEFT (0) or RIGHT (1) at each level. 
        node = leaf >> (self.L - level)
        # Add offset for this level (2^level - 1)
        # This calculates how many buckets exist at this level and exist in ALL PREVIOUS LEVELS (the offset),
        # adding which bucket within this level (node)
        return (1 << level) - 1 + node
    
    def _get_path(self, leaf: int) -> List[int]:
        """Get all bucket IDs from root to leaf."""
        return [self._path_node(leaf, y) for y in range(self.L + 1)]
    
    def _read_bucket(self, bucket_id: int) -> List[Tuple[int, bytes]]:
        """Read a bucket from the server."""
        self.total_blocks_read += len(self.tree[bucket_id])
        blocks = self.tree[bucket_id].copy()
        self.tree[bucket_id] = []  # Clear bucket after reading
        return blocks
    
    def _write_bucket(self, bucket_id: int, blocks: List[Tuple[int, bytes]]):
        """Write blocks to a bucket on the server."""
        self.total_blocks_written += len(blocks)
        self.tree[bucket_id] = blocks[:self.Z]  # Ensure we don't exceed Z blocks
    
    def _on_path(self, block_leaf: int, path_leaf: int, level: int) -> bool:
        """
        Check if block assigned to block_leaf can be placed at level on path to path_leaf.
        """
        return self._path_node(block_leaf, level) == self._path_node(path_leaf, level)
    
    def access(self, op: str, block_id: int, data: Optional[bytes] = None) -> Optional[bytes]:
        """
        Access operation (read or write).
        
        Args:
            op: 'read' or 'write'
            block_id: ID of block to access
            data: Data to write (only for write operations)
            
        Returns:
            Data read from block (for read operations)
        """
        if op == 'read':
            self.read_count += 1
        else:
            self.write_count += 1
        
        # Step 1-2: Get current position and assign new random position
        if block_id not in self.position:
            raise ValueError(f"Block {block_id} not found in position map")
        
        x = self.position[block_id]  # Current leaf assignment
        self.position[block_id] = random.randint(0, self.num_leaves - 1)  # New random leaf
        
        # Step 3-5: Read path from root to leaf x
        path = self._get_path(x)
        for bucket_id in path:
            blocks = self._read_bucket(bucket_id)
            for blk_id, blk_data in blocks:
                self.stash[blk_id] = blk_data
        
        # Step 6: Read block from stash
        if block_id not in self.stash:
            raise ValueError(f"Block {block_id} not found in stash after reading path")
        
        result_data = self.stash[block_id]
        
        # Step 7-9: If write, update the block in stash
        if op == 'write':
            if data is None:
                raise ValueError("Write operation requires data")
            self.stash[block_id] = data
            result_data = data
        
        # Step 10-15: Write back blocks to path (from leaf to root)
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
            
            # Write to bucket
            self._write_bucket(bucket_id, selected)
        
        # Update statistics
        self.max_stash_size = max(self.max_stash_size, len(self.stash))
        
        return result_data
    
    def read(self, block_id: int) -> bytes:
        """Read a block."""
        return self.access('read', block_id)
    
    def write(self, block_id: int, data: bytes):
        """Write a block."""
        self.access('write', block_id, data)
    
    def get_statistics(self) -> Dict:
        """Get statistics about ORAM operations."""
        return {
            'total_reads': self.read_count,
            'total_writes': self.write_count,
            'total_blocks_read': self.total_blocks_read,
            'total_blocks_written': self.total_blocks_written,
            'max_stash_size': self.max_stash_size,
            'current_stash_size': len(self.stash),
            'tree_height': self.L,
            'num_leaves': self.num_leaves,
            'Z': self.Z
        }
    
    def print_statistics(self):
        """Print statistics."""
        stats = self.get_statistics()
        print("\n=== PathORAM Statistics ===")
        for key, value in stats.items():
            print(f"{key}: {value}")
        print("===========================\n")


def load_csv_data(filename: str, max_blocks: Optional[int] = None) -> Dict[int, bytes]:
    """
    Load data from CSV file into blocks.
    
    Args:
        filename: Path to CSV file
        max_blocks: Maximum number of blocks to load (None for all)
        
    Returns:
        Dictionary mapping block_id -> serialized data
    """
    data_blocks = {}
    
    with open(filename, 'r') as f:
        reader = csv.reader(f)
        headers = next(reader)  # Get headers
        
        for idx, row in enumerate(reader):
            if max_blocks and idx >= max_blocks:
                break
            
            # Create a dictionary for this row
            row_data = {headers[i]: row[i] for i in range(len(headers))}
            
            # Serialize to JSON bytes
            serialized = json.dumps(row_data).encode('utf-8')
            
            data_blocks[idx] = serialized
    
    return data_blocks


def deserialize_block(data: bytes) -> Dict:
    """Deserialize a block back to dictionary."""
    return json.loads(data.decode('utf-8'))


# Test functions
def test_basic_operations():
    """Test basic read/write operations."""
    print("\n=== Test 1: Basic Operations ===")
    
    # Create small ORAM with 8 blocks
    oram = PathORAM(N=8, Z=4)
    
    # Create test data
    test_data = {}
    for i in range(8):
        data = json.dumps({'id': i, 'value': f'data_{i}'}).encode('utf-8')
        test_data[i] = data
    
    # Initialize
    oram.initialize_with_data(test_data)
    
    # Test reads
    print("Reading blocks...")
    for i in range(3):
        result = oram.read(i)
        result_dict = deserialize_block(result)
        print(f"Block {i}: {result_dict}")
    
    # Test writes
    print("\nWriting blocks...")
    new_data = json.dumps({'id': 0, 'value': 'UPDATED_DATA'}).encode('utf-8')
    oram.write(0, new_data)
    
    # Read updated block
    result = oram.read(0)
    result_dict = deserialize_block(result)
    print(f"Updated Block 0: {result_dict}")
    
    oram.print_statistics()


def test_with_csv(csv_file: str):
    """Test with CSV data."""
    print(f"\n=== Test 2: CSV Data ({csv_file}) ===")
    
    # Load data from CSV
    data_blocks = load_csv_data(csv_file, max_blocks=20)
    print(f"Loaded {len(data_blocks)} blocks from CSV")
    
    # Create ORAM
    oram = PathORAM(N=len(data_blocks), Z=4)
    oram.initialize_with_data(data_blocks)
    
    # Read some random blocks
    print("\nReading random blocks...")
    for _ in range(5):
        block_id = random.randint(0, len(data_blocks) - 1)
        result = oram.read(block_id)
        result_dict = deserialize_block(result)
        print(f"Block {block_id}: {result_dict}")
    
    # Update a block
    print("\nUpdating a block...")
    block_to_update = 0
    old_data = deserialize_block(oram.read(block_to_update))
    print(f"Old data: {old_data}")
    
    old_data['updated'] = 'YES'
    new_data = json.dumps(old_data).encode('utf-8')
    oram.write(block_to_update, new_data)
    
    updated_data = deserialize_block(oram.read(block_to_update))
    print(f"New data: {updated_data}")
    
    oram.print_statistics()


def test_range_query_simulation(csv_file: str, range_start: int, range_end: int):
    """
    Simulate range query by breaking into individual point queries.
    This demonstrates oblivious computation where access pattern is hidden.
    """
    print(f"\n=== Test 3: Range Query Simulation [{range_start}, {range_end}] ===")
    
    # Load data
    data_blocks = load_csv_data(csv_file, max_blocks=50)
    print(f"Loaded {len(data_blocks)} blocks from CSV")
    
    # Create ORAM
    oram = PathORAM(N=len(data_blocks), Z=4)
    oram.initialize_with_data(data_blocks)
    
    # Perform range query as individual point queries
    print(f"\nQuerying range [{range_start}, {range_end}]...")
    results = []
    
    for block_id in range(range_start, min(range_end + 1, len(data_blocks))):
        result = oram.read(block_id)
        result_dict = deserialize_block(result)
        results.append(result_dict)
        print(f"  Block {block_id}: {result_dict}")
    
    print(f"\nRetrieved {len(results)} blocks")
    oram.print_statistics()


if __name__ == "__main__":
    # Run basic test
    test_basic_operations()
    
    print("\n" + "="*60)
    print("To test with your CSV files, run:")
    print("  python pathoram.py <csv_file>")
    print("Or import and use the functions in your own script")
    print("="*60)