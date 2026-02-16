# PathORAM Quick Start Guide

## Installation
No external dependencies needed - uses only Python standard library!

## Files Overview
- `pathoram.py` - Core PathORAM implementation
- `test_pathoram.py` - Full test suite
- `example_usage.py` - Example scripts showing various use cases
- `sample_data.csv` - Sample employee data for testing
- `README.md` - Complete documentation
- `QUICKSTART.md` - This file

## Quick Test

```bash
# Run all tests with sample data
python test_pathoram.py

# Run example scripts
python example_usage.py

# Test with your own CSV file
python test_pathoram.py your_data.csv
```

## 5-Minute Tutorial

### 1. Basic Usage

```python
from pathoram import PathORAM
import json

# Create ORAM with 10 blocks, 4 blocks per bucket
oram = PathORAM(N=10, Z=4)

# Create data
data = {i: json.dumps({'id': i, 'data': f'value_{i}'}).encode('utf-8') 
        for i in range(10)}

# Initialize
oram.initialize_with_data(data)

# Read block 5
result = oram.read(5)
print(json.loads(result))

# Write to block 5
new_data = json.dumps({'id': 5, 'data': 'updated'}).encode('utf-8')
oram.write(5, new_data)
```

### 2. Using CSV Data

```python
from pathoram import load_csv_data, PathORAM, deserialize_block

# Load CSV
data = load_csv_data('sample_data.csv')

# Create and initialize ORAM
oram = PathORAM(N=len(data), Z=4)
oram.initialize_with_data(data)

# Query
result = deserialize_block(oram.read(0))
print(result)
```

### 3. Range Queries

```python
# Query blocks 10-20 as individual point queries
results = []
for i in range(10, 21):
    results.append(deserialize_block(oram.read(i)))
```

## Key Concepts

### What is ORAM?
Oblivious RAM hides access patterns from adversaries. Even with encryption, 
the pattern of which storage locations you access reveals information. 
ORAM solves this by making all access patterns indistinguishable.

### PathORAM Specifics
- **Binary tree structure**: O(log N) height
- **Buckets**: Each tree node holds up to Z blocks (typically 4)
- **Stash**: Client-side temporary storage
- **Position map**: Tracks which leaf each block is assigned to
- **Random remapping**: Each access assigns block to new random leaf

### How It Works
1. Each block assigned to random leaf
2. Block must be on path from root to its assigned leaf
3. On access:
   - Read entire path (root to leaf)
   - Update block if needed
   - Assign block to new random leaf
   - Write blocks back along path

## Common Use Cases

### Private Database Queries
```python
# Query user record without revealing which user
user_data = deserialize_block(oram.read(user_id))
```

### Secure Cloud Storage
```python
# Access files without revealing access pattern to cloud provider
file_data = oram.read(file_id)
```

### Range Queries
```python
# Find records in age range 25-35 (must scan all to hide pattern)
matching = []
for i in range(total_records):
    record = deserialize_block(oram.read(i))
    if 25 <= int(record['age']) <= 35:
        matching.append(record)
```

## Performance Notes

- **Bandwidth**: Each access touches O(log N) blocks
- **Typical overhead**: 7.5x for N=1000 blocks
- **Stash size**: Usually small (< 20 blocks) with high probability
- **Security**: Statistically indistinguishable access patterns

## Troubleshooting

### "Block not found in stash"
This shouldn't happen with correct implementation. If it does:
- Check that block IDs are valid (0 to N-1)
- Verify initialization completed successfully

### Stash overflow
Very rare with Z=4. If it happens:
- Increase Z (e.g., Z=5 or Z=6)
- Reduces bandwidth efficiency but increases stash capacity

### Performance issues
For N > 10,000 blocks:
- Consider recursive position map (not implemented in basic version)
- Each position map entry also stored in ORAM
- Reduces client storage to O(1)

## Next Steps

1. **Read README.md** for complete documentation
2. **Run example_usage.py** to see various patterns
3. **Test with your data** using test_pathoram.py
4. **Check statistics** using oram.print_statistics()

## CSV Format Requirements

Your CSV must have:
- Header row with column names
- Consistent number of columns per row
- Text or numeric data (no binary)

Example:
```csv
id,name,value
1,Item A,100
2,Item B,200
```

## Getting Help

1. Check README.md for detailed documentation
2. Look at example_usage.py for code patterns
3. Review test_pathoram.py for testing approaches

## Key Parameters

- **N**: Number of blocks (size of your dataset)
- **Z**: Blocks per bucket (4 is standard, higher = more robust)
- **block_size**: Bytes per block (256 default, adjust for your data)

## Statistics to Monitor

```python
stats = oram.get_statistics()
print(stats)
```

Key metrics:
- `max_stash_size`: Should be < 30 for good parameters
- `total_blocks_read/total_reads`: Shows bandwidth overhead (~log N)
- `current_stash_size`: Should be 0 or small after operations

---

**Ready to start?** Run `python test_pathoram.py` to see it in action!