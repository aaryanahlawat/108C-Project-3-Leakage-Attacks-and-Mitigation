#!/usr/bin/env python3
"""
Example script showing how to use PathORAM with your own CSV data.
"""

from pathoram import PathORAM, load_csv_data, deserialize_block
import json

def example_1_basic():
    """Basic PathORAM usage with synthetic data."""
    print("\n" + "="*60)
    print("Example 1: Basic PathORAM Operations")
    print("="*60)
    
    # Create ORAM with 16 blocks
    oram = PathORAM(N=16, Z=4)
    
    # Create some test data
    data_blocks = {}
    for i in range(16):
        data = json.dumps({
            'block_id': i,
            'content': f'This is block {i}',
            'timestamp': f'2024-01-{i+1:02d}'
        }).encode('utf-8')
        data_blocks[i] = data
    
    # Initialize ORAM
    oram.initialize_with_data(data_blocks)
    
    # Perform some reads
    print("\nReading blocks 0, 5, 10:")
    for block_id in [0, 5, 10]:
        result = deserialize_block(oram.read(block_id))
        print(f"  Block {block_id}: {result}")
    
    # Perform a write
    print("\nUpdating block 5:")
    updated_data = json.dumps({
        'block_id': 5,
        'content': 'UPDATED CONTENT',
        'timestamp': '2024-01-05',
        'modified': True
    }).encode('utf-8')
    oram.write(5, updated_data)
    
    # Read the updated block
    result = deserialize_block(oram.read(5))
    print(f"  Updated Block 5: {result}")
    
    oram.print_statistics()


def example_2_csv_data():
    """Using PathORAM with CSV data."""
    print("\n" + "="*60)
    print("Example 2: PathORAM with CSV Data")
    print("="*60)
    
    # Load CSV data
    csv_file = 'sample_data.csv'
    data_blocks = load_csv_data(csv_file, max_blocks=15)
    print(f"\nLoaded {len(data_blocks)} records from {csv_file}")
    
    # Create and initialize ORAM
    oram = PathORAM(N=len(data_blocks), Z=4)
    oram.initialize_with_data(data_blocks)
    
    # Query specific employees
    print("\nQuerying specific employee records:")
    for block_id in [0, 5, 10]:
        employee = deserialize_block(oram.read(block_id))
        print(f"  Employee {block_id}: {employee['name']} - {employee['department']}")
    
    # Update an employee's salary
    print("\nUpdating employee record:")
    emp_data = deserialize_block(oram.read(0))
    print(f"  Before: {emp_data['name']} - Salary: ${emp_data['salary']}")
    
    emp_data['salary'] = '90000'
    emp_data['last_modified'] = '2024-02-12'
    oram.write(0, json.dumps(emp_data).encode('utf-8'))
    
    emp_data = deserialize_block(oram.read(0))
    print(f"  After: {emp_data['name']} - Salary: ${emp_data['salary']}")
    
    oram.print_statistics()


def example_3_range_query():
    """Simulating range queries with PathORAM."""
    print("\n" + "="*60)
    print("Example 3: Range Query (Oblivious)")
    print("="*60)
    
    # Load data
    csv_file = 'sample_data.csv'
    data_blocks = load_csv_data(csv_file, max_blocks=25)
    
    # Create ORAM
    oram = PathORAM(N=len(data_blocks), Z=4)
    oram.initialize_with_data(data_blocks)
    
    # Simulate a range query: "Find all employees with IDs 10-15"
    # In PathORAM, we break this into individual point queries
    print("\nQuerying employee IDs 10-15 (as individual point queries):")
    results = []
    
    for block_id in range(10, 16):
        if block_id < len(data_blocks):
            employee = deserialize_block(oram.read(block_id))
            results.append(employee)
            print(f"  ID {employee['id']}: {employee['name']} - {employee['department']}")
    
    print(f"\nTotal employees in range: {len(results)}")
    
    # Note: The adversary sees 6 accesses but cannot determine which specific
    # employee IDs were queried because all accesses look the same
    oram.print_statistics()


def example_4_filtering():
    """Filter data based on criteria using PathORAM."""
    print("\n" + "="*60)
    print("Example 4: Filtering with PathORAM")
    print("="*60)
    
    # Load data
    csv_file = 'sample_data.csv'
    all_data = load_csv_data(csv_file)
    
    # Create ORAM
    oram = PathORAM(N=len(all_data), Z=4)
    oram.initialize_with_data(all_data)
    
    # Find all Engineering employees (requires scanning all blocks obliviously)
    print("\nFinding all Engineering employees:")
    engineering_employees = []
    
    # In an oblivious query, we must scan ALL blocks to hide which ones match
    for block_id in range(len(all_data)):
        employee = deserialize_block(oram.read(block_id))
        if employee['department'] == 'Engineering':
            engineering_employees.append(employee)
            print(f"  {employee['name']} - Age: {employee['age']}, Salary: ${employee['salary']}")
    
    print(f"\nTotal Engineering employees: {len(engineering_employees)}")
    
    # The adversary cannot tell which employees were selected because
    # we accessed all blocks in the same way
    oram.print_statistics()


def example_5_your_csv():
    """Template for using your own CSV file."""
    print("\n" + "="*60)
    print("Example 5: Using Your Own CSV File")
    print("="*60)
    
    # Replace with your CSV file path
    your_csv = 'sample_data.csv'  # Change this to your file
    
    try:
        # Load your data
        data_blocks = load_csv_data(your_csv, max_blocks=None)  # None = all rows
        print(f"\nLoaded {len(data_blocks)} records from {your_csv}")
        
        # Peek at the first record to see the structure
        first_record = deserialize_block(data_blocks[0])
        print(f"Record structure: {list(first_record.keys())}")
        
        # Create ORAM
        oram = PathORAM(N=len(data_blocks), Z=4)
        oram.initialize_with_data(data_blocks)
        
        # Read a few random records
        import random
        print("\nReading 3 random records:")
        for _ in range(min(3, len(data_blocks))):
            block_id = random.randint(0, len(data_blocks) - 1)
            record = deserialize_block(oram.read(block_id))
            print(f"  Record {block_id}: {record}")
        
        oram.print_statistics()
        
    except FileNotFoundError:
        print(f"\nFile not found: {your_csv}")
        print("Please update the 'your_csv' variable with your CSV file path")
    except Exception as e:
        print(f"\nError: {e}")


if __name__ == "__main__":
    # Run all examples
    example_1_basic()
    example_2_csv_data()
    example_3_range_query()
    example_4_filtering()
    example_5_your_csv()
    
    print("\n" + "="*60)
    print("All examples completed!")
    print("\nTo use with your own CSV:")
    print("1. Edit example_5_your_csv() and change 'your_csv' variable")
    print("2. Or import the functions and use them in your own code")
    print("="*60 + "\n")