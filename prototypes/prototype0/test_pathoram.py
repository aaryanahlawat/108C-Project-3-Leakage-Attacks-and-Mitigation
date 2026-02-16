#!/usr/bin/env python3
"""
Test script for PathORAM implementation.
Demonstrates various use cases including CSV data loading and range queries.
"""

import sys
from pathoram import (
    PathORAM, 
    load_csv_data, 
    deserialize_block,
    test_basic_operations,
    test_with_csv,
    test_range_query_simulation
)

def main():
    print("="*60)
    print("PathORAM Test Suite")
    print("="*60)
    
    # Test 1: Basic operations with synthetic data
    test_basic_operations()
    
    # Test 2: CSV data operations
    csv_file = 'sample_data.csv'
    try:
        test_with_csv(csv_file)
    except FileNotFoundError:
        print(f"Warning: {csv_file} not found. Skipping CSV test.")
    
    # Test 3: Range query simulation (ages 20-32 example from your notes)
    try:
        test_range_query_simulation(csv_file, range_start=5, range_end=15)
    except FileNotFoundError:
        print(f"Warning: {csv_file} not found. Skipping range query test.")
    
    # Test 4: Custom test with your own CSV
    if len(sys.argv) > 1:
        custom_csv = sys.argv[1]
        print(f"\n=== Test 4: Custom CSV ({custom_csv}) ===")
        try:
            test_with_csv(custom_csv)
            
            # Also test range query
            print(f"\n=== Range Query on {custom_csv} ===")
            test_range_query_simulation(custom_csv, range_start=0, range_end=10)
        except FileNotFoundError:
            print(f"Error: File {custom_csv} not found.")
        except Exception as e:
            print(f"Error processing {custom_csv}: {e}")
    
    print("\n" + "="*60)
    print("All tests completed!")
    print("="*60)

if __name__ == "__main__":
    main()