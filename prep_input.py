#!/usr/bin/env python3
"""
prep_input.py — Generate ORAM input CSV from the Chicago Crime dataset
(or any CSV with a categorical attribute column).

The ORAM client stores integers, not strings. This script:
  1. Reads the Chicago crime CSV (or any dataset CSV).
  2. Picks a target attribute column (e.g. "Primary Type").
  3. Assigns each distinct value an integer code (1, 2, 3, ...).
  4. Generates a client input CSV:  op, block_id, data
       - One WRITE per record: WRITE <row_index> <value_code>
       - One READ per distinct value (queries every keyword once)
  5. Writes a value map JSON so attack.py can map integer codes back
     to plaintext strings for the attack evaluation.

The value map is also what connects the integer ORAM world to the
string-valued Chicago dataset in attack.py.

Usage:
    # Basic: generate from Primary Type column, first 1000 rows
    python3 prep_input.py \\
        --dataset Crimes_2001_to_Present.csv \\
        --attribute "Primary Type" \\
        --rows 1000 \\
        --output input.csv \\
        --value-map value_map.json

    # With a specific random seed and custom read fraction
    python3 prep_input.py \\
        --dataset Crimes_2001_to_Present.csv \\
        --attribute "Primary Type" \\
        --rows 5000 \\
        --read-all \\
        --output input_5k.csv \\
        --value-map value_map.json \\
        --seed 42

Output CSV format (directly usable by client.py):
    WRITE,1,3
    WRITE,2,1
    WRITE,3,7
    ...
    READ,1
    READ,2
    ...

The --read-all flag adds one READ per block after all WRITEs.
Without it, only one READ per distinct value is added (one per keyword).
"""

import argparse
import csv
import json
import os
import random
import sys
from collections import Counter


def parse_args():
    p = argparse.ArgumentParser(
        description="Generate ORAM client input CSV from a crime/dataset CSV",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1000 records, one read per distinct value (good for attack demo)
  python3 prep_input.py \\
      --dataset Crimes_2001_to_Present.csv \\
      --attribute "Primary Type" \\
      --rows 1000 \\
      --output input.csv --value-map value_map.json

  # 500 records, read every block back (stress test)
  python3 prep_input.py \\
      --dataset Crimes_2001_to_Present.csv \\
      --attribute "Primary Type" \\
      --rows 500 --read-all \\
      --output input.csv --value-map value_map.json

  # Then run:
  python3 server.py
  python3 client.py input.csv output.txt -a 2 -x 2 --query-log queries.jsonl
  python3 attack.py --dataset Crimes_2001_to_Present.csv \\
                    --attribute "Primary Type" \\
                    --query-log queries.jsonl \\
                    --value-map value_map.json
        """
    )
    p.add_argument("--dataset",    required=True,
                   help="Path to the Chicago crime CSV (or any dataset CSV)")
    p.add_argument("--attribute",  required=True,
                   help="Column to use as the query keyword (e.g. 'Primary Type')")
    p.add_argument("--rows",       type=int, default=1000,
                   help="Number of records to load (default: 1000). "
                        "Use 0 for all rows (can be slow for 8M row datasets).")
    p.add_argument("--output",     default="input.csv",
                   help="Output CSV path for client.py (default: input.csv)")
    p.add_argument("--value-map",  default="value_map.json", dest="value_map",
                   help="Output JSON mapping int codes → string values "
                        "(default: value_map.json)")
    p.add_argument("--read-all",   action="store_true", dest="read_all",
                   help="Add one READ per block (in addition to per-value READs). "
                        "Default: one READ per distinct value only.")
    p.add_argument("--shuffle",    action="store_true",
                   help="Shuffle the order of rows before generating queries.")
    p.add_argument("--seed",       type=int, default=None,
                   help="Random seed for shuffling.")
    p.add_argument("--se-mode",    action="store_true", dest="se_mode",
                   help=(
                       "Generate SE-mode GROUP_READ queries instead of single-block "
                       "READs. Each GROUP_READ queries ALL records of one crime type, "
                       "producing result_size = freq[value]. This enables the QR "
                       "volume attack in attack.py and replicates the SEAL paper's "
                       "searchable encryption model. Recommended for Chicago dataset."
                   ))
    return p.parse_args()


def load_column(csv_path: str, attribute: str, max_rows: int) -> list:
    """Load (row_index, value) pairs from the given attribute column."""
    rows = []
    with open(csv_path, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        if attribute not in (reader.fieldnames or []):
            available = ', '.join(reader.fieldnames or [])
            print(f"[ERROR] Attribute '{attribute}' not found in CSV.")
            print(f"  Available columns: {available}")
            sys.exit(1)
        for i, row in enumerate(reader):
            if max_rows > 0 and i >= max_rows:
                break
            val = row[attribute].strip()
            if val:  # skip blank values
                rows.append((i + 1, val))  # 1-indexed block_id
    return rows


def main():
    args = parse_args()

    if not os.path.exists(args.dataset):
        print(f"[ERROR] Dataset not found: {args.dataset}")
        sys.exit(1)

    rng = random.Random(args.seed)

    print(f"Loading '{args.attribute}' from {args.dataset} ...")
    rows = load_column(args.dataset, args.attribute, args.rows)

    if not rows:
        print("[ERROR] No rows loaded — check your CSV path and attribute name.")
        sys.exit(1)

    print(f"  Loaded {len(rows):,} records.")

    if args.shuffle:
        rng.shuffle(rows)
        print(f"  Shuffled.")

    # Build value → integer code mapping (sorted by frequency, most common = 1)
    freq = Counter(val for _, val in rows)
    # Sort by frequency descending so code 1 = most common (THEFT, etc.)
    sorted_values = [v for v, _ in freq.most_common()]
    value_to_code = {v: i + 1 for i, v in enumerate(sorted_values)}
    code_to_value = {i + 1: v for i, v in enumerate(sorted_values)}

    print(f"  Distinct values: {len(value_to_code)}")
    print(f"  Top 5 by frequency:")
    for val, cnt in freq.most_common(5):
        code = value_to_code[val]
        print(f"    [{code:>3}] {val:40s}  {cnt:>6,} records  "
              f"({cnt/len(rows)*100:.1f}%)")

    # Generate queries
    write_queries = []
    for block_id, val in rows:
        code = value_to_code[val]
        write_queries.append(("WRITE", block_id, code))

    if args.se_mode:
        # SE MODE: one GROUP_READ per distinct value.
        # GROUP_READ <value_code> tells client.py to read ALL blocks whose
        # stored integer equals value_code, producing result_size = freq[value].
        # This replicates the SEAL paper's SE query model:
        #   SELECT * FROM crimes WHERE Primary_Type = 'THEFT'
        # The adversary sees padded_size = x^ceil(log_x(freq[value])) and uses
        # it to identify which crime type was queried (Figure 7 QR attack).
        read_queries = [
            ("GROUP_READ", value_to_code[val], None)
            for val in sorted_values
        ]
        read_label = "GROUP_READ per distinct value (SE mode)"
    else:
        # PROTOTYPE MODE: one single-block READ per distinct value.
        # result_size = 1 always — volume attack not applicable.
        first_occurrence: dict = {}
        for block_id, val in rows:
            if val not in first_occurrence:
                first_occurrence[val] = block_id
        read_queries = [
            ("READ", first_occurrence[val], None)
            for val in sorted_values
        ]
        read_label = "READ per distinct value (prototype mode)"

    # Optional: one READ per every block (stress / correctness test)
    read_queries_all = [("READ", block_id, None) for block_id, _ in rows]

    all_queries = write_queries + read_queries
    if args.read_all:
        all_queries += read_queries_all

    total_writes = len(write_queries)
    total_reads  = len(read_queries) + (len(read_queries_all) if args.read_all else 0)
    print(f"\n  Query plan  ({'SE mode' if args.se_mode else 'prototype mode'}):")
    print(f"    WRITEs : {total_writes:,}")
    print(f"    READs  : {total_reads:,}  ({read_label})")
    if args.se_mode:
        import math as _math
        print(f"    Result sizes (actual → padded with x=2):")
        for val, cnt in freq.most_common():
            ps = 2 ** _math.ceil(_math.log2(cnt)) if cnt > 1 else 1
            print(f"      [{value_to_code[val]:>3}] {val:38s}  {cnt:>7,} → {ps:>7,}")
    print(f"    Total  : {len(all_queries):,}")

    # Recommend ORAM parameters
    N = len(rows)
    import math
    recommended_L = max(2, math.ceil(math.log2(N)) - 1)
    print(f"\n  Recommended ORAM parameters for {N:,} records:")
    print(f"    -l {recommended_L}   (tree height, L = ⌈log2({N})⌉ - 1 = {recommended_L})")
    print(f"    -a 1 to 3  (leakage α, start with 1 or 2)")
    print(f"    -x 2 to 4  (padding, start with 2)")
    print(f"\n  Full example command:")
    print(f"    python3 server.py")
    print(f"    python3 client.py {args.output} output.txt "
          f"-a 2 -l {recommended_L} -x 2 --query-log queries.jsonl")
    if not args.se_mode:
        print(f"  Tip: re-run with --se-mode to enable the QR volume attack")

    # Write output CSV
    with open(args.output, 'w', newline='') as f:
        writer = csv.writer(f)
        for q in all_queries:
            op, block_id, data = q
            if op == "WRITE":
                writer.writerow([op, block_id, data])
            else:
                writer.writerow([op, block_id])

    print(f"\n✓ Input CSV written to   : {args.output}")

    # Write value map JSON
    value_map = {
        "attribute":     args.attribute,
        "dataset":       args.dataset,
        "rows_loaded":   len(rows),
        "se_mode":       args.se_mode,
        "code_to_value": {str(k): v for k, v in code_to_value.items()},
        "value_to_code": value_to_code,
        "frequencies":   {v: cnt for v, cnt in freq.items()},
        # group_sizes: str(value_code) → actual record count in this dataset slice
        # Used by attack.py in SE mode to verify result sizes
        "group_sizes":   {str(value_to_code[v]): cnt for v, cnt in freq.items()},
    }
    with open(args.value_map, 'w') as f:
        json.dump(value_map, f, indent=2)

    print(f"✓ Value map written to   : {args.value_map}")
    print(f"\nNext steps:")
    print(f"  1. python3 server.py")
    print(f"  2. python3 client.py {args.output} output.txt "
          f"-a 2 -l {recommended_L} -x 2 --query-log queries.jsonl")
    print(f"  3. python3 attack.py --dataset {args.dataset} "
          f"--attribute \"{args.attribute}\" \\")
    print(f"              --query-log queries.jsonl "
          f"--value-map {args.value_map}")


if __name__ == "__main__":
    main()
