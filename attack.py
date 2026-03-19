#!/usr/bin/env python3
"""
SEAL Leakage-Abuse Attacks
Implements the Query Recovery Attack and Database Recovery Attack from:
  Demertzis et al., "SEAL: Attack Mitigation for Encrypted Databases
  via Adjustable Leakage", USENIX Security 2020, Section 5.

Threat model (Section 5.1):
  - Adversary is the server (honest-but-curious).
  - Has full visibility of all server-side execution.
  - Has 100% plaintext access to the input dataset (worst-case).
  - Observes ALL queries (worst-case leakage).
  - Knows SEAL parameters α and x (public).

Two operating modes (auto-detected from the query log):

  SE MODE  (group queries, result_size > 1):
    The client issues one logical query per keyword value, touching
    multiple ORAM blocks per query. The adversary sees the *padded
    result size* and uses ADJ-PADDING-x frequency matching to recover
    the queried keyword (Figure 7) and then map encrypted records to
    plaintext records (Figure 8).

  PROTOTYPE MODE  (single-block queries, result_size = 1):
    Every READ touches exactly 1 ORAM block. Volume is always 1 so
    size-based matching is useless. The adversary's only signal is the
    *partition access frequency* — which partition is hit how often.
    More accesses to partition p → more records were in partition p →
    the adversary matches observed partition frequencies to expected
    per-value partition frequencies from the plaintext dataset.

Usage:
    python3 attack.py \\
        --dataset  Crimes_2001_to_Present.csv \\
        --attribute "Primary Type" \\
        --query-log queries.jsonl \\
        [--alpha 1] [--padding 2] [--trials 1000] [--seed 42]
"""

import argparse
import csv
import json
import math
import os
import random
import sys
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def padded_size(actual: int, x: Optional[int]) -> int:
    """ADJ-PADDING-x: smallest x^i >= actual. Figure 5, SEAL paper."""
    if x is None or actual == 0:
        return actual
    i = math.ceil(math.log(actual, x))
    return x ** i


def load_query_log(path: str) -> Tuple[dict, List[dict]]:
    header = None
    queries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj["type"] == "header":
                header = obj
            elif obj["type"] == "query":
                queries.append(obj)
    if header is None:
        raise ValueError("Query log missing header — run client.py with --query-log.")
    return header, queries


def load_dataset_column(csv_path: str, attribute: str) -> List[str]:
    values = []
    with open(csv_path, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        if attribute not in (reader.fieldnames or []):
            available = ', '.join(reader.fieldnames or [])
            raise ValueError(
                f"Attribute '{attribute}' not found.\nAvailable: {available}"
            )
        for row in reader:
            values.append(row[attribute].strip())
    return values


def detect_mode(queries: List[dict]) -> str:
    """
    Auto-detect SE mode (result_size > 1) vs prototype mode (all sizes == 1).
    GROUP_READ entries always indicate SE mode.
    """
    # Any GROUP_READ entry means SE mode
    if any(q["op"] == "GROUP_READ" for q in queries):
        return "se"
    read_qs = [q for q in queries if q["op"] == "READ"]
    if not read_qs:
        return "prototype"
    sizes = [q.get("padded_size", 1) for q in read_qs]
    if max(sizes) > 1:
        return "se"
    return "prototype"


# ---------------------------------------------------------------------------
# SE MODE — Attack 1: Query Recovery  (Figure 7, padded-size matching)
# ---------------------------------------------------------------------------

def qr_attack_se_mode(
    plaintext_values: List[str],
    queries: List[dict],
    x: Optional[int],
    trials: int,
    rng: random.Random,
    query_truth: Optional[Dict[int, str]] = None,
    slice_freq: Optional[Dict[str, int]] = None,
) -> dict:
    """
    Query Recovery Attack for SE mode (result_size > 1).
    The adversary matches observed padded result sizes against the
    padded frequencies of plaintext keyword values (Figure 7).
    """
    # Use full-dataset frequencies for baseline and candidate detection.
    # If slice_freq is provided (from value_map.json), use it for padded_size
    # matching because the query log padded_sizes were computed from the slice,
    # not the full dataset. The adversary observes the actual padded_size in the
    # query and matches it against what each value would produce in that same
    # database slice — which is exactly what the paper models.
    freq = Counter(plaintext_values)
    match_freq = slice_freq if slice_freq is not None else freq
    distinct = list(match_freq.keys())
    baseline = 1.0 / max(1, len(distinct))

    # Padded frequency for each plaintext value (using slice frequencies)
    padded_freq = {v: padded_size(cnt, x) for v, cnt in match_freq.items()}

    # Group plaintext values by their padded frequency
    candidates_by_padded: Dict[int, List[str]] = defaultdict(list)
    for v, ps in padded_freq.items():
        candidates_by_padded[ps].append(v)

    # Build ground truth: block_id → true keyword (from WRITE ops in log)
    block_value: Dict[int, str] = {}
    for q in queries:
        if q["op"] == "WRITE":
            block_value[q["block_id"]] = str(q.get("data", ""))

    # Include both single-block READ and SE-mode GROUP_READ queries
    read_qs = [q for q in queries if q["op"] in ("READ", "GROUP_READ")]

    total_correct = 0
    total_qs = 0
    total_candidates = 0
    pv_correct: Dict[str, int] = defaultdict(int)
    pv_total:   Dict[str, int] = defaultdict(int)
    detail = []

    for _ in range(trials):
        remaining: Dict[int, List[str]] = {
            ps: list(vals) for ps, vals in candidates_by_padded.items()
        }
        for q in read_qs:
            obs = q.get("padded_size", 1)
            cands = remaining.get(obs, [])
            total_candidates += len(cands)

            if not cands:
                detail.append({
                    "block_id": q["block_id"],
                    "observed_padded_size": obs,
                    "guess": None,
                    "correct": False,
                    "candidate_set_size": 0,
                })
                continue

            guess = rng.choice(cands)
            cands.remove(guess)

            tv = query_truth.get_for_query(q) if (query_truth is not None and hasattr(query_truth, "get_for_query")) else block_value.get(q["block_id"])
            correct = tv is not None and guess == tv
            if tv is not None:
                pv_total[tv]   += 1
                total_qs       += 1
                if correct:
                    pv_correct[tv] += 1
                    total_correct  += 1

            detail.append({
                "block_id":             q["block_id"],
                "observed_padded_size": obs,
                "guess":                guess,
                "true_value":           tv,
                "correct":              correct,
                "candidate_set_size":   len(cands) + 1,
            })

    qrsr = total_correct / total_qs if total_qs else 0.0
    avg_cands = total_candidates / max(1, len(read_qs) * trials)

    return {
        "qrsr":       qrsr,
        "baseline":   baseline,
        "candidates": avg_cands,
        "per_value":  {v: pv_correct[v]/pv_total[v] for v in pv_total},
        "detail":     detail,
        "mode":       "se",
    }


# ---------------------------------------------------------------------------
# PROTOTYPE MODE — Attack 1: Query Recovery  (partition-frequency matching)
# ---------------------------------------------------------------------------
#
# When every READ touches exactly 1 block, padded_size is always 1.
# The adversary's only signal per query is the partition_id (α bits).
#
# Strategy: count how many times each partition is accessed. Compare to
# the expected per-value partition hit rate from the plaintext dataset
# (records are spread uniformly across P partitions, so a value with
# frequency f contributes ~f/P hits to each partition on average).
#
# The adversary then uses a frequency-analysis style match:
# rank observed partition counts against expected per-value partition
# frequencies, and assign the most likely keyword per partition.

def qr_attack_prototype_mode(
    plaintext_values: List[str],
    queries: List[dict],
    alpha: int,
    x: Optional[int],
    trials: int,
    rng: random.Random,
    query_truth: Optional[Dict[int, str]] = None,
) -> dict:
    """
    Query Recovery Attack for prototype mode (all result_size == 1).
    Uses partition access frequency as the adversary's signal.
    """
    P = 2 ** alpha
    freq   = Counter(plaintext_values)
    N      = len(plaintext_values)
    distinct = list(freq.keys())
    baseline = 1.0 / max(1, len(distinct))

    # Build ground truth
    block_value: Dict[int, str] = {}
    for q in queries:
        if q["op"] == "WRITE":
            block_value[q["block_id"]] = str(q.get("data", ""))

    read_qs = [q for q in queries if q["op"] == "READ"]

    # Observed partition access counts
    partition_counts: Counter = Counter(q["partition_id"] for q in read_qs)

    # Expected fraction of reads going to each partition for each value:
    # with uniform random partition assignment, each value v contributes
    # freq[v] / (N * P) hits per partition on average.
    # For matching, we use the total expected count per partition:
    # E[partition p hits from value v] ≈ freq[v] / P
    expected_per_value_partition = {
        v: freq[v] / P for v in distinct
    }

    # For each READ query, the adversary knows which partition was hit.
    # They guess: which keyword is most likely to have been queried given
    # this partition was accessed?
    # P(value v | partition p accessed) ∝ freq[v] / P  (uniform assignment)
    # = freq[v]  (constant factor)
    # So the adversary should always guess the MOST FREQUENT value — which
    # is exactly the greedy/frequency-analysis attack.
    # With α > 0, the partition hint adds information: values assigned more
    # records to partition p are more likely. But since assignment is random
    # and uniform, the prior is just proportional to frequency.

    total_correct = 0
    total_qs      = 0
    pv_correct: Dict[str, int] = defaultdict(int)
    pv_total:   Dict[str, int] = defaultdict(int)
    detail = []

    for _ in range(trials):
        # For each READ, adversary picks the most frequent value
        # (frequency analysis, same as paper's frequency attack)
        sorted_by_freq = sorted(distinct, key=lambda v: freq[v], reverse=True)

        for q in read_qs:
            partition_id = q["partition_id"]

            # Adversary ranks values by expected contribution to this partition
            # With uniform random assignment: still proportional to global frequency
            # (no additional information from partition ID alone)
            guess = sorted_by_freq[0] if sorted_by_freq else None

            tv = query_truth.get_for_query(q) if (query_truth is not None and hasattr(query_truth, "get_for_query")) else block_value.get(q["block_id"])
            correct = tv is not None and guess == tv
            if tv is not None:
                pv_total[tv] += 1
                total_qs     += 1
                if correct:
                    pv_correct[tv] += 1
                    total_correct  += 1

            detail.append({
                "block_id":     q["block_id"],
                "partition_id": partition_id,
                "guess":        guess,
                "true_value":   tv,
                "correct":      correct,
                "note":         "partition-frequency attack (all result sizes = 1)",
            })

    qrsr = total_correct / total_qs if total_qs else 0.0

    return {
        "qrsr":     qrsr,
        "baseline": baseline,
        "candidates": 1.0,
        "per_value": {v: pv_correct[v]/pv_total[v] for v in pv_total},
        "detail":   detail,
        "mode":     "prototype",
        "note": (
            "Prototype mode: all result sizes = 1 (one ORAM block per READ). "
            "Volume-based matching is not applicable. "
            "Adversary uses global frequency analysis (always guesses most common value). "
            "ADJ-PADDING-x has no effect here; ADJ-ORAM-α is the relevant defence."
        ),
    }


# ---------------------------------------------------------------------------
# Attack 2: Database Recovery  (Figure 8, both modes)
# ---------------------------------------------------------------------------

def dr_attack(
    plaintext_values: List[str],
    queries: List[dict],
    alpha: int,
    x: Optional[int],
    qr_detail: List[dict],
    trials: int,
    rng: random.Random,
    query_truth: Optional[Dict[int, str]] = None,
) -> dict:
    """
    Database Recovery Attack (Figure 8).
    Given the QR attack's guessed keyword per query, the adversary
    uses the α-bit partition identifier to narrow candidate records.

    For each encrypted tuple returned by a query:
      - Adversary knows: partition_id (α bits)
      - Adversary guesses: query keyword (from QR attack)
      - Candidate records: plaintext records with matching keyword
        AND matching partition assignment
      - Adversary picks one at random from candidates

    DRSR = correctly mapped tuples / total tuples.
    Greedy baseline = always assign the most frequent value.
    """
    P = 2 ** alpha
    freq = Counter(plaintext_values)
    N    = len(plaintext_values)

    most_common_val   = freq.most_common(1)[0][0]
    most_common_count = freq.most_common(1)[0][1]
    greedy_baseline   = most_common_count / N

    # Ground truth: WRITE block_id → string value
    block_value: Dict[int, str] = {}
    for q in queries:
        if q["op"] == "WRITE":
            block_value[q["block_id"]] = str(q.get("data", ""))

    # QR guess map from Attack 1 detail
    guessed_value: Dict[int, Optional[str]] = {
        d["block_id"]: d.get("guess") for d in qr_detail
    }

    read_qs = [q for q in queries if q["op"] in ("READ", "GROUP_READ")]

    total_correct = 0
    total_tuples  = 0
    pv_correct: Dict[str, int] = defaultdict(int)
    pv_total:   Dict[str, int] = defaultdict(int)
    detail = []

    for _ in range(trials):
        # Assign plaintext indices to partitions (simulates PRP assignment)
        indices_by_partition: Dict[int, List[int]] = defaultdict(list)
        for idx in range(N):
            p = rng.randint(0, P - 1)
            indices_by_partition[p].append(idx)

        for q in read_qs:
            block_id     = q["block_id"]
            partition_id = q["alpha_bits"]

            q_prime = guessed_value.get(block_id)

            # Candidate indices:
            # - GROUP_READ (alpha_bits=-1): query spans all partitions, so
            #   candidates = ALL plaintext records matching the guessed keyword.
            # - Single-block READ (alpha_bits=0..P-1): filter by partition.
            if partition_id == -1:  # GROUP_READ
                if q_prime is not None:
                    candidate_indices = [
                        idx for idx in range(N)
                        if plaintext_values[idx] == q_prime
                    ]
                else:
                    candidate_indices = list(range(N))
            elif q_prime is not None:
                candidate_indices = [
                    idx for idx in indices_by_partition.get(partition_id, [])
                    if plaintext_values[idx] == q_prime
                ]
            else:
                # QR failed — use all records in this partition
                candidate_indices = list(indices_by_partition.get(partition_id, []))

            tv = query_truth.get_for_query(q) if (query_truth is not None and hasattr(query_truth, "get_for_query")) else block_value.get(block_id)

            if not candidate_indices:
                detail.append({
                    "block_id":               block_id,
                    "partition_id":           partition_id,
                    "guessed_query_value":    q_prime,
                    "chosen_plaintext_value": None,
                    "true_value":             tv,
                    "correct":                False,
                    "candidate_set_size":     0,
                })
                continue

            chosen_idx   = rng.choice(candidate_indices)
            chosen_value = plaintext_values[chosen_idx]
            correct      = tv is not None and chosen_value == tv

            if tv is not None:
                pv_total[tv]   += 1
                total_tuples   += 1
                if correct:
                    pv_correct[tv] += 1
                    total_correct  += 1

            detail.append({
                "block_id":               block_id,
                "partition_id":           partition_id,
                "guessed_query_value":    q_prime,
                "chosen_plaintext_value": chosen_value,
                "true_value":             tv,
                "correct":                correct,
                "candidate_set_size":     len(candidate_indices),
            })

    drsr = total_correct / total_tuples if total_tuples else 0.0

    return {
        "drsr":      drsr,
        "greedy":    greedy_baseline,
        "per_value": {v: pv_correct[v]/pv_total[v] for v in pv_total},
        "detail":    detail,
    }


# ---------------------------------------------------------------------------
# Pretty printers
# ---------------------------------------------------------------------------

def section(title: str):
    print(f"\n{'='*62}")
    print(f"  {title}")
    print(f"{'='*62}")


def print_qr(result: dict, attribute: str, x: Optional[int]):
    section("ATTACK 1 — QUERY RECOVERY  (SEAL §5, Figure 7)")
    print(f"  Attribute : {attribute}")
    print(f"  Padding x : {x if x is not None else '⊥ (disabled)'}")
    print(f"  Mode      : {result.get('mode','?').upper()}")
    print()
    print(f"  QRSR (attack success) : {result['qrsr']*100:6.2f}%")
    print(f"  Random baseline       : {result['baseline']*100:6.2f}%")
    if result.get("mode") == "se":
        print(f"  Avg candidate set     : {result['candidates']:.1f}  "
              "(smaller = easier for adversary)")
    print()

    note = result.get("note")
    if note:
        print(f"  ℹ  {note}")
        print()

    if result["qrsr"] <= result["baseline"] * 1.1:
        verdict = "✓ EFFECTIVE  — attack ≈ random guessing"
    elif result["qrsr"] < 0.5:
        verdict = "~  PARTIAL   — attack below 50%, tune parameters"
    else:
        verdict = "✗ INEFFECTIVE — increase x (more padding) for this attribute"
    print(f"  Verdict: {verdict}")

    pv = result.get("per_value", {})
    if pv:
        print()
        print("  Per-value success (top 10):")
        for val, rate in sorted(pv.items(), key=lambda kv: kv[1], reverse=True)[:10]:
            bar = "█" * int(rate * 20)
            print(f"    {str(val)[:32]:32s}  {rate*100:5.1f}%  {bar}")

    detail = result.get("detail", [])
    if detail:
        print()
        print("  Sample (first 10 READ queries):")
        print(f"  {'Block':>6}  {'ObsSize':>7}  {'Cands':>5}  "
              f"{'Guess':>22}  {'True':>22}  OK")
        print(f"  {'-'*6}  {'-'*7}  {'-'*5}  {'-'*22}  {'-'*22}  --")
        for d in detail[:10]:
            g  = str(d.get("guess")      or "?")[:22]
            tv = str(d.get("true_value") or "?")[:22]
            ok = "✓" if d.get("correct") else "✗"
            sz = d.get("observed_padded_size", d.get("partition_id", "?"))
            cs = d.get("candidate_set_size", "?")
            print(f"  {d['block_id']:>6}  {str(sz):>7}  {str(cs):>5}  "
                  f"{g:>22}  {tv:>22}  {ok}")


def print_dr(result: dict, attribute: str, alpha: int, x: Optional[int]):
    section("ATTACK 2 — DATABASE RECOVERY  (SEAL §5, Figure 8)")
    print(f"  Attribute : {attribute}")
    print(f"  Alpha α   : {alpha}  ({2**alpha} partitions)")
    print(f"  Padding x : {x if x is not None else '⊥ (disabled)'}")
    print()
    print(f"  DRSR (attack success) : {result['drsr']*100:6.2f}%")
    print(f"  Greedy baseline       : {result['greedy']*100:6.2f}%")
    print()

    if result["drsr"] <= result["greedy"] * 1.1:
        verdict = "✓ EFFECTIVE  — attack ≈ greedy baseline"
    elif result["drsr"] < 0.5:
        verdict = "~  PARTIAL   — attack below 50%, tune α"
    else:
        verdict = "✗ INEFFECTIVE — decrease α (more partitions) for more privacy"
    print(f"  Verdict: {verdict}")

    pv = result.get("per_value", {})
    if pv:
        print()
        print("  Per-value success (top 10):")
        for val, rate in sorted(pv.items(), key=lambda kv: kv[1], reverse=True)[:10]:
            bar = "█" * int(rate * 20)
            print(f"    {str(val)[:32]:32s}  {rate*100:5.1f}%  {bar}")

    detail = result.get("detail", [])
    if detail:
        print()
        print("  Sample (first 10 READ queries):")
        print(f"  {'Block':>6}  {'Part':>4}  {'GuessedQuery':>20}  "
              f"{'ChosenVal':>20}  {'True':>20}  OK")
        print(f"  {'-'*6}  {'-'*4}  {'-'*20}  {'-'*20}  {'-'*20}  --")
        for d in detail[:10]:
            gq = str(d.get("guessed_query_value")    or "?")[:20]
            cv = str(d.get("chosen_plaintext_value")  or "?")[:20]
            tv = str(d.get("true_value")              or "?")[:20]
            ok = "✓" if d.get("correct") else "✗"
            print(f"  {d['block_id']:>6}  {d['partition_id']:>4}  "
                  f"{gq:>20}  {cv:>20}  {tv:>20}  {ok}")


# ---------------------------------------------------------------------------
# Ground truth helpers
# ---------------------------------------------------------------------------

class _NamespacedTruth:
    """
    Separates GROUP_READ truth (value_code → string) from WRITE truth
    (block_id → string) to avoid integer key collisions.
    Callers use .get(key, op) where op determines which namespace to use.
    Implements dict-like .get() with an op hint.
    """
    def __init__(self, write_truth: dict, group_truth: dict):
        self._w = write_truth
        self._g = group_truth

    def get_for_query(self, q: dict) -> Optional[str]:
        """Look up ground truth for a query dict."""
        if q["op"] == "GROUP_READ":
            vc = q.get("value_code", q["block_id"])
            return self._g.get(vc)
        else:
            return self._w.get(q["block_id"])

    def get(self, key: int, default=None):
        """Fallback dict-like get — checks write_truth only.
        Use get_for_query() when a query dict is available."""
        return self._w.get(key, default)


# ---------------------------------------------------------------------------
# Ground truth builder
# ---------------------------------------------------------------------------

def _build_query_truth_with_map(
    queries: List[dict],
    code_to_value: Dict[str, str],
) -> Dict[int, str]:
    """
    Maps block_id / value_code → plaintext string for correctness evaluation.
    Returns a tuple: (write_truth, group_truth)
      write_truth:  block_id → string (from WRITE entries)
      group_truth:  value_code → string (from GROUP_READ entries via code_to_value)
    Kept separate to avoid collision when value_code == block_id of a WRITE.
    For backward compatibility, returns a special dict that checks group_truth
    first for GROUP_READ lookups, then write_truth for WRITE/READ lookups.
    """
    write_truth: Dict[int, str] = {}
    for q in queries:
        if q["op"] == "WRITE":
            write_truth[q["block_id"]] = str(q.get("data", ""))
    group_truth: Dict[int, str] = {}
    for q in queries:
        if q["op"] == "GROUP_READ":
            vc = q.get("value_code", q["block_id"])
            val = code_to_value.get(str(vc))
            if val:
                group_truth[vc] = val
    # Return a NamespacedTruth object that routes lookups correctly
    return _NamespacedTruth(write_truth, group_truth)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="SEAL leakage-abuse attacks (Query Recovery + Database Recovery)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Workflow:
  1.  python3 server.py
  2.  python3 client.py input.csv output.txt -a 1 -x 2 --query-log queries.jsonl
  3.  python3 attack.py --dataset Crimes_2001.csv --attribute "Primary Type"
                        --query-log queries.jsonl

The attack auto-detects SE mode (result_size > 1) vs prototype mode (result_size = 1).

For the most informative SE-mode results against Chicago crime data:
  - Use group queries in your input file (one READ per keyword value)
  - Compare QRSR across different -x values to see padding effectiveness
  - Compare DRSR across different -a values to see ORAM effectiveness
        """
    )
    p.add_argument("--dataset",   required=True,
                   help="Plaintext CSV (e.g. Crimes_2001_to_Present.csv)")
    p.add_argument("--attribute", required=True,
                   help="Column to attack (e.g. 'Primary Type')")
    p.add_argument("--query-log", required=True, dest="query_log",
                   help="JSON-lines query log from client.py --query-log")
    p.add_argument("--alpha",     type=int, default=None,
                   help="Override α (default: read from log header)")
    p.add_argument("--padding",   type=int, default=None,
                   help="Override x (default: read from log header)")
    p.add_argument("--trials",    type=int, default=100,
                   help="Monte-Carlo trials (default: 100)")
    p.add_argument("--seed",      type=int, default=None,
                   help="Random seed for reproducibility")
    p.add_argument("--skip-db",   action="store_true", dest="skip_db",
                   help="Skip Database Recovery Attack")
    p.add_argument("--json-out",  default=None, dest="json_out",
                   help="Write full results as JSON to this path")
    p.add_argument("--value-map", default=None, dest="value_map",
                   help="Path to value_map.json from prep_input.py. "
                        "Maps integer block data codes back to plaintext strings "
                        "for meaningful attack output against Chicago crime data.")
    return p.parse_args()


def main():
    args  = parse_args()
    rng   = random.Random(args.seed)

    # ── Load query log ────────────────────────────────────────────────────
    if not os.path.exists(args.query_log):
        print(f"[ERROR] Query log not found: {args.query_log}")
        sys.exit(1)

    print(f"Loading query log : {args.query_log} ...", end=" ", flush=True)
    header, queries = load_query_log(args.query_log)
    print(f"{len(queries)} entries.")

    alpha = args.alpha   if args.alpha   is not None else header["alpha"]
    x     = args.padding if args.padding is not None else header["padding_x"]
    P     = 2 ** alpha

    print(f"\nSEAL parameters   : α={alpha} (P={P}), x={x if x is not None else '⊥'}")

    # Load value map if provided (maps integer codes → string values)
    code_to_value: dict = {}
    if args.value_map:
        if not os.path.exists(args.value_map):
            print(f"[ERROR] Value map not found: {args.value_map}")
            sys.exit(1)
        with open(args.value_map) as _vmf:
            _vm = json.load(_vmf)
        code_to_value = {str(k): v for k, v in _vm.get("code_to_value", {}).items()}
        print(f"Value map loaded  : {len(code_to_value)} codes from {args.value_map}")
        # Patch query log entries: translate integer data values to string labels
        for q in queries:
            if q["op"] == "WRITE" and "data" in q:
                q["data"] = code_to_value.get(str(q["data"]), str(q["data"]))

    mode = detect_mode(queries)
    print(f"Attack mode       : {mode.upper()}")

    # ── Load dataset ──────────────────────────────────────────────────────
    if not os.path.exists(args.dataset):
        print(f"\n[ERROR] Dataset not found: {args.dataset}")
        sys.exit(1)

    print(f"Loading dataset   : {args.dataset}")
    print(f"Attribute         : '{args.attribute}' ...", end=" ", flush=True)
    try:
        plaintext_values = load_dataset_column(args.dataset, args.attribute)
    except ValueError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
    print(f"{len(plaintext_values):,} records.")

    freq = Counter(plaintext_values)
    print(f"Distinct values   : {len(freq)}")
    print(f"Top 5 frequencies :")
    for val, cnt in freq.most_common(5):
        print(f"  {str(val)[:40]:40s}  {cnt:>9,}  ({cnt/len(plaintext_values)*100:.1f}%)")

    read_count  = sum(1 for q in queries if q["op"] == "READ")
    group_count = sum(1 for q in queries if q["op"] == "GROUP_READ")
    attackable  = read_count + group_count
    print(f"\nQuery log         : {len(queries)} total, "f"{read_count} READs, {group_count} GROUP_READs")

    if attackable == 0:
        print("\n[WARNING] No READ or GROUP_READ queries in log.")
        print("  → Re-run prep_input.py with --se-mode and regenerate the query log.")
        sys.exit(0)

    # Build ground truth once, shared by both attacks
    _qtruth = _build_query_truth_with_map(queries, code_to_value)

    # ── Attack 1 ──────────────────────────────────────────────────────────
    print(f"\nRunning Query Recovery Attack ({args.trials} trials) ...")
    if mode == "se":
        # slice_freq: frequencies from the dataset slice used to generate queries.
        # This ensures padded_size matching uses the same frequencies the client
        # used, not the full 8.5M dataset which would produce different padded sizes.
        _slice_freq = None
        if args.value_map:
            with open(args.value_map) as _vmf2:
                _vm2 = json.load(_vmf2)
            raw = _vm2.get("frequencies", {})
            _slice_freq = {k: int(v) for k, v in raw.items() if int(v) > 0}
        qr = qr_attack_se_mode(
            plaintext_values, queries, x, args.trials, rng,
            query_truth=_qtruth, slice_freq=_slice_freq
        )
    else:
        qr = qr_attack_prototype_mode(
            plaintext_values, queries, alpha, x, args.trials, rng,
            query_truth=_qtruth
        )
    print_qr(qr, args.attribute, x)

    # ── Attack 2 ──────────────────────────────────────────────────────────
    dr = None
    if not args.skip_db:
        print(f"\nRunning Database Recovery Attack ({args.trials} trials) ...")
        dr = dr_attack(
            plaintext_values, queries, alpha, x,
            qr["detail"], args.trials, rng,
            query_truth=_qtruth
        )
        print_dr(dr, args.attribute, alpha, x)

    # ── Summary ───────────────────────────────────────────────────────────
    section("SUMMARY")
    print(f"  Attribute : {args.attribute}")
    print(f"  SEAL(α={alpha}, x={x if x is not None else '⊥'})")
    print(f"  Mode      : {mode.upper()}")
    print()
    print(f"  Attack 1  QRSR : {qr['qrsr']*100:6.2f}%  "
          f"(baseline {qr['baseline']*100:.2f}%)")
    if dr:
        print(f"  Attack 2  DRSR : {dr['drsr']*100:6.2f}%  "
              f"(greedy   {dr['greedy']*100:.2f}%)")
    print()
    if mode == "prototype":
        print("  ℹ  Prototype mode: each READ accesses exactly 1 block.")
        print("     Volume-based QR attack not applicable (all sizes = 1).")
        print("     For SE-mode volume attacks, use group queries in your input")
        print("     where one logical query returns multiple records.")
        print()
    print("  Tuning guidance:")
    print("    QRSR ≈ baseline → x is effective (or mode is prototype)")
    print("    QRSR >> baseline → increase x for this attribute")
    print("    DRSR ≈ greedy   → α is effective against DB recovery")
    print("    DRSR >> greedy  → decrease α (more partitions = more privacy)")
    print()

    # ── JSON output ───────────────────────────────────────────────────────
    if args.json_out:
        out = {
            "seal_params":     {"alpha": alpha, "padding_x": x, "P": P},
            "attribute":       args.attribute,
            "dataset_size":    len(plaintext_values),
            "distinct_values": len(freq),
            "mode":            mode,
            "query_recovery":  {k:v for k,v in qr.items() if k != "detail"},
        }
        if dr:
            out["database_recovery"] = {k:v for k,v in dr.items() if k != "detail"}
        with open(args.json_out, 'w') as jf:
            json.dump(out, jf, indent=2)
        print(f"✓ Full results written to: {args.json_out}")

    print("="*62)


if __name__ == "__main__":
    main()
