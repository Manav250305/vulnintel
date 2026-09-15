"""
Phase 4, Step 1 — build the CWE-CWE co-occurrence matrix (Module 6).

Co-occurrence is defined at vendor/product-year granularity per the design
doc's Section 5.2 load-bearing decision: two CWE categories co-occur if both
appear among vulnerabilities affecting the same vendor's product in the same
year. A single CVE almost always has one CWE, so co-occurrence can't be
derived directly from cve_cwe -- it has to be built from these shared
"incident buckets" instead.

Design decision: generic NVD placeholder labels (NVD-CWE-Other,
NVD-CWE-noinfo) are excluded from the matrix entirely. Co-occurrence between
a real category and "the analyst didn't pick a specific one" doesn't tell
us anything about structural relationships between actual weakness types --
including them would just add noise to every row/column they touch.

Builds the upper triangle only (i < j) -- the Octave power-iteration script
(design doc Section 6.2) symmetrizes with `A = A + A'` itself, so there's no
need to double the work here.

Usage:
    python3 build_cooccurrence.py
"""
import sqlite3
import csv
import re
import collections
import itertools
import numpy as np
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"
OUT_DIR = Path(__file__).resolve().parent / "data"


def cwe_sort_key(cwe_id: str) -> int:
    m = re.match(r"CWE-(\d+)", cwe_id)
    return int(m.group(1)) if m else 999999


def main():
    OUT_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)

    # Raw frequency: how many in-scope CVEs carry each real (non-generic) CWE
    # as their canonical label. Needed later (Step 3) to compare against
    # eigenvector centrality.
    freq_rows = conn.execute("""
        SELECT cwe_id, COUNT(*) FROM v_canonical_cwe
        WHERE is_generic = 0 GROUP BY cwe_id
    """).fetchall()
    cwe_ids = sorted((r[0] for r in freq_rows), key=cwe_sort_key)
    n = len(cwe_ids)
    idx_of = {cwe: i for i, cwe in enumerate(cwe_ids)}
    freq_by_cwe = dict(freq_rows)
    print(f"{n} distinct real CWE categories (generic labels excluded)")

    # One row per (vendor, product, year, cwe_id) present -- a CVE contributes
    # its ONE canonical CWE; duplicate (bucket, cwe_id) rows from multiple
    # CVEs sharing a CWE are expected and get deduplicated into a set below.
    rows = conn.execute("""
        SELECT vendor, product, published_year, cwe_id
        FROM (
            SELECT DISTINCT cp.vendor, cp.product, cv.published_year, cp.cve_id
            FROM cve_cpe cp JOIN cves_in_scope cv ON cp.cve_id = cv.id
        ) vp
        JOIN v_canonical_cwe c ON vp.cve_id = c.cve_id
        WHERE c.is_generic = 0
    """).fetchall()

    buckets = collections.defaultdict(set)
    for vendor, product, year, cwe_id in rows:
        buckets[(vendor, product, year)].add(cwe_id)

    print(f"{len(buckets)} vendor-product-year buckets scanned")

    A = np.zeros((n, n), dtype=np.int64)
    multi_cwe_buckets = 0
    for cwe_set in buckets.values():
        if len(cwe_set) < 2:
            continue
        multi_cwe_buckets += 1
        for cwe_a, cwe_b in itertools.combinations(sorted(cwe_set, key=cwe_sort_key), 2):
            i, j = idx_of[cwe_a], idx_of[cwe_b]
            A[i, j] += 1  # upper triangle only (i < j by construction)

    print(f"{multi_cwe_buckets} buckets contributed >=1 co-occurrence pair "
          f"({100*multi_cwe_buckets/len(buckets):.1f}% of all buckets)")
    print(f"Matrix density (upper triangle nonzero): "
          f"{100*np.count_nonzero(A)/(n*(n-1)/2):.1f}%")
    print(f"Max single pairwise co-occurrence count: {A.max()}")

    # Export for Octave
    np.savetxt(OUT_DIR / "cooccurrence_matrix.csv", A, delimiter=",", fmt="%d")
    with open(OUT_DIR / "cwe_index.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["index", "cwe_id", "raw_frequency"])
        for i, cwe in enumerate(cwe_ids):
            w.writerow([i + 1, cwe, freq_by_cwe[cwe]])  # 1-indexed for Octave

    print(f"\nWrote {OUT_DIR / 'cooccurrence_matrix.csv'} ({n}x{n})")
    print(f"Wrote {OUT_DIR / 'cwe_index.csv'} (index -> CWE ID + raw frequency)")

    # Sanity check: top 10 co-occurring pairs by raw count
    print("\n--- Top 10 co-occurring CWE pairs (raw count) ---")
    pairs = [(A[i, j], cwe_ids[i], cwe_ids[j]) for i in range(n) for j in range(i + 1, n) if A[i, j] > 0]
    for count, a, b in sorted(pairs, reverse=True)[:10]:
        print(f"  {a} <-> {b}: {count}")

    conn.close()


if __name__ == "__main__":
    main()