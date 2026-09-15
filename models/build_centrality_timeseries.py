"""
Model 2 (stretch goal), Step A — per-year centrality time series.

Phase 4 computed ONE pooled centrality vector across the full 2019-2023
window. Forecasting "next year's centrality" needs a time series instead --
one co-occurrence matrix and centrality vector PER YEAR. Reuses Phase 4's
fixed 366-CWE index (octave/data/cwe_index.csv) so every year's vector is
directly comparable position-for-position, rather than each year silently
having a different CWE universe.

Note on method: Phase 4's actual deliverable was demonstrating manual power
iteration in Octave, which is already done and verified (cross-validated
against numpy.linalg.eigh to 2e-10). Repeating that exact manual exercise 5
more times here, for a stretch-goal's feature engineering, isn't the
pedagogical point of Module 6 -- eigh is used directly for these auxiliary
per-year vectors, since it's already been shown equivalent.

Usage:
    python3 build_centrality_timeseries.py
"""
import sqlite3
import csv
import itertools
import collections
import numpy as np
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"
OCTAVE_DATA = Path(__file__).resolve().parent.parent / "octave" / "data"
OUT_DIR = Path(__file__).resolve().parent / "data"

# Years are read from the data rather than hardcoded, but the pre-1999 records
# (1988-1998, all under 300 CVEs each) are too thin to build a meaningful
# 366x366 co-occurrence matrix from -- they'd contribute near-empty vectors
# that read as "this CWE vanished" rather than "nothing was catalogued yet".
MIN_YEAR_CVES = 500


def analysis_years(conn):
    return [y for (y,) in conn.execute(
        "SELECT published_year FROM cves GROUP BY published_year "
        "HAVING COUNT(*) >= ? ORDER BY published_year", (MIN_YEAR_CVES,))]


def main():
    OUT_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    YEARS = analysis_years(conn)
    print(f"Building centrality for {len(YEARS)} years: {YEARS[0]}-{YEARS[-1]}")

    with open(OCTAVE_DATA / "cwe_index.csv") as f:
        cwe_index_rows = list(csv.DictReader(f))
    cwe_ids = [r["cwe_id"] for r in cwe_index_rows]
    idx_of = {cwe: i for i, cwe in enumerate(cwe_ids)}
    n = len(cwe_ids)
    print(f"Using Phase 4's fixed {n}-CWE universe for all years")

    rows_out = []
    for year in YEARS:
        rows = conn.execute("""
            SELECT vendor, product, cwe_id
            FROM (
                SELECT DISTINCT cp.vendor, cp.product, cp.cve_id
                FROM cve_cpe cp JOIN cves_in_scope cv ON cp.cve_id = cv.id
                WHERE cv.published_year = ?
            ) vp
            JOIN v_canonical_cwe c ON vp.cve_id = c.cve_id
            WHERE c.is_generic = 0
        """, (year,)).fetchall()

        buckets = collections.defaultdict(set)
        for vendor, product, cwe_id in rows:
            if cwe_id in idx_of:  # restrict to Phase 4's fixed universe
                buckets[(vendor, product)].add(cwe_id)

        A = np.zeros((n, n))
        for cwe_set in buckets.values():
            if len(cwe_set) < 2:
                continue
            for a, b in itertools.combinations(cwe_set, 2):
                i, j = idx_of[a], idx_of[b]
                A[i, j] += 1
                A[j, i] += 1  # build symmetric directly this time -- simpler for a
                              # per-year loop than carrying the upper-triangle
                              # convention through 5 separate matrices

        # Centrality via eigh (see module docstring for why not manual power
        # iteration here). Non-negative matrix -> dominant eigenvalue is the
        # largest one (Perron-Frobenius), same reasoning as Phase 4.
        # eigh can return either sign for the dominant eigenvector -- pin the
        # sign convention to positive-sum, consistent across all 5 years.
        eigenvalues, eigenvectors = np.linalg.eigh(A)
        dominant = eigenvectors[:, -1]
        centrality = dominant if dominant.sum() >= 0 else -dominant

        degree = (A > 0).sum(axis=1)

        # Raw per-year frequency, for the growth feature in Step B
        freq_rows = dict(conn.execute("""
            SELECT cwe_id, COUNT(*) FROM v_canonical_cwe c
            JOIN cves_in_scope cv ON c.cve_id = cv.id
            WHERE c.is_generic = 0 AND cv.published_year = ?
            GROUP BY cwe_id
        """, (year,)).fetchall())

        for i, cwe_id in enumerate(cwe_ids):
            rows_out.append((cwe_id, year, float(centrality[i]), int(degree[i]),
                              freq_rows.get(cwe_id, 0)))

        print(f"{year}: {len(buckets)} vendor-product buckets, "
              f"{int((A > 0).sum() / 2)} co-occurrence edges")

    with open(OUT_DIR / "centrality_timeseries.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cwe_id", "year", "centrality", "degree", "raw_frequency"])
        w.writerows(rows_out)

    print(f"\nWrote {OUT_DIR / 'centrality_timeseries.csv'} "
          f"({len(rows_out)} rows = {n} CWEs x {len(YEARS)} years)")

    conn.close()


if __name__ == "__main__":
    main()