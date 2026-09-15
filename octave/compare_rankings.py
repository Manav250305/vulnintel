"""
Phase 4, Step 3 — centrality vs. frequency: the core finding (Module 6).

Per design doc Section 6.2: "Divergence between the two rankings is the
central finding of this module: a moderately common weakness that
habitually co-occurs with many other serious weaknesses may be structurally
more important to prioritize than a very frequent but isolated one."

Usage:
    python3 compare_rankings.py
"""
import csv
import numpy as np
from pathlib import Path
from scipy.stats import spearmanr

DATA_DIR = Path(__file__).resolve().parent / "data"


def main():
    with open(DATA_DIR / "cwe_index.csv") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    cwe_ids = [r["cwe_id"] for r in rows]
    raw_freq = np.array([int(r["raw_frequency"]) for r in rows])
    centrality = np.loadtxt(DATA_DIR / "centrality_scores.csv", delimiter=",")

    n = len(cwe_ids)
    # Rank 1 = highest. argsort ascending, so reverse for descending rank.
    rank_freq = n - np.argsort(np.argsort(raw_freq))
    rank_centrality = n - np.argsort(np.argsort(centrality))

    rho, p_value = spearmanr(raw_freq, centrality)
    print(f"Spearman rank correlation (frequency vs. centrality): {rho:.3f} (p={p_value:.2e})")
    print(f"({n} CWE categories compared)\n")

    print("--- Top 10 by raw frequency ---")
    for i in np.argsort(-raw_freq)[:10]:
        print(f"  {cwe_ids[i]:<10} freq_rank={rank_freq[i]:>3}  centrality_rank={rank_centrality[i]:>3}  "
              f"freq={raw_freq[i]:>6}  centrality={centrality[i]:.4f}")

    print("\n--- Top 10 by eigenvector centrality ---")
    for i in np.argsort(-centrality)[:10]:
        print(f"  {cwe_ids[i]:<10} centrality_rank={rank_centrality[i]:>3}  freq_rank={rank_freq[i]:>3}  "
              f"centrality={centrality[i]:.4f}  freq={raw_freq[i]:>6}")

    # The actual finding: divergence between the two rankings. Restricted to
    # CWEs with freq >= 20 (132 of 366 categories) -- below that, both ranks
    # are dominated by ties among near-singleton categories, where "rank"
    # is essentially noise, not signal. An unfiltered version of this
    # comparison was tried first and came back entirely populated by
    # freq=1..3 categories at the tail -- not the "moderately common
    # weakness" story Section 6.2 is actually asking for.
    FREQ_FLOOR = 20
    keep = raw_freq >= FREQ_FLOOR
    print(f"\n=== Divergence analysis restricted to freq >= {FREQ_FLOOR} ({keep.sum()} of {n} CWEs) ===")

    f_cwe_ids = [c for c, k in zip(cwe_ids, keep) if k]
    f_raw_freq = raw_freq[keep]
    f_centrality = centrality[keep]
    m = len(f_cwe_ids)
    f_rank_freq = m - np.argsort(np.argsort(f_raw_freq))
    f_rank_centrality = m - np.argsort(np.argsort(f_centrality))
    divergence = f_rank_freq - f_rank_centrality  # positive = centrality rank better than freq rank

    print(f"\n--- Top 10 'structurally underrated by raw frequency' (within freq>={FREQ_FLOOR} set) ---")
    for i in np.argsort(-divergence)[:10]:
        print(f"  {f_cwe_ids[i]:<10} freq_rank={f_rank_freq[i]:>3} -> centrality_rank={f_rank_centrality[i]:>3}  "
              f"(freq={f_raw_freq[i]}, centrality={f_centrality[i]:.4f})")

    print(f"\n--- Top 10 'frequent but relatively isolated' (within freq>={FREQ_FLOOR} set) ---")
    for i in np.argsort(divergence)[:10]:
        print(f"  {f_cwe_ids[i]:<10} freq_rank={f_rank_freq[i]:>3} -> centrality_rank={f_rank_centrality[i]:>3}  "
              f"(freq={f_raw_freq[i]}, centrality={f_centrality[i]:.4f})")


if __name__ == "__main__":
    main()