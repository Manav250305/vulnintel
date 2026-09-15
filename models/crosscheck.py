"""
Phase 5, Step 4 — cross-check against the co-occurrence network (Module 3).

Per design doc Section 6.3: for the most confused category pairs in the
classifier's confusion matrix, look up their edge weight in the Octave
co-occurrence matrix from Phase 4. Agreement between an independently
trained classifier and the structural network is stronger evidence than
either method alone.

"Other" is excluded from this cross-check -- it's a catch-all bucket for
346 different real CWEs, not itself a CWE with a co-occurrence edge weight
to look up.

Usage:
    python3 crosscheck.py
"""
import csv
import numpy as np
import joblib
from pathlib import Path

MODELS_DATA = Path(__file__).resolve().parent / "data"
OCTAVE_DATA = Path(__file__).resolve().parent.parent / "octave" / "data"


def main():
    results = joblib.load(MODELS_DATA / "classifier_results.joblib")
    cm, labels = results["confusion_matrix"], results["labels_sorted"]

    with open(OCTAVE_DATA / "cwe_index.csv") as f:
        cwe_index_rows = list(csv.DictReader(f))
    cwe_to_idx = {r["cwe_id"]: int(r["index"]) - 1 for r in cwe_index_rows}  # back to 0-indexed
    A = np.loadtxt(OCTAVE_DATA / "cooccurrence_matrix.csv", delimiter=",")
    A = A + A.T  # symmetrize, same as Phase 4

    # Find top confused pairs (off-diagonal), combining both directions
    # (true=A/pred=B and true=B/pred=A both count as "confusion between A and B")
    n = len(labels)
    pair_confusion = {}
    for i in range(n):
        for j in range(n):
            if i == j or labels[i] == "Other" or labels[j] == "Other":
                continue
            key = tuple(sorted([labels[i], labels[j]]))
            pair_confusion[key] = pair_confusion.get(key, 0) + cm[i, j]

    print("--- Top 15 most-confused CWE pairs vs. their co-occurrence edge weight ---")
    print(f"{'pair':<25} {'confusion_count':>15} {'cooccurrence_weight':>20}")
    rows_out = []
    for (a, b), confusion_count in sorted(pair_confusion.items(), key=lambda x: -x[1])[:15]:
        weight = A[cwe_to_idx[a], cwe_to_idx[b]] if a in cwe_to_idx and b in cwe_to_idx else None
        weight_str = f"{weight:.0f}" if weight is not None else "N/A"
        print(f"{a}<->{b:<15} {confusion_count:>15} {weight_str:>20}")
        rows_out.append((a, b, confusion_count, weight))

    # Correlation between confusion count and co-occurrence weight, across
    # ALL pairs that appear in the confusion matrix at all (not just top 15) --
    # the actual "agreement between methods" the design doc asks about.
    all_pairs = [(a, b, c, A[cwe_to_idx[a], cwe_to_idx[b]])
                 for (a, b), c in pair_confusion.items()
                 if a in cwe_to_idx and b in cwe_to_idx and c > 0]
    confusions = [p[2] for p in all_pairs]
    weights = [p[3] for p in all_pairs]
    from scipy.stats import spearmanr
    rho, p_value = spearmanr(confusions, weights)
    print(f"\nSpearman correlation (confusion count vs. co-occurrence weight, "
          f"n={len(all_pairs)} pairs): rho={rho:.3f} (p={p_value:.2e})")


if __name__ == "__main__":
    main()