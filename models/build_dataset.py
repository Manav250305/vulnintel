"""
Phase 5, Step 1 — build the labeled classifier dataset (Module 3).

Class scheme: "top-level CWE category" is interpreted here as the top 20
most frequent real (non-generic) CWE labels, individually, with everything
else bucketed into "Other" -- 21 classes total, covering 68.6% of all
real-CWE CVEs directly and the remaining long tail (346 other categories)
via the catch-all. A true MITRE CWE-hierarchy rollup would be a more
literal reading of "top-level category," but requires sourcing external
hierarchy data for a rollup that wouldn't materially change the
classification demonstration -- documented here as the practical choice.

Only CVEs with a real (non-generic) canonical CWE are included -- a CVE
tagged NVD-CWE-Other or with no CWE at all has no meaningful ground truth
to train or evaluate against.

Split: time-based per design doc Section 6.3 -- train on published_year
< 2021, test on >= 2021 -- specifically to allow checking whether accuracy
degrades on later data as a drift signal (Step 3), not just to get a
representative accuracy number the way a random split would.

Usage:
    python3 build_dataset.py
"""
import sqlite3
import csv
import collections
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"
OUT_DIR = Path(__file__).resolve().parent / "data"
TOP_K = 20
SPLIT_YEAR = 2021  # train: < 2021, test: >= 2021


def main():
    OUT_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)

    top_cwes = [r[0] for r in conn.execute("""
        SELECT cwe_id FROM v_canonical_cwe WHERE is_generic = 0
        GROUP BY cwe_id ORDER BY COUNT(*) DESC LIMIT ?
    """, (TOP_K,)).fetchall()]
    top_cwe_set = set(top_cwes)
    print(f"Top {TOP_K} classes: {top_cwes}")

    rows = conn.execute("""
        SELECT n.cve_id, n.cleaned_description, n.cwe_id, n.quarter
        FROM nlp_docs n
        WHERE n.cwe_id IS NOT NULL AND n.is_generic = 0
    """).fetchall()

    dataset = []
    for cve_id, desc, cwe_id, quarter in rows:
        year = int(quarter[:4])
        label = cwe_id if cwe_id in top_cwe_set else "Other"
        split = "train" if year < SPLIT_YEAR else "test"
        dataset.append((cve_id, desc, cwe_id, label, year, split))

    with open(OUT_DIR / "classifier_dataset.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cve_id", "cleaned_description", "raw_cwe", "label", "year", "split"])
        w.writerows(dataset)

    print(f"\nTotal labeled examples: {len(dataset)}")
    by_split = collections.Counter(d[5] for d in dataset)
    print(f"Train (year < {SPLIT_YEAR}): {by_split['train']}")
    print(f"Test (year >= {SPLIT_YEAR}):  {by_split['test']}")

    print(f"\n--- Class distribution (train) ---")
    train_labels = collections.Counter(d[3] for d in dataset if d[5] == "train")
    for label, n in train_labels.most_common():
        print(f"  {label:<10} {n:>6}")

    print(f"\n--- Class distribution (test) ---")
    test_labels = collections.Counter(d[3] for d in dataset if d[5] == "test")
    for label, n in test_labels.most_common():
        print(f"  {label:<10} {n:>6}")

    # Check for any class present in test but completely absent from train --
    # the classifier could never predict it correctly if so.
    missing = set(test_labels) - set(train_labels)
    if missing:
        print(f"\n[WARNING] Classes in test but never seen in train: {missing}")
    else:
        print(f"\n[OK] Every test-set class was seen at least once in training")

    conn.close()


if __name__ == "__main__":
    main()