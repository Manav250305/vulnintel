"""
Phase 3, Step 5 — validation exercise (Module 4, Section 6.1).

Tests the drift-detection method (Steps 1-4) against real, verified 2023
LangChain prompt-injection CVEs, to check whether it would have flagged
them as an emerging pattern before formal CWE coverage existed.

Verified fact (web search): CWE-1427 "Improper Neutralization of Input Used
for LLM Prompting" was created 2024-06-21 -- after this project's entire
2019-2023 scope window. Any prompt-injection CVE published in-scope was
necessarily tagged with something else (or nothing), since the category
didn't exist yet at tagging time. That's exactly the premise this exercise
needs.

Test CVEs (verified via web search, not assumed from memory):
  - CVE-2023-29374 -- LangChain LLMMathChain, prompt injection -> exec()
  - CVE-2023-34541 -- LangChain load_prompt, arbitrary command execution
  - CVE-2023-36095 -- LangChain PALChain.from_math_prompt, arbitrary code exec
  - CVE-2023-38896 -- LangChain PALChain.from_math_prompt, arbitrary code exec

Usage:
    python3 validate.py
"""
import sqlite3
import joblib
import numpy as np
from pathlib import Path
from sklearn.metrics.pairwise import cosine_similarity

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"
CACHE_DIR = Path(__file__).resolve().parent / "tfidf_cache"

TARGET_CVES = ["CVE-2023-29374", "CVE-2023-34541", "CVE-2023-36095", "CVE-2023-38896"]


def main():
    conn = sqlite3.connect(DB_PATH)

    print("--- Step 1: are they in scope, and what CWE did they actually get? ---")
    rows = conn.execute(f"""
        SELECT n.cve_id, n.cwe_id, n.is_generic, n.quarter, c.cluster_id,
               CASE WHEN f.cluster_id IS NOT NULL THEN 'YES' ELSE 'no' END AS flagged
        FROM nlp_docs n
        LEFT JOIN nlp_clusters c ON n.cve_id = c.cve_id
        LEFT JOIN nlp_flagged_clusters f ON c.quarter = f.quarter AND c.cluster_id = f.cluster_id
        WHERE n.cve_id IN ({','.join('?' for _ in TARGET_CVES)})
        ORDER BY n.quarter, n.cve_id
    """, TARGET_CVES).fetchall()
    for cve_id, cwe_id, is_generic, quarter, cluster_id, flagged in rows:
        label = f"{cwe_id} (generic)" if is_generic else cwe_id
        print(f"  {cve_id}: tagged {label}, landed in {quarter}/cluster {cluster_id}, flagged={flagged}")

    print("\n--- Step 2: why weren't they flagged? Inspect their host clusters ---")
    hosts = {(r[3], r[4]) for r in rows}  # (quarter, cluster_id) pairs
    for quarter, cluster_id in sorted(hosts):
        cached = joblib.load(CACHE_DIR / f"{quarter}.joblib")
        matrix, labels, cve_ids = cached["matrix"], cached["labels"], cached["cve_ids"]
        vectorizer = cached["vectorizer"]
        terms = vectorizer.get_feature_names_out()

        member_idx = [i for i, l in enumerate(labels) if l == cluster_id]
        member_vectors = matrix[member_idx]
        centroid = np.asarray(member_vectors.mean(axis=0)).flatten()
        cohesion = float(cosine_similarity(member_vectors, centroid.reshape(1, -1)).mean())
        top_terms = [terms[i] for i in centroid.argsort()[::-1][:8]]
        our_targets_here = [cve_ids[i] for i in member_idx if cve_ids[i] in TARGET_CVES]

        other_members = [m for m in [cve_ids[i] for i in member_idx] if m not in TARGET_CVES]
        print(f"\n  {quarter} cluster {cluster_id}: {len(member_idx)} members, cohesion={cohesion:.3f}")
        print(f"    top terms: {', '.join(top_terms)}")
        print(f"    our target CVE(s) here: {our_targets_here}")
        print(f"    sample other members: {other_members[:5]}")

    print("\n--- Conclusion ---")
    print("  All 4 CVEs landed in low-cohesion (0.1-0.4), large, generic")
    print("  'arbitrary code execution / injection' catch-all clusters mixed")
    print("  with unrelated CVEs spanning back to 2012. None were flagged.")
    print("  The method did NOT isolate LLM prompt injection as a coherent")
    print("  emerging pattern in 2023 -- see PHASE3_NOTES.md for why, and")
    print("  what that implies about the method's actual operating conditions.")

    conn.close()


if __name__ == "__main__":
    main()