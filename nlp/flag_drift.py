"""
Phase 3, Step 4 — the actual drift signal (Module 4).

For every (quarter, cluster) from Step 3, computes:
  - cohesion: mean cosine similarity of members to their cluster centroid
    (how tight/textually coherent the cluster actually is)
  - generic_rate: fraction of CWE-labeled members whose canonical CWE is a
    generic NVD placeholder (NVD-CWE-Other / NVD-CWE-noinfo)
  - no_cwe_rate: fraction of members with no CWE assignment at all
  - cwe_entropy: Shannon entropy (bits) of the distribution of *real*
    (non-generic) CWE labels among members that have one -- high entropy
    means analysts are scattering textually-similar CVEs across many
    different real CWE categories, not agreeing on one

Kept as three separate signals rather than one blended score because the
design doc names two distinct failure modes ("inconsistent OR generic") --
collapsing them would hide which failure mode is driving a given flag.

Flagging rule: a cluster is flagged if its cohesion is in the top quartile
for its quarter (genuinely tight, not a diffuse catch-all bucket) AND its
uncategorized_rate (generic_rate + no_cwe_rate) OR cwe_entropy is in the top
quartile for its quarter. Quartiles are computed per-quarter, not globally,
since TF-IDF cohesion values aren't directly comparable across quarters with
different vocabularies and document counts.

Usage:
    python3 flag_drift.py
"""
import sqlite3
import math
import collections
import joblib
import numpy as np
from pathlib import Path
from sklearn.metrics.pairwise import cosine_similarity

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"
CACHE_DIR = Path(__file__).resolve().parent / "tfidf_cache"


def shannon_entropy(counts: list) -> float:
    total = sum(counts)
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts if c > 0)


def analyze_cluster(matrix, labels, cluster_id, cve_ids, cwe_lookup):
    member_idx = [i for i, l in enumerate(labels) if l == cluster_id]
    member_vectors = matrix[member_idx]
    centroid = np.asarray(member_vectors.mean(axis=0)).flatten()
    cohesion = float(cosine_similarity(member_vectors, centroid.reshape(1, -1)).mean())

    member_cve_ids = [cve_ids[i] for i in member_idx]
    n = len(member_cve_ids)
    n_generic, n_no_cwe = 0, 0
    real_cwe_counts = collections.Counter()
    for cve_id in member_cve_ids:
        cwe_id, is_generic = cwe_lookup.get(cve_id, (None, None))
        if cwe_id is None:
            n_no_cwe += 1
        elif is_generic:
            n_generic += 1
        else:
            real_cwe_counts[cwe_id] += 1

    generic_rate = n_generic / n
    no_cwe_rate = n_no_cwe / n
    cwe_entropy = shannon_entropy(list(real_cwe_counts.values()))
    top_real_cwes = real_cwe_counts.most_common(3)

    return {
        "cluster_id": cluster_id, "size": n, "cohesion": cohesion,
        "generic_rate": generic_rate, "no_cwe_rate": no_cwe_rate,
        "uncategorized_rate": generic_rate + no_cwe_rate,
        "n_distinct_real_cwe": len(real_cwe_counts), "cwe_entropy": cwe_entropy,
        "top_real_cwes": top_real_cwes,
    }


def main():
    conn = sqlite3.connect(DB_PATH)
    cwe_lookup = {
        cve_id: (cwe_id, bool(is_generic))
        for cve_id, cwe_id, is_generic in conn.execute(
            "SELECT cve_id, cwe_id, is_generic FROM nlp_docs"
        )
    }

    conn.execute("DROP TABLE IF EXISTS nlp_flagged_clusters")
    conn.execute("""
        CREATE TABLE nlp_flagged_clusters (
            quarter TEXT NOT NULL, cluster_id INTEGER NOT NULL, size INTEGER,
            cohesion REAL, generic_rate REAL, no_cwe_rate REAL,
            uncategorized_rate REAL, n_distinct_real_cwe INTEGER, cwe_entropy REAL,
            top_terms TEXT, top_real_cwes TEXT,
            PRIMARY KEY (quarter, cluster_id)
        )
    """)

    all_flagged = []
    total_clusters = 0

    for cache_file in sorted(CACHE_DIR.glob("*.joblib")):
        quarter = cache_file.stem
        cached = joblib.load(cache_file)
        matrix, labels, cve_ids = cached["matrix"], cached["labels"], cached["cve_ids"]
        vectorizer, km = cached["vectorizer"], cached["kmeans"]
        terms = vectorizer.get_feature_names_out()

        cluster_stats = [
            analyze_cluster(matrix, labels, cid, cve_ids, cwe_lookup)
            for cid in range(cached["k"])
        ]
        total_clusters += len(cluster_stats)

        cohesions = [c["cohesion"] for c in cluster_stats]
        uncategorized = [c["uncategorized_rate"] for c in cluster_stats]
        entropies = [c["cwe_entropy"] for c in cluster_stats]
        cohesion_p75 = np.percentile(cohesions, 75)
        uncategorized_p75 = np.percentile(uncategorized, 75)
        entropy_p75 = np.percentile(entropies, 75)

        for c in cluster_stats:
            is_tight = c["cohesion"] >= cohesion_p75
            is_scattered = (c["uncategorized_rate"] >= uncategorized_p75) or (c["cwe_entropy"] >= entropy_p75)
            if is_tight and is_scattered and c["size"] >= 15:  # avoid flagging noise-sized clusters
                member_idx = [i for i, l in enumerate(labels) if l == c["cluster_id"]]
                centroid = np.asarray(matrix[member_idx].mean(axis=0)).flatten()
                top_terms = [terms[i] for i in centroid.argsort()[::-1][:8]]
                all_flagged.append({
                    "quarter": quarter, **c,
                    "top_terms": ", ".join(top_terms),
                    "top_real_cwes_str": ", ".join(f"{cwe}({n})" for cwe, n in c["top_real_cwes"]),
                })

    conn.executemany(
        "INSERT INTO nlp_flagged_clusters "
        "(quarter, cluster_id, size, cohesion, generic_rate, no_cwe_rate, "
        "uncategorized_rate, n_distinct_real_cwe, cwe_entropy, top_terms, top_real_cwes) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [(f["quarter"], f["cluster_id"], f["size"], f["cohesion"], f["generic_rate"],
          f["no_cwe_rate"], f["uncategorized_rate"], f["n_distinct_real_cwe"], f["cwe_entropy"],
          f["top_terms"], f["top_real_cwes_str"]) for f in all_flagged],
    )
    conn.commit()

    print(f"Total clusters across all quarters: {total_clusters}")
    print(f"Flagged (tight AND scattered, size>=15): {len(all_flagged)} "
          f"({100*len(all_flagged)/total_clusters:.1f}%)")

    print(f"\n--- Flagged clusters per quarter ---")
    by_quarter = collections.Counter(f["quarter"] for f in all_flagged)
    for q in sorted(by_quarter):
        print(f"  {q}: {by_quarter[q]}")

    print(f"\n--- Top 15 flagged clusters by size (largest = most evidence) ---")
    for f in sorted(all_flagged, key=lambda x: -x["size"])[:15]:
        print(f"\n[{f['quarter']} cluster {f['cluster_id']}] size={f['size']} "
              f"cohesion={f['cohesion']:.3f} uncategorized={f['uncategorized_rate']:.2f} "
              f"entropy={f['cwe_entropy']:.2f} n_distinct_cwe={f['n_distinct_real_cwe']}")
        print(f"  terms: {f['top_terms']}")
        print(f"  top real CWEs present: {f['top_real_cwes_str'] or '(none)'}")

    conn.close()


if __name__ == "__main__":
    main()