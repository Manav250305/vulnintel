"""
Phase 3, Step 3 — clustering within each quarter (Module 4).

Fits K-means separately per quarter (matching Step 2's per-quarter TF-IDF
vectorization).

K selection: originally attempted via silhouette-score maximization over a
candidate range -- diagnostic testing showed silhouette climbs monotonically
on this data (checked up to k=130 on a 6,347-doc quarter, score still rising
with no plateau), a known pathology of silhouette maximization on sparse,
high-dimensional TF-IDF vectors. It has no genuine interior optimum here; it
just keeps preferring more, smaller clusters. That criterion is the wrong
tool for this data, and following it would push toward near-singleton
clusters -- useless for Step 4, which needs clusters large enough that
"are the CWE labels within this cluster consistent or scattered" is a
meaningful question to ask.

Fixed by choosing K from a target average cluster size instead -- a
purpose-driven choice tied to what Step 4 actually needs, rather than a
statistic with no real optimum in this regime. Silhouette is still computed
and reported per quarter, but as a diagnostic only, not the selection
criterion.

Usage:
    python3 cluster.py
"""
import sqlite3
import joblib
from pathlib import Path
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"
CACHE_DIR = Path(__file__).resolve().parent / "tfidf_cache"

TARGET_CLUSTER_SIZE = 50  # aim for ~50 docs/cluster on average
MIN_K = 10
SILHOUETTE_SAMPLE_SIZE = 1500  # subsample for speed; silhouette_score is O(n^2)
RANDOM_STATE = 42


def choose_k(n_docs):
    return max(MIN_K, round(n_docs / TARGET_CLUSTER_SIZE))


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS nlp_clusters")
    conn.execute("""
        CREATE TABLE nlp_clusters (
            cve_id TEXT PRIMARY KEY,
            quarter TEXT NOT NULL,
            cluster_id INTEGER NOT NULL
        )
    """)

    cache_files = sorted(CACHE_DIR.glob("*.joblib"))
    print(f"{len(cache_files)} quarter caches found")

    summary = []
    for cache_file in cache_files:
        quarter = cache_file.stem
        cached = joblib.load(cache_file)
        vectorizer, matrix, cve_ids = cached["vectorizer"], cached["matrix"], cached["cve_ids"]

        k = choose_k(len(cve_ids))
        km = KMeans(n_clusters=k, random_state=RANDOM_STATE, n_init=5)
        labels = km.fit_predict(matrix)
        score = silhouette_score(matrix, labels, sample_size=min(SILHOUETTE_SAMPLE_SIZE, len(cve_ids)),
                                  random_state=RANDOM_STATE)

        conn.executemany(
            "INSERT INTO nlp_clusters (cve_id, quarter, cluster_id) VALUES (?,?,?)",
            [(cve_id, quarter, int(label)) for cve_id, label in zip(cve_ids, labels)],
        )
        summary.append((quarter, len(cve_ids), k, score))

        # Cache the fitted model + labels for Step 4 (CWE-inconsistency flagging)
        joblib.dump(
            {"vectorizer": vectorizer, "matrix": matrix, "cve_ids": cve_ids,
             "kmeans": km, "labels": labels, "k": k},
            cache_file,  # overwrite with clustering added
        )

    conn.commit()

    print(f"\n{'quarter':>10} {'docs':>7} {'k':>4} {'avg_size':>9} {'silhouette':>11}")
    for quarter, n_docs, k, score in summary:
        print(f"{quarter:>10} {n_docs:>7} {k:>4} {n_docs/k:>9.1f} {score:>11.3f}")

    # Verification: cluster size distribution + top terms for one example quarter
    example_quarter = summary[len(summary) // 2][0]  # a middle quarter, not first/last
    cached = joblib.load(CACHE_DIR / f"{example_quarter}.joblib")
    vectorizer, km, labels = cached["vectorizer"], cached["kmeans"], cached["labels"]
    terms = vectorizer.get_feature_names_out()

    print(f"\n--- Cluster sizes and top terms, {example_quarter} (k={cached['k']}) ---")
    import collections
    sizes = collections.Counter(labels)
    for cluster_id in sorted(sizes, key=lambda c: -sizes[c])[:15]:  # top 15 by size
        centroid = km.cluster_centers_[cluster_id]
        top_terms = [terms[i] for i in centroid.argsort()[::-1][:6]]
        print(f"  cluster {cluster_id} (n={sizes[cluster_id]}): {', '.join(top_terms)}")

    conn.close()


if __name__ == "__main__":
    main()