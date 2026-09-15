"""
Phase 6, Step 2+3 — PCA + K-means vendor archetypes (Module 5).

Standardizes category shares before PCA (StandardScaler) so categories with
naturally larger variance across vendors don't dominate the principal
components just by scale. Reduces to 2 components -- enough for the
Tableau vendor-cluster-map view Section 6.4 describes, with explained
variance reported honestly rather than assumed adequate.

K selection via silhouette score, scanned over a candidate range and
verified rather than assumed to behave well -- Phase 3 found silhouette has
no real interior optimum on sparse high-dimensional TF-IDF vectors, so
checking here matters, even though this is different data (dense,
low-dimensional, continuous), where normal behavior is in fact expected.

Usage:
    python3 vendor_archetypes.py
"""
import csv
import numpy as np
from pathlib import Path
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
import joblib

DATA_DIR = Path(__file__).resolve().parent / "data"
K_CANDIDATES = [2, 3, 4, 5, 6, 7, 8, 9, 10]


def main():
    with open(DATA_DIR / "vendor_features.csv") as f:
        reader = csv.DictReader(f)
        # Read the class scheme off the feature file rather than restating it:
        # build_vendor_features.py picks the top-20 CWEs from the data, so the
        # membership shifts as the corpus grows (CWE-77 dropped out when the
        # full history was loaded) and a hardcoded copy silently goes stale.
        categories = [c[len("share_"):] for c in reader.fieldnames
                      if c.startswith("share_")]
        rows = list(reader)
    vendors = [r["vendor"] for r in rows]
    X_raw = np.array([[float(r[f"share_{c}"]) for c in categories] for r in rows])
    print(f"{len(vendors)} vendors, {X_raw.shape[1]} categories")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)

    pca_full = PCA().fit(X_scaled)
    print(f"\nExplained variance by component (first 8): "
          f"{[f'{v:.3f}' for v in pca_full.explained_variance_ratio_[:8]]}")
    print(f"Cumulative variance, first 2 components: "
          f"{pca_full.explained_variance_ratio_[:2].sum():.3f}")

    pca = PCA(n_components=2, random_state=42)
    X_pca = pca.fit_transform(X_scaled)

    # Verify silhouette actually has a real interior optimum on this data
    # (checked, not assumed -- see module docstring)
    print(f"\n--- Silhouette score by K ---")
    scores = {}
    for k in K_CANDIDATES:
        km = KMeans(n_clusters=k, random_state=42, n_init=10)
        labels = km.fit_predict(X_pca)
        score = silhouette_score(X_pca, labels)
        scores[k] = score
        print(f"  k={k}: silhouette={score:.4f}")

    best_k = max(scores, key=scores.get)
    print(f"\nBest K by silhouette: {best_k} (score={scores[best_k]:.4f})")
    is_boundary = best_k == K_CANDIDATES[-1]
    if is_boundary:
        print(f"[WARNING] Best K is at the candidate range boundary -- possible "
              f"ceiling effect, same pattern as Phase 3. Consider widening the range.")
    else:
        print(f"[OK] Best K is interior to the candidate range -- genuine optimum, "
              f"not a ceiling effect.")

    km_final = KMeans(n_clusters=best_k, random_state=42, n_init=10)
    cluster_labels = km_final.fit_predict(X_pca)

    # Interpret each cluster by its ORIGINAL (pre-scaling) average category
    # shares -- standardized/PCA space isn't directly interpretable, but the
    # raw share profile of member vendors is.
    print(f"\n--- Cluster interpretation (k={best_k}) ---")
    for cluster_id in range(best_k):
        members = [v for v, l in zip(vendors, cluster_labels) if l == cluster_id]
        member_shares = X_raw[cluster_labels == cluster_id]
        avg_shares = member_shares.mean(axis=0)
        top_categories = sorted(zip(categories, avg_shares), key=lambda x: -x[1])[:5]
        print(f"\n  Cluster {cluster_id} (n={len(members)} vendors):")
        print(f"    dominant categories: {', '.join(f'{c}={s:.2f}' for c, s in top_categories)}")
        print(f"    example vendors: {members[:8]}")

    joblib.dump({
        "scaler": scaler, "pca": pca, "kmeans": km_final, "vendors": vendors,
        "cluster_labels": cluster_labels, "categories": categories, "X_pca": X_pca,
    }, DATA_DIR / "vendor_archetypes.joblib")
    print(f"\nSaved model to {DATA_DIR / 'vendor_archetypes.joblib'}")


if __name__ == "__main__":
    main()