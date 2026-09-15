"""
Phase 7, Export 2 — vendor cluster map (Module 7, dashboard view 2).

Exports the pooled 2019-2023 vendor archetype clustering from Phase 6:
vendor, its 2D PCA coordinates, its archetype cluster, a human-readable
archetype label, total CVE volume, and category shares (so Tableau tooltips
can show the underlying profile, not just the cluster ID).

Archetype labels use PHASE6_NOTES.md's three interpretations (memory-safety-
heavy, web-injection-heavy, diffuse/no-dominant-category) but are matched to
clusters by profile, not by cluster ID. K-means numbers its clusters
arbitrarily, so an ID->label table silently mislabels everything the first
time the clustering is refit: refitting on the full CVE history swapped
clusters 0 and 2 and mislabeled 957 of 1481 vendors. The category groupings
below are the judgment call; which cluster they land on is measured.

Usage:
    python3 export_vendor_cluster_map.py
"""
import collections
import csv
from pathlib import Path
import joblib
import numpy as np

CLUSTERING_DATA = Path(__file__).resolve().parent.parent / "clustering" / "data"
OUT_DIR = Path(__file__).resolve().parent / "exports"

MEMORY_SAFETY_CWES = {"CWE-787", "CWE-119", "CWE-125", "CWE-416", "CWE-476",
                      "CWE-120", "CWE-190", "CWE-908", "CWE-415", "CWE-122"}
WEB_INJECTION_CWES = {"CWE-79", "CWE-89", "CWE-352", "CWE-22", "CWE-78",
                      "CWE-94", "CWE-74", "CWE-77", "CWE-434", "CWE-98"}


def label_clusters(cluster_labels, X_raw, categories):
    """Name each cluster from its mean category profile.

    Whichever family of weaknesses carries the most share wins, unless the
    catch-all "Other" bucket outweighs both -- that is what "no dominant
    category" means."""
    idx = {c: i for i, c in enumerate(categories)}
    mem_cols = [idx[c] for c in MEMORY_SAFETY_CWES if c in idx]
    web_cols = [idx[c] for c in WEB_INJECTION_CWES if c in idx]
    other_col = idx.get("Other")

    labels = {}
    for cluster_id in sorted(set(int(c) for c in cluster_labels)):
        profile = X_raw[cluster_labels == cluster_id].mean(axis=0)
        mem = float(profile[mem_cols].sum())
        web = float(profile[web_cols].sum())
        other = float(profile[other_col]) if other_col is not None else 0.0
        if other > max(mem, web):
            labels[cluster_id] = "Diffuse (no dominant category)"
        elif mem >= web:
            labels[cluster_id] = "Memory-safety-heavy"
        else:
            labels[cluster_id] = "Web-injection-heavy"
        print(f"  cluster {cluster_id}: memory={mem:.2f} web={web:.2f} "
              f"other={other:.2f} -> {labels[cluster_id]}")
    return labels


def main():
    OUT_DIR.mkdir(exist_ok=True)
    model = joblib.load(CLUSTERING_DATA / "vendor_archetypes.joblib")
    vendors = model["vendors"]
    labels = model["cluster_labels"]
    X_pca = model["X_pca"]
    categories = model["categories"]

    with open(CLUSTERING_DATA / "vendor_features.csv") as f:
        feature_rows = {r["vendor"]: r for r in csv.DictReader(f)}

    X_raw = np.array([[float(feature_rows[v][f"share_{c}"]) for c in categories]
                      for v in vendors])
    print("Matching archetype labels to clusters by profile:")
    archetype_labels = label_clusters(np.asarray(labels), X_raw, categories)

    with open(OUT_DIR / "vendor_cluster_map.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["vendor", "pca_x", "pca_y", "archetype_cluster", "archetype_label",
                    "total_cves"] + [f"share_{c}" for c in categories])
        for vendor, cluster_id, (x, y) in zip(vendors, labels, X_pca):
            fr = feature_rows[vendor]
            shares = [fr[f"share_{c}"] for c in categories]
            w.writerow([vendor, x, y, int(cluster_id),
                        archetype_labels.get(int(cluster_id), "Unknown"),
                        fr["total_cves"]] + shares)

    counts = collections.Counter(archetype_labels[int(c)] for c in labels)
    print(f"Wrote {OUT_DIR / 'vendor_cluster_map.csv'} ({len(vendors)} vendors)")
    for name, n in counts.most_common():
        print(f"  {name}: {n}")


if __name__ == "__main__":
    main()