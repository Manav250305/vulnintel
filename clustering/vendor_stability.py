"""
Phase 6, Step 4+5 — vendor archetype stability over time (Module 5).

Uses the SAME fitted scaler/PCA/KMeans from vendor_archetypes.py (the
pooled 2019-2023 clustering) to define fixed archetypes, then transforms
each vendor's per-year feature vector through that same fitted pipeline and
predicts its nearest archetype. This is deliberate: archetypes need to be
fixed reference points to meaningfully ask "did this vendor drift between
archetypes," rather than refitting a new clustering each year, which would
change the archetype definitions themselves and make "drift" meaningless
(there'd be nothing stable to drift away from).

Per-year threshold is more lenient than the pooled analysis (>=5 CVEs in a
given year, vs. >=20 pooled) -- a single year naturally has less volume, and
requiring the pooled threshold per-year would leave almost nothing to track.

Usage:
    python3 vendor_stability.py
"""
import sqlite3
import collections
import numpy as np
from pathlib import Path
import joblib

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"
DATA_DIR = Path(__file__).resolve().parent / "data"
MIN_YEARLY_CVES = 5
# Tracked years come from the data, floored at the same volume cutoff the
# centrality time series uses -- a vendor's "archetype" in a year with a
# couple of hundred CVEs project-wide is noise, not drift.
MIN_YEAR_CVES = 500


def main():
    model = joblib.load(DATA_DIR / "vendor_archetypes.joblib")
    scaler, pca, kmeans = model["scaler"], model["pca"], model["kmeans"]
    categories = model["categories"]
    pooled_vendors = set(model["vendors"])
    pooled_labels = dict(zip(model["vendors"], model["cluster_labels"]))
    top_cwe_set = set(c for c in categories if c != "Other")

    conn = sqlite3.connect(DB_PATH)
    years = [y for (y,) in conn.execute(
        "SELECT published_year FROM cves GROUP BY published_year "
        "HAVING COUNT(*) >= ? ORDER BY published_year", (MIN_YEAR_CVES,))]
    tracked_years = set(years)
    print(f"Tracking archetype stability across {len(years)} years: {years[0]}-{years[-1]}")
    rows = conn.execute("""
        SELECT vc.vendor, cv.published_year, c.cwe_id, c.is_generic
        FROM (SELECT DISTINCT vendor, cve_id FROM cve_cpe) vc
        JOIN cves_in_scope cv ON vc.cve_id = cv.id
        JOIN v_canonical_cwe c ON vc.cve_id = c.cve_id
        WHERE vc.vendor IN ({})
    """.format(",".join("?" for _ in pooled_vendors)), list(pooled_vendors)).fetchall()

    vendor_year_counts = collections.defaultdict(lambda: collections.Counter())
    vendor_year_totals = collections.Counter()
    for vendor, year, cwe_id, is_generic in rows:
        vendor_year_totals[(vendor, year)] += 1
        if not is_generic:
            label = cwe_id if cwe_id in top_cwe_set else "Other"
            vendor_year_counts[(vendor, year)][label] += 1

    vendor_year_archetype = {}
    for (vendor, year), total in vendor_year_totals.items():
        if year not in tracked_years or total < MIN_YEARLY_CVES:
            continue
        counts = vendor_year_counts[(vendor, year)]
        total_labeled = sum(counts.values())
        if total_labeled == 0:
            continue
        shares = np.array([[counts[c] / total_labeled for c in categories]])
        X_scaled = scaler.transform(shares)
        X_pca = pca.transform(X_scaled)
        archetype = int(kmeans.predict(X_pca)[0])
        vendor_year_archetype[(vendor, year)] = archetype

    print(f"{len(vendor_year_archetype)} (vendor, year) archetype assignments "
          f"(>= {MIN_YEARLY_CVES} CVEs that year)")

    # Stability: for vendors with archetype assignments in >=2 years, did the
    # archetype ever change?
    by_vendor = collections.defaultdict(dict)
    for (vendor, year), archetype in vendor_year_archetype.items():
        by_vendor[vendor][year] = archetype

    multi_year_vendors = {v: years for v, years in by_vendor.items() if len(years) >= 2}
    print(f"Vendors with archetype data in >=2 years: {len(multi_year_vendors)}")

    stable, drifting = [], []
    for vendor, years in multi_year_vendors.items():
        archetypes = set(years.values())
        if len(archetypes) == 1:
            stable.append(vendor)
        else:
            drifting.append((vendor, years))

    print(f"\nStable (same archetype every year present): {len(stable)} "
          f"({100*len(stable)/len(multi_year_vendors):.1f}%)")
    print(f"Drifted (different archetype in different years): {len(drifting)} "
          f"({100*len(drifting)/len(multi_year_vendors):.1f}%)")

    print(f"\n--- Vendors whose overall (pooled) archetype matches their most\n"
          f"    recent single-year archetype (sanity check) ---")
    agree = sum(1 for v in multi_year_vendors if pooled_labels.get(v) ==
                by_vendor[v].get(max(by_vendor[v].keys())))
    print(f"  {agree}/{len(multi_year_vendors)} agree "
          f"({100*agree/len(multi_year_vendors):.1f}%)")

    print(f"\n--- Example drifting vendors (up to 10) ---")
    for vendor, years in sorted(drifting, key=lambda x: -len(x[1]))[:10]:
        year_str = ", ".join(f"{y}->cluster{a}" for y, a in sorted(years.items()))
        print(f"  {vendor}: {year_str}")

    conn.close()


if __name__ == "__main__":
    main()