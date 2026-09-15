"""
Phase 6, Step 1 — per-vendor CWE-category feature vectors (Module 5).

Reuses Phase 5's Top-20-CWE + "Other" class scheme (21 categories) for
consistency across the project, rather than inventing a second rollup
scheme for the same underlying data.

Only vendors with >=20 total in-scope CVEs are included (618 of 14,838
vendors) -- a vendor with a handful of CVEs can't give a statistically
meaningful category distribution; the excluded long tail is 13,601 vendors
with fewer than 10 CVEs each.

Feature vector: normalized frequency (share, not raw count) across the 21
categories, so vendors of very different total volume (Google's 6,863 CVEs
vs. a 20-CVE vendor) are comparable on the same 0-1 scale per category.

Usage:
    python3 build_vendor_features.py
"""
import sqlite3
import csv
import collections
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"
OUT_DIR = Path(__file__).resolve().parent / "data"
MIN_VENDOR_CVES = 20
TOP_K = 20


def main():
    OUT_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)

    top_cwes = [r[0] for r in conn.execute("""
        SELECT cwe_id FROM v_canonical_cwe WHERE is_generic = 0
        GROUP BY cwe_id ORDER BY COUNT(*) DESC LIMIT ?
    """, (TOP_K,)).fetchall()]
    top_cwe_set = set(top_cwes)
    categories = top_cwes + ["Other"]
    print(f"Categories ({len(categories)}): {categories}")

    # One row per (vendor, cve_id, cwe_id) -- a CVE affecting multiple
    # products from the same vendor should count once per vendor, not once
    # per product, consistent with Phase 2's v_vendor_year_trend dedup logic.
    rows = conn.execute("""
        SELECT vc.vendor, c.cwe_id, c.is_generic
        FROM (SELECT DISTINCT vendor, cve_id FROM cve_cpe) vc
        JOIN v_canonical_cwe c ON vc.cve_id = c.cve_id
    """).fetchall()

    vendor_counts = collections.defaultdict(lambda: collections.Counter())
    vendor_totals = collections.Counter()
    for vendor, cwe_id, is_generic in rows:
        label = cwe_id if (not is_generic and cwe_id in top_cwe_set) else \
                ("Other" if not is_generic else None)
        # CVEs with only a generic CWE are excluded from category shares
        # (same reasoning as Phase 5: no meaningful category to assign),
        # but DO count toward the vendor's total CVE volume for the
        # >=20 threshold, since that's about data sufficiency, not label quality.
        vendor_totals[vendor] += 1
        if label is not None:
            vendor_counts[vendor][label] += 1

    qualifying_vendors = [v for v, n in vendor_totals.items() if n >= MIN_VENDOR_CVES]
    print(f"Vendors with >= {MIN_VENDOR_CVES} total CVEs: {len(qualifying_vendors)}")

    with open(OUT_DIR / "vendor_features.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["vendor", "total_cves"] + [f"share_{c}" for c in categories])
        for vendor in sorted(qualifying_vendors):
            counts = vendor_counts[vendor]
            total_labeled = sum(counts.values())
            shares = [counts[c] / total_labeled if total_labeled > 0 else 0.0 for c in categories]
            w.writerow([vendor, vendor_totals[vendor]] + shares)

    print(f"Wrote {OUT_DIR / 'vendor_features.csv'}")

    conn.close()


if __name__ == "__main__":
    main()