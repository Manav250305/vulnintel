"""
Phase 7, Export 1 — vendor/CWE trend timeline (Module 7, dashboard view 1).

Reuses Phase 2's v_vendor_year_trend and v_cwe_year_trend views directly --
no new computation, just exporting what's already correct and verified into
Tableau-friendly flat CSVs. Two separate files (different grain/columns);
Tableau can relate or filter across them within one dashboard.

Usage:
    python3 export_trend_timeline.py
"""
import sqlite3
import csv
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"
OUT_DIR = Path(__file__).resolve().parent / "exports"


def export_query(conn, query, out_path):
    cur = conn.execute(query)
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        w.writerows(rows)
    print(f"Wrote {out_path} ({len(rows)} rows)")


def main():
    OUT_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)

    export_query(conn, "SELECT * FROM v_vendor_year_trend ORDER BY vendor, year",
                 OUT_DIR / "vendor_year_trend.csv")
    export_query(conn, "SELECT * FROM v_cwe_year_trend ORDER BY cwe_id, year",
                 OUT_DIR / "cwe_year_trend.csv")
    export_query(conn, "SELECT * FROM v_severity_year_trend ORDER BY year, severity",
                 OUT_DIR / "severity_year_trend.csv")

    # Per-year enrichment coverage. Vendor/product analysis depends on CPE
    # records, which NVD attaches well after publication -- recent years look
    # like a decline in vendor activity when they are really a reporting lag.
    # Exported so the dashboard can show that gap instead of hiding it.
    export_query(conn, """
        SELECT
            c.published_year AS year,
            COUNT(DISTINCT c.id) AS total_cves,
            COUNT(DISTINCT p.cve_id) AS cves_with_cpe,
            COUNT(DISTINCT w.cve_id) AS cves_with_cwe,
            ROUND(100.0 * COUNT(DISTINCT p.cve_id) / COUNT(DISTINCT c.id), 1) AS cpe_coverage_pct,
            ROUND(100.0 * COUNT(DISTINCT w.cve_id) / COUNT(DISTINCT c.id), 1) AS cwe_coverage_pct
        FROM cves c
        LEFT JOIN cve_cpe p ON p.cve_id = c.id
        LEFT JOIN cve_cwe w ON w.cve_id = c.id AND w.is_generic = 0
        GROUP BY c.published_year
        ORDER BY c.published_year
    """, OUT_DIR / "data_coverage.csv")

    conn.close()


if __name__ == "__main__":
    main()