"""
Phase 2 — apply trends.sql to vulnintel.db and sanity-check each view.

Usage:
    python3 build_trends.py
"""
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"
TRENDS_SQL = Path(__file__).resolve().parent / "trends.sql"

# NVD backdates its oldest records to the original disclosure, well before CVE
# IDs existed -- CVE-1999-0095 (sendmail debug) is published 1988-10-01 -- so
# the floor is 1988, not 1999. Anything beyond next year is a malformed record.
# Plausibility bounds only: the project no longer restricts analysis to a window.
PLAUSIBLE_START = 1988


def check_years(conn: sqlite3.Connection):
    """Report the published_year span and flag implausible values.

    This used to DELETE anything outside a hardcoded 2019-2023 window. That
    made sense when the project was scoped to those five years, but it now
    silently destroys good data, so it only reports."""
    min_year, max_year, n = conn.execute(
        "SELECT MIN(published_year), MAX(published_year), COUNT(*) FROM cves"
    ).fetchone()
    print(f"[OK] `cves` holds {n} rows spanning {min_year}-{max_year}")

    plausible_end = datetime.now().year + 1
    cur = conn.execute(
        "SELECT COUNT(*), MIN(published_year), MAX(published_year) FROM cves "
        "WHERE published_year < ? OR published_year > ?",
        (PLAUSIBLE_START, plausible_end),
    )
    n_bad, bad_min, bad_max = cur.fetchone()
    if n_bad:
        print(f"[WARNING] {n_bad} rows have an implausible published_year "
              f"({bad_min}-{bad_max}, expected {PLAUSIBLE_START}-{plausible_end}). "
              f"Left in place -- inspect before removing.")


def show(conn, title, query, params=()):
    print(f"\n--- {title} ---")
    cur = conn.execute(query, params)
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()
    print("  " + " | ".join(cols))
    for row in rows:
        print("  " + " | ".join(str(v) for v in row))
    return rows


def main():
    if not DB_PATH.exists():
        raise SystemExit(f"{DB_PATH} not found — run ingest_all.py first.")

    conn = sqlite3.connect(DB_PATH)

    check_years(conn)
    latest = conn.execute("SELECT MAX(published_year) FROM cves").fetchone()[0]

    conn.executescript(TRENDS_SQL.read_text())
    print(f"Applied {TRENDS_SQL.name}: created v_canonical_cwe, v_vendor_year_trend, "
          f"v_vendor_rank_by_year, v_product_year_trend, v_cwe_year_trend, v_severity_year_trend")

    # --- Row-count sanity check: every view should be non-empty ---
    for view in ["v_canonical_cwe", "v_vendor_year_trend", "v_vendor_rank_by_year",
                 "v_product_year_trend", "v_cwe_year_trend", "v_severity_year_trend"]:
        n = conn.execute(f"SELECT COUNT(*) FROM {view}").fetchone()[0]
        print(f"  {view}: {n} rows")

    # --- v_canonical_cwe: exactly one row per CVE that has >=1 CWE assignment ---
    n_canonical = conn.execute("SELECT COUNT(*) FROM v_canonical_cwe").fetchone()[0]
    n_distinct_cves = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM cve_cwe").fetchone()[0]
    assert n_canonical == n_distinct_cves, (
        f"v_canonical_cwe should have exactly one row per CVE with a CWE "
        f"assignment ({n_distinct_cves}), got {n_canonical}"
    )
    print(f"\n[OK] v_canonical_cwe: {n_canonical} rows == {n_distinct_cves} distinct CVEs with a CWE")

    # --- Cross-check against the Phase 1 manual query (microsoft/google/apache/oracle) ---
    show(conn, "v_vendor_year_trend for known vendors (cross-check vs. Phase 1 manual query)",
         """SELECT vendor, year, cve_count, avg_cvss, rolling_avg_cvss_3yr, yoy_cve_growth_pct
            FROM v_vendor_year_trend
            WHERE vendor IN ('microsoft','google','apache','oracle')
            ORDER BY vendor, year""")

    show(conn, f"Top 5 vendors by CVE count, {latest}",
         """SELECT vendor, cve_count, rank_in_year
            FROM v_vendor_rank_by_year
            WHERE year = ?
            ORDER BY rank_in_year LIMIT 5""", (latest,))

    show(conn, f"Top 5 products by CVE count, {latest}",
         """SELECT vendor, product, cve_count, avg_cvss, rank_in_year
            FROM v_product_year_trend
            WHERE year = ?
            ORDER BY rank_in_year LIMIT 5""", (latest,))

    show(conn, f"Top 5 fastest-growing CWE categories, {latest} vs {latest - 1} (min 50 CVEs to avoid noise)",
         """SELECT cwe_id, year, cve_count, pct_of_year, yoy_growth_pct
            FROM v_cwe_year_trend
            WHERE year = ? AND cve_count >= 50 AND yoy_growth_pct IS NOT NULL
            ORDER BY yoy_growth_pct DESC LIMIT 5""", (latest,))

    show(conn, "Severity mix by year",
         """SELECT year, severity, cve_count, pct_of_year
            FROM v_severity_year_trend
            ORDER BY year,
                     CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                                    WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3
                                    WHEN 'NONE' THEN 4 WHEN 'UNSCORED' THEN 5 ELSE 6 END""")

    conn.close()


if __name__ == "__main__":
    main()