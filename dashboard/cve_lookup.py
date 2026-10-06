"""
Record-level search and lookup for the dashboard.

The one place the UI reads the database directly rather than a CSV: 391k
records are too many to export and load, while a filtered search returns at
most a page of rows. It goes through the assistant's read-only connection, so
a rebuild holding the write lock surfaces as DataUnavailable, not a traceback.

Weakness filters and labels use v_canonical_cwe -- the same one-CWE-per-CVE
choice the charts count by -- so a drill-down lists exactly the records
behind the number it was opened from.
"""
import re

from assistant import DataUnavailable, _connect, _fetch  # noqa: F401 -- re-exported

CVE_ID_PATTERN = re.compile(r"^(?:CVE-)?(\d{4})-(\d{4,})$", re.IGNORECASE)


def normalize_id(text):
    """'cve-2026-53900', ' 2026-53900 ' -> 'CVE-2026-53900'; None if not a CVE ID."""
    m = CVE_ID_PATTERN.match(text.strip())
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else None


PAGE_SIZE = 200
ORDERINGS = {
    "newest": "c.published_date DESC, c.id DESC",
    "severity": "c.cvss_score IS NULL, c.cvss_score DESC, c.published_date DESC",
}


def search(vendors=(), cwe_ids=(), year_from=None, year_to=None, text=None,
           missing_vendor=False, order="newest", limit=PAGE_SIZE):
    """Records matching every given filter, as (total_matches, page_of_rows).

    `text` is either a CVE ID (exact match) or keywords that must all appear
    in the description. Each row carries its canonical CWE and vendors, so
    the result table can be read without opening every record.
    """
    where, params = [], []
    if vendors:
        where.append(f"c.id IN (SELECT cve_id FROM cve_cpe WHERE vendor IN "
                     f"({','.join('?' * len(vendors))}))")
        params += list(vendors)
    if cwe_ids:
        where.append(f"c.id IN (SELECT cve_id FROM v_canonical_cwe WHERE cwe_id IN "
                     f"({','.join('?' * len(cwe_ids))}))")
        params += list(cwe_ids)
    if year_from is not None:
        where.append("c.published_year >= ?")
        params.append(year_from)
    if year_to is not None:
        where.append("c.published_year <= ?")
        params.append(year_to)
    if missing_vendor:
        where.append("NOT EXISTS (SELECT 1 FROM cve_cpe p WHERE p.cve_id = c.id)")
    if text and text.strip():
        exact = normalize_id(text)
        if exact:
            where.append("c.id = ?")
            params.append(exact)
        else:
            for word in text.split():
                escaped = word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                where.append("c.description LIKE ? ESCAPE '\\'")
                params.append(f"%{escaped}%")
    clause = f"WHERE {' AND '.join(where)}" if where else ""

    with _connect() as conn:
        columns = "c.id, c.published_date, c.severity, c.cvss_score, c.description"
        if cwe_ids:
            # The weakness filter's view is the slow part. COUNT(*) OVER () is
            # evaluated before LIMIT, so one pass yields the page and the full
            # count instead of running the view twice.
            rows = _fetch(conn, f"""
                SELECT {columns}, COUNT(*) OVER () FROM cves c {clause}
                ORDER BY {ORDERINGS[order]} LIMIT ?
            """, params + [limit])
            total = rows[0][5] if rows else 0
            rows = [r[:5] for r in rows]
        else:
            # Without it, a separate count is cheap, and ORDER BY ... LIMIT
            # alone keeps only the top rows while scanning, whereas the window
            # would materialise and sort every match first.
            total = _fetch(conn, f"SELECT COUNT(*) FROM cves c {clause}", params)[0][0]
            rows = _fetch(conn, f"""
                SELECT {columns} FROM cves c {clause}
                ORDER BY {ORDERINGS[order]} LIMIT ?
            """, params + [limit])
        if not rows:
            return total, []

        ids = [r[0] for r in rows]
        marks = ",".join("?" * len(ids))
        vendors_by_id = dict(_fetch(conn, f"""
            SELECT cve_id, group_concat(DISTINCT vendor) FROM cve_cpe
            WHERE cve_id IN ({marks}) GROUP BY cve_id
        """, ids))
        # When the search already pinned one weakness, that is every row's
        # label; only an unfiltered search pays for the canonical-CWE view.
        if len(cwe_ids) == 1:
            cwe_by_id = dict.fromkeys(ids, cwe_ids[0])
        else:
            cwe_by_id = dict(_fetch(conn, f"""
                SELECT cve_id, cwe_id FROM v_canonical_cwe WHERE cve_id IN ({marks})
            """, ids))

    return total, [
        {"id": cid, "published": published, "severity": severity or "UNSCORED",
         "cvss_score": score, "cwe_id": cwe_by_id.get(cid),
         "vendors": (vendors_by_id.get(cid) or "").replace(",", ", "),
         "description": description}
        for cid, published, severity, score, description in rows
    ]


def lookup(cve_id):
    """Everything stored for one CVE, or None when it is not in the database."""
    with _connect() as conn:
        return fetch_record(conn, cve_id)


def fetch_record(conn, cve_id):
    """lookup() on a connection the caller already holds -- the assistant
    builds its whole briefing on one.

    Returns every CWE assignment, not just the canonical one, with a flag
    marking which one the aggregate views count it under -- a CVE with two
    CWEs is only ever counted once elsewhere in the dashboard.
    """
    rows = _fetch(conn, """
        SELECT id, published_date, published_year, last_modified, vuln_status,
               description, cvss_score, cvss_version, severity
        FROM cves WHERE id = ?
    """, (cve_id,))
    if not rows:
        return None
    (cid, published, year, modified, status,
     description, score, cvss_version, severity) = rows[0]

    canonical = _fetch(conn, "SELECT cwe_id FROM v_canonical_cwe WHERE cve_id = ?",
                       (cve_id,))
    canonical_cwe = canonical[0][0] if canonical else None

    cwes = [
        {"cwe_id": cwe, "source": source, "type": wtype,
         "is_generic": bool(generic), "is_canonical": cwe == canonical_cwe}
        for cwe, source, wtype, generic in _fetch(conn, """
            SELECT cwe_id, source, type, is_generic FROM cve_cwe
            WHERE cve_id = ? ORDER BY type, cwe_id
        """, (cve_id,))
    ]
    products = [
        {"part": part, "vendor": vendor, "product": product, "version": version}
        for part, vendor, product, version in _fetch(conn, """
            SELECT part, vendor, product, version FROM cve_cpe
            WHERE cve_id = ? ORDER BY vendor, product, version
        """, (cve_id,))
    ]

    return {
        "id": cid, "published": published, "year": year, "last_modified": modified,
        "status": status, "description": description, "cvss_score": score,
        "cvss_version": cvss_version, "severity": severity,
        "canonical_cwe": canonical_cwe, "cwes": cwes, "products": products,
    }
