"""
Shared NVD API v2.0 'cve' object parsing logic.

Used by both ingest_all.py (streaming batch load from the CVE-all feed) and
ingest_live.py (incremental live-API sync), so the two canonical ingestion
paths stay in exact agreement on field mapping without depending on each
other or on the superseded per-year ingest.py.
"""

GENERIC_CWE_LABELS = {"NVD-CWE-Other", "NVD-CWE-noinfo"}


def pick_cvss(metrics: dict):
    """Version-preference cascade: v3.1 > v3.0 > v2. Prefer Primary/nvd@nist.gov
    entries within a version when multiple sources disagree."""
    for key, version_label in [
        ("cvssMetricV31", "v31"),
        ("cvssMetricV30", "v30"),
        ("cvssMetricV2", "v2"),
    ]:
        entries = metrics.get(key)
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss_data = primary.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or primary.get("baseSeverity")
        return score, version_label, severity
    return None, None, None


def parse_cpe_criteria(criteria: str):
    """Parse a CPE 2.3 URI: cpe:2.3:{part}:{vendor}:{product}:{version}:..."""
    parts = criteria.split(":")
    if len(parts) < 6:
        return None
    _, _, part, vendor, product, version = parts[:6]
    vendor = vendor.replace("_", " ").strip()
    product = product.replace("_", " ").strip()
    if not vendor or not product or vendor == "*" or product == "*":
        return None
    return part, vendor, product, version


def extract_cpes(configurations: list):
    seen = set()
    results = []
    for config in configurations or []:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                parsed = parse_cpe_criteria(match.get("criteria", ""))
                if parsed is None:
                    continue
                if parsed in seen:
                    continue
                seen.add(parsed)
                results.append(parsed)
    return results


def extract_cwes(weaknesses: list):
    seen = set()
    results = []
    for entry in weaknesses or []:
        source = entry.get("source")
        wtype = entry.get("type")
        for d in entry.get("description", []):
            if d.get("lang") != "en":
                continue
            cwe_id = d["value"]
            key = (cwe_id, source, wtype)
            if key in seen:
                continue
            seen.add(key)
            results.append((cwe_id, source, wtype))
    return results


def parse_item(item: dict):
    """Convert one NVD API v2.0 'cve' object into (cve_row, cwe_rows, cpe_rows).
    Returns None if the record has no English description (unparseable)."""
    desc = next(
        (d["value"] for d in item.get("descriptions", []) if d.get("lang") == "en"),
        None,
    )
    if not desc:
        return None

    published = item["published"]
    published_date = published[:10]
    published_year = int(published_date[:4])

    score, cvss_version, severity = pick_cvss(item.get("metrics", {}))
    score = float(score) if score is not None else None  # ijson yields Decimal, not float

    cve_row = (
        item["id"], published_date, published_year, item.get("lastModified"),
        item.get("vulnStatus"), desc, score, cvss_version, severity,
    )

    cwe_rows = [
        (item["id"], cwe_id, source, wtype, 1 if cwe_id in GENERIC_CWE_LABELS else 0)
        for cwe_id, source, wtype in extract_cwes(item.get("weaknesses"))
    ]

    cpe_rows = [
        (item["id"], part, vendor, product, version)
        for part, vendor, product, version in extract_cpes(item.get("configurations"))
    ]

    return cve_row, cwe_rows, cpe_rows
