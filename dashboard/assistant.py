"""
Local question-answering over the vulnerability data, via Ollama.

Runs entirely on this machine -- no vulnerability data leaves it, and there is
no API key or per-token cost.

The model is never asked to recall facts or do arithmetic on raw records.
Every number it can cite is computed here from the database and handed to it
as a briefing; its job is only to read that briefing and answer in prose. A 2-7B
model asked "which vendor had the most vulnerabilities" will happily invent a
plausible name and count, so the figures are pre-computed and the model is told
to refuse anything the briefing does not cover.
"""
import json
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path

DASHBOARD_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DASHBOARD_DIR.parent
DB_PATH = PROJECT_ROOT / "data" / "processed" / "vulnintel.db"
DATA_DIR = DASHBOARD_DIR / "data"

OLLAMA_URL = "http://localhost:11434"
REQUEST_TIMEOUT = 180

SYSTEM_PROMPT = """You are a vulnerability-intelligence analyst assistant.

You answer questions using ONLY the briefing below. It is computed directly from \
the database and is the single source of truth.

Rules:
- Never invent numbers. Quote figures only if they appear in the briefing.
- If the briefing does not contain the answer, say exactly what is missing and \
suggest which part of the dashboard would show it. Do not guess.
- Vendor and product figures from recent years are undercounted; whenever you \
quote them for those years, say so.
- Be concise and concrete. Prefer a short paragraph or a few bullets.
- Do not describe your own reasoning or restate these rules.

=== BRIEFING ===
{briefing}
=== END BRIEFING ==="""


def available_models():
    """Model names Ollama currently has, or [] if it is not reachable."""
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=5) as resp:
            payload = json.load(resp)
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
        return []
    return [m["name"] for m in payload.get("models", [])]


def _fetch(conn, query, params=()):
    return conn.execute(query, params).fetchall()


def build_briefing():
    """Assemble the facts the model is allowed to speak from.

    Kept to a few kilobytes: small models lose the thread of a long context,
    and everything here has to survive being read by a 2B model."""
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    lines = []

    total, y_min, y_max, newest = _fetch(conn, """
        SELECT COUNT(*), MIN(published_year), MAX(published_year), MAX(published_date)
        FROM cves
    """)[0]
    lines.append("## Scope")
    lines.append(f"{total:,} vulnerability records, published {y_min} to {y_max}. "
                 f"Most recent record: {newest}.")

    lines.append("\n## Records published per year (last 10)")
    for year, n in _fetch(conn, """
        SELECT published_year, COUNT(*) FROM cves
        GROUP BY published_year ORDER BY published_year DESC LIMIT 10
    """):
        lines.append(f"  {year}: {n:,}")

    lines.append("\n## Data completeness (why recent vendor counts look low)")
    lines.append("Vendor/product attribution arrives after publication, so recent "
                 "years are incomplete. Percent of each year's records carrying "
                 "vendor data:")
    for year, pct in _fetch(conn, """
        SELECT c.published_year,
               ROUND(100.0 * COUNT(DISTINCT p.cve_id) / COUNT(DISTINCT c.id), 1)
        FROM cves c LEFT JOIN cve_cpe p ON p.cve_id = c.id
        GROUP BY c.published_year
        ORDER BY c.published_year DESC LIMIT 6
    """):
        lines.append(f"  {year}: {pct}%")

    lines.append(f"\n## Vendors with the most records in {y_max}")
    lines.append("(undercounted -- see completeness above)")
    for vendor, n in _fetch(conn, """
        SELECT vendor, COUNT(DISTINCT cve_id) n FROM cve_cpe
        WHERE cve_id IN (SELECT id FROM cves WHERE published_year = ?)
        GROUP BY vendor ORDER BY n DESC LIMIT 10
    """, (y_max,)):
        lines.append(f"  {vendor}: {n:,}")

    lines.append("\n## Vendors with the most records, all years")
    for vendor, n in _fetch(conn, """
        SELECT vendor, COUNT(DISTINCT cve_id) n FROM cve_cpe
        GROUP BY vendor ORDER BY n DESC LIMIT 10
    """):
        lines.append(f"  {vendor}: {n:,}")

    lines.append(f"\n## Most common weakness types in {y_max}")
    for cwe, n, pct in _fetch(conn, """
        SELECT cwe_id, cve_count, pct_of_year FROM v_cwe_year_trend
        WHERE year = ? ORDER BY cve_count DESC LIMIT 10
    """, (y_max,)):
        lines.append(f"  {cwe}: {n:,} ({pct}% of the year)")

    lines.append(f"\n## Severity mix, {y_max}")
    for sev, n, pct in _fetch(conn, """
        SELECT severity, cve_count, pct_of_year FROM v_severity_year_trend
        WHERE year = ? ORDER BY cve_count DESC
    """, (y_max,)):
        lines.append(f"  {sev}: {n:,} ({pct}%)")

    conn.close()

    # Model outputs live in CSVs rather than the database.
    trend = DATA_DIR / "cwe_year_trend.csv"
    if trend.exists():
        import csv as _csv
        with open(trend) as f:
            rows = [r for r in _csv.DictReader(f) if r["year"] == str(y_max)]
        growers = sorted(
            (r for r in rows if r.get("yoy_growth_pct") and int(r["cve_count"]) >= 50),
            key=lambda r: float(r["yoy_growth_pct"]), reverse=True,
        )[:8]
        if growers:
            lines.append(f"\n## Fastest-growing weakness types in {y_max} "
                         f"(at least 50 records)")
            for r in growers:
                lines.append(f"  {r['cwe_id']}: {r['yoy_growth_pct']}% vs prior year "
                             f"({int(r['cve_count']):,} records)")

    vendor_map = DATA_DIR / "vendor_cluster_map.csv"
    if vendor_map.exists():
        import csv as _csv
        import collections
        with open(vendor_map) as f:
            rows = list(_csv.DictReader(f))
        counts = collections.Counter(r["archetype_label"] for r in rows)
        lines.append("\n## Vendor archetypes (grouped by weakness profile)")
        for label, n in counts.most_common():
            examples = [r["vendor"] for r in rows if r["archetype_label"] == label][:6]
            lines.append(f"  {label}: {n} vendors, e.g. {', '.join(examples)}")

    nodes = DATA_DIR / "cooccurrence_nodes.csv"
    if nodes.exists():
        import csv as _csv
        with open(nodes) as f:
            rows = sorted(_csv.DictReader(f),
                          key=lambda r: float(r["centrality"]), reverse=True)[:10]
        lines.append("\n## Most structurally central weakness types")
        lines.append("(central = co-occurs with many other weakness types in the "
                     "same products, so it sits at the hub of the network)")
        for r in rows:
            lines.append(f"  {r['cwe_id']}: centrality {float(r['centrality']):.4f}, "
                         f"{int(r['raw_frequency']):,} records")

    return "\n".join(lines)


def stream_answer(question, model, briefing, history=None):
    """Yield the model's reply in chunks as Ollama produces them."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT.format(briefing=briefing)}]
    for turn in (history or []):
        messages.append({"role": turn["role"], "content": turn["content"]})
    messages.append({"role": "user", "content": question})

    payload = json.dumps({
        "model": model,
        "messages": messages,
        "stream": True,
        "options": {"temperature": 0.2},  # answering from a briefing, not brainstorming
    }).encode()

    request = urllib.request.Request(
        f"{OLLAMA_URL}/api/chat", data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as resp:
            for raw in resp:
                if not raw.strip():
                    continue
                try:
                    chunk = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                piece = chunk.get("message", {}).get("content")
                if piece:
                    yield piece
                if chunk.get("done"):
                    return
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        yield f"\n\n*Could not reach the local model: {e}*"


if __name__ == "__main__":
    print(build_briefing())
