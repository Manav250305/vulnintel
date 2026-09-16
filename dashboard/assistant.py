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
import functools
import json
import re
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path

import cwe_names

DASHBOARD_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DASHBOARD_DIR.parent
DB_PATH = PROJECT_ROOT / "data" / "processed" / "vulnintel.db"
DATA_DIR = DASHBOARD_DIR / "data"

OLLAMA_URL = "http://localhost:11434"
REQUEST_TIMEOUT = 180

SYSTEM_PROMPT = """You are a vulnerability-intelligence analyst assistant.

You answer using ONLY the briefing below. It is computed directly from the \
database for this specific question and is the single source of truth.

Rules:
- Every figure you give must appear verbatim in the briefing. Never compute, \
estimate, or adjust a number.
- Numbers belong to the heading they appear under. A figure listed under an \
overall total is NOT that of a particular vendor, weakness or year. If the \
briefing has no section for what was asked, say so instead of borrowing the \
nearest-looking numbers.
- Only expand a CWE identifier into words if the briefing supplies that name. \
Otherwise write the bare identifier, e.g. "CWE-1021". Never guess what a CWE \
number means.
- When the briefing DOES have a section covering what was asked, answer from it \
directly and completely. Do not refuse, hedge, or send the reader to an \
external source for something the briefing already states.
- Only when the briefing genuinely lacks the answer, say plainly what is missing \
and point to the dashboard tab that would show it. A short refusal is a correct \
answer; a fabricated one is not.
- Vendor and product figures for recent years are undercounted. Say so whenever \
you quote them.
- Be concise and concrete. A short paragraph or a few bullets.
- Do not describe your reasoning or restate these rules.

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


class DataUnavailable(RuntimeError):
    """The database could not be read right now, almost always because a
    rebuild stage is holding the write lock."""


# Long enough to ride out a batch commit, short enough that the page still
# renders promptly when a rebuild really is holding the lock for a while.
LOCK_WAIT_SECONDS = 8


def _connect():
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True,
                               timeout=LOCK_WAIT_SECONDS)
        conn.execute(f"PRAGMA busy_timeout = {LOCK_WAIT_SECONDS * 1000}")
        return conn
    except sqlite3.OperationalError as e:
        raise DataUnavailable(str(e)) from e


def _fetch(conn, query, params=()):
    try:
        return conn.execute(query, params).fetchall()
    except sqlite3.OperationalError as e:
        # Surfaced as DataUnavailable so callers can show "a rebuild is
        # running" rather than a traceback.
        raise DataUnavailable(str(e)) from e


@functools.lru_cache(maxsize=1)
def _known_vendors():
    """Vendors substantial enough to be worth name-matching in a question.

    Matching against all 36k vendor strings produces constant false positives --
    'one', 'go' and 'now' are all registered vendor names."""
    with _connect() as conn:
        rows = _fetch(conn, """
            SELECT vendor, COUNT(DISTINCT cve_id) n FROM cve_cpe
            GROUP BY vendor HAVING n >= 20
        """)
    return {v for v, _ in rows if len(v) >= 3}


def find_entities(question):
    """Vendors, weaknesses and years named in a question."""
    lowered = question.lower()
    words = re.findall(r"[a-z0-9][a-z0-9._-]*", lowered)

    vendors = _known_vendors()
    found_vendors = [w for w in dict.fromkeys(words) if w in vendors]
    # Two-word vendor names ("trend micro") lose to single-token matching.
    for a, b in zip(words, words[1:]):
        for joined in (f"{a} {b}", f"{a}_{b}"):
            if joined in vendors and joined not in found_vendors:
                found_vendors.append(joined)

    cwes = [f"CWE-{n}" for n in dict.fromkeys(re.findall(r"cwe[-\s]?(\d+)", lowered))]
    years = [int(y) for y in dict.fromkeys(re.findall(r"\b(19[89]\d|20[0-4]\d)\b", lowered))]
    return found_vendors[:3], cwes[:3], years[:3]


def describe_vendor(conn, vendor):
    """Everything the database knows about one vendor."""
    total = _fetch(conn, "SELECT COUNT(DISTINCT cve_id) FROM cve_cpe WHERE vendor = ?",
                   (vendor,))[0][0]
    if not total:
        return None

    lines = [f"\n## Vendor profile: {vendor}",
             f"{total:,} vulnerabilities across all years."]

    shares = _fetch(conn, """
        SELECT c.cwe_id, COUNT(DISTINCT c.cve_id) n
        FROM v_canonical_cwe c
        WHERE c.is_generic = 0 AND c.cve_id IN (
            SELECT cve_id FROM cve_cpe WHERE vendor = ?)
        GROUP BY c.cwe_id ORDER BY n DESC LIMIT 10
    """, (vendor,))
    classified = sum(n for _, n in shares)
    if shares:
        lines.append(f"\nMost common weakness types for {vendor} "
                     f"(share of its {classified:,} classified vulnerabilities):")
        mem = web = 0
        for cwe, n in shares:
            pct = 100.0 * n / classified
            lines.append(f"  {cwe_names.label(cwe)}: {n:,} ({pct:.1f}%)")
            if cwe in cwe_names.MEMORY_SAFETY:
                mem += pct
            elif cwe in cwe_names.WEB_INJECTION:
                web += pct
        lines.append(f"Of the ten above, memory-safety types account for "
                     f"{mem:.1f}% and web/injection types {web:.1f}%.")

    products = _fetch(conn, """
        SELECT product, COUNT(DISTINCT cve_id) n FROM cve_cpe
        WHERE vendor = ? GROUP BY product ORDER BY n DESC LIMIT 5
    """, (vendor,))
    if products:
        lines.append(f"\nMost affected {vendor} products:")
        lines.extend(f"  {p}: {n:,}" for p, n in products)

    by_year = _fetch(conn, """
        SELECT v.published_year, COUNT(DISTINCT p.cve_id) n
        FROM cve_cpe p JOIN cves v ON p.cve_id = v.id
        WHERE p.vendor = ? GROUP BY v.published_year
        ORDER BY v.published_year DESC LIMIT 8
    """, (vendor,))
    if by_year:
        lines.append(f"\n{vendor} vulnerabilities per year (recent years undercounted):")
        lines.extend(f"  {y}: {n:,}" for y, n in by_year)

    archetype = _vendor_archetype(vendor)
    if archetype:
        lines.append(f"\nArchetype group: {archetype}")
    return "\n".join(lines)


def _vendor_archetype(vendor):
    path = DATA_DIR / "vendor_cluster_map.csv"
    if not path.exists():
        return None
    import csv as _csv
    with open(path) as f:
        for row in _csv.DictReader(f):
            if row["vendor"] == vendor:
                return row["archetype_label"]
    return None


def describe_cwe(conn, cwe_id):
    """Everything the database knows about one weakness type."""
    # Canonical (one label per CVE), matching the trend views. Counting raw
    # cve_cwe rows instead would double-count vulnerabilities that carry both a
    # vendor and an NVD classification, and disagree with the vendor sections.
    total = _fetch(conn, "SELECT COUNT(DISTINCT cve_id) FROM v_canonical_cwe WHERE cwe_id = ?",
                   (cwe_id,))[0][0]
    if not total:
        return f"\n## {cwe_id}\nNo records carry this weakness identifier."

    name = cwe_names.lookup(cwe_id)
    lines = [f"\n## Weakness profile: {cwe_id}"]
    lines.append(f"Official name: {name}" if name
                 else "Official name: not available -- refer to it as "
                      f"{cwe_id} without expanding it.")
    definition = cwe_names.describe(cwe_id)
    if definition:
        lines.append(f"What it is (MITRE's definition): {definition}")
    lines.append(f"{total:,} vulnerabilities classified as this type.")

    by_year = _fetch(conn, """
        SELECT year, cve_count, pct_of_year, yoy_growth_pct
        FROM v_cwe_year_trend WHERE cwe_id = ? ORDER BY year DESC LIMIT 8
    """, (cwe_id,))
    if by_year:
        lines.append("\nPer year (count, share of that year, change vs prior year):")
        for y, n, pct, growth in by_year:
            g = f"{growth:+.0f}%" if growth is not None else "n/a"
            lines.append(f"  {y}: {n:,} ({pct}% of year, {g})")

    vendors = _fetch(conn, """
        SELECT p.vendor, COUNT(DISTINCT p.cve_id) n
        FROM cve_cpe p
        WHERE p.cve_id IN (SELECT cve_id FROM v_canonical_cwe WHERE cwe_id = ?)
        GROUP BY p.vendor ORDER BY n DESC LIMIT 8
    """, (cwe_id,))
    if vendors:
        lines.append(f"\nVendors most affected by {cwe_id}:")
        lines.extend(f"  {v}: {n:,}" for v, n in vendors)
    return "\n".join(lines)


def describe_year(conn, year):
    rows = _fetch(conn, """
        SELECT COUNT(DISTINCT c.id), COUNT(DISTINCT p.cve_id)
        FROM cves c LEFT JOIN cve_cpe p ON p.cve_id = c.id
        WHERE c.published_year = ?
    """, (year,))[0]
    if not rows[0]:
        return f"\n## {year}\nNo records published in this year."

    lines = [f"\n## Year in detail: {year}",
             f"{rows[0]:,} published; {rows[1]:,} carry vendor data "
             f"({100.0 * rows[1] / rows[0]:.1f}%)."]

    top_cwe = _fetch(conn, """
        SELECT cwe_id, cve_count, pct_of_year FROM v_cwe_year_trend
        WHERE year = ? ORDER BY cve_count DESC LIMIT 8
    """, (year,))
    if top_cwe:
        lines.append(f"\nMost common weakness types in {year}:")
        lines.extend(f"  {cwe_names.label(c)}: {n:,} ({p}%)" for c, n, p in top_cwe)

    top_vendor = _fetch(conn, """
        SELECT vendor, COUNT(DISTINCT cve_id) n FROM cve_cpe
        WHERE cve_id IN (SELECT id FROM cves WHERE published_year = ?)
        GROUP BY vendor ORDER BY n DESC LIMIT 8
    """, (year,))
    if top_vendor:
        lines.append(f"\nVendors with the most records in {year}:")
        lines.extend(f"  {v}: {n:,}" for v, n in top_vendor)
    return "\n".join(lines)


def build_briefing(question=None, trace=None):
    """Assemble the facts the model is allowed to speak from.

    The overview below is always included. When a question names a vendor,
    weakness or year, that entity is looked up and its real figures appended:
    a fixed summary made the model borrow whatever numbers were nearest when
    asked about something it did not cover, which is worse than refusing.

    Still only a few kilobytes -- small models lose the thread of a long
    context, and this has to survive being read by a 2B model.

    Pass `trace` (a list) to collect a step-by-step record of what was looked
    up. That record is what the dashboard shows as the assistant's reasoning:
    it is the retrieval that actually happened, not a narration asked of the
    model after the fact."""
    conn = _connect()
    lines = []

    def step(text):
        if trace is not None:
            trace.append(text)

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
        lines.append(f"  {cwe_names.label(cwe)}: {n:,} ({pct}% of the year)")

    lines.append(f"\n## Severity mix, {y_max}")
    for sev, n, pct in _fetch(conn, """
        SELECT severity, cve_count, pct_of_year FROM v_severity_year_trend
        WHERE year = ? ORDER BY cve_count DESC
    """, (y_max,)):
        lines.append(f"  {sev}: {n:,} ({pct}%)")

    # Look up whatever this particular question is about. Without this the
    # overview above is all the model has, and it will repurpose overall
    # totals as if they belonged to the vendor or year that was asked about.
    step(f"Loaded overview: {total:,} records, {y_min}-{y_max}.")

    if question:
        vendors, cwes, years = find_entities(question)
        named = []
        if vendors:
            named.append(f"vendor {', '.join(vendors)}")
        if cwes:
            named.append(f"weakness {', '.join(cwes)}")
        if years:
            named.append(f"year {', '.join(str(y) for y in years)}")
        step(f"Scanned the question and matched {'; '.join(named)}." if named
             else "Scanned the question: no specific vendor, weakness or year "
                  "named, so only the overview applies.")

        for vendor in vendors:
            section = describe_vendor(conn, vendor)
            if section:
                lines.append(section)
                step(f"Pulled {vendor}'s weakness breakdown, top products and "
                     f"yearly counts from the database.")
            else:
                step(f"No records found for '{vendor}'.")
        for cwe in cwes:
            lines.append(describe_cwe(conn, cwe))
            name = cwe_names.lookup(cwe)
            step(f"Pulled {cwe} history and affected vendors"
                 + (f"; official name is '{name}'." if name
                    else f"; no official name on file, so it stays unexpanded."))
        for year in years:
            if year != y_max:  # the overview already covers the newest year
                lines.append(describe_year(conn, year))
                step(f"Pulled {year} in detail.")

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

    briefing = "\n".join(lines)
    step(f"Assembled a {len(briefing):,}-character briefing. The model sees "
         f"this and nothing else.")
    return briefing


def stream_answer(question, model, briefing, history=None):
    """Yield ("thinking" | "answer", chunk) pairs as Ollama produces them.

    Reasoning models (deepseek-r1, qwen3 and similar) wrap their working in
    <think> tags and would otherwise dump it into the reply. Splitting the
    stream lets the dashboard show it separately. Models without a reasoning
    mode simply never emit the tag and yield only "answer"."""
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
    in_thought = False
    buffer = ""
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as resp:
            for raw in resp:
                if not raw.strip():
                    continue
                try:
                    chunk = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                message = chunk.get("message", {})
                # Newer Ollama builds expose reasoning as its own field.
                reasoning = message.get("thinking") or message.get("reasoning")
                if reasoning:
                    yield "thinking", reasoning

                piece = message.get("content")
                if piece:
                    # Tags can straddle chunk boundaries, so hold text back
                    # until it is clear which side of a tag it belongs to.
                    buffer += piece
                    while True:
                        marker = "</think>" if in_thought else "<think>"
                        idx = buffer.find(marker)
                        if idx == -1:
                            break
                        before, buffer = buffer[:idx], buffer[idx + len(marker):]
                        if before:
                            yield ("thinking" if in_thought else "answer"), before
                        in_thought = not in_thought

                    # A partial tag at the tail must wait for the next chunk.
                    safe = len(buffer)
                    for n in range(1, min(8, len(buffer)) + 1):
                        if "<think>".startswith(buffer[-n:]) or "</think>".startswith(buffer[-n:]):
                            safe = len(buffer) - n
                            break
                    if safe > 0:
                        yield ("thinking" if in_thought else "answer"), buffer[:safe]
                        buffer = buffer[safe:]

                if chunk.get("done"):
                    if buffer:
                        yield ("thinking" if in_thought else "answer"), buffer
                    return
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        yield "answer", f"\n\n*Could not reach the local model: {e}*"


if __name__ == "__main__":
    print(build_briefing())
