"""
Phase 3, Step 1 — NLP text prep (Module 4).

Pulls CVE descriptions, excludes Rejected candidates (templated
administrative boilerplate, not real vulnerability text -- see PHASE3_NOTES.md),
cleans domain-specific noise that generic stopword removal won't catch
(self-referencing CVE IDs, version-number tokens, URLs), bins into quarters
by published_date, and stores the result in a new `nlp_docs` table so later
steps (TF-IDF, clustering) can just query it rather than re-deriving it.

Usage:
    python3 preprocess.py
"""
import re
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"

CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://\S+")
VERSION_RE = re.compile(r"\b\d+(?:\.\d+){1,3}\b")  # e.g. 4.7.9, 2021.005.20060
WHITESPACE_RE = re.compile(r"\s+")


def clean_text(desc: str) -> str:
    text = desc.lower()
    text = URL_RE.sub(" ", text)
    text = CVE_ID_RE.sub(" ", text)      # self-references add no topical signal
    text = VERSION_RE.sub(" ", text)     # dotted version numbers are noise for topic clustering
    text = re.sub(r"[^a-z0-9\s]", " ", text)  # drop punctuation, but KEEP digits for now --
    # alphanumeric identifiers (6lbr, log4j, sha256, ipv6, oauth2) carry real topical
    # signal and must not be stripped just because they contain a digit. Only a
    # standalone, purely-numeric token (a port number, a stray leftover year) is noise.
    tokens = [t for t in text.split() if not t.isdigit()]
    text = " ".join(tokens)
    text = WHITESPACE_RE.sub(" ", text).strip()
    return text


def quarter_of(published_date: str) -> str:
    year, month = published_date[:4], int(published_date[5:7])
    q = (month - 1) // 3 + 1
    return f"{year}-Q{q}"


def main():
    conn = sqlite3.connect(DB_PATH)

    conn.execute("DROP TABLE IF EXISTS nlp_docs")
    conn.execute("""
        CREATE TABLE nlp_docs (
            cve_id TEXT PRIMARY KEY,
            quarter TEXT NOT NULL,
            cleaned_description TEXT NOT NULL,
            cwe_id TEXT,           -- from v_canonical_cwe, NULL if no CWE assigned
            is_generic INTEGER     -- 1 if the canonical CWE is a generic NVD placeholder
        )
    """)

    rows = conn.execute("""
        SELECT s.id, s.published_date, s.description, c.cwe_id, c.is_generic
        FROM cves_in_scope s
        LEFT JOIN v_canonical_cwe c ON s.id = c.cve_id
        WHERE s.vuln_status != 'Rejected'
    """).fetchall()

    prepped = []
    empty_after_cleaning = 0
    for cve_id, published_date, desc, cwe_id, is_generic in rows:
        cleaned = clean_text(desc)
        if len(cleaned) < 10:  # near-empty after cleaning -- track, don't silently drop
            empty_after_cleaning += 1
        prepped.append((cve_id, quarter_of(published_date), cleaned, cwe_id, is_generic))

    conn.executemany(
        "INSERT INTO nlp_docs (cve_id, quarter, cleaned_description, cwe_id, is_generic) "
        "VALUES (?,?,?,?,?)",
        prepped,
    )
    conn.commit()

    n_total = conn.execute("SELECT COUNT(*) FROM cves_in_scope").fetchone()[0]
    n_rejected = conn.execute("SELECT COUNT(*) FROM cves_in_scope WHERE vuln_status='Rejected'").fetchone()[0]
    print(f"Total in-scope CVEs: {n_total}")
    print(f"Rejected excluded: {n_rejected}")
    print(f"Docs prepped: {len(prepped)}")
    print(f"Near-empty after cleaning (<10 chars, flagged not dropped): {empty_after_cleaning}")

    print("\n--- Docs per quarter (first 8) ---")
    for quarter, n in conn.execute(
        "SELECT quarter, COUNT(*) FROM nlp_docs GROUP BY quarter ORDER BY quarter LIMIT 8"
    ):
        print(f"  {quarter}: {n}")

    print("\n--- Before/after cleaning, 3 samples ---")
    for cve_id, published_date, desc, _, _ in rows[:3]:
        print(f"\n[{cve_id}] RAW: {desc[:150]}")
        print(f"[{cve_id}] CLEANED: {clean_text(desc)[:150]}")

    conn.close()


if __name__ == "__main__":
    main()