"""
Ingest from the consolidated 'CVE-all' feed (fkie-cad/nvd-json-data-feeds
"All" release asset) instead of per-year files.

Why this replaces ingest.py's per-year approach: CVE-all contains every CVE
ever published (1999-present), so there's no guessing which CVE-ID-year files
to download to avoid under-counting at the edges (see PHASE1_NOTES.md's note
on the 2018 backfill; that workaround is no longer needed with this source).

Loads the full published-year history by default. --scope-start/--scope-end
remain available to restrict to a window, but nothing is filtered unless one
is explicitly passed.

Memory: the decompressed file is ~3GB, which OOMs a naive json.load() in
memory-constrained environments. This script never materializes the full
JSON structure at once -- it streams directly out of the .xz archive with
ijson, filtering to the in-scope window and batch-inserting into SQLite as it
goes, so peak memory stays roughly constant regardless of file size.

Accepts several feeds in one pass. They load in the order given and later
files win, so a stale bulk archive can be topped up with fresher per-year
files from the same fkie-cad release without re-downloading the whole thing:

    python3 ingest_all.py --input CVE-all.json.xz CVE-2025.json.xz CVE-2026.json.xz

Usage:
    python3 ingest_all.py --input /path/to/CVE-all.json.xz
    python3 ingest_all.py --input /path/to/CVE-all.json        # also accepts plain JSON
"""
import argparse
import lzma
import sqlite3
from pathlib import Path

import ijson

from nvd_parser import parse_item  # reuse shared parsing logic

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
BATCH_SIZE = 10_000


def open_feed(path: Path):
    """Return a binary file-like object, transparently handling .xz or plain .json."""
    if path.suffix == ".xz":
        return lzma.open(path, "rb")
    return open(path, "rb")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, nargs="+",
                    help="One or more CVE-*.json/.json.xz feeds. Loaded in order; later files win.")
    ap.add_argument("--scope-start", type=int, default=None,
                    help="Optional earliest published_year to load (default: no lower bound)")
    ap.add_argument("--scope-end", type=int, default=None,
                    help="Optional latest published_year to load (default: no upper bound)")
    ap.add_argument("--append", action="store_true",
                    help="Top up the existing database instead of rebuilding it from scratch. "
                         "Use to apply a fresher per-year feed without re-parsing the bulk archive.")
    args = ap.parse_args()
    input_paths = [Path(p) for p in args.input]
    missing = [p for p in input_paths if not p.exists()]
    if missing:
        raise SystemExit("Input feed(s) not found: " + ", ".join(str(p) for p in missing))

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if args.append and not DB_PATH.exists():
        raise SystemExit(f"--append needs an existing database at {DB_PATH}")
    if not args.append and DB_PATH.exists():
        DB_PATH.unlink()

    conn = sqlite3.connect(DB_PATH)
    # Write-ahead logging so the dashboard can keep reading while a rebuild
    # writes. In the default rollback mode a writer locks the file outright and
    # even read-only connections fail, which took the whole dashboard down
    # whenever a long stage was running. The setting persists in the file.
    conn.execute("PRAGMA journal_mode = WAL")
    if not args.append:
        # Load only the table/index DDL, not the old scope-filtering view --
        # `cves_in_scope` is created as a passthrough below so Phase 2+ queries
        # (written against that name) don't need to change.
        ddl = SCHEMA_PATH.read_text().split("CREATE INDEX idx_cves_year")[0]
        conn.executescript(ddl)
        conn.executescript("""
            CREATE INDEX idx_cves_year ON cves(published_year);
            CREATE INDEX idx_cve_cwe_cve ON cve_cwe(cve_id);
            CREATE INDEX idx_cve_cwe_cwe ON cve_cwe(cwe_id);
            CREATE INDEX idx_cve_cpe_cve ON cve_cpe(cve_id);
            CREATE INDEX idx_cve_cpe_vendor_product ON cve_cpe(vendor, product);
        """)

    cve_buf, cwe_buf, cpe_buf = [], [], []
    total, in_scope, skipped = 0, 0, 0

    def flush(replace=False):
        # When a later feed restates a CVE, drop its existing child rows first:
        # INSERT OR IGNORE alone would leave stale CWE/CPE rows behind whenever
        # an assignment was withdrawn upstream.
        if replace and cve_buf:
            ids = [(r[0],) for r in cve_buf]
            conn.executemany("DELETE FROM cve_cwe WHERE cve_id = ?", ids)
            conn.executemany("DELETE FROM cve_cpe WHERE cve_id = ?", ids)
        if cve_buf:
            conn.executemany(
                "INSERT OR REPLACE INTO cves (id, published_date, published_year, last_modified, "
                "vuln_status, description, cvss_score, cvss_version, severity) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                cve_buf,
            )
        if cwe_buf:
            conn.executemany(
                "INSERT OR IGNORE INTO cve_cwe (cve_id, cwe_id, source, type, is_generic) "
                "VALUES (?,?,?,?,?)",
                cwe_buf,
            )
        if cpe_buf:
            conn.executemany(
                "INSERT OR IGNORE INTO cve_cpe (cve_id, part, vendor, product, version) "
                "VALUES (?,?,?,?,?)",
                cpe_buf,
            )
        conn.commit()
        cve_buf.clear(); cwe_buf.clear(); cpe_buf.clear()

    for n_file, input_path in enumerate(input_paths):
        replace = args.append or n_file > 0  # only a fresh DB's first feed can skip the overwrite path
        print(f"\nLoading {input_path.name}...")
        with open_feed(input_path) as f:
            for item in ijson.items(f, "cve_items.item"):
                total += 1
                parsed = parse_item(item)
                if parsed is None:
                    skipped += 1
                    continue

                cve_row, item_cwe_rows, item_cpe_rows = parsed
                published_year = cve_row[2]
                if args.scope_start is not None and published_year < args.scope_start:
                    continue
                if args.scope_end is not None and published_year > args.scope_end:
                    continue

                in_scope += 1
                cve_buf.append(cve_row)
                cwe_buf.extend(item_cwe_rows)
                cpe_buf.extend(item_cpe_rows)

                if len(cve_buf) >= BATCH_SIZE:
                    flush(replace)
                    print(f"  ...{total} scanned, {in_scope} loaded so far")

        flush(replace)

    conn.execute("DROP VIEW IF EXISTS cves_in_scope")
    conn.execute("CREATE VIEW cves_in_scope AS SELECT * FROM cves")  # already scoped at ingest time
    conn.commit()

    window = "all years" if args.scope_start is None and args.scope_end is None else \
             f"published {args.scope_start or 'min'}-{args.scope_end or 'max'}"
    print(f"\nScanned {total} total CVEs across full NVD history, skipped {skipped} (no English description)")
    print(f"Loaded {in_scope} CVEs ({window})")

    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cves")
    print("cves table count:", cur.fetchone()[0])
    cur.execute("SELECT MIN(published_year), MAX(published_year) FROM cves")
    print("published_year range: %s-%s" % cur.fetchone())
    cur.execute("SELECT COUNT(DISTINCT cve_id) FROM cve_cwe")
    print("CVEs with >=1 CWE:", cur.fetchone()[0])
    cur.execute("SELECT COUNT(DISTINCT cve_id) FROM cve_cpe")
    print("CVEs with >=1 CPE match:", cur.fetchone()[0])
    cur.execute("SELECT COUNT(DISTINCT vendor) FROM cve_cpe")
    print("Distinct vendors:", cur.fetchone()[0])

    conn.close()


if __name__ == "__main__":
    main()
