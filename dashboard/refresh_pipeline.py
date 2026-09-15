"""
Phase 9 -- real-time refresh pipeline (fast tier only).

Deliberately scoped to what's safe to run frequently: incremental live-data
sync, rebuilding Phase 2's SQL trend views, and re-exporting the trend CSVs
the dashboard's Trends tab reads. NOT included: NLP clustering, Octave
centrality, classifier training, vendor archetypes -- these take minutes and
depend on the full corpus, which doesn't meaningfully shift in a 15-30
minute refresh window. Running them on the same cadence as the fast tier
would make every refresh (button or scheduled) take minutes, defeating the
point of "real-time." They're left on manual/periodic refresh instead --
see PHASE9_NOTES.md for the reasoning.

Data comes from the fkie-cad/nvd-json-data-feeds release assets, not the
live NVD API. The API path (ingest_live.py, still present) had to walk the
gap since the last sync in 120-day windows at 5 requests per 30 seconds,
so a database more than a few weeks stale could not catch up inside any
sane timeout -- an actual failure mode here, not a hypothetical. The repo
republishes the whole corpus daily, so a refresh is one file download whose
cost does not grow with how far behind the database is.

Which feed to pull depends on staleness: the 8-day `modified` delta when
the data is fresh, the current year's file when it is not. Both land in
data/raw/ and load via ingest_all.py --append.

Usage (CLI, for manual testing):
    python3 refresh_pipeline.py
"""
import json
import sqlite3
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path

DASHBOARD_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DASHBOARD_DIR.parent
SQL_DIR = PROJECT_ROOT / "sql"
TABLEAU_DIR = PROJECT_ROOT / "tableau"
DATA_DIR = DASHBOARD_DIR / "data"
RAW_DIR = PROJECT_ROOT / "data" / "raw"
DB_PATH = PROJECT_ROOT / "data" / "processed" / "vulnintel.db"
STATUS_PATH = DATA_DIR / "refresh_status.json"

# The `modified` feed only reaches back 8 days; past that it would leave a
# hole, so fall back to the whole current year (bigger, but still one file).
MODIFIED_FEED_COVERAGE_DAYS = 8

TREND_CSV_NAMES = ["vendor_year_trend.csv", "cwe_year_trend.csv", "severity_year_trend.csv",
                   "data_coverage.csv"]


def _run(cmd, cwd, timeout):
    """Run a subprocess, always returning a result rather than raising --
    a failed step (e.g. no network) shouldn't crash the whole refresh; later
    steps should still run against whatever's already on disk."""
    try:
        result = subprocess.run(
            [sys.executable] + cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
        )
        return {"ok": result.returncode == 0, "stdout": result.stdout[-2000:],
                "stderr": result.stderr[-2000:], "returncode": result.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": f"Timed out after {timeout}s", "returncode": None}
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": str(e), "returncode": None}


def _choose_feed():
    """Pick the smallest feed that still covers everything we're missing."""
    if not DB_PATH.exists():
        return "all"
    try:
        with sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True) as conn:
            newest = conn.execute("SELECT MAX(published_date) FROM cves").fetchone()[0]
    except sqlite3.Error:
        return "all"
    if not newest:
        return "all"

    gap_days = (datetime.now(timezone.utc).date() - date.fromisoformat(newest[:10])).days
    if gap_days <= MODIFIED_FEED_COVERAGE_DAYS:
        return "modified"
    return str(datetime.now(timezone.utc).year)


def refresh(verbose=True, on_step=None):
    steps = {}
    started = datetime.now(timezone.utc)

    def _emit(key, label):
        """Report a finished step to the caller as it happens, so a UI can show
        progress instead of blocking silently until the whole run returns."""
        if on_step:
            on_step(key, label, steps[key])

    # Step 1: pull the newest feed from the fkie-cad release and load it.
    # Network-dependent, so a failure here is logged and stepped over rather
    # than aborting the refresh -- views and exports still rebuild against
    # whatever is already in the database.
    feed = _choose_feed()
    if verbose:
        print(f"[1/3] Fetching '{feed}' feed from fkie-cad release...")
    steps["ingest"] = _run(["fetch_feeds.py", "--feeds", feed], cwd=SQL_DIR, timeout=900)
    steps["ingest"]["mode"] = feed

    if steps["ingest"]["ok"]:
        if verbose:
            print(f"[1/3] Loading CVE-{feed}.json.xz into the database...")
        load = _run(["ingest_all.py", "--append", "--input",
                     str(RAW_DIR / f"CVE-{feed}.json.xz")], cwd=SQL_DIR, timeout=1800)
        # Surface the load's outcome under the same key the dashboard reads:
        # a fetch that downloaded fine but failed to load is not a success.
        steps["ingest"]["ok"] = load["ok"]
        steps["ingest"]["stdout"] = (steps["ingest"]["stdout"] + load["stdout"])[-2000:]
        steps["ingest"]["stderr"] = (steps["ingest"]["stderr"] + load["stderr"])[-2000:]
    _emit("ingest", f"Fetch '{feed}' feed and load into database")

    # Step 2: rebuild Phase 2 SQL views -- runs regardless of step 1's outcome,
    # against whatever's currently in the database
    if verbose:
        print("[2/3] Rebuilding trend views...")
    steps["rebuild_views"] = _run(["build_trends.py"], cwd=SQL_DIR, timeout=120)
    _emit("rebuild_views", "Rebuild trend views")

    # Step 3: re-export the trend CSVs the dashboard reads, then copy them
    # into dashboard/data/
    if verbose:
        print("[3/3] Re-exporting trend CSVs...")
    steps["export"] = _run(["export_trend_timeline.py"], cwd=TABLEAU_DIR, timeout=60)
    if steps["export"]["ok"]:
        for name in TREND_CSV_NAMES:
            src = TABLEAU_DIR / "exports" / name
            if src.exists():
                (DATA_DIR / name).write_bytes(src.read_bytes())
    _emit("export", "Re-export trend CSVs")

    finished = datetime.now(timezone.utc)
    status = {
        "started": started.isoformat(),
        "finished": finished.isoformat(),
        "duration_seconds": (finished - started).total_seconds(),
        "ingest_ok": steps["ingest"]["ok"],
        "ingest_mode": steps["ingest"]["mode"],
        "rebuild_views_ok": steps["rebuild_views"]["ok"],
        "export_ok": steps["export"]["ok"],
        "overall_ok": steps["rebuild_views"]["ok"] and steps["export"]["ok"],
        # ingest failing (e.g. no network) doesn't mark the whole refresh
        # failed -- views/export still ran against the existing database
        "steps": steps,
    }
    STATUS_PATH.write_text(json.dumps(status, indent=2, default=str))

    if verbose:
        print(f"\nDone in {status['duration_seconds']:.1f}s. "
              f"ingest_ok={status['ingest_ok']} (mode={status['ingest_mode']}), "
              f"rebuild_views_ok={status['rebuild_views_ok']}, export_ok={status['export_ok']}")
        if not status["ingest_ok"]:
            print(f"  ingest stderr (informational, non-fatal): {steps['ingest']['stderr'][:300]}")

    return status


if __name__ == "__main__":
    refresh()