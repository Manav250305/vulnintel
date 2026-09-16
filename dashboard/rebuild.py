"""
Run the heavy analysis stages that the quick refresh deliberately skips.

The quick refresh only reloads CVE records and rebuilds the SQL trend views,
because everything else -- text clustering, the weakness-relationship network,
vendor profiles, the forecast -- takes minutes to hours and would make a
routine data pull unusable. Those stages live here instead, each one startable
on its own.

Runs detached: a stage is spawned in its own session, writes to its own log,
and keeps going if the dashboard is closed or restarted mid-run. The dashboard
polls the status file rather than holding the job open.

Usage:
    python3 rebuild.py --list
    python3 rebuild.py --stage network        # run in the foreground
    python3 rebuild.py --stage network --detach
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

DASHBOARD_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DASHBOARD_DIR.parent
DATA_DIR = DASHBOARD_DIR / "data"
STATE_DIR = DATA_DIR / "rebuild_state"
VENV_PY = PROJECT_ROOT / "venv" / "bin" / "python3"
PYTHON = str(VENV_PY if VENV_PY.exists() else sys.executable)

# Each stage lists the commands to run in order, plus the dashboard files it
# refreshes, so the UI can say what a rebuild actually changes.
STAGES = {
    "text": {
        "title": "Description clustering",
        "blurb": "Re-groups vulnerability descriptions by wording, quarter by "
                 "quarter, and flags clusters whose labelling looks inconsistent. "
                 "This is the slow one.",
        "runtime": "~30-45 minutes",
        "updates": [],
        "depends_on": [],
        "steps": [
            ([PYTHON, "preprocess.py"], PROJECT_ROOT / "nlp"),
            ([PYTHON, "vectorize.py"], PROJECT_ROOT / "nlp"),
            ([PYTHON, "cluster.py"], PROJECT_ROOT / "nlp"),
            ([PYTHON, "flag_drift.py"], PROJECT_ROOT / "nlp"),
        ],
        "artifacts": [],
    },
    "network": {
        "title": "Weakness relationship network",
        "blurb": "Recomputes which weakness types co-occur in the same products "
                 "and scores how central each one is.",
        "runtime": "~2 minutes",
        "updates": ["CWE Co-occurrence"],
        "depends_on": [],
        "steps": [
            ([PYTHON, "build_cooccurrence.py"], PROJECT_ROOT / "octave"),
            (["octave", "--no-gui", "--quiet", "power_iteration.m"], PROJECT_ROOT / "octave"),
            ([PYTHON, "verify_power_iteration.py"], PROJECT_ROOT / "octave"),
            ([PYTHON, "export_cooccurrence_network.py"], PROJECT_ROOT / "tableau"),
        ],
        "artifacts": ["cooccurrence_nodes.csv", "cooccurrence_edges.csv"],
    },
    "vendors": {
        "title": "Vendor profiles",
        "blurb": "Rebuilds each vendor's weakness profile and regroups vendors "
                 "into archetypes.",
        "runtime": "~2 minutes",
        "updates": ["Vendor Archetypes"],
        "depends_on": [],
        "steps": [
            ([PYTHON, "build_vendor_features.py"], PROJECT_ROOT / "clustering"),
            ([PYTHON, "vendor_archetypes.py"], PROJECT_ROOT / "clustering"),
            ([PYTHON, "vendor_stability.py"], PROJECT_ROOT / "clustering"),
            ([PYTHON, "export_vendor_cluster_map.py"], PROJECT_ROOT / "tableau"),
        ],
        "artifacts": ["vendor_cluster_map.csv"],
    },
    "centrality": {
        "title": "Centrality history and forecast",
        "blurb": "Rebuilds the per-year centrality series and retrains the "
                 "next-year forecast.",
        "runtime": "~2 minutes",
        "updates": ["Centrality Time Series"],
        # Reads the fixed weakness index the network stage writes, and the
        # clustering tables the text stage writes.
        "depends_on": ["network", "text"],
        "steps": [
            ([PYTHON, "build_centrality_timeseries.py"], PROJECT_ROOT / "models"),
            ([PYTHON, "train_forecast.py"], PROJECT_ROOT / "models"),
        ],
        "artifacts": ["centrality_timeseries.csv", "forecast_results.csv"],
    },
    "classifier": {
        "title": "Weakness classifier",
        "blurb": "Retrains the model that predicts a weakness category from a "
                 "vulnerability description, and re-measures its accuracy by year.",
        "runtime": "~5 minutes",
        "updates": [],
        # Trains on the cleaned descriptions the text stage writes.
        "depends_on": ["text"],
        "steps": [
            ([PYTHON, "build_dataset.py"], PROJECT_ROOT / "models"),
            ([PYTHON, "train_classifier.py"], PROJECT_ROOT / "models"),
        ],
        "artifacts": [],
    },
}

# Files each stage copies from the export folders into the dashboard's own
# data folder once it finishes.
EXPORT_SOURCES = [PROJECT_ROOT / "tableau" / "exports", PROJECT_ROOT / "models" / "data"]


def state_path(stage):
    return STATE_DIR / f"{stage}.json"


def log_path(stage):
    return STATE_DIR / f"{stage}.log"


def read_state(stage):
    path = state_path(stage)
    if not path.exists():
        return None
    try:
        state = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    # A crashed or killed job never gets to write its own ending, so treat a
    # "running" record whose process is gone as failed rather than showing a
    # job that appears to run forever.
    if state.get("status") == "running" and not _pid_alive(state.get("pid")):
        state["status"] = "interrupted"
        state["finished"] = state.get("finished") or datetime.now(timezone.utc).isoformat()
    return state


def _pid_alive(pid):
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
    except (OSError, ValueError):
        return False
    return True


def _write_state(name, **fields):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    existing = {}
    if state_path(name).exists():
        try:
            existing = json.loads(state_path(name).read_text())
        except (json.JSONDecodeError, OSError):
            existing = {}
    existing.update(fields, stage=name)
    state_path(name).write_text(json.dumps(existing, indent=2, default=str))
    return existing


def is_running(stage):
    state = read_state(stage)
    return bool(state and state.get("status") == "running")


def _finished_at(stage):
    state = read_state(stage)
    if not state or state.get("status") != "complete" or not state.get("finished"):
        return None
    try:
        return datetime.fromisoformat(state["finished"])
    except ValueError:
        return None


def blocking_dependencies(stage):
    """Dependencies that would make this stage's output wrong if run now.

    Two ways a dependency can be a problem: it has never completed, so the
    input file or table this stage reads is absent or left over from an older
    dataset; or it completed before the most recent data refresh, so its output
    describes a corpus that no longer matches the database. Both produce a
    stage that runs cleanly and reports figures for the wrong data, which is
    worse than failing."""
    problems = []
    data_changed = _last_refresh_time()

    for dependency in STAGES[stage].get("depends_on", []):
        finished = _finished_at(dependency)
        if finished is None:
            problems.append((dependency, "has not completed"))
        elif data_changed and finished < data_changed:
            problems.append((dependency, "last ran before the newest data arrived"))
    return problems


def _last_refresh_time():
    path = DATA_DIR / "refresh_status.json"
    if not path.exists():
        return None
    try:
        status = json.loads(path.read_text())
        return datetime.fromisoformat(status["finished"])
    except (json.JSONDecodeError, OSError, KeyError, ValueError):
        return None


def recommended_order():
    """Stage names in an order that satisfies every dependency."""
    ordered, seen = [], set()

    def visit(name):
        if name in seen:
            return
        seen.add(name)
        for dependency in STAGES[name].get("depends_on", []):
            visit(dependency)
        ordered.append(name)

    for name in STAGES:
        visit(name)
    return ordered


def start(stage):
    """Spawn a stage in its own session and return immediately."""
    if stage not in STAGES:
        raise KeyError(stage)
    if is_running(stage):
        return read_state(stage)

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    log_path(stage).write_text("")
    cmd = [PYTHON, str(Path(__file__).resolve()), "--stage", stage, "--_child"]
    with open(log_path(stage), "a") as log:
        proc = subprocess.Popen(
            cmd, cwd=str(DASHBOARD_DIR), stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,  # outlives the dashboard process
        )
    return _write_state(
        stage, status="running", pid=proc.pid,
        started=datetime.now(timezone.utc).isoformat(), finished=None,
        failed_step=None,
    )


def cancel(stage):
    state = read_state(stage)
    if not state or state.get("status") != "running":
        return state
    try:
        os.killpg(os.getpgid(int(state["pid"])), signal.SIGTERM)
    except (OSError, ValueError, KeyError):
        pass
    return _write_state(stage, status="cancelled",
                        finished=datetime.now(timezone.utc).isoformat())


def tail_log(stage, max_bytes=20000):
    path = log_path(stage)
    if not path.exists():
        return ""
    data = path.read_text(errors="replace")
    return data[-max_bytes:]


def _copy_artifacts(stage):
    """Publish a finished stage's outputs into the dashboard's data folder."""
    copied = []
    for name in STAGES[stage]["artifacts"]:
        for source_dir in EXPORT_SOURCES:
            src = source_dir / name
            if src.exists():
                (DATA_DIR / name).write_bytes(src.read_bytes())
                copied.append(name)
                break
    return copied


def run(stage, verbose=True):
    """Run a stage's steps in order. Stops at the first failure."""
    spec = STAGES[stage]
    _write_state(stage, status="running", pid=os.getpid(),
                 started=datetime.now(timezone.utc).isoformat(), finished=None,
                 failed_step=None)
    started = time.time()

    for i, (cmd, cwd) in enumerate(spec["steps"], start=1):
        label = " ".join(Path(c).name if "/" in c else c for c in cmd)
        if verbose:
            print(f"\n=== [{i}/{len(spec['steps'])}] {label} ===", flush=True)
        result = subprocess.run(cmd, cwd=str(cwd), stdout=sys.stdout,
                                 stderr=subprocess.STDOUT)
        if result.returncode != 0:
            print(f"\n[FAILED] {label} exited {result.returncode}", flush=True)
            _write_state(stage, status="failed", failed_step=label,
                         finished=datetime.now(timezone.utc).isoformat(),
                         duration_seconds=time.time() - started)
            return False

    copied = _copy_artifacts(stage)
    if copied:
        print(f"\nPublished to dashboard: {', '.join(copied)}", flush=True)
    print(f"\nDone in {time.time() - started:.1f}s", flush=True)
    _write_state(stage, status="complete",
                 finished=datetime.now(timezone.utc).isoformat(),
                 duration_seconds=time.time() - started)
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=sorted(STAGES))
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--detach", action="store_true", help="Spawn and return immediately")
    ap.add_argument("--_child", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.list or not args.stage:
        print("Run in this order after new data arrives "
              f"({' -> '.join(recommended_order())}):\n")
        for name in recommended_order():
            spec = STAGES[name]
            state = read_state(name)
            status = state["status"] if state else "never run"
            needs = ", ".join(spec.get("depends_on", [])) or "-"
            print(f"{name:<12} {spec['runtime']:<18} {status:<12} "
                  f"needs: {needs:<16} {spec['title']}")
            for dependency, reason in blocking_dependencies(name):
                print(f"{'':<12} ^ '{dependency}' {reason}")
        return

    if args.detach:
        state = start(args.stage)
        print(f"Started '{args.stage}' (pid {state['pid']}). Log: {log_path(args.stage)}")
        return

    sys.exit(0 if run(args.stage) else 1)


if __name__ == "__main__":
    main()
