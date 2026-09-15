"""
Phase 9 -- background scheduler for periodic refresh.

Runs independently of the Streamlit app/browser session -- this is a
genuinely separate process, not tied to anyone having the dashboard open.
That distinction matters: Streamlit's own st.fragment(run_every=...) can
auto-rerun something while a browser tab is connected, but the underlying
data would go stale the moment everyone closes the tab. This script keeps
refreshing on a fixed interval regardless of whether anyone is looking.

This is a simple loop, not a production-grade job scheduler -- it does not
survive a crash or reboot on its own. For an actual production deployment,
run this under systemd (Linux), a Scheduled Task (Windows), launchd
(macOS), or cron, rather than as a bare background process. Documented
here rather than built, since that choice depends on the person's actual
deployment target, which this project doesn't have one fixed answer for.

Usage:
    python3 scheduler.py                  # default: every 20 minutes
    python3 scheduler.py --interval 300   # every 5 minutes (seconds)

Run it in the background, e.g.:
    nohup python3 scheduler.py > scheduler.log 2>&1 &
"""
import argparse
import time
from datetime import datetime, timezone

from refresh_pipeline import refresh

DEFAULT_INTERVAL_SECONDS = 20 * 60  # 20 minutes -- frequent enough to feel
                                     # "real-time" for a fast-tier refresh,
                                     # infrequent enough not to hammer the
                                     # NVD API or waste requests on a corpus
                                     # that hasn't meaningfully changed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_SECONDS,
                     help=f"Seconds between refreshes (default {DEFAULT_INTERVAL_SECONDS})")
    args = ap.parse_args()

    print(f"Scheduler started. Refreshing every {args.interval}s. Ctrl+C to stop.")
    while True:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"\n[{now}] Running scheduled refresh...")
        try:
            status = refresh(verbose=True)
            print(f"[{now}] Refresh complete: overall_ok={status['overall_ok']}")
        except Exception as e:
            # A failed refresh cycle should never kill the scheduler itself --
            # log it and try again next interval.
            print(f"[{now}] Refresh cycle raised an unhandled exception: {e}")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()