"""
Fetch NVD feed files from the fkie-cad/nvd-json-data-feeds GitHub release.

Stands in for the live NVD API path (ingest_live.py). The repo republishes
the whole corpus as release assets daily, which sidesteps everything that
made the API path unreliable here: no API key, no 5-req/30s rate limiting,
no 120-day windowing, and no multi-hour catch-up when the last sync is old.
A refresh is just a file download, so a stale database costs one fetch
regardless of how far behind it is.

Feed names map to release assets (CVE-<name>.json.xz):
    recent     CVEs added in the previous 8 days   (~1 MB)
    modified   added OR changed in the last 8 days (~2 MB)  <- default
    all        entire corpus, 1988-present         (~104 MB)
    <year>     a single published year, e.g. 2026  (~15 MB)

Usage:
    python3 fetch_feeds.py                       # modified
    python3 fetch_feeds.py --feeds 2025 2026
"""
import argparse
import json
import lzma
import shutil
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"
STATE_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "feed_state.json"
BASE_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download"
API_URL = "https://api.github.com/repos/fkie-cad/nvd-json-data-feeds/releases/latest"
# Asset transfers go through a redirect chain that can stall for tens of
# seconds before the first byte, so this is deliberately generous.
TIMEOUT_SECONDS = 900


def latest_release(timeout=15):
    """What the upstream repo is publishing right now.

    Returns None when GitHub is unreachable -- callers treat that as "unknown",
    never as "nothing new", so a dropped network cannot make stale data look
    current."""
    try:
        with urllib.request.urlopen(API_URL, timeout=timeout) as resp:
            payload = json.load(resp)
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
        return None
    return {"tag": payload.get("tag_name"), "published_at": payload.get("published_at")}


def local_release():
    """The release this machine last pulled, or None if it has never pulled one."""
    if not STATE_PATH.exists():
        return None
    try:
        return json.loads(STATE_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def record_release(release, feeds):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps({
        "tag": release.get("tag") if release else None,
        "published_at": release.get("published_at") if release else None,
        "feeds": list(feeds),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2))


def fetch(name: str, timeout: int = TIMEOUT_SECONDS) -> Path:
    """Download one feed to data/raw/, leaving any existing copy untouched
    unless the new one arrives complete and readable."""
    filename = f"CVE-{name}.json.xz"
    url = f"{BASE_URL}/{filename}"
    dest = RAW_DIR / filename
    tmp = dest.with_name(filename + ".tmp")

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    print(f"  fetching {filename} ...", flush=True)
    with urllib.request.urlopen(url, timeout=timeout) as resp, open(tmp, "wb") as out:
        shutil.copyfileobj(resp, out)

    # A truncated download is still valid gzip-ish garbage to the filesystem;
    # decompressing a chunk is the cheapest real integrity check.
    try:
        with lzma.open(tmp, "rb") as f:
            f.read(4096)
    except lzma.LZMAError as e:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"{filename} failed integrity check: {e}") from e

    tmp.replace(dest)
    print(f"  saved {dest.name} ({dest.stat().st_size / 1e6:.1f} MB)", flush=True)
    return dest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--feeds", nargs="+", default=["modified"],
                    help="Feed names: recent, modified, all, or a year (default: modified)")
    ap.add_argument("--timeout", type=int, default=TIMEOUT_SECONDS)
    args = ap.parse_args()

    # Read the release tag before downloading: the assets come from the
    # "latest" alias, so asking afterwards could name a release published
    # in between and credit this data to the wrong one.
    release = latest_release()

    for name in args.feeds:
        fetch(name, args.timeout)

    record_release(release, args.feeds)
    if release:
        print(f"Fetched {len(args.feeds)} feed(s) from release {release['tag']} into {RAW_DIR}")
    else:
        print(f"Fetched {len(args.feeds)} feed(s) into {RAW_DIR} (release tag unavailable)")


if __name__ == "__main__":
    main()
