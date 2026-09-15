"""
CWE identifier -> official MITRE name.

The NVD feed records weakness identifiers only, never their names, so without
this a language model asked about "CWE-416" has nothing to work from and will
invent a plausible-sounding expansion. (Observed: CWE-416 rendered as "Improper
Use of a Long or Cyclic Buffer", which is not a real weakness.)

Names come from MITRE's published catalog, checked in as data/cwe_catalog.json
so the dashboard needs no network access and every install resolves an
identifier the same way. Refresh it with:

    python3 dashboard/fetch_cwe_catalog.py

An identifier missing from the catalog is reported as unknown rather than
guessed -- lookup() returns None so callers can tell the difference.
"""
import functools
import json
from pathlib import Path

CATALOG_PATH = Path(__file__).resolve().parent / "data" / "cwe_catalog.json"

# Coarse families, used to characterise a vendor's profile. These groupings are
# our own editorial judgement, not part of MITRE's taxonomy.
MEMORY_SAFETY = {"CWE-787", "CWE-119", "CWE-125", "CWE-416", "CWE-476", "CWE-120",
                 "CWE-190", "CWE-908", "CWE-415", "CWE-121", "CWE-122", "CWE-843",
                 "CWE-401", "CWE-824", "CWE-134", "CWE-129"}
WEB_INJECTION = {"CWE-79", "CWE-89", "CWE-352", "CWE-22", "CWE-78", "CWE-94",
                 "CWE-74", "CWE-77", "CWE-434", "CWE-98", "CWE-918", "CWE-611",
                 "CWE-80", "CWE-90", "CWE-113", "CWE-1321"}


@functools.lru_cache(maxsize=1)
def _catalog():
    try:
        return json.loads(CATALOG_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def lookup(cwe_id):
    """Official name, or None when the identifier is not in the catalog."""
    if cwe_id in ("NVD-CWE-noinfo", "NVD-CWE-Other"):
        return ("No weakness information provided" if cwe_id.endswith("noinfo")
                else "Other / not mapped to a specific weakness")
    entry = _catalog().get(cwe_id)
    return entry.get("name") if entry else None


def describe(cwe_id):
    """MITRE's one-line definition of the weakness, or None."""
    entry = _catalog().get(cwe_id)
    return (entry.get("description") or None) if entry else None


def label(cwe_id):
    """'CWE-416 (Use After Free)', or just 'CWE-416' when the name is unknown."""
    name = lookup(cwe_id)
    return f"{cwe_id} ({name})" if name else cwe_id
