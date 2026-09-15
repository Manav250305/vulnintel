"""
Refresh the local CWE identifier -> name catalog from MITRE.

The vulnerability feed records weakness identifiers without names, so this
supplies them. The result is checked into the repository: it is small, changes
only when MITRE publishes a new catalog version, and shipping it means the
dashboard resolves identifiers with no network access.

Run after a new CWE release if identifiers start showing up unnamed:
    python3 dashboard/fetch_cwe_catalog.py
"""
import io
import json
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

CATALOG_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
OUT_PATH = Path(__file__).resolve().parent / "data" / "cwe_catalog.json"
TIMEOUT_SECONDS = 180

# Weaknesses are the real classes; categories and views also appear as CWE-N in
# NVD records, so all three are collected.
NAMED_ELEMENTS = {"Weakness", "Category", "View"}


def main():
    print(f"Downloading {CATALOG_URL} ...")
    with urllib.request.urlopen(CATALOG_URL, timeout=TIMEOUT_SECONDS) as resp:
        payload = resp.read()

    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        xml_name = next(n for n in archive.namelist() if n.endswith(".xml"))
        print(f"Parsing {xml_name} ...")
        root = ET.fromstring(archive.read(xml_name))

    entries = {}
    for element in root.iter():
        if element.tag.split("}")[-1] not in NAMED_ELEMENTS:
            continue
        cwe_id, name = element.get("ID"), element.get("Name")
        if not (cwe_id and name):
            continue
        description = ""
        for child in element:
            if child.tag.split("}")[-1] == "Description":
                # itertext() because descriptions embed inline markup.
                description = " ".join("".join(child.itertext()).split())
                break
        entries[f"CWE-{cwe_id}"] = {"name": name, "description": description}

    ordered = dict(sorted(entries.items(), key=lambda kv: int(kv[0].split("-")[1])))
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(ordered, indent=0))
    print(f"Wrote {OUT_PATH} ({len(ordered)} identifiers, "
          f"{OUT_PATH.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
