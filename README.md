# VulnIntel

Vulnerability intelligence over the full public CVE record — **400,000+ vulnerabilities published between 1988 and 2026** — surfaced through a Streamlit dashboard, with a local LLM for plain-English questions.

It answers questions that a CVE search box cannot: which vendors' problems look alike, which weakness types sit at the structural centre of the ecosystem, how severity has shifted over three decades, and how much of the recent record is still incomplete.

---

## What it does

| View | Question it answers |
|---|---|
| **Trends** | How have disclosures broken down by vendor and weakness type over time? |
| **Vendor profiles** | Which vendors have similar weakness profiles? Memory-safety shops vs. web-injection shops. |
| **Weakness network** | Which weakness types co-occur in the same products, and which are structurally central? |
| **Centrality over time** | Which weakness types are becoming more connected — not just more frequent? Which types does each one travel with, and which products drive that? |
| **Data coverage** | How complete is each year's record, and which figures should you distrust? |
| **Ask the data** | Plain-English questions, including about specific CVE IDs, answered locally by an LLM grounded in computed figures. |

Every view is aggregate, but the records behind it are one step away: a search box above the tabs finds a vulnerability by CVE ID or by words in its description, and each tab has a drill-down listing the records behind what it shows. Select any record to see its severity, description, every weakness assignment (and which one the charts count it under), and its affected products.

---

## Quickstart

Requires Python 3.10+, and [GNU Octave](https://octave.org) for the centrality step.

```bash
git clone https://github.com/<your-username>/vulnintel.git
cd vulnintel

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

streamlit run dashboard/app.py
```

The dashboard ships with the generated CSVs it reads, so it renders immediately. To build the database from scratch — required before any rebuild or refresh:

```bash
python3 sql/fetch_feeds.py --feeds all      # ~100 MB download
python3 sql/ingest_all.py --input data/raw/CVE-all.json.xz
python3 sql/build_trends.py
python3 tableau/export_trend_timeline.py
```

The full ingest streams ~3 GB of decompressed JSON and takes a few minutes. Record search, the drill-downs and the assistant read this database; the weakness neighbourhood also needs the `network` rebuild stage (below) to have run once.

---

## Data source

Vulnerability records come from [fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds), which mirrors NVD and republishes the whole corpus daily as release assets.

**This replaced a direct NVD API integration, deliberately.** The API path had to walk the gap since the last sync in 120-day windows at 5 requests per 30 seconds. Once a database fell more than a few weeks behind, catch-up could not finish inside any reasonable timeout — a real failure mode, not a hypothetical one. Pulling a published archive costs the same whether you are a day or three years behind.

`sql/fetch_feeds.py` picks the smallest sufficient feed:

| Feed | Size | Used when |
|---|---|---|
| `modified` | ~2 MB | database is less than 8 days stale |
| `<year>` | ~15 MB | staler than the 8-day delta covers |
| `all` | ~100 MB | first build |

---

## Two update paths

This split is the core operational idea: routine updates must be fast, so the expensive analysis is decoupled from them.

### Refresh — seconds

The **Refresh now** button, or:

```bash
python3 dashboard/refresh_pipeline.py
```

Fetches the newest feed, loads it, rebuilds the SQL trend views, re-exports CSVs. Takes ~15 seconds. Updates **Trends** and **Data coverage** only.

### Rebuild — minutes

The heavier stages, individually startable from the sidebar or the CLI:

```bash
python3 dashboard/rebuild.py --list
python3 dashboard/rebuild.py --stage network --detach
```

| Stage | Runtime | Updates |
|---|---|---|
| `network` | ~2 min | Weakness network, and the weakness neighbourhood in Centrality over time |
| `vendors` | ~2 min | Vendor profiles |
| `centrality` | ~2 min | Centrality over time (run `network` first) |
| `classifier` | ~5 min | Classifier metrics |
| `text` | ~30–45 min | Description clustering |

Rebuilds run **detached**, so closing the dashboard mid-run does not kill a 40-minute job. They run one at a time — these stages share SQLite's single-writer lock and will otherwise collide. A job whose process dies is reported as `interrupted` rather than appearing to run forever.

An indicator in the sidebar compares the release tag you last ingested against what upstream is publishing, so you can see when new data is available.

---

## Ask the data

A local LLM via [Ollama](https://ollama.com). Nothing leaves the machine; there is no API key and no per-token cost.

```bash
ollama pull mistral
ollama serve
```

**The model never sees raw records.** A 2–7B model asked "which vendor had the most vulnerabilities" will invent a plausible name and count. So every figure it can cite is computed from the database first and handed over as a briefing; the model only reads that briefing and writes prose. It is instructed to refuse anything the briefing does not cover, and does:

> **Q:** How many vulnerabilities did Siemens disclose in March 2019, with CVE IDs?
> **A:** The briefing does not contain information about vulnerabilities disclosed by Siemens for the month of March 2019. To find this information, you would need to check the CVE database, which is not included in the provided briefing.

Naming a CVE ID in a question adds that record to the briefing — description, severity, weakness types and affected products — so the model can explain it in plain English or compare two. The briefing also states what the database does not hold (fixed versions, advisories, exploitation status), so the model refuses those rather than filling them in from general knowledge.

The exact briefing is visible in the UI, so any answer can be audited against its source.

---

## Known data caveat

**Vendor and product figures for recent years are incomplete, and the dashboard says so.**

NVD publishes a CVE first and attaches vendor/product (CPE) records later. The backlog is severe:

| Year | Published | With vendor data |
|---|---|---|
| 2022 | 26,431 | 94.9% |
| 2023 | 30,949 | 93.1% |
| 2024 | 40,704 | 79.1% |
| 2025 | 49,972 | 60.4% |
| 2026 | 76,156 | **46.9%** |

Taken naively this reads as vendor activity plateauing after 2023. It is the opposite: publication volume more than doubled while attribution coverage halved. Distinct vendors appearing per year falls from 6,423 (2023) to 2,847 (2026) for this reason alone.

Treat recent vendor counts as a floor, not a measurement. Weakness-type (CWE) coverage stays near 90% and is unaffected. The **Data coverage** tab quantifies the gap, and affected charts are shaded.

---

## Layout

```
sql/         feed fetching, ingestion, schema, trend views
nlp/         description cleaning, TF-IDF, per-quarter clustering, drift flags
octave/      CWE co-occurrence matrix + from-scratch power iteration
clustering/  vendor feature vectors, PCA + k-means archetypes, stability
models/      weakness classifier, centrality time series, offline forecast experiment
tableau/     CSV exports consumed by the dashboard
dashboard/   Streamlit UI, refresh/rebuild pipelines, local assistant
```

The charts read only the generated CSVs and never compute, so a slow query cannot hang the page. The record-level features — search, drill-downs, the weakness neighbourhood and the assistant's briefing — are the exception: there are too many records to export, so they query the database directly, through a read-only connection, only when opened, using indexed lookups. While a rebuild holds the write lock they say so instead of erroring.

### Design notes

- **Power iteration is implemented from scratch** in Octave and cross-validated against `numpy.linalg.eigh` on every run (`verify_power_iteration.py`), agreeing to ~6e-10.
- **Cluster labels are derived, never hardcoded to cluster IDs.** k-means numbers clusters arbitrarily, so an ID→label table silently mislabels everything the first time you refit. Archetype names are matched to measured category profiles.
- **Analysis years are derived from the data** with a volume floor, not a fixed window. Years before 1999 hold too few records to build a meaningful co-occurrence matrix.
- **Record views add up to the charts.** Drill-downs filter by the same one-weakness-per-record rule the charts count by, and the weakness neighbourhood reads the exact vendor-product-year groups the network is summed from (the `cwe_bucket` table the network stage writes), so its counts equal the network's edge weights.

---

## Caveats worth stating plainly

- **A next-year centrality forecast was tried and left out of the dashboard**, since the project's aim is analysis rather than prediction. `models/train_forecast.py` keeps it as offline work: in a rolling backtest over 2006–2026 it calls whether a weakness type's centrality rises or falls right 60% of the time (45% for always guessing the most common direction), but its error is only 1.3% below "predict no change". The dashboard shows each weakness type's neighbourhood in its place.
- The **classifier degrades on recent data**: ~0.75 accuracy through 2024, falling to 0.571 by 2026. That is a genuine drift signal about vulnerability descriptions changing over time, and it is surfaced rather than hidden.
- **A record with two equally ranked weakness assignments is counted under one of them, but which one is not pinned down.** The canonical-weakness view ranks NVD's own assignments first and has no further tiebreak, so when both come from the same other source (CVE-2026-53900's CWE-345 and CWE-384, for example) the choice depends on how SQLite reads the table. The record view shows every assignment and marks the counted one.
- **Pre-1999 records exist** (NVD backdates some entries to original disclosure — CVE-1999-0095 is dated 1988) but are too sparse for year-over-year analysis.

---

## License

MIT
