# VulnIntel

Vulnerability intelligence over the full public CVE record — **391,000+ vulnerabilities published between 1988 and 2026** — surfaced through a Streamlit dashboard, with a local LLM for plain-English questions.

It answers questions that a CVE search box cannot: which vendors' problems look alike, which weakness types sit at the structural centre of the ecosystem, how severity has shifted over three decades, and how much of the recent record is still incomplete.

---

## What it does

| View | Question it answers |
|---|---|
| **Trends** | How have disclosures broken down by vendor and weakness type over time? |
| **Vendor profiles** | Which vendors have similar weakness profiles? Memory-safety shops vs. web-injection shops. |
| **Weakness network** | Which weakness types co-occur in the same products, and which are structurally central? |
| **Centrality over time** | Which weakness types are becoming more connected — not just more frequent? |
| **Data coverage** | How complete is each year's record, and which figures should you distrust? |
| **Ask the data** | Plain-English questions, answered locally by an LLM grounded in computed figures. |

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

The full ingest streams ~3 GB of decompressed JSON and takes a few minutes.

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
| `network` | ~2 min | Weakness network |
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
| 2026 | 66,288 | **49.3%** |

Taken naively this reads as vendor activity plateauing after 2023. It is the opposite: publication volume more than doubled while attribution coverage halved. Distinct vendors appearing per year falls from 6,423 (2023) to 2,828 (2026) for this reason alone.

Treat recent vendor counts as a floor, not a measurement. Weakness-type (CWE) coverage stays near 90% and is unaffected. The **Data coverage** tab quantifies the gap, and affected charts are shaded.

---

## Layout

```
sql/         feed fetching, ingestion, schema, trend views
nlp/         description cleaning, TF-IDF, per-quarter clustering, drift flags
octave/      CWE co-occurrence matrix + from-scratch power iteration
clustering/  vendor feature vectors, PCA + k-means archetypes, stability
models/      weakness classifier, centrality time series, forecast
tableau/     CSV exports consumed by the dashboard
dashboard/   Streamlit UI, refresh/rebuild pipelines, local assistant
```

The dashboard is presentation-only — it reads CSVs and never computes, so a slow query cannot hang the page.

### Design notes

- **Power iteration is implemented from scratch** in Octave and cross-validated against `numpy.linalg.eigh` on every run (`verify_power_iteration.py`), agreeing to ~6e-10.
- **Cluster labels are derived, never hardcoded to cluster IDs.** k-means numbers clusters arbitrarily, so an ID→label table silently mislabels everything the first time you refit. Archetype names are matched to measured category profiles.
- **Analysis years are derived from the data** with a volume floor, not a fixed window. Years before 1999 hold too few records to build a meaningful co-occurrence matrix.

---

## Caveats worth stating plainly

- The **centrality forecast does not beat a "predict no change" baseline.** Feature importance is 0.95 on the previous year's value — it is closer to a persistence model than a forecast. It is shown to demonstrate the approach, not to plan against.
- The **classifier degrades on recent data**: ~0.75 accuracy through 2024, falling to 0.571 by 2026. That is a genuine drift signal about vulnerability descriptions changing over time, and it is surfaced rather than hidden.
- **Pre-1999 records exist** (NVD backdates some entries to original disclosure — CVE-1999-0095 is dated 1988) but are too sparse for year-over-year analysis.

---

## License

MIT
