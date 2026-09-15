"""
Vulnerability Intelligence Dashboard — Streamlit UI.

Presentation layer only: everything shown here is read from the CSVs in
dashboard/data/, which the refresh and rebuild pipelines write. No analysis
runs in this file, so a slow query can never hang the page.

Run with: streamlit run app.py
"""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import json
from datetime import datetime, timezone
from pathlib import Path

import sys

import assistant
import rebuild
from refresh_pipeline import refresh, STATUS_PATH

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sql"))
import fetch_feeds  # noqa: E402  -- lives with the ingestion code, not the UI

DATA_DIR = Path(__file__).resolve().parent / "data"
REFRESH_TTL_SECONDS = 300  # data reloads from disk at least this often even
                             # without a manual click, so the app doesn't
                             # serve indefinitely-stale cached data between
                             # scheduler cycles
# The feed repo rebuilds its release once a day, so checking more often than
# this only adds GitHub round-trips to every page load.
UPSTREAM_CHECK_TTL_SECONDS = 1800

st.set_page_config(
    page_title="VulnIntel — Vulnerability Intelligence Dashboard",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Design tokens + custom CSS
# ---------------------------------------------------------------------------
COLORS = {
    "bg": "#0B0F14", "surface": "#141B24", "border": "#232D38",
    "text": "#E6EDF3", "muted": "#7D8B99", "signal": "#2DD4BF",
}
SEVERITY_COLORS = {
    "CRITICAL": "#E11D48", "HIGH": "#F97316", "MEDIUM": "#EAB308",
    "LOW": "#10B981", "NONE": "#3B82F6", "UNSCORED": "#4B5563",
}
ARCHETYPE_COLORS = {
    "Memory-safety-heavy": "#3B82F6",
    "Web-injection-heavy": "#8B5CF6",
    "Diffuse (no dominant category)": "#6B7280",
}
# A qualitative sequence tuned to the dark theme -- Plotly's default palette
# (muted blue/red/green) reads as an unstyled default against this background.
LINE_COLORS = ["#2DD4BF", "#F97316", "#8B5CF6", "#3B82F6", "#EAB308", "#E11D48", "#10B981"]

CUSTOM_CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"] {{
    font-family: 'IBM Plex Sans', sans-serif;
}}

.eyebrow {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.75rem;
    letter-spacing: 0.15em;
    color: {COLORS['signal']};
    text-transform: uppercase;
    margin-bottom: 0.25rem;
}}

.hero-title {{
    font-size: 2.4rem;
    font-weight: 700;
    color: {COLORS['text']};
    margin: 0;
    line-height: 1.15;
}}

.data-readout {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.85rem;
    color: {COLORS['muted']};
    margin-top: 0.5rem;
    letter-spacing: 0.02em;
}}

.data-readout .sep {{ color: {COLORS['border']}; margin: 0 0.5rem; }}

.stat-card {{
    background: {COLORS['surface']};
    border: 1px solid {COLORS['border']};
    border-top: 2px solid {COLORS['signal']};
    border-radius: 4px;
    padding: 1rem 1.2rem;
}}

.stat-value {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 1.7rem;
    font-weight: 600;
    color: {COLORS['text']};
}}

.stat-label {{
    font-size: 0.78rem;
    color: {COLORS['muted']};
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-top: 0.2rem;
}}

.section-note {{
    font-size: 0.85rem;
    color: {COLORS['muted']};
    border-left: 2px solid {COLORS['border']};
    padding-left: 0.8rem;
    margin: 0.5rem 0 1.2rem 0;
}}

hr {{ border-color: {COLORS['border']}; }}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
@st.cache_data(ttl=REFRESH_TTL_SECONDS)
def load_data():
    return {
        "vendor_year": pd.read_csv(DATA_DIR / "vendor_year_trend.csv"),
        "cwe_year": pd.read_csv(DATA_DIR / "cwe_year_trend.csv"),
        "severity_year": pd.read_csv(DATA_DIR / "severity_year_trend.csv"),
        "vendor_map": pd.read_csv(DATA_DIR / "vendor_cluster_map.csv"),
        "nodes": pd.read_csv(DATA_DIR / "cooccurrence_nodes.csv"),
        "edges": pd.read_csv(DATA_DIR / "cooccurrence_edges.csv"),
        "centrality_ts": pd.read_csv(DATA_DIR / "centrality_timeseries.csv"),
        "forecast": pd.read_csv(DATA_DIR / "forecast_results.csv"),
        "coverage": pd.read_csv(DATA_DIR / "data_coverage.csv"),
    }


data = load_data()

# ---------------------------------------------------------------------------
# Live data controls (sidebar)
# ---------------------------------------------------------------------------
def _tail(text, max_lines=18):
    """Last few whole lines of a step's output.

    The pipeline stores each step's output clipped to the final 2000 characters,
    which usually severs the first surviving line mid-row; dropping it keeps the
    log from opening on a fragment."""
    lines = text.splitlines()
    dropped = len(lines) > max_lines
    lines = lines[-max_lines:]
    if dropped:
        lines = lines[1:]
    return ("  ...\n" if dropped else "") + "\n".join(lines)


@st.cache_data(ttl=UPSTREAM_CHECK_TTL_SECONDS, show_spinner=False)
def _upstream_release():
    """Latest release the feed repo has published. Cached so that opening the
    page repeatedly does not hammer GitHub; None means the check failed."""
    return fetch_feeds.latest_release()


def _feed_freshness():
    """Compare what this machine has ingested against what upstream offers.

    Returns (state, detail) where state is one of: 'behind', 'current',
    'unknown', 'never'. Anything uncertain reports 'unknown' rather than
    claiming the data is current."""
    local = fetch_feeds.local_release()
    upstream = _upstream_release()

    if upstream is None:
        return "unknown", "Could not reach the feed repository."
    if local is None or not local.get("tag"):
        return "never", f"Upstream is publishing {upstream['tag']}."
    if local["tag"] == upstream["tag"]:
        return "current", f"Matches upstream release {upstream['tag']}."
    return "behind", (f"Upstream published {upstream['tag']}; "
                      f"this database was built from {local['tag']}.")


def _load_status():
    if STATUS_PATH.exists():
        try:
            return json.loads(STATUS_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            return None
    return None


def _time_ago(iso_ts):
    then = datetime.fromisoformat(iso_ts)
    delta = datetime.now(timezone.utc) - then
    mins = int(delta.total_seconds() // 60)
    if mins < 1:
        return "just now"
    if mins < 60:
        return f"{mins} min ago"
    return f"{mins // 60}h {mins % 60}m ago"


with st.sidebar:
    st.markdown("### Live data")
    st.caption(
        "Pulls the newest CVE feed from the fkie-cad release, reloads it, and "
        "rebuilds the SQL trend views \u2014 seconds, not minutes."
    )
    st.caption(
        ":material/check: Updates **Trends** and **Data coverage**  \n"
        ":material/remove: Leaves **Vendor profiles**, **Weakness network** and "
        "**Centrality** unchanged \u2014 those are rebuilt separately, below."
    )

    feed_state, feed_detail = _feed_freshness()
    if feed_state == "behind":
        st.warning("New data available upstream", icon=":material/cloud_download:")
        st.caption(feed_detail)
    elif feed_state == "current":
        st.success("Up to date with upstream", icon=":material/cloud_done:")
        st.caption(feed_detail)
    elif feed_state == "never":
        st.info("Upstream release not yet pulled here", icon=":material/cloud:")
        st.caption(feed_detail)
    else:
        st.caption(f":material/cloud_off: {feed_detail}")

    if st.button("Refresh now", width='stretch', icon=":material/refresh:"):
        with st.status("Refreshing\u2026", expanded=True) as status_box:
            def on_step(key, label, step):
                st.write(f"{':material/check:' if step['ok'] else ':material/close:'} {label}")
                output = "\n".join(
                    part.strip() for part in (step.get("stdout", ""), step.get("stderr", ""))
                    if part and part.strip()
                )
                st.code(output[-1500:] if output else "(no output)", language=None)

            result = refresh(verbose=False, on_step=on_step)
            ok = result["overall_ok"]
            status_box.update(
                label=(f"Refreshed in {result['duration_seconds']:.0f}s" if ok
                       else "Refresh completed with issues"),
                state="complete" if ok else "error",
            )
        st.session_state["_last_refresh_result"] = result
        st.cache_data.clear()
        st.rerun()

    # Bug caught via interactive testing (not by AppTest, which only checks
    # for exceptions): showing st.success()/st.warning() immediately before
    # st.rerun() never actually renders it -- the rerun restarts the script
    # before Streamlit displays the message. Fixed by stashing the result in
    # session_state and showing it on the NEXT run instead, popping it so it
    # only appears once.
    just_refreshed = False
    if "_last_refresh_result" in st.session_state:
        result = st.session_state.pop("_last_refresh_result")
        just_refreshed = True
        if result["overall_ok"]:
            st.success(f"Refreshed in {result['duration_seconds']:.0f}s")
        else:
            st.warning("Refresh completed with issues \u2014 see the log below")

    @st.fragment(run_every="30s")
    def status_readout():
        status = _load_status()
        if status is None:
            st.caption("No refresh has run yet in this environment.")
            return
        ago = _time_ago(status["finished"])
        if status["overall_ok"]:
            st.markdown(f"**Trend data:** updated {ago}")
        else:
            st.markdown(f"**Trend data:** issue during refresh {ago}")
        ingest_icon = "\u2713" if status["ingest_ok"] else "\u26a0"
        views_icon = "\u2713" if status["rebuild_views_ok"] else "\u2717"
        export_icon = "\u2713" if status["export_ok"] else "\u2717"
        st.caption(f"{ingest_icon} Feed sync ({status['ingest_mode']}) \u00b7 "
                    f"{views_icon} Views \u00b7 "
                    f"{export_icon} Export")
        if not status["ingest_ok"]:
            st.caption(
                "Feed sync is non-fatal \u2014 trend views still rebuilt from the "
                "existing database. Usually no network access to github.com, or "
                "the release asset download timed out."
            )

    status_readout()

    # The live st.status above is destroyed by the rerun that reloads the data,
    # so the run's output is replayed from the status file instead of being
    # lost the moment it finishes.
    last = _load_status()
    if last:
        with st.expander("Refresh log", expanded=just_refreshed,
                          icon=":material/terminal:"):
            step_labels = [
                ("ingest", f"Fetch + load '{last.get('ingest_mode', '?')}' feed"),
                ("rebuild_views", "Rebuild trend views"),
                ("export", "Re-export trend CSVs"),
            ]
            lines = [f"$ refresh_pipeline.py    # {last['finished'][:19]}Z"]
            for key, label in step_labels:
                step = last.get("steps", {}).get(key)
                if not step:
                    continue
                lines.append(f"\n[{'ok' if step['ok'] else 'FAILED'}] {label}")
                body = "\n".join(
                    part.strip() for part in (step.get("stdout", ""), step.get("stderr", ""))
                    if part and part.strip()
                )
                lines.append(_tail(body) if body else "  (no output)")
            lines.append(f"\nfinished in {last['duration_seconds']:.1f}s")
            st.code("\n".join(lines), language=None)

    st.divider()
    st.markdown("### Rebuild analysis")
    st.caption(
        "The deeper views are computed in batches rather than on every data "
        "pull. Rebuild one when you want it to reflect the latest records."
    )

    @st.fragment(run_every="4s")
    def rebuild_controls():
        any_running = any(rebuild.is_running(name) for name in rebuild.STAGES)
        for name, spec in rebuild.STAGES.items():
            state = rebuild.read_state(name)
            status = state["status"] if state else None
            running = status == "running"

            icon = {
                "complete": ":material/check_circle:",
                "failed": ":material/error:",
                "interrupted": ":material/help:",
                "cancelled": ":material/cancel:",
                "running": ":material/progress_activity:",
            }.get(status, ":material/circle:")

            with st.container(border=True):
                st.markdown(f"{icon} **{spec['title']}**")
                st.caption(f"{spec['blurb']} {spec['runtime']}.")

                if running:
                    st.caption(f"Running since {_time_ago(state['started'])}.")
                    if st.button("Stop", key=f"stop_{name}", width='stretch',
                                  icon=":material/stop:"):
                        rebuild.cancel(name)
                        st.rerun(scope="fragment")
                else:
                    if status == "complete":
                        st.caption(f"Last rebuilt {_time_ago(state['finished'])} "
                                   f"in {state.get('duration_seconds', 0):.0f}s.")
                    elif status == "failed":
                        st.caption(f"Failed at `{state.get('failed_step', '?')}`.")
                    elif status == "interrupted":
                        st.caption("Stopped before finishing.")
                    elif status is None:
                        st.caption("Not rebuilt in this environment yet.")

                    # One at a time: these stages write to the same database and
                    # would otherwise collide on SQLite's single-writer lock.
                    if st.button("Rebuild", key=f"run_{name}", width='stretch',
                                  disabled=any_running, icon=":material/play_arrow:"):
                        rebuild.start(name)
                        st.rerun(scope="fragment")

                log = rebuild.tail_log(name)
                if log and status in {"running", "failed", "interrupted"}:
                    with st.expander("Output", expanded=(status == "failed")):
                        st.code(_tail(log, max_lines=14), language=None)

        if any_running:
            st.caption("Another rebuild is running; the rest are paused until it finishes.")

    rebuild_controls()

st.markdown('<div class="eyebrow">VULNINTEL // CWE STRUCTURAL ANALYSIS</div>', unsafe_allow_html=True)
st.markdown('<h1 class="hero-title">Vulnerability Intelligence Dashboard</h1>', unsafe_allow_html=True)

total_cves = int(data["vendor_year"]["cve_count"].sum())
n_vendors = data["vendor_map"]["vendor"].nunique()
n_cwe = data["nodes"]["cwe_id"].nunique()
yr_min, yr_max = int(data["vendor_year"]["year"].min()), int(data["vendor_year"]["year"].max())

st.markdown(
    f'<div class="data-readout">{yr_min}\u2013{yr_max}'
    f'<span class="sep">·</span>{total_cves:,} VENDOR-CVE RECORDS'
    f'<span class="sep">·</span>{n_vendors} VENDORS TRACKED'
    f'<span class="sep">·</span>{n_cwe} CWE CATEGORIES</div>',
    unsafe_allow_html=True,
)
st.write("")

# ---------------------------------------------------------------------------
# Stat cards
# ---------------------------------------------------------------------------
top_vendor = data["vendor_year"][data["vendor_year"]["year"] == yr_max].nlargest(1, "cve_count")
fastest_cwe = data["cwe_year"][(data["cwe_year"]["year"] == yr_max) &
                                 (data["cwe_year"]["yoy_growth_pct"].notna())].nlargest(1, "yoy_growth_pct")

COMPLETE_CPE_COVERAGE_PCT = 85.0  # below this, vendor counts are visibly short

cov = data["coverage"].sort_values("year")
cov_recent = cov[cov["year"] >= yr_max - 9]
latest_cov = cov[cov["year"] == yr_max].iloc[0]

# Walk back from the newest year while coverage stays low, so the flagged
# span is the current backlog rather than every dip in NVD's history.
undercounted_from = None
for _, row in cov.sort_values("year", ascending=False).iterrows():
    if row["cpe_coverage_pct"] >= COMPLETE_CPE_COVERAGE_PCT:
        break
    undercounted_from = int(row["year"])
prev_total = cov[cov["year"] == yr_max - 1]["total_cves"].iloc[0]
cve_growth = 100.0 * (latest_cov["total_cves"] - prev_total) / prev_total

with st.container(horizontal=True):
    st.metric(
        f"CVEs published in {yr_max}", f"{int(latest_cov['total_cves']):,}",
        f"{cve_growth:+.0f}% vs {yr_max - 1}", border=True,
        chart_data=cov_recent["total_cves"].tolist(), chart_type="line",
    )
    st.metric(
        f"Top vendor by CVEs, {yr_max}", top_vendor.iloc[0]["vendor"].title(),
        f"{int(top_vendor.iloc[0]['cve_count']):,} CVEs", border=True, delta_color="off",
    )
    st.metric(
        f"Fastest-growing CWE, {yr_max}", fastest_cwe.iloc[0]["cwe_id"],
        f"{fastest_cwe.iloc[0]['yoy_growth_pct']:+.0f}% YoY", border=True,
    )
    st.metric(
        f"Vendor attribution, {yr_max}", f"{latest_cov['cpe_coverage_pct']:.0f}%",
        f"{latest_cov['cpe_coverage_pct'] - cov[cov['year'] == yr_max - 1]['cpe_coverage_pct'].iloc[0]:+.0f} pts",
        border=True, help="Share of CVEs with CPE vendor/product data. NVD adds these "
                          "after publication, so recent years undercount vendor activity.",
        chart_data=cov_recent["cpe_coverage_pct"].tolist(), chart_type="line",
    )

st.write("")

# ---------------------------------------------------------------------------
# Shared plotly dark theme
# ---------------------------------------------------------------------------
PLOTLY_LAYOUT = dict(
    paper_bgcolor=COLORS["bg"],
    plot_bgcolor=COLORS["bg"],
    font=dict(family="IBM Plex Sans, sans-serif", color=COLORS["text"]),
    xaxis=dict(gridcolor=COLORS["border"], zerolinecolor=COLORS["border"]),
    yaxis=dict(gridcolor=COLORS["border"], zerolinecolor=COLORS["border"]),
    legend=dict(bgcolor="rgba(0,0,0,0)"),
    margin=dict(l=10, r=10, t=40, b=10),
)

(tab_trends, tab_archetypes, tab_network, tab_centrality, tab_coverage,
 tab_assistant) = st.tabs([
    "Trends", "Vendor profiles", "Weakness network", "Centrality over time",
    "Data coverage", "Ask the data",
])

# ---------------------------------------------------------------------------
# Tab 1 -- Trends
# ---------------------------------------------------------------------------
with tab_trends:
    st.markdown(
        f'<div class="section-note">How disclosures break down by vendor and '
        f'weakness type, {yr_min}\u2013{yr_max}. Records are counted by the year '
        f'they were published. Average severity is smoothed over three years, so '
        f'one unusual year does not swing the line.</div>',
        unsafe_allow_html=True,
    )

    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown("**CVE volume by vendor**")
        top_vendors_overall = (
            data["vendor_year"].groupby("vendor")["cve_count"].sum()
            .nlargest(12).index.tolist()
        )
        selected_vendors = st.multiselect(
            "Vendors", options=sorted(data["vendor_year"]["vendor"].unique()),
            default=top_vendors_overall[:5],
        )
        if selected_vendors:
            vdf = data["vendor_year"][data["vendor_year"]["vendor"].isin(selected_vendors)]
            fig = px.line(
                vdf, x="year", y="cve_count", color="vendor", markers=True,
                labels={"cve_count": "CVEs", "year": "Year"},
                color_discrete_sequence=LINE_COLORS,
            )
            if undercounted_from is not None:
                # Vendor counts depend on CPE data NVD attaches late, so the
                # tail of every vendor line bends down for reporting reasons
                # rather than real ones. Mark it on the chart, not just in prose.
                fig.add_vrect(
                    x0=undercounted_from - 0.5, x1=yr_max + 0.5,
                    fillcolor=COLORS["muted"], opacity=0.12, line_width=0,
                    annotation_text="incomplete vendor data",
                    annotation_position="top left",
                    annotation_font=dict(size=10, color=COLORS["muted"]),
                )
            fig.update_layout(**PLOTLY_LAYOUT, height=380)
            st.plotly_chart(fig, width='stretch')
        else:
            st.info("Select at least one vendor above.")

    with col_right:
        st.markdown("**Severity mix by year**")
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNSCORED"]
        sdf = data["severity_year"].copy()
        sdf["severity"] = pd.Categorical(sdf["severity"], categories=sev_order, ordered=True)
        sdf = sdf.sort_values(["year", "severity"])
        sdf["year"] = sdf["year"].astype(str)  # bug fix: numeric year only showed
        # sparse auto-ticks (2020, 2022); categorical axis shows every year explicitly.
        fig = px.bar(
            sdf, x="year", y="pct_of_year", color="severity",
            color_discrete_map=SEVERITY_COLORS,
            labels={"pct_of_year": "% of year", "year": "Year"},
        )
        fig.update_layout(**PLOTLY_LAYOUT, height=380, barmode="stack")
        fig.update_xaxes(type="category")
        st.plotly_chart(fig, width='stretch')

    st.markdown("**CWE category trend**")
    top_cwes_overall = (
        data["cwe_year"].groupby("cwe_id")["cve_count"].sum()
        .nlargest(15).index.tolist()
    )
    selected_cwes = st.multiselect(
        "CWE categories", options=sorted(data["cwe_year"]["cwe_id"].unique()),
        default=[c for c in ["CWE-79", "CWE-352", "CWE-787"] if c in top_cwes_overall],
    )
    if selected_cwes:
        cdf = data["cwe_year"][data["cwe_year"]["cwe_id"].isin(selected_cwes)]
        fig = px.line(
            cdf, x="year", y="cve_count", color="cwe_id", markers=True,
            labels={"cve_count": "CVEs", "year": "Year", "cwe_id": "CWE"},
            color_discrete_sequence=LINE_COLORS,
        )
        fig.update_layout(**PLOTLY_LAYOUT, height=340)
        st.plotly_chart(fig, width='stretch')
    else:
        st.info("Select at least one CWE category above.")

# ---------------------------------------------------------------------------
# Tab 2 -- Vendor Archetypes
# ---------------------------------------------------------------------------
with tab_archetypes:
    st.markdown(
        '<div class="section-note">Every dot is a vendor, placed so that vendors '
        'with similar weakness profiles sit near each other. Colour marks which '
        'of three groups it falls into — mostly memory-safety bugs, mostly '
        'web-injection bugs, or no dominant pattern. Dot size is how many '
        'vulnerabilities the vendor has. Pick a vendor below to see the profile '
        'behind its position.</div>',
        unsafe_allow_html=True,
    )

    archetypes_present = data["vendor_map"]["archetype_label"].unique().tolist()
    selected_archetypes = st.multiselect(
        "Archetypes", options=archetypes_present, default=archetypes_present,
    )
    vmap = data["vendor_map"][data["vendor_map"]["archetype_label"].isin(selected_archetypes)]

    fig = px.scatter(
        vmap, x="pca_x", y="pca_y", color="archetype_label", size="total_cves",
        color_discrete_map=ARCHETYPE_COLORS, hover_name="vendor",
        size_max=40, opacity=0.75,
        labels={"pca_x": "PC1", "pca_y": "PC2", "archetype_label": "Archetype"},
        hover_data={"pca_x": False, "pca_y": False, "total_cves": True},
    )
    fig.update_layout(**PLOTLY_LAYOUT, height=520)
    st.plotly_chart(fig, width='stretch')

    st.markdown("**Inspect a vendor's category profile**")
    inspect_vendor = st.selectbox("Vendor", options=sorted(data["vendor_map"]["vendor"].unique()))
    vrow = data["vendor_map"][data["vendor_map"]["vendor"] == inspect_vendor].iloc[0]
    share_cols = [c for c in data["vendor_map"].columns if c.startswith("share_")]
    profile = pd.DataFrame({
        "category": [c.replace("share_", "") for c in share_cols],
        "share": [vrow[c] for c in share_cols],
    }).sort_values("share", ascending=True).tail(10)
    fig2 = px.bar(profile, x="share", y="category", orientation="h",
                  labels={"share": "Share of vendor's CVEs", "category": ""})
    fig2.update_traces(marker_color=ARCHETYPE_COLORS.get(vrow["archetype_label"], COLORS["signal"]))
    fig2.update_layout(**PLOTLY_LAYOUT, height=340)
    st.plotly_chart(fig2, width='stretch')

# ---------------------------------------------------------------------------
# Tab 3 -- CWE Co-occurrence Network (signature view)
# ---------------------------------------------------------------------------
with tab_network:
    nodes_all = data["nodes"]
    n_isolated = int(nodes_all["is_isolated"].sum())
    nodes_positioned = nodes_all[nodes_all["is_isolated"] == False].copy()  # noqa: E712

    st.markdown(
        '<div class="section-note">Two weakness types are linked when both show up '
        'in the same product. Types that travel together are pulled close, so '
        'clusters here are families of problems that tend to appear side by side. '
        'Colour is how central a type is \u2014 warmer means it connects to more of '
        'the network, which makes it a better place to spend hardening effort than '
        'raw frequency alone would suggest. Drag the slider to hide weaker links. '
        f'{n_isolated} types never co-occur significantly and are left out rather '
        'than scattered at the edges.</div>',
        unsafe_allow_html=True,
    )

    min_weight = st.slider(
        "Minimum co-occurrence weight shown", min_value=1,
        max_value=int(data["edges"]["weight"].max()), value=1,
    )
    edges_f = data["edges"][data["edges"]["weight"] >= min_weight]

    edge_x, edge_y = [], []
    for _, e in edges_f.iterrows():
        edge_x += [e["source_x"], e["target_x"], None]
        edge_y += [e["source_y"], e["target_y"], None]

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y, mode="lines",
        line=dict(width=0.6, color="rgba(45,212,191,0.18)"),
        hoverinfo="none", showlegend=False,
    )

    nodes = nodes_positioned
    node_trace = go.Scatter(
        x=nodes["x"], y=nodes["y"], mode="markers",
        marker=dict(
            size=6 + 14 * (nodes["raw_frequency"] / nodes["raw_frequency"].max()) ** 0.4,
            color=nodes["centrality"],
            colorscale=[[0, "#1E3A5F"], [0.5, "#2DD4BF"], [1, "#F97316"]],
            showscale=True,
            colorbar=dict(title="Centrality", tickfont=dict(color=COLORS["muted"])),
            line=dict(width=0.5, color=COLORS["bg"]),
        ),
        text=[f"{row.cwe_id}<br>Frequency: {row.raw_frequency}<br>Centrality: {row.centrality:.4f}"
              for row in nodes.itertuples()],
        hoverinfo="text", showlegend=False,
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        **{**PLOTLY_LAYOUT, "xaxis": dict(visible=False), "yaxis": dict(visible=False)},
        height=640,
    )
    st.plotly_chart(fig, width='stretch')

# ---------------------------------------------------------------------------
# Tab 4 -- Centrality over time
# ---------------------------------------------------------------------------
with tab_centrality:
    _n_cwe_universe = data["centrality_ts"]["cwe_id"].nunique()
    st.markdown(
        f'<div class="section-note">How central each weakness type has been, year '
        f'by year. Centrality measures how widely a weakness co-occurs with others '
        f'rather than how often it appears, so a type can climb here while its raw '
        f'count stays flat. All years are scored against the same '
        f'{_n_cwe_universe} weakness types, so the lines are directly comparable.</div>',
        unsafe_allow_html=True,
    )

    ts = data["centrality_ts"]
    ts_latest = int(ts["year"].max())
    ts_prev = int(ts[ts["year"] < ts_latest]["year"].max())
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown("**Centrality trajectory**")
        default_cwes = [c for c in ["CWE-129", "CWE-79", "CWE-352", "CWE-787"]
                         if c in ts["cwe_id"].unique()]
        selected = st.multiselect(
            "CWE categories", options=sorted(ts["cwe_id"].unique()), default=default_cwes,
            key="centrality_cwe_select",
        )
        if selected:
            tsf = ts[ts["cwe_id"].isin(selected)]
            fig = px.line(
                tsf, x="year", y="centrality", color="cwe_id", markers=True,
                labels={"centrality": "Eigenvector centrality", "year": "Year", "cwe_id": "CWE"},
                color_discrete_sequence=LINE_COLORS,
            )
            fig.update_layout(**PLOTLY_LAYOUT, height=380)
            fig.update_xaxes(type="category")
            st.plotly_chart(fig, width='stretch')
        else:
            st.info("Select at least one CWE category above.")

    with col_right:
        st.markdown(f"**Biggest movers, {ts_prev} \u2192 {ts_latest}**")
        piv = ts[ts["year"].isin([ts_prev, ts_latest])].pivot(index="cwe_id", columns="year", values="centrality")
        piv = piv.dropna()
        piv["change"] = piv[ts_latest] - piv[ts_prev]
        movers = pd.concat([piv.nlargest(5, "change"), piv.nsmallest(5, "change")]).reset_index()
        movers = movers.sort_values("change")
        fig = px.bar(
            movers, x="change", y="cwe_id", orientation="h",
            color=movers["change"] > 0,
            color_discrete_map={True: SEVERITY_COLORS["LOW"], False: SEVERITY_COLORS["CRITICAL"]},
            labels={"change": "Centrality change", "cwe_id": ""},
        )
        fig.update_layout(**PLOTLY_LAYOUT, height=380, showlegend=False)
        st.plotly_chart(fig, width='stretch')

    st.markdown("---")
    st.markdown("**Can this year's network position predict next year's?**")

    fc = data["forecast"]
    mae_model = (fc["actual_next_centrality"] - fc["predicted_next_centrality"]).abs().mean()
    mae_naive = (fc["actual_next_centrality"] - fc["naive_predicted_next_centrality"]).abs().mean()
    true_dir = fc["actual_next_centrality"] > fc["current_centrality"]
    pred_dir = fc["predicted_next_centrality"] > fc["current_centrality"]
    dir_acc = (true_dir == pred_dir).mean()

    m1, m2, m3 = st.columns(3)
    with m1:
        st.markdown(f'<div class="stat-card"><div class="stat-value">{mae_model:.4f}</div>'
                     f'<div class="stat-label">Model MAE (test)</div></div>', unsafe_allow_html=True)
    with m2:
        st.markdown(f'<div class="stat-card"><div class="stat-value">{mae_naive:.4f}</div>'
                     f'<div class="stat-label">Naive baseline MAE</div></div>', unsafe_allow_html=True)
    with m3:
        st.markdown(f'<div class="stat-card"><div class="stat-value">{dir_acc:.1%}</div>'
                     f'<div class="stat-label">Direction accuracy</div></div>', unsafe_allow_html=True)

    _beats_naive = mae_model < mae_naive
    _beats_coin = dir_acc > 0.5
    _verdict = (
        f'<b>The model {"beats" if _beats_naive else "does not beat"} the naive '
        f'"predict no change" baseline, and its direction call is '
        f'{"better" if _beats_coin else "no better"} than a coin flip.</b> '
    )
    st.markdown(
        f'<div class="section-note">{_verdict}'
        f'Trained on year-over-year changes through {int(fc["feature_year"].max())}. '
        f'Treat it as an illustration of the approach, not something to plan '
        f'against: it leans almost entirely on the previous year\'s value, which '
        f'makes it closer to "assume no change" than a genuine forecast.</div>',
        unsafe_allow_html=True,
    )

    fig = go.Figure()
    lims = [fc[["current_centrality", "actual_next_centrality", "predicted_next_centrality"]].min().min(),
            fc[["current_centrality", "actual_next_centrality", "predicted_next_centrality"]].max().max()]
    fig.add_trace(go.Scatter(x=lims, y=lims, mode="lines", line=dict(color=COLORS["muted"], dash="dash"),
                              name="Perfect prediction", hoverinfo="skip"))
    fig.add_trace(go.Scatter(
        x=fc["actual_next_centrality"], y=fc["predicted_next_centrality"], mode="markers",
        marker=dict(color=COLORS["signal"], size=7, opacity=0.6),
        name="Model prediction", text=fc["cwe_id"], hovertemplate="%{text}<br>actual=%{x:.4f}<br>pred=%{y:.4f}",
    ))
    _target_year = int(fc["feature_year"].max()) + 1
    fig.update_layout(**PLOTLY_LAYOUT, height=420,
                       xaxis_title=f"Actual {_target_year} centrality",
                       yaxis_title=f"Predicted {_target_year} centrality")
    st.plotly_chart(fig, width='stretch')

# ---------------------------------------------------------------------------
# Tab 5 -- Data coverage
# ---------------------------------------------------------------------------
with tab_coverage:
    st.markdown(
        '<div class="section-note">How complete each year\'s records are. NVD '
        'publishes a CVE first and enriches it later, so the newest years are '
        'still filling in — which looks like a decline in activity if the '
        'gap is not accounted for.</div>',
        unsafe_allow_html=True,
    )

    if undercounted_from is not None:
        st.warning(
            f"**Vendor and product figures from {undercounted_from} onward are "
            f"incomplete.** Only {latest_cov['cpe_coverage_pct']:.0f}% of {yr_max} CVEs "
            f"carry the CPE vendor/product records those views are built from, against "
            f"{cov[cov['year'] == undercounted_from - 1]['cpe_coverage_pct'].iloc[0]:.0f}% "
            f"in {undercounted_from - 1}. Vendor counts for these years are a floor, not a "
            f"measurement. CWE-based views are unaffected "
            f"({latest_cov['cwe_coverage_pct']:.0f}% coverage in {yr_max}).",
            icon=":material/warning:",
        )

    plot_cov = cov[cov["year"] >= 2005]
    left, right = st.columns(2)

    with left:
        with st.container(border=True):
            st.markdown("**Enrichment coverage by year**")
            melted = plot_cov.melt(
                id_vars="year", value_vars=["cpe_coverage_pct", "cwe_coverage_pct"],
                var_name="kind", value_name="pct",
            )
            melted["kind"] = melted["kind"].map({
                "cpe_coverage_pct": "CPE (vendor/product)",
                "cwe_coverage_pct": "CWE (weakness type)",
            })
            fig = px.line(
                melted, x="year", y="pct", color="kind", markers=True,
                labels={"pct": "% of CVEs with data", "year": "Year", "kind": ""},
                color_discrete_sequence=[SEVERITY_COLORS["HIGH"], COLORS["signal"]],
            )
            fig.add_hline(
                y=COMPLETE_CPE_COVERAGE_PCT, line_dash="dot",
                line_color=COLORS["muted"],
                annotation_text="completeness threshold",
                annotation_font=dict(size=10, color=COLORS["muted"]),
            )
            fig.update_layout(**PLOTLY_LAYOUT, height=380)
            fig.update_yaxes(range=[0, 100])
            st.plotly_chart(fig, width='stretch')

    with right:
        with st.container(border=True):
            st.markdown("**Published vs. vendor-attributed**")
            fig = go.Figure()
            fig.add_trace(go.Bar(
                x=plot_cov["year"], y=plot_cov["total_cves"], name="Published",
                marker_color=COLORS["border"],
            ))
            fig.add_trace(go.Bar(
                x=plot_cov["year"], y=plot_cov["cves_with_cpe"], name="With vendor data",
                marker_color=COLORS["signal"],
            ))
            fig.update_layout(**PLOTLY_LAYOUT, height=380, barmode="overlay")
            st.plotly_chart(fig, width='stretch')
            st.caption(
                "The gap between the bars is what vendor-based views cannot see."
            )

    with st.container(border=True):
        st.markdown("**Coverage by year**")
        table = cov[cov["year"] >= 2015][
            ["year", "total_cves", "cves_with_cpe", "cpe_coverage_pct",
             "cves_with_cwe", "cwe_coverage_pct"]
        ].sort_values("year", ascending=False)
        st.dataframe(
            table, hide_index=True, width='stretch',
            column_config={
                "year": st.column_config.NumberColumn("Year", format="%d"),
                "total_cves": st.column_config.NumberColumn("Published", format="%,d"),
                "cves_with_cpe": st.column_config.NumberColumn("With CPE", format="%,d"),
                "cpe_coverage_pct": st.column_config.ProgressColumn(
                    "CPE coverage", format="%.1f%%", min_value=0, max_value=100),
                "cves_with_cwe": st.column_config.NumberColumn("With CWE", format="%,d"),
                "cwe_coverage_pct": st.column_config.ProgressColumn(
                    "CWE coverage", format="%.1f%%", min_value=0, max_value=100),
            },
        )

# ---------------------------------------------------------------------------
# Tab 6 -- Ask the data
# ---------------------------------------------------------------------------
with tab_assistant:
    st.markdown(
        '<div class="section-note">Ask questions about this data in plain English. '
        'The model runs locally, so nothing is sent anywhere. It answers from a '
        'briefing of figures computed from the database, and is told to say so '
        'rather than guess when a question falls outside it.</div>',
        unsafe_allow_html=True,
    )

    models = assistant.available_models()

    if not models:
        st.warning(
            "**No local model is reachable.** The assistant talks to Ollama on "
            "`localhost:11434`.",
            icon=":material/power_off:",
        )
        st.markdown("Start it, then reopen this tab:")
        st.code("ollama serve", language="bash")
        st.caption("If no models are installed yet, pull one first:")
        st.code("ollama pull mistral", language="bash")
    else:
        controls, _ = st.columns([2, 3])
        with controls:
            # Bigger models follow the "only use the briefing" instruction more
            # reliably, so prefer one when it is available.
            default_model = next((m for m in models if m.startswith("mistral")), models[0])
            model = st.selectbox(
                "Model", models, index=models.index(default_model),
                help="Served by your local Ollama install.",
            )

        briefing = assistant.build_briefing()

        with st.expander("What the assistant can see", icon=":material/description:"):
            st.caption(
                "This briefing is rebuilt from the database on every question. "
                "The model gets nothing else, which is why it cannot invent "
                "figures that contradict the dashboard."
            )
            st.code(briefing, language=None)

        if "chat" not in st.session_state:
            st.session_state.chat = []

        if st.session_state.chat and st.button("Clear conversation",
                                                icon=":material/delete_sweep:"):
            st.session_state.chat = []
            st.rerun()

        if not st.session_state.chat:
            st.caption("For example:")
            for example in [
                "Which weakness types are growing fastest, and are any of them worth worrying about?",
                "Summarise how severity has shifted in the most recent year.",
                "Which vendors look memory-safety heavy, and what does that mean?",
                "Why did vendor counts drop after 2023?",
            ]:
                st.markdown(f"- {example}")

        for turn in st.session_state.chat:
            with st.chat_message(turn["role"]):
                st.markdown(turn["content"])

        if question := st.chat_input("Ask about vendors, weaknesses, severity or coverage"):
            st.session_state.chat.append({"role": "user", "content": question})
            with st.chat_message("user"):
                st.markdown(question)
            with st.chat_message("assistant"):
                answer = st.write_stream(
                    assistant.stream_answer(
                        question, model, briefing,
                        history=st.session_state.chat[:-1][-6:],  # keep the prompt small
                    )
                )
            st.session_state.chat.append({"role": "assistant", "content": answer})