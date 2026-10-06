"""
Model 2 (stretch goal), Step B+C — assemble features and train the forecast
model (Module 3).

Reconciling a real inconsistency in the design doc before building anything:
Section 6.3 frames this model as predicting whether centrality will "rise or
fall" (classification), but Section 7's evaluation table asks for "mean
absolute error against actual next-year centrality" (a regression metric).
Resolved by training a regression model (satisfies the MAE requirement) and
deriving the rise/fall call from its prediction vs. the current year's value
(satisfies the classification framing) -- rather than silently picking one
half of the design doc and dropping the other.

Features (per design doc Section 6.3): current centrality, degree, frequency
growth, NLP-drift score -- all computed at year Y, predicting centrality at
year Y+1. Added to those: centrality momentum over the two previous
transitions, log frequency, and the change in degree. Momentum is what makes
the model work at all -- see the target note below.

NLP-drift score proxy: fraction of a CWE's CVEs in year Y that landed in a
cluster Phase 3's flag_drift.py flagged as coherent-but-taxonomically-
scattered. Phase 3 didn't produce a per-CWE scalar directly -- this is a
reasonable, documented derivation from its actual output (nlp_flagged_clusters).

Target: the CHANGE in centrality, added back onto the current value. The
first version predicted next year's level directly, and lost to "assume no
change" in every year of the backtest. A depth-limited tree predicting a
level can only output a handful of leaf values, so it cannot even reproduce
its own input, let alone improve on it. Predicting the change makes "no
change" the model's natural fallback rather than something it has to learn.

Model: GradientBoostingRegressor with absolute-error loss. Year-to-year
changes are heavy-tailed -- a few weakness types swing hard while most barely
move -- and squared-error loss chases those swings. Ablations in the
backtest: squared-error loss, or the original four features alone, both lose
to the baseline; it takes the robust loss AND the momentum features.

Evaluation: rolling-origin backtest over every year with at least
MIN_TRAIN_EXAMPLES of history before it (2006 onward). Each year is
predicted by a model trained only on the years before it, so one unusual
test year cannot carry the verdict -- the previous version's single 2025->2026 test came within 3%
of the baseline by luck, while losing every other year by 15-35%. Compared
against two baselines: "no change", and a mean-reversion rule (shrink every
centrality by one constant fitted on the training years) -- the model is only
worth showing if it beats the simple rule too, not just the trivial one.

Usage:
    python3 train_forecast.py
"""
import sqlite3
import csv
import collections
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import GradientBoostingRegressor

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"
DATA_DIR = Path(__file__).resolve().parent / "data"
MIN_FEATURE_YEAR_FREQ = 5  # exclude near-absent CWEs -- all-zero features aren't a real forecast signal
# Every year with enough history before it is scored -- not a chosen recent
# window, which can (and with 8 years did) land on the most flattering span.
MIN_TRAIN_EXAMPLES = 50
# Years scoring fewer weakness types than this are flagged as thin: before
# ~2017 only 13-50 types per year have the data to score, so one year's
# result rests on a handful of points. Set by sample size, not by results.
DATA_RICH_MIN_CWES = 100
FEATURE_NAMES = ["centrality", "degree", "freq_growth_pct", "nlp_drift_score",
                 "momentum_1y", "momentum_2y", "log_frequency", "degree_change"]


def load_centrality_timeseries():
    ts = collections.defaultdict(dict)  # ts[cwe_id][year] = {centrality, degree, raw_frequency}
    with open(DATA_DIR / "centrality_timeseries.csv") as f:
        for row in csv.DictReader(f):
            ts[row["cwe_id"]][int(row["year"])] = {
                "centrality": float(row["centrality"]),
                "degree": int(row["degree"]),
                "raw_frequency": int(row["raw_frequency"]),
            }
    return ts


def compute_nlp_drift_scores(conn):
    """fraction of each CWE's CVEs, per year, that landed in a flagged cluster"""
    rows = conn.execute("""
        SELECT n.cwe_id, CAST(SUBSTR(n.quarter,1,4) AS INTEGER) AS year,
               CASE WHEN f.cluster_id IS NOT NULL THEN 1 ELSE 0 END AS flagged
        FROM nlp_docs n
        LEFT JOIN nlp_clusters c ON n.cve_id = c.cve_id
        LEFT JOIN nlp_flagged_clusters f ON c.quarter = f.quarter AND c.cluster_id = f.cluster_id
        WHERE n.cwe_id IS NOT NULL AND n.is_generic = 0
    """).fetchall()
    totals = collections.Counter()
    flagged = collections.Counter()
    for cwe_id, year, is_flagged in rows:
        totals[(cwe_id, year)] += 1
        flagged[(cwe_id, year)] += is_flagged
    return {k: flagged[k] / v for k, v in totals.items()}


def build_examples(ts, drift_scores):
    """One example per (CWE, feature year): features at Y, centrality at Y+1.

    Momentum needs two prior years and the target needs the next one, so a
    feature year must sit inside the series with Y-2 and Y+1 present."""
    examples = []  # (cwe_id, feature_year, X, current_centrality, next_centrality)
    for cwe_id, years in ts.items():
        for y in sorted(years):
            if not all(k in years for k in (y - 2, y - 1, y + 1)):
                continue
            cur, prev, prev2, nxt = years[y], years[y - 1], years[y - 2], years[y + 1]
            if cur["raw_frequency"] < MIN_FEATURE_YEAR_FREQ:
                continue
            freq_growth_pct = (
                100.0 * (cur["raw_frequency"] - prev["raw_frequency"]) / prev["raw_frequency"]
                if prev["raw_frequency"] > 0 else 0.0
            )
            X = [
                cur["centrality"], cur["degree"], freq_growth_pct,
                drift_scores.get((cwe_id, y), 0.0),
                cur["centrality"] - prev["centrality"],
                prev["centrality"] - prev2["centrality"],
                np.log1p(cur["raw_frequency"]),
                cur["degree"] - prev["degree"],
            ]
            examples.append((cwe_id, y, X, cur["centrality"], nxt["centrality"]))
    return examples


def make_model():
    return GradientBoostingRegressor(
        loss="absolute_error", n_estimators=200, max_depth=3,
        learning_rate=0.03, subsample=0.8, random_state=42,
    )


def fit_predict(X_train, cur_train, next_train, X_test, cur_test):
    model = make_model().fit(X_train, next_train - cur_train)
    return model, cur_test + model.predict(X_test)


def fit_reversion(cur_train, next_train):
    """The constant c minimising |next - c * current| on the training years."""
    candidates = np.linspace(0.80, 1.05, 251)
    return min(candidates, key=lambda c: np.abs(next_train - c * cur_train).mean())


def main():
    conn = sqlite3.connect(DB_PATH)
    ts = load_centrality_timeseries()
    drift_scores = compute_nlp_drift_scores(conn)
    conn.close()

    examples = build_examples(ts, drift_scores)
    years = np.array([e[1] for e in examples])
    X = np.array([e[2] for e in examples])
    cur = np.array([e[3] for e in examples])
    nxt = np.array([e[4] for e in examples])

    feature_years = sorted(set(years.tolist()))
    print(f"Total examples (freq >= {MIN_FEATURE_YEAR_FREQ} in feature year): {len(examples)}, "
          f"feature years {feature_years[0]}-{feature_years[-1]}")

    # --- Rolling-origin backtest -------------------------------------------
    test_years = [y for y in feature_years if (years < y).sum() >= MIN_TRAIN_EXAMPLES]
    backtest = []
    print(f"\n=== Backtest: each year predicted by a model trained on earlier years only ===")
    print(f"{'predicting':>10}  {'n':>4}  {'model':>7}  {'no-chg':>7}  {'revert':>7}  {'dir':>5}  {'maj':>5}")
    for ty in test_years:
        tr, te = years < ty, years == ty
        _, pred = fit_predict(X[tr], cur[tr], nxt[tr], X[te], cur[te])
        c = fit_reversion(cur[tr], nxt[tr])
        rose = nxt[te] > cur[te]
        majority_rise = (nxt[tr] > cur[tr]).mean() > 0.5
        row = {
            "target_year": ty + 1,
            "n_train": int(tr.sum()),
            "n_cwes": int(te.sum()),
            "data_rich": bool(te.sum() >= DATA_RICH_MIN_CWES),
            "model_mae": float(np.abs(nxt[te] - pred).mean()),
            "naive_mae": float(np.abs(nxt[te] - cur[te]).mean()),
            "reversion_mae": float(np.abs(nxt[te] - c * cur[te]).mean()),
            "model_direction_acc": float((rose == (pred > cur[te])).mean()),
            "majority_direction_acc": float((rose == majority_rise).mean()),
        }
        backtest.append(row)
        print(f"{row['target_year']:>10}  {row['n_cwes']:>4}  {row['model_mae']:.5f}  "
              f"{row['naive_mae']:.5f}  {row['reversion_mae']:.5f}  "
              f"{row['model_direction_acc']:.3f}  {row['majority_direction_acc']:.3f}")

    bt = pd.DataFrame(backtest)
    for label, part in [("All years", bt), ("Data-rich years", bt[bt["data_rich"]])]:
        weights = part["n_cwes"]
        pooled = {k: float((part[k] * weights).sum() / weights.sum())
                  for k in ["model_mae", "naive_mae", "reversion_mae",
                            "model_direction_acc", "majority_direction_acc"]}
        wins = int((part["model_mae"] < part["naive_mae"]).sum())
        print(f"\n{label} ({int(part['target_year'].min())}-{int(part['target_year'].max())}): "
              f"MAE model {pooled['model_mae']:.5f}, no-change {pooled['naive_mae']:.5f} "
              f"({100 * (pooled['model_mae'] / pooled['naive_mae'] - 1):+.1f}%), mean-reversion "
              f"{pooled['reversion_mae']:.5f}")
        print(f"  Beats no-change in {wins}/{len(part)} years. Direction accuracy "
              f"{pooled['model_direction_acc']:.3f} vs {pooled['majority_direction_acc']:.3f} "
              f"for always calling the majority direction.")
    bt.to_csv(DATA_DIR / "forecast_backtest.csv", index=False)
    print(f"Wrote {DATA_DIR / 'forecast_backtest.csv'}")

    # --- Final model: latest year held out, for the dashboard scatter -------
    test_year = feature_years[-1]
    tr, te = years < test_year, years == test_year
    model, y_pred = fit_predict(X[tr], cur[tr], nxt[tr], X[te], cur[te])

    print(f"\n=== Feature importances (predicting the change) ===")
    for name, importance in sorted(zip(FEATURE_NAMES, model.feature_importances_),
                                   key=lambda x: -x[1]):
        print(f"  {name:<18} {importance:.3f}")

    print(f"\n[CAUTION] {test_year + 1} is the newest year and still filling in -- its "
          f"vendor data is incomplete, so its centrality is the least settled target in "
          f"the backtest. Judge the model on the backtest, not on this one year.")

    # Persist predictions for the dashboard -- a predicted-vs-actual scatter is a
    # more honest way to show how close the model gets than an MAE alone.
    test = [e for e in examples if e[1] == test_year]
    results_df = pd.DataFrame({
        "cwe_id": [e[0] for e in test],
        "feature_year": [e[1] for e in test],
        "current_centrality": cur[te],
        "actual_next_centrality": nxt[te],
        "predicted_next_centrality": y_pred,
        "naive_predicted_next_centrality": cur[te],  # persistence baseline
    })
    results_df.to_csv(DATA_DIR / "forecast_results.csv", index=False)
    print(f"Wrote {DATA_DIR / 'forecast_results.csv'} ({len(results_df)} rows)")


if __name__ == "__main__":
    main()
