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
year Y+1.

NLP-drift score proxy: fraction of a CWE's CVEs in year Y that landed in a
cluster Phase 3's flag_drift.py flagged as coherent-but-taxonomically-
scattered. Phase 3 didn't produce a per-CWE scalar directly -- this is a
reasonable, documented derivation from its actual output (nlp_flagged_clusters).

Split: time-based, consistent with the rest of the project. Train on the
2020->2021 and 2021->2022 transitions, test on 2022->2023. 2019 can't be a
feature year (no 2018 data for frequency growth).

Model: RandomForestRegressor, max_depth=3 (explicitly shallow per Section
6.3 -- "centrality time series are short and noisy, and overfitting is
easy" -- with a training set this small, an unconstrained forest would
memorize it).

Usage:
    python3 train_forecast.py
"""
import sqlite3
import csv
import collections
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"
DATA_DIR = Path(__file__).resolve().parent / "data"
MIN_FEATURE_YEAR_FREQ = 5  # exclude near-absent CWEs -- all-zero features aren't a real forecast signal


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


def main():
    conn = sqlite3.connect(DB_PATH)
    ts = load_centrality_timeseries()
    drift_scores = compute_nlp_drift_scores(conn)

    examples = []  # (cwe_id, feature_year, X, y_true_next_centrality)
    # A usable feature year needs its predecessor (for growth) and its successor
    # (the target), so the first and last year of the series drop out.
    all_years = sorted({y for years in ts.values() for y in years})
    feature_years = [y for y in all_years if y - 1 in all_years and y + 1 in all_years]
    test_year = feature_years[-1]
    train_years = feature_years[:-1]

    for cwe_id, years in ts.items():
        for feature_year in feature_years:
            if feature_year not in years or (feature_year + 1) not in years or (feature_year - 1) not in years:
                continue
            cur, prev, nxt = years[feature_year], years[feature_year - 1], years[feature_year + 1]
            if cur["raw_frequency"] < MIN_FEATURE_YEAR_FREQ:
                continue
            freq_growth_pct = (
                100.0 * (cur["raw_frequency"] - prev["raw_frequency"]) / prev["raw_frequency"]
                if prev["raw_frequency"] > 0 else 0.0
            )
            drift = drift_scores.get((cwe_id, feature_year), 0.0)
            X = [cur["centrality"], cur["degree"], freq_growth_pct, drift]
            y = nxt["centrality"]
            examples.append((cwe_id, feature_year, X, y, cur["centrality"]))

    print(f"Total examples (freq >= {MIN_FEATURE_YEAR_FREQ} in feature year): {len(examples)}")
    by_year = collections.Counter(e[1] for e in examples)
    for year in sorted(by_year):
        print(f"  feature_year={year} (predicting {year+1}): {by_year[year]} CWEs")

    train = [e for e in examples if e[1] in train_years]
    test = [e for e in examples if e[1] == test_year]
    print(f"\nTrain (feature years {train_years[0]}-{train_years[-1]}, "
          f"{len(train_years)} transitions): {len(train)}")
    print(f"Test (feature year {test_year}, predicting {test_year + 1}): {len(test)}")

    if len(test) < 5:
        print("\n[CAUTION] Test set has fewer than 5 examples -- any metric below is "
              "barely more informative than anecdote. Reporting anyway per the design "
              "doc's request, with this caveat attached.")

    X_train = np.array([e[2] for e in train])
    y_train = np.array([e[3] for e in train])
    X_test = np.array([e[2] for e in test])
    y_test = np.array([e[3] for e in test])
    current_test = np.array([e[4] for e in test])  # current-year centrality, for direction derivation

    model = RandomForestRegressor(n_estimators=100, max_depth=3, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    mae = mean_absolute_error(y_test, y_pred)
    print(f"\n=== Regression: MAE against actual next-year centrality ===")
    print(f"MAE: {mae:.4f}")

    # Baseline for context: MAE of just predicting "next year = same as this year"
    # (a naive persistence forecast) -- the model needs to beat THIS to be useful,
    # not just have a small-looking MAE in isolation.
    naive_mae = mean_absolute_error(y_test, current_test)
    print(f"Naive persistence baseline MAE (predict no change): {naive_mae:.4f}")
    print(f"Model {'beats' if mae < naive_mae else 'does NOT beat'} the naive baseline")

    # Derived classification: did centrality rise or fall, predicted vs actual
    true_direction = (y_test > current_test)
    pred_direction = (y_pred > current_test)
    direction_accuracy = (true_direction == pred_direction).mean()
    print(f"\n=== Derived classification: rise/fall direction ===")
    print(f"Direction accuracy: {direction_accuracy:.3f} ({true_direction.sum()}/{len(true_direction)} "
          f"actually rose, {pred_direction.sum()}/{len(pred_direction)} predicted to rise)")

    print(f"\n=== Feature importances (shallow forest, max_depth=3) ===")
    for name, importance in zip(["centrality", "degree", "freq_growth_pct", "nlp_drift_score"],
                                  model.feature_importances_):
        print(f"  {name:<20} {importance:.3f}")

    print(f"\n[CAUTION -- per design doc Section 6.3] This model is trained on "
          f"{len(train)} examples across {len(train_years)} year-over-year transitions "
          f"({train_years[0]}-{train_years[-1]}) and tested on {len(test)} from "
          f"{test_year}. Read it as a demonstration of the forecasting approach: the "
          f"feature importances show centrality predicting almost entirely from its own "
          f"lagged value, so it is closer to a persistence model than a genuine forecast.")

    # Persist predictions for the dashboard -- a predicted-vs-actual scatter is a
    # more honest way to show "this doesn't beat the naive baseline" visually
    # than just quoting the MAE number.
    results_df = pd.DataFrame({
        "cwe_id": [e[0] for e in test],
        "feature_year": [e[1] for e in test],
        "current_centrality": current_test,
        "actual_next_centrality": y_test,
        "predicted_next_centrality": y_pred,
        "naive_predicted_next_centrality": current_test,  # persistence baseline
    })
    results_df.to_csv(DATA_DIR / "forecast_results.csv", index=False)
    print(f"\nWrote {DATA_DIR / 'forecast_results.csv'} ({len(results_df)} rows)")

    conn.close()


if __name__ == "__main__":
    main()