"""
Phase 5, Step 2+3 — train and evaluate the CWE classifier (Module 3).

TF-IDF is fit on the TRAINING set only, then used to transform the test
set -- fitting on the full dataset (train+test combined) would leak
test-set vocabulary statistics into the model, silently inflating reported
performance. This matters more here than in Phase 3's clustering, where
there was no train/test distinction to leak across.

Model: multinomial logistic regression with class_weight='balanced' -- a
standard, interpretable baseline for TF-IDF text classification, and the
balancing matters given a ~47x imbalance between the largest and smallest
training classes (9,712 "Other" vs. 205 CWE-77).

Reports macro-F1 (not just accuracy, per design doc Section 6.3 -- a
handful of categories dominate the class distribution) and breaks test
performance down by year, specifically to check whether accuracy degrades
on later data as a drift signal, which is the actual point of the
time-based split rather than a random one.

Usage:
    python3 train_classifier.py
"""
import csv
import numpy as np
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
import joblib

DATA_DIR = Path(__file__).resolve().parent / "data"


def load_dataset():
    with open(DATA_DIR / "classifier_dataset.csv") as f:
        rows = list(csv.DictReader(f))
    train = [r for r in rows if r["split"] == "train"]
    test = [r for r in rows if r["split"] == "test"]
    return train, test


def main():
    train, test = load_dataset()
    print(f"Train: {len(train)}, Test: {len(test)}")

    X_train_text = [r["cleaned_description"] for r in train]
    y_train = [r["label"] for r in train]
    X_test_text = [r["cleaned_description"] for r in test]
    y_test = [r["label"] for r in test]

    vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), min_df=3, max_df=0.5)
    X_train = vectorizer.fit_transform(X_train_text)  # fit on TRAIN ONLY
    X_test = vectorizer.transform(X_test_text)         # transform test with train's vocabulary
    print(f"TF-IDF vocabulary size (from train only): {len(vectorizer.vocabulary_)}")

    clf = LogisticRegression(class_weight="balanced", max_iter=1000, C=1.0)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    print(f"\nOverall test accuracy: {accuracy:.4f}")
    print(f"Overall test macro-F1: {macro_f1:.4f}")

    print("\n--- Per-class report ---")
    print(classification_report(y_test, y_pred, zero_division=0))

    # Drift check: does performance degrade across the test period (2021-2023)?
    # This is the actual point of the time-based split, not just accuracy.
    print("--- Accuracy/macro-F1 by test year (drift check) ---")
    test_years = [int(r["year"]) for r in test]
    for year in sorted(set(test_years)):
        idx = [i for i, y in enumerate(test_years) if y == year]
        y_true_y = [y_test[i] for i in idx]
        y_pred_y = [y_pred[i] for i in idx]
        acc_y = accuracy_score(y_true_y, y_pred_y)
        f1_y = f1_score(y_true_y, y_pred_y, average="macro")
        print(f"  {year}: n={len(idx):>6}  accuracy={acc_y:.4f}  macro_F1={f1_y:.4f}")

    # Save everything Step 4 (cross-check against co-occurrence) needs
    labels_sorted = sorted(set(y_train) | set(y_test))
    cm = confusion_matrix(y_test, y_pred, labels=labels_sorted)
    joblib.dump({
        "vectorizer": vectorizer, "clf": clf, "labels_sorted": labels_sorted,
        "confusion_matrix": cm, "y_test": y_test, "y_pred": y_pred,
    }, DATA_DIR / "classifier_results.joblib")
    print(f"\nSaved model + confusion matrix to {DATA_DIR / 'classifier_results.joblib'}")


if __name__ == "__main__":
    main()