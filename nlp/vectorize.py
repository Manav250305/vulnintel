"""
Phase 3, Step 2 — TF-IDF vectorization per quarter (Module 4).

Fits a SEPARATE TfidfVectorizer per quarter (not one global vocabulary
across the whole corpus) -- the design doc's intent is to find each
quarter's own topic structure independently, which a shared vocabulary
would blur together. Caches each quarter's (vectorizer, matrix, cve_ids)
to disk so Step 3 (clustering) can load them directly.

Usage:
    python3 vectorize.py
"""
import sqlite3
import joblib
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "vulnintel.db"
CACHE_DIR = Path(__file__).resolve().parent / "tfidf_cache"

MIN_DF = 3            # drop terms in fewer than 3 docs this quarter -- typos, one-off product names
MAX_DF = 0.5          # drop terms in more than 50% of docs this quarter -- too generic to be a topic signal
NGRAM_RANGE = (1, 2)  # unigrams + bigrams: "buffer overflow", "sql injection" are meaningful as phrases

# NVD's earliest quarters hold only a handful of backdated records (1989-Q1 has
# one). Below this, min_df=3 leaves an empty vocabulary and Step 3's K-means
# asks for more clusters than there are documents. Skipping them costs 0.2% of
# the corpus and starts the series at 1999-Q1.
MIN_DOCS = 100


def main():
    CACHE_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)

    quarters = [r[0] for r in conn.execute(
        "SELECT DISTINCT quarter FROM nlp_docs ORDER BY quarter"
    ).fetchall()]
    print(f"{len(quarters)} quarters found: {quarters[0]} .. {quarters[-1]}")

    summary = []
    skipped = []
    for quarter in quarters:
        rows = conn.execute(
            "SELECT cve_id, cleaned_description FROM nlp_docs WHERE quarter = ?",
            (quarter,),
        ).fetchall()
        cve_ids = [r[0] for r in rows]
        docs = [r[1] for r in rows]

        if len(docs) < MIN_DOCS:
            skipped.append((quarter, len(docs)))
            continue

        vectorizer = TfidfVectorizer(
            stop_words="english",
            min_df=MIN_DF,
            max_df=MAX_DF,
            ngram_range=NGRAM_RANGE,
        )
        matrix = vectorizer.fit_transform(docs)

        joblib.dump(
            {"vectorizer": vectorizer, "matrix": matrix, "cve_ids": cve_ids},
            CACHE_DIR / f"{quarter}.joblib",
        )
        summary.append((quarter, len(docs), len(vectorizer.vocabulary_)))

    if skipped:
        print(f"\nSkipped {len(skipped)} quarters under {MIN_DOCS} docs "
              f"({sum(n for _, n in skipped)} docs total): "
              f"{skipped[0][0]} .. {skipped[-1][0]}")

    print(f"\n{'quarter':>10} {'docs':>7} {'vocab_size':>11}")
    for quarter, n_docs, vocab_size in summary:
        print(f"{quarter:>10} {n_docs:>7} {vocab_size:>11}")

    # Sanity check: top terms by summed TF-IDF weight for the first and last quarter,
    # as a quick eyeball check that vectorization is producing sensible vocabulary
    for quarter in [quarters[0], quarters[-1]]:
        cached = joblib.load(CACHE_DIR / f"{quarter}.joblib")
        vectorizer, matrix = cached["vectorizer"], cached["matrix"]
        term_weights = matrix.sum(axis=0).A1
        top_idx = term_weights.argsort()[::-1][:15]
        terms = vectorizer.get_feature_names_out()
        print(f"\n--- Top 15 terms by summed TF-IDF weight, {quarter} ---")
        for i in top_idx:
            print(f"  {terms[i]}: {term_weights[i]:.1f}")

    conn.close()


if __name__ == "__main__":
    main()