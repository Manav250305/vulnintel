"""
Phase 4 cross-validation — check the from-scratch Octave power iteration
against numpy's trusted eigh() eigensolver, before trusting any analytical
conclusions drawn from it.

Usage:
    python3 verify_power_iteration.py
"""
import numpy as np
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"


def main():
    A = np.loadtxt(DATA_DIR / "cooccurrence_matrix.csv", delimiter=",")
    A = A + A.T  # same symmetrization as power_iteration.m
    n = A.shape[0]

    v_octave = np.loadtxt(DATA_DIR / "centrality_scores.csv", delimiter=",")

    # eigh returns eigenvalues ascending, for a real symmetric matrix -- the
    # dominant one (largest magnitude) is the last one, since this
    # co-occurrence matrix is non-negative (Perron-Frobenius: dominant
    # eigenvalue is the largest, not just largest-magnitude, for this case).
    eigenvalues, eigenvectors = np.linalg.eigh(A)
    lambda_true = eigenvalues[-1]
    v_true = eigenvectors[:, -1]

    print(f"Octave dominant eigenvalue (Rayleigh quotient): reported separately, compare below")
    print(f"numpy dominant eigenvalue (eigh):                {lambda_true:.4f}")

    # Eigenvectors are only defined up to sign -- align signs before comparing
    if np.dot(v_octave, v_true) < 0:
        v_true = -v_true

    max_abs_diff = np.max(np.abs(v_octave - v_true))
    correlation = np.dot(v_octave, v_true) / (np.linalg.norm(v_octave) * np.linalg.norm(v_true))

    print(f"\nMax absolute element-wise difference: {max_abs_diff:.2e}")
    print(f"Cosine similarity (should be ~1.0):   {correlation:.10f}")

    if max_abs_diff < 1e-4 and correlation > 0.9999:
        print("\n[PASS] Octave power iteration matches numpy's trusted eigensolver")
    else:
        print("\n[FAIL] Meaningful divergence -- investigate before trusting centrality rankings")

    # Also recompute the Rayleigh quotient here for a direct side-by-side
    lambda_octave = (v_octave @ A @ v_octave) / (v_octave @ v_octave)
    print(f"\nOctave eigenvalue (recomputed here): {lambda_octave:.4f}")
    print(f"numpy eigenvalue:                    {lambda_true:.4f}")
    print(f"Difference: {abs(lambda_octave - lambda_true):.6f}")


if __name__ == "__main__":
    main()