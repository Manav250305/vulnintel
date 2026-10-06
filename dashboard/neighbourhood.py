"""
A weakness type's neighbourhood: which other types appear alongside it in the
same product in the same year, and which products those pairings come from.

Reads the cwe_bucket table the network stage writes (octave/
build_cooccurrence.py) -- the exact vendor-product-year groups the
co-occurrence matrix is summed from -- so every figure here adds up to the
edge weights behind the Weakness network tab. Goes through the assistant's
read-only connection, so a rebuild holding the write lock surfaces as
DataUnavailable rather than a traceback.
"""
import sqlite3

import pandas as pd

from assistant import DataUnavailable, _connect, _fetch  # noqa: F401 -- re-exported


class NotBuilt(RuntimeError):
    """The database predates the cwe_bucket table; the network stage writes it."""


def _query(conn, sql, params):
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError as e:
        if "no such table" in str(e):
            raise NotBuilt(str(e)) from e
        raise DataUnavailable(str(e)) from e


def load(cwe_id):
    """(products, pairings) for one weakness type.

    products -- one row per vendor-product-year the type appears in.
    pairings -- one row per (year, partner, vendor, product) where another
                type appears in that same vendor-product-year.
    """
    with _connect() as conn:
        products = _query(conn, """
            SELECT year, vendor, product FROM cwe_bucket WHERE cwe_id = ?
        """, (cwe_id,))
        pairings = _query(conn, """
            SELECT b.year, b.cwe_id, b.vendor, b.product
            FROM cwe_bucket t
            JOIN cwe_bucket b ON b.vendor = t.vendor AND b.product = t.product
                             AND b.year = t.year
            WHERE t.cwe_id = ? AND b.cwe_id <> ?
        """, (cwe_id, cwe_id))
    return (pd.DataFrame(products, columns=["year", "vendor", "product"]),
            pd.DataFrame(pairings, columns=["year", "partner", "vendor", "product"]))
