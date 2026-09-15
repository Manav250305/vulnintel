"""
Phase 7, Export 3 — CWE co-occurrence network (Module 7, dashboard view 3).

TABLEAU CAVEAT (design doc Section 6.4, stated explicitly per that
instruction): Tableau has no native network-graph chart type. This script
computes node (x, y) positions externally via networkx's force-directed
(spring) layout, and exports those coordinates plus a weighted edge list.
The intended Tableau technique is a dual-axis path chart: plot edges as
line segments between each pair's (x, y) coordinates, and overlay nodes as
a separate scatter layer sized/colored by degree or centrality. Tableau is
NOT rendering the network natively -- it's drawing pre-computed coordinates
that happen to look like one. Stating this plainly here and in the report,
rather than letting the dashboard imply otherwise.

Pruning strategy: a first attempt used a single global weight threshold
(95th percentile, >=174 co-occurrences) and left 295 of 366 nodes (80.6%)
completely isolated -- co-occurrence weight is heavily concentrated in the
memory-safety "core" identified in Phase 4, so a global cutoff shows one
dense clump plus a field of disconnected dots, not a useful network view.
Fixed by keeping each node's top-K strongest edges instead (K=5) --
guarantees every category with at least one real co-occurrence relationship
keeps some visible connection, while still pruning the bulk of weak edges
for legibility. A node with truly zero co-occurrence above noise (see
Phase 4's frequency-floor discussion) can still end up isolated; that's a
real property of the data, not a pruning artifact.

Usage:
    python3 export_cooccurrence_network.py
"""
import csv
import numpy as np
import networkx as nx
from pathlib import Path

OCTAVE_DATA = Path(__file__).resolve().parent.parent / "octave" / "data"
OUT_DIR = Path(__file__).resolve().parent / "exports"
TOP_K_PER_NODE = 5
LAYOUT_SEED = 42


def main():
    OUT_DIR.mkdir(exist_ok=True)

    with open(OCTAVE_DATA / "cwe_index.csv") as f:
        cwe_rows = list(csv.DictReader(f))
    cwe_ids = [r["cwe_id"] for r in cwe_rows]
    raw_freq = {r["cwe_id"]: int(r["raw_frequency"]) for r in cwe_rows}
    centrality = dict(zip(cwe_ids, np.loadtxt(OCTAVE_DATA / "centrality_scores.csv", delimiter=",")))

    A = np.loadtxt(OCTAVE_DATA / "cooccurrence_matrix.csv", delimiter=",")
    A = A + A.T
    n = A.shape[0]
    total_edges = int((A > 0).sum() / 2)

    # Keep each node's top-K strongest edges (union across both endpoints --
    # an edge survives if EITHER endpoint considers it one of its strongest)
    keep = set()
    for i in range(n):
        row = A[i]
        top_j = np.argsort(row)[::-1][:TOP_K_PER_NODE]
        for j in top_j:
            if row[j] > 0:
                keep.add((min(i, j), max(i, j)))

    G = nx.Graph()
    G.add_nodes_from(cwe_ids)
    for i, j in keep:
        G.add_edge(cwe_ids[i], cwe_ids[j], weight=A[i, j])
    print(f"Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges "
          f"(pruned from {total_edges} total, keeping each node's top {TOP_K_PER_NODE})")

    isolated = set(nx.isolates(G))
    print(f"Isolated nodes after pruning (no co-occurrence edge at all): {len(isolated)}")

    # Layout bug caught in dashboard review: computing spring_layout on the
    # FULL graph (connected nodes + isolates together) let the isolated
    # nodes' arbitrary positions dominate the auto-scaled canvas, squeezing
    # the actual connected structure into a tiny corner. Fixed by laying out
    # only the connected subgraph -- isolates get no (x, y) at all (NaN) and
    # are excluded from the visual, reported by count in a caption instead
    # of being scattered meaninglessly across the plot.
    connected_nodes = [c for c in cwe_ids if c not in isolated]
    G_connected = G.subgraph(connected_nodes)
    pos = nx.spring_layout(G_connected, seed=LAYOUT_SEED, weight="weight", k=0.4, iterations=100)

    with open(OUT_DIR / "cooccurrence_nodes.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cwe_id", "x", "y", "raw_frequency", "centrality", "degree", "is_isolated"])
        for cwe_id in cwe_ids:
            if cwe_id in isolated:
                x, y = "", ""
            else:
                x, y = pos[cwe_id]
            w.writerow([cwe_id, x, y, raw_freq[cwe_id], centrality[cwe_id],
                        G.degree(cwe_id), cwe_id in isolated])
    print(f"Wrote {OUT_DIR / 'cooccurrence_nodes.csv'} ({len(cwe_ids)} nodes, "
          f"{len(connected_nodes)} positioned)")

    with open(OUT_DIR / "cooccurrence_edges.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["source", "target", "weight", "source_x", "source_y", "target_x", "target_y"])
        for u, v, data in G.edges(data=True):
            ux, uy = pos[u]
            vx, vy = pos[v]
            w.writerow([u, v, data["weight"], ux, uy, vx, vy])
    print(f"Wrote {OUT_DIR / 'cooccurrence_edges.csv'} ({G.number_of_edges()} edges)")


if __name__ == "__main__":
    main()