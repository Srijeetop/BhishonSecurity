"""
visualizer.py
-------------
Generates rich network topology maps using NetworkX + matplotlib.
Outputs:
  • network_map.png        – full topology with risk-colored nodes
  • risk_heatmap.png       – adjacency risk heatmap
  • blast_radius_map.png   – risk propagation from top-3 critical nodes
"""

import os
import math
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.colors as mcolors
import networkx as nx
from typing import List, Dict, Optional

from network_scanner import NetworkNode
from vuln_engine import RISK_COLORS, blast_radius


OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ── helpers ───────────────────────────────────────────────────────────────────

def _build_graph(nodes: List[NetworkNode]) -> nx.DiGraph:
    G = nx.DiGraph()
    for n in nodes:
        G.add_node(
            n.ip,
            hostname    = n.hostname,
            device_type = n.device_type,
            risk_zone   = n.risk_zone,
            vuln_score  = n.vulnerability_score,
            vlan        = n.vlan,
            is_gateway  = n.is_gateway,
        )
    for n in nodes:
        for peer_ip in n.connections:
            if peer_ip != n.ip and peer_ip in {nd.ip: nd for nd in nodes}:
                G.add_edge(n.ip, peer_ip)
    return G


def _risk_color(score: float) -> str:
    if score < 0.30:   return RISK_COLORS["LOW"]
    if score < 0.55:   return RISK_COLORS["MEDIUM"]
    if score < 0.75:   return RISK_COLORS["HIGH"]
    return RISK_COLORS["CRITICAL"]


def _node_shape_marker(dtype: str) -> str:
    shapes = {
        "Router":          "D",
        "Firewall":        "^",
        "Switch":          "s",
        "Database Server": "p",
        "Web Server":      "h",
        "IoT Device":      "X",
        "Workstation":     "o",
        "Server":          "s",
        "NAS":             "8",
        "Printer":         "P",
    }
    return shapes.get(dtype, "o")


# ── Main network map ──────────────────────────────────────────────────────────

def draw_network_map(
    nodes: List[NetworkNode],
    filename: str = "network_map.png",
    title: str = "Office Network – Vulnerability Map"
) -> str:
    G = _build_graph(nodes)
    node_map = {n.ip: n for n in nodes}

    fig, ax = plt.subplots(figsize=(20, 14))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    # Layout: gateway in centre, rest spread
    try:
        pos = nx.kamada_kawai_layout(G, scale=3)
    except Exception:
        pos = nx.spring_layout(G, seed=42, k=2.5, scale=3)

    # Draw edges with risk-based alpha
    edge_colors, edge_widths, edge_alphas = [], [], []
    for u, v in G.edges():
        src_score = node_map.get(u, None)
        risk      = src_score.vulnerability_score if src_score else 0.3
        edge_colors.append(_risk_color(risk))
        edge_widths.append(0.8 + risk * 2)
        edge_alphas.append(0.3 + risk * 0.5)

    nx.draw_networkx_edges(
        G, pos, ax=ax,
        edge_color=edge_colors,
        width=edge_widths,
        alpha=0.6,
        arrows=True,
        arrowsize=15,
        connectionstyle="arc3,rad=0.05",
    )

    # Draw nodes grouped by device type for shape variety
    for dtype in set(n.device_type for n in nodes):
        subset = [n for n in nodes if n.device_type == dtype]
        sub_ips = [n.ip for n in subset]
        sub_pos = {ip: pos[ip] for ip in sub_ips if ip in pos}
        if not sub_pos:
            continue
        colors  = [_risk_color(n.vulnerability_score) for n in subset if n.ip in pos]
        sizes   = [600 + n.vulnerability_score * 1200 for n in subset if n.ip in pos]
        marker  = _node_shape_marker(dtype)

        nx.draw_networkx_nodes(
            G, pos, nodelist=list(sub_pos.keys()),
            node_color=colors, node_size=sizes,
            node_shape=marker, ax=ax,
            edgecolors="#ffffff", linewidths=0.8, alpha=0.93,
        )

    # Labels (short hostname)
    labels = {n.ip: n.hostname.split("-")[0] + "\n" + n.ip.split(".")[-1]
              for n in nodes if n.ip in pos}
    nx.draw_networkx_labels(G, pos, labels=labels, ax=ax,
                            font_size=6.5, font_color="white", font_weight="bold")

    # ── Legend ────────────────────────────────────────────────────────────────
    risk_patches = [
        mpatches.Patch(color=RISK_COLORS[z], label=f"{z} Risk")
        for z in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    ]
    device_patches = [
        plt.scatter([], [], marker=_node_shape_marker(dt),
                    c="#aaaaaa", s=80, label=dt)
        for dt in ("Router", "Server", "Workstation", "Database Server",
                   "IoT Device", "Firewall")
    ]
    legend1 = ax.legend(handles=risk_patches, loc="upper left",
                        framealpha=0.3, facecolor="#0a0a1a",
                        labelcolor="white", fontsize=9, title="Risk Zone",
                        title_fontsize=9)
    legend1.get_title().set_color("white")
    ax.add_artist(legend1)
    legend2 = ax.legend(handles=device_patches, loc="lower left",
                        framealpha=0.3, facecolor="#0a0a1a",
                        labelcolor="white", fontsize=8, title="Device Type",
                        title_fontsize=8)
    legend2.get_title().set_color("white")

    ax.set_title(title, color="white", fontsize=16, fontweight="bold", pad=15)
    ax.axis("off")
    plt.tight_layout()

    out = os.path.join(OUTPUT_DIR, filename)
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    return out


# ── Risk heatmap ──────────────────────────────────────────────────────────────

def draw_risk_heatmap(nodes: List[NetworkNode], filename: str = "risk_heatmap.png") -> str:
    node_map = {n.ip: n for n in nodes}
    ips      = [n.ip for n in nodes]
    n        = len(ips)

    matrix = np.zeros((n, n))
    for i, src in enumerate(nodes):
        br = blast_radius(src, nodes)
        for j, tgt_ip in enumerate(ips):
            matrix[i][j] = br.get(tgt_ip, 0.0)

    fig, ax = plt.subplots(figsize=(max(10, n * 0.55), max(8, n * 0.45)))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    cmap = plt.cm.RdYlGn_r
    im   = ax.imshow(matrix, cmap=cmap, vmin=0, vmax=1, aspect="auto")

    short = [f"{n.hostname.split('-')[0]}\n.{n.ip.split('.')[-1]}" for n in nodes]
    ax.set_xticks(range(n))
    ax.set_yticks(range(n))
    ax.set_xticklabels(short, rotation=45, ha="right", fontsize=7, color="white")
    ax.set_yticklabels(short, fontsize=7, color="white")

    # Annotate cells
    for i in range(n):
        for j in range(n):
            v = matrix[i][j]
            if v > 0.05:
                ax.text(j, i, f"{v:.2f}", ha="center", va="center",
                        fontsize=5.5, color="white" if v > 0.5 else "black")

    cbar = plt.colorbar(im, ax=ax, fraction=0.03)
    cbar.set_label("Propagated Risk Score", color="white", fontsize=9)
    cbar.ax.yaxis.set_tick_params(color="white")
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color="white")

    ax.set_title("Risk Propagation Heatmap (row→source, col→target)",
                 color="white", fontsize=13, fontweight="bold")
    ax.tick_params(colors="white")
    for spine in ax.spines.values():
        spine.set_edgecolor("#444")

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, filename)
    plt.savefig(out, dpi=130, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    return out


# ── Blast radius map ──────────────────────────────────────────────────────────

def draw_blast_radius_map(
    nodes: List[NetworkNode],
    source_ips: Optional[List[str]] = None,
    filename: str = "blast_radius_map.png"
) -> str:
    """Highlight risk propagation from the top critical nodes."""
    node_map = {n.ip: n for n in nodes}

    # Default: top 3 by score
    if source_ips is None:
        sorted_nodes = sorted(nodes, key=lambda x: x.vulnerability_score, reverse=True)
        source_ips   = [n.ip for n in sorted_nodes[:3]]

    G   = _build_graph(nodes)
    fig, axes = plt.subplots(1, len(source_ips),
                             figsize=(9 * len(source_ips), 10))
    fig.patch.set_facecolor("#1a1a2e")
    if len(source_ips) == 1:
        axes = [axes]

    try:
        pos = nx.kamada_kawai_layout(G, scale=3)
    except Exception:
        pos = nx.spring_layout(G, seed=42, k=2.5, scale=3)

    for ax, src_ip in zip(axes, source_ips):
        ax.set_facecolor("#16213e")
        src_node = node_map.get(src_ip)
        if not src_node:
            continue

        br = blast_radius(src_node, nodes)

        # Node colours: source=red, affected=orange gradient, safe=green
        node_colors, node_sizes = [], []
        for n in nodes:
            if n.ip == src_ip:
                node_colors.append("#ff0000")
                node_sizes.append(1800)
            elif n.ip in br:
                r    = br[n.ip]
                rgba = plt.cm.hot_r(0.2 + r * 0.8)
                node_colors.append(rgba)
                node_sizes.append(600 + r * 900)
            else:
                node_colors.append("#2ecc71")
                node_sizes.append(450)

        nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#555577",
                               width=0.9, alpha=0.4, arrows=True, arrowsize=12)
        nx.draw_networkx_nodes(G, pos, node_color=node_colors,
                               node_size=node_sizes, ax=ax,
                               edgecolors="white", linewidths=0.7, alpha=0.92)
        labels = {n.ip: n.ip.split(".")[-1] for n in nodes}
        nx.draw_networkx_labels(G, pos, labels=labels, ax=ax,
                                font_size=6, font_color="white")

        title = f"Blast Radius: {src_node.hostname}\n" \
                f"Score {src_node.vulnerability_score:.2f} [{src_node.risk_zone}]"
        ax.set_title(title, color="white", fontsize=11, fontweight="bold")
        ax.axis("off")

        # Annotation: top 3 most-affected
        top3 = sorted(br.items(), key=lambda x: x[1], reverse=True)[:3]
        ann  = "\n".join([f"{node_map[ip].hostname}: {v:.2f}" for ip, v in top3 if ip in node_map])
        ax.text(0.02, 0.02, f"Most affected:\n{ann}",
                transform=ax.transAxes, color="white", fontsize=8,
                verticalalignment="bottom",
                bbox=dict(boxstyle="round", facecolor="#0a0a1a", alpha=0.6))

    fig.suptitle("Blast Radius Analysis – Top Critical Nodes",
                 color="white", fontsize=15, fontweight="bold", y=1.01)
    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, filename)
    plt.savefig(out, dpi=130, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    return out


# ── Risk zone summary bar ─────────────────────────────────────────────────────

def draw_risk_summary_chart(nodes: List[NetworkNode], filename: str = "risk_summary.png") -> str:
    from collections import Counter
    zone_order  = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    counts      = Counter(n.risk_zone for n in nodes)
    vals        = [counts.get(z, 0) for z in zone_order]
    colors      = [RISK_COLORS[z] for z in zone_order]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    fig.patch.set_facecolor("#1a1a2e")

    # Bar chart
    ax1.set_facecolor("#16213e")
    bars = ax1.bar(zone_order, vals, color=colors, edgecolor="white", linewidth=0.8)
    for bar, val in zip(bars, vals):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                 str(val), ha="center", va="bottom", color="white", fontsize=12)
    ax1.set_title("Node Count by Risk Zone", color="white", fontsize=13, fontweight="bold")
    ax1.set_ylabel("Count", color="white")
    ax1.tick_params(colors="white")
    for spine in ax1.spines.values():
        spine.set_edgecolor("#444")
    ax1.set_facecolor("#16213e")

    # Score distribution histogram
    ax2.set_facecolor("#16213e")
    scores = [n.vulnerability_score for n in nodes]
    ax2.hist(scores, bins=15, color="#e67e22", edgecolor="white", linewidth=0.6, alpha=0.85)
    ax2.axvline(x=0.30, color=RISK_COLORS["MEDIUM"], linestyle="--", linewidth=1.5, label="LOW/MED")
    ax2.axvline(x=0.55, color=RISK_COLORS["HIGH"],   linestyle="--", linewidth=1.5, label="MED/HIGH")
    ax2.axvline(x=0.75, color=RISK_COLORS["CRITICAL"],linestyle="--", linewidth=1.5, label="HIGH/CRIT")
    ax2.set_title("Vulnerability Score Distribution", color="white", fontsize=13, fontweight="bold")
    ax2.set_xlabel("Score", color="white")
    ax2.set_ylabel("Nodes", color="white")
    ax2.tick_params(colors="white")
    ax2.legend(facecolor="#0a0a1a", labelcolor="white", fontsize=8)
    for spine in ax2.spines.values():
        spine.set_edgecolor("#444")

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, filename)
    plt.savefig(out, dpi=130, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    return out
