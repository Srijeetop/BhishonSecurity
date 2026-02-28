#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   NET-VULN-ANALYZER  •  Network Security Scanner             ║
║            • sklearn + networkx + matplotlib                 ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python main.py                          # demo with 20 simulated nodes
    python main.py --subnet 192.168.1.0/24 --nodes 30 --seed 99
    python main.py --retrain               # force model retrain

Architecture:
    network_scanner.py  → discover/simulate nodes & open ports
    vuln_engine.py      → score vulnerabilities, compute blast radius
    ml_optimizer.py     → IsolationForest + KMeans + GBM recommendations
    visualizer.py       → matplotlib network maps & heatmaps
    reporter.py         → full text/markdown security report
"""

import sys
import os
import argparse
import time

# ── CLI ───────────────────────────────────────────────────
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    C = {
        "RED":    Fore.RED,
        "YLW":    Fore.YELLOW,
        "GRN":    Fore.GREEN,
        "CYN":    Fore.CYAN,
        "MAG":    Fore.MAGENTA,
        "WHT":    Fore.WHITE,
        "BOLD":   Style.BRIGHT,
        "RST":    Style.RESET_ALL,
    }
except ImportError:
    C = {k: "" for k in ("RED","YLW","GRN","CYN","MAG","WHT","BOLD","RST")}

RISK_CLR = {
    "LOW":      C["GRN"],
    "MEDIUM":   C["YLW"],
    "HIGH":     C["RED"],
    "CRITICAL": C["RED"] + C["BOLD"],
}


def banner():
    print(f"""
{C['CYN']}{C['BOLD']}
╔══════════════════════════════════════════════════════════════════╗
║   🔐  NET-VULN-ANALYZER  •   Network Security Tool               ║
║      Scan  •  Assess  •  Visualise  •  ML-Optimize               ║
╚══════════════════════════════════════════════════════════════════╝
{C['RST']}""")


def step(msg: str):
    print(f"  {C['CYN']}▶{C['RST']} {msg}")


def ok(msg: str):
    print(f"  {C['GRN']}✓{C['RST']} {msg}")


def warn(msg: str):
    print(f"  {C['YLW']}⚠{C['RST']}  {msg}")


def err(msg: str):
    print(f"  {C['RED']}✗{C['RST']} {msg}")


def risk_str(zone: str, score: float) -> str:
    clr = RISK_CLR.get(zone, "")
    return f"{clr}[{zone}] {score:.3f}{C['RST']}"


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Network Vulnerability Analyser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--subnet",  default="192.168.1.0/24", help="Network subnet to scan")
    parser.add_argument("--nodes",   type=int, default=20,      help="Node count (simulation)")
    parser.add_argument("--seed",    type=int, default=42,       help="Random seed")
    parser.add_argument("--retrain", action="store_true",        help="Force ML model retrain")
    parser.add_argument("--no-vis",  action="store_true",        help="Skip visualisation")
    parser.add_argument("--real", action="store_true", help="Run real nmap scan instead of simulation")
    args = parser.parse_args()

    banner()

    # ── 1. Network discovery ──────────────────────────────────────────────────
    step(f"Scanning network {args.subnet} ({args.nodes} nodes)…")
    t0 = time.time()
    from network_scanner import simulate_network
    # NEW (supports both modes)
    if getattr(args, 'real', False):
        from network_scanner import real_scan
        nodes = real_scan(subnet=args.subnet)
    else:
        nodes = simulate_network(subnet=args.subnet, node_count=args.nodes, seed=args.seed)
    ok(f"Discovered {len(nodes)} nodes in {time.time()-t0:.1f}s")

    # ── 2. Vulnerability assessment ───────────────────────────────────────────
    step("Running vulnerability assessment…")
    from vuln_engine import assess_all, network_risk_summary, blast_radius
    nodes   = assess_all(nodes)
    summary = network_risk_summary(nodes)

    print(f"\n  {C['BOLD']}Network Overview:{C['RST']}")
    print(f"    Overall Risk  : {risk_str(summary['overall_risk'], summary['average_score'])}")
    zc = summary['zone_counts']
    print(f"    CRITICAL: {zc['CRITICAL']}  HIGH: {zc['HIGH']}  MEDIUM: {zc['MEDIUM']}  LOW: {zc['LOW']}")
    print()

    print(f"  {C['BOLD']}Top 5 Most Vulnerable Nodes:{C['RST']}")
    for n in nodes[:5]:
        ports_open = sum(1 for sp in n.open_ports if sp.state == "open")
        print(f"    {risk_str(n.risk_zone, n.vulnerability_score)}  "
              f"{n.hostname:<28} {n.ip:<16} {n.device_type}  "
              f"({ports_open} open ports)")
    print()

    if summary["critical_path"]:
        warn(f"Gateway-adjacent CRITICAL nodes: {', '.join(summary['critical_path'])}")

    # ── 3. ML pipeline ────────────────────────────────────────────────────────
    step("Running ML analysis (IsolationForest + KMeans + GBM)…")
    from ml_optimizer import load_models, train_and_save_models, run_ml_pipeline
    import os as _os

    models_dir = _os.path.join(_os.path.dirname(__file__), "models")
    models = None if args.retrain else load_models()

    if models is None:
        print(f"  {C['MAG']}  Training ML models…{C['RST']}")
        models = train_and_save_models(nodes)
        ok("Models trained and saved to ./models/")
    else:
        ok("Loaded pre-trained models from ./models/")

    ml_results = run_ml_pipeline(nodes, models)

    # Print anomalies
    anoms = ml_results.get("anomalous_nodes", [])
    if anoms:
        warn(f"Anomalous nodes detected ({len(anoms)}):")
        for a in anoms[:5]:
            from network_scanner import NetworkNode
            nm_list = [n for n in nodes if n.ip == a["ip"]]
            nm = nm_list[0].hostname if nm_list else a["ip"]
            print(f"    {C['YLW']}⚠{C['RST']}  {nm} ({a['ip']})  anomaly_score={a['score']:.3f}")

    # Print top recommendations
    recs = ml_results.get("recommendations", [])
    if recs:
        print(f"\n  {C['BOLD']}Top ML Recommendations:{C['RST']}")
        for rec in recs[:3]:
            print(f"    {risk_str(rec['current_zone'], rec['current_score'])} → "
                  f"{risk_str(rec['projected_zone'], rec['projected_score'])}  "
                  f"({rec['risk_reduction']}% reduction)  {rec['hostname']}")
            for act in rec["actions"][:2]:
                pri = f"{C['RED']}‼{C['RST']}" if act["priority"]=="HIGH" else "•"
                print(f"      {pri} {act['detail'][:75]}")

    # ── 4. Visualisation ──────────────────────────────────────────────────────
    generated_files = []
    if not args.no_vis:
        step("Generating network maps…")
        from visualizer import (draw_network_map, draw_risk_heatmap,
                                 draw_blast_radius_map, draw_risk_summary_chart)

        f1 = draw_network_map(nodes)
        ok(f"Network map       → {f1}")
        generated_files.append(f1)

        f2 = draw_risk_heatmap(nodes)
        ok(f"Risk heatmap       → {f2}")
        generated_files.append(f2)

        f3 = draw_blast_radius_map(nodes)
        ok(f"Blast radius map   → {f3}")
        generated_files.append(f3)

        f4 = draw_risk_summary_chart(nodes)
        ok(f"Risk summary chart → {f4}")
        generated_files.append(f4)
    else:
        warn("Visualisation skipped (--no-vis)")

    # ── 5. Report ─────────────────────────────────────────────────────────────
    step("Generating full vulnerability report…")
    from reporter import generate_report
    report_path, report_text = generate_report(nodes, ml_results)
    ok(f"Report saved       → {report_path}")
    generated_files.append(report_path)

    # Print last section of report to console
    print()
    print(f"  {C['BOLD']}{'─'*60}{C['RST']}")
    print(f"  {C['BOLD']}TOPOLOGY REDESIGN SUMMARY (ML):{C['RST']}")
    for line in ml_results.get("topology_plan", [])[:10]:
        print(f"  {line}")

    # ── Done ──────────────────────────────────────────────────────────────────
    print()
    print(f"{C['GRN']}{C['BOLD']}{'═'*60}")
    print(f"  Analysis complete!  All output saved to ./output/")
    print(f"{'═'*60}{C['RST']}")
    print()

    return generated_files


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(__file__))
    main()
