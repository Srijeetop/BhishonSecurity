"""
reporter.py
-----------
Generates a detailed plain-text + markdown security report.
"""

import os
import datetime
from typing import List, Dict
from network_scanner import NetworkNode
from vuln_engine import network_risk_summary, blast_radius, CVE_SEVERITY

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def _bar(score: float, width: int = 30) -> str:
    filled = int(score * width)
    empty  = width - filled
    return f"[{'█' * filled}{'░' * empty}] {score:.0%}"


def _severity_label(score: float) -> str:
    if score < 0.3:  return "LOW     "
    if score < 0.55: return "MEDIUM  "
    if score < 0.75: return "HIGH    "
    return              "CRITICAL"


def generate_report(
    nodes: List[NetworkNode],
    ml_results: Dict,
    output_file: str = "vulnerability_report.txt"
) -> str:
    now     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary = network_risk_summary(nodes)
    node_map = {n.ip: n for n in nodes}
    lines   = []

    def h1(t): lines.append(""); lines.append("=" * 80); lines.append(f"  {t}"); lines.append("=" * 80)
    def h2(t): lines.append(""); lines.append(f"── {t} " + "─" * max(0, 74 - len(t)))
    def ln(t=""): lines.append(t)

    # ── HEADER ────────────────────────────────────────────────────────────────
    h1("🔐  NETWORK VULNERABILITY ASSESSMENT REPORT")
    ln(f"  Generated : {now}")
    ln(f"  Nodes     : {summary['total_nodes']}")
    ln(f"  Avg Score : {summary['average_score']:.3f}")
    ln(f"  Overall   : {summary['overall_risk']} RISK")

    # ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
    h2("EXECUTIVE SUMMARY")
    zc = summary["zone_counts"]
    ln(f"  CRITICAL  : {zc['CRITICAL']:3d} nodes   HIGH    : {zc['HIGH']:3d} nodes")
    ln(f"  MEDIUM    : {zc['MEDIUM']:3d} nodes   LOW     : {zc['LOW']:3d} nodes")
    if summary["critical_path"]:
        ln(f"\n  ⚠  Critical nodes directly connected to gateway:")
        for ip in summary["critical_path"]:
            n = node_map.get(ip)
            if n:
                ln(f"     • {n.hostname} ({ip})  score={n.vulnerability_score:.3f}")

    # ── PER-NODE ANALYSIS ─────────────────────────────────────────────────────
    h2("DETAILED NODE ANALYSIS (sorted by risk)")
    for n in nodes:
        risk_lbl = _severity_label(n.vulnerability_score)
        ln()
        ln(f"  ┌─ [{risk_lbl}] {n.hostname:<30} {n.ip}")
        ln(f"  │  Device : {n.device_type}   OS: {n.os}   VLAN: {n.vlan}")
        ln(f"  │  Score  : {_bar(n.vulnerability_score)}")
        if n.open_ports:
            ln(f"  │  Ports  :")
            for sp in sorted(n.open_ports, key=lambda x: x.risk_base, reverse=True):
                cve_str = ", ".join(sp.cve_ids[:2]) if sp.cve_ids else "none"
                ln(f"  │    {'►' if sp.state=='open' else '○'} {sp.port:5d}/{sp.service:<15} "
                   f"risk={sp.risk_base:.0%}  state={sp.state}  CVEs: {cve_str}")
        br = blast_radius(n, nodes)
        if br:
            top = sorted(br.items(), key=lambda x: x[1], reverse=True)[:3]
            ln(f"  │  Blast radius (top 3):")
            for tgt_ip, r in top:
                tgt = node_map.get(tgt_ip)
                if tgt:
                    ln(f"  │    → {tgt.hostname} ({tgt_ip})  propagated={r:.0%}")
        ln(f"  └{'─'*60}")

    # ── CVE HIGHLIGHTS ────────────────────────────────────────────────────────
    h2("HIGH-SEVERITY CVEs DETECTED")
    cve_hits: Dict[str, List[str]] = {}
    for n in nodes:
        for sp in n.open_ports:
            for cve in sp.cve_ids:
                cve_hits.setdefault(cve, []).append(f"{n.hostname} ({n.ip})")

    sorted_cves = sorted(
        cve_hits.items(),
        key=lambda x: CVE_SEVERITY.get(x[0], 0),
        reverse=True
    )
    for cve, affected in sorted_cves[:15]:
        cvss = CVE_SEVERITY.get(cve, "?")
        ln(f"  {cve:<20}  CVSS {cvss:<5}  Affects: {', '.join(affected[:3])}"
           f"{'...' if len(affected)>3 else ''}")

    # ── ML RESULTS ────────────────────────────────────────────────────────────
    h1("🤖  ML ANALYSIS & TOPOLOGY RECOMMENDATIONS")

    if "error" in ml_results:
        ln(f"  [ML unavailable: {ml_results['error']}]")
    else:
        # Anomalies
        h2("ANOMALOUS NODES (IsolationForest)")
        anoms = ml_results.get("anomalous_nodes", [])
        if anoms:
            for a in anoms:
                n = node_map.get(a["ip"])
                nm = n.hostname if n else a["ip"]
                ln(f"  ⚠  {nm} ({a['ip']})  anomaly_score={a['score']:.3f}")
        else:
            ln("  No anomalous nodes detected.")

        # Clusters
        h2("SECURITY SEGMENTS (KMeans Clustering)")
        segs  = ml_results.get("security_segments", {})
        risks = ml_results.get("segment_risk_scores", {})
        for cid, c_ips in sorted(segs.items(), key=lambda x: risks.get(x[0],0), reverse=True):
            r    = risks.get(cid, 0)
            zone = _severity_label(r)
            hostnames = [node_map[ip].hostname for ip in c_ips if ip in node_map][:5]
            ln(f"  Segment {cid}  risk={r:.0%}  [{zone}]")
            ln(f"    Members: {', '.join(hostnames)}{'...' if len(c_ips)>5 else ''}")

        # Recommendations
        h2("NODE-LEVEL HARDENING RECOMMENDATIONS")
        recs = ml_results.get("recommendations", [])
        if recs:
            for rec in recs:
                ln()
                ln(f"  Node: {rec['hostname']} ({rec['node']})")
                ln(f"  Score: {rec['current_score']:.3f} → {rec['projected_score']:.3f}  "
                   f"(↓ {rec['risk_reduction']}%)")
                ln(f"  Zone:  {rec['current_zone']} → {rec['projected_zone']}")
                for act in rec["actions"]:
                    pri = "‼" if act["priority"] == "HIGH" else "•"
                    ln(f"    {pri} [{act['action']}] {act['detail']}")
        else:
            ln("  No high/critical nodes requiring action.")

        # Topology plan
        h2("TOPOLOGY REDESIGN PLAN")
        for line in ml_results.get("topology_plan", []):
            ln(f"  {line}")

    # ── FOOTER ────────────────────────────────────────────────────────────────
    h1("END OF REPORT")
    ln(f"  Total findings: {sum(zc.values())} nodes assessed")
    ln(f"  Files generated in ./output/")
    ln()

    report_text = "\n".join(lines)
    out_path    = os.path.join(OUTPUT_DIR, output_file)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    return out_path, report_text
