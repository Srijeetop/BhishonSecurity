"""
vuln_engine.py
--------------
Scores each node's vulnerability, assigns risk zones, and computes
how one compromised node threatens its neighbours (blast radius).
"""

import math
from typing import List, Dict, Tuple
from network_scanner import NetworkNode, ScannedPort

# ── CVE severity map (CVSS base score approximation) ─────────────────────────
# In production query NVD for free: https://services.nvd.nist.gov/rest/json/cves/2.0
CVE_SEVERITY: Dict[str, float] = {
    "CVE-2017-0144":  9.8,  # EternalBlue / WannaCry
    "CVE-2020-0796":  10.0, # SMBGhost
    "CVE-2019-0708":  9.8,  # BlueKeep
    "CVE-2020-0609":  9.8,  # RDP pre-auth RCE
    "CVE-2021-41773": 9.8,  # Apache path traversal
    "CVE-2020-11996": 7.5,
    "CVE-2022-0543":  10.0, # Redis Lua sandbox escape
    "CVE-2023-38408": 9.8,  # ssh-agent RCE
    "CVE-2019-15681": 9.8,  # VNC no-auth
    "CVE-2018-15473": 5.3,  # OpenSSH user enum
    "CVE-2020-1350":  10.0, # SIGRed DNS
    "CVE-2011-2523":  10.0, # vsftpd backdoor
    "CVE-2020-9054":  9.8,  # Zyxel FTP
    "CVE-2020-7247":  10.0, # OpenSMTPD RCE
    "CVE-2003-0352":  7.5,  # MS-RPC
    "CVE-2003-0965":  6.5,
    "CVE-2021-38371": 7.5,
    "CVE-2021-3449":  5.9,  # OpenSSL DoS
    "CVE-2020-0618":  8.8,  # MSSQL
    "CVE-2012-3137":  6.4,
    "CVE-2012-2122":  5.1,
    "CVE-2021-2307":  4.9,
    "CVE-2022-22947": 10.0, # Spring4Shell
    "CVE-2019-2389":  6.5,  # MongoDB
    "CVE-2020-10188": 9.8,  # Telnet
    "CVE-2017-0145":  8.1,
}


RISK_THRESHOLDS = {
    "LOW":      (0.00, 0.30),
    "MEDIUM":   (0.30, 0.55),
    "HIGH":     (0.55, 0.75),
    "CRITICAL": (0.75, 1.00),
}

RISK_COLORS = {
    "LOW":      "#2ecc71",
    "MEDIUM":   "#f1c40f",
    "HIGH":     "#e67e22",
    "CRITICAL": "#e74c3c",
}


def score_node(node: NetworkNode) -> float:
    """
    Compute a composite vulnerability score [0-1] for a node.
    Factors:
      1. Open port risk (weighted by service criticality)
      2. CVE severity from open services
      3. Device-type exposure multiplier
      4. Filtered port partial credit
    """
    if not node.open_ports:
        return 0.05  # always some ambient risk

    port_score = 0.0
    cve_score  = 0.0
    open_count = 0

    for sp in node.open_ports:
        w = 1.0 if sp.state == "open" else 0.3
        port_score += sp.risk_base * w
        open_count += w
        for cve in sp.cve_ids:
            cvss = CVE_SEVERITY.get(cve, 5.0)
            cve_score = max(cve_score, cvss / 10.0)

    # Normalize port contribution
    port_contrib = min(port_score / max(open_count, 1), 1.0)

    # Device-type multiplier
    type_mult = {
        "Router":          1.4,
        "Firewall":        1.2,
        "Database Server": 1.3,
        "Web Server":      1.2,
        "NAS":             1.1,
        "Server":          1.2,
        "IoT Device":      1.3,
        "Workstation":     1.0,
        "Printer":         0.9,
        "Switch":          1.1,
    }.get(node.device_type, 1.0)

    # Combine: 50% port risk, 30% CVE, 20% type
    raw = (0.50 * port_contrib + 0.30 * cve_score) * type_mult
    return min(raw, 1.0)


def assign_risk_zone(score: float) -> str:
    for zone, (lo, hi) in RISK_THRESHOLDS.items():
        if lo <= score <= hi:
            return zone
    return "CRITICAL"


def propagation_score(
    source: NetworkNode,
    target: NetworkNode,
    all_nodes_map: Dict[str, NetworkNode]
) -> float:
    """
    Estimate how much risk propagates from source -> target.
    High-connectivity + high-risk source is most dangerous.
    """
    if target.ip not in source.connections:
        return 0.0

    # Same VLAN is more dangerous
    vlan_factor = 1.5 if source.vlan == target.vlan else 0.6

    # Lateral movement risk: SMB/RDP presence on target
    lateral_ports = {139, 445, 3389, 22}
    target_lateral = sum(
        1 for sp in target.open_ports
        if sp.port in lateral_ports and sp.state == "open"
    )
    lateral_factor = 1.0 + 0.15 * target_lateral

    propagated = source.vulnerability_score * 0.65 * vlan_factor * lateral_factor
    return min(propagated, 1.0)


def blast_radius(
    node: NetworkNode,
    all_nodes: List[NetworkNode]
) -> Dict[str, float]:
    """
    For a given node, return {ip: propagated_risk} for all neighbours.
    Uses a simple 2-hop BFS so distant nodes get diluted risk.
    """
    node_map = {n.ip: n for n in all_nodes}
    result: Dict[str, float] = {}

    # 1-hop
    for peer_ip in node.connections:
        if peer_ip == node.ip:
            continue
        peer = node_map.get(peer_ip)
        if peer:
            r = propagation_score(node, peer, node_map)
            result[peer_ip] = r

            # 2-hop (diluted by 0.4)
            for peer2_ip in peer.connections:
                if peer2_ip in (node.ip, peer_ip):
                    continue
                peer2 = node_map.get(peer2_ip)
                if peer2:
                    r2 = propagation_score(peer, peer2, node_map) * 0.4
                    result[peer2_ip] = max(result.get(peer2_ip, 0.0), r2)

    return result


def assess_all(nodes: List[NetworkNode]) -> List[NetworkNode]:
    """Score and zone every node in place, return sorted by risk desc."""
    for n in nodes:
        n.vulnerability_score = score_node(n)
        n.risk_zone           = assign_risk_zone(n.vulnerability_score)
    return sorted(nodes, key=lambda x: x.vulnerability_score, reverse=True)


def network_risk_summary(nodes: List[NetworkNode]) -> Dict:
    zone_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    total_score = 0.0
    for n in nodes:
        zone_counts[n.risk_zone] += 1
        total_score += n.vulnerability_score

    avg = total_score / len(nodes) if nodes else 0
    overall = assign_risk_zone(avg)

    # Critical path: highest-risk node connected to gateway
    gateway = next((n for n in nodes if n.is_gateway), None)
    critical_path = []
    if gateway:
        for n in nodes:
            if gateway.ip in n.connections and n.risk_zone in ("HIGH", "CRITICAL"):
                critical_path.append(n.ip)

    return {
        "total_nodes":    len(nodes),
        "zone_counts":    zone_counts,
        "average_score":  round(avg, 3),
        "overall_risk":   overall,
        "critical_path":  critical_path,
    }
