"""
ml_optimizer.py
---------------
ML-powered network topology analyser and recommender.

Models used (all free / scikit-learn):
  1. IsolationForest   – anomaly detection to flag unusual nodes
  2. KMeans            – cluster nodes into security segments
  3. RandomForestRegressor – predict risk-reduction potential
  4. Custom greedy optimizer – suggests edge removals / VLAN moves

Import pattern (as requested): models are built and saved to disk,
then imported for inference via load_models() / run_ml_pipeline().
"""

import os
import pickle
import warnings
import numpy as np
from typing import List, Dict, Tuple, Optional

warnings.filterwarnings("ignore")

try:
    from sklearn.ensemble import IsolationForest, RandomForestRegressor, GradientBoostingRegressor
    from sklearn.cluster import KMeans
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("[WARN] scikit-learn not found; ML features disabled.")

from network_scanner import NetworkNode
from vuln_engine import blast_radius, CVE_SEVERITY

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODEL_DIR, exist_ok=True)

MODEL_PATHS = {
    "anomaly":    os.path.join(MODEL_DIR, "anomaly_detector.pkl"),
    "cluster":    os.path.join(MODEL_DIR, "node_clusterer.pkl"),
    "risk_pred":  os.path.join(MODEL_DIR, "risk_predictor.pkl"),
    "scaler":     os.path.join(MODEL_DIR, "feature_scaler.pkl"),
}


# ── Feature extraction ────────────────────────────────────────────────────────

def extract_features(node: NetworkNode, all_nodes: List[NetworkNode]) -> np.ndarray:
    """
    Turn a NetworkNode into a numeric feature vector for ML:
    [open_port_count, filtered_port_count, max_cvss, avg_cvss,
     connection_degree, same_vlan_peers, has_telnet, has_smb,
     has_rdp, has_ftp, is_gateway, device_type_encoded,
     vuln_score, blast_radius_sum]
    """
    open_p   = sum(1 for sp in node.open_ports if sp.state == "open")
    filt_p   = sum(1 for sp in node.open_ports if sp.state == "filtered")

    cvss_scores = [
        CVE_SEVERITY.get(cve, 5.0)
        for sp in node.open_ports for cve in sp.cve_ids
    ]
    max_cvss = max(cvss_scores, default=0.0)
    avg_cvss = float(np.mean(cvss_scores)) if cvss_scores else 0.0

    degree = len(node.connections)
    same_vlan = sum(
        1 for n in all_nodes
        if n.ip != node.ip and n.vlan == node.vlan and n.ip in node.connections
    )

    port_nums = {sp.port for sp in node.open_ports if sp.state == "open"}
    has_telnet = int(23 in port_nums)
    has_smb    = int(445 in port_nums or 139 in port_nums)
    has_rdp    = int(3389 in port_nums)
    has_ftp    = int(21 in port_nums)

    dtype_enc = {
        "Router": 0, "Firewall": 1, "Server": 2, "Workstation": 3,
        "Database Server": 4, "Web Server": 5, "IoT Device": 6,
        "NAS": 7, "Printer": 8, "Switch": 9,
    }.get(node.device_type, 5)

    br = blast_radius(node, all_nodes)
    blast_sum = sum(br.values())

    return np.array([
        open_p, filt_p, max_cvss, avg_cvss,
        degree, same_vlan,
        has_telnet, has_smb, has_rdp, has_ftp,
        int(node.is_gateway), dtype_enc,
        node.vulnerability_score, blast_sum
    ], dtype=float)


def build_feature_matrix(nodes: List[NetworkNode]) -> Tuple[np.ndarray, List[str]]:
    X = np.array([extract_features(n, nodes) for n in nodes])
    ips = [n.ip for n in nodes]
    return X, ips


# ── Model training / saving ───────────────────────────────────────────────────

def train_and_save_models(nodes: List[NetworkNode]) -> Dict:
    if not ML_AVAILABLE:
        return {}

    X, ips = build_feature_matrix(nodes)

    # 1. Scaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    with open(MODEL_PATHS["scaler"], "wb") as f:
        pickle.dump(scaler, f)

    # 2. Anomaly detector
    iso = IsolationForest(n_estimators=200, contamination=0.15, random_state=42)
    iso.fit(X_scaled)
    with open(MODEL_PATHS["anomaly"], "wb") as f:
        pickle.dump(iso, f)

    # 3. Node clusterer (segment the network into security zones)
    n_clusters = min(4, len(nodes))
    km = KMeans(n_clusters=n_clusters, n_init=10, random_state=42)
    km.fit(X_scaled)
    with open(MODEL_PATHS["cluster"], "wb") as f:
        pickle.dump(km, f)

    # 4. Risk predictor – synthetic training via risk augmentation
    #    Target: what would score be if we close high-risk ports?
    X_train, y_train = _synthesize_training_data(nodes, X_scaled)
    rf = GradientBoostingRegressor(n_estimators=200, max_depth=4, random_state=42)
    rf.fit(X_train, y_train)
    with open(MODEL_PATHS["risk_pred"], "wb") as f:
        pickle.dump(rf, f)

    return {
        "scaler":  scaler,
        "anomaly": iso,
        "cluster": km,
        "risk_pred": rf,
    }


def _synthesize_training_data(
    nodes: List[NetworkNode], X_scaled: np.ndarray
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Simulate what happens to risk score when we take hardening steps.
    Each row: original features → target = improved score.
    """
    from copy import deepcopy
    import random
    random.seed(0)

    X_aug, y_aug = [], []
    for i, node in enumerate(nodes):
        original_score = node.vulnerability_score

        # Simulate 5 hardening variants per node
        for _ in range(5):
            modified = deepcopy(node)
            # Randomly close some open ports
            modified.open_ports = [
                sp for sp in modified.open_ports
                if random.random() > 0.3
            ]
            # Recompute score
            from vuln_engine import score_node
            new_score = score_node(modified)
            features  = extract_features(modified, nodes)
            X_aug.append(features)
            y_aug.append(new_score)

    return np.array(X_aug), np.array(y_aug)


# ── Model loading ─────────────────────────────────────────────────────────────

def load_models() -> Optional[Dict]:
    """Load previously saved models from disk (import phase)."""
    if not ML_AVAILABLE:
        return None
    models = {}
    for key, path in MODEL_PATHS.items():
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            models[key] = pickle.load(f)
    return models


# ── Inference & recommendations ───────────────────────────────────────────────

def run_ml_pipeline(
    nodes: List[NetworkNode],
    models: Optional[Dict] = None
) -> Dict:
    """
    Full ML pipeline:
      1. Detect anomalous nodes
      2. Cluster into security segments
      3. Predict risk-reduction potential
      4. Greedy topology optimizer

    Returns a rich recommendations dict.
    """
    if not ML_AVAILABLE:
        return {"error": "scikit-learn not available"}

    # Train fresh if models not pre-loaded
    if models is None:
        print("  [ML] Training models (first run)...")
        models = train_and_save_models(nodes)

    X, ips = build_feature_matrix(nodes)
    scaler  = models["scaler"]
    iso     = models["anomaly"]
    km      = models["cluster"]
    rf      = models["risk_pred"]

    X_scaled = scaler.transform(X)

    # ── Anomaly detection ────────────────────────────────────────────────────
    anomaly_preds = iso.predict(X_scaled)   # -1 = anomalous
    anomaly_scores = iso.score_samples(X_scaled)
    anomalous_nodes = [
        {"ip": ips[i], "score": round(anomaly_scores[i], 3)}
        for i in range(len(ips)) if anomaly_preds[i] == -1
    ]

    # ── Clustering ───────────────────────────────────────────────────────────
    cluster_labels = km.predict(X_scaled)
    cluster_map: Dict[int, List[str]] = {}
    for i, lbl in enumerate(cluster_labels):
        cluster_map.setdefault(int(lbl), []).append(ips[i])

    # Assign cluster risk based on member scores
    node_score_map = {n.ip: n.vulnerability_score for n in nodes}
    cluster_risk = {}
    for c, c_ips in cluster_map.items():
        avg = np.mean([node_score_map[ip] for ip in c_ips])
        cluster_risk[c] = round(float(avg), 3)

    # ── Risk prediction & greedy optimisation ────────────────────────────────
    recommendations = _greedy_optimize(nodes, rf, scaler)

    # ── Topology restructuring plan ──────────────────────────────────────────
    topology_plan = _topology_plan(nodes, cluster_labels, cluster_risk, ips)

    return {
        "anomalous_nodes":     anomalous_nodes,
        "security_segments":   cluster_map,
        "segment_risk_scores": cluster_risk,
        "recommendations":     recommendations,
        "topology_plan":       topology_plan,
    }


def _greedy_optimize(
    nodes: List[NetworkNode],
    rf, scaler
) -> List[Dict]:
    """
    For each high/critical node, suggest the minimum set of actions
    (port closures, VLAN moves, edge removals) that reduce predicted risk the most.
    """
    from copy import deepcopy
    from vuln_engine import score_node, assign_risk_zone
    import itertools

    HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 3389, 5900}  # highest priority to close
    recs = []

    for node in nodes:
        if node.risk_zone not in ("HIGH", "CRITICAL"):
            continue

        actions = []
        projected_score = node.vulnerability_score

        # Action 1: Close dangerous ports
        dangerous = [
            sp for sp in node.open_ports
            if sp.port in HIGH_RISK_PORTS and sp.state == "open"
        ]
        for sp in dangerous:
            reduction = sp.risk_base * 0.45
            projected_score = max(0, projected_score - reduction)
            actions.append({
                "action": "CLOSE_PORT",
                "detail": f"Close port {sp.port} ({sp.service}) — reduces risk by ~{reduction:.0%}",
                "priority": "HIGH" if sp.risk_base >= 0.8 else "MEDIUM",
            })

        # Action 2: VLAN segmentation
        same_vlan_high = [
            n for n in nodes
            if n.ip != node.ip
            and n.vlan == node.vlan
            and n.risk_zone in ("HIGH", "CRITICAL")
        ]
        if same_vlan_high and len(same_vlan_high) >= 2:
            actions.append({
                "action": "VLAN_SEGMENT",
                "detail": f"Move {node.hostname} to isolated VLAN to separate from "
                          f"{len(same_vlan_high)} other high-risk nodes on VLAN {node.vlan}",
                "priority": "HIGH",
            })
            projected_score *= 0.7

        # Action 3: Remove high-risk peer connections
        node_map = {n.ip: n for n in nodes}
        risky_peers = [
            ip for ip in node.connections
            if node_map.get(ip) and node_map[ip].risk_zone in ("HIGH","CRITICAL")
        ]
        if risky_peers:
            for rip in risky_peers[:2]:  # top 2
                peer = node_map[rip]
                actions.append({
                    "action": "ISOLATE_CONNECTION",
                    "detail": f"Remove direct link to {peer.hostname} ({rip}) "
                              f"[{peer.risk_zone} risk node] — consider firewall rule",
                    "priority": "MEDIUM",
                })
                projected_score *= 0.85

        if actions:
            recs.append({
                "node":            node.ip,
                "hostname":        node.hostname,
                "device_type":     node.device_type,
                "current_score":   round(node.vulnerability_score, 3),
                "current_zone":    node.risk_zone,
                "projected_score": round(projected_score, 3),
                "projected_zone":  assign_risk_zone(projected_score),
                "risk_reduction":  round((node.vulnerability_score - projected_score) / node.vulnerability_score * 100, 1),
                "actions":         actions,
            })

    return sorted(recs, key=lambda x: x["current_score"], reverse=True)


def _topology_plan(nodes, cluster_labels, cluster_risk, ips) -> List[str]:
    """
    High-level topology redesign suggestions based on clustering results.
    """
    plan = []
    sorted_clusters = sorted(cluster_risk.items(), key=lambda x: x[1], reverse=True)

    plan.append("=== ML-GENERATED TOPOLOGY REDESIGN PLAN ===")
    plan.append("")
    plan.append(f"The ML model identified {len(sorted_clusters)} natural security segments.")
    plan.append("")

    for rank, (cid, risk) in enumerate(sorted_clusters, 1):
        c_ips = [ips[i] for i, l in enumerate(cluster_labels) if l == cid]
        node_map = {n.ip: n for n in nodes if n.ip in c_ips}
        level = "DMZ / Isolated" if risk > 0.6 else ("Restricted" if risk > 0.4 else "Trusted")
        plan.append(f"Segment {rank} (Cluster {cid}) → Avg Risk {risk:.0%} → Recommended Zone: {level}")
        plan.append(f"  Nodes ({len(c_ips)}): {', '.join(c_ips[:5])}{'...' if len(c_ips)>5 else ''}")

        if risk > 0.6:
            plan.append("  ► Place behind dedicated firewall with strict ingress/egress rules")
            plan.append("  ► Enable IDS/IPS on all traffic to this segment")
            plan.append("  ► Enforce MFA for all access")
        elif risk > 0.4:
            plan.append("  ► Apply least-privilege access control")
            plan.append("  ► Segment from TRUSTED zone with ACLs")
        else:
            plan.append("  ► Standard monitoring; enforce patch policy")
        plan.append("")

    plan.append("General recommendations:")
    plan.append("  • Add a dedicated DMZ VLAN for all internet-facing services")
    plan.append("  • Isolate IoT devices on a separate VLAN with no lateral access")
    plan.append("  • Place all databases on an isolated backend VLAN")
    plan.append("  • Use Zero-Trust micro-segmentation between all segments")
    plan.append("  • Deploy honeypots at VLAN boundaries to detect lateral movement")

    return plan
