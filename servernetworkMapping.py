import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.lines import Line2D
import numpy as np

# ── DATA ──────────────────────────────────────────────────────────────────────

import ast

with open('networkdata.txt', 'r') as f:
    raw = f.read()

# Split on blank line separating the two subnets
parts = [p.strip() for p in raw.strip().split('\n\n') if p.strip()]

subnet1     = ast.literal_eval(parts[0])
subnet2_raw = ast.literal_eval(parts[1])

# ── COMPUTE VULNERABILITY SCORES ──────────────────────────────────────────────

def compute_score(device):
    ports = device.get('open_ports', [])
    if not ports:
        return 0.0
    max_risk = max(p['risk_base'] for p in ports)
    num_cves = sum(len(p['cve_ids']) for p in ports)
    score = max_risk * 0.6 + min(num_cves * 0.05, 0.4)
    return round(score, 3)

def risk_zone(score):
    if score >= 0.7:   return 'CRITICAL'
    elif score >= 0.5: return 'HIGH'
    elif score >= 0.3: return 'MEDIUM'
    elif score > 0.0:  return 'LOW'
    else:              return 'SAFE'

for d in subnet1 + subnet2_raw:
    d['vulnerability_score'] = compute_score(d)
    d['risk_zone'] = risk_zone(d['vulnerability_score'])

# ── COLOUR MAP ─────────────────────────────────────────────────────────────────

ZONE_COLORS = {
    'SAFE':     '#3DDC97',   # mint green
    'LOW':      '#A8D5BA',   # pale green
    'MEDIUM':   '#F9C74F',   # amber
    'HIGH':     '#F3722C',   # orange
    'CRITICAL': '#E63946',   # crimson
}
GATEWAY_BORDER = '#FFFFFF'

def node_color(d):
    return ZONE_COLORS[d['risk_zone']]

# ── BUILD GRAPH ────────────────────────────────────────────────────────────────

G = nx.Graph()
all_devices = {}

for d in subnet1 + subnet2_raw:
    ip = d['ip']
    all_devices[ip] = d
    G.add_node(ip,
               label=d['hostname'],
               color=node_color(d),
               is_gateway=d['is_gateway'],
               score=d['vulnerability_score'],
               zone=d['risk_zone'],
               subnet='192.168.137' if ip.startswith('192.168.137') else '192.168.40')

# subnet1 internal edges
gw1 = '192.168.137.1'
for d in subnet1:
    if not d['is_gateway']:
        G.add_edge(gw1, d['ip'], edge_type='intra')

# cross-subnet edge (gateway of subnet1 → gateway of subnet2)
gw2 = '192.168.40.1'
G.add_edge(gw1, gw2, edge_type='inter')

# subnet2 internal edges
for d in subnet2_raw:
    if not d['is_gateway']:
        G.add_edge(gw2, d['ip'], edge_type='intra')

# ── LAYOUT ─────────────────────────────────────────────────────────────────────

# Manually place gateways; arrange clients in concentric rings
def ring_positions(center, nodes, radii_start=2.2, gap=1.8):
    positions = {}
    nodes = list(nodes)
    np.random.seed(42)
    np.random.shuffle(nodes)
    ring = 0
    idx = 0
    cx, cy = center
    while idx < len(nodes):
        r = radii_start + ring * gap
        capacity = max(6, int(2 * np.pi * r / 1.6))
        chunk = nodes[idx:idx+capacity]
        angles = np.linspace(0, 2*np.pi, len(chunk), endpoint=False)
        for node, angle in zip(chunk, angles):
            positions[node] = (cx + r*np.cos(angle), cy + r*np.sin(angle))
        idx += capacity
        ring += 1
    return positions

pos = {}
pos[gw1] = (0, 0)
pos[gw2] = (14, 0)

s1_clients = [d['ip'] for d in subnet1 if not d['is_gateway']]
s2_clients = [d['ip'] for d in subnet2_raw if not d['is_gateway']]

# Subnet 1 has only one client — place it explicitly to the LEFT of gw1
# so it doesn't block the inter-subnet path (gw1 → gw2 runs rightward along y=0)
s1_angles = np.linspace(np.pi / 2, 3 * np.pi / 2, max(len(s1_clients), 1), endpoint=False)
for client, angle in zip(s1_clients, s1_angles):
    r = 3.5
    pos[client] = (0 + r * np.cos(angle), 0 + r * np.sin(angle))
pos.update(ring_positions((14, 0), s2_clients, radii_start=2.2, gap=1.9))

# ── DRAW ───────────────────────────────────────────────────────────────────────

fig, ax = plt.subplots(figsize=(32, 22), facecolor='#0D1117')
ax.set_facecolor('#0D1117')
ax.set_aspect('equal')
ax.axis('off')

# Subtle subnet halos
from matplotlib.patches import Circle, FancyBboxPatch
halo1 = Circle((0,0),  5.5, color='#1E3A5F', alpha=0.18, zorder=0)
halo2 = Circle((14,0), 13.5, color='#1A3A2A', alpha=0.12, zorder=0)
ax.add_patch(halo1)
ax.add_patch(halo2)

# Subnet labels
ax.text(0,  -6.5,  '192.168.137.x\nSubnet 1', ha='center', va='top',
        fontsize=13, color='#5B9BD5', fontweight='bold', style='italic')
ax.text(14, -16.5, '192.168.40.x\nSubnet 2 (48 Devices)', ha='center', va='top',
        fontsize=13, color='#56A86B', fontweight='bold', style='italic')

# Edges
intra_edges = [(u,v) for u,v,d in G.edges(data=True) if d['edge_type']=='intra']
inter_edges = [(u,v) for u,v,d in G.edges(data=True) if d['edge_type']=='inter']

for u, v in intra_edges:
    # color the edge based on the non-gateway node's color
    client = v if not G.nodes[v]['is_gateway'] else u
    edge_col = G.nodes[client]['color']
    nx.draw_networkx_edges(G, pos, edgelist=[(u, v)], ax=ax,
                           edge_color=edge_col, width=0.8, alpha=0.6)
nx.draw_networkx_edges(G, pos, edgelist=inter_edges, ax=ax,
                       edge_color='#F59E0B', width=3.0, alpha=0.95,
                       style='dashed')

# Nodes
nodes_list = list(G.nodes())
colors     = [G.nodes[n]['color'] for n in nodes_list]
sizes      = [1400 if G.nodes[n]['is_gateway'] else 350 for n in nodes_list]
edgecolors = ['#FFD700' if G.nodes[n]['is_gateway'] else '#1E293B' for n in nodes_list]
linewidths = [3.5 if G.nodes[n]['is_gateway'] else 0.8 for n in nodes_list]

nx.draw_networkx_nodes(G, pos, nodelist=nodes_list, ax=ax,
                       node_color=colors, node_size=sizes,
                       edgecolors=edgecolors, linewidths=linewidths)

# Labels for ALL nodes
for node in nodes_list:
    d = G.nodes[node]
    x, y = pos[node]
    is_gw = d['is_gateway']
    offset = 0.65 if is_gw else 0.42
    label = f"{d['label']}\n{node}\nScore:{d['score']:.2f}"
    ax.text(x, y - offset, label, ha='center', va='top',
            fontsize=8 if is_gw else 5.5,
            color='#E2E8F0',
            fontweight='bold' if is_gw else 'normal',
            bbox=dict(boxstyle='round,pad=0.15', fc='#0D1117', alpha=0.72, ec='none'))

# Score badges on all nodes briefly (tiny dot to denote score class):
# (labels handled above for important nodes)

# ── LEGEND ─────────────────────────────────────────────────────────────────────

legend_patches = [
    mpatches.Patch(color=ZONE_COLORS['SAFE'],     label='SAFE   (score = 0.0)'),
    mpatches.Patch(color=ZONE_COLORS['LOW'],      label='LOW    (0 < score < 0.3)'),
    mpatches.Patch(color=ZONE_COLORS['MEDIUM'],   label='MEDIUM (0.3 – 0.5)'),
    mpatches.Patch(color=ZONE_COLORS['HIGH'],     label='HIGH   (0.5 – 0.7)'),
    mpatches.Patch(color=ZONE_COLORS['CRITICAL'], label='CRITICAL (≥ 0.7)'),
]
gateway_handle = Line2D([0],[0], marker='o', color='none', markerfacecolor='#888',
                        markeredgecolor='#FFD700', markeredgewidth=2.5,
                        markersize=11, label='Gateway node')
inter_handle   = Line2D([0],[0], color='#F59E0B', linewidth=2.5, linestyle='--',
                        label='Inter-subnet link')
intra_handle   = Line2D([0],[0], color='#334155', linewidth=1.5, label='Intra-subnet link')

legend = ax.legend(
    handles=legend_patches + [gateway_handle, inter_handle, intra_handle],
    loc='lower left', fontsize=9.5,
    facecolor='#161B22', edgecolor='#30363D',
    labelcolor='#C9D1D9', framealpha=0.95,
    title='Risk Zones & Legend', title_fontsize=10,
)
legend.get_title().set_color('#F0F6FF')

# ── TITLE ──────────────────────────────────────────────────────────────────────

ax.set_title('Enterprise Network Map — Vulnerability Risk Heat View',
             fontsize=20, color='#F0F6FF', fontweight='bold', pad=20,
             fontfamily='monospace')

# Score distribution summary box
zone_counts = {}
for n in nodes_list:
    z = G.nodes[n]['zone']
    zone_counts[z] = zone_counts.get(z, 0) + 1

summary_lines = ['Node Distribution:'] + [
    f"  {z}: {zone_counts.get(z,0)}" for z in ['SAFE','LOW','MEDIUM','HIGH','CRITICAL']
]
ax.text(0.99, 0.99, '\n'.join(summary_lines),
        transform=ax.transAxes, va='top', ha='right',
        fontsize=9, color='#8B949E',
        fontfamily='monospace',
        bbox=dict(boxstyle='round,pad=0.5', fc='#161B22', ec='#30363D', alpha=0.9))

plt.tight_layout()
plt.savefig('network_map.png', dpi=160,
            bbox_inches='tight', facecolor='#0D1117')
print("Saved.")