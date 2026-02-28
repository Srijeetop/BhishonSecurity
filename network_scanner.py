"""
network_scanner.py
------------------
Handles network discovery and port/service scanning using.
"""

import socket
import random
import ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Optional


# ── Common service fingerprints ──────────────────────────────────────────────
SERVICE_DB: Dict[int, Dict] = {
    21:   {"name": "FTP",        "risk_base": 0.85, "cve_ids": ["CVE-2011-2523", "CVE-2020-9054"]},
    22:   {"name": "SSH",        "risk_base": 0.35, "cve_ids": ["CVE-2018-15473", "CVE-2023-38408"]},
    23:   {"name": "Telnet",     "risk_base": 0.95, "cve_ids": ["CVE-2020-10188"]},
    25:   {"name": "SMTP",       "risk_base": 0.60, "cve_ids": ["CVE-2020-7247"]},
    53:   {"name": "DNS",        "risk_base": 0.50, "cve_ids": ["CVE-2020-1350"]},
    80:   {"name": "HTTP",       "risk_base": 0.55, "cve_ids": ["CVE-2021-41773", "CVE-2022-22947"]},
    110:  {"name": "POP3",       "risk_base": 0.65, "cve_ids": ["CVE-2003-0965"]},
    135:  {"name": "MS-RPC",     "risk_base": 0.80, "cve_ids": ["CVE-2003-0352", "CVE-2017-0144"]},
    139:  {"name": "NetBIOS",    "risk_base": 0.75, "cve_ids": ["CVE-2017-0145", "CVE-2020-0796"]},
    143:  {"name": "IMAP",       "risk_base": 0.60, "cve_ids": ["CVE-2021-38371"]},
    443:  {"name": "HTTPS",      "risk_base": 0.30, "cve_ids": ["CVE-2021-3449"]},
    445:  {"name": "SMB",        "risk_base": 0.90, "cve_ids": ["CVE-2017-0144", "CVE-2020-0796"]},
    1433: {"name": "MSSQL",      "risk_base": 0.75, "cve_ids": ["CVE-2020-0618"]},
    1521: {"name": "Oracle DB",  "risk_base": 0.70, "cve_ids": ["CVE-2012-3137"]},
    3306: {"name": "MySQL",      "risk_base": 0.65, "cve_ids": ["CVE-2012-2122", "CVE-2021-2307"]},
    3389: {"name": "RDP",        "risk_base": 0.85, "cve_ids": ["CVE-2019-0708", "CVE-2020-0609"]},
    5900: {"name": "VNC",        "risk_base": 0.80, "cve_ids": ["CVE-2019-15681"]},
    6379: {"name": "Redis",      "risk_base": 0.80, "cve_ids": ["CVE-2022-0543"]},
    8080: {"name": "HTTP-Alt",   "risk_base": 0.55, "cve_ids": ["CVE-2020-11996"]},
    8443: {"name": "HTTPS-Alt",  "risk_base": 0.35, "cve_ids": []},
    27017:{"name": "MongoDB",    "risk_base": 0.78, "cve_ids": ["CVE-2019-2389"]},
}

DEVICE_TYPES = [
    "Workstation", "Server", "Router", "Switch", "Firewall",
    "Printer", "IoT Device", "Database Server", "Web Server", "NAS"
]

OS_TYPES = [
    "Windows 10", "Windows Server 2019", "Ubuntu 20.04", "CentOS 7",
    "Debian 11", "macOS 12", "Unknown Linux", "Cisco IOS", "FreeNAS"
]


@dataclass
class ScannedPort:
    port: int
    service: str
    state: str           # open / filtered / closed
    risk_base: float
    cve_ids: List[str]


@dataclass
class NetworkNode:
    ip: str
    hostname: str
    mac: str
    device_type: str
    os: str
    open_ports: List[ScannedPort] = field(default_factory=list)
    vulnerability_score: float = 0.0   # 0-1
    risk_zone: str = "LOW"             # LOW / MEDIUM / HIGH / CRITICAL
    connections: List[str] = field(default_factory=list)  # list of IPs
    is_gateway: bool = False
    vlan: int = 1


# ── Helpers ──────────────────────────────────────────────────────────────────

def _random_mac() -> str:
    return ":".join(f"{random.randint(0,255):02X}" for _ in range(6))


def _random_hostname(device_type: str, idx: int) -> str:
    prefix = device_type.replace(" ", "-").upper()
    return f"{prefix}-{idx:03d}"


def simulate_network(
    subnet: str = "192.168.1.0/24",
    node_count: int = 20,
    seed: int = 42
) -> List[NetworkNode]:
    """
    Simulate a realistic office network scan.
    Replace this function with real nmap calls in production:

        import nmap
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments='-sV -O --script vuln')
    """
    random.seed(seed)
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = list(net.hosts())
    nodes: List[NetworkNode] = []

    # always place a router/firewall at .1
    gateway_ip = str(hosts[0])

    for i in range(min(node_count, len(hosts))):
        ip = str(hosts[i])
        dtype = "Router" if i == 0 else random.choice(DEVICE_TYPES)
        os    = random.choice(OS_TYPES)
        node  = NetworkNode(
            ip          = ip,
            hostname    = _random_hostname(dtype, i + 1),
            mac         = _random_mac(),
            device_type = dtype,
            os          = os,
            is_gateway  = (i == 0),
            vlan        = random.choice([1, 10, 20, 30]),
        )

        # ── Assign open ports based on device type ──────────────────────────
        port_pool = _port_pool_for_device(dtype)
        chosen_ports = random.sample(port_pool, k=min(random.randint(1, 6), len(port_pool)))
        for p in chosen_ports:
            svc = SERVICE_DB.get(p, {"name": f"unknown-{p}", "risk_base": 0.4, "cve_ids": []})
            state = random.choices(["open", "filtered"], weights=[0.75, 0.25])[0]
            node.open_ports.append(ScannedPort(
                port      = p,
                service   = svc["name"],
                state     = state,
                risk_base = svc["risk_base"],
                cve_ids   = svc["cve_ids"]
            ))

        # ── Connections (random mesh with gateway always connected) ─────────
        node.connections.append(gateway_ip)
        if i > 1:
            peers = random.sample(
                [str(hosts[j]) for j in range(1, i) if j != i],
                k=min(random.randint(1, 3), i - 1)
            )
            node.connections.extend(peers)
        node.connections = list(set(node.connections))  # deduplicate

        nodes.append(node)

    return nodes


def _port_pool_for_device(dtype: str) -> List[int]:
    all_ports = list(SERVICE_DB.keys())
    pools = {
        "Workstation":     [22, 80, 139, 443, 445, 3389],
        "Server":          [22, 25, 80, 443, 8080, 8443, 3389, 135, 139, 445],
        "Router":          [22, 23, 80, 443, 53],
        "Switch":          [22, 23, 80],
        "Firewall":        [22, 443],
        "Printer":         [80, 443, 9100],
        "IoT Device":      [80, 443, 5900, 23],
        "Database Server": [3306, 1433, 1521, 27017, 6379, 22],
        "Web Server":      [80, 443, 22, 8080, 8443],
        "NAS":             [22, 80, 443, 139, 445, 21],
    }
    return pools.get(dtype, all_ports)

def real_scan(subnet: str = "192.168.1.0/24") -> list:
    """
    Performs a REAL network scan using nmap.
    On Windows, run Command Prompt as Administrator.
    
    """
    import nmap

    print(f"  [SCAN] Starting real nmap scan on {subnet}...")
    print(f"  [SCAN] This may take 2-5 minutes depending on network size...")

    nm = nmap.PortScanner()

    # -sV = detect service versions
    # -O  = detect OS (requires root/admin)
    # --open = only show open ports
    # -T4 = faster timing
    nm.scan(
        hosts=subnet,
        arguments='-sV -O -T4 --script=banner'
    )

    nodes = []
    idx   = 0

    for ip in nm.all_hosts():
        host = nm[ip]
        if host.state() != 'up':
            continue

        idx += 1

        # Detect device type from OS info
        os_guess = "Unknown"
        dtype    = "Workstation"
        os_matches = host.get('osmatch', [])
        if os_matches:
            os_guess = os_matches[0].get('name', 'Unknown')
            os_lower = os_guess.lower()
            if any(x in os_lower for x in ['router', 'cisco', 'juniper']):
                dtype = "Router"
            elif any(x in os_lower for x in ['windows server', 'ubuntu server']):
                dtype = "Server"
            elif 'printer' in os_lower:
                dtype = "Printer"
            elif any(x in os_lower for x in ['android', 'embedded', 'linux 2.']):
                dtype = "IoT Device"

        # Get hostname
        try:
            hostname = nm[ip].hostname() or f"HOST-{idx:03d}"
        except Exception:
            hostname = f"HOST-{idx:03d}"

        node = NetworkNode(
            ip          = ip,
            hostname    = hostname,
            mac         = host['addresses'].get('mac', '??:??:??:??:??:??'),
            device_type = dtype,
            os          = os_guess,
            is_gateway  = (idx == 1),
            vlan        = 1,  # Real VLAN detection needs SNMP — set manually
        )

        # Scan open ports
        for proto in host.all_protocols():
            for port in host[proto].keys():
                port_info = host[proto][port]
                if port_info['state'] != 'open':
                    continue
                svc_info = SERVICE_DB.get(port, {
                    'name':     port_info.get('name', f'unknown-{port}'),
                    'risk_base': 0.40,
                    'cve_ids':  []
                })
                node.open_ports.append(ScannedPort(
                    port      = port,
                    service   = svc_info['name'],
                    state     = 'open',
                    risk_base = svc_info['risk_base'],
                    cve_ids   = svc_info['cve_ids'],
                ))

        # Build connections from nmap trace (simplified: all connect to gateway)
        node.connections = [list(nm.all_hosts())[0]] if idx > 1 else []

        nodes.append(node)
        print(f"  [SCAN] Found: {ip} ({hostname}) — {len(node.open_ports)} open ports")

    print(f"  [SCAN] Complete. Found {len(nodes)} live hosts.")
    return nodes