import ast
from datetime import datetime
from collections import defaultdict

# ── LOAD DATA ─────────────────────────────────────────────────────────────────

with open('networkdata.txt', 'r') as f:
    raw = f.read()

parts = [p.strip() for p in raw.strip().split('\n\n') if p.strip()]
subnet1     = ast.literal_eval(parts[0])
subnet2_raw = ast.literal_eval(parts[1])
all_devices = subnet1 + subnet2_raw

# ── CVE METADATA ──────────────────────────────────────────────────────────────

CVE_INFO = {
    'CVE-2003-0352': {'name': 'DCOM RPC Buffer Overflow',         'cvss': 7.5,  'severity': 'HIGH',     'desc': 'Remote code execution via malformed RPC request targeting DCOM interface.'},
    'CVE-2017-0144': {'name': 'EternalBlue (MS17-010)',            'cvss': 9.3,  'severity': 'CRITICAL', 'desc': 'Critical SMBv1 RCE exploited by WannaCry and NotPetya ransomware.'},
    'CVE-2017-0145': {'name': 'EternalRomance (MS17-010)',         'cvss': 9.3,  'severity': 'CRITICAL', 'desc': 'SMBv1 RCE vulnerability, part of the Shadow Brokers NSA leak.'},
    'CVE-2020-0796': {'name': 'SMBGhost (CoronaBlue)',             'cvss': 10.0, 'severity': 'CRITICAL', 'desc': 'Wormable RCE in SMBv3 compression. No authentication required.'},
    'CVE-2019-0708': {'name': 'BlueKeep (RDP RCE)',                'cvss': 9.8,  'severity': 'CRITICAL', 'desc': 'Pre-auth RCE in RDP, wormable. Affects Windows 7/Server 2008.'},
    'CVE-2020-0609': {'name': 'RD Gateway RCE',                   'cvss': 9.8,  'severity': 'CRITICAL', 'desc': 'Pre-authentication RCE in Windows Remote Desktop Gateway.'},
    'CVE-2018-15473': {'name': 'OpenSSH User Enumeration',        'cvss': 5.3,  'severity': 'MEDIUM',   'desc': 'Allows attackers to enumerate valid usernames via timing differences.'},
    'CVE-2023-38408': {'name': 'OpenSSH ssh-agent RCE',           'cvss': 9.8,  'severity': 'CRITICAL', 'desc': 'Remote code execution via forwarded ssh-agent.'},
    'CVE-2020-10188': {'name': 'Telnet Remote Code Execution',    'cvss': 9.8,  'severity': 'CRITICAL', 'desc': 'RCE in telnetd. Telnet is also plaintext — credentials fully exposed.'},
    'CVE-2021-41773': {'name': 'Apache Path Traversal/RCE',       'cvss': 9.8,  'severity': 'CRITICAL', 'desc': 'Path traversal and RCE in Apache 2.4.49. Actively exploited in the wild.'},
    'CVE-2022-22947': {'name': 'Spring Cloud Gateway SPEL RCE',   'cvss': 10.0, 'severity': 'CRITICAL', 'desc': 'Unauth code injection via Spring Expression Language in Spring Gateway.'},
    'CVE-2021-3449':  {'name': 'OpenSSL NULL Pointer DoS',        'cvss': 5.9,  'severity': 'MEDIUM',   'desc': 'NULL pointer dereference in OpenSSL causing service denial.'},
    'CVE-2012-2122': {'name': 'MySQL Auth Bypass',                'cvss': 5.1,  'severity': 'MEDIUM',   'desc': 'Authentication bypass in MySQL — repeated connection attempts may grant root.'},
    'CVE-2021-2307': {'name': 'MySQL Local File Read',            'cvss': 6.1,  'severity': 'MEDIUM',   'desc': 'Allows reading arbitrary files from server via MySQL client.'},
    'CVE-2020-11996': {'name': 'Apache Tomcat HTTP/2 DoS',        'cvss': 7.5,  'severity': 'HIGH',     'desc': 'HTTP/2 request storm causes denial of service in Apache Tomcat.'},
}

# ── SCORING ───────────────────────────────────────────────────────────────────

def compute_score(device):
    ports = device.get('open_ports', [])
    if not ports:
        return 0.0
    max_risk  = max(p['risk_base'] for p in ports)
    num_cves  = sum(len(p['cve_ids']) for p in ports)
    score     = max_risk * 0.6 + min(num_cves * 0.05, 0.4)
    return round(score, 3)

def risk_zone(score):
    if score >= 0.7:   return 'CRITICAL'
    elif score >= 0.5: return 'HIGH'
    elif score >= 0.3: return 'MEDIUM'
    elif score > 0.0:  return 'LOW'
    else:              return 'SAFE'

for d in all_devices:
    d['vulnerability_score'] = compute_score(d)
    d['risk_zone']           = risk_zone(d['vulnerability_score'])

# Identify gateways
gateways = [d for d in all_devices if d['is_gateway']]
gw1 = next(d for d in subnet1     if d['is_gateway'])
gw2 = next(d for d in subnet2_raw if d['is_gateway'])

# ── HELPERS ───────────────────────────────────────────────────────────────────

def bar(score, width=30):
    filled = int(score * width)
    return '[' + '█' * filled + '░' * (width - filled) + f'] {score:.3f}'

def section(title, char='═'):
    line = char * 80
    return f"\n{line}\n  {title}\n{line}\n"

def subsection(title):
    return f"\n  {'─' * 76}\n  {title}\n  {'─' * 76}\n"

ZONE_BADGE = {
    'CRITICAL': '🔴 CRITICAL',
    'HIGH':     '🟠 HIGH    ',
    'MEDIUM':   '🟡 MEDIUM  ',
    'LOW':      '🟢 LOW     ',
    'SAFE':     '✅ SAFE    ',
}

# ── REPORT BUILDER ────────────────────────────────────────────────────────────

lines = []
W = lines.append

def rule(char='═', n=80): W(char * n)
def blank(): W('')

# ══════════════════════════════════════════════════════════════════════════════
# HEADER
# ══════════════════════════════════════════════════════════════════════════════
rule()
W('  NETWORK VULNERABILITY ASSESSMENT REPORT')
W(f'  Generated : {datetime.now().strftime("%Y-%m-%d  %H:%M:%S")}')
W(f'  Scope     : {len(all_devices)} devices across 2 subnets')
W(f'  Subnets   : 192.168.137.x  ←→  192.168.40.x')
rule()

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — EXECUTIVE SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
W(section('SECTION 1 — EXECUTIVE SUMMARY'))

zone_counts = defaultdict(int)
for d in all_devices:
    zone_counts[d['risk_zone']] += 1

total       = len(all_devices)
avg_score   = sum(d['vulnerability_score'] for d in all_devices) / total
max_device  = max(all_devices, key=lambda d: d['vulnerability_score'])
all_cves    = set()
for d in all_devices:
    for p in d.get('open_ports', []):
        all_cves.update(p['cve_ids'])

W(f"  Total Devices Scanned    : {total}")
W(f"  Average Vulnerability    : {bar(avg_score)}")
W(f"  Unique CVEs Identified   : {len(all_cves)}")
W(f"  Highest Risk Device      : {max_device['hostname']} ({max_device['ip']}) — Score {max_device['vulnerability_score']:.3f}")
blank()
W("  Risk Zone Distribution:")
for zone in ['CRITICAL','HIGH','MEDIUM','LOW','SAFE']:
    count = zone_counts[zone]
    pct   = count / total * 100
    W(f"    {ZONE_BADGE[zone]}  {count:>3} devices  ({pct:5.1f}%)")

blank()
# Network-wide threat narrative
critical_devices = [d for d in all_devices if d['risk_zone'] == 'CRITICAL']
high_devices     = [d for d in all_devices if d['risk_zone'] == 'HIGH']

W("  Threat Narrative:")
W("  " + "─"*76)
narrative = f"""  This network of {total} devices presents a mixed security posture. The most
  severe finding is the IoT gateway HOST-001 (192.168.40.1) acting as the
  default gateway for 47 client devices while running Telnet (port 23) —
  a plaintext protocol with a CVSS 9.8 RCE vulnerability (CVE-2020-10188).
  Any attacker gaining a foothold on this gateway has lateral access to the
  entire 192.168.40.x subnet.

  Multiple workstations expose the SMBv1/v3 attack surface (EternalBlue,
  SMBGhost) and RDP (BlueKeep), vulnerabilities weaponised in real-world
  ransomware campaigns (WannaCry, NotPetya). The inter-subnet link between
  LAPTOP-12CUK0D7 and HOST-001 creates a pivot path from Subnet 1 into
  Subnet 2, amplifying blast radius significantly.

  Immediate remediation priority: disable Telnet on HOST-001, patch all
  SMBv1 endpoints, and restrict RDP to authorised IPs only."""
W(narrative)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — Gateway OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════
W(section('SECTION 2 — GateWay OVERVIEW'))

for subnet_label, subnet, gw in [
    ('Gateway 1  —  192.168.137.1', subnet1, gw1),
    ('Gateway 2  —  192.168.40.1',  subnet2_raw, gw2),
]:
    W(subsection(subnet_label))
    W(f"  Gateway   : {gw['hostname']}  ({gw['ip']})  MAC: {gw['mac']}")
    W(f"  OS        : {gw['os']}")
    W(f"  Device Type: {gw['device_type']}")
    W(f"  Devices   : {len(subnet)}")
    s_scores = [d['vulnerability_score'] for d in subnet]
    W(f"  Avg Score : {bar(sum(s_scores)/len(s_scores))}")
    W(f"  Max Score : {max(s_scores):.3f}  |  Min Score : {min(s_scores):.3f}")
    blank()
    W(f"  {'Hostname':<22} {'IP':<18} {'Zone':<10} {'Score':<8} {'Open Ports'}")
    W(f"  {'─'*22} {'─'*18} {'─'*10} {'─'*8} {'─'*20}")
    for d in sorted(subnet, key=lambda x: -x['vulnerability_score']):
        ports_str = ', '.join(str(p['port']) for p in d.get('open_ports', [])) or 'None'
        W(f"  {d['hostname']:<22} {d['ip']:<18} {d['risk_zone']:<10} {d['vulnerability_score']:<8.3f} {ports_str}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — DEVICE-BY-DEVICE ANALYSIS (non-SAFE only, full detail)
# ══════════════════════════════════════════════════════════════════════════════
W(section('SECTION 3 — DETAILED DEVICE ANALYSIS'))
W("  Devices with open ports are analysed below, sorted by risk score (desc).\n")

analysed = [d for d in all_devices if d.get('open_ports')]
analysed.sort(key=lambda d: -d['vulnerability_score'])

for idx, d in enumerate(analysed, 1):
    W(f"  [{idx:02d}] {d['hostname']}  —  {d['ip']}")
    W(f"       MAC          : {d['mac']}")
    W(f"       OS           : {d['os']}")
    W(f"       Device Type  : {d['device_type']}")
    W(f"       Subnet       : {'192.168.137.x' if d['ip'].startswith('192.168.137') else '192.168.40.x'}")
    W(f"       Gateway Role : {'YES' if d['is_gateway'] else 'No'}")
    W(f"       Risk Zone    : {ZONE_BADGE[d['risk_zone']]}")
    W(f"       Vuln Score   : {bar(d['vulnerability_score'])}")
    blank()
    W(f"       Open Ports & Services:")
    W(f"       {'Port':<8} {'Service':<18} {'Risk Base':<12} {'CVEs'}")
    W(f"       {'─'*8} {'─'*18} {'─'*12} {'─'*30}")
    for p in sorted(d['open_ports'], key=lambda x: -x['risk_base']):
        cve_str = ', '.join(p['cve_ids']) if p['cve_ids'] else 'None'
        W(f"       {p['port']:<8} {p['service']:<18} {p['risk_base']:<12.2f} {cve_str}")

    # CVE deep-dive
    device_cves = []
    for p in d['open_ports']:
        for cve_id in p['cve_ids']:
            if cve_id not in [c[0] for c in device_cves]:
                device_cves.append((cve_id, p['service']))
    if device_cves:
        blank()
        W(f"       CVE Details:")
        for cve_id, svc in device_cves:
            info = CVE_INFO.get(cve_id, {})
            W(f"       ▸ {cve_id}  [{info.get('severity','?')}  CVSS {info.get('cvss','?')}]")
            W(f"         Name    : {info.get('name', 'Unknown')}")
            W(f"         Service : {svc}")
            W(f"         Impact  : {info.get('desc', 'No description available.')}")

    # Attack vector analysis
    blank()
    W(f"       Attack Vector Analysis:")
    has_smb  = any(p['service'] in ('SMB','NetBIOS','MS-RPC') for p in d['open_ports'])
    has_rdp  = any(p['service'] == 'RDP'    for p in d['open_ports'])
    has_tel  = any(p['service'] == 'Telnet' for p in d['open_ports'])
    has_db   = any(p['service'] == 'MySQL'  for p in d['open_ports'])
    has_http = any(p['service'] in ('HTTP','HTTP-Alt','http') for p in d['open_ports'])
    if has_smb:  W("       ⚠  SMB exposed — EternalBlue/SMBGhost lateral movement risk")
    if has_rdp:  W("       ⚠  RDP exposed — BlueKeep RCE / brute-force / credential spray risk")
    if has_tel:  W("       🚨 Telnet active — plaintext protocol, trivial credential interception")
    if has_db:   W("       ⚠  MySQL exposed — auth bypass, data exfiltration risk")
    if has_http: W("       ⚠  HTTP exposed — path traversal / web exploitation risk")
    if d['is_gateway']:
        W("       🚨 GATEWAY NODE — compromise grants access to all downstream devices")

    blank()
    W("       Remediation:")
    if has_tel:  W("       → URGENT: Disable Telnet immediately. Replace with SSH.")
    if has_smb:  W("       → Disable SMBv1. Apply MS17-010 patch. Restrict SMB to required hosts only.")
    if has_rdp:  W("       → Restrict RDP via firewall to known IPs. Enable NLA. Patch BlueKeep.")
    if has_db:   W("       → Bind MySQL to localhost or restrict to app server IPs. Update to latest.")
    if has_http: W("       → Update web server. Apply WAF rules. Patch path traversal CVEs.")
    W(f"  {'═'*76}")
    blank()

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — CVE SUMMARY TABLE
# ══════════════════════════════════════════════════════════════════════════════
W(section('SECTION 4 — CVE EXPOSURE SUMMARY'))

# Count affected devices per CVE
cve_device_map = defaultdict(list)
for d in all_devices:
    for p in d.get('open_ports', []):
        for cve_id in p['cve_ids']:
            cve_device_map[cve_id].append(d['hostname'])

W(f"  {'CVE ID':<20} {'Severity':<10} {'CVSS':<6} {'Affected':<10} {'Name'}")
W(f"  {'─'*20} {'─'*10} {'─'*6} {'─'*10} {'─'*36}")

for cve_id, hosts in sorted(cve_device_map.items(),
                             key=lambda x: -CVE_INFO.get(x[0], {}).get('cvss', 0)):
    info = CVE_INFO.get(cve_id, {})
    W(f"  {cve_id:<20} {info.get('severity','?'):<10} {str(info.get('cvss','?')):<6} {len(hosts):<10} {info.get('name','Unknown')}")

blank()
W("  Most Widespread CVEs (by device count):")
for cve_id, hosts in sorted(cve_device_map.items(), key=lambda x: -len(x[1]))[:5]:
    info = CVE_INFO.get(cve_id, {})
    W(f"    {cve_id}  —  {len(hosts)} devices  [{info.get('severity','?')} / CVSS {info.get('cvss','?')}]")
    W(f"      Affected: {', '.join(sorted(set(hosts)))}")
    blank()

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — NETWORK TOPOLOGY RISK
# ══════════════════════════════════════════════════════════════════════════════
W(section('SECTION 5 — NETWORK TOPOLOGY & ATTACK PATH ANALYSIS'))

W("  Inter-Subnet Link:")
W(f"    {gw1['hostname']} ({gw1['ip']})  ←→  {gw2['hostname']} ({gw2['ip']})")
W(f"    This link bridges Subnet 1 and Subnet 2. Compromise of either gateway")
W(f"    enables pivot attacks across both subnets.")
blank()

W("  Critical Attack Paths:")
blank()
W("  PATH 1 — Internet → HOST-001 (via Telnet/HTTP/SSH)")
W("  ┌─────────────────────────────────────────────────────────────────────┐")
W("  │  Attacker  →  PORT 23 (Telnet/CVE-2020-10188)  →  HOST-001 ROOT   │")
W("  │  HOST-001 is gateway to 47 devices. Full subnet compromise.        │")
W("  └─────────────────────────────────────────────────────────────────────┘")
blank()
W("  PATH 2 — HOST-001 → Windows Workstations (SMB Lateral Movement)")
W("  ┌─────────────────────────────────────────────────────────────────────┐")
W("  │  HOST-001  →  EternalBlue (CVE-2017-0144)  →  HOST-002/005/015/   │")
W("  │               HOST-018/023/034/040 etc.  (SMBv1 hosts)            │")
W("  │  Ransomware deployment / data exfiltration possible.               │")
W("  └─────────────────────────────────────────────────────────────────────┘")
blank()
W("  PATH 3 — Subnet 2 → Subnet 1 (Gateway Pivot)")
W("  ┌─────────────────────────────────────────────────────────────────────┐")
W("  │  HOST-001  →  inter-subnet link  →  LAPTOP-12CUK0D7  →  Srijeet   │")
W("  │  Subnet 1 devices exposed if Subnet 2 gateway is compromised.      │")
W("  └─────────────────────────────────────────────────────────────────────┘")
blank()
W("  PATH 4 — RDP Brute Force / BlueKeep")
W("  ┌─────────────────────────────────────────────────────────────────────┐")
W("  │  Attacker  →  PORT 3389  →  HOST-018/030/040 (CVE-2019-0708)      │")
W("  │  Pre-auth wormable RCE. No credentials needed.                     │")
W("  └─────────────────────────────────────────────────────────────────────┘")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — SERVICE EXPOSURE STATISTICS
# ══════════════════════════════════════════════════════════════════════════════
W(section('SECTION 6 — SERVICE EXPOSURE STATISTICS'))

service_count = defaultdict(int)
service_risk  = defaultdict(list)
for d in all_devices:
    for p in d.get('open_ports', []):
        service_count[p['service']] += 1
        service_risk[p['service']].append(p['risk_base'])

W(f"  {'Service':<20} {'Exposed On':<12} {'Avg Risk':<12} {'Max Risk'}")
W(f"  {'─'*20} {'─'*12} {'─'*12} {'─'*10}")
for svc, count in sorted(service_count.items(), key=lambda x: -x[1]):
    risks   = service_risk[svc]
    avg_r   = sum(risks) / len(risks)
    max_r   = max(risks)
    W(f"  {svc:<20} {count:<12} {avg_r:<12.2f} {max_r:.2f}")

blank()
W("  Devices with NO open ports (minimal attack surface):")
safe_devices = [d for d in all_devices if not d.get('open_ports')]
for d in safe_devices:
    W(f"    ✅  {d['hostname']:<22}  {d['ip']}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — OS LANDSCAPE
# ══════════════════════════════════════════════════════════════════════════════
W(section('SECTION 7 — OPERATING SYSTEM LANDSCAPE'))

os_count = defaultdict(int)
for d in all_devices:
    os_count[d['os']] += 1

W(f"  {'Operating System':<45} {'Count':<8} {'% of Fleet'}")
W(f"  {'─'*45} {'─'*8} {'─'*10}")
for os_name, count in sorted(os_count.items(), key=lambda x: -x[1]):
    W(f"  {os_name:<45} {count:<8} {count/total*100:.1f}%")

blank()
unknown = os_count.get('Unknown', 0)
W(f"  ⚠  {unknown} devices have unknown OS — fingerprinting failed or OS hardened.")
W(f"     Recommend manual inspection or authenticated scans on these hosts.")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — PRIORITISED REMEDIATION PLAN
# ══════════════════════════════════════════════════════════════════════════════
W(section('SECTION 8 — PRIORITISED REMEDIATION PLAN'))

W("  PRIORITY 1 — IMMEDIATE (Within 24 hours)")
W("  " + "─"*76)
W("  ▸ Disable Telnet (port 23) on HOST-001 (192.168.40.1)")
W("    Replace with SSH. CVE-2020-10188 CVSS 9.8. Gateway-level risk.")
W("  ▸ Patch or isolate all SMBv1-enabled hosts (EternalBlue/SMBGhost):")
smb_hosts = [d for d in all_devices if any(p['service']=='SMB' for p in d.get('open_ports',[]))]
for d in smb_hosts:
    W(f"    → {d['hostname']} ({d['ip']})")
blank()
W("  PRIORITY 2 — SHORT TERM (Within 1 week)")
W("  " + "─"*76)
W("  ▸ Patch RDP BlueKeep (CVE-2019-0708) on all exposed hosts:")
rdp_hosts = [d for d in all_devices if any(p['service']=='RDP' for p in d.get('open_ports',[]))]
for d in rdp_hosts:
    W(f"    → {d['hostname']} ({d['ip']})")
W("  ▸ Enable Network Level Authentication (NLA) on all RDP endpoints.")
W("  ▸ Restrict RDP access via firewall to jump-host IPs only.")
blank()
W("  PRIORITY 3 — MEDIUM TERM (Within 1 month)")
W("  " + "─"*76)
W("  ▸ Update MySQL on all exposed hosts. Patch CVE-2012-2122 and CVE-2021-2307.")
W("  ▸ Bind MySQL to localhost unless remote access is explicitly required.")
W("  ▸ Conduct authenticated vulnerability scan to identify unknown OS devices.")
W("  ▸ Implement network segmentation — isolate IoT gateway from workstations.")
W("  ▸ Deploy IDS/IPS rules targeting EternalBlue and BlueKeep exploit signatures.")
blank()
W("  PRIORITY 4 — LONG TERM (Ongoing)")
W("  " + "─"*76)
W("  ▸ Implement Zero Trust architecture — deny all, permit by exception.")
W("  ▸ Regular vulnerability scanning (weekly automated + quarterly manual).")
W("  ▸ Enforce patch management policy with SLAs by severity.")
W("  ▸ Replace legacy OS versions (Windows 10 1511 — end of life).")
W("  ▸ MAC address audit — several devices show '??:??:??:??:??:??' (ARP spoofing risk).")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — ANOMALIES & SPECIAL FINDINGS
# ══════════════════════════════════════════════════════════════════════════════
W(section('SECTION 9 — ANOMALIES & SPECIAL FINDINGS'))

unknown_mac = [d for d in all_devices if d.get('mac','').startswith('??')]
W(f"  1. Unknown MAC Addresses ({len(unknown_mac)} devices)")
W(f"     Devices with unresolvable MACs may indicate ARP spoofing, stealth")
W(f"     mode, or VM/container interfaces. Investigate manually.")
for d in unknown_mac:
    W(f"     → {d['hostname']} ({d['ip']})")
blank()

iot_gw = [d for d in all_devices if d['device_type']=='IoT Device' and d['is_gateway']]
W(f"  2. IoT Device Acting as Network Gateway")
W(f"     HOST-001 is classified as an IoT Device yet serves as gateway for")
W(f"     47 workstations. IoT devices typically lack enterprise security")
W(f"     controls, logging, and patch support. This is a critical design flaw.")
blank()

legacy_os = [d for d in all_devices if '1511' in d.get('os','') or '1607' in d.get('os','')]
W(f"  3. End-of-Life Operating Systems ({len(legacy_os)} devices)")
for d in legacy_os:
    W(f"     → {d['hostname']} ({d['ip']}) — OS: {d['os']}")
W(f"     These OS versions no longer receive security patches from Microsoft.")
blank()

W(f"  4. Nessus Scanner Port (3001) Exposed")
nessus_hosts = [d for d in all_devices if any(p['port']==3001 for p in d.get('open_ports',[]))]
for d in nessus_hosts:
    W(f"     → {d['hostname']} ({d['ip']})")
W(f"     Port 3001 (Nessus) suggests vulnerability scanners are running on")
W(f"     workstations. Ensure scanner access is restricted and credentials secured.")

# ══════════════════════════════════════════════════════════════════════════════
# FOOTER
# ══════════════════════════════════════════════════════════════════════════════
blank()
rule()
W(f"  END OF REPORT  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Total Devices: {total}  |  CVEs Found: {len(all_cves)}")
rule()

# ── WRITE OUTPUT ──────────────────────────────────────────────────────────────

output = '\n'.join(lines)
with open('vulnerability_report.txt', 'w', encoding='utf-8') as f:
    f.write(output)

print(f"Report saved to vulnerability_report.txt  ({len(lines)} lines)")