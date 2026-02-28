# BhishonSecurity

> ML-powered network vulnerability scanner. Built in 24 hours.

---

BhishonSecurity scans your network, detects vulnerabilities, and uses machine learning to tell you what actually matters — ranked by real exploitability risk, not just CVSS scores.

**Scan → Detect → Prioritize → Report**

---

## Stack

| File | Role |
|---|---|
| `network_scanner.py` | Host discovery, port scanning, service fingerprinting |
| `vuln_engine.py` | CVE matching and risk scoring |
| `ml_optimizer.py` | ML-based threat prioritization |
| `visualizer.py` | Network topology and vulnerability graphs |
| `reporter.py` | Output reports (HTML / JSON) |

---

## Quickstart

```bash
git clone https://github.com/Srijeetop/BhishonSecurity.git
cd BhishonSecurity
pip install -r requirements.txt
python main.py --target 192.168.1.0/24
```

---

## Usage

```bash
# Basic scan
python main.py --target 10.0.0.1

# With ML prioritization
python main.py --target 10.0.0.1 --ml-optimize

# Generate HTML report
python main.py --target 10.0.0.1 --report --format html

# Visualize topology
python main.py --target 192.168.1.0/24 --visualize
```

---

## Sample Output

```
[*] Scanning 192.168.1.0/24
[+] 12 hosts discovered, 47 open ports
[!] 3 critical · 8 high · 14 medium
[~] Running ML optimizer...
[✓] Done in 42.3s → report_2024-02-28.html
```

---

## Disclaimer

For authorized use only. Only scan systems you own or have permission to test.

---

*Made by [@Srijeetop](https://github.com/Srijeetop)*
