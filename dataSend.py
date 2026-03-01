import http.server
import socketserver
import os

def createFile(nodes):
    results = []
    for node in nodes:
        node_dict = {
            "ip": node.ip,
            "hostname": node.hostname,
            "mac": node.mac,
            "device_type": node.device_type,
            "os": node.os,
            "vulnerability_score": node.vulnerability_score,
            "risk_zone": node.risk_zone,
            "connections": node.connections,
            "is_gateway": node.is_gateway,
            "vlan": node.vlan,
            "open_ports": []
        }
        for p in node.open_ports:
            node_dict["open_ports"].append({
                "port": p.port,
                "service": p.service,
                "state": p.state,
                "risk_base": p.risk_base,
                "cve_ids": p.cve_ids
            })
        results.append(node_dict)

    with open("networkdata.txt", "a") as f:
        f.write(f"{results}\n\n")


def wrapper(nodes):
    createFile(nodes)

    PORT = 8080
    os.chdir("Folder path containing your file")  # folder containing your file not the file itself

    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"Serving on port {PORT}")
        print("Press Ctrl+C to stop")
        httpd.serve_forever()