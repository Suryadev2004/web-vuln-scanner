import socket
from urllib.parse import urlparse

def check_ports(url):
    findings = []

    parsed_url = urlparse(url)
    target_host = parsed_url.hostname

    if not target_host:
        findings.append("[ERROR] Invalid URL for port scanning.")
        return findings

    common_ports = [21, 22, 80, 443, 3306]

    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((target_host, port))

            if result == 0:
                findings.append(f"[INFO] Port {port} is OPEN")
            else:
                findings.append(f"[CLOSED] Port {port} is closed")

            sock.close()

        except Exception as e:
            findings.append(f"[ERROR] Port {port} scan failed: {e}")

    return findings
