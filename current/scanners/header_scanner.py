import requests

def check_headers(url):
    findings = []

    try:
        response = requests.get(url)
        headers = response.headers

        required_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security"
        ]

        for header in required_headers:
            if header not in headers:
                findings.append(f"[LOW] Missing Security Header: {header}")
            else:
                findings.append(f"[OK] {header} is present")

    except requests.exceptions.RequestException as e:
        findings.append(f"[ERROR] Could not connect: {e}")

    return findings
