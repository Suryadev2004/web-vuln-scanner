import requests

def check_xss(url):
    findings = []

    xss_payload = "<script>alert(1)</script>"
    test_url = url + xss_payload

    try:
        response = requests.get(test_url)

        if xss_payload in response.text:
            findings.append("[MEDIUM] Possible Reflected XSS vulnerability detected!")
        else:
            findings.append("[OK] No obvious reflected XSS detected.")

    except requests.exceptions.RequestException as e:
        findings.append(f"[ERROR] XSS test failed: {e}")

    return findings
