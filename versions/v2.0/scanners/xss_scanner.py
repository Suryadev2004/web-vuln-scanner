import requests

def check_xss(url):
    findings = []

    if "?" not in url:
        return ["[INFO] No query parameters found. Skipping XSS test."]

    payload = "<script>alert(1)</script>"
    test_url = url + payload

    try:
        response = requests.get(test_url)

        if payload in response.text:
            findings.append("[MEDIUM] Possible Reflected XSS vulnerability detected!")
        else:
            findings.append("[OK] No obvious reflected XSS detected.")

    except requests.exceptions.RequestException as e:
        findings.append(f"[ERROR] XSS test failed: {e}")

    return findings