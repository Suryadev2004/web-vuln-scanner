import requests
import time

TRUE_PAYLOAD = "' OR 1=1 -- "
FALSE_PAYLOAD = "' AND 1=2 -- "

THRESHOLD_PERCENT = 20

def percentage_difference(a, b):
    if a == 0:
        return 0
    return abs(a - b) / a * 100


def check_sql_injection(url):
    findings = []

    if "?" not in url:
        findings.append("[INFO] No query parameters found. Skipping SQL injection test.")
        return findings

    try:
        true_url = url + TRUE_PAYLOAD
        false_url = url + FALSE_PAYLOAD

        true_response = requests.get(true_url, timeout=5)
        false_response = requests.get(false_url, timeout=5)

        true_len = len(true_response.text)
        false_len = len(false_response.text)

        diff_percent = percentage_difference(true_len, false_len)

        if diff_percent > THRESHOLD_PERCENT:
            findings.append(
                f"[MEDIUM] Boolean-based Blind SQL Injection suspected at {url} (Diff: {diff_percent:.2f}%)"
            )
        else:
            findings.append("[OK] No obvious SQL Injection detected.")

    except Exception as e:
        findings.append(f"[ERROR] SQL test failed: {str(e)}")

    return findings