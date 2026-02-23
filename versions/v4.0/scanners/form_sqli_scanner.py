import requests

TRUE_PAYLOAD = "' OR 1=1 -- "
FALSE_PAYLOAD = "' AND 1=2 -- "

THRESHOLD_PERCENT = 20


def percentage_difference(a, b):
    if a == 0:
        return 0
    return abs(a - b) / a * 100


def check_form_sql_injection(form):
    findings = []

    action = form["action"]
    method = form["method"]
    inputs = form["inputs"]

    if not inputs:
        return findings

    try:
        true_data = {name: TRUE_PAYLOAD for name in inputs}
        false_data = {name: FALSE_PAYLOAD for name in inputs}

        if method == "post":
            true_response = requests.post(action, data=true_data, timeout=5)
            false_response = requests.post(action, data=false_data, timeout=5)
        else:
            true_response = requests.get(action, params=true_data, timeout=5)
            false_response = requests.get(action, params=false_data, timeout=5)

        true_len = len(true_response.text)
        false_len = len(false_response.text)

        diff_percent = percentage_difference(true_len, false_len)

        if diff_percent > THRESHOLD_PERCENT:
            findings.append(
                f"[MEDIUM] Boolean-based Blind SQL Injection suspected in form at {action} (Diff: {diff_percent:.2f}%)"
            )
        else:
            findings.append(
                f"[OK] No obvious SQL Injection detected in form at {action}"
            )

    except Exception as e:
        findings.append(f"[ERROR] Form SQL test failed at {action}: {str(e)}")

    return findings