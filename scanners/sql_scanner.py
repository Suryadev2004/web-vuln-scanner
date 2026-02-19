import requests

def check_sql_injection(url):
    findings = []

    sql_payload = "' OR '1'='1"
    test_url = url + sql_payload

    sql_errors = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sqlite error"
    ]

    try:
        response = requests.get(test_url)

        for error in sql_errors:
            if error in response.text.lower():
                findings.append("[HIGH] Possible SQL Injection vulnerability detected!")
                break
        else:
            findings.append("[OK] No obvious SQL Injection detected.")

    except requests.exceptions.RequestException as e:
        findings.append(f"[ERROR] SQL test failed: {e}")

    return findings

