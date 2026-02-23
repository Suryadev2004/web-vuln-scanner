import requests

SQL_PAYLOAD = "' OR '1'='1"

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "syntax error"
]

def check_form_sql_injection(form):
    findings = []

    action = form.get("action")
    method = form.get("method", "GET").upper()
    inputs = form.get("inputs", [])

    if not action or not inputs:
        return findings

    for field in inputs:
        data = {}

        # Inject payload into ONE field only
        for input_name in inputs:
            if input_name == field:
                data[input_name] = SQL_PAYLOAD
            else:
                data[input_name] = "test123"

        try:
            if method == "POST":
                response = requests.post(action, data=data, timeout=5)
            else:
                response = requests.get(action, params=data, timeout=5)

            content = response.text.lower()

            for error in SQL_ERRORS:
                if error in content:
                    findings.append(
                        f"[HIGH] Possible SQL Injection in form field '{field}' at {action}"
                    )
                    break

        except Exception as e:
            findings.append(f"[ERROR] Form SQL test failed: {str(e)}")

    return findings