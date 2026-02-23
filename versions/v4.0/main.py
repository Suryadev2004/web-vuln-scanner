import argparse
from colorama import Fore, Style, init

from scanners.header_scanner import check_headers
from scanners.sql_scanner import check_sql_injection
from scanners.xss_scanner import check_xss
from scanners.port_scanner import check_ports
from scanners.crawler import crawl_links
from scanners.form_scanner import extract_forms
from scanners.form_sqli_scanner import check_form_sql_injection
from utils.report import ReportManager

# Initialize colorama
init(autoreset=True)

print("=================================")
print("  Modular Web Vulnerability Scanner")
print("=================================")

# CLI Argument Parsing
parser = argparse.ArgumentParser(description="Modular Web Vulnerability Scanner")
parser.add_argument("--url", required=True, help="Target URL to scan")
args = parser.parse_args()

base_url = args.url.rstrip("/")

print(f"\nStarting Scan on: {base_url}\n")

# Severity Tracking
severity_count = {
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0,
    "OK": 0,
    "ERROR": 0
}

def update_severity(result):
    for level in severity_count:
        if result.startswith(f"[{level}]"):
            severity_count[level] += 1

def colorize(message):
    if message.startswith("[HIGH]"):
        return Fore.RED + message + Style.RESET_ALL
    elif message.startswith("[MEDIUM]"):
        return Fore.YELLOW + message + Style.RESET_ALL
    elif message.startswith("[LOW]"):
        return Fore.CYAN + message + Style.RESET_ALL
    elif message.startswith("[ERROR]"):
        return Fore.MAGENTA + message + Style.RESET_ALL
    elif message.startswith("[OK]"):
        return Fore.GREEN + message + Style.RESET_ALL
    else:
        return message

# Start Report
report = ReportManager(base_url)

# Crawl Links
print("Crawling for internal links...\n")
all_urls = crawl_links(base_url)

for url in all_urls:
    print(f"\n========== Scanning: {url} ==========\n")
    report.write_section(f"Scanning: {url}")

    # -------------------------
    # Header Scan
    # -------------------------
    print("Checking Security Headers...\n")
    header_results = check_headers(url)

    for result in header_results:
        print(colorize(result))
        report.write_finding(result)
        update_severity(result)

    # -------------------------
    # Form Detection
    # -------------------------
    print("\nChecking for Forms...\n")

    forms = extract_forms(url)

    if forms:
        for form in forms:
            if "error" in form:
                error_msg = f"[ERROR] {form['error']}"
                print(colorize(error_msg))
                report.write_finding(error_msg)
                update_severity(error_msg)
            else:
                info_msg = f"[INFO] Form detected | Action: {form['action']} | Method: {form['method']} | Inputs: {', '.join(form['inputs']) if form['inputs'] else 'No named inputs'}"
                print(colorize(info_msg))
                report.write_finding(info_msg)
                update_severity(info_msg)
    else:
        ok_msg = "[OK] No forms detected."
        print(colorize(ok_msg))
        report.write_finding(ok_msg)
        update_severity(ok_msg)

    # -------------------------
    # Form SQL Injection Testing
    # -------------------------
    print("\nTesting Forms for SQL Injection...\n")

    for form in forms:
        if "error" not in form:
            form_results = check_form_sql_injection(form)
            for result in form_results:
                print(colorize(result))
                report.write_finding(result)
                update_severity(result)

    # -------------------------
    # URL SQL Injection Scan
    # -------------------------
    print("\nChecking for SQL Injection...\n")
    sql_results = check_sql_injection(url)

    for result in sql_results:
        print(colorize(result))
        report.write_finding(result)
        update_severity(result)

    # -------------------------
    # XSS Scan
    # -------------------------
    print("\nChecking for XSS vulnerabilities...\n")
    xss_results = check_xss(url)

    for result in xss_results:
        print(colorize(result))
        report.write_finding(result)
        update_severity(result)

# -------------------------
# Port Scan (Base URL only)
# -------------------------
print("\nChecking Common Open Ports...\n")
port_results = check_ports(base_url)

for result in port_results:
    print(colorize(result))
    report.write_finding(result)
    update_severity(result)

# -------------------------
# Summary
# -------------------------
print("\n========== Scan Summary ==========\n")
report.write_section("Scan Summary")

for level, count in severity_count.items():
    summary_line = f"{level}: {count}"
    print(summary_line)
    report.write_finding(summary_line)

report.close()

print("\nScan Completed.")
print("Report saved to report.txt")