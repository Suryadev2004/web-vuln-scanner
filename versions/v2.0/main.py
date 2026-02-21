import argparse
from colorama import Fore, Style, init

from scanners.header_scanner import check_headers
from scanners.sql_scanner import check_sql_injection
from scanners.xss_scanner import check_xss
from scanners.port_scanner import check_ports
from scanners.crawler import crawl_links
from utils.report import ReportManager

# Initialize colorama
init(autoreset=True)

print("=================================")
print("  Modular Web Vulnerability Scanner")
print("=================================")

# -------------------------
# CLI Argument Parsing
# -------------------------
parser = argparse.ArgumentParser(description="Modular Web Vulnerability Scanner")

parser.add_argument(
    "--url",
    required=True,
    help="Target URL to scan (example: http://example.com)"
)

args = parser.parse_args()
base_url = args.url.rstrip("/")  # remove trailing slash if exists

print(f"\nStarting Scan on: {base_url}\n")

# -------------------------
# Severity Tracking
# -------------------------
severity_counts = {
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0,
    "OK": 0,
    "ERROR": 0
}

def track_severity(message):
    for key in severity_counts:
        if f"[{key}]" in message:
            severity_counts[key] += 1

# -------------------------
# Color Formatting
# -------------------------
def colorize(message):
    if "[HIGH]" in message:
        return Fore.RED + message + Style.RESET_ALL
    elif "[MEDIUM]" in message:
        return Fore.YELLOW + message + Style.RESET_ALL
    elif "[LOW]" in message:
        return Fore.BLUE + message + Style.RESET_ALL
    elif "[INFO]" in message:
        return Fore.CYAN + message + Style.RESET_ALL
    elif "[OK]" in message:
        return Fore.GREEN + message + Style.RESET_ALL
    elif "[ERROR]" in message:
        return Fore.MAGENTA + message + Style.RESET_ALL
    else:
        return message

# -------------------------
# Initialize Report
# -------------------------
report = ReportManager(base_url)

# -------------------------
# Crawl Links
# -------------------------
print("Crawling for internal links...\n")
report.write_section("Crawled URLs:")

crawled_links = crawl_links(base_url)

# Always include base URL
all_urls = set()
all_urls.add(base_url)

# Add discovered links
for link in crawled_links:
    all_urls.add(link.rstrip("/"))

# Print discovered URLs
for link in all_urls:
    print(link)
    report.write_finding(link)

# -------------------------
# Scan Each URL
# -------------------------
for url in all_urls:

    print(f"\n========== Scanning: {url} ==========\n")
    report.write_section(f"Scanning: {url}")

    # Header Scan
    print("Checking Security Headers...\n")
    report.write_section("Security Header Analysis:")

    for result in check_headers(url):
        track_severity(result)
        print(colorize(result))
        report.write_finding(result)

    # SQL Injection Scan
    print("\nChecking for SQL Injection...\n")
    report.write_section("SQL Injection Analysis:")

    for result in check_sql_injection(url):
        track_severity(result)
        print(colorize(result))
        report.write_finding(result)

    # XSS Scan
    print("\nChecking for XSS vulnerabilities...\n")
    report.write_section("XSS Analysis:")

    for result in check_xss(url):
        track_severity(result)
        print(colorize(result))
        report.write_finding(result)

# -------------------------
# Port Scan (Only Once)
# -------------------------
print("\nChecking Common Open Ports...\n")
report.write_section("Port Scan Results:")

for result in check_ports(base_url):
    track_severity(result)
    print(colorize(result))
    report.write_finding(result)

# -------------------------
# Summary Section
# -------------------------
print("\n========== Scan Summary ==========\n")
report.write_section("Scan Summary:")

for level, count in severity_counts.items():
    summary_line = f"{level}: {count}"
    print(colorize(summary_line))
    report.write_finding(summary_line)

report.close()

print("\nScan Completed.")
print("Report saved to report.txt")