import argparse
from colorama import Fore, Style, init

from scanners.header_scanner import check_headers
from scanners.sql_scanner import check_sql_injection
from scanners.xss_scanner import check_xss
from scanners.port_scanner import check_ports
from scanners.crawler import crawl_links
from utils.report import ReportManager

init(autoreset=True)

print("=================================")
print("  Modular Web Vulnerability Scanner")
print("=================================")

parser = argparse.ArgumentParser(description="Modular Web Vulnerability Scanner")
parser.add_argument("--url", required=True, help="Target URL to scan")

args = parser.parse_args()
base_url = args.url.rstrip("/")

print(f"\nStarting Scan on: {base_url}\n")

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

def colorize(message):
    if "[HIGH]" in message:
        return Fore.RED + message
    elif "[MEDIUM]" in message:
        return Fore.YELLOW + message
    elif "[LOW]" in message:
        return Fore.BLUE + message
    elif "[INFO]" in message:
        return Fore.CYAN + message
    elif "[OK]" in message:
        return Fore.GREEN + message
    elif "[ERROR]" in message:
        return Fore.MAGENTA + message
    return message

report = ReportManager(base_url)

print("Crawling for internal links...\n")
report.write_section("Crawled URLs:")

crawled_links = crawl_links(base_url)

all_urls = set()
all_urls.add(base_url)

for link in crawled_links:
    all_urls.add(link.rstrip("/"))

for link in all_urls:
    print(link)
    report.write_finding(link)

for url in all_urls:

    print(f"\n========== Scanning: {url} ==========\n")
    report.write_section(f"Scanning: {url}")

    print("Checking Security Headers...\n")
    report.write_section("Security Header Analysis:")
    for result in check_headers(url):
        track_severity(result)
        print(colorize(result))
        report.write_finding(result)

    print("\nChecking for SQL Injection...\n")
    report.write_section("SQL Injection Analysis:")
    for result in check_sql_injection(url):
        track_severity(result)
        print(colorize(result))
        report.write_finding(result)

    print("\nChecking for XSS vulnerabilities...\n")
    report.write_section("XSS Analysis:")
    for result in check_xss(url):
        track_severity(result)
        print(colorize(result))
        report.write_finding(result)

print("\nChecking Common Open Ports...\n")
report.write_section("Port Scan Results:")
for result in check_ports(base_url):
    track_severity(result)
    print(colorize(result))
    report.write_finding(result)

print("\n========== Scan Summary ==========\n")
report.write_section("Scan Summary:")
for level, count in severity_counts.items():
    summary_line = f"{level}: {count}"
    print(colorize(summary_line))
    report.write_finding(summary_line)

report.close()

print("\nScan Completed.")
print("Report saved to report.txt")