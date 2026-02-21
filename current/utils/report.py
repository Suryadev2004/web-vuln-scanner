from datetime import datetime

class ReportManager:

    def __init__(self, url):
        self.file = open("report.txt", "w")
        self.file.write("=================================\n")
        self.file.write(" Modular Web Vulnerability Scan Report\n")
        self.file.write("=================================\n\n")
        self.file.write(f"Target: {url}\n")
        self.file.write(f"Scan Time: {datetime.now()}\n\n")

    def write_section(self, title):
        self.file.write(f"\n{title}\n")

    def write_finding(self, message):
        self.file.write(message + "\n")

    def close(self):
        self.file.write("\nScan Completed.\n")
        self.file.close()
