from datetime import datetime


class ReportManager:
    def __init__(self, target_url):
        self.filename = "report.txt"
        self.file = open(self.filename, "w", encoding="utf-8")

        self.file.write("=================================\n")
        self.file.write("  Modular Web Vulnerability Scan Report\n")
        self.file.write("=================================\n\n")
        self.file.write(f"Target: {target_url}\n")
        self.file.write(f"Scan Time: {datetime.now()}\n\n")

    def write_section(self, title):
        self.file.write("\n---------------------------------\n")
        self.file.write(f"{title}\n")
        self.file.write("---------------------------------\n")

    def write_finding(self, finding):
        self.file.write(f"{finding}\n")

    def close(self):
        self.file.write("\n=================================\n")
        self.file.write("  End of Report\n")
        self.file.write("=================================\n")
        self.file.close()