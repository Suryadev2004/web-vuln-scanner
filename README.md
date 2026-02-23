#  Web Vulnerability Scanner

A modular Python-based web application vulnerability scanner built for learning and practicing cybersecurity concepts.

This project is developed version-by-version to demonstrate structured growth from a basic scanner (v1.0) to a smarter crawler-based scanner (v2.0).

---

##  Project Goal

To understand how web vulnerability scanners work internally by building one from scratch using:

- Python
- Modular architecture
- Controlled crawling
- Basic injection testing logic
- Clean Git version management

---

##  Features (v2.0)

-  Internal link crawling (scope-restricted)
-  Security header analysis
-  Basic SQL Injection detection (query parameter-based)
-  Basic reflected XSS detection
-  Common port scanning (21, 22, 80, 443, 3306)
-  Structured text-based reporting
-  Clean modular architecture
-  Version evolution tracking (v1.0 → v2.0)

---

##  Project Architecture

current/
├── main.py
├── scanners/
│ ├── crawler.py
│ ├── header_scanner.py
│ ├── sql_scanner.py
│ ├── xss_scanner.py
│ └── port_scanner.py
└── utils/
└── report.py


### Design Principles

- `main.py` → Controls workflow and scan coordination  
- `scanners/` → Each vulnerability type is isolated into its own module  
- `utils/report.py` → Handles structured report generation  

This separation makes the project scalable and easier to extend in future versions.

---

##  Version Evolution

###  v1.0 – Modular Foundation
- Basic modular scanner
- Header scanning
- SQL & XSS payload testing
- Port scanning
- CLI-based execution

###  v2.0 – Smarter Scanning
- Internal crawler added
- Multi-URL scanning
- Injection surface detection
- Improved stability
- Clean Git tagging and structured version showcase

---

##  Installation

```bash
pip install requests
pip install beautifulsoup4
pip install colorama

---

## Usage 

#> python main.py --url http://example.com

- example

#> python main.py --url http://testphp.vulnweb.com

---

## Output

Console-based severity output

Structured report.txt file

Summary of detected findings

---

## Disclaimer

This tool is created strictly for educational purposes.

Only scan applications you own or have explicit permission to test.

Unauthorized scanning may be illegal.

---

