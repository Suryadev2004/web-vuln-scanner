# Web Vulnerability Scanner — v4.0

## Overview

Version 4.0 introduces Boolean-based Blind SQL Injection detection.

This version improves the SQL testing engine by comparing TRUE vs FALSE
payload responses instead of relying only on SQL error messages.

---

## What v4.0 Adds

- Boolean-based SQL Injection detection (TRUE vs FALSE logic)
- Blind response comparison using percentage difference
- Form-based blind SQL detection
- Reduced false positives with threshold control
- Clean modular architecture

---

## Detection Logic

TRUE payload:
' OR 1=1 --

FALSE payload:
' AND 1=2 --

If the application behaves differently between TRUE and FALSE conditions,
the scanner flags a possible blind SQL injection vulnerability.

---

## Severity Levels

HIGH → Confirmed error-based SQL injection  
MEDIUM → Boolean-based blind SQL suspected  
OK → No injection detected  
INFO → Informational output  

---

## Folder Structure

v4.0
│   main.py
├── scanners
│   ├── crawler.py
│   ├── form_scanner.py
│   ├── form_sqli_scanner.py
│   ├── header_scanner.py
│   ├── port_scanner.py
│   ├── sql_scanner.py
│   └── xss_scanner.py
└── utils
    └── report.py

---

## Limitations

- No time-based SQL detection
- No per-parameter injection testing
- Sequential scanning (no multithreading)

---

## Tag

Release tag: v4.0