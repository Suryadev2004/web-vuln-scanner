\# Web Vulnerability Scanner – v2.0



\## 📌 Overview



Version 2.0 builds upon the modular foundation of v1.0 and introduces smarter scanning capabilities through controlled internal crawling and injection surface detection.



This version represents a structural and logical improvement over v1.0.



---



\##  New Features in v2.0



\- Internal link crawler (scope-restricted)

\- Multi-URL scanning

\- Injection surface detection (query parameter awareness)

\- Improved error handling and stability

\- Cleaner report structure



---



\##  Improvements Over v1.0



\- Instead of scanning a single URL, v2.0 crawls internal links.

\- SQL and XSS tests now intelligently skip URLs without parameters.

\- More stable execution without crashing on malformed URLs.

\- Better severity tracking and structured output.



---



\##  Current Limitations



\- No form extraction yet

\- No POST-based injection testing

\- No multithreading (sequential scanning)

\- Detection logic is still payload-based (basic)



---



\##  Learning Focus



This version was built to understand:



\- Web crawling fundamentals

\- Scope restriction in security testing

\- Injection surface modeling

\- Progressive architectural upgrades

\- Version tagging and release discipline using Git

