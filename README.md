# WebGuardian 🔒

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)

*A Professional's Reconnaissance & Vulnerability Scanning Framework*

</div>

---

## ⚠️ **ETHICAL DISCLAIMER**

**WebGuardian is a tool designed for authorized security testing ONLY.** Using it on systems for which you do not have explicit, written permission is illegal and unethical. The creators are not responsible for any misuse of this software. **Use responsibly.**

---

## 🚀 Features

WebGuardian is not just another script; it's a modular framework built for professionals by professionals.

-   **Intelligent Crawling:** Discovers URLs, forms, and parameters while respecting `robots.txt` and implementing stealth techniques like delay and User-Agent rotation.
-   **Modular Scanning:** Easily run specific vulnerability checks (SQLi, XSS, etc.) or a full comprehensive scan.
-   **Data-Driven Approach:** Leverages extensive, external payload and signature files, making the tool's knowledge base easily updatable without touching the core code.
-   **High Performance:** Built on Python with a clean architecture, ready for C++ integration for performance-critical tasks.
-   **Structured Reporting:** Generates detailed, machine-readable JSON reports perfect for integration into other security tools or for generating professional client reports.
-   **Linux Native:** Designed from the ground up to run efficiently on Linux environments.

## 🛠️ Quick Start

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/anwylrony/WebGuardian.git
    cd WebGuardian
    ```

2.  **Install dependencies:**
    ```bash
    pip3 install -r requirements.txt
    ```

3.  **Run your first scan:**
    ```bash
    python3 webguardian.py https://example.com
    ```

A report file named `report_[timestamp].json` will be created in the current directory.

## 📖 Usage

```bash
# Basic scan
python3 webguardian.py http://target.local

# Scan only for SQL Injection and XSS
python3 webguardian.py http://target.local --modules sqli xss

# Use a custom configuration and save the report
python3 webguardian.py http://target.local -c my_config.json -o client_report.json
