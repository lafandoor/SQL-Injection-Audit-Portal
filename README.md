# SQL-Injection-Audit-Portal: End-to-End Vulnerability Analysis

This repository contains a professional security audit of SQL Injection vulnerabilities. It documents a complete attack lifecycle—from initial heuristic discovery and schema mapping to automated exfiltration and credential recovery.

**🔗 [Access Live Forensic Portal](https://lafandoor.github.io/SQL-Injection-Audit-Portal/)**

---

## 🛡️ Assessment Highlights

- **Full Exploitation Chain**: Validation of Boolean-based, UNION-based, and Time-based Blind SQLi vectors.
- **Credential Recovery**: Successful exfiltration and decryption of administrative MD5 hashes via dictionary-based attacks.
- **Custom Security Tooling**: Includes a bespoke Python scanner for heuristic vulnerability verification.
- **Interactive Report**: A professional security dashboard and formal audit report documenting findings with forensic evidence.

## 💻 Tech Stack

- **Exploitation**: SQLMap, Manual Proxy Manipulation.
- **Custom Scripting**: Python 3 (Requests).
- **Reporting**: HTML5, Vanilla CSS (Noir Design System).
- **Environment**: DVWA (Security Level: Low).

## 📂 Repository Structure

- `Script/sqli_scanner.py`: Custom Python-based heuristic detection script.
- `index.html`: Interactive security assessment dashboard.
- `formal_report.html`: Comprehensive formal audit report.
- `pics/`: Evidence gallery documenting schema enumeration and data exfiltration.
- `style.css`: Unified design system for the assessment platform.

## 🚀 Execution (Custom Scanner)

1. Ensure Python 3.x is installed.
2. Install the required library:
   ```bash
   pip install requests
   ```
3. Update the `SESSION_COOKIE` in `Script/sqli_scanner.py` with your active DVWA session.
4. Run the scanner:
   ```bash
   python3 Script/sqli_scanner.py
   ```

## 📝 Findings Summary
The audit confirmed critical vulnerabilities allowing for full database compromise. All administrative records were exfiltrated during the assessment, highlighting the critical need for prepared statements and robust input validation.

## 🔐 Remediation Recommendations
- Implement **Prepared Statements** (Parameterized Queries).
- Enforce strict input validation using type-whitelist filtering.
- Migrate to secure hashing algorithms (e.g., Argon2, bcrypt).

---
**Author**: Youssef Moataz  
**Goal**: Technical Portfolio Piece for Internship Submission
