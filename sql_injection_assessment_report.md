# 🛡️ SQL Injection Security Assessment Report: DVWA

**Date:** April 15, 2026  
**Lead Security Researcher:** Youssef Moataz  
**Target Application:** Damn Vulnerable Web Application (DVWA)  
**Security Level:** Low  

---

## 1. Executive Summary

This assessment details a comprehensive security evaluation of the SQL Injection module within the DVWA environment. The primary objective was to validate injection vulnerabilities, automate data exfiltration using industry-standard tools, and evaluate the efficacy of custom detection logic.

### 🔴 Critical Findings
*   **Vulnerability Type:** Unsanitized `id` parameter allowing Blind-Time, UNION, and Boolean-based SQL Injection.
*   **Data Impact:** 100% data exfiltration achievement, including plaintext credential recovery for all administrative and user accounts.
*   **Root Cause:** Lack of prepared statements and improper input validation in the backend PHP logic.

---

## 2. Technical Methodology

The assessment followed a structured three-tier approach to identify and exploit the vulnerability:

1.  **Manual Heuristics:** Initial verification using standard Boolean payloads (`1' OR '1'='1`) to confirm database interaction.
2.  **Automated Exploitation (SQLMap):** Comprehensive enumeration of database structure, table metadata, and credential dumping.
3.  **Custom Scripting (Python):** Development of a tailored vulnerability scanner (`sqli_scanner.py`) to simulate automated detection capabilities and analyze response patterns.

---

## 3. Phase 1: Manual Discovery & Confirmation

The initial test targeted the `id` parameter on the SQLi module. By injecting a simple Boolean payload, the application response was manipulated to dump the current database user's record, confirming the vulnerability.

> [!NOTE]
> **Payload Used:** `1' OR 1=1 --`  
> **Result:** The application rendered multiple records instead of a single ID-specific record, indicating a successful modification of the SQL query's `WHERE` clause.

---

## 4. Phase 2: Professional Exploitation (SQLMap)

SQLMap was utilized to perform a high-fidelity scan. The tool identified three distinct injection vectors:

| Injection Type | Technique Description |
| :--- | :--- |
| **Boolean-based Blind** | Inferring data through True/False response changes. |
| **Error-based** | Forcing the database to reveal structure through error messages. |
| **UNION query-based** | Appending malicious query results to the original output. |
| **Time-based Blind** | Measuring response latency to infer database state. |

### 4.1 Database & Table Enumeration
The tool successfully identified the backend DBMS as **MySQL/MariaDB**.

- **Databases:** `dvwa`, `information_schema`
- **Critical Tables:** `users`, `guestbook`

![Database Structure](file:///C:/Users/LEGION/.gemini/antigravity/scratch/pics/Screenshot_2026-04-15_15_55_54.png)
*Figure 1: Automated enumeration of the DVWA database schema.*

---

## 5. Phase 3: Data Exfiltration & Credential Cracking

Upon targeting the `users` table, SQLMap identified password hashes. A dictionary-based attack followed by verification of cracked hashes revealed a high percentage of weak credentials.

### 5.1 Recovered Credentials

| Username | Hash (MD5) | Cracked Password |
| :--- | :--- | :--- |
| **admin** | `5f4dcc3b5aa765d61d8327deb882cf99` | **password** |
| **gordonb** | `e99a18c428cb38d5f260853678922e03` | **abc123** |
| **1337** | `8d3533d75ae2c3966d7e04fcc69216b` | **charley** |
| **pablo** | `0d107d09f5bbe40cade3de5c71e9e9b7` | **letmein** |
| **smithy** | `5f4dcc3b5aa765d61d8327deb882cf99` | **password** |

![Credential Recovery](file:///C:/Users/LEGION/.gemini/antigravity/scratch/pics/Screenshot_2026-04-15_15_56_00.png)
*Figure 2: Successful table dump showing user accounts and cracked passwords.*

---

## 6. Custom Scanner Technical Analysis

A custom Python scanner, `sqli_scanner.py`, was developed to understand the mechanics of automated detection.

### 6.1 Script Logic: `sqli_scanner.py`
The scanner implements three primary detection methods:
1.  **Indicator Matching:** Searching for database signatures (e.g., "first name", "surname", "mysql error").
2.  **Timing Correlation:** Measuring delta time for sleep-based payloads to identify blind vulnerabilities.
3.  **Baseline Differential:** Comparing the response byte-size against a known safe response.

```python
# Technical snippet of the detection logic
def is_vulnerable(response, baseline, elapsed, payload):
    # 1. Strong indicator found (e.g., 'admin')
    for indicator in SUCCESS_INDICATORS:
        if indicator in response.lower():
            return True, f"Indicator found: {indicator}"
            
    # 2. Time-based detection
    if "sleep" in payload.lower() and elapsed > 1.5:
        return True, "Time-based delay detected"
```

### 6.2 Performance Evaluation
While the scanner successfully identified **Boolean-based** vulnerabilities, it highlighted the difficulty of reliable **UNION** detection without complex parser logic.

![Scanner Output](file:///C:/Users/LEGION/.gemini/antigravity/scratch/pics/Screenshot_2026-04-15_16_06_31.png)
*Figure 3: Execution trace of the custom security scanner.*

---

## 7. Remediation & Recommendations

To mitigate these critical risks, the following security controls must be implemented:

### 🔐 7.1 Primary Defense: Prepared Statements
Use Parameterized Queries (Prepared Statements) for all database interactions. This ensures that user input is treated as data, not executable code.

**Vulnerable Code:**
```php
$query = "SELECT * FROM users WHERE id = '$id'";
```

**Secure Implementation:**
```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $id]);
```

### 🛡️ 7.2 Secondary Controls
*   **Input Validation:** Enforce strict type checking (e.g., ensure `id` is an integer).
*   **Web Application Firewall (WAF):** Deploy rules to block common SQLi patterns.
*   **Credential Security:** Enforce salt-based hashing (Argon2 or bcrypt) to protect against dictionary attacks.

---

## 8. Conclusion

The assessment successfully demonstrated a full exploitation chain, from initial parameter discovery to full credential recovery. The parity between automated tools and custom scripting underscores the critical need for robust input sanitization and secure coding standards in modern web applications.

---

**Author:** Youssef Moataz  
**Contact:** [Professional Profile Link Pre-filled]
