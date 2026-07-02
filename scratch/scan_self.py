import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

from app.services.scanner import scan_code

# Scan all python files in app/
findings_count = 0
for root, dirs, files in os.walk("app"):
    for file in files:
        if file.endswith(".py"):
            filepath = os.path.join(root, file)
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            findings = scan_code(content)
            if findings:
                print(f"File: {filepath}")
                for fnd in findings:
                    print(f"  [{fnd.rule_id}] {fnd.title} - Evidence: {fnd.evidence}")
                    findings_count += 1

print(f"\nTotal findings: {findings_count}")
