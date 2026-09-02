import os
import re
import sys

TARGET_DIRS = ["docs", "support", "frontend", "README.md", "ONBOARDING.md"]

LEAK_PATTERNS = [
    (r"(?i)\b(submit|enter|send|paste|give me|email|attach|upload)\b.{0,40}\b(raw credential|private key|wallet key|secret key|PHI|patient info|witness json)\b", "Asking for raw credentials/PHI"),
    (r"(?i)\b(submit|enter|send|paste|give me|email|attach|upload)\b.{0,40}\b(wallet-to-pharmacy|pharmacy mapping|link your wallet)\b", "Asking for wallet-to-pharmacy identity mappings"),
    (r"(?i)\b(submit|enter|send|paste|give me|email|attach|upload)\b.{0,40}\b(rpc trace|network trace|ip address)\b", "Asking for RPC traces or IP addresses"),
    (r"(?i)\bemail us your\b.{0,40}\b(key|json|witness|credential)\b", "Asking to email sensitive data"),
]

def scan_file(filepath):
    violations = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                for pattern, desc in LEAK_PATTERNS:
                    if re.search(pattern, line):
                        violations.append(f"{filepath}:{line_num} - {desc}\n  Line: {line.strip()}")
    except (UnicodeDecodeError, IsADirectoryError):
        pass
    return violations

def main():
    print("==================================================")
    print("PRIVACY LEAK SCANNER")
    print("==================================================")
    
    all_violations = []
    for target in TARGET_DIRS:
        if not os.path.exists(target):
            continue
        if os.path.isfile(target):
            all_violations.extend(scan_file(target))
        else:
            for root, _, files in os.walk(target):
                for file in files:
                    if file.endswith((".md", ".txt", ".js", ".html", ".tsx", ".jsx", ".json")):
                        filepath = os.path.join(root, file)
                        all_violations.extend(scan_file(filepath))
                        
    if all_violations:
        print(f"FAILED: Found {len(all_violations)} potential privacy leaks!")
        for v in all_violations:
            print(v)
        sys.exit(1)
    else:
        print("PASSED: No privacy leaks detected in public-facing materials.")
        sys.exit(0)

if __name__ == "__main__":
    main()

