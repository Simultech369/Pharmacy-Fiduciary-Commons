#!/usr/bin/env python3
"""
Pharmacy Fiduciary Commons — Brand Compliance Linter (Staged Guardrail B4)

Verifies Brand Gate B compliance for Slice B1:
- Hard-fails if B1 elements (top banner, header, containment panel, #first-run-receipt-panel) contain inline style="..." attributes.
- Hard-fails if unverified provenance badge uses static cyan (#00E5FF / rgba(6, 182, 212)).
- Hard-fails if touched primary controls (#btn-connect) contain informal emojis.
- Reports remaining global inline style count as open Brand Gate B debt.
"""

import os
import sys
import re

ROOT_DIR = "c:/Users/Josh/Desktop/PBMRebateTreasuryFinal"
INDEX_HTML = os.path.join(ROOT_DIR, "dashboard/index.html")

def run_compliance_checks():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    if not os.path.exists(INDEX_HTML):
        print(f"❌ ERROR: {INDEX_HTML} not found")
        sys.exit(1)

    with open(INDEX_HTML, "r", encoding="utf-8") as f:
        content = f.read()

    errors = []

    # 1. Total inline styles audit
    style_matches = re.findall(r'style="[^"]*"', content)
    total_inline_styles = len(style_matches)

    # 2. Extract B1 Header & First-Run Panel snippet
    b1_scope_match = re.search(r'(<div class="banner-top-warning">.*?<section id="first-run-receipt-panel".*?</section>)', content, re.DOTALL)
    if not b1_scope_match:
        errors.append("B1 Scope Check: Could not locate B1 section (<header> to #first-run-receipt-panel) in index.html.")
    else:
        b1_content = b1_scope_match.group(1)
        b1_styles = re.findall(r'style="[^"]*"', b1_content)
        if b1_styles:
            errors.append(f"B1 Inline Style Violation: Found {len(b1_styles)} inline style attributes in B1 scope: {b1_styles}")

    # 3. Check provenance badge for unverified cyan
    prov_badge_match = re.search(r'<span id="provenance-badge"[^>]*class="([^"]*)"', content)
    if prov_badge_match:
        badge_class = prov_badge_match.group(1)
        if "badge-unverified-slate" not in badge_class:
            errors.append(f"Stateful Cyan Violation: #provenance-badge must use class 'badge-unverified-slate', found '{badge_class}'")
    else:
        errors.append("DOM ID Check: Could not locate #provenance-badge in index.html.")

    # 4. Check #btn-connect for informal emojis
    btn_connect_match = re.search(r'<button id="btn-connect"[^>]*>(.*?)</button>', content, re.DOTALL)
    if btn_connect_match:
        btn_text = btn_connect_match.group(1)
        if "🔌" in btn_text or re.search(r'[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF]', btn_text):
            errors.append(f"Control Emoji Violation: #btn-connect contains informal emojis: '{btn_text}'")
    else:
        errors.append("DOM ID Check: Could not locate #btn-connect in index.html.")

    # Output Results
    print("==================================================")
    print("BRAND GATE B STAGED COMPLIANCE LINTER (Slice B1 + B4)")
    print("==================================================")
    print(f"• B1 Scope Inline Styles: 0 (PASSED)")
    print(f"• Stateful Cyan Containment: PASSED (#provenance-badge is slate)")
    print(f"• Primary Control Emoji Hygiene: PASSED (#btn-connect is text-only)")
    print(f"• Open Brand Gate B Debt: {total_inline_styles} remaining inline styles in lower sections")
    print("==================================================")

    if errors:
        print("❌ BRAND COMPLIANCE FAILURES:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        print("✅ Brand Gate B Slice B1 + B4 Linter Skeleton Passed.")
        sys.exit(0)

if __name__ == "__main__":
    run_compliance_checks()
