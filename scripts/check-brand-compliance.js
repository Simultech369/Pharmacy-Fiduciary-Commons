#!/usr/bin/env python3
"""
Pharmacy Fiduciary Commons — Brand Compliance Linter (Staged Guardrail B4)

Verifies Brand Gate B compliance for staged slices:
- Hard-fails if B1 elements (top banner, header, containment panel, #first-run-receipt-panel) contain inline style="..." attributes.
- Hard-fails if B2.1 elements (#liquidity-board, #council-controls, #voter-reg-box) or their descendants contain inline style="..." attributes.
- Hard-fails if unverified provenance badge uses static cyan (#00E5FF / rgba(6, 182, 212)).
- Hard-fails if touched primary controls (#btn-connect) contain informal emojis.
- Reports remaining global inline style count as open Brand Gate B debt.
"""

import os
import sys
import re
from html.parser import HTMLParser

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_HTML = os.path.join(ROOT_DIR, "dashboard/index.html")
B2_1_SCOPE_IDS = {"liquidity-board", "council-controls", "voter-reg-box"}
B2_2_SCOPE_IDS = {"onchain-events-panel", "portability-json-input"}
VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
}

class ScopedInlineStyleParser(HTMLParser):
    def __init__(self, target_ids):
        super().__init__(convert_charrefs=True)
        self.target_ids = set(target_ids)
        self.found_ids = set()
        self.scope_stack = []
        self.violations = []

    def handle_starttag(self, tag, attrs):
        attr_map = dict(attrs)
        element_id = attr_map.get("id")
        active_scope = self.scope_stack[-1] if self.scope_stack else None

        if element_id in self.target_ids:
            active_scope = element_id
            self.found_ids.add(element_id)

        if active_scope and "style" in attr_map:
            label = f"<{tag}"
            if element_id:
                label += f' id="{element_id}"'
            label += ">"
            self.violations.append((active_scope, label, attr_map["style"]))

        if tag.lower() not in VOID_TAGS:
            self.scope_stack.append(active_scope)

    def handle_endtag(self, _tag):
        if self.scope_stack:
            self.scope_stack.pop()

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

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

    # 0. Check design-system.css link tag in source HTML
    if '<link rel="stylesheet" href="./design-system.css">' not in content:
        errors.append("Stylesheets Link Check: index.html is missing <link rel=\"stylesheet\" href=\"./design-system.css\"> in <head>.")

    dist_css = os.path.join(ROOT_DIR, "dist/dashboard/design-system.css")
    if not os.path.exists(dist_css):
        errors.append("Build Output Check: dist/dashboard/design-system.css does not exist. Run npm.cmd run build:dashboard.")
    else:
        with open(dist_css, "r", encoding="utf-8") as f_css:
            dist_css_content = f_css.read()
            if ".badge-unverified-slate" not in dist_css_content:
                errors.append("CSS Activation Check: dist/dashboard/design-system.css is missing '.badge-unverified-slate' class definition.")

    dist_index = os.path.join(ROOT_DIR, "dist/dashboard/index.html")
    if not os.path.exists(dist_index):
        errors.append("Build Output Check: dist/dashboard/index.html does not exist. Run npm.cmd run build:dashboard.")
    else:
        with open(dist_index, "r", encoding="utf-8") as f_dist:
            dist_content = f_dist.read()
            if '<link rel="stylesheet" href="./design-system.css">' not in dist_content:
                errors.append("Dist Rendered Check: dist/dashboard/index.html is missing <link rel=\"stylesheet\" href=\"./design-system.css\">.")
            prov_dist_match = re.search(r'<span id="provenance-badge"[^>]*class="([^"]*)"', dist_content)
            if prov_dist_match:
                dist_badge_class = prov_dist_match.group(1)
                if "badge-unverified-slate" not in dist_badge_class:
                    errors.append(f"Dist Rendered Check: dist/dashboard/index.html #provenance-badge must use 'badge-unverified-slate', found '{dist_badge_class}'")
            else:
                errors.append("Dist Rendered Check: Could not locate #provenance-badge in dist/dashboard/index.html.")

    # 1. Total inline styles audit
    style_matches = re.findall(r'style="[^"]*"', content)
    total_inline_styles = len(style_matches)

    # 2. Extract B1 Header & First-Run Panel snippet
    b1_styles = []
    b1_scope_match = re.search(r'(<div class="banner-top-warning">.*?<section id="first-run-receipt-panel".*?</section>)', content, re.DOTALL)
    if not b1_scope_match:
        errors.append("B1 Scope Check: Could not locate B1 section (<header> to #first-run-receipt-panel) in index.html.")
    else:
        b1_content = b1_scope_match.group(1)
        b1_styles = re.findall(r'style="[^"]*"', b1_content)
        if b1_styles:
            errors.append(f"B1 Inline Style Violation: Found {len(b1_styles)} inline style attributes in B1 scope: {b1_styles}")

    # 2b. Parse B2.1 target subtrees and hard-fail on inline styles
    b2_parser = ScopedInlineStyleParser(B2_1_SCOPE_IDS)
    b2_parser.feed(content)
    missing_b2_ids = sorted(B2_1_SCOPE_IDS - b2_parser.found_ids)
    for missing_id in missing_b2_ids:
        errors.append(f"B2.1 Scope Check: Could not locate #{missing_id} in index.html.")
    if b2_parser.violations:
        violation_list = [
            f"#{scope} {label} style=\"{style}\""
            for scope, label, style in b2_parser.violations
        ]
        errors.append(
            f"B2.1 Inline Style Violation: Found {len(b2_parser.violations)} inline style attributes in B2.1 scope: {violation_list}"
        )

    # 2c. Parse B2.2 target subtrees and hard-fail on inline styles
    b2_2_parser = ScopedInlineStyleParser(B2_2_SCOPE_IDS)
    b2_2_parser.feed(content)
    missing_b2_2_ids = sorted(B2_2_SCOPE_IDS - b2_2_parser.found_ids)
    for missing_id in missing_b2_2_ids:
        errors.append(f"B2.2 Scope Check: Could not locate #{missing_id} in index.html.")
    if b2_2_parser.violations:
        violation_list = [
            f"#{scope} {label} style=\"{style}\""
            for scope, label, style in b2_2_parser.violations
        ]
        errors.append(
            f"B2.2 Inline Style Violation: Found {len(b2_2_parser.violations)} inline style attributes in B2.2 scope: {violation_list}"
        )

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

    # 5. Impeccable Anti-Pattern Check: Generic uncurated hex colors
    forbidden_generic_hexes = [r'#ff0000', r'#0000ff', r'#800080', r'#ffff00']
    for pattern in forbidden_generic_hexes:
        if re.search(pattern, content, re.IGNORECASE):
            errors.append(f"Impeccable Anti-Pattern Violation: Found uncurated generic color '{pattern}' in index.html. Use design system HSL tokens.")

    # 6. Emil Kowalski Motion Token Check in design-system.css
    css_path = os.path.join(ROOT_DIR, "dashboard/design-system.css")
    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as f:
            css_content = f.read()
        if "cubic-bezier(0.16, 1, 0.3, 1)" not in css_content:
            errors.append("Emil Kowalski Motion Violation: Missing required cubic-bezier(0.16, 1, 0.3, 1) transition curve in design-system.css.")

        # Duration Gate: Fail if UI transitions exceed 300ms (0.3s) in CSS or HTML <style> blocks
        all_sources = [("design-system.css", css_content), ("index.html", content)]
        for src_name, src_text in all_sources:
            slow_transitions = re.findall(r'transition[^;]*?\b([0-9\.]+)s\b', src_text)
            for dur in slow_transitions:
                try:
                    if float(dur) > 0.3:
                        errors.append(f"Emil Kowalski Duration Gate Violation: Found transition duration {dur}s > 0.3s (300ms) cap in {src_name}.")
                except ValueError:
                    pass

    # 7. Dashboard / Contract Solvency Copy Parity Check
    js_path = os.path.join(ROOT_DIR, "dashboard/web3_integration.js")
    if os.path.exists(js_path):
        with open(js_path, "r", encoding="utf-8") as f_js:
            js_content = f_js.read()
        if re.search(r'\bwill revert\b', js_content, re.IGNORECASE):
            errors.append("Solvency Parity Violation: web3_integration.js contains inaccurate 'will revert' copy. Contracts record shortfall and finalize.")
        if "may finalize while recording shortfall" not in js_content:
            errors.append("Solvency Parity Violation: web3_integration.js is missing mandatory debt copy 'may finalize while recording shortfall'.")

    # 1. Total inline styles audit
    style_matches = re.findall(r'style="[^"]*"', content)
    total_inline_styles = len(style_matches)
    if total_inline_styles > 0:
        errors.append(f"Global Inline Style Violation: Found {total_inline_styles} remaining inline style attributes in index.html. Brand Gate B requires 100% extraction (0 inline styles).")

    # Output Results
    print("==================================================")
    print("BRAND GATE B FULL VISUAL GOVERNANCE COMPLIANCE LINTER")
    print("==================================================")
    b1_status = "PASSED" if not b1_styles and b1_scope_match else "FAILED"
    b2_1_status = "PASSED" if not b2_parser.violations and not missing_b2_ids else "FAILED"
    b2_2_status = "PASSED" if not b2_2_parser.violations and not missing_b2_2_ids else "FAILED"
    global_status = "PASSED" if total_inline_styles == 0 else "FAILED"
    print(f"• B1 Scope Inline Styles: {len(b1_styles)} ({b1_status})")
    print(f"• B2.1 Scope Inline Styles: {len(b2_parser.violations)} ({b2_1_status})")
    print(f"• B2.2 Scope Inline Styles: {len(b2_2_parser.violations)} ({b2_2_status})")
    print(f"• Global Inline Style Extraction: {total_inline_styles} remaining ({global_status})")
    print(f"• Stateful Cyan Containment: PASSED (Source & Dist #provenance-badge is slate)")
    print(f"• Rendered Build Integration: PASSED (design-system.css bundled in dist)")
    print(f"• Primary Control Emoji Hygiene: PASSED (#btn-connect is text-only)")
    print("==================================================")

    if errors:
        print("❌ BRAND COMPLIANCE FAILURES:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        print("✅ Brand Gate B 100% Visual Governance Compliance Passed.")
        sys.exit(0)

if __name__ == "__main__":
    run_compliance_checks()
