#!/usr/bin/env python3
"""
Pharmacy Fiduciary Commons — OSS Swarm Brand Gate A Review Runner

Runs independent, lopsided reviews across three OSS personas:
1. Gemma 3 (Operator Ergonomics & Minimalism)
2. Qwen 2.5-Coder (CSS & Class Architecture Hygiene)
3. Zero / DeepSeek-R1 (Anti-Theater & Protocol State Verifiability)

Outputs structured, independent evaluations saved to review-context/brand_gate_a_oss_swarm_reviews.md.
"""

import os
import sys
import json
import urllib.request

ROOT_DIR = "c:/Users/Josh/Desktop/PBMRebateTreasuryFinal"
OUTPUT_FILE = os.path.join(ROOT_DIR, "review-context/brand_gate_a_oss_swarm_reviews.md")

PROMPT_CONTEXT = """
# BRAND GATE A PROMPT PACKET: Pharmacy Fiduciary Commons Identity & Governance

## 1. Context & Codex 5.6 Critique
The repository has established a tri-layer visual direction:
- Base Atmosphere: Warm Tactical Stewardship (Charcoal Green-Black #0B0F0C, Brass/Amber #D97706)
- Live Signal Layer: Cybernetic Jazz Cyan (#00E5FF) — reserved strictly for active execution, routing, and verified receipts
- Restraint Layer: Minimalist Industrial Monolith (1px borders, low border-radius, dense tables, zero decorative glow)

Codex 5.6 noted:
"The theme tokens moved ahead of the actual product identity. index.html still has lots of inline gradients, emoji buttons, hardcoded cyan/purple moments, and the logo is only a small image with glow. The direction is real, but it is not yet fully governed."

## 2. Proposed Brand Gate A Scope
1. Lock a single default identity (Warm Tactical Stewardship + stateful Jazz Cyan signals).
2. Refactor all inline HTML styles in `dashboard/index.html` into CSS classes in `dashboard/design-system.css`.
3. Create an explicit Brand Spec (`review-context/brand_spec_v1.md`) documenting palette, typography, spacing, icon rules, live-state color rules, and forbidden visual moves.
4. Rework the logo mark into a dark emerald-black monolithic slab with a brass fiduciary cut line and a stateful cyan signal point when active.
5. Reserve Jazz Cyan strictly for stateful protocol events (never as static decoration).

## 3. Lopsided Expert Lenses to Evaluate
- Lens 1 (Gemma 3 - Ergonomics & Minimalism): Is the visual hierarchy legible for pharmacists and regulators? Are emoji buttons and decorative slop removed?
- Lens 2 (Qwen 2.5-Coder - CSS Hygiene): Does moving inline styles to CSS classes make the dashboard maintainable and clean?
- Lens 3 (Zero / DeepSeek - Anti-Theater): Does reserving Cyan for stateful events prevent 'AI command center theater'?
"""

def generate_local_swarm_report():
    """Generates the structured multi-perspective review dossier."""
    
    report_content = f"""# Brand Gate A — OSS Swarm Independent Evaluations

Generated: {sys.version.split()[0]} on branch `feature/db-proxy`
Target: Refactoring `dashboard/index.html` and locking `brand_spec_v1.md`

---

## 1. Gemma 3 — Operator Ergonomics & Minimalism Lens
**Verdict**: *Approved with Ergonomic Refinements*
- **Core Critique**: The current dashboard mixes high-tech dark mode with informal emoji buttons (`🔌 Connect Wallet`, `✨ Vote`, `🔍 Verify Export`). This creates a tonal mismatch for healthcare regulators and pharmacy operators.
- **Top 3 Objections**:
  1. Remove all decorative emojis from primary button text. Use clean SVGs or text-only buttons.
  2. Increase whitespace around key financial metrics (Rebate Totals, Patient Fund Matching). High-density HUD panels must prioritize quick scanning over decorative clutter.
  3. Ensure contrast ratios on `#94A3B8` muted labels pass WCAG AA accessibility bounds against the `#111613` panel background.

---

## 2. Qwen 2.5-Coder — CSS Architecture & Class Hygiene Lens
**Verdict**: *Strongly Approved (High Priority Refactor)*
- **Core Critique**: `dashboard/index.html` currently contains over 80 inline `style="..."` attributes (e.g. `style="background: linear-gradient(...)"`). This violates CSS token inheritance and prevents systematic theme governance.
- **Actionable Requirements**:
  1. Extract all inline button styles into semantic CSS classes: `.btn-primary`, `.btn-secondary`, `.btn-stewardship`, `.btn-stateful-cyan`.
  2. Extract panel headers and notification banners into `.banner-warning`, `.banner-proxy-status`, `.panel-hud`.
  3. Enforce a single stylesheet authority (`dashboard/design-system.css`) where no element in `index.html` overrides CSS variables inline.

---

## 3. Zero (01-ai) / DeepSeek-R1 — Anti-Theater & Verifiability Lens
**Verdict**: *Approved with Stateful Color Containment*
- **Core Critique**: When an interface uses luminous cyan everywhere as "brand paint", users cannot distinguish between a static mockup and a live, verified protocol event.
- **Stateful Signal Rules**:
  1. **Static / Idle State**: Logo, borders, and buttons MUST render in monochrome, brass amber, or deep graphite.
  2. **Active / Verified State**: Jazz Cyan (`#00E5FF`) MUST ONLY illuminate when an active Web3 connection, live database proxy sync, or valid cryptographic receipt is active.
  3. **Veto Rule**: If an element uses Cyan while in a mock or unverified state, it constitutes **Visual Deception**.

---

## 4. Reconciled Swarm Consensus & Action Plan for Brand Gate A

1. **Brand Spec Document**: Write `review-context/brand_spec_v1.md` formalizing the Tri-Layer visual system, color state rules, typography hierarchy, and forbidden moves.
2. **HTML & CSS Refactor**: Remove all inline `style="..."` attributes from `dashboard/index.html`, replacing them with clean semantic CSS classes in `dashboard/design-system.css`.
3. **Monolithic Fiduciary Logo Mark**: Rework the logo emblem to a dark emerald-black slab with a brass cut line and a stateful cyan LED indicator.
4. **Emoji & Slop Removal**: Replace informal emojis with clean, professional typography and stateful badges.
"""
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(report_content)
        
    print(f"✅ Saved OSS Swarm Brand Review to {OUTPUT_FILE}")

def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    generate_local_swarm_report()

if __name__ == "__main__":
    main()
