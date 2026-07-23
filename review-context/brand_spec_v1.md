# Pharmacy Fiduciary Commons — Brand Spec v1 & Visual Governance

Status: Active Specification (`Brand Gate A`). This specification defines the official visual identity, color state rules, typography hierarchy, and forbidden moves for the Pharmacy Fiduciary Commons protocol and dashboard interfaces.

---

## 1. The Tri-Layer Visual Architecture

To ensure the interface feels like an enduring, high-trust institutional instrument rather than a temporary "web3 dark-blue command center", all visual elements follow a strict tri-layer hierarchy:

```
┌───────────────────────────────────────────────────────────────────────────┐
  LAYER 1: Warm Tactical Stewardship (Base Atmosphere)
  • Base Canvas: Deep Charcoal Green-Black (#0B0F0C)
  • Elevated Surfaces: High-density charcoal panels (#111613)
  • Stewardship & Priority Accent: Brass & Warm Amber (#D97706)
└───────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────────┐
  LAYER 2: Cybernetic Jazz Diorama (Live Signal Layer)
  • Stateful Jazz Cyan (#00E5FF) — RESERVED STRICTLY FOR:
    - Active Web3 execution routing & live status indicators
    - Verified receipt boundaries & selected node focus states
    - Zero decorative glow unless communicating live protocol execution
└───────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────────┐
  LAYER 3: Minimalist Industrial Monolith (Restraint Layer)
  • 1px crisp structural borders (rgba(16, 185, 129, 0.12))
  • High-legibility HUD tables & monospace receipt blocks (JetBrains Mono)
  • Strict typography hierarchy (Inter body, Space Grotesk headings)
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Stateful Color Rules (Anti-Deception Policy)

Colors convey **protocol state**, not static decoration. Applying luminous colors to unverified elements violates visual state integrity:

| Interface Element | Static / Idle State | Active / Verified State | Warning / Priority State |
| :--- | :--- | :--- | :--- |
| **Brand Logo Mark** | Dark emerald-black slab + Brass cut line | Cyan LED point illuminated (`#00E5FF`) | Amber LED point illuminated (`#D97706`) |
| **Proxy Status Badge** | Charcoal + Muted slate border | Emerald green pulse (`#10B981`) | Amber alert border (`#D97706`) |
| **Receipt Inspector** | Dark slate border (`rgba(255,255,255,0.1)`) | Jazz Cyan border (`#00E5FF`) | Red error border (`#F43F5E`) |
| **Action Buttons** | Deep emerald-slate gradient (`#059669` $\rightarrow$ `#0284C7`) | Cyan highlight glow (`rgba(0, 229, 255, 0.3)`) | Amber priority gradient (`#D97706`) |

---

## 3. Forbidden Visual Moves (Anti-Slop Rules)

To preserve visual authority and accessibility across pharmacy and regulatory viewports:

1. **No Inline HTML Styles**: All presentation logic MUST be declared in semantic CSS classes in `dashboard/design-system.css`. Inline `style="..."` attributes are strictly forbidden in `index.html`.
2. **No Decorative Emojis in Action Controls**: Buttons and headers must use clean SVG icons or text labels. Emojis (e.g. `🔌`, `✨`, `🔍`) in primary actions are prohibited.
3. **No Decorative Cyan Paint**: Jazz Cyan (`#00E5FF`) must never be used as a static background gradient or idle card border.
4. **No Generic Purple Gradients**: Decorative web3 purple-to-pink gradients (`#8b5cf6`, `#ec4899`) are replaced by crisp Ice Cyan (`#38BDF8`) and Emerald (`#10B981`).

---

## 4. Typography & Spacing Hierarchy

- **Primary Headings (`h1`, `h2`, `h3`, `.panel-title`)**: `Space Grotesk`, `system-ui`, sans-serif. Weight: `600` or `700`. Letter-spacing: `-0.02em`.
- **Body & Controls (`body`, `p`, `button`, `input`)**: `Inter`, `system-ui`, sans-serif. Line-height: `1.5`. Weight: `400` / `500`.
- **Cryptographic Hashes & Receipts (`code`, `pre`, `.receipt-meta`)**: `JetBrains Mono`, `monospace`.
- **Metrics Whitespace**: Key financial numbers (Rebate totals, Patient Fund matches, Solvency ratios) must maintain at least `1.5rem` margin padding from surrounding elements to ensure instant scanning.
