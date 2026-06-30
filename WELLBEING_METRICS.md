# WELLBEING_METRICS.md
Calculation rules, audit thresholds, and triggers for surplus allocations in the Pharmacy Fiduciary Commons.

---

## 1. Metric Framework

Rather than evaluating the system using financial abstractions (like token price, total value locked, or transactional volume), the commons evaluates itself using concrete wellbeing metrics.

Surplus allocations are routed strictly to reduce precarity and lower the cost of essential maintenance and preventative care.

---

## 2. Calculation Rules

### Patient Fund Matching Ratio ($R_m$)
The proportion of community funds routed to patient health projects vs. administrative fees.

$$R_m = \frac{\sum Payouts_{\text{health}}}{\sum Fees_{\text{admin}}}$$

### Cooperative Procurement Savings ($S_{coop}$)
The percentage discount achieved by purchasing drugs through the cooperative procurement layer (P-02) compared to PBM wholesale pricing.

$$S_{coop} = 1 - \frac{\sum Cost_{\text{cooperative}}}{\sum Cost_{\text{wholesale}}}$$

---

## 3. Mathematical Audit Thresholds

To maintain an anti-extractive operational posture, operators evaluate the following audit thresholds:

- **Administrative Capture Limit**: The total amount of captured fees diverted to administrative maintenance or hosting costs must never exceed **15%** of the total matching pool in any given epoch.
  $$Fees_{\text{admin}} \leq 0.15 \times Pool_{\text{matching}}$$
- **Minimum Drug Discount Spread**: The average discount achieved across key index drugs (e.g. Lipitor, Crestor) must remain at or above **10%** relative to local PBM pharmacy pricing.
  $$S_{coop} \geq 0.10$$

---

## 4. Review Triggers

These are policy triggers, not executable contract controls at this checkpoint. If any trigger is tripped, operators should pause automatic surplus allocations, record an evidence packet, and flag an epoch exception through the governance process. A future implementation should add a `tools/wellbeing/audit.mjs` script and explicit contract or runbook hooks before representing these checks as automated.

1. **Admin Overhead Exception**: If $Fees_{\text{admin}} > 15\%$ for a finalized epoch, council should log a manual adjustment, fee-reduction patch, or explicit waiver before continuing surplus allocations.
2. **Savings Dispersion Drop**: If the cooperative savings spread ($S_{coop}$) falls below **10%** for 3 consecutive epochs, the council should open a review loop, publish the pricing-list evidence packet, and document whether Dizzy was used as an advisory analysis layer.
3. **Sybil Vote Concentration**: If any project receives more than **80%** of its votes from accounts registered within the same 24-hour window, operators should pause the affected voting round until credential-collusion evidence is reviewed.
