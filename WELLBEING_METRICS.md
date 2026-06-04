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

To maintain an anti-extractive operational posture, the system enforces the following mathematical constraints:

- **Administrative Capture Limit**: The total amount of captured fees diverted to administrative maintenance or hosting costs must never exceed **15%** of the total matching pool in any given epoch.
  $$Fees_{\text{admin}} \leq 0.15 \times Pool_{\text{matching}}$$
- **Minimum Drug Discount Spread**: The average discount achieved across key index drugs (e.g. Lipitor, Crestor) must remain at or above **10%** relative to local PBM pharmacy pricing.
  $$S_{coop} \geq 0.10$$

---

## 4. Automated Review Triggers

If any of the following triggers are tripped, the system pauses automatic surplus allocations and flags an epoch exception:

1. **Admin Overhead Exception**: If $Fees_{\text{admin}} > 15\%$ for a finalized epoch, the contract will refuse matching round distributions until the council logs a manual adjustment or executes a fee-reduction patch.
2. **Savings Dispersion Drop**: If the cooperative savings spread ($S_{coop}$) falls below **10%** for 3 consecutive epochs, the system triggers a mandatory review loop in Dizzy to evaluate wholesale catalog pricing lists and flag potential cartel pricing.
3. **Sybil Vote Concentration**: If any project receives more than **80%** of its votes from accounts registered within the same 24-hour window, the voting round is put on hold to investigate voter credential collusion.
