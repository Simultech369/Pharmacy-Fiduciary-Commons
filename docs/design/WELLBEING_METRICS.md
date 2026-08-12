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

---

## 5. Multi-Dimensional Complexity of Value Indicators

To avoid the pitfalls of hyper-optimizing for simple, single-dimensional proxies (Goodhart's Law), the Commons tracks the following non-reductive indicators:

### Medication Access Precarity Index (MAPI)
* **Definition**: A multi-dimensional measure of a patient's risk of access disruption, incorporating credit capacity constraints, pharmacy proximity, and historical formulary shifts.
* **Calculation**:
  $$MAPI_i = 1 - \left( \frac{\text{CreditAvailable}_i}{\text{AvgMonthlyDrugCost}_i} \times \text{PharmacyDensity}_i \times (1 - \text{PastFormularyShifts}_i) \right)$$
* **Usage**: Guides the Council in prioritizing credit expansions to pharmacies in high-precarity areas, prioritizing patient safety over credit ledger optimization.

### Systemic Trust Dispersion (STD)
* **Definition**: Evaluates the diversity of cooperative voting behaviors across participating entities to check for sybil correlation.
* **Calculation**: Measures the cosine similarity of voting vectors across registered accounts. An STD near 1 indicates diverse, independent consensus; an STD near 0 indicates tight, coordinated collusion.
* **Usage**: Triggers matching-subsidy penalties when collusion is detected.

### Cooperative Liquidity Balance (CLB)
* **Definition**: Assesses whether the mutual credit ledger behaves as a positive-sum clearing network rather than a zero-sum, extractive system.
* **Calculation**: The velocity of voucher redemptions relative to outstanding capacity.
* **Usage**: Ensures that the ledger is facilitating trade and care continuity, rather than hoarding or credit stagnation.
