# Patient Fund Policy

The Patient Fund is an on-chain, community-directed treasury designed to fund preventative health projects, protect medication access, and stabilize local pharmacy infrastructure.

---

## 1. Preventative Economics

The fund operates on the principle that keeping people healthy and providing access to medically necessary care prevents downstream crisis costs (hospitalization, emergency room visits) and keeps community pharmacy infrastructure viable. 

---

## 2. Funding Sources

The Patient Fund accumulates resources from:
1. **Gross Claim Routing**: 10% of every gross rebate claim (`patientClaimBP`) is automatically routed to the `patientFund` at claim time.
2. **Unclaimed Recall**: 100% of unclaimed epoch funds are recalled to the `patientFund` after the 30-day delay.
3. **Non-Payout Sweep**: 100% of non-payout ERC-20 tokens swept from the contract are directed to the `patientFund`.

---

## 3. Participatory Budgeting & Squared Vote Weighting

To prevent centralized control, the Patient Fund is allocated via a participatory matching model:
* **Submissions**: Pharmacies, community organizations, and patients submit local projects, medication needs, or service expansions.
* **Credential-Gated Voting**: Registered community members cast one vote per project.
* **Squared Vote Weighting**: The prototype allocates the matching pool in proportion to each project's squared vote count. It is not canonical contribution-based quadratic funding.
* **Council Role**: The Council acts strictly as an eligibility and fraud gate (e.g., verifying that a project does not violate medical safety laws). The Council cannot direct matching funds or override community votes.
* **Deadlines & Circulation**: Finalized project shares are claimable by the project recipient for a 90-day grace period. After that deadline, the Council may reclaim unclaimed shares into an internal recycled matching pool that is automatically applied to the next round. This makes a finalized share a deadline-bounded claim, not a perpetual debt, while keeping reclaimed funds inside participatory budgeting rather than council custody.

---

## 4. Anti-Sybil and Identity Requirements

Squared vote weighting is vulnerable to Sybil attacks because fake identities can distort project vote counts. The prototype therefore applies the following identity checks to voting eligibility:
- **Verifiable Pharmacy/Advocate Credentials**: All voting entities must present a verifiable credential indicating active licensing, community advocate status, or verified enrollment in a local health access program.
- **Unique Patient Attestations**: Patient voters must present a unique cryptographically signed attestation (e.g. proof of unique patient ID or advocate attestation) without revealing medical history.
- **Dispensing Receipt Matching**: Votes may be weighted or validated by matching them to verified dispensing receipt hashes from the Omission Ledger, ensuring that participation is linked to real, physical health-access interactions.

---

## 5. Prohibited Uses

To protect the legitimacy and fiduciary integrity of the commons, the Patient Fund is subject to strict spending exclusions. **Under no circumstances shall fund assets be used for:**
- **Lobbying and Political Activity**: Direct or indirect funding of political campaigns, candidate PACs, or government lobbying.
- **Administrative Salaries**: Executive compensation or staff payroll for Council operations (these are strictly capped and funded separately under the 1% Governance Reserve).
- **Marketing and Promotion**: Brand advertising, corporate public relations, or promotional campaigns.
- **Speculative Investments**: Yield-farming, lending protocols, highly volatile tokens, or other speculative financial instruments. All assets must remain in stable coins (DAI/USDC) or cash-equivalent vaults.
- **Rebate Arbitrage**: Buying back debt or engaging in transactional rebate extraction schemes.

---

## 6. Ecological & Resource Efficiency Primitives

Projects must align with resource-efficient, low-waste health access. Eligible projects include:
* **Medication Waste Reduction**: Digital tracking and exchange systems to prevent shelf expiration and recover unopened medications.
* **Cold-Chain Efficiency**: Solar-powered medical refrigeration for local pharmacies to preserve temperature-sensitive drugs without grid reliance.
* **Local Delivery Route Efficiency**: Shared, low-carbon delivery logistics for bringing medications to homebound patients in rural areas.
* **Pharmacy Energy Resilience**: Small-scale solar + storage systems for independent pharmacies to maintain cooling and operations during climate disasters.
* **Safe Disposal Programs**: Community drug take-back boxes and eco-friendly disposal kits to keep active pharmaceuticals out of local water systems.
* **Low-Waste Refill Logistics**: Transitioning to bulk refill dispensing and reusable container packaging where permitted by health codes.
* **Disaster-Resilient Medication Access**: Pre-positioned emergency medicine supplies and secure mobile pharmacy units for deployment during severe weather events.
