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

## 3. Participatory Budgeting & Quadratic Funding (QF)

To prevent centralized control, the Patient Fund is allocated via a participatory matching model:
* **Submissions**: Pharmacies, community organizations, and patients submit local projects, medication needs, or service expansions.
* **Small-Dollar Voting**: Community members vote on proposed projects using small-dollar contributions or verifiable credentials.
* **Quadratic Matching**: The Patient Fund acts as a matching pool that amplifies projects based on the *number* of unique supporters rather than the amount of money raised.
* **Council Role**: The Council acts strictly as an eligibility and fraud gate (e.g., verifying that a project does not violate medical safety laws). The Council cannot direct matching funds or override community votes.
* **Deadlines & Circulation**: Unallocated funds cannot accumulate indefinitely. Idle funds beyond 90 days are automatically rolled into the next PB/QF round.

---

## 4. Ecological & Resource Efficiency Primitives

Projects must align with resource-efficient, low-waste health access. Eligible projects include:
* **Medication Waste Reduction**: Digital tracking and exchange systems to prevent shelf expiration and recover unopened medications.
* **Cold-Chain Efficiency**: Solar-powered medical refrigeration for local pharmacies to preserve temperature-sensitive drugs without grid reliance.
* **Local Delivery Route Efficiency**: Shared, low-carbon delivery logistics for bringing medications to homebound patients in rural areas.
* **Pharmacy Energy Resilience**: Small-scale solar + storage systems for independent pharmacies to maintain cooling and operations during climate disasters.
* **Safe Disposal Programs**: Community drug take-back boxes and eco-friendly disposal kits to keep active pharmaceuticals out of local water systems.
* **Low-Waste Refill Logistics**: Transitioning to bulk refill dispensing and reusable container packaging where permitted by health codes.
* **Disaster-Resilient Medication Access**: Pre-positioned emergency medicine supplies and secure mobile pharmacy units for deployment during severe weather events.
