# Wellbeing Metrics & Accountability

This document defines the metrics discipline for the Fiduciary Rebate Commons. The goal is to prioritize actual human health access, pharmacy resilience, and ecological resource efficiency over financial scale, total volume, or treasury TVL (Total Value Locked).

---

## 1. Core Health Access Metrics

These metrics quantify the direct preventative and stabilizing impact of the rebate commons on patient well-being and access legibility.

| Metric | Definition | Target / Benchmark | Adjudication Method |
| :--- | :--- | :--- | :--- |
| **Patients Assisted** | Number of unique patients receiving direct co-pay assistance, preventative care support, or matching patient fund subsidies. | Maximize coverage in designated care deserts. | Audited claim logs matched to patient fund disbursements. |
| **Access Gaps Closed** | Number of pharmacy care-deserts (regions with zero independent pharmacies within a 10-mile radius) resolved or stabilized. | Zero care-desert growth; stabilization of at-risk pharmacies. | Public geographic access mapping cross-referenced with active pharmacies. |
| **Preventative Care Rate** | Percentage of matches/disbursements directed to chronic disease prevention (e.g. insulin, cardiovascular care) vs. downstream crisis intervention. | > 70% preventative allocation. | Categorized match allocations under the participatory matching rounds. |

---

## 2. Pharmacy Resilience Metrics

Independent pharmacies are the critical physical infrastructure of the health commons. These metrics track their operational viability and protection from extractive PBM behaviors.

| Metric | Definition | Target / Benchmark | Adjudication Method |
| :--- | :--- | :--- | :--- |
| **Pharmacies Supported** | Number of unique independent pharmacies receiving rebate distributions and matched match funds per epoch. | Growth or stability in participant count. | Validated Merkle claims and matching participant registrations. |
| **Surplus Retention Rate** | Percentage of the total rebate surplus retained by local pharmacies and patients vs. captured by intermediate brokers. | > 99% retained locally (90/10 split on claimed rebates). | On-chain audit of treasury inflow vs. final pharmacy payout. |
| **Dispute Resolution Speed** | Average time (in days) to resolve `flagExclusion` root omission disputes and normal claim challenges. | < 14 days from dispute filing to Council resolution. | Epoch contract timestamps comparing `flagClaim`/`flagExclusion` to `resolveClaim`. |

---

## 3. Transparency & Omissions Visibility

Accountability requires making extraction visible. These metrics track PBM non-participation and omission frequencies.

- **Omitted Surplus Volume**: Estimated dollar amount of rebate surplus retained by PBMs due to non-participation, calculated via public dispensing price benchmarks.
- **Omission Ledger Accuracy**: Factual consistency of deposit timestamps and root data entries, checked each epoch.
- **Disputed Omissions Rate**: Ratio of validated on-chain exclusion disputes (`flagExclusion`) successfully resolved to `RELEASE_TO_PHARMACY` vs. dismissed, measuring Merkle root accuracy.

---

## 4. Operational Overhead & Admin Ratio

To prevent the commons from becoming a self-serving administration or manager-heavy structure, we enforce a strict overhead cap.

- **Administrative Ratio**:
  $$\text{Admin Ratio} = \frac{\text{Governance Payouts}}{\text{Total Rebates Distributed}} \times 100$$
  - **Hard Cap**: Enforced by the smart contract's `governanceBP` (maximum 5% parameter limit, default 1%).
  - **Target**: < 2% of total rebate volume directed to Council/governance operations.

---

## 5. Preventative Ecological Metrics

As defined in the [Patient Fund Policy](file:///C:/Users/Josh/.gemini/antigravity/scratch/Pharmacy-Fiduciary-Commons/PATIENT_FUND_POLICY.md), ecological and resource-efficiency metrics are mapped directly to matching eligibility:

1. **Medication Waste Reduction**: Volume/weight of unused or expired medications diverted from municipal waste streams via verified disposal and low-waste logistics.
2. **Cold-Chain Efficiency**: Percentage of refrigerated shipments using reusable, high-efficiency insulation packages vs. single-use styrofoam.
3. **Local Route Optimization**: Estimated carbon reduction achieved through coordinated local medication deliveries and route-efficiency algorithms.
4. **Pharmacy Energy Resilience**: Share of participant pharmacies powered by local solar, wind, or high-efficiency microgrids.
5. **Safe Disposal Compliance**: Rate of patient participation in pharmacy-hosted take-back programs.
6. **Low-Waste Refill Logistics**: Share of recurring prescriptions dispensed via multi-month or low-packaging options.
7. **Disaster-Resilient Access**: Percentage of matching funds pre-allocated to emergency off-grid backup systems for temperature-sensitive medication storage.
