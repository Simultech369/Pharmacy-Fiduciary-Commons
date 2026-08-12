# The Ledger of Omissions: Political-Economic Meaning & Policies

The `PBMRebateTreasury` contract maintains a permanent, on-chain registry of every rebate deposit (`rebateDeposits`). Equally important is the empty space: deposits absent from this voluntary ledger. A ledger absence becomes an actionable omission only when paired with independently sourced expected-deposit evidence. This is the **Ledger of Omissions**.

---

## 1. Political-Economic Meaning: Silence is Evidence

In the current pharmaceutical supply chain, Pharmacy Benefit Managers (PBMs) capture billions in manufacturer drug rebates. Because these negotiations happen behind closed, proprietary doors, this capture remains invisible. 

The Ledger of Omissions changes the default:
* **Measurable Non-Participation**: If a PBM or payer claims they pass through rebates to local communities, but has no recorded deposits in the contract for a given quarter, their non-participation is mathematically measurable on-chain.
* **Omission as Pressure**: Making the silence visible creates non-violent, anti-extractive pressure. Payers, unions, and local governments can demand that their PBMs reconcile or deposit funds into the treasury, using the absence of records as evidence of non-participation in this treasury and a basis for reconciliation inquiry.
* **Structural Accountability**: On-chain opacity is currently free for middlemen. The Ledger of Omissions makes opacity public and auditable, imposing a social and structural cost on silence.

---

## 2. Legal Guardrails: Avoiding Defamation

To maintain the project's legitimacy and protect the commons from legal harassment, the public dashboard and communications must adhere to strict guidelines:
* **Factual Records Only**: The dashboard must display only raw, verifiable facts (e.g., "0 deposits recorded from PBM X in Q1 2026"). It must never publish speculative accusations of theft, fraud, or illegal behavior.
* **Opt-in PBM Profiles**: PBMs or plans are represented by their public addresses. Labeling a public address with a real-world corporate identity must be backed by signed on-chain verification or public corporate registry filings.
* **Safe Harbor Disclaimers**: All public interfaces must feature explicit disclaimers:
  > "The absence of a deposit in this contract indicates only that no tokens were sent to this treasury address during the specified period. It does not constitute a legal claim of contract breach, regulatory violation, or financial impropriety by any party."
* **Neutral Registry Posture**: The registry is a public utility. It does not campaign, threaten, or harass; it simply logs deposits. The numbers speak for themselves.

---

## 3. Omission Taxonomy

The ledger should distinguish factual absence from possible market evasion. A missing deposit does not prove any one of these categories, but reviewers may use the taxonomy to frame reconciliation questions:

| Omission Class | Neutral Description | Evidence Needed Before Public Attribution |
| --- | --- | --- |
| **No recorded deposit** | No tokens were sent to this treasury for the period under review. | On-chain event range, contract address, chain ID, and reporting period. |
| **Delayed deposit** | Funds may have been remitted after the expected reconciliation window. | Timestamped deposits, payer/PBM notice, and period mapping. |
| **Partial deposit** | Some funds were deposited, but amount completeness is unresolved. | Deposit records plus off-chain rebate or claims basis. |
| **Relabeled value stream** | Value may have moved through administrative fees, formulary placement fees, clinical education grants, data-processing fees, network fees, or other non-rebate labels. | Contract terms, public filings, payer/PBM statements, or audited reconciliation data. |
| **Off-ledger pass-through** | A payer or PBM may have passed value through another mechanism outside this treasury. | Signed attestation, payment records, or independently auditable reporting. |
| **Unverifiable or legally constrained disclosure** | Data is missing because records are unavailable, confidential, disputed, or legally constrained. | Availability metadata, redaction policy, and reason code. |

Public dashboards should present these as reconciliation categories, not accusations.
