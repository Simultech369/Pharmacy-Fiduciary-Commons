# Commons Capture Risks

This document tracks, assesses, and outlines mitigations for the structural capture risks facing the Pharmacy Fiduciary Commons.

---

## 1. Council Capture (Multisig Compromise)
* **Risk**: 3 of the 5 Council signers collude or are compromised, gaining the ability to pause the system indefinitely, sanction arbitrary pharmacies, or publish fraudulent Merkle roots.
* **Mitigation**: Signers must use independent hardware wallets, reside in different jurisdictions, and rotate annually. The `GUARDIAN_ROLE` is held by a separate, fast-acting address that can freeze operations (`pause`) but cannot access funds, allowing the community time to coordinate.

## 2. PBM Legal Pressure
* **Risk**: PBMs use legal threats, cease-and-desist letters, or antitrust claims to intimidate independent pharmacies or Council members from participating in the commons.
* **Mitigation**: Use a decentralized, open-source organization model. Frame the treasury strictly as a neutral public utility registry that registers public deposits, avoiding corporate targeting in favor of mathematical transparency.

## 3. Fake Pharmacy Claims
* **Risk**: Malicious actors deploy contracts mimicking pharmacy addresses, submit fake proofs of dispensing, and successfully claim rebate allocations.
* **Mitigation**: Double-hash leaf verification on-chain (`claim` requires valid Merkle proofs). The off-chain root generation scripts verify every pharmacy address against state licensing registries and active NCPDP credentials.

## 4. Patient-Fund Favoritism
* **Risk**: Council members or donors direct Patient Fund grants to friendly projects or affiliated organizations.
* **Mitigation**: Remove Council discretion over funding direction. The Council acts only as an eligibility/fraud gate. Actual allocations must be determined by community small-dollar votes amplified by Quadratic Funding (QF) matching.

## 5. Donor Capture
* **Risk**: Large depositors or philanthropic donors demand governance control or custom allocation rules in exchange for funding the treasury.
* **Mitigation**: The smart contract is non-upgradeable and rules are locked. The 99/1 split is hardcoded. Donors can deposit funds, but they cannot buy votes, influence signers, or alter on-chain distributions.

## 6. Governance Reserve Misuse
* **Risk**: The 1% governance reserve is spent on excessive administration, high legal fees, or non-essential operations.
* **Mitigation**: Expose all governance reserve withdrawals on-chain (`withdrawGovernanceReserve` emits public events). Require the Council to publish plain-language expense reports matching the on-chain withdrawals.

## 7. Dashboard Metric Capture
* **Risk**: The project team optimizes for total value locked (TVL) or deposit volume, shifting focus from pharmacy health to speculative growth (startup logic).
* **Mitigation**: Gating rules require that the dashboard prioritizes metrics such as: patient assistance delivered, number of independent pharmacies supported, and regional access gaps closed.

## 8. Quadratic Funding Sybil Attacks
* **Risk**: Attackers create multiple fake patient accounts to vote on projects, artificially inflating matching ratios in QF rounds.
* **Mitigation**: Require proof-of-humanity credentials (e.g. Gitcoin Passport, local community verification) to vote in matching rounds, and apply math-based Sybil dampening (like Connection-Oriented Cluster Matching) to the matching algorithm.

## 9. Over-Centralized Merkle Root Authority
* **Risk**: A single off-chain script creates the Merkle root, making the system dependent on one computer or developer.
* **Mitigation**: Open-source the root generation scripts. Require at least two separate Council members to independently run the generator and confirm the root matches on-chain before co-signing (`proposeRoot` and `confirmRoot` distinct signer requirement).

## 10. Relayer Verifier Trust Root
* **Risk**: The participatory budgeting self-registration flow depends on a Council-selected `relayerVerifier`. If that key is compromised or operated without transparent eligibility rules, it can register ineligible voters or exclude eligible advocates.
* **Mitigation**: Treat the verifier as a bounded testnet/prototype trust root until it has key rotation, public eligibility criteria, signed credential provenance, and an appeal path. Council should rotate the verifier immediately after suspected compromise.
