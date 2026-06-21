# Draft Constitutional Audit Report v0.1

*Status: Draft Review. This report maps the Pharmacy Fiduciary Commons codebase to the principles defined in `COMMONS_CONSTITUTION.md` to identify gaps and design flaws.*

---

## 1. Codebase Alignment Analysis

This section analyzes the structural implementation of the smart contracts against the ten constitutional principles, identifying specific contract functions and active gaps.

### 1.1 No Permanent Sovereign
* **Code References**: `contracts/OZTimelockControllerImport.sol`, `contracts/PBMRebateTreasury.sol`
* **Status**: **Partial protocol-enforced alignment**.
* **Analysis**:
  * Role separation between `COUNCIL_ROLE` (proposer of roots) and `ROOT_CONFIRMER_ROLE` (verifier of roots) is contract-enforced in `PBMRebateTreasury.sol`.
  * The `GUARDIAN_ROLE` holds pause capabilities but is blocked from unpausing or claiming, enforcing emergency separation.
* **Gaps**:
  * Timelocks and role splits do not ensure replaceability of the trust root.
  * The annual nominations, signer elections, and removal petitions (requiring a 10% threshold) defined in `GOVERNANCE.md` are **docs-only**. No smart contract logic allows credentialed participants to execute a signer rotation or revoke a compromised council key.

### 1.2 Subsidiarity
* **Code References**: `contracts/PharmacyMutualCredit.sol`
* **Status**: **Aspirational / Gapped**.
* **Analysis**:
  * `PharmacyMutualCredit.sol` allows peer-to-peer credit transfers and voucher redemption.
* **Gaps**:
  * All credit limits (`updateCreditLimit`) and authorized voucher issuers (`updateIssuerStatus`) are managed by the global `COUNCIL_ROLE`. 
  * There is no local autonomy: a local federation cannot set its own credit constraints, approve its own local emergency issuers, or partition its liabilities from the global registry.

### 1.3 Socialized Surplus, Not Socialized Loss
* **Code References**: `contracts/PBMRebateTreasury.sol` (reserves partitioning)
* **Status**: **Partially protocol-enforced**.
* **Analysis**:
  * The contract divides rebate inflows strictly: 99% to the distribution pool/escrow and 1% to the governance reserve.
  * `exclusionRemediationReserve` is explicitly funded via `fundExclusionRemediation` and is the *only* source of funds for approved exclusion claims, preventing old errors from depleting active pools.
* **Gaps**:
  * The broader promise that experimental features or governance failures will not shift losses to pharmacies and patients is not contract-enforced.

### 1.4 Stale Recovery Liveness (Known Design Risk)
* **Code References**: `contracts/PBMRebateTreasury.sol#L1093` (`recoverStaleDistributionPool`)
* **Status**: **Known tested design risk**.
* **Analysis**:
  * If unallocated distribution funds sit inactive for 180 days, the `Executor` can recover them to the `patientFund` to prevent permanent locks.
* **Gaps**:
  * Any caller can deposit `1 wei` to reset `lastDepositTimestamp`, restarting the 180-day delay. This allows cheap, malicious denial-of-liveness attacks on stale pool recovery.

### 1.5 Forkability and Portability
* **Code References**: `scripts/export-portability.js`, `scripts/verify-export.js`
* **Status**: **Tool-supported prototype**.
* **Analysis**:
  * The scripts extract and verify claims, Merkle proofs, and votes locally.
* **Gaps**:
  * Portability is entirely dependent on off-chain JSON tools. The smart contracts contain no mechanisms to recognize or interoperably migrate state to a federated fork.

### 1.6 Anti-Plutocracy
* **Code References**: `contracts/PatientFundParticipatoryBudgeting.sol`
* **Status**: **Partially protocol-enforced**.
* **Analysis**:
  * Payout matching weights use approval counts rather than token size.
* **Gaps**:
  * Aggracted project votes are squared for payout weighting (`castVote` increments approval count, and finalization squares it). While non-token-weighted, this approval system amplifies majorities and does not intrinsically prevent minority project exclusion.

### 1.7 Contestable Identity
* **Code References**: `contracts/PBMRebateTreasury.sol#L1208` (`appealSanction`)
* **Status**: **Partial protocol support + unimplemented procedure**.
* **Analysis**:
  * Any sanctioned account can submit a string reason to log an appeal on-chain.
* **Gaps**:
  * Credential revocation (managed off-chain or by the credential relayer key) has no general appeal mechanism.
  * The 14-day review timeout and the requirement to lift or sustain sanctions are documented in `GOVERNANCE.md` but are not enforced in contract code.

### 1.8 Legible Power
* **Code References**: Events (`ClaimResolved`, `SanctionUpdated`, etc.)
* **Status**: **Partially protocol-enforced**.
* **Analysis**:
  * Core state modifications emit events detailing the actor and transaction parameters.
* **Gaps**:
  * Events show the *outcome* of power, not the *evidence* behind it. `ClaimResolved` and `SanctionUpdated` do not bind or store cryptographic hashes of the audit evidence, NCPDP logs, or Council meeting rationales.

### 1.9 Bounded Experimentation
* **Code References**: `contracts/PBMRebateTreasury.sol#L1130` (`reduceHardCap`)
* **Status**: **Partially protocol-enforced**.
* **Analysis**:
  * Enforces caps on daily and absolute epoch volumes.
* **Gaps**:
  * Caps are manual administrative parameters; they are not bound to live pharmacy transaction metrics or external sandboxes.

### 1.10 The Protocol is Not the Community
* **Code References**: `WELLBEING_METRICS.md`
* **Status**: **Aspirational / interpretive**.
* **Analysis**:
  * Metrics define real-world benchmarks (pricing spreads, matching ratios) to evaluate institutional success.
* **Gaps**:
  * No concrete procedure or code currently implements these checks; the wellbeing CLI auditor script is absent.

---

## 2. Participant Co-Authorship & Ratification Pathways

To transition `COMMONS_CONSTITUTION.md` from a draft proposal to a legitimate governance covenant, we outline three potential ratification pathways:

1. **Credential-Gated Referendum**:
   * Leverage the existing `PatientFundParticipatoryBudgeting.sol` infrastructure to hold a ratification vote.
   * Registered participant pharmacies and patient advocates vote to approve the text.
2. **Multi-Sig Cooperative Signing**:
   * Require Council members and representatives from independent pharmacy cooperatives to execute a multi-signature transaction binding their addresses to the IPFS hash of the ratified constitution.
3. **Consensus Forking**:
   * If a subgroup disagrees with the draft, their right to fork the scripts and contracts is protected, allowing them to redeploy a separate federation with a modified constitution.

---

## 3. Unresolved Ideological Disagreements

Two core governance tensions remain active and unresolved:

### 3.1 Advisory vs. Algorithmic AI Arbitration
* **Disagreement**: Should the off-chain advisory layer (*Dizzy the Polymath*) remain strictly advisory, or should its findings be programmatically bound to the smart contracts?
* **Tension**: 
  * If strictly advisory, the Council retains execution authority and can ignore findings, risking administrative capture.
  * If programmatically bound, we risk delegating authority to unappealable, opaque algorithmic models, violating the *Contestable identity* and *No permanent sovereign* principles.

### 3.2 Public Ledger Transparency vs. Corporate Retaliation
* **Disagreement**: Should the system record stable, searchable participant credential hashes, or should it prioritize absolute privacy?
* **Tension**:
  * Stable hashes are required to prevent double-claiming and verify duplicate voter registration.
  * However, stable hashes allow payers (PBMs) to profile and retaliate against independent pharmacies that join the commons. Resolving this requires evaluating zero-knowledge nullifiers which add implementation complexity.
