# External Reviewer & Collaborator Guide

Pharmacy Fiduciary Commons is an open-source, on-chain rebate accounting and patient fund prototype designed to bring transparency to pharmaceutical supply chains.

> **Primary Review Boundary**
> Pharmacy Fiduciary Commons is a **tested prototype seeking external collaborator review**. It is **not audited**, **not deployed to mainnet**, **not production-ready**, and must not be used with real funds, real PHI, or real pharmacy credentials.

---

## 1. What This Does

* **Quarterly Rebate Settlement**: Transparent escrow allocation for manufacturer rebates with administrative fee caps and non-reentrant distribution pools ([`contracts/PBMRebateTreasury.sol`](../../contracts/PBMRebateTreasury.sol)).
* **Participatory Budgeting**: Quadratic matching calculations for community patient funds with explicit solvency debt tracking ([`contracts/PatientFundParticipatoryBudgeting.sol`](../../contracts/PatientFundParticipatoryBudgeting.sol)).
* **Mutual Credit Network**: Bilateral credit lines with rolling 24-hour clearing caps for independent pharmacy networks ([`contracts/PharmacyMutualCredit.sol`](../../contracts/PharmacyMutualCredit.sol)).
* **Client Witness Isolation**: Prototype witness-input adapter that recursively strips side-channel metadata, normalizes field elements, and blocks known client-side leakage fields ([`tools/zk/ClientWitnessAdapter.js`](../../tools/zk/ClientWitnessAdapter.js)).
* **Multi-Layer Verification**: A 10-step master verification command that validates test suites, local gates, and claim grounding for release-candidate checkpoints ([`scripts/verify_all.py`](../../scripts/verify_all.py)).

---

## 2. What This Does Not Claim

* **No Mainnet Readiness**: We make no claim of production deployment or economic security on public networks.
* **No Audit Sign-Off**: The repository includes local static-analysis and verification artifacts where available, but these do not replace an independent third-party audit.
* **No Live Patient Data (PHI)**: Test fixtures and dashboard examples are for synthetic demonstration only and must not contain real patient records, pharmacy credentials, or claims logs.
* **No Complete Unlinkability**: Client-side witness sanitization does not solve relayer network privacy, gas payer linkage, or timing correlation.
* **No Autonomous External Authority**: Automated agent reviews (e.g., Council Engine, Codex, Kimi) are local heuristic review aids, not legal or fiduciary authorities.

---

## 3. How To Verify Locally

Reviewers should always verify claims against local execution truth.

```bash
# 1. Install dependencies
npm install

# 2. Run Hardhat unit & state machine tests (438 tests)
npx hardhat test

# 3. Build dashboard and run Brand Gate B visual governance check
npm run build:dashboard
npm run check:frontend

# 4. Check prototype readiness and run privacy leak scanner
npm run check:readiness -- --env local
python scripts/privacy_leak_scanner.py

# 5. Run the master verification pipeline
python scripts/verify_all.py
```

A clean pass outputs `MASTER VERIFICATION RESULT: PASSED (10 / 10)` and writes a local receipt to `cache/verification_master_receipt.json` [generated cache].

---

## 4. Dedicated Review Lanes

We invite feedback and independent scrutiny across five key lanes:

### Lane 1: Solidity & Treasury Invariants
* **Key Targets**: [`contracts/PBMRebateTreasury.sol`](../../contracts/PBMRebateTreasury.sol), [`contracts/PatientFundParticipatoryBudgeting.sol`](../../contracts/PatientFundParticipatoryBudgeting.sol).
* **Questions to Explore**:
  * Does `flagClaim()` or `resolveClaim()` introduce potential escrow lockouts or race conditions?
  * Does `_syncSolvencyDebt()` preserve the documented solvency-debt behavior under round deficit scenarios [committed HEAD]?
  * Are AccessControl role grants properly partitioned between `COUNCIL_ROLE`, `ROOT_CONFIRMER_ROLE`, and `EXECUTOR_ROLE`?

### Lane 2: ZK & Privacy Boundaries [committed HEAD]
* **Key Targets**: [`tools/zk/ClientWitnessAdapter.js`](../../tools/zk/ClientWitnessAdapter.js), [`test/ClientWitnessAdapter.test.js`](../../test/ClientWitnessAdapter.test.js).
* **Questions to Explore**:
  * Does the adapter thoroughly reject forbidden metadata keys and nested network side-channels?
  * Are BN254 scalar field inputs properly bounded below the prime order $r$?
  * What additional off-chain leakage risks persist at the relayer/bundler level?

### Lane 3: Public Documentation & Claim Grounding
* **Key Targets**: [`README.md`](../../README.md), [`ONBOARDING.md`](../../ONBOARDING.md), [`SECURITY.md`](../../SECURITY.md), [`NEXT.md`](../../NEXT.md).
* **Questions to Explore**:
  * Are prototype boundaries and non-claims stated plainly without ambiguity?
  * Do any descriptions overstate system maturity or imply production readiness [external reviewer claim]?

### Lane 4: Dashboard Accessibility & Governance
* **Key Targets**: [`dashboard/index.html`](../../dashboard/index.html), [`dashboard/design-system.css`](../../dashboard/design-system.css).
* **Questions to Explore**:
  * Does the interface meet WCAG 2.4.1 keyboard bypass and focus navigation standards?
  * Are synthetic demonstration labels unmistakable across all panels?
  * Does the CSS strictly comply with Brand Gate B (zero inline styles)?

### Lane 5: Dependency Migration Review
* **Key Targets**: `package.json`, deferred Dependabot branches (`openzeppelin/contracts-5.6.1`, `hardhat-3.9.0`).
* **Questions to Explore**:
  * What breaking storage layout or API changes occur when transitioning to OpenZeppelin v5?
  * What test fixtures need migration before updating Hardhat?

---

## 5. Known Launch Blockers

The following items are formal launch blockers that must be resolved prior to any production deployment [committed HEAD]:

1. **Independent Third-Party Security Audit**: Formal human audit of contracts, access controls, and settlement math.
2. **Relayer & Network Privacy Architecture**: Production-grade relayer infrastructure to address gas payer and IP correlation for ZK claims [external reviewer claim].
3. **Decentralized Governance Timelock Calibration**: Production multisig ceremony and timelock parameter formalization [external reviewer claim].
4. **Dependency Migration**: Upgrading to OpenZeppelin v5 and Hardhat v3 with full regression coverage.

---

## 6. How To Submit Feedback

* **Public Findings**: Submit via GitHub Issues using the appropriate [issue template](../../.github/ISSUE_TEMPLATE/).
* **Security Disclosures**: For sensitive or critical vulnerabilities, consult [`SECURITY.md`](../../SECURITY.md).
