# Pharmacy Fiduciary Commons

<div align="center">

**On-chain rebate transparency infrastructure for independent pharmacies and patient funds.**

![CI](https://github.com/Simultech369/Pharmacy-Fiduciary-Commons/actions/workflows/test.yml/badge.svg)
![Audit](https://img.shields.io/badge/audit-not%20audited-dc2626?style=for-the-badge)
![Mainnet](https://img.shields.io/badge/mainnet-not%20deployed-6b7280?style=for-the-badge)
![Solidity](https://img.shields.io/badge/solidity-0.8.20-363636?style=for-the-badge&logo=solidity)
![Node](https://img.shields.io/badge/node-20%20%7C%2022-339933?style=for-the-badge&logo=node.js&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)

</div>

> [!CAUTION]
> **NOT AUDITED - DO NOT USE REAL FUNDS YET**
>
> This repository is a working local/testnet prototype. Do not deploy, deposit, or route real capital to this treasury on mainnet until an independent security audit has been completed and published.

---

## What This Cannot Do (Adversarial Limitations & Disclaimers)

> [!WARNING]
> **This system is a smart contract prototype for rebate accounting and custody. It does NOT solve physical supply chain problems:**
> * **No Physical Medicine or Inventory Guarantees:** This protocol records accounting entries and custody movements. It does not track, verify, or guarantee physical inventory, drug availability, delivery, pharmacy stock, clinical outcomes, or patient access. On-chain actions do not guarantee physical medicine supply or pharmacy fulfillment.
> * **Mutual Credit Vouchers = Ledger Reservations Only:** Mutual credit vouchers create ledger capacity reservations only — they do not represent or guarantee physical medicine on-chain, and they do not bypass local supply shortages or distributor caps.
> * **Mutual Credit Clearing ≠ Guaranteed Supply:** The mutual credit clearing mechanism operates as a liquid accounting framework for settlements and liquidity support between pharmacies. It does not guarantee physical supply, logistics, or distribution capacity.
> * **Scarcity Triage = Proposed Only:** Scarcity-based triage policies and design proposals are theoretical frameworks. They are not executed autonomously on-chain or enforced by smart contracts.
> * **Centralized Governance Control:** The `COUNCIL_ROLE` retains significant administrative control. Autonomy is restricted to off-chain governance and multi-sig operations; there is no autonomous on-chain local federation execution.
> * **Privacy and Linkage Risks:** Legacy registration still uses stable credential hashes on-chain, creating a persistent identification vector that could be used for profiling or blacklisting. A mock ZK/nullifier registration slice now exists for semantic testing in `PatientFundParticipatoryBudgeting`, but it is not production privacy: `msg.sender`, public voting events, transaction gas source, timing, and RPC metadata remain linkable. The production zk-nullifier design in [IDENTITY_NULLIFIER_DESIGN.md](IDENTITY_NULLIFIER_DESIGN.md) remains a design specification only.
> * **Participatory Budgeting Solvency Debt (Liveness & Trust Risk):** The contract no longer hard-reverts when round start/finalization finds the patient-fund balance below outstanding obligations. It records the shortfall as `totalDebt`/`roundDeficit` and lets the round lifecycle continue, but actual project claims still require real token liquidity. Council or donor top-ups remain necessary to clear debt and make underbacked shares claimable.
> * **No Professional Advice:** All outputs, files, and dashboards are for local prototype demonstration only. None of the contents constitute legal, financial, or medical advice.
>
> For deeper documentation on safety, scarcity, and threat boundaries, see [SCARCITY_GOVERNANCE.md](SCARCITY_GOVERNANCE.md), [CARE_CONTINUITY.md](CARE_CONTINUITY.md), and [RETALIATION_AND_PRIVACY_THREAT_MODEL.md](RETALIATION_AND_PRIVACY_THREAT_MODEL.md).

---

## Status Summary

The current checkpoint is a prototype with tested treasury, voting, mutual-credit, portability, and dashboard surfaces, but it is not audited, not mainnet deployed, and not public-wallet ready. Runtime behavior and policy boundaries are tracked in [MECHANISM_COVERAGE.md](MECHANISM_COVERAGE.md); care-continuity and participant-safety boundaries are documented in [CARE_CONTINUITY.md](CARE_CONTINUITY.md), [RETALIATION_AND_PRIVACY_THREAT_MODEL.md](RETALIATION_AND_PRIVACY_THREAT_MODEL.md), and [SCARCITY_GOVERNANCE.md](SCARCITY_GOVERNANCE.md). Public launch remains blocked by [PRODUCTION_READINESS_CHECKLIST.md](PRODUCTION_READINESS_CHECKLIST.md).

---

## What Runs Today

| Surface | Status |
|---------|--------|
| `PBMRebateTreasury` | Working Solidity contract with epoch escrow, Merkle claims, dispute handling, sanctions, recall, pause, and cap controls |
| `PatientFundParticipatoryBudgeting` | Working patient-fund voting prototype with council registration and relayer-assisted voter self-registration |
| Mock ZK/nullifier registration | Semantic mock only: verifier/root/version-gated registration and nullifier reuse tests exist, but production unlinkability is not implemented |
| `PharmacyMutualCredit` | Working decoupled mutual-credit prototype with reserved-capacity, recipient-bound vouchers |
| Experimental governance/manifold drafts | Draft prototypes deployed only in focused tests for review; not integrated into treasury/PB/mutual-credit runtime and not production mechanisms |
| Tests | Compile and unit tests run in CI; run locally with `npm.cmd test` |
| Dashboard | Static prototype with local/test Web3 integration, synthetic-data labels, accessibility improvements, and offline verifier panel |
| Merkle tooling | Allocation root/proof generator |
| Portability export | Prototype JSON export plus offline self-consistency checks; RPC-backed verification is required for chain provenance |
| Continuity artifacts | Draft Node.js and static-browser tools for local paper-voucher and relay-intake review; not a live relay or on-chain settlement authority |
| Mainnet | Not deployed |
| External audit | Pending |

---

## Quickstart

Prereqs: Node.js 20 LTS or 22 LTS + npm.

Windows PowerShell note: if `npm` is blocked by script execution policy, use `npm.cmd` instead.

```bash
npm.cmd ci
npm.cmd run compile
npm.cmd test
```

Generate Merkle roots and proofs:

```bash
npm.cmd run merkle:allocations -- --in allocations.json --out merkle.json
```

Run the portability export prototype:

```bash
node scripts/export-portability.js \
  --exporter <participant_address> \
  --from-block <deployment_block> \
  --to-block <end_block_or_latest>
```

Exports fail closed by default on RPC/query failures or missing Merkle allocation material. `--allow-partial` and `--allow-unbounded-query` are explicit prototype/debug overrides, not production defaults.

Verify a portability export:

```bash
npm.cmd run verify:export -- --file exports/<participant_address>.json
```

Offline verification requires proof material when claims are present, but it only checks untrusted export self-consistency and Merkle math. Use `--allow-incomplete` only when intentionally inspecting an incomplete export; add `--rpc <url>` for chain-provenance verification.

Draft continuity tooling is available at `tools/resilience/continuity-engine.mjs`,
`tools/offline/continuity-kit.html`, and `tools/resilience/proxy-validator.js`.
The Node engine requires a local `LOCAL_MAC_SECRET`, fails closed on missing or
invalid MACs, and produces review/intake artifacts only. The static browser kit
uses Web Crypto for local voucher MAC checks. The proxy validator checks relay
batch shape, duplicate nullifiers, and metadata leakage. None of these artifacts
is a live proxy relay, redemption path, settlement authority, or production ZK
proof generator.

---

## Architecture

```mermaid
flowchart LR
  Depositor["PBM / depositor"] --> Treasury["PBMRebateTreasury"]
  Council["Council Safe"] --> Treasury
  Confirmer["Root confirmer"] --> Treasury
  Guardian["Guardian pause key"] --> Treasury
  Timelock["Timelock executor"] --> Treasury
  Remediation["Exclusion remediation reserve"] --> Treasury
  Treasury --> Pharmacy["Merkle pharmacy claims"]
  Treasury --> PatientFund["Patient fund"]
  PatientFund --> PB["PatientFundParticipatoryBudgeting"]
  Voters["Credentialed voters"] --> PB
  PB --> Projects["Community health projects"]
  Issuer["Credential issuer / relayer"] --> PB
  MutualCredit["PharmacyMutualCredit"] -. decoupled .-> Pharmacy
  MutualCredit --> Vouchers["Recipient-bound vouchers"]
  Dashboard["Dashboard prototype"] --> Treasury
  Dashboard --> PB
  Dashboard --> MutualCredit
  Export["Portability export + verifier"] --> Treasury
  Export --> PB
```

## Current Checkpoint

- Treasury remediation, root-backed claims, governance funds, and epoch escrow are separated in contract accounting.
- Voter registration supports EIP-712 relayer authorizations and direct trusted-issuer credential signatures.
- Patient-fund matching now uses pull-based project claims after round finalization.
- Mutual-credit vouchers reserve issuer capacity and can be redeemed only by the intended registered recipient.
- Dashboard values are explicitly synthetic unless contract-backed.
- Portability exports can be checked offline for structure/Merkle math and with RPC for chain provenance.

---

## What This Is

`PBMRebateTreasury` is an Ethereum smart contract that:

- records rebate deposits on-chain with depositor identity, amount, timestamp, and a free-form source string (which may encode quarter and drug class);
- routes captured funds to independent pharmacies through Merkle-proof claims;
- allocates 10% of every gross claim to a dedicated patient fund at claim time;
- makes ledger absences visible when paired with independently sourced expected-deposit records;
- separates treasury custody from adjacent prototypes such as mutual credit, vouchers, dashboard tooling, and participatory budgeting.

This is infrastructure for transparent rebate pass-through. It is not legal, financial, medical, or investment advice.

---

## Core Lifecycle

1. PBM or depositor calls `depositRebate()`.
2. The council Safe calls `proposeRoot()` for the current epoch.
3. A separately configured root-confirmer Safe calls `confirmRoot()`.
4. Pharmacies claim with Merkle proofs through `claim()`.
5. Council calls `finalizeEpoch()` to close the epoch.
6. After the 30-day `RECALL_DELAY`, unclaimed funds can be recalled to `patientFund`.

---

## Treasury Buckets

| Bucket | Allocation | Purpose |
|--------|------------|---------|
| Distribution pool | 99% | Pharmacy Merkle claims |
| Governance reserve | 1% | Council operations through `EXECUTOR_ROLE` |

## Patient Fund

| Source | Amount |
|--------|--------|
| Every gross claim | 10% routed to `patientFund` |
| Unclaimed epoch funds after recall delay | 100% routed to `patientFund` |
| Non-payout token sweeps | 100% routed to `patientFund` |

If `patientFund` is configured directly as the `PatientFundParticipatoryBudgeting` contract, payout-token inflows and direct payout-token surplus in that contract are treated as patient-bound matching liquidity for the next round and logged with `ExternalPatientFundsApplied`. They are not treated as council-refundable funds.

## Roles

| Role | Holder | Permissions |
|------|--------|-------------|
| `COUNCIL_ROLE` | 3/5 Gnosis Safe | Epoch management, root proposal, recall, sanctions, unpause |
| `ROOT_CONFIRMER_ROLE` | Separate Safe or governance address | Independently confirms proposed Merkle roots; rotation is timelocked |
| `EXECUTOR_ROLE` | TimelockController | Cap changes, governance reserve withdrawal, environment fund update, confirmer rotation |
| `GUARDIAN_ROLE` | Separate fast-response address | Emergency pause only; cannot unpause or access funds |

---

## Security Properties

- Hard cap enforced at root proposal and claim.
- Daily cap enforced at root proposal and claim.
- Root total enforced at claim.
- Per-pharmacy cap enforced through Merkle leaf encoding.
- Double-hash leaf construction for second-preimage protection.
- Root publication requires proposal by `COUNCIL_ROLE` and approval by a separately configured `ROOT_CONFIRMER_ROLE`.
- Council and root-confirmer membership are mutually exclusive, including future role rotations.
- `EXECUTOR_ROLE` and `ROOT_CONFIRMER_ROLE` administration is controlled by the timelock rather than council default administration.
- Daily cap remains bounded by hard cap.
- Recall only after `RECALL_DELAY`, only for unclaimed amount, sent to `patientFund`.
- Payout token cannot be swept.
- Non-payout tokens are swept to `patientFund`, not a general fund.
- `GUARDIAN_ROLE` is separate from `COUNCIL_ROLE`.
- `flagClaim` requires a valid Merkle proof.
- Disputed active-epoch claims update cap and recall accounting consistently.
- Root-exclusion payouts require independent confirmer approval and remain bounded by epoch caps.
- Root-exclusion payouts use a separately funded remediation reserve and cannot consume root or future distribution liquidity.
- Root-backed claims, exclusion payouts, and escrow-backed unclaimed balances are reported separately.
- Dismissed exclusion claims cannot redirect unreserved treasury funds as a penalty.
- Sanctioned addresses cannot flag claims.
- Open dispute flag blocks a parallel claim on the same epoch.
- ETH is rejected through `receive()` and `fallback()`.
- No upgradeability.

---

## Merkle Leaf Encoding

```solidity
// Double-hash leaf. abi.encodePacked is safe here because all fields are fixed-size.
bytes32 leaf = keccak256(
    bytes.concat(keccak256(abi.encodePacked(pharmacy, grossAmount, eligibleCap)))
);
```

Each leaf encodes:

- `pharmacy`: claimant address
- `grossAmount`: gross allocation for this epoch
- `eligibleCap`: per-pharmacy maximum enforced on-chain

> Off-chain tooling must use `encodePacked`, not `encode`, when hashing leaves.

---

## Deployment Parameters

```solidity
constructor(
    address _token,
    address _patientFund,
    address _environmentalFund,
    uint256 _initialDailyCap,
    uint256 _minimumEpochVolume,
    address _council,
    address _rootConfirmer,
    address _executor,
    address _guardian
)
```

Before mainnet deployment:

- complete a formal security audit;
- configure a 3/5 Gnosis Safe for `_council`;
- configure a separate Safe or governance address for `_rootConfirmer`;
- deploy and configure a `TimelockController` for `_executor`;
- confirm `_guardian` is separate from council;
- verify every address on the target network.
- set `_initialDailyCap` and `_minimumEpochVolume` in the payout token's smallest units (for example, six-decimal units for USDC).

---

## Deployment Script

This repo includes a convenience Hardhat script:

```text
scripts/deploy-timelock-and-treasury.js
```

Required environment variables:

- `TOKEN`
- `PATIENT_FUND`
- `ENVIRONMENTAL_FUND`
- `INITIAL_DAILY_CAP`
- `MINIMUM_EPOCH_VOLUME`
- `COUNCIL`
- `ROOT_CONFIRMER`
- `GUARDIAN`

Required timelock setup variable:

- `TIMELOCK_ADMIN` - explicit temporary or retained admin; never defaults silently to council

Optional timelock variables:

- `TIMELOCK_MIN_DELAY_SECONDS`
- `TIMELOCK_PROPOSERS`
- `TIMELOCK_EXECUTORS` - comma-separated executor addresses; set `ALLOW_OPEN_TIMELOCK_EXECUTOR=true` only if open execution is intentional
- `ALLOW_OPEN_TIMELOCK_EXECUTOR=true` - explicit acknowledgement that ready timelock operations may be executed by any address
- `RENOUNCE_TIMELOCK_ADMIN=true` - supported only when `TIMELOCK_ADMIN` is the deployer; removes the temporary human admin after deployment checks

Audit a deployed timelock and treasury against the expected environment configuration:

```bash
npm.cmd run audit:deployment -- --network <network>
```

The audit requires the deployment variables above plus `TIMELOCK_ADDRESS` and
`TREASURY_ADDRESS`. It verifies the deployed constructor bindings, caps, role
memberships, role administrators, timelock delay, proposers, executors, and
external-admin state. After legitimate cap ratchets, set
`EXPECTED_DAILY_VOLUME_CAP` and `EXPECTED_HARD_ABSOLUTE_VOLUME_CAP` to the
expected current values; otherwise the original deployment cap values are used.
On non-local networks the audit is strict and also requires `COUNCIL_SAFE_OWNERS`,
`COUNCIL_SAFE_PROXY_CODE_HASH`, and `COUNCIL_SAFE_SINGLETON`; if any Safe modules
are intentionally enabled, set `COUNCIL_SAFE_MODULES` and matching
`COUNCIL_SAFE_MODULE_CODE_HASHES`.

---

## Audit And Production Status

| Item | Status |
|------|--------|
| Internal review | Complete enough for prototype iteration |
| External audit | Pending |
| Mainnet deployment | Not deployed |
| Production frontend build | Build/check scripts present; public deployment still pending |
| Database/API/RLS surface | Not present yet |
| Rate limiting, caching, scaling, observability | Design gate only; not implemented yet |
| ADA/WCAG production audit | Pending |
| Production readiness checklist | See `PRODUCTION_READINESS_CHECKLIST.md` |
| Mechanism coverage | See `MECHANISM_COVERAGE.md` |
| Security reporting | See `SECURITY.md` |
| Open product decisions | See `OPEN_DESIGN_DECISIONS.md` |
| Implemented design decisions | See `DESIGN_DECISIONS.md` |

---

## Adjacent Designs

To preserve treasury simplicity, these systems are intentionally decoupled:

- `PatientFundParticipatoryBudgeting`: patient-fund project allocation prototype.
- `PharmacyMutualCredit`: mutual-credit and recipient-bound emergency voucher prototype.
- `tools/credentials`: credential issuance and verification prototype with wallet binding, expiry, and local revocation checks.
- `scripts/export-portability.js`: portability export prototype.
- `dashboard/`: static dashboard and local/test Web3 prototype; omission examples use provenance-labeled synthetic organizations rather than claims about real PBMs.

---

## Background

The project is motivated by rebate pass-through gaps affecting independent pharmacies and patient access. Policy references in this repository are context for the model, not legal conclusions. Any procurement clause, ERISA-facing language, deployment plan, or real-funds workflow requires qualified legal review.

---

## Contributing

Contributions are welcome, especially:

- test suite expansion;
- dashboard hardening and accessibility;
- Merkle and portability tooling;
- documentation cleanup;
- security review.

Open an issue before submitting a large PR.

---

## License

MIT. See [LICENSE](./LICENSE).

---

## Mission

Independent pharmacies serve communities that large chains abandon. They dispense prescriptions on thin margins, absorb clawbacks they cannot audit, and often lack a durable ledger to point to when the numbers do not add up.

This repository explores that ledger.

Every deposit is permanent. Every ledger absence is visible; calling it an omission requires independent expected-deposit evidence. The machine comes first; the mission can stand on it.
