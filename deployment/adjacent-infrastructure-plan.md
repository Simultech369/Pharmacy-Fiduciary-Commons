# Adjacent Infrastructure Plan

Status: roadmap only unless an item names executable evidence.

Adjacent primitives must stay decoupled from treasury custody until each has its own threat model, tests, deployment gate, and user-facing boundary language.

## 1. Cooperative Procurement Layer

Current evidence: `tools/procurement/pricing_analysis.mjs` and mock procurement fixtures.

Next gates:

- Define whether procurement data is public market intelligence, member-only operational data, or protected commercial data.
- Add a neutral-language report format that avoids unsupported accusations.
- Add source provenance, stale-data labels, and dispute/correction workflow.
- Keep procurement outputs out of treasury authorization.

## 2. Mutual Credit And Voucher Operations

Current evidence: `contracts/PharmacyMutualCredit.sol` with recipient-bound vouchers and capacity reservation tests.

Next gates:

- Define bad-debt, write-off, freeze, appeal, and local federation solvency rules.
- Decide whether ledgers are per federation or global.
- Add operational monitoring for expired voucher reservations awaiting cleanup.
- Do not claim inventory, medicine availability, or distributor capacity guarantees.

## 3. Rebate Transparency Registry

Current evidence: omission and dashboard language is prototype-level and must stay neutral.

Next gates:

- Define evidence custodian and correction process.
- Preserve contract-backed versus submitted/unverified evidence labels.
- Add a language linter for legally risky phrasing.
- Add chain-event reconciliation before public claims.

## 4. Offline Receipt Reconciliation

Current evidence: `tools/resilience/continuity-engine.mjs` creates Node-based local voucher and relay-intake artifacts.

Next gates:

- Run tabletop scenarios for duplicate receipt, forged receipt, delayed sync, lost connectivity, and trusted-proxy abuse.
- Define who can enter offline claims, who reviews them, and how disputes are appealed.
- Build a standalone air-gapped verifier only after evidence and authority boundaries are settled.
- Do not let offline artifacts become settlement authority without a ratified workflow.
