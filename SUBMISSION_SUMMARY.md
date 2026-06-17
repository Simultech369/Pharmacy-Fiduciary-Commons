# Submission Summary

## Project

**Pharmacy Fiduciary Commons** is an open-source local/testnet prototype for transparent pharmacy rebate escrow, auditable Merkle distributions, patient-fund routing, participatory allocation, recipient-bound mutual-credit vouchers, and participant data portability.

Repository: https://github.com/Simultech369/Pharmacy-Fiduciary-Commons

## Current Status

- Not audited.
- Not deployed to mainnet.
- No real funds should be routed through the contracts.
- Current local verification: `93 passing` via `npm.cmd test`.
- Current head reviewed locally: `65e4e38`.

## What Works Today

- `PBMRebateTreasury` handles rebate deposits, root proposal/confirmation, Merkle claims, dispute handling, sanctions, recall, pause, and bucket accounting.
- Exclusion remediation is isolated in a separately funded reserve.
- Root publication uses separate council and root-confirmer authority with timelocked rotation.
- `PatientFundParticipatoryBudgeting` supports credentialed voter registration, EIP-712 relayer authorization, direct trusted-issuer registration, project proposals, support thresholds, and pull-based project matching claims.
- `PharmacyMutualCredit` supports registered participants, issuer credit limits, capacity-reserved recipient-bound vouchers, expiry cleanup, pause, and token sweep recovery.
- Portability export tooling includes offline validation and optional RPC-backed provenance checks.
- Dashboard is explicitly labeled as local/test and synthetic where values are not contract-backed.

## Why It Is Interesting

The project treats pharmacy rebate transparency as a verifiable accounting problem rather than a narrative promise. Deposits, omissions, root allocations, claims, patient-fund routing, and portability artifacts are designed to be legible and independently checkable.

## Boundaries

- This is not legal, medical, financial, or investment advice.
- The dashboard is not a production frontend.
- Credential privacy remains a future design area because stable credential hashes can become correlation handles.
- External audit, deployment runbooks, production hosting, and formal compliance review are still required before any real-funds use.

## Useful Review Targets

- Treasury accounting invariants under adversarial dispute sequences.
- Timelock deployment and admin-renunciation workflow.
- Credential privacy and nullifier strategy.
- Dashboard accessibility and production build hardening.
- Operational funding target for the exclusion-remediation reserve.
