# Start Here: Pharmacy Fiduciary Commons

Pharmacy Fiduciary Commons is a local/testnet prototype for showing how rebate deposits, Merkle pharmacy claims, patient-fund matching, and portability exports can be checked without asking a PBM or dashboard operator to be trusted by default.

It is not audited, not deployed to mainnet, and not ready for real funds.

## The 10-Minute Path

Prerequisites: Node.js 20 LTS or 22 LTS and npm.

On Windows PowerShell, prefer `npm.cmd` when script execution policy blocks `npm`.

1. Install reproducible dependencies:

```bash
npm.cmd ci
```

2. Run the local demo path:

```bash
npm.cmd run demo:local
```

This command compiles the contracts, creates a synthetic pharmacy allocation file, generates a Merkle root and proofs, runs focused claim/export and patient-fund matching tests, builds the static dashboard, and checks the dashboard bundle for release-blocking frontend issues.

3. Open the dashboard prototype:

```text
dist/dashboard/index.html
```

The dashboard is a static prototype. Values marked as synthetic fixtures are not live PBM claims, real patient records, or mainnet contract state.

## What You Should See

The demo writes these local artifacts:

- `cache/local-demo/allocations.json`: synthetic pharmacy allocations.
- `cache/local-demo/merkle.json`: generated root and per-pharmacy proofs.
- `dist/dashboard/index.html`: static dashboard build.

The focused tests exercise two concrete flows:

- A pharmacy claim exported into a portability JSON payload and checked against Merkle proof material.
- Patient-fund matching distribution using squared vote weights.

## Plain-Language Tour

### For Independent Pharmacies

The prototype shows a rebate distribution pool where pharmacy claims are committed through a Merkle root. A pharmacy can prove it belongs in an allocation set without the dashboard inventing numbers after the fact.

What it does today: local contract tests cover deposits, claims, caps, disputes, recall timing, and accounting boundaries.

What it does not do: guarantee drug supply, physical inventory, reimbursement law compliance, or production custody safety.

### For Patient Funds and Advocates

The prototype routes a share of gross claims into a patient fund and tests participatory allocation mechanics. The dashboard uses synthetic project cards to explain the flow without claiming that real patient programs have been funded.

What it does today: local tests cover round setup, voting mechanics, matching calculations, and pull-based project claims.

What it does not do: provide production privacy, medical advice, or a live claims administration system.

### For Auditors and Fiduciary Managers

The repo separates contract-backed checks from synthetic demo labels. Portability exports can be checked offline for schema, receipts, and Merkle math; RPC-backed verification is required before treating an export as chain-provenance-backed.

## Manual Commands

Run the full test suite:

```bash
npm.cmd test
```

Generate Merkle roots and proofs from your own allocation file:

```bash
npm.cmd run merkle:allocations -- --in allocations.json --out merkle.json
```

Run a portability export against a local or configured RPC endpoint:

```bash
node scripts/export-portability.js --exporter <participant_address> --from-block <deployment_block> --to-block <end_block_or_latest> --merkle merkle.json
```

Verify a portability export offline:

```bash
npm.cmd run verify:export -- --file exports/<participant_address>.json
```

Add `--rpc <url>` when you need chain-provenance verification instead of local self-consistency checks only.

## Documentation Path

Read in this order:

1. [README.md](README.md): status, architecture, quickstart, and safety boundaries.
2. [MECHANISM_COVERAGE.md](MECHANISM_COVERAGE.md): what is implemented, mocked, proposed, or blocked.
3. [PORTABILITY.md](PORTABILITY.md): export schema and verification expectations.
4. [GOVERNANCE.md](GOVERNANCE.md): council, timelock, confirmer, and guardian role boundaries.
5. [PRODUCTION_READINESS_CHECKLIST.md](PRODUCTION_READINESS_CHECKLIST.md): launch blockers.

Use the deeper review and threat-model documents after the first demo path is working.

## Demo Walkthrough Ideas

These are good short GIF or screen-recording targets:

- Run `npm.cmd run demo:local` and open the generated Merkle output.
- Open `dist/dashboard/index.html` and point out the synthetic provenance labels.
- Show the portability verifier warning that offline mode checks self-consistency only.
- Trace one patient-fund matching calculation from test setup to expected payout.
