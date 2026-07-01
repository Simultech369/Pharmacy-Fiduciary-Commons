# Security Policy

## Current Status

Pharmacy Fiduciary Commons is a local/testnet prototype. It is not audited and must not be used with real funds until an independent audit is completed and published.

## Scope

Security review is welcome for:

- Solidity contracts in `contracts/`
- Hardhat tests in `test/`
- deployment and verification scripts in `scripts/`
- credential and Merkle tooling in `tools/`
- dashboard code in `dashboard/`
- governance, portability, and production-readiness documentation

Out of scope:

- live-funds incidents, because this repository is not deployed to mainnet;
- vulnerabilities that require intentionally leaking private keys or secrets;
- denial-of-service reports against third-party services not controlled by this project.

## Reporting

Please do not open a public issue for a suspected exploitable vulnerability.

Instead, contact the maintainer privately first. If a private channel is not available yet, open a GitHub issue with a minimal title such as:

```text
Private security report requested
```

Do not include exploit details, private keys, credentials, wallet signatures, patient-adjacent data, or proof material in the public issue.

## What To Include

Useful reports include:

- affected file and function;
- impact;
- reproduction steps;
- expected behavior;
- observed behavior;
- suggested fix, if known.

## Response Targets

Because this is an early-stage prototype, response times are best-effort:

- acknowledgement: within 7 days;
- triage: within 14 days;
- fix or mitigation plan: depends on severity and audit status.

## Severity Guide

High severity:

- loss, locking, or unauthorized movement of funds;
- bypass of Merkle claim constraints;
- bypass of council, executor, guardian, or voter authorization;
- private-key or credential compromise path;
- dashboard behavior that could mislead users into using real funds.

Medium severity:

- incorrect accounting, cap, recall, or portability behavior;
- signature malleability or replay surfaces;
- missing environment or chain checks;
- dependency or build issues affecting wallet-facing code.

Low severity:

- documentation ambiguity;
- test gaps without a demonstrated exploit;
- prototype UX issues that do not affect funds, credentials, or authorization.

## Audit Requirement

No mainnet deployment should occur until:

- the full test suite passes;
- production-readiness gates are reviewed;
- deployment addresses and chain IDs are verified;
- an independent smart-contract audit is completed;
- audit findings are fixed or explicitly accepted with rationale.

## Privacy, Correlation, and Retaliation Risks

The on-chain voting and registration mechanism uses EIP-712 structured credential signatures that reference `credentialHash`. Because on-chain transactions and event logs are fully public, participants face risks of correlation and corporate retaliation.

For the complete risk vectors and safety architectures, see:
* **[RETALIATION_AND_PRIVACY_THREAT_MODEL.md](RETALIATION_AND_PRIVACY_THREAT_MODEL.md)**: Details threat actors (PBMs, data brokers), attack scenarios, participant safety tiers, and the Patient Dignity Protocol.
* **[CARE_CONTINUITY.md](CARE_CONTINUITY.md)**: Addresses the critical distinction between auditable value flows and actual care continuity, outlining stockout/network risks and proposed community-jury escalation pathways.
* **[IDENTITY_NULLIFIER_DESIGN.md](IDENTITY_NULLIFIER_DESIGN.md)**: Explains the planned scoped-nullifier ZK architecture for cross-round privacy.

## Payout Token Assumption

Treasury accounting assumes the configured payout token is a standard, non-rebasing, non-deflationary ERC-20 with no fee-on-transfer behavior. Deposits and reserve funding are accounted by the requested transfer amount, so production deployments must not use tokens whose received balance can differ from the transfer amount.

## Stale Distribution Recovery

The unallocated distribution pool recovery mechanism uses `epochStartTimestamp`, not `lastDepositTimestamp`, to enforce the 180-day stale recovery delay. A later dust deposit updates deposit metadata but does not extend the recovery window.
1. **Liveness Mitigation**: A 1 wei deposit can no longer restart the stale recovery timer for the entire distribution pool.
2. **Safety Guards**: Recovery remains limited to the current epoch when no root is live, no pending root proposal remains unexpired, and the timelock executor routes recovered liquidity to the `patientFund`.

## Dispute Cap-Reservation Tradeoff

The `PBMRebateTreasury` contract checks `epochVolume` (disputed and claimed volumes in the active epoch) against `dailyVolumeCap` and `hardAbsoluteVolumeCap`.
1. **Liveness/Griefing Risk**: When a pharmacy flags a normal dispute (`flagClaim`), the disputed amount is reserved from the epoch escrow and the `epochVolume` increases immediately. If a pharmacy has a very large dispute, it can lock up the remaining daily volume cap, causing subsequent legitimate claims to temporarily revert with `DailyCapExceeded` until the Council resolves or dismisses the dispute.
2. **Design Tradeoff**: This is an intentional design choice. The alternative (not checking caps at dispute time) would allow an attacker to flag large arbitrary disputes to drain or lock the entire distribution pool without cap enforcement.
3. **Mitigation**: The Council holds the authority to quickly review and resolve or dismiss disputes via `resolveClaim`, which immediately releases the reserved volume cap if dismissed.

## Content Security Policy (CSP) Guidelines

To mitigate Cross-Site Scripting (XSS) and data injection risks in production:
1. **CSP Configuration**: A strict Content-Security-Policy header should be served by the web server (or configured in the hosting environment config, e.g. Netlify/Vercel headers) restricting sources.
2. **Recommended CSP Policy**:
   ```http
   Content-Security-Policy: default-src 'self'; font-src 'self' https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:;
   ```
