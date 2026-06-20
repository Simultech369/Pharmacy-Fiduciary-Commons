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

## Privacy and Correlation Risks

The on-chain voting and registration mechanism uses EIP-712 structured credential signatures that reference `credentialHash`. Because on-chain transactions and event logs are fully public:
1. **Correlation Risk**: If a voter uses the same `credentialHash` (or if it is derived from a long-term identifier) across multiple rounds or rounds in different deployments, their voting patterns can be correlated by on-chain watchdogs.
2. **Mitigation**: Trusted issuers should rotate policy versions regularly and use different credential hashes per round or participant. Future iterations will consider using nullifier sets or Zero-Knowledge (ZK) proofs to completely hide correlation markers while preserving double-vote prevention.

## Dust-Deposit Griefing Tradeoff

The unallocated distribution pool recovery mechanism uses `lastDepositTimestamp` of the latest deposit to enforce the 180-day stale recovery delay.
1. **Liveness Risk**: Any participant or adversary can execute a cheap dust deposit (as small as 1 wei) just before the 180-day window expires. This updates `lastDepositTimestamp` and resets the stale recovery timer for the entire distribution pool, delaying recovery.
2. **Acceptance Rationale**: This is a known liveness tradeoff accepted for prototype simplicity and security. It prevents the council or unauthorized executors from prematurely reclaiming the distribution pool while active deposits are being made. Legitimate allocation to a Merkle root remains fully executable via the root confirmation role, regardless of recovery timer resets.

## Content Security Policy (CSP) Guidelines

To mitigate Cross-Site Scripting (XSS) and data injection risks in production:
1. **CSP Configuration**: A strict Content-Security-Policy header should be served by the web server (or configured in the hosting environment config, e.g. Netlify/Vercel headers) restricting sources.
2. **Recommended CSP Policy**:
   ```http
   Content-Security-Policy: default-src 'self'; font-src 'self' https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:;
   ```
