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
