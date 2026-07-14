# Privacy And Trust Boundary Review

Status: required before hosted auth, database, public intake forms, production RPC keys, error tracking, or public dashboard deployment.

This review is intentionally conservative. A provider is not acceptable because it is popular; it is acceptable only after the repo can say what it may read, what it may write, what it may log, how secrets are stored, and how participants can exit.

## Current Decision

No hosted database, hosted auth provider, public form intake provider, production error tracking provider, or production RPC provider is selected at this checkpoint.

The current repository remains local/testnet oriented. Static dashboard data must remain synthetic or contract-backed with visible provenance labels.

## Data Classes

| Data class | Examples | Minimum boundary |
| --- | --- | --- |
| Public contract data | Contract addresses, events, roots, cap settings | Public cacheable data, but labels must not imply audit or production readiness |
| Participant identity | Pharmacy wallet, credential subject, voter wallet | Server-side only unless explicitly public on-chain; avoid support logs and browser bundles |
| Credential material | Raw credentials, issuer signatures, revocation state | Never store in public dashboard assets; hash/nullifier design requires separate review |
| Patient-adjacent data | Copay need, medication category, care-continuity metrics | Do not collect until privacy-safe protocol and appeal process exist |
| Operator secrets | RPC secrets, deployer keys, service-role keys, webhook secrets | Managed secret store only; never browser, docs, screenshots, or support logs |
| Evidence packets | Omission evidence, dispute evidence, appeal records | Evidence hashes on-chain; preimages need custodian, retention, and access policy |

## Provider Review Matrix

| Surface | Candidate options | Required before selection |
| --- | --- | --- |
| Static hosting | Cloudflare Pages, GitHub Pages, Vercel, self-hosted static server | Security headers, preview isolation, no public source maps, no secret-bearing build logs |
| Database | Supabase, Firebase, self-hosted Postgres | RLS/security rules tests, export plan, audit logs, service-role key isolation |
| Auth | Clerk, Supabase Auth, Firebase Auth, wallet-only, self-hosted | Resource authorization beyond login, webhook validation, account recovery policy |
| Public forms | Cloudflare Turnstile plus server validation, custom API, no public forms | Abuse controls, server-side validation, hidden-field tamper tests, no protected data in logs |
| RPC | Public RPC, managed provider, self-hosted node | Rate limits, fallback behavior, key exposure model, metadata leakage review |
| Error tracking | Sentry-like hosted service, self-hosted logs, none | Redaction tests, private source maps only, no wallet signatures or credential material in events |

## Required Threat Questions

- Who can read raw request bodies, headers, IP addresses, user-agent strings, wallet addresses, credential fields, export payloads, and support records?
- Which values are publishable/client-safe and which are server-only secrets?
- Can a user access another participant's records by changing a wallet address, route parameter, form field, or client-side identifier?
- Are preview deployments isolated from production data, webhooks, RPC keys, and admin/provider secrets?
- Can participants export or delete off-chain records without breaking on-chain auditability?
- What is logged during failed auth, credential verification, export generation, and dispute flows?
- Which provider failure mode blocks care-continuity workflows, and what is the manual fallback?

## Acceptance Gates

- Document selected providers and rejected alternatives.
- Add tests for RLS/security rules or API authorization before storing protected records.
- Run `npm.cmd run build:dashboard` and `npm.cmd run check:frontend` before any public dashboard build.
- Keep server-only keys out of browser bundles, docs, screenshots, issue reports, and build logs.
- Do not claim production privacy until the ZK/nullifier and hosted metadata boundary are both reviewed.
