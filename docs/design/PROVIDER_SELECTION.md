# Long-Term Provider Selection & Auth Architecture (Assessment Only)

> [!IMPORTANT]
> **No hosted database or auth provider code is active in the current prototype phase.** The following analysis provides architectural guidelines for future development gates. No centralized provider should be adopted without a complete cryptographic privacy review.

---

## 1. Candidate Evaluation & Trust Boundaries

Any public exposure of pharmacy, patient-fund, credential, or voucher data must be evaluated under a hostile adversary threat model (e.g., predatory Pharmacy Benefit Managers or insurance carriers aiming to identify, audit, or penalize participants).

### Cloudflare Workers & KV/D1
* **Pros**: Edge-routing enables rapid request sanitization; static assets can be served close to clients. Cloudflare Turnstile provides robust bot challenge mitigation.
* **Cons**: Log aggregation and edge key storage are centralized. Standard relational databases placed behind CF workers still rely on connection pool security.
* **Verdict**: Excellent candidate for static asset hosting and rate-limiting/honeypot API middleware, but insufficient on its own for raw credential storage.

### Supabase (PostgreSQL + PostgREST)
* **Pros**: Row Level Security (RLS) is native and enforced at the database level.
* **Cons**: Database connection strings must be kept strictly server-side. RLS is only as secure as the database role policies written; a mistake in policy logic exposes the entire table.
* **Verdict**: Strong candidate if PostgreSQL is required, but requires strict RLS unit testing and a backend proxy to prevent direct client database queries.

### Firebase (Firestore + Authentication)
* **Pros**: Granular security rules and local emulator suite allow robust testing of resource ownership.
* **Cons**: Firestore is a proprietary document store; data portability and lock-in are high. No built-in ZK verification support.
* **Verdict**: Acceptable for rapid application development but carries high vendor lock-in risk and offers poor support for decentralized cryptographic workflows.

### Clerk / Auth0
* **Pros**: Out-of-the-box user management, multi-factor authentication, and session handling.
* **Cons**: Direct reliance on a third-party hosted SaaS provider. Clerk collects user metadata, IP addresses, and identity profiles, creating a high-risk correlation path for participant tracking.
* **Verdict**: **DO NOT USE** for direct patient or pharmacy identity tracking without wrapping their identifiers in a zk-nullifier structure. Using SaaS identity providers directly compromises the anonymity of independent pharmacies fearing PBM retaliation.

---

## 2. Privacy-Preserving Prerequisites (P1 Warning)

Before any centralized backend or auth provider is integrated:
1. **Prioritize ZK-Nullifiers**: Real-world PBM/retaliation prevention requires that a participant's real identity (wallet address or legal credentials) is never bound on-chain or in a centralized database to their specific rebate claims. Credentials must utilize a deployment-scoped zk-SNARK nullifier schema (as proposed in `IDENTITY_NULLIFIER_DESIGN.md`).
2. **Strict Secret Isolation**: Clerk secret keys, database service roles, and private keys must never be bundled into frontend JS.

---

## 3. Liveness and Voucher Cleanup Monitoring

The mutual credit voucher system (`PharmacyMutualCredit.sol`) has a critical operational requirement: expired voucher capacities are not cleaned up automatically on-chain because Solidity cannot trigger self-running cron jobs. 

* **The Problem**: If a voucher expires, its reserved credit capacity remains locked in the issuer's reservation pool until the `releaseExpiredVoucher` function is called. If left unmanaged, expired vouchers can consume the issuer's entire credit limit, resulting in a credit lock-out (liveness failure).
* **The Solution**: Production environments must deploy an automated monitoring and event listener script (e.g., using a secure Cloudflare Worker or keeper bot) that:
  * Listens for block time progression.
  * Queries expired voucher states.
  * Triggers batches of `releaseExpiredVoucher` transactions.
  * Sends automated Slack/Email alerts if an issuer's reserved capacity exceeds 80% of their credit limit.
