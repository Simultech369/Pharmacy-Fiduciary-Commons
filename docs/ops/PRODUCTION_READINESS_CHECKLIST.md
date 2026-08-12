# Production Readiness Checklist

This checklist is a deployment gate for moving the Pharmacy Fiduciary Commons beyond local demo/testnet status. Items marked "not present yet" still matter: they become required as soon as that surface exists.

---

## 1. Front End Build Hygiene

Status: Operational build pipeline and scanners configured.

- [x] Build dashboard assets through a production bundler/minifier (`npm.cmd run build:dashboard` writes `dist/dashboard` with local script assets and an asset manifest).
- [x] Do not expose private keys, API secrets, RPC provider secrets, or admin addresses in client-side code.
- [x] Disable public source map publishing for production builds.
- [x] If source maps are needed for debugging, upload them only to the private error-tracking service.
- [x] Pin or bundle third-party JavaScript dependencies.
- [x] Add Subresource Integrity (SRI) hashes for any remaining CDN assets (none present; all self-hosted).
- [x] Keep visible "NOT AUDITED" and testnet/local-network warnings until audit and deployment status change.

Acceptance test:

- [x] Inspect built assets and confirm no `.map` files are publicly served.
- [x] Search built assets for known secret names and private key patterns.
- [x] Confirm wallet-facing JavaScript is bundled/pinned or protected by SRI.
- [x] Run `npm.cmd run check:frontend` against the generated dashboard build.

## 2. Database And Authentication

Status: Gate DB1 verified (Supabase schema + migrations, EIP-191/EIP-712 security proxy in `server/createApp.js`, and multi-tenant RLS policy JS simulation harness passing in `test/server.test.js`).

- [x] Choose database and auth provider before storing user or patient-adjacent records (Supabase selected for DB1 proxy boundary).
- [x] Enable Row Level Security (RLS) before launch (`supabase/schema.sql` & `supabase/migrations/20260721000000_hardened_rls_and_ledger.sql`).
- [x] Write RLS policies for every table containing user, pharmacy, patient, credential, vote, or export data.
- [x] Add tests proving users cannot read or mutate records they do not own (`test/server.test.js` 19/19 passing).
- [x] Separate admin/service-role access from normal authenticated user access.
- [x] Never expose service-role database keys to the browser.
- [x] Do not rely on identity-provider login alone for authorization; enforce EIP-191/EIP-712 cryptographic signature authorization in `server/createApp.js`.
- [x] Classify every key as publishable/client-safe or secret/server-only before use. Supabase service-role keys and HMAC pepper parameters remain server-side.
- [ ] If Firebase is selected, deploy locked-down Security Rules and emulator/unit tests before storing protected records.

Acceptance test:

- [ ] Run unauthorized read/write tests against every protected table.
- [ ] Confirm anonymous and authenticated users receive only the minimum intended rows.
- [ ] Inspect built frontend assets for service-role keys, secret keys, private keys, RPC secrets, webhook secrets, and provider admin tokens.
- [ ] Prove provider-specific authorization cannot be bypassed by changing client-side user IDs, wallet addresses, route params, or form fields.

## 2A. Offline And Non-Digital Workflow Safety

Status: partially present (draft offline voucher generation, proxy validation, and deterministic local reconciliation scripts exist; SMS integration and live reconciliation remain unimplemented).

- [ ] Define the SMS, paper voucher, or trusted-proxy workflows before claiming non-digital access.
- [ ] Add receipt identifiers that can be reconciled without exposing PHI or patient precarity.
- [x] Add an offline-receipt audit script or documented reconciliation procedure.
- [ ] Define who can enter offline claims, who reviews them, and how disputes are handled.
- [ ] Test duplicate receipt, forged receipt, delayed sync, and lost-connectivity cases.
- [ ] Define a privacy-safe, fraud-resistant data collection protocol for care-continuity metrics such as Continuous Refill Ratio (CRR).

Acceptance test:

- [x] Offline receipts can be reconciled to on-chain events or explicitly marked unresolved (local deterministic script classifies them as reconciled, duplicate_conflict, or unresolved).
- [ ] Offline workflows do not publish diagnosis, income, immigration, disability, or stigmatized medication data.
- [ ] Operators can measure Non-Digital Workflow Adoption without exposing protected participant data.
- [ ] Care-continuity metrics can be audited without exposing patient identity, diagnosis, income, or stigmatized medication category, and without relying solely on self-reported pharmacy data.

## 3. Version Control

Status: partially present.

- [ ] Keep `main` protected.
- [ ] Require pull requests for production changes.
- [ ] Require tests to pass before merge.
- [ ] Require code review for contract, credential, dashboard, deployment, and governance changes.
- [ ] Tag release commits.
- [ ] Keep generated build artifacts, private keys, local exports, cache files, and source maps out of Git.
- [ ] Maintain a rollback plan for every release.

Acceptance test:

- [ ] `git status` is clean before release.
- [ ] CI passes on the exact commit being deployed.
- [ ] Release tag points to the deployed commit.

## 3A. Patient Fund Matching Liquidity

Status: Operational enforcement implemented.

- [x] Verify the matching token balance is present before starting any patient-fund matching round.
- [x] Document whether matching pools are pre-funded, escrowed, or otherwise guaranteed before `finalizeRound`; operators can use `dryRunFinalize` / `previewFinalize` to compare expected shares with actual token balance.
- [x] Define what happens if approved projects exceed available matching liquidity.
- [x] Add operator runbook steps for paused, underfunded, or partially funded rounds.

Acceptance test:

- [x] A `dryRunFinalize` / `previewFinalize` dry-run proves every registered project can claim its expected match from the funded pool.
- [x] Underfunded matching rounds fail before public launch or are clearly marked unresolved; no public interface implies partial-payment queueing exists.
- [x] Operators verify recorded matching allocations against the contract's actual token balance, distinguishing accounting shares from spendable liquidity.

## 4. APIs

Status: partially present (honeypot, XSS, CSRF, and admin-field protections verified via threat-model simulation).

- [ ] Define every public API route and auth requirement.
- [ ] Validate all request bodies, query parameters, and path parameters.
- [ ] Enforce authorization server-side, not only in the UI.
- [x] Treat public forms as untrusted input. Hidden honeypot fields may be used as a secondary spam signal, but never as the only abuse control or authorization check (honeypot, payload size, and XSS sanitization verified in simulated threat model).
- [x] Prevent hidden form fields from carrying trusted prices, roles, wallet addresses, patient status, credential claims, or payout destinations without server-side recomputation or verification (administrative role and parameter injection blocked).
- [x] Add CSRF/session-origin protections for state-changing browser flows once cookies or hosted auth sessions exist (CSRF token verification implemented in simulated threat model).
- [ ] Do not return sensitive internal errors to clients.
- [ ] Log security-relevant events without logging secrets or protected data.
- [ ] Add contract/API compatibility tests where APIs call smart contracts.

Acceptance test:

- [ ] Unauthorized users cannot access protected API routes.
- [ ] Malformed requests fail safely.
- [ ] API logs do not include tokens, private keys, raw credentials, or protected patient data.
- [x] Bot/spam tests show that honeypot bypass, direct POSTs, replayed submissions, and modified hidden fields fail safely (validated via PublicFormThreatModel.test.js).

## 5. Hosting And Deployment

Status: needs definition before public launch.

- [ ] Define target environments: local, testnet/staging, production.
- [ ] Use separate config and secrets for each environment.
- [ ] Store secrets in a managed secret store, not files committed to Git.
- [ ] Do not share a full server `.env` file with the browser, docs, issue reports, screenshots, support tickets, or public build logs.
- [ ] If using Cloudflare Workers/Pages, store sensitive values as Cloudflare secrets and fail deploys when required secrets are missing.
- [ ] If using Supabase/Firebase/Clerk, document which keys are publishable and which are server-only, then verify that server-only keys are absent from client bundles.
- [ ] Keep preview deployments isolated from production data, webhooks, RPC keys, and admin/provider secrets.
- [ ] Enforce HTTPS.
- [ ] Set security headers: CSP, HSTS, X-Content-Type-Options, Referrer-Policy, and frame restrictions.
- [x] Implement fail-before-write deployment policy preflights, rejecting open executors on non-local networks and enforcing role/time constraints before any deployment transactions.
- [ ] Confirm deployed contract addresses and chain IDs are environment-specific.
- [ ] Confirm cap and minimum-epoch values use the selected payout token's base units and decimals.
- [ ] Document release and rollback steps.
- [x] Add example static-hosting security headers and cache policy in `deployment/hosting.headers.example.json`.

Acceptance test:

- [ ] Production deploy uses production config only.
- [ ] Staging/testnet deploy cannot accidentally present itself as audited mainnet infrastructure.
- [ ] Security headers are present on public routes.
- [ ] Secret scanning of repo, build output, and deployment logs finds no server-only provider keys or private keys.

## 6. Rate Limiting And Abuse Controls

Status: not present yet.

- [ ] Rate-limit login, credential verification, export generation, vote registration, and any expensive API endpoints.
- [ ] Add per-IP and per-account limits where appropriate.
- [ ] Add bot/automation protections for public forms.
- [ ] Add backoff or queueing for expensive export/report generation.
- [ ] Monitor failed authentication, credential, and registration attempts.

Acceptance test:

- [ ] Repeated abusive requests are throttled.
- [ ] Legitimate users receive clear retry behavior.

## 7. Caching

Status: needs design.

- [ ] Cache public, non-sensitive dashboard data where possible.
- [ ] Do not cache personalized, credential, export, patient, or auth-token data in shared caches.
- [ ] Set cache headers intentionally for every route.
- [ ] Invalidate cached dashboard data after new contract events or deployment changes.
- [ ] Use stale-while-revalidate only for data where temporary staleness is acceptable.

Acceptance test:

- [ ] Sensitive responses include `no-store` or equivalent.
- [ ] Public dashboard responses can be cached without leaking user data.

## 8. Scaling

Status: partially present (paginated on-chain event history implemented in dashboard).

- [ ] Identify high-cost tasks: export generation, chain event queries, credential checks, and dashboard aggregation.
- [ ] Move expensive tasks to background jobs or queues when usage grows.
- [x] Add pagination for event/history APIs (block-paginated event query history implemented in dashboard).
- [ ] Add database indexes for common queries once a database exists.
- [ ] Set RPC provider limits and fallback behavior.
- [ ] Load-test critical public flows before production launch.

Acceptance test:

- [ ] Core flows remain responsive under expected traffic.
- [ ] Expensive tasks do not block normal dashboard or voting flows.

## 9. Error Tracking And Observability

Status: not present yet.

- [ ] Add frontend error tracking.
- [ ] Add backend/API error tracking when APIs exist.
- [ ] Upload source maps privately only if needed.
- [ ] Redact secrets, wallet signatures, credentials, patient data, and auth tokens from logs.
- [ ] Add uptime checks for hosted dashboard and APIs.
- [ ] Add alerts for failed deploys, API spikes, repeated auth failures, and contract integration failures.
- [ ] Select an error-tracking provider only after `deployment/trust-boundary-review.md` is completed; private source maps must not be public.

Acceptance test:

- [ ] A test frontend error appears in the tracking dashboard without exposing sensitive data.
- [ ] A test backend/API error appears with useful context and redacted secrets.

## 10. ADA / WCAG Accessibility

Status: Operational accessibility pass verified.

- [x] Target WCAG 2.2 AA.
- [x] Use semantic HTML landmarks: header, nav, main, sections, buttons, labels.
- [x] Ensure all interactive controls are keyboard reachable.
- [x] Add visible focus states.
- [x] Ensure color contrast meets AA thresholds.
- [x] Add accessible labels for icon-only controls and form inputs.
- [x] Ensure alerts, status changes, and transaction state changes are announced to screen readers.
- [x] Avoid relying on color alone to communicate status.
- [x] Test at 200% zoom and common mobile viewport widths.
- [x] Respect reduced-motion preferences.

Acceptance test:

- [x] Run automated accessibility checks.
- [x] Manually test keyboard-only navigation.
- [x] Manually test wallet/status flows with screen-reader-friendly text.
- [x] Fix all critical and serious accessibility findings before public launch.

## 11. Contract Security And Scanner Prep

Status: scanner triage present; refresh required before public deployment claims.

- [x] Preserve local scanner artifacts and dispositions in `SCANNER_TRIAGE.md`.
- [x] Cross-check Slither, Aderyn, and targeted Mythril findings against live contract paths before making code changes.
- [x] Add adversarial callback and forced-ETH regression coverage for accepted residual scanner findings where practical.
- [ ] Rerun Slither, Aderyn, targeted Mythril, and GitHub-hosted SolidityScan from the exact release commit.
- [ ] Complete, publish, and pin an independent smart-contract audit report to the exact release commit before any production-network release or real-funds use.
- [ ] Resolve or explicitly accept any new high-confidence production-contract findings before testnet or public deployment.

Acceptance test:

- [ ] Release scanner artifacts are dated, commit-pinned, and linked from `SCANNER_TRIAGE.md`.
- [ ] Any accepted residual finding has an exploitability rationale and, where practical, a regression test.

## Current Repo-Specific Next Fixes

- [x] Pin dashboard JavaScript libraries locally and remove unsafe public CDN dependency patterns (note: full asset bundling is deferred to production build tooling).
- [x] Add a dashboard accessibility pass for labels, focus states, contrast, status messages, and reduced motion.
- [x] Add runtime environment checks and dashboard locks to prevent network confusion (note: deployment-level multi-environment configuration remains in progress).
- [x] Add provider-selection notes covering Cloudflare, Supabase/Firebase, Clerk, and any Bolin/IODR-style identity flow before adding hosted auth or database code.
- [x] Add simulated public-form threat-model tests (note: real hosted form/API validation is deferred to backend integration).
- [x] Add a public release checklist tied to `npm.cmd test`, contract verification, and dashboard build output inspection.
- [x] Add dashboard production build and frontend hygiene check scripts.
- [x] Add privacy/trust-boundary review, parameter calibration, and governance-role templates under `deployment/`.
