# Production Readiness Checklist

This checklist is a deployment gate for moving the Pharmacy Fiduciary Commons beyond local demo/testnet status. Items marked "not present yet" still matter: they become required as soon as that surface exists.

---

## 1. Front End Build Hygiene

Status: needs implementation before public wallet use.

- [ ] Build dashboard assets through a production bundler/minifier.
- [ ] Do not expose private keys, API secrets, RPC provider secrets, or admin addresses in client-side code.
- [ ] Disable public source map publishing for production builds.
- [ ] If source maps are needed for debugging, upload them only to the private error-tracking service.
- [ ] Pin or bundle third-party JavaScript dependencies.
- [ ] Add Subresource Integrity (SRI) hashes for any remaining CDN assets.
- [ ] Keep visible "NOT AUDITED" and testnet/local-network warnings until audit and deployment status change.

Acceptance test:

- [ ] Inspect built assets and confirm no `.map` files are publicly served.
- [ ] Search built assets for known secret names and private key patterns.
- [ ] Confirm wallet-facing JavaScript is bundled/pinned or protected by SRI.

## 2. Database And Authentication

Status: not present yet.

- [ ] Choose database and auth provider before storing user or patient-adjacent records.
- [ ] Enable Row Level Security (RLS) before launch.
- [ ] Write RLS policies for every table containing user, pharmacy, patient, credential, vote, or export data.
- [ ] Add tests proving users cannot read or mutate records they do not own.
- [ ] Separate admin/service-role access from normal authenticated user access.
- [ ] Never expose service-role database keys to the browser.

Acceptance test:

- [ ] Run unauthorized read/write tests against every protected table.
- [ ] Confirm anonymous and authenticated users receive only the minimum intended rows.

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

## 4. APIs

Status: not present yet.

- [ ] Define every public API route and auth requirement.
- [ ] Validate all request bodies, query parameters, and path parameters.
- [ ] Enforce authorization server-side, not only in the UI.
- [ ] Do not return sensitive internal errors to clients.
- [ ] Log security-relevant events without logging secrets or protected data.
- [ ] Add contract/API compatibility tests where APIs call smart contracts.

Acceptance test:

- [ ] Unauthorized users cannot access protected API routes.
- [ ] Malformed requests fail safely.
- [ ] API logs do not include tokens, private keys, raw credentials, or protected patient data.

## 5. Hosting And Deployment

Status: needs definition before public launch.

- [ ] Define target environments: local, testnet/staging, production.
- [ ] Use separate config and secrets for each environment.
- [ ] Store secrets in a managed secret store, not files committed to Git.
- [ ] Enforce HTTPS.
- [ ] Set security headers: CSP, HSTS, X-Content-Type-Options, Referrer-Policy, and frame restrictions.
- [ ] Confirm deployed contract addresses and chain IDs are environment-specific.
- [ ] Confirm cap and minimum-epoch values use the selected payout token's base units and decimals.
- [ ] Document release and rollback steps.

Acceptance test:

- [ ] Production deploy uses production config only.
- [ ] Staging/testnet deploy cannot accidentally present itself as audited mainnet infrastructure.
- [ ] Security headers are present on public routes.

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

Status: needs design.

- [ ] Identify high-cost tasks: export generation, chain event queries, credential checks, and dashboard aggregation.
- [ ] Move expensive tasks to background jobs or queues when usage grows.
- [ ] Add pagination for event/history APIs.
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

Acceptance test:

- [ ] A test frontend error appears in the tracking dashboard without exposing sensitive data.
- [ ] A test backend/API error appears with useful context and redacted secrets.

## 10. ADA / WCAG Accessibility

Status: needs audit before public launch.

- [ ] Target WCAG 2.2 AA.
- [ ] Use semantic HTML landmarks: header, nav, main, sections, buttons, labels.
- [ ] Ensure all interactive controls are keyboard reachable.
- [ ] Add visible focus states.
- [ ] Ensure color contrast meets AA thresholds.
- [ ] Add accessible labels for icon-only controls and form inputs.
- [ ] Ensure alerts, status changes, and transaction state changes are announced to screen readers.
- [ ] Avoid relying on color alone to communicate status.
- [ ] Test at 200% zoom and common mobile viewport widths.
- [ ] Respect reduced-motion preferences.

Acceptance test:

- [ ] Run automated accessibility checks.
- [ ] Manually test keyboard-only navigation.
- [ ] Manually test wallet/status flows with screen-reader-friendly text.
- [ ] Fix all critical and serious accessibility findings before public launch.

## Current Repo-Specific Next Fixes

- [ ] Bundle or pin dashboard JavaScript/CSS and remove unsafe public CDN dependency patterns.
- [ ] Add a dashboard accessibility pass for labels, focus states, contrast, status messages, and reduced motion.
- [ ] Add deployment environment config so local/test/mainnet addresses cannot be confused.
- [ ] Add a public release checklist tied to `npm.cmd test`, contract verification, and dashboard build output inspection.
