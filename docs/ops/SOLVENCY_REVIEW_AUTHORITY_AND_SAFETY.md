# Solvency Review Authority And Safety Ledger

Status: draft planning artifact. This file records review authority, claim disposition, and validation side-effect boundaries for the patient-fund solvency lane. It is not policy acceptance and does not authorize implementation.

Base checkpoint: `266016c83d544f86dbb67a49240356852e0498b4` (`Queue patient fund solvency debt`)

Purpose: keep model reviews, planning documents, tests, and implementation authority from collapsing into one another.

## Authority Order

1. Owner/governance decision records in `SOLVENCY_DEBT_SEMANTICS.md`, only after each required decision has an explicit selected option, decision-maker, date, and scope.
2. Owner/governance decision records in `SOLVENCY_OWNER_DECISION_WORKSHEET.md`, under the same explicit acceptance requirements.
3. Separate implementation authorization naming the approved slice and allowed files.
4. Runtime code and tests as characterization evidence for a specific commit.
5. `ANTIGRAVITY_SOLVENCY_IMPLEMENTATION_PACKET.md`, `CODEX_SOLVENCY_PLANNING_ADDENDUM.md`, and `HANDOFF_TO_CODEX_5_5.md` as coordination handoffs.
6. `AGENT_REVIEW_ORCHESTRATION.md` as reviewer protocol.
7. `review-context/*.md` as reconciled claim sources.
8. Raw model outputs, private notes, and external reviews as claim sources only.

No lower layer can silently ratify policy, authorize code changes, or override a higher layer.

## Artifact Roles

| Artifact | Role | Authority Limit |
|---|---|---|
| `ANTIGRAVITY_HANDOFF_BUNDLE_MANIFEST.md` | Current handoff entry point | Package map and stop gate summary; does not authorize implementation. |
| `SOLVENCY_DEBT_SEMANTICS.md` | Draft decision table | Authoritative only after owner/governance fills explicit decisions. |
| `SOLVENCY_OWNER_DECISION_WORKSHEET.md` | Decision-capture worksheet | May record `DEFER / DO NOT IMPLEMENT YET`; does not authorize code by itself. |
| `SOLVENCY_REVIEW_AUTHORITY_AND_SAFETY.md` | Review claim and safety ledger | Coordinates evidence; does not choose policy or authorize work. |
| `ANTIGRAVITY_SOLVENCY_IMPLEMENTATION_PACKET.md` | Implementation packet template | Starts as no-implementation-authorized; future use must name approved slice and files. |
| `PBM_EVM_HACK_LESSONS.md` | External hack-pattern translation | Security checklist only; does not import exploit code or authorize implementation. |
| `PBM_HUMAN_LANGUAGE_AND_DESIGN_NOTES.md` | Optional human-facing language/design guidance | Copy/design checklist only; not a style gate or implementation authority. |
| `PBM_BOUNDED_WORK_LOOP_NOTES.md` | Optional bounded-work guidance | Workflow framing only; does not install Loopy, schedule work, or authorize implementation. |
| `CODEX_SOLVENCY_PLANNING_ADDENDUM.md` | Antigravity-facing planning addendum | Handoff only; implementation still needs separate authorization. |
| `HANDOFF_TO_CODEX_5_5.md` | Bounded Codex planning handoff | Reviewer/planner scope only. |
| `AGENT_REVIEW_ORCHESTRATION.md` | Model-review protocol | Controls prompt and disclosure discipline, not policy. |
| `PUBLIC_PROGRESS_NOTE_DRAFT.md` | Draft public-safe update | Publication requires owner approval of exact text and destination. |
| `review-context/*.md` | Reconciled reviewer notes | Claim sources only; not public by default. |
| `contracts/PatientFundParticipatoryBudgeting.sol` | Current enforced behavior | Characterizes checkpoint behavior; does not prove governance acceptance. |
| `test/PatientFundParticipatoryBudgeting.test.js` | Regression evidence | Preserves observed behavior; does not ratify policy defaults. |
| Stale public docs/dashboard copy | Contradiction surfaces | Update only after decisions and explicit scope. |

Root presence, model agreement, or test existence does not create authority.

## Claim Ledger

| Source | Reviewed Head | Evidence | Claim | Classification | Disposition | Owner |
|---|---|---|---|---|---|---|
| Codex 5.6 Terra | `266016c83d544f86dbb67a49240356852e0498b4` | `review-context/2026-07-18-codex56-terra-solvency-handoff-reconciliation.md` | Older handoff language could bypass the decision gate and reintroduce hard-revert assumptions. | Verified planning defect | Adopted by replacing stale handoff language and adding authority rules. | Codex |
| Local Qwen | Summary packet only | `review-context/2026-07-18-qwen-local-solvency-policy-reconciliation.md` | Claimant priority, council refund priority, reclaim timing, and debt terminology remain unresolved policy gates. | Advisory, zero repo grounding | Retain as intelligibility signal; owner decision still required. | Owner/Codex |
| Local DeepSeek | Summary packet only | `review-context/2026-07-18-deepseek-local-debtsettled-reconciliation.md` | Shortfall-reduction events must not imply repayment when caused by cancellation or snapshot refresh. | Advisory semantic risk | Adopt as docs/dashboard wording gate. | Codex/Owner |
| Codex 5.6 Luna | PBM plus local comparison docs | `review-context/2026-07-18-codex56-luna-dizzy-crossover-reconciliation.md` | PBM should borrow a narrow claim ledger, artifact-role map, and solvency-scoped side-effect matrix, not broader comparison-project architecture. | Pattern-transfer recommendation | Adopt docs-only in this ledger. | Codex |
| EVM hack registry/analyzer | External reference repos | `PBM_EVM_HACK_LESSONS.md` | Historical hack taxonomy maps to PBM-specific accounting, role, external-call, auth, arithmetic, and liveness checks. | Advisory pattern-transfer | Adopt as checklist for future authorized slices; no code import. | Codex/Antigravity |
| Human-language/design references | External reference repos | `PBM_HUMAN_LANGUAGE_AND_DESIGN_NOTES.md` | PBM public copy and dashboard language should show deliberate choices, specific claims, authority boundaries, and operator safety without becoming a new style mandate. | Advisory pattern-transfer | Adopt as optional copy/design check; no scanners or broad rewrite. | Codex/Antigravity |
| Loopy reference | External reference repo | `PBM_BOUNDED_WORK_LOOP_NOTES.md` | PBM handoff prep, reviewer cycles, public drafts, and future implementation slices should have explicit checks and stop states. | Advisory workflow pattern-transfer | Adopt as optional loop framing; no installation or automation. | Codex/Antigravity |
| Local Mistral/Gemma/Qwen final scan | Handoff snippets only | Chat transcript only; no repo artifact | Dangerous-verb review found one softer readiness phrase and tighter start-round deferral language. | Advisory wording signal | Adopted docs-only; no implementation scope added. | Codex |
| Cohere North Mini Code | Explicitly approved redacted mini-packet | Chat transcript only; no repo artifact | Returned `content: null` twice with reasoning metadata only. | Provider failure | Do not promote or reconstruct claims from hidden/reasoning-only output. | Codex |
| Tencent Hy3 | Explicitly approved redacted mini-packet | Chat transcript only; no repo artifact | Confirmed lifecycle/payment and debt-event boundaries; suggested "read-only intake observation" phrasing. | Duplicate signal with minor wording improvement | Retain as launch-card wording option only; no new blocker or scope. | Codex |

Future reviewer claims should be added here only after reconciliation against the current checkpoint. Unverified claims remain non-authoritative.

Recommended classifications: `verified defect`, `verified contradiction`, `plausible risk`, `policy question`, `stale claim`, `advisory`, `future backlog`.

## Solvency Validation Side-Effect Matrix

| Check Or Command Class | Expected Mutable Surface | Current Classification | Rule |
|---|---|---|---|
| `git rev-parse HEAD`, `git branch --show-current`, `git status --short` | None | Read-only candidate | Safe for snapshot gates. |
| `rg`, `Get-Content`, file reads | None | Read-only candidate | Safe for planning review. |
| Focused patient-fund Hardhat tests | Hardhat artifacts/cache and local mock chain state | Mixed | Run only after explicit validation approval; use local mocks and record artifacts written. |
| Full test suite | Hardhat artifacts/cache plus unrelated test surfaces | Mixed/broad | Hold until exact scope is approved. |
| Dashboard build/check commands | Build outputs or generated assets may change | Unknown until inspected | Classify exact command before running. |
| `scripts/pre_commit_audit.py` | Provider/network access, review outputs, possible credentials | Held | External route is packet-gated to `PUBLIC_SAFE` only and requires exact `PBM_APPROVE_EXTERNAL_REVIEW=PUBLIC_SAFE`; dirty code remains local-only. |
| `scripts/openrouter_review.py` | External disclosure and review outputs | Held | Requires explicit approval for exact packet and provider route. |
| Top-up or recovery experiments | Token balances, accounts, approvals, RPC/provider state | Prohibited in planning | Use only local mock-token tests after separate approval. |
| Git stage/commit/push | Repository/public state | Requires explicit approval | Stage only exact approved files. |
| Cleanup/delete/move/reset operations | Filesystem and git history | Prohibited by default | Missing resources stop the task; do not substitute targets. |

Before any command that may write, record:

1. exact command;
2. expected mutable paths;
3. disposable-root boundary, if applicable;
4. cleanup target;
5. files written, deleted, and remaining.

Do not call a validation check safe until its cleanup target resolves inside a verified disposable root or the command has been reclassified as read-only by current code inspection.

## Public-Building Boundary

Public updates must be commit-anchored and redacted. Exclude private reviewer context, raw model artifacts, provider details, dirty local path lists, credentials, endpoints, participant identity material, and comparison-project internals.

Docs-only public progress can describe:

- lifecycle liveness versus payment liveness;
- unresolved policy decisions;
- the existence of a decision-gated handoff process;
- the exact committed checkpoint when public evidence supports it.

Do not publish claim-ledger rows or review-context notes unless a separate redaction pass approves them.

## Patterns Not Borrowed

Do not import unrelated prompt-pack, memory, agent-runtime, provider-routing, route-registry, file-locking, or broad cleanup architecture into this solvency lane. Borrow the containment discipline only.
