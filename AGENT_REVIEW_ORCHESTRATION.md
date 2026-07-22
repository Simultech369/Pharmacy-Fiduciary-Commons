# Agent Review Orchestration

Status: draft operating protocol. This file is for Codex-led planning/review cycles. It does not authorize external disclosure, repository mutation, cleanup, commits, pushes, deployments, credentials use, or live-chain actions.

Current PBM checkpoint for solvency planning: `266016c83d544f86dbb67a49240356852e0498b4`

## Protocol Consensus Definition

In this repository, consensus is defined strictly as **operator-visible claims that have survived protocol checks**:

- *Shared files are NOT consensus.*
- *Green tests are NOT consensus.*
- *Agent confidence is NOT consensus.*

True protocol consensus is reached exclusively through a bounded four-role architecture:

```
[ 1. Implementer Agent ]
   └── Produces bounded patch + claim list
          │
          ▼
[ 2. Reviewer Agent ]
   └── Attacks claim list from clean/staged state (Read-Only)
          │
          ▼
[ 3. Lineage Verifier ]
   └── Maps claims to empirical evidence in review-context/agent_work_lineage_ledger.md
          │
          ▼
[ 4. Human Operator ]
   └── Accepts, rejects, narrows, or parks the claim
```

The architecture is not "more agents talk more." Shared files, passed tests, and
agent agreement are inputs to review, not consensus. A claim reaches consensus
only when the operator can see:

- where the claim came from;
- how to state the claim in plain human language;
- what the claim implies to a newcomer or operator;
- what the evidence actually proves, narrowly;
- what live-code or command evidence checked it;
- what transformed it from opinion into accepted fact;
- which artifact now depends on it;
- what would invalidate it.

The required consensus output is a recorded claim disposition in the lineage
ledger or a directly linked handoff packet. If the operator has not accepted,
rejected, narrowed, or parked the claim, the claim remains unpromoted no matter
how many agents repeated it.

## Non-Negotiable Boundary

More autonomy in review orchestration must mean more explicit gates, not more permission to act.

- No destructive cleanup.
- No `git reset`, broad delete, branch substitution, VM substitution, or closest-match resource operation.
- No global `$HOME`, PATH, credentials, shell profile, RPC endpoint, provider config, or database mutation to make a reviewer run pass.
- No real funds, real credentials, production data, live privileged endpoints, or irreversible approvals in tests or prompts.
- No external disclosure without explicit approval for the exact packet class and provider route.
- No reviewer output is truth until reconciled against local files, commands, and tests.
- No reviewer may edit, stage, commit, push, open PRs, open issues, deploy, publish roots, move funds, grant roles, revoke users, submit claims, or clean the working tree.

## Disclosure Classes

| Class | Contents | Default route |
|---|---|---|
| `PUBLIC_COMMITTED` | Public GitHub commit files only, no local dirty/untracked artifacts | May be prepared for external review only after explicit approval |
| `LOCAL_PLANNING` | Untracked handoffs, prompts, review-context notes, local docs | Local or explicitly approved external review only |
| `LOCAL_CODE_DIRTY` | Modified working tree files not yet committed | Local review only unless the user approves exact file disclosure |
| `SECRET_OR_SENSITIVE` | Credentials, API keys, PHI, patient/pharmacy identity, witness material, private keys, support-ticket identifiers, stable wallet-to-pharmacy mappings | Never send to reviewer prompts |
| `LIVE_PRIVILEGED` | Production RPCs, deploy keys, multisig/role operations, real funds, database service roles | Never send or use in review cycles |

If the packet class is ambiguous, classify upward and stop for approval.

## Cycle State

Each reviewer cycle should record:

- repo path;
- branch;
- HEAD;
- `git status --short`;
- disclosure class;
- exact files included;
- exact model/provider/launcher;
- prompt path or inline prompt;
- raw output path;
- provider errors or truncation warnings;
- reconciliation result;
- next action.

Recommended output location:

- raw outputs: `review-context/<date>-<lane>-raw.md`;
- model metadata: `review-context/<date>-<lane>-model.txt`;
- reconciliation: `review-context/<date>-<lane>-reconciliation.md`;
- Antigravity summary: a parallel handoff doc, not an overwrite of Antigravity's own work.

## Reviewer Lanes

| Lane | Best at | Weakness | Default packet |
|---|---|---|---|
| Codex 5.6 | high-stakes repo-grounded planning critique, policy separation, implementation-risk review | can sound authoritative; must not become implementer | `PUBLIC_COMMITTED` plus selected local planning docs only after approval |
| OpenClaude | blind spots, strategy, governance legitimacy, threat framing, disruption paths | may overgeneralize; needs exact snapshot and no-edits frame | smallest docs packet |
| Zero | proof-vs-theater checks, repo-grounded command-aware critique, boundary leakage | provider/tooling can be brittle | committed repo snapshot or narrow local packet |
| Kimi/Hunyuan long context | stale docs, contradiction discovery across many files, overclaim detection | flat bundles can confuse duplicate basenames; external disclosure | filtered bundle with path labels |
| Qwen coder/planner | code-path critique, implementation-plan stress tests, script/test review | may optimize toward coding; external unless verified local | selected code/tests plus planning gate |
| DeepSeek reasoner/coder | adversarial logic, invariant gaps, economic/accounting edge cases | may overstate severity; external unless verified local | focused contract/tests/spec packet |
| Cohere command/retrieval reviewer | document retrieval, summarization, policy consistency, enterprise-style risk classification | less ideal for Solidity edge cases; usually external | docs packet with explicit citation requirement |
| Gemma local/open-weight | private-first sanity review of small excerpts and policy docs | less reliable on whole-repo evidence unless context is curated | local excerpts or public docs |
| Gemma via OpenRouter | same as above, but external and context/provider dependent | external disclosure | approved filtered packet |
| Seed-style agentic reviewer | "what will break when implemented" and implementation-plan stress tests | external/proprietary unless verified local; may push toward coding | policy docs plus tests, no dirty full repo |
| Muse-style UX/strategy reviewer | UX, product language, participant trust, multimodal critique if route exists | external/proprietary; not evidenced locally for PBM runs | public docs/screenshots only with approval |

Do not substitute one lane for another without recording why.

## Debug Rules

Provider failures should not become environment repair.

- `402` or zero credits: downgrade only to a previously approved free model in the same disclosure class, or stop.
- `429` or rate limit: retry with bounded backoff, then stop.
- context too large: reduce the packet by explicit file manifest, preserving path labels.
- model missing: skip and record unavailable; do not pick a random nearby model.
- duplicate basenames in a zip: wrap each file as `--- START OF FILE: relative/path ---` to avoid root README confusion.
- network blocked: request approval only if the user has approved external disclosure for the exact packet.
- launcher flag mismatch: verify `--help`; for current Windows `codex.cmd exec`, use `-s read-only -` and do not use `-a never`.
- missing named file, branch, VM, env var, or provider: stop instead of using a closest match.
- local model spinner/no-output: stop the model by exact model or PID, record the failed attempt, and retry only with a smaller packet and a bounded timeout.

After two failures of the same class, write a blocker note instead of continuing to improvise.

## Core Loop

1. Snapshot gate
   - `git rev-parse HEAD`
   - `git branch --show-current`
   - `git status --short`
   - Stop on unexpected mismatch unless the task is drift reconciliation.

2. Packet gate
   - Pick disclosure class.
   - List exact files.
   - Exclude `.git`, `node_modules`, `artifacts`, `cache`, `dist`, secrets, raw support data, and prior raw model outputs unless intentionally reviewed.
   - For external review, ask for explicit approval before sending.

3. Capability prompt
   - Use the lane-specific prompt below.
   - State no edits, no commits, no pushes, no cleanup.
   - Require evidence, uncertainty, and verification steps.

4. Raw capture
   - Save model output unchanged.
   - Save model/provider metadata.
   - Record context-limit or truncation issues.

5. Reconciliation
   - Verify each finding against the live repo.
   - Classify as confirmed defect, confirmed design risk, partially true, false, stale, duplicate, or useful provocation.
   - Do not patch from raw output alone.

6. Handoff update
   - Add accepted planning results to a parallel Codex/Antigravity handoff.
   - Keep unresolved decisions explicit.
   - Pick the next reviewer only if it answers a different question.

## Reviewer-Cycle Disposition Rule

Before running any model review, name its intended output bucket:

- acceptance criterion;
- contradiction to reconcile;
- under-asked question;
- duplicate signal;
- wording improvement;
- provider failure.

A reviewer result may be preserved only inside its named bucket. It does not become policy acceptance, implementation authority, publication authority, or backlog scope by default.

If the result does not fit one of those buckets, do not promote it into the handoff packet. Summarize it as exploratory only or discard it.

Duplicate signal is still useful: it can increase confidence that a concern is real, but it does not create a new task unless it adds evidence, sharper wording, or a better local verification question.

## Prompt Templates

### Codex 5.6 Planning Critic

```text
You are Codex 5.6 acting as a read-only strategic reviewer and plan critic.

Repository:
<LOCAL_REPO_ROOT>

Expected HEAD:
<HEAD>

Boundary:
- Review/planning only.
- Do not edit files.
- Do not stage, commit, push, branch, clean, delete, reset, deploy, or repair environment state.
- Treat all local handoffs and previous model outputs as claim sets until verified.
- If a target is missing or ambiguous, stop rather than substitute a nearby target.

Task:
Critique whether the current planning artifact separates policy from implementation. Focus on governance decisions, accounting semantics, claimant fairness, operator confusion, and non-destructive workflow risk.

Difficulty instruction:
This is high-stakes planning work. Use deeper reasoning, but do not become more autonomous. If uncertain, increase grounding, cite evidence, and ask for permission rather than recommending irreversible action.

Output:
- Executive take
- Snapshot concerns
- Policy decisions that must remain human/governance choices
- Repo-grounded risks with file/line evidence
- What Antigravity should be prepared to implement only after approval
- What explicitly must not be touched
```

PowerShell shape:

```powershell
$prompt | codex.cmd exec -C "<LOCAL_REPO_ROOT>" -m "gpt-5.6-sol" -s read-only -
```

### OpenClaude Blind-Spot Reviewer

```text
Review this repo packet as a no-edits blind-spot reviewer.

Your strength is adversarial framing, institutional risk, governance legitimacy, and under-asked questions.

Do not propose implementation. Do not edit files. Treat the packet as evidence plus claims, not truth.

Before findings, list 7 under-asked questions. For each:
- why it matters;
- who is harmed if ignored;
- what repo evidence could answer it;
- whether it is blocker, roadmap, or philosophical/product direction.

Then give findings focused on:
- policy hidden inside code;
- participant retaliation or metadata leakage;
- governance capture;
- safety theater;
- future obsolescence from over-eager completion;
- where Antigravity needs explicit owner decisions before coding.
```

### Kimi/Hunyuan Long-Context Contradiction Reviewer

```text
You are a long-context contradiction and overclaim reviewer.

You are given a filtered repo packet with file path sentinels:
--- START OF FILE: relative/path ---
...
--- END OF FILE: relative/path ---

Do not edit, patch, or recommend broad implementation.

Primary task:
Find contradictions between code, tests, README, handoffs, dashboards, runbooks, and planning docs.

Pay special attention to:
- stale snapshot pins;
- duplicate basename confusion;
- docs that say a function reverts when current code permits lifecycle continuation;
- words such as "debt", "settled", "verified", "proof", "production", "private", "unlinkable", "safe", or "automated";
- dashboard language that may tell operators the wrong action will fail or succeed.

Return exactly 7 findings. For each:
- title;
- severity;
- verified defect vs design risk vs stale claim;
- file/path evidence;
- why it matters;
- smallest local verification step;
- whether it blocks Antigravity implementation.
```

### Qwen Code-Path Reviewer

```text
You are a read-only code-path and implementation-plan reviewer.

Do not edit, patch, stage, commit, push, branch, clean, or repair environment state.

Your strength is following code paths and predicting where a future implementer could make the wrong small change.

Review only the supplied files. If context is missing, say what file or command would verify it rather than guessing.

Focus on:
- tests that assert the wrong policy;
- scripts that can pass while enforcing a stale assumption;
- docs that would lead Antigravity to edit the wrong file;
- ambiguous API semantics;
- places where a narrow implementation could accidentally become a broad refactor.

Return:
- 5 code-path risks;
- 3 missing verification steps;
- 3 implementation instructions Antigravity should not be allowed to infer silently.
```

### DeepSeek Invariant Reviewer

```text
You are a read-only invariant and edge-case reviewer.

Do not edit, patch, stage, commit, push, branch, clean, or repair environment state.

Your strength is adversarial reasoning over accounting, liveness, fairness, and governance invariants.

For each finding:
- state the invariant being assumed;
- state the counterexample or uncertainty;
- classify as confirmed defect, design risk, stale claim, or needs verification;
- provide the smallest local test or inspection that could settle it.

Focus on:
- claimant priority under scarce liquidity;
- council refund priority;
- debt/shortfall naming vs actual semantics;
- reclaim grace period under insolvency;
- preview/dashboard/operator mismatch;
- repeated loss/top-up cycles.

Do not recommend implementation until the policy decision is explicit.
```

### Cohere Policy Retrieval Reviewer

```text
You are a read-only policy-consistency and retrieval reviewer.

Do not edit, patch, stage, commit, push, branch, clean, or repair environment state.

Your strength is comparing documents, extracting contradictions, and classifying claims with citations.

For every claim you make, cite the exact file path and quoted phrase or line reference from the packet. If citation is impossible, mark the claim NEEDS_RETRIEVAL.

Focus on:
- whether policy docs disagree with contract/test descriptions;
- whether public docs overclaim production readiness, privacy, proof, settlement, or safety;
- whether handoff docs are stale relative to the current checkpoint;
- whether the same term means different things across docs.

Return a table:
claim | files in tension | risk | classification | smallest reconciliation edit
```

### Gemma Private-First Policy Reviewer

Known local note: a full three-document `gemma3:12b` pass on this packet produced only progress spinner output and the final text `Okay`. Treat that as no review signal. Retry Gemma with one narrow excerpt or table at a time and a timeout.

```text
Review this excerpt as a private-first policy sanity checker.

Your job is not whole-repo audit. Your job is to classify recommendations using deterministic gates:
- SAFE_TO_PLAN
- NEEDS_VERIFICATION
- NEEDS_PERMISSION
- DO_NOT_TOUCH

For each major recommendation:
- classify it;
- name the evidence required;
- name the permission boundary;
- identify any destructive cleanup or future-obsolescence risk.

Prefer concise contradictions and missing definitions over broad architecture advice.
```

### Zero Proof-Vs-Theater Reviewer

```text
Review the current repo as a read-only proof-vs-theater critic.

Do not edit, commit, push, branch, clean, or fix environment state.

First verify:
- branch;
- HEAD;
- status;
- whether tests or docs being cited are from the same snapshot.

Focus on claims that sound verified but are only:
- docs-only;
- dashboard-only;
- local MAC/integrity checks;
- semantic/mock proof paths;
- model/reviewer assertions;
- uncommitted artifacts;
- stale scanner notes.

Return findings only when you can point to file/line evidence or a small verification command.
```

### Seed-Style Agentic Implementation-Risk Reviewer

```text
Review this as an implementation-risk planner, not as an implementer.

Your strength is predicting how an autonomous implementer could accidentally encode unresolved policy.

Do not write code. Do not suggest cleanup. Do not assume permission to mutate files.

Find places where an implementer could silently choose:
- claimant priority;
- council refund priority;
- grace-period tolling;
- "debt" vs "shortfall" semantics;
- environment overrides;
- closest-match resource behavior;
- tests that use live credentials, live funds, or privileged endpoints.

For each risk:
- name the unresolved decision;
- name the likely accidental implementation;
- name the safer owner decision gate;
- name a narrow test or doc that should exist before code.
```

### Muse-Style UX/Strategy Reviewer

```text
Review this as a UX/strategy and participant-trust critic.

Do not edit files or suggest implementation details beyond planning guidance.

Focus on:
- whether public language creates false confidence;
- whether dashboard/operator copy could cause unsafe action;
- whether participants could misunderstand accounting commitments as liquid guarantees;
- whether the product story hides retaliation, metadata, or governance risks;
- whether "building in public" is honest about backlog and prototype boundaries.

Return:
- strongest public-trust risk;
- language that should be softened or made more precise;
- one participant-safety warning that must remain visible;
- one thing not to polish until policy is decided.
```

## Current Solvency Review Queue

For `266016c83d544f86dbb67a49240356852e0498b4`, current local review status is:

1. Gemma local/private-first: attempted full three-document pass; no usable signal.
2. Qwen local policy pass: completed summary-based response with zero repo grounding; reconciled in `review-context/2026-07-18-qwen-local-solvency-policy-reconciliation.md`.
3. DeepSeek local `DebtSettled` semantics pass: completed summary-based response with zero repo grounding; reconciled in `review-context/2026-07-18-deepseek-local-debtsettled-reconciliation.md`.
4. Codex 5.6 Terra-style handoff review: completed read-only, repo-grounded second-opinion pass; reconciled in `review-context/2026-07-18-codex56-terra-solvency-handoff-reconciliation.md`.
5. Codex 5.6 Luna crossover review: completed light read-only comparison pass; reconciled in `review-context/2026-07-18-codex56-luna-dizzy-crossover-reconciliation.md`.

Next useful reviewer options:

1. No further model review before owner/governance decision capture unless a narrow question emerges.
2. Local narrow Gemma retry on only the decision table if a second local sanity check is worth the time.
3. Kimi/Hunyuan, Cohere, Muse-style, Seed-style, or external Qwen/DeepSeek only after explicit approval for the exact disclosure packet.
4. Another Codex 5.6 review only after owner decisions are filled in, focused on implementation-risk framing rather than policy selection.

Do not run another broad external bundle until the exact packet is selected and approved.

Archive this orchestration packet once owner/governance decisions and the next authorized implementation slice are recorded. Do not keep adding reviewer cycles unless they answer a newly identified blocker.

## Stop Conditions

Stop and write a blocker instead of continuing when:

- the model/provider route would disclose unapproved local files;
- the model is unavailable and no approved equivalent lane exists;
- a command would mutate git, environment, credentials, live endpoints, or production state;
- the same provider/debug class fails twice;
- a reviewer asks to edit or take actions;
- output lacks file/path evidence and cannot be reconciled;
- the next step would let implementation choose unresolved policy.

## Agentic Collaboration & Review Framework (ACRF)

This framework defines how autonomous agents collaborate on review, operations, and communications within this repository.

### Philosophy
The repository is not purely written in "inter-agent API protocol" language. It serves two distinct audiences:
1. **Machines / Agents / Operators**: Require deterministic, receipt-friendly, exact language.
2. **Humans / Pharmacies / Patients / Councils**: Require plain-language legitimacy, care-continuity framing, and honest boundaries.

*Core Rule:* Write machine-checkable operations, then translate them into human-legible governance language without overclaiming.
*Safety Principle:* **These contracts should be agent-readable and agent-assistable before they are agent-operated.** Agents remain strictly advisory: they may monitor, classify, draft, simulate, and prepare receipts, but they hold no signing or execution authority.

### Backlog Lanes

#### 1. Agentic Review Layer
*   **Researcher:** Builds target dossiers containing files, dependencies, and past context before edits.
*   **Classifier:** Separates incoming signals into defect, risk, stale claim, design idea, or noise.
*   **ICP/Gravity Scorer:** Ranks issues so attention is allocated to security boundaries, invariants, or launch blockers.
*   **Qualifier:** Screens out low-evidence or out-of-scope work.

#### 2. Agentic Operations Layer
*   **Sequence Builder:** Defines prompt chains (opener, follow-up, backup, stop condition).
*   **Signal Hunter:** Monitors git state, tests, compiler lints, timelocks, and contract events.
*   **Agent Operator:** Functions in advisory mode only—drafting actions and simulating execution without key custody.

#### 3. Agentic Communication Layer (Anti-Slop Overlay)
*   **Voice Writer:** Drafts commit messages, handoffs, and prompts in direct, human, evidence-grounded prose.
*   **Anti-Slop Rules:**
    *   No production privacy/security claims without absolute evidence.
    *   No "trustless" descriptions where trust roots or governance keys exist.
    *   Explicitly distinguish contract-enforced rules from docs-only behaviors and future designs.
    *   Cite specific files, tests, commits, and events.
    *   Keep affected human stakeholders visible.
