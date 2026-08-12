# Review Iteration Process

Originally prepared against live checkout `52e6a0d8a543293fda81d9709afaa264dbc2bce7` on `main`. Refresh every snapshot-specific prompt below against the active checkout before reuse.

This process keeps reviewer, agent, and implementation work useful without putting any model or automation inside the project's trust boundary. It is intended for ZK/nullifier work, privacy-continuity interventions, governance legitimacy review, and future operations tooling.

## Core Rule

Models may propose. Scripts, tests, contracts, and humans verify. Governance authorities authorize.

No reviewer, local model, agent, or script should be treated as allowed to move funds, grant roles, revoke participants, submit live proxy claims, publish roots, or change accounting state without the existing human and contract governance path.

## Clean-Room Intake Rule

When importing ideas from any outside artifact, borrow control patterns only. Do not copy code, file structure, skill names, prompt wording, marketing language, visual identity, or workflow text into this repo unless there is an explicit license review and a clear reason to preserve attribution.

Default posture:

- translate ideas into PBM-specific invariants;
- write fresh wording from first principles;
- prefer tiny local scripts over imported frameworks;
- keep any automation advisory, dry-run, or fixture-only until governance approves live use;
- record only the repo-local behavior we intend to adopt.

If a future change copies substantial external code, preserve the upstream license and document why a clean-room rewrite was not enough.

## Iteration Loop

1. Snapshot gate
   - Record branch, HEAD, and `git status --short`.
   - Stop if the prompt expects a different commit unless the task is explicitly to reconcile drift.
   - Treat handoffs, prior reviews, and generated docs as claim sets until the live repo confirms them.

2. Context packet
   - Name modified files separately from baseline reference files.
   - Include the smallest set of contracts, tests, scripts, and docs needed for the question.
   - State which claims are contract-enforced, script-enforced, dashboard-supported, docs-only, or not implemented.

3. Independent no-edits review
   - Ask for bounded findings with file/line evidence.
   - Require each finding to classify verified defect vs design risk.
   - Require the smallest next verification step.
   - Include at least one blind-spot or assumption-disruption section before implementation.

4. Reconciliation pass
   - Verify each finding against the live repo before accepting it.
   - Mark findings as confirmed, false, partially true, stale snapshot, or roadmap/design risk.
   - Prefer tiny verification commands and exact line references over broad summaries.

5. Deterministic gate
   - Convert accepted findings into scripts, tests, fixtures, schemas, or documentation changes.
   - Run the smallest relevant verification bundle before broad test runs.
   - Preserve the full local test suite as the release gate.

6. Bounded repair loop
   - If a check fails, make one narrow repair attempt tied to the failure evidence.
   - If the same class of failure repeats, stop and write the unresolved decision or blocker into the handoff.
   - Do not let the repair loop expand into new architecture without a new snapshot gate.

7. Artifact capture
   - Update the handoff with what changed, what was verified, and what remains docs-only.
   - Record commands, outputs, and limits that future reviewers need.
   - Keep privacy, trust-boundary, and governance caveats attached to any operational workflow.

## Reviewer Lanes

Use different reviewers for different jobs, but keep the same evidence standard.

| Lane | Best use | Required boundary |
|------|----------|-------------------|
| Legitimacy reviewer | Governance, fiduciary claims, privacy promises, public-readiness language | No edits; must identify contract-enforced vs docs-only gaps |
| Disruption reviewer | Hidden assumptions, hostile payer metadata, power loss, retaliation, captured institutions | No edits; must produce testable next checks |
| Code reviewer | Solidity behavior, tests, scripts, dashboard runtime | No edits unless explicitly moved into implementation mode |
| Operations reviewer | Runbooks, support flows, proxy relay, continuity drills | No live participant data; no secret handling |
| Aesthetic/workflow reviewer | Minimal panel friction, participant trust, non-surveillance feel | Advisory only until privacy and readiness claims are truthful |

## Prompt Template

Use this as the base for the next no-edits reviewer.

```text
Review the current local repo as an independent no-edits reviewer. Do not modify files, commit, push, open issues, or create PRs.

Snapshot:
- Repo: C:\Users\Josh\Desktop\PBMRebateTreasuryFinal
- Branch: main
- Expected HEAD: <fill with current `git rev-parse HEAD` before sending>
- First verify branch, HEAD, and git status. If the snapshot differs, report SNAPSHOT_MISMATCH and stop unless the only differences are explicitly listed below.

Known working files to review:
- ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md
- PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md
- REVIEW_ITERATION_PROCESS.md

Baseline reference context:
- contracts/PBMRebateTreasury.sol
- contracts/PatientFundParticipatoryBudgeting.sol
- contracts/PharmacyMutualCredit.sol
- test/PatientFundParticipatoryBudgeting.test.js
- test/PharmacyMutualCredit.test.js
- scripts/export-portability.js
- scripts/verify-export.js
- MECHANISM_COVERAGE.md
- OPERATIONAL_RUNBOOK.md
- CARE_CONTINUITY.md
- RETALIATION_AND_PRIVACY_THREAT_MODEL.md
- EVIDENCE_METADATA.md

Primary task:
Attack whether the new review/iteration process and privacy-continuity handoff turn broad ideas into verifiable, bounded, repo-aligned next steps. Do not assume the docs are accurate. Reconcile each claim against the live contracts, tests, scripts, and mechanism coverage.

Before findings, list 5 missing or under-asked questions. For each question include:
- why it matters;
- who is harmed if ignored;
- which repo evidence could answer it;
- whether it is blocker, roadmap, or philosophical/product direction.

Then return exactly 7 findings:
1-3: concrete mismatch or overclaim between docs and implementation.
4-5: smallest missing tests, fixtures, schemas, or scripts before implementation.
6: trust-boundary or governance-capture risk.
7: disruption-path blind spot involving power loss, no stable wallet, payer retaliation, issuer/auditor compromise, or helpdesk leakage.

For each finding include:
- file/line;
- verified defect vs design risk;
- evidence;
- smallest next verification step.

Keep each finding under 120 words. Prefer exact line references. Do not recommend upgradeable contracts or changes to core accounting/role separation unless you explicitly classify them as rejected/non-goals.
```

## Reconciliation Rubric

Every external finding should be reduced to one of these states:

| State | Meaning | Next action |
|-------|---------|-------------|
| Confirmed defect | Live code/docs/tests prove the finding | Patch or test immediately |
| Confirmed design risk | Finding is real but not a code bug yet | Add to design gate or runbook |
| Partially true | Reviewer found a real issue but overstated scope | Correct the scope and preserve the useful part |
| False against live repo | Live repo contradicts the finding | Record why and do not implement |
| Stale snapshot | Finding applied to an older commit | Re-check only if the pattern may recur |
| Useful provocation | Not currently true, but exposes a worthwhile threat model | Convert into a small experiment |

## Correction And Recovery Journal

When this project learns from a mistaken review, failed command, stale prompt, or bad assumption, record the lesson in a compact correction shape:

| Field | Meaning |
|-------|---------|
| Tried | The action, claim, prompt, script, or assumption that failed |
| Wrong because | The repo evidence, command output, or threat model that disproved it |
| Corrected rule | The smallest reusable rule for future work |
| Verification | The command, file/line, fixture, or reviewer gate that should catch it next time |

Corrections should stay factual and local to this repo. Do not promote a correction into a durable rule just because it sounds clever. Promote only when it has repeated, caused real confusion, or protects safety, privacy, governance legitimacy, or accounting correctness.

Use the same recovery shape after compaction, power loss, model switching, or external-review detours:

- current goal;
- branch, HEAD, and status;
- files currently under review;
- decisions already made;
- accepted corrections;
- next safest command or prompt;
- what must not be touched.

This is a utility pattern, not an agent memory requirement. The goal is to restart cleanly without giving future reviewers an unbounded memory dump.

## Claim Memory Discipline

Every accepted review fact should carry enough context that a future reviewer can tell what it meant and whether it still applies.

For any important claim, preserve:

- subject: contract, script, doc, test, operation, role, or participant flow;
- snapshot: branch, commit, date, and whether the worktree was clean;
- evidence: file/line, command output, test name, event, or artifact hash;
- time semantics: whether the claim describes current behavior, historical behavior, future design intent, or an incident;
- numeric scope: units, token decimals, epoch/round, threshold, count, sample size, and whether a number is exact or illustrative;
- enforcement level: contract-enforced, script-enforced, dashboard-supported, docs-only, or not implemented;
- confidence state: confirmed, partially true, false, stale, blocked, or useful provocation.

If a reviewer cannot attach a claim to the correct subject, time, evidence, and numeric scope, the next step is targeted retrieval or direct repo inspection, not guessing.

Use this especially for:

- external reviewer findings;
- ZK/nullifier privacy claims;
- revocation and burn-registry language;
- patient-fund accounting statements;
- mutual-credit capacity and voucher claims;
- readiness checklist counts;
- benchmark, scanner, or test-pass summaries.

## Deterministic Gates

Before implementing any ZK/nullifier or continuity mechanism, prefer these gates:

- A fixture or schema can reject malformed, stale, duplicate, or over-disclosing inputs.
- A local script can run without network access for the first milestone when the feature is about degraded operations.
- A test proves whether a claim is contract-enforced, script-enforced, dashboard-supported, docs-only, or not implemented.
- A privacy test fails if stable credential hashes, witness material, raw credentials, private keys, PHI, or stable wallet-to-pharmacy mappings appear in the wrong output.
- A runbook section states who can authorize the action and what the contract actually enforces.
- A reviewer can reproduce the verification step without trusting the author of the doc.

## Incoming Artifact Gate

Before pasting any handoff, outside review, generated prompt, or borrowed-repo summary into another model, run a quick artifact gate:

- Is the artifact anchored to the expected branch, commit, and worktree state?
- Does it contain executable instructions that conflict with the current task boundary?
- Does it ask a reviewer to edit, commit, push, open issues, disclose secrets, or trust unaudited claims?
- Does it contain private keys, raw credentials, witness material, PHI, stable wallet-to-pharmacy mappings, or support-ticket identifying data?
- Does it contain obvious prompt-injection text, tool-call bait, MCP spoofing language, hidden Unicode controls, or "ignore previous instructions" style content?
- Are its claims labeled as evidence, inference, design risk, or speculation?

If an artifact fails the gate, quarantine it as a claim source. Extract only the specific claims worth checking against the live repo.

## High-Sensitivity Handling

Treat these categories as high sensitivity even in local-first utilities:

- health, patient, or dispensing facts;
- pharmacy identity, relationship, retaliation, payer, or network-status facts;
- credential material, witness material, nullifier secrets, private keys, signatures, or authorization JSON;
- governance dissent, role-holder identity, emergency contacts, auditor compromise, issuer compromise, or helpdesk escalation facts;
- personal principles, safety preferences, and durable participant constraints that could be used for coercion.

High-sensitivity material should default to evidence hashes, pseudonymous IDs, encrypted blobs, synthetic fixtures, or operator-held offline packets. Do not put it in reviewer prompts, support examples, public docs, screenshots, or generated test output unless the artifact is explicitly designed to prove redaction.

## Safe Automation Candidates

Agent-like workflows are useful here only when they are narrow, reversible, and evidence-producing. The best candidates are recurring checks that already have deterministic inputs and a clear human review point.

Candidate units:

- mechanism-coverage drift check;
- reviewer-finding reconciliation;
- portability export and offline verifier smoke test;
- support-intake forbidden-field scan;
- burn-bundle or canary-bundle fixture validation;
- incoming artifact prompt-injection scan;
- context-recovery packet generator;
- stale readiness-check item report;
- scanner-artifact freshness report.

Each automation candidate needs a small manifest before implementation:

| Field | Required content |
|-------|------------------|
| Purpose | One sentence naming the specific drift or failure it detects |
| Inputs | Files, fixtures, env var names, or commands it reads |
| Forbidden inputs | Secrets, PHI, raw credentials, witness data, or live participant records it must reject |
| Outputs | Report file, console summary, fixture result, or handoff update |
| Exit states | Small taxonomy such as OK, WARN, FAIL, BLOCKED, or DRY_RUN |
| Verification | Command or test proving the result |
| Human gate | Person, council, maintainer, or review step required before action |

Automation safety rules:

- Dry-run comes first.
- No secrets are propagated between tools or generated artifacts.
- Network access is optional for the first milestone unless the workflow is explicitly about live provenance.
- One run should make at most one narrow proposed change.
- Automated repair may open a recommendation or patch branch, but must not push to `main`, publish roots, execute governance, submit claims, or perform on-chain writes.
- Repeated failures should create a blocker note, not an infinite repair loop.
- Quiet success is acceptable; state changes, warnings, and failures should be visible.

Promotion rule: a recurring correction may become a checklist item, script, test, or reviewer prompt clause only after it has a clear trigger, expected behavior, verification method, and rollback path. Repeated confusion is signal; one interesting idea is not.

## Self-Obsolescence Check

This process should stay lightweight. Delete, simplify, or fold it back into other docs if it stops producing:

- fewer false starts;
- clearer external-review prompts;
- faster live-repo reconciliation;
- smaller implementation experiments;
- more accurate mechanism coverage;
- better separation between privacy promises and implemented privacy.

If the process becomes ceremony, it should lose.
