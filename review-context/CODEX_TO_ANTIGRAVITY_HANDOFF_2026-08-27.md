# Codex to Antigravity Handoff - 2026-08-27

## 0. Read This First

This is a path-first handoff from Codex after reconciling Antigravity's latest
PBM and scratch Council Engine updates.

Primary rule: use the weakest valid claim. Do not promote inherited green
handoff prose into fact unless the current local tree and current receipt prove
it.

## 1. Live PBM Repo Anchor

```text
Repository Root:
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal

Current branch:
main

Current HEAD observed by Codex:
7be1cb91ad39091b81f3cf4b873a342dc247f859

Local branch state:
main is ahead of origin/main by 2 commits.

Local commits ahead of origin/main:
7be1cb9 feat(governance): harden pre-commit external disclosure gate and packet deduplication
45af107 Promote repo-local council gateway proof boundary

origin/main observed locally:
4a892575d1ef15486baedcc4012a7ec87c0d3838
```

## 2. Current Dirty Working Tree

Codex last observed a dirty working tree with these tracked changes:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.agents\memory\LEARNINGS_QUEUE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\MODEL_INVENTORY.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\dossier_rag_eval_summary.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\dossier_tree_index.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\multimodal_harness_receipt.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\verification_master_receipt.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\PBMRebateTreasury.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\hardhat.config.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\MULTIMODAL_ROSTER_LOOPS.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\SINGLE_REPO_STATE_LEDGER.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\SWARM_ROSTER_40_MODELS.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\MODEL_INVENTORY.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\provider_capability_matrix.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\provider_capability_matrix.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\context_hygiene_audit.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\dossier_rag_retrieval.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\eval_dossier_rag.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\verify_all.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\AgentClaimVerifier.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PBMRebateTreasury.dispute-timeout.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PBMRebateTreasury.security.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PharmacyMutualCredit.test.js
```

Codex last observed these untracked paths:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\ANTIGRAVITY_TO_CODEX_HANDOFF_2026-08-26.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\5_6_sol\
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\verify_agent_claims.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\A2AProtocolEngine.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\AgentClaimVerifier.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\AutonomousPatchAndChaosPipeline.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\CouncilEngineModules.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\NeurosymbolicFormalAndP2PEngine.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PBMRebateTreasury.fuzz.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\ZeroDatabaseLiveness.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\foundry\TreasurySolvencyInvariant.t.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\resilience\zero-database-drill.mjs
```

Note: `test\AgentClaimVerifier.test.js` appears in the dirty tree because Codex
edited it after it had already been introduced as an untracked Antigravity file.
Re-run `git status --short --branch` before staging.

## 3. What Codex Reconciled

### Bucket 1 and Bucket 2

These are already committed locally on `main`, but not pushed:

```text
45af107 Promote repo-local council gateway proof boundary
7be1cb9 feat(governance): harden pre-commit external disclosure gate and packet deduplication
```

Do not re-stage those as if they were still dirty work.

### New Antigravity PBM Bundle

Antigravity's latest PBM handoff claims a unified milestone:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\ANTIGRAVITY_TO_CODEX_HANDOFF_2026-08-26.md
```

Useful, but not self-proving. Codex found one stale/incomplete receipt boundary:
the handoff claimed `cache\verification_master_receipt.json` was a live 9/9
PASSED receipt with 419 passing Hardhat tests, but the local cache was missing
or later contained a failed/incomplete receipt during Codex verification.

## 4. Codex Verification Results Since Pickup

### Scratch Council Engine

Run from this exact cwd:

```text
C:\Users\Josh\.gemini\antigravity\scratch\council_engine
```

Codex verified:

```text
python -B -m unittest discover -p "test_*.py"
Result: 298 tests passed in 279.152s
```

Important cwd boundary:

```text
Running scratch discovery from C:\Users\Josh\Desktop\PBMRebateTreasuryFinal produced 29 false CLI failures.
Reason: scratch CLI tests shell out to council_cli.py relative to cwd.
Fix: run scratch discovery from C:\Users\Josh\.gemini\antigravity\scratch\council_engine.
```

Focused scratch checks also passed:

```text
python -B -m unittest discover -s C:\Users\Josh\.gemini\antigravity\scratch\council_engine -p test_cross_project_federation_bridge.py
Result: 4 tests passed

python -B -m unittest discover -s C:\Users\Josh\.gemini\antigravity\scratch\council_engine -p test_a2a_protocol_engine.py
Result: 12 tests passed
```

### PBM Focused Checks

Codex verified these PBM focused gates:

```text
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'

npx.cmd --no-install hardhat test test\A2AProtocolEngine.test.js --no-compile
Result: 7 passing

npx.cmd --no-install hardhat test test\AutonomousPatchAndChaosPipeline.test.js --no-compile
Result: 5 passing

npx.cmd --no-install hardhat test test\NeurosymbolicFormalAndP2PEngine.test.js --no-compile
Result: 5 passing

npx.cmd --no-install hardhat test test\AgentClaimVerifier.test.js --no-compile
Result after Codex patch: 8 passing

python scripts\index_dossier_tree.py
Result: PASSED, dirty/untracked count 35, documents scanned 13, contradictions 0

python scripts\eval_dossier_rag.py
Result: PASSED, positive cases 26, adversarial no-hit cases 8, hit rate@5 1.0, MRR 0.8782, NDCG@5 0.907

python scripts\verify_agent_claims.py --target reviews\rotational_swarm_review_dossier.md
Result: PASSED, 40 claims audited, 0 violations

python scripts\multimodal_swarm_harness.py --mode dry-run --offline --harness openhands-gemma3 --role formal_contract_checker --packet review-context\packet-openrouter-public-baseline.json --timeout-seconds 120
Result: PLANNED_DRY_RUN, no external dispatch, wrote cache\multimodal_harness_receipt.json
```

### Full PBM Master Verification

First full run:

```text
python scripts\verify_all.py
Result: FAILED after Step 1
Hardhat observed: 418 passing, 1 failing
Failure: test\AgentClaimVerifier.test.js expected receipt_cross_audit.receipt_found/status assumptions while cache receipt was absent or failed.
Receipt written: cache\verification_master_receipt.json with overall_status FAILED, steps_executed 1/9.
```

Codex repair:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\AgentClaimVerifier.test.js
```

Patch summary:

```text
- Added createTempReceipt() fixture helper.
- Ensures cache temp directory exists before writing test fixtures.
- The genuine dossier test now passes --receipt <temp fixture> instead of depending on the ambient generated master receipt.
- This removes a circular dependency where verify_all.py required Hardhat to pass, but a Hardhat test required a pre-existing successful verify_all.py receipt.
```

Focused post-repair check:

```text
npx.cmd --no-install hardhat test test\AgentClaimVerifier.test.js --no-compile
Result: 8 passing
```

Second full run:

```text
python scripts\verify_all.py
Result: outer Codex command timed out at 20 minutes
Hardhat Step 1 reached: 419 passing in about 17 minutes
Important: verify_all.py did not get enough time to continue Steps 2-9 or stamp a final 9/9 PASSED receipt before Codex's outer command timeout killed it.
```

Therefore the weakest valid PBM claim is:

```text
Hardhat reached 419 passing after the AgentClaimVerifier bootstrap fix, but the current local 9-step master receipt is not yet a fresh final 9/9 PASSED receipt.
```

## 5. A2A Proof Boundary

Current PBM and scratch A2A code is useful, but keep the claim narrow:

```text
Council-native signed handoff envelopes, trust-store verification, anti-replay nonces, prompt-injection sanitization, negotiation receipts, and reconciliation receipts are implemented and tested locally.
```

Do not yet claim:

```text
Full external A2A interoperability.
Agent Card discovery.
Task / Message / Part / Artifact external compatibility.
JSON-RPC over HTTP interoperability.
SSE task update streaming.
External push notification compatibility.
Live cross-project remote execution authority.
```

Primary local A2A paths:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\a2a_protocol_engine.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\test_a2a_protocol_engine.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\A2AProtocolEngine.test.js
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\a2a_protocol_engine.py
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\test_a2a_protocol_engine.py
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\cross_project_federation_bridge.py
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\test_cross_project_federation_bridge.py
```

Recommended A2A next slice after PBM receipt is clean:

```text
1. Add explicit Agent Card schema fixtures only.
2. Map Council-native message fields to external A2A shapes in read-only adapters.
3. Add tests proving no PHI/PII, private tool state, raw receipts, local code diffs, or secrets are exposed.
4. Only then add JSON-RPC/SSE handlers.
```

## 6. Proposed Commit Slices

Do not land the entire dirty tree as one mega-commit unless the operator
explicitly chooses reviewability tradeoffs. Better slices:

### Slice 3A - PBM Solvency, Zero-DB, and Treasury Invariants

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\PBMRebateTreasury.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\hardhat.config.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PBMRebateTreasury.security.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PBMRebateTreasury.dispute-timeout.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PBMRebateTreasury.fuzz.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PharmacyMutualCredit.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\ZeroDatabaseLiveness.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\resilience\zero-database-drill.mjs
```

Suggested verification:

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
npx.cmd --no-install hardhat test test\PBMRebateTreasury.security.test.js --no-compile
npx.cmd --no-install hardhat test test\PBMRebateTreasury.dispute-timeout.test.js --no-compile
npx.cmd --no-install hardhat test test\PBMRebateTreasury.fuzz.test.js --no-compile
npx.cmd --no-install hardhat test test\PharmacyMutualCredit.test.js --no-compile
npx.cmd --no-install hardhat test test\ZeroDatabaseLiveness.test.js --no-compile
node tools\resilience\zero-database-drill.mjs run
```

### Slice 3B - Agent Claim Verifier and Bootstrappable Master Verification

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\verify_agent_claims.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\AgentClaimVerifier.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\verify_all.py
```

Suggested verification:

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
npx.cmd --no-install hardhat test test\AgentClaimVerifier.test.js --no-compile
python scripts\verify_agent_claims.py --target reviews\rotational_swarm_review_dossier.md
```

### Slice 3C - Council Swarm Local Promotion

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\CouncilEngineModules.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\A2AProtocolEngine.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\AutonomousPatchAndChaosPipeline.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\NeurosymbolicFormalAndP2PEngine.test.js
```

Suggested verification:

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
python -B -m unittest discover -s tools\council -p "test_*.py"
npx.cmd --no-install hardhat test test\CouncilEngineModules.test.js --no-compile
npx.cmd --no-install hardhat test test\A2AProtocolEngine.test.js --no-compile
npx.cmd --no-install hardhat test test\AutonomousPatchAndChaosPipeline.test.js --no-compile
npx.cmd --no-install hardhat test test\NeurosymbolicFormalAndP2PEngine.test.js --no-compile
```

### Slice 3D - RAG, Model Roster, and Generated Evidence

Only stage generated cache files after a fresh successful run stamps them.

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\context_hygiene_audit.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\dossier_rag_retrieval.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\eval_dossier_rag.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\MODEL_INVENTORY.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\MODEL_INVENTORY.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\provider_capability_matrix.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\provider_capability_matrix.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\SINGLE_REPO_STATE_LEDGER.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\SWARM_ROSTER_40_MODELS.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\MULTIMODAL_ROSTER_LOOPS.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.agents\memory\LEARNINGS_QUEUE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\dossier_tree_index.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\dossier_rag_eval_summary.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\lineage_eval_benchmark.jsonl
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\multimodal_harness_receipt.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\verification_master_receipt.json
```

Suggested verification:

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
python scripts\index_dossier_tree.py
python scripts\eval_dossier_rag.py
python scripts\context_hygiene_audit.py
```

## 7. Immediate Next Command for Antigravity

Run the full master verifier with a long enough timeout. Codex's 20-minute
outer cap was too short after the suite grew to 419 Hardhat tests.

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
python scripts\verify_all.py
```

Acceptance criteria before any commit:

```text
cache\verification_master_receipt.json exists
overall_status == PASSED
expected_step_count == 9
steps_executed == 9
Hardhat observed_counts.passing_tests == 419 or the current live count from that run
git_lineage.head_commit == 7be1cb91ad39091b81f3cf4b873a342dc247f859 unless a new commit was intentionally created
```

Do not call the PBM tree "9/9 green" until that receipt exists and says so.

## 8. External Disclosure and Commit Boundary

Do not send local dirty code externally unless the operator explicitly approves
the exact disclosure class and the packet compiler says it is safe.

Current safer rule from Bucket 2:

```text
External review dispatch should be limited to PUBLIC_SAFE packets with exact operator approval.
LOCAL_CODE_DIRTY and INTERNAL_NO_TRAIN_OK are not enough for automatic external disclosure.
```

Commit/push remain L3 actions:

```text
No staging, commit, push, branch creation, deployment, paid model call, secret access, or live-chain action should be performed without explicit operator authorization.
```

## 9. Pickup Friction Notes

These slowed Codex pickup and should be improved in future handoffs:

```text
1. Dirty files were not labeled by owner/slice/generated-cache status.
2. Generated cache deletion looked like product deletion until generators were rerun.
3. Scratch tests fail falsely from the wrong cwd.
4. Windows test duration now exceeds 20 minutes for full master verification.
5. A2A language can drift from "Council-native signed envelopes" to "external A2A protocol" unless kept narrow.
```

Recommended new durable rule:

```text
Every Antigravity/Codex handoff should include a slice ownership manifest:
file path -> owner/source -> intended slice -> generated/manual -> required verifier -> known timeout budget.
```

## 10. Mental Model

Acceptance:

```text
The current tree is dirty. The cache receipt is not yet a final 9/9 pass. The
new A2A layer is local signed-envelope infrastructure, not external protocol
interoperability. Full verification is slow on Windows.
```

Change:

```text
The AgentClaimVerifier circular dependency has been repaired. Focused tests are
green. Scratch Council Engine is 298/298 green from the correct cwd. PBM
Hardhat reached 419 passing after repair. The next change is to run the full
9-step verifier with enough time and stamp a real receipt.
```

