# Codex Fresh Iteration Handoff - 2026-09-04

Purpose [dirty working tree]: copy-paste this file into a fresh Codex, Antigravity, OpenClaude, or OSS council session to resume work on `PBMRebateTreasuryFinal` without losing proof boundaries.

## 1. Current Repository Anchor

```text
Repository root:
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal

Current live anchor checked by Codex on 2026-09-04:
main@c3035199b8e2e763c58c4a1f75eefcad5bb02a1f [committed HEAD]

Remote sync checked by Codex on 2026-09-04:
origin/main matches HEAD; rev-list origin/main...HEAD returned 0 0.

Working tree before this handoff file was written:
clean.

Working tree after this handoff file is written:
dirty only if this file remains uncommitted.

Latest local verification receipt:
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\verification_master_receipt.json
```

Latest receipt summary from `cache\verification_master_receipt.json` [generated cache]:

```text
timestamp: 2026-09-04T15:39:24Z
overall_status: PASSED
steps_executed: 10 / 10
lineage: main@c3035199b8e2e763c58c4a1f75eefcad5bb02a1f [committed HEAD]
dirty_file_count: 0
Hardhat observed count: 438 passing tests
PageIndex: 0 dirty/untracked files detected, 0 contradictory claims identified
Agent Claim Lie Detector: 40 claims audited, 0 violations
Privacy Leak Scanner: PASSED
```

Proof boundary for fresh agents [committed HEAD]:

```text
This repository is a prototype fiduciary commons and verification harness.
It is not a third-party audit, not a mainnet deployment clearance, not a custody system, and not a production healthcare claims processor.
Council outputs are off-chain verifier evidence and review artifacts, not replacements for professional legal, security, actuarial, healthcare, or fiduciary review.
Never request or paste private keys, raw PHI, raw pharmacy claims, wallet-to-pharmacy mappings, seed phrases, or unredacted credentials into prompts, issues, screenshots, docs, or review packets.
```

## 2. Read First

Use these files first to orient a fresh iteration:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\README.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\CONTRIBUTING.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\NEXT.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\SECURITY.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\ONBOARDING.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\COMMONS_CONSTITUTION.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\AGENT_REVIEW_ORCHESTRATION.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.agents\AGENTS.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\review\EXTERNAL_REVIEW_GUIDE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\verification_master_receipt.json
```

Start every fresh iteration with these state checks:

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
git status --short --branch
git rev-list --left-right --count origin/main...HEAD
Get-Content -Raw -LiteralPath cache\verification_master_receipt.json
```

## 3. Governance, Rules, and Agent Protocol

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.agents\AGENTS.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.agents\memory\MEMORY.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.agents\memory\LEARNINGS_QUEUE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.agents\memory\WAITING_ON_ME.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\COMMONS_CONSTITUTION.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\AGENT_REVIEW_ORCHESTRATION.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\GOVERNANCE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\NEXT.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\ROADMAP.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\SECURITY.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\ONBOARDING.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\CONTRIBUTING.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.github\PULL_REQUEST_TEMPLATE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.github\CODEOWNERS
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.github\dependabot.yml
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.github\ISSUE_TEMPLATE\config.yml
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.github\ISSUE_TEMPLATE\security_review.yml
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.github\ISSUE_TEMPLATE\solidity_invariant_review.yml
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.github\ISSUE_TEMPLATE\zk_privacy_review.yml
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.github\ISSUE_TEMPLATE\docs_ui_review.yml
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.github\ISSUE_TEMPLATE\bug_report.yml
```

Fresh-agent rule of thumb:

```text
Keep public language humble and receipt-bound.
Prefer "prototype", "local verification", "generated receipt", "review artifact", and "launch blocker" over broad production claims.
Use "What This Does Not Claim" sections where public readers could misunderstand the proof boundary.
```

## 4. Verification Pipeline and Integrity Gates

Primary master runner:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\verify_all.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\verification_master_receipt.json
```

Fast public-surface and build gates:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\build-dashboard.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\check-frontend-build.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\check-brand-compliance.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\check-readiness.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\privacy_leak_scanner.py
```

Evidence, review, and claim gates:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\index_dossier_tree.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\eval_dossier_rag.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\context_hygiene_audit.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\eval_constitutional_rubric.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\observability_dashboard.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\verify_agent_claims.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\compile_review_packet.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\pre_commit_audit.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\openrouter_review.py
```

Security and branch hygiene runners:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\run_solidity_security_audit.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\run_symbolic_probes.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\auto_merge_dependabot.py
```

Recommended fast gate sequence:

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
npm.cmd run build:dashboard
npm.cmd run check:frontend
npm.cmd run check:readiness -- --env local
python scripts\privacy_leak_scanner.py
python scripts\index_dossier_tree.py
```

Seal a milestone with:

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
python scripts\verify_all.py
```

## 5. Core Smart Contracts

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\PBMRebateTreasury.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\PatientFundParticipatoryBudgeting.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\PharmacyMutualCredit.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\ReflexiveFiduciaryManifold.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\CooperativeParticipatoryBudgeting.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\OZTimelockControllerImport.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\mocks\ForceETH.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\mocks\MockERC20.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\mocks\MockFeeOnTransferERC20.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\mocks\MockERC1271Verifier.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\mocks\StartRoundReentrantToken.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\mocks\TreasuryReentrantToken.sol
```

Design context:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\design\SOLVENCY_DEBT_SEMANTICS.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\design\PATIENT_FUND_POLICY.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\design\IDENTITY_NULLIFIER_DESIGN.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\design\RETALIATION_AND_PRIVACY_THREAT_MODEL.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\design\ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\ops\PRODUCTION_READINESS_CHECKLIST.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\ops\SCANNER_TRIAGE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\ops\SOLIDITYSCAN_TRIAGE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\ops\SOLVENCY_REVIEW_AUTHORITY_AND_SAFETY.md
```

## 6. ZK Privacy, Witness Isolation, and Fixtures [committed HEAD]

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\circuits\vote_nullifier.circom
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\zk\ClientWitnessAdapter.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\ClientWitnessAdapter.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\ZKNullifierCircuit.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\ZKNullifierFixtureGate.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\fixtures\metadataLeakageTable.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\fixtures\projectScopedZKCircuitInterface.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\fixtures\unlinkablePayload.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\fixtures\mockPathPayload.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\fixtures\mockPathPayloadSchema.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\fixtures\futurePayloadSchema.json
```

Note for fresh agents:

```text
The verified metadata leakage table path in this repo is:
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\fixtures\metadataLeakageTable.json

Do not assume this is:
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\zk\metadataLeakageTable.json
```

## 7. Dashboard and Public Frontend Surface

Source:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\dashboard\index.html
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\dashboard\design-system.css
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\dashboard\web3_integration.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\dashboard\supabase.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\dashboard\ethers.umd.min.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\dashboard\assets\logo.png
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\dashboard\assets\onboarding_mockup.png
```

Built output:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\dist\dashboard\index.html
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\dist\dashboard\design-system.css
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\dist\dashboard\web3_integration.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\dist\dashboard\asset-manifest.json
```

Dashboard posture:

```text
Institutional and developer-first.
High information density.
Low motion.
Prototype/readiness boundaries visible.
No private-key, PHI, raw claim, or wallet-to-pharmacy submission flows.
```

## 8. Hardhat and Foundry Test Surfaces

Primary Solidity and systems bridge tests:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\A2AProtocolEngine.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\AgentClaimVerifier.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\AgentTaskRouter.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\AutonomousPatchAndChaosPipeline.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\ClientWitnessAdapter.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\CouncilEngineModules.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\CouncilReceiptVerifier.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\DashboardCredibility.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\DeploymentGovernance.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\DisasterRecoveryOutage.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\NeurosymbolicFormalAndP2PEngine.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PatientFundParticipatoryBudgeting.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PBMFraudFormalInvariants.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PBMRebateTreasury.delta.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PBMRebateTreasury.dispute-timeout.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PBMRebateTreasury.fuzz.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PBMRebateTreasury.security.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PBMRebateTreasuryStaleRecovery.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PharmacyMutualCredit.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PreCommitDisclosureGate.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PublicFormThreatModel.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\RateLimitingContracts.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\ReviewPacketCompiler.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\RouterReceiptHarness.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\VoucherSagaQueue.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\ZeroDatabaseLiveness.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\ZKNullifierCircuit.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\ZKNullifierFixtureGate.test.js
```

Foundry invariant surfaces:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\foundry\TreasurySolvencyInvariant.t.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\foundry\PatientFundInvariants.t.sol
```

Focused commands:

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
npx.cmd --no-install hardhat test test\PBMFraudFormalInvariants.test.js --no-compile
npx.cmd --no-install hardhat test test\ClientWitnessAdapter.test.js --no-compile
npx.cmd --no-install hardhat test test\A2AProtocolEngine.test.js --no-compile
```

## 9. Council Engine Modules in This Repo

Directory:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council
```

Core contracts, receipts, verification, and guardrails:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\council_contracts.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\council_verifier.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\governance_rules.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\lifecycle_hooks.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\human_approval.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\gate0_policy_preflight.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\log_derived_context_engine.py
```

Routing, A2A, deliberation, and synchronization:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\task_router.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\a2a_protocol_engine.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\external_a2a_adapter.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\heterogeneous_jury_engine.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\distributed_merkle_state_sync.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\p2p_gossip_transport.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\handoff_reconciliation_daemon.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\webhook_event_fanout.py
```

PBM, fraud, formal proof, and formalized evidence [committed HEAD]:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\pbm_rebate_engine.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\pbm_fraud_detector.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\pbm_fraud_formal_invariants.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\formal_theorem_prover_engine.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\neurosymbolic_proof_planner.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\rlvr_dataset_exporter.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\rlvr_ruler_reward_engine.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\semantic_ast_cache.py
```

Autonomous patching, sandboxing, red-team, and resilience:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\autonomous_patch_synthesis_pipeline.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\sandboxed_patch_generator.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\docker_sandbox_daemon.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\adversarial_red_team_engine.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\council_chaos_resilience_engine.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\dead_letter_queue.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\bounty_vulnerability_engine.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\authority_conflict_detector.py
```

Gateway, observability, local model review, and API surfaces:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\model_gateway.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\model_routes.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\qualification_matrix.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\model_qualification_runner.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\model_qualification_evaluator.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\council_api_server.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\council_cli.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\council_web_dashboard.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\council_telemetry.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\web_evidence_acquisition_engine.py
```

Focused Python council commands:

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
python -m unittest discover tools\council -p "test_task_router.py"
python -m unittest discover tools\council -p "test_pbm_fraud_formal_invariants.py"
python -m unittest discover tools\council -p "test_external_a2a_adapter.py"
python -m unittest discover tools\council -p "test_webhook_event_fanout.py"
```

## 10. Static Analysis and Security Artifacts

Repository artifacts:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\solidity-security-audit-report.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\slither-report.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\aderyn-report.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\ops\SCANNER_TRIAGE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\ops\SOLIDITYSCAN_TRIAGE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\ops\SOLVENCY_REVIEW_AUTHORITY_AND_SAFETY.md
```

Antigravity triage context [external reviewer claim until rechecked]:

```text
C:\Users\Josh\.gemini\antigravity\brain\85f7ecfd-2816-4d72-a605-14233de21c23\slither_aderyn_triage.md
```

Security posture:

```text
Scanner outputs are triage artifacts, not an audit certificate.
Slither and Aderyn findings should be tied to source lines, tests, and explicit false-positive rationale.
CEI refactoring of PBMRebateTreasury deposit functions remains a semantic debate, not an automatic cleanup task.
Current design intentionally avoids publishing unconfirmed internal accounting during external token callbacks while also using nonReentrant guards.
```

## 11. Review Context and Handoff Files

Current/fresh handoff paths:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\CODEX_FRESH_ITERATION_HANDOFF_2026-09-04.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\CODEX_TO_ANTIGRAVITY_HANDOFF_2026-09-02_CLIENT_WITNESS_ADAPTER_HARDENING.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\CODEX_TO_ANTIGRAVITY_HANDOFF_2026-09-02_PATIENT_FUND_CAP_SURPLUS_REPAIR.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\CODEX_TO_ANTIGRAVITY_HANDOFF_2026-08-31_PUBLIC_TRUST_NEXT.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\CODEX_TO_ANTIGRAVITY_HANDOFF_2026-08-28_PUBLIC_UI_DOCS.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\CODEX_TO_ANTIGRAVITY_HANDOFF_2026-08-28_A2A_FRAUD_ATTESTATION.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\ANTIGRAVITY_TO_CODEX_HANDOFF_2026-08-28.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\ANTIGRAVITY_TO_CODEX_HANDOFF_2026-08-27.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\ANTIGRAVITY_TO_CODEX_HANDOFF_2026-08-26.md
```

State ledgers and model/review context:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\SINGLE_REPO_STATE_LEDGER.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\SWARM_ROSTER_40_MODELS.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\MULTIMODAL_ROSTER_LOOPS.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\AI_SYSTEMS_CONCEPT_COVERAGE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\CODEX_5_6_SOL_REVIEW_QUEUE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\HANDOFF_PBM_REBATE_COUNCIL_SPECIALIZATION.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\oss_council_context.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\full_repo_oss_swarm_review_dossier.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\rotational_swarm_review_dossier.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\MODEL_INVENTORY.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\MODEL_INVENTORY.md
```

Specialized dossiers:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\zk_nullifier_claims_and_lineage_spec.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\project_scoped_zk_circuit_verifier_interface_spec.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\dossier_zk_nullifier.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\dossier_disputes_refactor.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\dossier_asymmetric_vouchers.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\dossier_non_digital_scenarios.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\pbm-review-observatory-v0.1.md
```

5.6 Sol review artifacts:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\5_6_sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\5_6_sol\codex_5_6_sol_arch_review_20260822-134318.txt
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews\5_6_sol\codex_5_6_sol_full_continued_review_live_20260822-150553.combined.txt
```

## 12. Caches and Generated Evidence

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\verification_master_receipt.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\council_convocation_demo_receipt.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\dossier_tree_index.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\dossier_rag_eval_summary.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\observability_summary.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\lineage_eval_benchmark.jsonl
```

Cache boundary:

```text
Treat cache files as generated local evidence.
Do not hand-edit receipts unless the task is explicitly receipt repair and the result is clearly labeled.
Prefer rerunning the script that creates the receipt.
```

## 13. Antigravity Scratch and Crossover Context

Antigravity scratch council engine [external workspace, contextual]:

```text
C:\Users\Josh\.gemini\antigravity\scratch\council_engine
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\FULL_SYSTEM_HANDOFF.md
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\MASTER_STATE_CHECKPOINT.md
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\MODEL_INVENTORY.md
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\pbm_rebate_engine.py
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\test_pbm_rebate_engine.py
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\pbm_fraud_detector.py
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\pbm_claims_fraud_audit_spec.md
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\outputs\handoff_pbm_rebate_council_specialization.md
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\outputs\antigravity_auditcode_handoff_2026-09-02.md
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\outputs\antigravity_to_codex_ollama_seat_verification_2026-09-04.md
C:\Users\Josh\.gemini\antigravity\scratch\council_engine\outputs\README_UPDATES_2026-08-28.md
```

OpenClaude / Clawd crossover [checked by Codex on 2026-09-04]:

```text
C:\Users\Josh\clawd
C:\Users\Josh\clawd\README.md
C:\Users\Josh\clawd\NEXT.md
C:\Users\Josh\clawd\UNIFIED_HANDOFF_PACKET.md
C:\Users\Josh\clawd\MODEL_INVENTORY.md
C:\Users\Josh\clawd\reviews\oss_council_verdict_latest.json
C:\Users\Josh\clawd\reviews\model_review_cycle_runbook.md
C:\Users\Josh\clawd\reviews\antigravity_public_readiness_handoff_latest.md
C:\Users\Josh\clawd\reviews\pbm_clawd_crossover_patterns.md
```

Clawd status note [live local check]:

```text
C:\Users\Josh\clawd is on main and aligned with origin/main, but has a modified MODEL_INVENTORY.md.
Do not describe clawd as clean until that dirty file is reviewed, committed, or intentionally left as local-only.
```

WSL / Free-Code crossover [contextual, not rechecked by Codex in this handoff]:

```text
\\wsl$\Ubuntu\home\josh\free-code
\\wsl$\Ubuntu-24.04\home\josh\free-code
```

Historical Codex outputs:

```text
C:\Users\Josh\Documents\Codex\2026-08-22\c-users-josh-documents-codex-2026\outputs\public_collab_handoff_index_2026-08-28.md
C:\Users\Josh\Documents\Codex\2026-08-22\c-users-josh-documents-codex-2026\outputs\public_collab_handoff_pharmacy_fiduciary_commons_2026-08-28.md
```

## 14. Remote Branch State

Remote branch state checked by Codex on 2026-09-04:

```text
origin/HEAD -> origin/main
origin/main
origin/dependabot/npm_and_yarn/ethers-6.17.0
origin/dependabot/npm_and_yarn/hardhat-3.9.0
origin/dependabot/npm_and_yarn/nomicfoundation/hardhat-ethers-4.0.13
origin/dependabot/npm_and_yarn/nomicfoundation/hardhat-verify-3.0.20
origin/dependabot/npm_and_yarn/openzeppelin/contracts-5.6.1
```

Branch hygiene status:

```text
The previous extra feature and GitHub Actions Dependabot branches were merged.
Five npm dependency update branches remain deferred.
Do not merge all dependency branches together.
Treat OpenZeppelin 5.x as the riskiest lane because imports and APIs may differ from current contracts.
Treat Hardhat 3.x as a migration lane rather than a routine patch.
```

## 15. Recommended Execution Plan

### P0 - Re-anchor before any work

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
git status --short --branch
git rev-list --left-right --count origin/main...HEAD
Get-Content -Raw -LiteralPath cache\verification_master_receipt.json
```

Decision rule:

```text
If the tree is dirty, classify changes before editing.
If HEAD and receipt lineage differ, rerun focused gates before trusting counts.
If cache receipt is stale, call it stale and rerun verify_all.py before public claims.
```

### P1 - Keep public collaborator readiness polished

Relevant files:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\README.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\CONTRIBUTING.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\review\EXTERNAL_REVIEW_GUIDE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.github\ISSUE_TEMPLATE
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\SECURITY.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\NEXT.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\dashboard
```

Plan:

```text
Keep README first-screen claims restrained.
Keep issue templates lane-specific and privacy-safe.
Add reviewer FAQ entries only when repeated external questions appear.
Keep dashboard proof panels tied to generated local receipts and explicit launch blockers.
Run privacy_leak_scanner.py after doc, issue-template, dashboard, or onboarding edits.
```

### P2 - Formal invariant SMT fixtures

Relevant files:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\pbm_fraud_formal_invariants.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\test_pbm_fraud_formal_invariants.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PBMFraudFormalInvariants.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\pbm_fraud_detector.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\pbm_rebate_engine.py
```

Plan:

```text
Add formal constraints only where they prove narrow local arithmetic or state-machine properties.
MME bounds: prove threshold classification behavior, not clinical truth.
Refill-too-soon: prove timestamp comparison and bounded windows, not external dispensing accuracy.
Duplicate therapy and HHI: prove deterministic classification, not real-world monopoly proof.
Benford: keep as ANOMALY_REVIEW_REQUIRED triage only, never absolute fraud proof.
```

Fast gates:

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
python -m unittest discover tools\council -p "test_pbm_fraud_formal_invariants.py"
npx.cmd --no-install hardhat test test\PBMFraudFormalInvariants.test.js --no-compile
```

### P3 - Dependency and branch reconciliation

Relevant files:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\auto_merge_dependabot.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\package.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\package-lock.json
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\hardhat.config.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.github\dependabot.yml
```

Plan:

```text
Run the branch hygiene reporter first.
Handle one dependency PR branch at a time.
Prefer lockfile-only or GitHub Actions updates before Hardhat/OpenZeppelin migrations.
For Hardhat 3.x, expect config and plugin changes.
For OpenZeppelin 5.x, expect import and API migration work.
Abort dependency merges that break compile or core tests.
```

Suggested start:

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
python scripts\auto_merge_dependabot.py
```

### P4 - External review packet compilation

Relevant files:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\scripts\compile_review_packet.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\reviews
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\review\EXTERNAL_REVIEW_GUIDE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\SECURITY.md
```

Plan:

```text
Compile public-safe packets only.
Do not approve external disclosure of dirty local code unless the operator explicitly authorizes it.
Prefer public docs, security policy, scanner triage, and minimal contract excerpts over full private working diffs.
Label every packet with source lineage and freshness.
```

### P5 - Optional next technical build

Candidate:

```text
External A2A fraud-attestation endpoint with read-only signed query shapes.
```

Boundaries:

```text
Read-only.
No remote code execution.
No PHI.
No raw claims.
No private receipts.
No custody authority.
Only expose narrow formal-invariant summaries and verifier receipt hashes.
```

Relevant files:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\external_a2a_adapter.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\a2a_protocol_engine.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\webhook_event_fanout.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\pbm_fraud_formal_invariants.py
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\A2AProtocolEngine.test.js
```

## 16. High-Review Queue

Good candidates for 5.6 Sol or equivalent high-skill review:

```text
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\PBMRebateTreasury.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\PatientFundParticipatoryBudgeting.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\contracts\PharmacyMutualCredit.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\PBMRebateTreasury.fuzz.test.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\foundry\TreasurySolvencyInvariant.t.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\test\foundry\PatientFundInvariants.t.sol
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\zk\ClientWitnessAdapter.js
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\tools\council\pbm_fraud_formal_invariants.py
```

Ask high-review models to focus on:

```text
Solvency accounting edge cases.
False assumptions in dispute, recall, and stale recovery flows.
ZK witness side-channel leaks.
Dependency migration risk.
Scanner false-positive triage.
Public wording that overstates prototype evidence.
```

## 17. Final Fresh-Agent Prompt

Copy-paste this block into a fresh session:

```text
You are resuming PBMRebateTreasuryFinal.

Root:
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal

Read first:
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\review-context\CODEX_FRESH_ITERATION_HANDOFF_2026-09-04.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\README.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\CONTRIBUTING.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\NEXT.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\SECURITY.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\docs\review\EXTERNAL_REVIEW_GUIDE.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\.agents\AGENTS.md
C:\Users\Josh\Desktop\PBMRebateTreasuryFinal\cache\verification_master_receipt.json

Current anchor from Codex live check on 2026-09-04:
main@c3035199b8e2e763c58c4a1f75eefcad5bb02a1f [committed HEAD], origin/main synchronized, receipt 10/10 PASSED, 438 Hardhat tests, 0 PageIndex contradictions, 40/40 claims audited, privacy leak scanner passed.

First commands:
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
git status --short --branch
git rev-list --left-right --count origin/main...HEAD
Get-Content -Raw -LiteralPath cache\verification_master_receipt.json

Operating posture:
Keep credibility, boundaries, and verifiable claims at the center.
Do not frame the system as audited, production-ready, mainnet-ready, or custody-safe.
Council claims are off-chain verifier evidence, not audit replacement.
Rotate through local evidence surfaces before editing.
When editing docs, dashboard, issue templates, onboarding, or support flows, run the privacy leak scanner.
When sealing a milestone, run python scripts\verify_all.py.

Next suggested work:
1. Re-anchor and classify any dirty files.
2. If public review is the goal, keep README/CONTRIBUTING/SECURITY/NEXT/dashboard/issue templates crisp and prototype-honest.
3. If technical depth is the goal, expand formal PBM fraud invariant fixtures with narrow SMT-style claims.
4. If repo hygiene is the goal, triage the five remaining Dependabot branches one at a time.
```
