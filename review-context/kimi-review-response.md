SNAPSHOT_CHECK:
- reviewed_head: f1a8f00275b4d3fff1ee993091e02c692faa29cc (from prompt; bundle excludes .git so not independently confirmed)
- stale_embedded_snapshot_claims: yes, ANTIGRAVITY_CURRENT_HANDOFF.md pins HEAD 3b62ce9c… while the review prompt specifies f1a8f002…
- context_files_seen: yes, both README.md and ANTIGRAVITY_CURRENT_HANDOFF.md are included in the uploaded bundle
- strongest_overclaim_pressure: draft governance and continuity tooling use “verified”/“registration” language and compile/test green, creating pressure to mistake degraded-mode artifacts for production ZK settlement or authority.

Finding 1: README.md is procurement boilerplate, contradicting handoff’s claimed ZK/privacy language
- Severity: High
- Classification: stale claim / verified defect
- File/line: `README.md` lines 1-7 (entire file: `# Independent Pharmacy Cooperative Procurement Layer (P-02)`…)
- Evidence: `ANTIGRAVITY_CURRENT_HANDOFF.md` §1 claims “README language now distinguishes legacy stable-hash linkage risk, semantic mock ZK registration, and production ZK design status.” The bundled README contains zero mentions of treasury, PatientFund, ZK, nullifier, or privacy; `package.json` name is `pbmrebatetreasuryfinal` confirming real scope.
- Reproduction: `grep -iE "zk|nullifier|patientfund|privacy" README.md` → no matches.
- Correction: Replace README with accurate system description matching handoff intent, or correct the handoff claim.
- Blocks next ZK milestone? No, but blocks accurate external review.

Finding 2: Handoff pins obsolete HEAD `3b62ce9c…` vs current `f1a8f002…`
- Severity: Medium
- Classification: stale claim
- File/line: `ANTIGRAVITY_CURRENT_HANDOFF.md` line 3 and §7 (`Expected HEAD: 3b62ce9c55617600c895825787e8c4c2b033094d`)
- Evidence: Review prompt specifies current local HEAD `f1a8f00275b4d3fff1ee993091e02c692faa29cc`. Handoff’s snapshot gate and §7 prompt still cite the older commit and claim 193 passing tests at that commit.
- Reproduction: `git rev-parse HEAD` in live repo; compare to handoff.
- Correction: Re-anchor handoff to `f1a8f002…` or explicitly mark as historical snapshot.
- Blocks next ZK milestone? No.

Finding 3: Continuity tool prints “Verified Status: TRUE” for local MAC only
- Severity: Low
- Classification: overclaim risk
- File/line: `tools/resilience/continuity-engine.mjs` `verify-offline` case (string `Verified Status:    TRUE (Failsafe baseline satisfied)`; line unknown in uploaded bundle but inside the verify-offline switch)
- Evidence: The offline voucher MAC check is operator-local integrity, not a ZK proof. Test `ContinuityAndAdversarialTools.test.js` only asserts the *failure* case excludes “TRUE”; the pass case emits “TRUE” which can be misread as proof validity.
- Reproduction: `LOCAL_MAC_SECRET=secret123456789012 node tools/resilience/continuity-engine.mjs generate-voucher 1` then `verify-offline` on the file → observe “Verified Status: TRUE”.
- Correction: Change output to “LOCAL MAC ONLY — NOT A PROOF”.
- Blocks next ZK milestone? No.

Finding 4: `updateSanction` bypasses guardian pause
- Severity: Low
- Classification: verified defect (minor)
- File/line: `contracts/PBMRebateTreasury.sol` `updateSanction` (function defined without `whenNotPaused`; line unknown in uploaded bundle, located near `appealSanction`)
- Evidence: `OPERATIONAL_RUNBOOK.md` states pause blocks `resolveClaim` while recovery paths stay open. `updateSanction` lacks `whenNotPaused`, so council can sanction addresses during an active guardian pause. Council is trusted, but the inconsistency can confuse operators.
- Reproduction: Deploy, `pause()` as guardian, `updateSanction(addr,true,"x")` as council → succeeds.
- Correction: Add `whenNotPaused` to `updateSanction` or document the exception.
- Blocks next ZK milestone? No.

Finding 5: Deploy script allows open timelock executor on non-local “demo”
- Severity: Medium
- Classification: architectural risk / overclaim risk
- File/line: `scripts/deploy-timelock-and-treasury.js` (open-executor guard: `if (hasOpenExecutor && process.env.DEPLOYMENT_ENV !== "demo" && process.env.DEPLOYMENT_ENV !== "local")`)
- Evidence: Setting `DEPLOYMENT_ENV=demo` and `ALLOW_OPEN_TIMELOCK_EXECUTOR=true` lets the script deploy to a public testnet with `ZeroAddress` executor (open execution). `check-production-release.js` blocks *release*, but the insecure deployment still succeeds.
- Reproduction: On testnet, set env vars above, run deploy script → succeeds with open executor.
- Correction: Disallow open executor on any non-local chain regardless of `DEPLOYMENT_ENV`, or fail loudly.
- Blocks next ZK milestone? No.