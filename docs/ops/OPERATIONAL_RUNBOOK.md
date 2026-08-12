# Operational Runbook - Pharmacy Fiduciary Commons

This pre-production operational runbook defines guidelines, thresholds, and emergency procedures intended for future production management of the Pharmacy Fiduciary Commons contracts. It does not override the public readiness checklist or audit warnings.

---

## 1. Exclusion Remediation Reserve Management

To ensure that pharmacy exclusion claims do not compete with regular epoch distribution liquidity, a separate `exclusionRemediationReserve` is maintained on-chain.

### Target Thresholds
- **Minimum Target:** The reserve must target a minimum balance of **5% of the total epoch distribution volume**, or **10,000 tokens** (whichever is higher).
- **Replenishment Frequency:** Checked and replenished at the end of every epoch prior to calling `finalizeEpoch`.

### Funding the Reserve
The Council or any external funding source can deposit funds directly to the reserve using the `fundExclusionRemediation` interface:
```solidity
// Call from a multisig or funding wallet
PBMRebateTreasury.fundExclusionRemediation(uint256 amount);
```

### Dispute Remediation Flow
1. **Flagging:** When a pharmacy flags an exclusion dispute, the claims are quarantined.
2. **Audit:** The Council audits the pharmacy's dispensing data (NCPDP standards) against the PBM's reported epoch files.
3. **Resolution:**
   - **Approved Payouts:** The Council proposes the resolution. Payouts are drawn automatically from `exclusionRemediationReserve` and remain subject to the treasury's configured daily and absolute volume caps.
   - **Dismissal:** If the dispute is dismissed, the quarantined caps are freed back to the active epoch.

---

## 2. Relayer Verifier Key Management Policy

The configured `relayerVerifier` holds the authority to authorize voter self-registration signatures in the `PatientFundParticipatoryBudgeting` contract. For local and bounded testnet trials this may be an EOA; before any public prototype, set it to a governed ERC-1271 multisig or equivalent contract wallet so authorization is not controlled by one private key.

The separate trusted-issuer credential path currently verifies issuer signatures with ECDSA recovery. Do not describe ERC-1271 support as applying to every credential path unless contract issuer verification is explicitly implemented and tested.

### Key Storage Guidelines
- **No plaintext storage:** Private keys must never be stored in plain text files, environment configuration files (`.env`), or code repositories.
- **Hardware/KMS Security:** In production, keys must be stored in a hardware security module (HSM) or a managed Key Management Service (e.g., AWS KMS, GCP Cloud KMS, HashiCorp Vault) configured with strict access control lists (ACLs).
- **Access Delegation:** Only the automated relayer daemon service account is authorized to invoke signature operations.

### Key Rotation and Revocation
- **Regular Rotation:** Relayer verifier authority should be rotated every 90 days or whenever signer membership changes.
- **Emergency Revocation:** If a relayer key is suspected of being compromised:
  1. The Council must immediately replace the active verifier using `setRelayerVerifier` on the `PatientFundParticipatoryBudgeting` contract:
     ```solidity
     // Call from Council multisig
     PatientFundParticipatoryBudgeting.setRelayerVerifier(newRelayerAddress);
     ```
  2. If relayer-assisted registration must be paused while a replacement key is prepared, set the verifier to a controlled break-glass address that will not sign new authorizations:
     ```solidity
     PatientFundParticipatoryBudgeting.setRelayerVerifier(breakGlassAddress);
     ```
  3. Council voter registration changes also advance `registrationNonces(roundId, voter)`, invalidating outstanding signatures for affected voters. Existing relayer signatures from the old verifier are rejected after `setRelayerVerifier` points to the new verifier.

---

## 3. Emergency Pause and Investigation procedures

In the event of an identified contract exploit, front-end compromise, or mathematical invariant violation:

### Step 1: Pausing the Contract (Guardian)
- The separately configured **Guardian** EOA or multisig must call the `pause` function immediately to halt token deposits, direct claims, and dispute-resolution payouts:
  ```solidity
  // Call from Guardian EOA
  PBMRebateTreasury.pause();
  ```
- *Note:* The Council cannot pause the contract; this is a safety separation of concerns.
- *Boundary:* Pause is not a full custody freeze. Timelock/council recovery paths such as recall, stale recovery, reserve withdrawal, and ETH sweep remain callable so operators can finish explicitly authorized containment or cleanup actions. Recall moves only finalized unclaimed epoch escrow; proof-backed dispute amounts remain quarantined in `flaggedAmount` until unpause and either council resolution or post-timeout pharmacy retraction.

### Step 2: Investigation & Diagnostics
- Monitor contract state invariants:
  - Verify that the ledger balance matches the token balance.
  - Review transaction logs of the block preceding the exploit.
- Keep the public warned of the pause via a status alert on the dashboard.

### Step 3: Unpausing the Contract (Council)
- Once the exploit has been resolved or identified as a false alarm, the **Council** (not the Guardian) must invoke `unpause` to restore operations:
  ```solidity
  // Call from Council multisig
  PBMRebateTreasury.unpause();
  ```
- *Note:* This ensures that pausing (quick safety reaction) and unpausing (requires governance consensus) are separate roles.

---

## 4. Production Deploy Timelock Renunciation

During production deployment, the temporary setup admin role in the `TimelockController` must be renounced to ensure true decentralized self-administration.

### Verification Step
When executing `deploy-timelock-and-treasury.js` in production, you MUST set the environment variable:
```bash
RENOUNCE_TIMELOCK_ADMIN=true
```
This forces the deployment script to call `renounceRole` on the `TIMELOCK_ADMIN_ROLE` for the deployer address immediately after configuring the self-administered roles.

Confirm the renunciation in the deployment logs:
```
Temporary timelock setup admin renounced: 0x...
Final timelock self-admin: true
Final external admin retained: false
```

---

## 5. Handling Patient Fund Matching Pool Depletion

### Patient Fund Address Models
Deployment must choose and publish one of two patient-fund address models:

1. **Safe / Intermediate Treasury Model:** `patientFund` is a governed Safe or treasury address. Treasury claim shares and recalled funds accumulate there until operators intentionally fund participatory-budgeting rounds.
2. **PB Sink Model:** `patientFund` is the `PatientFundParticipatoryBudgeting` contract itself. Any payout-token surplus in that contract beyond `totalUnclaimedShares + recycledMatchingPool` is treated as patient-bound matching liquidity on the next `startRound` call, emits `ExternalPatientFundsApplied`, and is not refundable to the council as fresh matching funds.

Accidental direct payout-token transfers into `PatientFundParticipatoryBudgeting` follow the same PB Sink rule. Non-payout tokens remain governed by the contract's sweep policy.

If the contract's actual token balance falls below the required accounting balance (due to manual withdrawals, accidental sweep operations, or general funding gaps):

### Step 1: Verification & Diagnosis
1. Identify the depletion on the public dashboard (which will display a `LIQUIDITY DEFICIT` warning) or query the view helper `previewFinalize(roundId)` on the `PatientFundParticipatoryBudgeting` contract.
2. Calculate the exact deficit:
   \[\text{Deficit} = \text{Required Accounting Balance} - \text{Actual Contract Balance}\]
   where:
   \[\text{Required Accounting Balance} = \text{totalUnclaimedShares} + \text{recycledMatchingPool} + \text{activeRoundMatchingPool}\]

### Step 2: Operational Action (Top-Up / Pause / Notify)
1. **Top-Up**: Send the required amount of matching ERC-20 tokens directly to the contract address to cover outstanding claims:
   ```solidity
   IERC20(tokenAddress).transfer(pbAddress, deficitAmount);
   ```
2. **Pause**: If funding cannot be secured immediately and claims are failing, the Guardian must call `pause()` to halt further claims:
   ```solidity
   PatientFundParticipatoryBudgeting.pause();
   ```
3. **Notify**: Post an alert warning users on the dashboard. Ensure that the dashboard and documentation make it clear that finalized shares are accounting commitments rather than physical liquidity guarantees. No partial-payment queue or automated liquidity backstop exists or is implied.

---

## 6. Mutual Credit Defaults And Voucher Capacity Cleanup

The current mutual-credit contract enforces registration, credit limits, issuer status, and voucher capacity accounting. It does not implement default adjudication, bad-debt socialization, write-offs, local federation solvency rules, or emergency credit freezes short of the global pause control.

Expired vouchers do not free issuer capacity automatically. Anyone may call `releaseExpiredVoucher` or `releaseExpiredVouchersBatch` after expiry, but until cleanup is called the issuer's `reservedVoucherCredit` remains committed. Operators should monitor expired voucher reservations and publish cleanup transactions as maintenance, not as discretionary debt forgiveness.

---

## 7. Calibration of Daily Volume Cap (`dailyVolumeCap`)

Despite its name, `dailyVolumeCap` operates as an **epoch-wide claim volume cap** (effectively an epoch volume cap parameter) at the contract level because `epochVolume` accumulates claims across the entire epoch (usually 30 days) and is only reset on finalization. The variable name is legacy/misleading.

### Calibrating the Parameter:
- Do **NOT** set `dailyVolumeCap` to your target daily volume (e.g. `$10,000`). If you do, the contract will block all claims once cumulative monthly claims exceed `$10,000`.
- **Parameter Calculation:** Set the parameter to represent the target maximum volume for the **entire epoch** rather than a single day. For example, a target of `$10,000` daily volume over a 30-day epoch requires setting the `dailyVolumeCap` parameter to at least `$300,000`.

---

## 8. AI Reliability & Incident Management Runbook (Stage 10)

This section governs operational procedures for non-deterministic AI reviewer swarms, capability probers, and multi-agent review handoffs. AI models act as review witnesses, **never** as sole reliability authorities.

### Fallback Chain Discipline
Reviewer execution MUST follow a strict deterministic-first fallback hierarchy:
$$\text{1. Deterministic Rule / Hardhat / Schema Checks} \longrightarrow \text{2. Local Ollama Model Review} \longrightarrow \text{3. Approved External Model Review}$$

### Incident Playbooks

#### Incident A: Hallucinated / Overclaimed Proof Claims
- **Symptom**: Model review dossier claims ZK privacy, production unlinkability, or solvency proof readiness not backed by test suite execution.
- **Triage Action**:
  1. Reject the review claim immediately under the **Weakest Valid Claim Rule**.
  2. Demote the status label from `[live verification just run]` to `[external reviewer claim]` or `[prototype_static_policy]`.
  3. Require explicit test command output before promoting the claim.

#### Incident B: Provider Rate-Limiting or Cloud API Outage (HTTP 429 / 500)
- **Symptom**: OpenRouter or external LLM API fails or returns rate-limit error responses.
- **Triage Action**:
  1. Do NOT retry external cloud API with unapproved private diffs.
  2. Fall back to local Ollama model (`deepseek-r1:1.5b` or equivalent) or local deterministic schema verification (`python scripts/index_dossier_tree.py`).
  3. Record the provider outage in `reviews/provider_capability_matrix.json` with `callable: false`.

#### Incident C: Multi-Agent Reviewer Disagreement
- **Symptom**: Secondary models (Codex, Kimi, Grok, Antigravity) emit contradictory review verdicts on contract solvency or proxy security.
- **Triage Action**:
  1. **Do NOT force artificial consensus.**
  2. Record the dissenting agent findings explicitly in the handoff brief under `Unresolved Risks`.
  3. Gate Level 3 promotion until the human owner resolves the dissent.

#### Incident D: Stale Status Claims / Branch Mismatch
- **Symptom**: Dossier files claim historical branch baseline (e.g. `feature/db-proxy`) contradicting live Git HEAD (`main`).
- **Triage Action**:
  1. Execute `python scripts/index_dossier_tree.py` to audit document status claims against Git truth.
  2. Reconcile stale header references in `review-context/SINGLE_REPO_STATE_LEDGER.md` and `review-context/AI_SYSTEMS_CONCEPT_COVERAGE.md`.
  3. Verify index audit reports `0 contradictory claims`.

#### Incident E: Unintended Staging of Raw Model Output / Account Residue
- **Symptom**: Raw attempt logs containing provider user IDs or raw API error strings (`reviews/model_attempt_ledger.jsonl`) appear in `git status`.
- **Triage Action**:
  1. Verify `.gitignore` contains `reviews/model_attempt_ledger.jsonl` and `reviews/model_attempts/`.
  2. Run `git restore --staged reviews/model_attempt_ledger.jsonl` before committing.
  3. Execute `git diff --cached --check` to confirm clean staging snapshot.
