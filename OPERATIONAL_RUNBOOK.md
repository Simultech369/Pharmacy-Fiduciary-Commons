# Operational Runbook - Pharmacy Fiduciary Commons

This runbook defines operational guidelines, thresholds, and emergency procedures for managing the Pharmacy Fiduciary Commons contracts in production.

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

## 2. Relayer EOA Key Management Policy

The Relayer EOA holds the authority to submit voter self-registration signatures to the `PatientFundParticipatoryBudgeting` contract. Protecting this key is critical to prevent Sybil registrations.

### Key Storage Guidelines
- **No plaintext storage:** Private keys must never be stored in plain text files, environment configuration files (`.env`), or code repositories.
- **Hardware/KMS Security:** In production, keys must be stored in a hardware security module (HSM) or a managed Key Management Service (e.g., AWS KMS, GCP Cloud KMS, HashiCorp Vault) configured with strict access control lists (ACLs).
- **Access Delegation:** Only the automated relayer daemon service account is authorized to invoke signature operations.

### Key Rotation and Revocation
- **Regular Rotation:** Relayer keys should be rotated every 90 days.
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
- The separately configured **Guardian** EOA or multisig must call the `pause` function immediately to halt all token deposits, claims, and resolutions:
  ```solidity
  // Call from Guardian EOA
  PBMRebateTreasury.pause();
  ```
- *Note:* The Council cannot pause the contract; this is a safety separation of concerns.

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
