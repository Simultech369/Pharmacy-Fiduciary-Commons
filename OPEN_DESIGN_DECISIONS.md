# Open Design Decisions

These choices are intentionally unresolved at this checkpoint. The repository records current behavior without presenting it as final product policy. Future changes should select a model explicitly, document the trust and economic consequences, and add acceptance tests before changing contract behavior.

## Dismissed Disputes And Claim Rights

Current behavior: flagging either dispute path sets `hasClaimed`; dismissal reverses applicable amount accounting but does not automatically restore ordinary claim rights.

Decision still needed: distinguish final rejection from dismissal that restores claim eligibility. A single automatic reset is not adopted because it could let a rejected proof-backed claim bypass the dispute outcome.

Required evidence: explicit resolution reasons, sanction interaction, UI warnings, and tests proving that unpaid legitimate claimants can recover without enabling double payment or review bypass. The volume cap-reservation / anti-griefing tradeoff is now covered by security tests (`PBMRebateTreasury.security.test.js`).

## Credential Privacy Identifier

Current behavior: the exact canonical credential hash is signed and emitted as a stable public identifier.

Decision still needed: retain the stable hash for audit and duplicate detection or replace it with a deployment/round-scoped nullifier. The current hash is a correlation handle but is not represented as proof that credential contents are brute-force recoverable.

Required evidence: intended anonymity level, cross-round duplicate policy, credential disclosure workflow, and a reviewed nullifier construction if privacy scope expands. The proposed roadmap for ZK nullifiers is detailed in [IDENTITY_NULLIFIER_DESIGN.md](IDENTITY_NULLIFIER_DESIGN.md).

## Participatory Project Eligibility

Current behavior: council controls project registration and voter eligibility; registered voters determine squared vote-count weights.

Decision still needed: retain council eligibility screening, add an appeal/community nomination process, or move eligibility to another governance mechanism.

Required evidence: fraud-screening requirements, conflicts policy, appeal process, and a clear statement of which decisions are administrative versus community-controlled. Proposed voter eligibility and admission criteria controls are defined in [RATIFICATION_PROCEDURE.md](RATIFICATION_PROCEDURE.md).

## Stale Pool Recovery Liveness

Current behavior: unallocated distribution pool recovery uses `epochStartTimestamp` to enforce the 180-day stale recovery delay. Later deposits still update `lastDepositTimestamp` for metadata, but they do not extend recovery eligibility.

Resolved checkpoint decision: the cheap dust-deposit griefing vector is mitigated by gating stale recovery on the current epoch age rather than the latest deposit timestamp. Recovery still fails when a current root is live or a pending root proposal has not expired.

Current tradeoff now covered by regression tests: a late legitimate unrooted deposit is recoverable once the epoch itself is stale. This favors liveness and anti-griefing over deposit-age protection.

Remaining evidence: expected frequency of legitimate unrooted deposits, participant notice requirements before stale recovery, whether recovery should require a public notice period keyed to `lastDepositTimestamp`, and whether future releases should expose richer recovery status in the dashboard.

## Exclusion Cap Ratchets

Current behavior: root-exclusion disputes are checked against current daily and hard caps at flag time and again at resolution time. If governance reduces a cap after a dispute is flagged and approved, the older approved payout remains pending until the current caps allow it or council dismisses it.

Decision still needed: decide whether remediation should be governed by current safety caps, historical caps from flag time, or a separate remediation-specific cap. Current behavior favors live blast-radius control but can strand older exclusion remediation after an emergency cap reduction.

Required evidence: operator playbooks for cap reductions, participant notice before dismissing stranded remediation, and dashboard/readiness warnings that approved exclusion claims can remain unpaid while current caps are lower than the approved amount.
