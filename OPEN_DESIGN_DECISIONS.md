# Open Design Decisions

These choices are intentionally unresolved at this checkpoint. The repository records current behavior without presenting it as final product policy. Future changes should select a model explicitly, document the trust and economic consequences, and add acceptance tests before changing contract behavior.

## Exclusion Remediation Funding

Current behavior: approved exclusion payouts draw from the global unallocated `distributionPool`, while confirmed root allocations remain in `epochEscrow`.

Decision still needed: whether remediation remains a global pool responsibility, becomes epoch-bounded, or receives a separately funded reserve. The decision must define whether old-epoch remediation may reduce liquidity available for future roots.

Required evidence: expected dispute frequency and size, funding source, insolvency behavior, dashboard terminology, and accounting invariants for the selected model.

## Dismissed Disputes And Claim Rights

Current behavior: flagging either dispute path sets `hasClaimed`; dismissal reverses applicable amount accounting but does not automatically restore ordinary claim rights.

Decision still needed: distinguish final rejection from dismissal that restores claim eligibility. A single automatic reset is not adopted because it could let a rejected proof-backed claim bypass the dispute outcome.

Required evidence: explicit resolution reasons, sanction interaction, UI warnings, and tests proving that unpaid legitimate claimants can recover without enabling double payment or review bypass.

## Voucher Redemption Model

Current behavior: vouchers reserve issuer credit and are redeemable by any registered participant possessing the voucher ID.

Decision still needed: retain intentional bearer semantics, bind vouchers to a recipient, or require recipient acceptance. Recipient binding improves theft resistance but removes transferability.

Required evidence: real workflow requirements, voucher-ID entropy rules, cancellation policy, acceptance records, and theft/replay threat modeling.

## Credential Privacy Identifier

Current behavior: the exact canonical credential hash is signed and emitted as a stable public identifier.

Decision still needed: retain the stable hash for audit and duplicate detection or replace it with a deployment/round-scoped nullifier. The current hash is a correlation handle but is not represented as proof that credential contents are brute-force recoverable.

Required evidence: intended anonymity level, cross-round duplicate policy, credential disclosure workflow, and a reviewed nullifier construction if privacy scope expands.

## Participatory Project Eligibility

Current behavior: council controls project registration and voter eligibility; registered voters determine squared vote-count weights.

Decision still needed: retain council eligibility screening, add an appeal/community nomination process, or move eligibility to another governance mechanism.

Required evidence: fraud-screening requirements, conflicts policy, appeal process, and a clear statement of which decisions are administrative versus community-controlled.
