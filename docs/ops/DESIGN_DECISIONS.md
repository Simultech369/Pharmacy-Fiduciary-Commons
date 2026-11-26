# Design Decisions

This file records product and accounting choices that are implemented and should not be changed casually. Revisions require an explicit rationale, updated threat model, and behavioral tests.

## Exclusion Remediation Uses A Dedicated Reserve

Approved root-exclusion claims are paid only from `exclusionRemediationReserve`. Anyone may fund the reserve through `fundExclusionRemediation`, but ordinary rebate deposits continue to split only between root distribution liquidity and governance operations.

Rationale:

- An old or disputed epoch cannot consume deposits intended for future Merkle roots.
- Remediation capacity is visible before approval and payout.
- Funding an omission remedy is an explicit act rather than an implicit claim on unrelated pharmacy liquidity.
- Root escrow, unallocated distribution funds, governance funds, and remediation funds remain separately auditable.

If the reserve is insufficient, an approved exclusion claim remains pending until independently funded or dismissed. The system does not borrow from another treasury bucket.

## Vouchers Are Recipient-Bound

Every mutual-credit voucher names a registered recipient at creation. Only that address may redeem it. Voucher IDs identify obligations but are not bearer secrets and do not transfer redemption rights.

Rationale:

- A leaked voucher ID cannot redirect credit to another registered participant.
- The issuer's reserved liability has a known beneficiary.
- Redemption events can be reconciled against the intended recipient.
- Transferability is not needed for the current emergency-pharmacy-credit use case.

Changing the recipient requires cancellation and reissuance in a future workflow; this checkpoint does not implement mutable recipients or transferable vouchers.

## OpenZeppelin Contracts Pinned Exactly to `4.9.6` (v4 Retention Over v5 Churn)

`@openzeppelin/contracts` is pinned to exact version `"4.9.6"` in `package.json` (no `^` or `~` range) rather than migrating to OpenZeppelin `5.x` prior to external audit.

Rationale:

- **Deterministic Audit Surface**: Exact version pinning guarantees identical dependency bytecode across local builds, CI, Slither, and external auditor checkouts.
- **Solidity `0.8.20` & `evmVersion: "paris"` Alignment**: All core custody and budgeting contracts (`PBMRebateTreasury`, `PatientFundParticipatoryBudgeting`, `PharmacyMutualCredit`) target Solidity `0.8.20` (`paris`) and rely on OpenZeppelin `4.9.6` `AccessControl`, `Pausable`, `ReentrancyGuard`, `SafeERC20`, `MerkleProof`, `EIP712`, and `TimelockController`.
- **Avoiding Unnecessary Pre-Audit Custody Churn (`LRN-014`)**: Migrating to OpenZeppelin `5.x` alters custom error signatures (replacing revert strings verified throughout the security/regression suites), removes `SafeMath`/legacy hooks, and changes `TimelockController` / `Pausable` import paths and constructor admin semantics without improving any treasury solvency invariant. Re-evaluating `5.x` is deferred until a future major protocol version is intentionally scoped.
