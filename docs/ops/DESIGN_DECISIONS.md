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
