# OpenRouter Free Review Reconciliation

Generated: 2026-08-09
Source review: `reviews/model_attempts/20260809T171351Z-openrouter_free-skeptic-review.md`
Packet: `review-context/packet-openrouter-public-baseline.json`
Status: unreconciled external review partially reconciled against live local tree.

## Survived And Integrated

- Request canonicalization DoS risk in `server/createApp.js`: live code used recursive `stableStringify(req.body)` without a local depth/key bound. Integrated bounded canonicalization, explicit `express.json({ limit: "10kb" })`, oversized-body handling, and focused tests in `test/server.test.js`.

## False Or Stale Against Live Code

- `flagExclusion` counter-inflation claim: false against live `contracts/PBMRebateTreasury.sol`. `flagExclusion` does not increment `epochClaimedTotal`, `epochRootClaimedTotal`, `pharmacyClaimedThisEpoch`, or `epochVolume`; `retractClaimDispute` therefore does not need to decrement those counters for exclusions.
- Missing nullifier consumption claim: stale against live `contracts/PatientFundParticipatoryBudgeting.sol`, which checks and sets `roundNullifiersUsed[roundId][nullifier]`.
- `finalizeRound` arithmetic wrap claim: overstated for Solidity 0.8.20 because arithmetic overflow reverts rather than silently wrapping. The broader matching-cap policy question remains separate from an overflow finding.

## Parked Or Policy-Level

- On-chain/off-chain registration split-brain: design boundary question, not a confirmed exploit from the packet alone.
- CSP / frame policy headers: low-risk hardening candidate; `X-Content-Type-Options`, `Referrer-Policy`, and `Cross-Origin-Resource-Policy` already exist.
- Credential pepper rotation: operational policy, already guarded against default dev pepper outside test mode.
