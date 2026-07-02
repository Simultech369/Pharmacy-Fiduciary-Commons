# SolidityScan Triage

This file records scanner findings against the current prototype implementation. It is a triage artifact, not an audit certification. Findings marked as false positives are still bounded by the broader production-readiness, governance, privacy, and participant-safety limits documented elsewhere.

## Current Status

| ID | Scanner label | Status | Evidence and boundary |
| --- | --- | --- | --- |
| C001 | Incorrect access control | Mostly false positive, with governance caveat | User paths require Merkle proofs, EIP-712 signatures, voter registration, or credential issuer checks; admin paths are role-gated. This does not resolve global council centralization, signer legitimacy, or local federation autonomy. |
| C002 | Public burn | False positive | The public `burn` helper is in `contracts/mocks/MockERC20.sol`, which is test-only mock infrastructure, not a production contract. |
| H001 | Reward ownership check | False positive | Rebate claims bind `msg.sender`, amount, and eligible cap into the Merkle leaf, and per-epoch claim accounting prevents duplicate or over-cap claims. |
| H002 | Reentrancy | Remediated for known external-transfer paths | `PBMRebateTreasury.sol` and `PatientFundParticipatoryBudgeting.sol` use `ReentrancyGuard` on token-moving and sweep paths. `PatientFundParticipatoryBudgeting.startRound` is also guarded because it pulls matching tokens before writing the new round. |
| M001 | Division by zero | False positive | Matching finalization and `previewFinalize` handle zero-vote / zero-weight rounds before proportional division. |
| M002 | Unchecked array length | False positive / bounded | Batch paths use single arrays, not paired arrays with mismatch risk. Project counts are capped for finalization boundedness. |
| M003 | Precision loss | Mitigated | Proportional matching division records integer shares and returns dust to the council address. Treasury tests include a six-decimal payout token regression. |
| M004 | Merkle leaf reuse | False positive | Claim accounting is keyed by epoch and claimant, with eligible-cap checks preventing duplicate or over-cap claims from the same leaf. |

## Do Not Overclaim

- This triage does not make the repo audited or production-ready.
- This triage does not resolve docs-only governance rotation, local federation autonomy, mutual-credit default handling, or privacy-preserving identity.
- ERC-1271 support currently applies to the configured participatory-budgeting `relayerVerifier`, not to every credential issuer path.
