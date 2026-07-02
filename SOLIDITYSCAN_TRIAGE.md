# SolidityScan Triage

This file records scanner findings against the current prototype implementation. It is a triage artifact, not an audit certification. Findings marked as false positives are still bounded by the broader production-readiness, governance, privacy, and participant-safety limits documented elsewhere.

## Current Status

| ID | Scanner label | Status | Evidence and boundary |
| --- | --- | --- | --- |
| C001 | Incorrect access control | Mostly false positive, with governance caveat | User paths require Merkle proofs, EIP-712 signatures, voter registration, or credential issuer checks; admin paths are role-gated. This does not resolve global council centralization, signer legitimacy, or local federation autonomy. |
| C002 | Public burn | False positive | The public `burn` helper is in `contracts/mocks/MockERC20.sol`, which is test-only mock infrastructure, not a production contract. |
| H001 | Reward ownership check | False positive | Rebate claims bind `msg.sender`, amount, and eligible cap into the Merkle leaf, and per-epoch claim accounting prevents duplicate or over-cap claims. |
| H002 | Reentrancy | Remediated for known external-transfer paths | `PBMRebateTreasury.sol`, `PatientFundParticipatoryBudgeting.sol`, and `PharmacyMutualCredit.sol` use `ReentrancyGuard` on token-moving and sweep paths. `PatientFundParticipatoryBudgeting.startRound` is also guarded because it pulls matching tokens before writing the new round. |
| M001 | Division by zero | False positive | Matching finalization and `previewFinalize` handle zero-vote / zero-weight rounds before proportional division. |
| M002 | Unchecked array length | False positive / bounded | Batch paths use single arrays, not paired arrays with mismatch risk. Project counts are capped for finalization boundedness. |
| M003 | Precision loss | Mitigated | Proportional matching division records integer shares and returns dust to the council address. Treasury tests include a six-decimal payout token regression. |
| M004 | Merkle leaf reuse | False positive | Claim accounting is keyed by epoch and claimant, with eligible-cap checks preventing duplicate or over-cap claims from the same leaf. |

## Do Not Overclaim

- This triage does not make the repo audited or production-ready.
- This triage does not resolve docs-only governance rotation, local federation autonomy, mutual-credit default handling, or privacy-preserving identity.
- ERC-1271 support currently applies to the configured participatory-budgeting `relayerVerifier`, not to every credential issuer path.

## Recommended Scanner Cross-Checks

- Run Slither as the primary local static-analysis pass because it produces line-level findings that are easier to map back to the repo than broad dashboard summaries.
- Run Aderyn as a second opinion when a Markdown, JSON, or SARIF artifact is useful for reviewer handoff.
- Reserve Mythril for targeted symbolic-execution checks on specific suspicious paths rather than treating it as the main scanner.
- Keep informational findings on timestamps, loops, and test-only mocks in this triage file unless a scanner ties them to a concrete exploit path.

## Slither 0.11.5 Local Pass

Command:

```powershell
C:\Users\Josh\AppData\Local\Temp\slither-venv-codex\Scripts\slither.exe . --exclude-dependencies --filter-paths "node_modules|contracts/mocks" --json exports\slither-production.json
```

Report artifact: `exports/slither-production.json` (ignored local analysis output).

Summary: Slither analyzed the production-scope contracts with 101 detectors and reported 36 results:

| Detector | Count | Local disposition |
| --- | ---: | --- |
| `arbitrary-send-eth` | 1 | Bounded: `sweepETH` is council-gated, sends only to configured `environmentalFund`, and checks the low-level call result. Still keep this visible because ETH sweeps are governance-sensitive. |
| `incorrect-equality` | 2 | Bounded / false positive: `balance == 0` is a zero-value guard, and `publishedAt == 0` is a sentinel in a view eligibility helper. |
| `reentrancy-no-eth` | 1 | Bounded / false positive: `PatientFundParticipatoryBudgeting.startRound` is `nonReentrant`; the external token pull happens before the new round and recycled matching state are activated, and callback senders do not satisfy council/voter gates. |
| `reentrancy-benign` | 2 | Bounded / false positive: `depositRebate` and `fundExclusionRemediation` are already `nonReentrant`; Slither still reports state writes after `safeTransferFrom`. |
| `timestamp` | 18 | Expected for governance deadlines, proposal expiry, recall windows, voucher expiry, and claim grace periods; tests cover the relevant timer boundaries. |
| `cyclomatic-complexity` | 3 | Informational: concentrated governance/accounting flows are complex but covered by tests and invariants. |
| `low-level-calls` | 1 | Expected in `sweepETH`; the call result is checked and the destination is the configured environmental fund. |
| `naming-convention` | 8 | Informational style issue for underscored parameter names. |

Tool note: the Windows run emitted an `EPERM` warning while `npx hardhat clean --global` tried to unlink the cached Solidity compiler, then continued through `npx hardhat compile --force` and produced a successful JSON report.
