# SolidityScan Triage

This file records scanner findings against the current prototype implementation. It is a triage artifact, not an audit certification. Findings marked as false positives are still bounded by the broader production-readiness, governance, privacy, and participant-safety limits documented elsewhere.

## Current Status

The 2026-07-14 SolidityScan input was a free dashboard summary only. It did not include file names, line numbers, source snippets, traces, or per-instance explanations. This file therefore records a best-effort local triage against the repository, not a formal per-instance disposition.

Important scanner-scope caveat: the dashboard appears to include `contracts/mocks/**`. Several critical/high labels map cleanly to test-only adversarial helpers and should not be counted against the production deployment surface unless SolidityScan later proves the same issue in a production contract.

| ID | Scanner label | Instances | Local status | Evidence and boundary |
| --- | --- | ---: | --- | --- |
| C001 | Incorrect access control | 13 | Unverified without line detail; likely role-governance cluster | Production admin paths are guarded with `onlyRole`, and constructors enforce council/root-confirmer/guardian separation. This remains an operational governance release gate, not something to silence blindly. |
| C002 | Public burn | 1 | Test-only false positive | The public `burn` helper is in `contracts/mocks/MockERC20.sol`, which is test-only infrastructure. |
| H001 | Claim reward token ownership not checked | 4 | Unverified without line detail; likely bounded/false positive | Rebate claims bind claimant, amount, and eligible cap into the Merkle leaf, use the current epoch root, and update per-epoch claimant accounting before payout. Need line detail to confirm all 4 instances. |
| H002 | Reentrancy | 4 | Bounded residual or test-only, depending on instance | Production token-moving paths use `ReentrancyGuard`, SafeERC20, checks-effects-interactions, and receive-delta guards. Reentrant mock contracts intentionally contain callback probes and should be excluded from production scans. |
| H003 | Use of self-destruct | 1 | Test-only false positive | `contracts/mocks/ForceETH.sol` uses `selfdestruct` only to test forced-ETH recovery; it is not a production contract. |
| H004 | Unchecked transfer | 1 | Unverified without line detail | Production ERC-20 transfers use SafeERC20. The only production low-level ETH call is `sweepETH`, which checks the boolean result and is executor-gated. |
| M001 | Division by zero | 2 | Bounded/likely false positive | Matching finalization handles zero-weight rounds before proportional division; reflexive scaling checks zero targets; PID update returns early for zero time delta. |
| M002 | Strict equality check in `block.timestamp` | 1 | Not reproduced locally | Local search finds no direct strict equality or inequality comparison against `block.timestamp` in `contracts`. |
| M003 | Unchecked array length | 2 | Bounded/likely false positive | Batch paths use single arrays rather than paired arrays with mismatch risk, and batch sizes are capped where needed. |
| M004 | Limitations of Solidity try-catch in external calls | 16 | Test-only false positive if mapped to current local hits | Solidity `try/catch` appears in adversarial mock contracts that deliberately probe blocked callbacks. Production contracts do not use Solidity `try/catch`. |
| M005 | Precision loss during division by large numbers | 14 | Accepted bounded arithmetic/dust behavior unless line detail shows otherwise | Proportional divisions are integer allocations with explicit dust handling. Treasury tests include six-decimal payout-token coverage; reflexive rebate scaling now uses `Math.mulDiv`. |
| M006 | Merkle leaf can be reused | 2 | Bounded/likely false positive | Claim and normal-dispute leaves use fixed-size fields and double hashing; state is keyed by epoch and claimant to prevent duplicate claim/flag use. Reusing the same allocation leaf in a later epoch root is intentional if a later epoch repeats the same allocation. |
| L001 | Balance equality | 1 | Likely accepted guard/sentinel | Previous Slither overlap reported zero-balance and sentinel equality checks, not authorization or randomness decisions. |
| L002 | Event based reentrancy | 1 | Unverified without line detail | Known external-transfer paths have callback regression coverage; need line detail before marking this instance. |
| L003 | Lack of zero value check in token transfers | 6 | Low severity / cleanup candidate | Some split transfers can mathematically become zero for dust-sized amounts. This is generally harmless for standard ERC-20s but can be guarded if scanner optics matter. |
| L004 | Legacy code generation issue with `.selector` access on expressions with side effects | 1 | Likely test-only false positive | The local `.selector` hit is in `contracts/mocks/MockERC1271Verifier.sol`, a test verifier. |
| L005 | Missing events | 22 | Style/review item | Needs line detail. AccessControl role changes already emit standard events; project-specific setter/event coverage should be reviewed only where operational monitoring depends on it. |
| L006 | Missing zero address validation | 14 | Unverified without line detail | Core constructor addresses and sensitive destination setters include zero-address checks. Need line detail to identify any real missing validation. |
| L007 | Outdated compiler version | 12 | Accepted release caveat | Project currently uses Solidity `0.8.20` with Hardhat `evmVersion: "paris"`. Compiler upgrade should be a deliberate release task, not a scanner-only patch. |

Informational and gas findings in the free report are not treated as security blockers without line detail: NatSpec completeness, named return style, underscore naming, event indexing, constructor events, public constant visibility, storage packing, cached lengths, revert splitting, and similar style/gas suggestions should be handled only if they improve maintainability or deployment cost without changing protocol behavior.

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
| `arbitrary-send-eth` | 1 | Bounded: `sweepETH` is executor/timelock-gated, sends only to configured `environmentalFund`, and checks the low-level call result. Still keep this visible because ETH sweeps are governance-sensitive. |
| `incorrect-equality` | 2 | Bounded / false positive: `balance == 0` is a zero-value guard, and `publishedAt == 0` is a sentinel in a view eligibility helper. |
| `reentrancy-no-eth` | 1 | Bounded / false positive: `PatientFundParticipatoryBudgeting.startRound` is `nonReentrant`; the external token pull happens before the new round and recycled matching state are activated, and callback senders do not satisfy council/voter gates. |
| `reentrancy-benign` | 2 | Bounded / false positive: `depositRebate` and `fundExclusionRemediation` are already `nonReentrant`; Slither still reports state writes after `safeTransferFrom`. |
| `timestamp` | 18 | Expected for governance deadlines, proposal expiry, recall windows, voucher expiry, and claim grace periods; tests cover the relevant timer boundaries. |
| `cyclomatic-complexity` | 3 | Informational: concentrated governance/accounting flows are complex but covered by tests and invariants. |
| `low-level-calls` | 1 | Expected in `sweepETH`; the call result is checked and the destination is the configured environmental fund. |
| `naming-convention` | 8 | Informational style issue for underscored parameter names. |

Tool note: the Windows run emitted an `EPERM` warning while `npx hardhat clean --global` tried to unlink the cached Solidity compiler, then continued through `npx hardhat compile --force` and produced a successful JSON report.
