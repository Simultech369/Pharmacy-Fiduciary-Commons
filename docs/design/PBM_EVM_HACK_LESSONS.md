# PBM EVM Hack Lessons

Status: draft planning artifact. This file translates lessons from the `sanbir/evm-hack-analyzer` ecosystem into PBM-specific review and handoff checks. It is not policy acceptance, implementation authority, or a request to import external code.

Reference sources:

- `sanbir/evm-hack-analyzer` at `fea421655e8909c9d191a4b8ec8bca41651cd526`.
- `sanbir/evm-hack-registry` at `c95c2126f9b038fc0a4d7c2894d6f8f51fe8584d`.

Clone note: the registry object clone succeeded, but Windows checkout hit long-path source filenames. Use the registry taxonomy and selected writeups as reference evidence; do not mirror raw exploit trees into PBM.

## Source Takeaways

The analyzer's strongest pattern is not a specific Solidity defense. It is reproducibility discipline:

- exact transaction or scripted exploit;
- exact fork/block state;
- exact source mapping;
- explicit vulnerable line;
- ordered exploit steps;
- shareable artifact that can be replayed locally.

The registry's taxonomy shows recurring exploit classes:

| Class | Registry signal | PBM translation |
|---|---:|---|
| Logic/accounting | largest category | Solvency changes need invariant tables, not only happy-path tests. |
| Access control | large category | Every privileged action needs caller, role, event, and negative-test coverage. |
| Unsafe external calls/dependencies | common | SafeERC20 is necessary but not sufficient; review callback/reentrancy surfaces. |
| Governance manipulation | common | Avoid letting process, role, or voter mechanics silently set policy. |
| Reentrancy | recurring | Preserve state-before-transfer and `nonReentrant` on value-moving paths. |
| Arithmetic/rounding | recurring | Dust, proportional shares, and cached-shortfall deltas need boundary tests. |
| Auth/signature | recurring | Signatures/verifiers need replay, domain, nonce, deadline, and rotation checks. |
| DoS/frozen funds | smaller but severe | Liveness fixes must not create new frozen-claim or operator-lock states. |

## PBM-Specific Lessons To Borrow

1. Treat solvency as a logic/accounting invariant lane.

   Every future solvency change should state how it changes:

   - physical token balance;
   - active round pool;
   - unclaimed project shares;
   - recycled matching pool;
   - council refund/cancellation;
   - cached observed shortfall.

   A transition is not "settlement" unless value was received or an obligation was actually paid.

2. Preserve the role-boundary map before code changes.

   For `PatientFundParticipatoryBudgeting`, keep a caller matrix for:

   - `startRound` / `startZKRound`;
   - verifier/root/issuer setters;
   - voter registration paths;
   - finalization;
   - claim;
   - reclaim;
   - pause/unpause;
   - sweep.

   Antigravity should not add convenience admin paths, closest-match recovery paths, or broad rescue hooks without explicit authorization.

3. Keep external-call review narrow and explicit.

   The relevant external token-call surfaces are:

   - `safeTransferFrom` during round start;
   - `safeTransfer` during council refund/dust transfer;
   - `safeTransfer` during project claim;
   - `safeTransfer` during non-matching-token sweep.

   Current defenses include `nonReentrant`, `SafeERC20`, balance-delta checks for fresh deposits, and state updates before value transfer on claim. Future validation should include a local malicious-token/callback fixture before treating this as production-safe.

4. Treat signature and verifier paths as hack-class surfaces.

   Existing registration signatures bind deployment domain, round, voter, nonce, credential hash, policy version, and deadline. Future ZK/verifier changes should not proceed without a replay matrix covering:

   - chain ID;
   - contract address;
   - round ID;
   - voter or nullifier;
   - credential policy or verifier version;
   - deadline;
   - root;
   - verifier rotation and outstanding authorization invalidation.

5. Add arithmetic and rounding questions to the Antigravity checklist.

   Before changing finalization math, test or inspect:

   - maximum project count;
   - high vote counts;
   - quadratic weight overflow/revert behavior;
   - `distributed + dust == pool`;
   - fresh-versus-recycled dust split;
   - repeated loss/top-up/reclaim cycles.

6. Keep liveness framed as anti-DoS, not as payment safety.

   The solvency checkpoint removed a hard lifecycle freeze. That is valuable. It does not prove:

   - all claimants can be paid;
   - scarce liquidity is fairly allocated;
   - the 90-day reclaim window is fair during insolvency;
   - council refunds are subordinated;
   - `DebtSettled` means repayment.

7. Borrow reproducible security artifacts, not exploit drama.

   If PBM later needs a public security proof, prefer a small local repro packet:

   - exact commit;
   - exact contract/test;
   - one exploit or invariant scenario;
   - expected failure before / expected behavior after;
   - no live RPC, credentials, production funds, or raw private review output.

## Do Not Borrow

- Do not import analyzer UI code, IPFS publishing, Pinata flows, raw exploit bundles, or registry runner scripts into PBM.
- Do not run historical exploit PoCs as part of PBM validation.
- Do not make external hack data a pre-commit gate.
- Do not publish raw exploit details as PBM marketing copy.
- Do not clone or vendor exploit source trees into the PBM repo.
- Do not let the presence of many hack examples expand Antigravity's implementation scope.

## Antigravity Handoff Insert

Before a solvency implementation slice is authorized, classify the slice against these hack-derived checks:

| Check | Required before code? | Current status |
|---|---|---|
| Accounting invariant table updated | yes for solvency behavior | partially drafted in `SOLVENCY_DEBT_SEMANTICS.md` |
| Caller/role matrix reviewed | yes for privileged paths | needs narrow review |
| External-call/callback surface reviewed | yes for value-moving changes | needs local fixture only after approval |
| Signature/verifier replay matrix reviewed | yes for auth/ZK changes | deferred |
| Arithmetic/rounding boundary tests named | yes for finalization math changes | deferred |
| DoS/frozen-claim scenario named | yes for liveness changes | partially drafted |
| Public proof/repro packet redacted | yes before public security claims | deferred |

If a proposed change does not touch one of these surfaces, record that as "not applicable" rather than expanding scope.

