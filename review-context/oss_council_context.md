# OSS Council Review Context - Pharmacy Fiduciary Commons

Status: Active context for multi-agent council review of `.next` roadmap sorting, under-asked question discovery, and repair-before-next-slice handoffs.

## 1. Repository State & Evidence Lineage
- Local Path: `C:\Users\Josh\Desktop\PBMRebateTreasuryFinal`
- Active Branch: `main` at `73c0ffd` (`feat(budgeting): implement explicit per-project quadratic matching cap`) `[committed HEAD]`
- Local Git Relation: `main...origin/main [ahead 2]` as observed from the local remote-tracking ref; no network fetch was performed in this Codex repair pass `[working tree]`
- Working Tree: Dirty with the Patient Fund cap-surplus custody repair, its regression tests, this context calibration document, and the Codex handoff addendum `[working tree]`
- Hardhat Suite Health: 430 passing tests after the cap-surplus repair (`npx.cmd --no-install hardhat test --no-compile`) `[live verification just run]`
- Master Receipt Boundary: `cache/verification_master_receipt.json` now records a 9/9 dirty-tree pass for `73c0ffd` with 430 Hardhat tests and 4 dirty/untracked files; rerun after commit before claiming a clean committed-HEAD receipt `[generated cache]`
- Exclusions: Local pre-commit guardrail artifacts (`reviews/guardrail-review.txt` and `reviews/guardrail-router-metadata.json`) are local-only review evidence and excluded from protocol state claims.

## 2. Recently Implemented & Verified Milestones `[live verification just run]`
1. **Public Trust UI/Docs Slice (`d9aad5f`)**: README, onboarding, constitution, security, dashboard, and public roadmap were polished around prototype-honest proof boundaries `[committed HEAD]`.
2. **A2A Fraud Attestation Slice (`7ec73d4`)**: Read-only external A2A fraud invariant attestation was added behind redaction and non-execution boundaries `[committed HEAD]`.
3. **Quadratic Matching Cap Slice (`73c0ffd`)**: `PatientFundParticipatoryBudgeting.sol` added an explicit per-project cap, defaulting to 10000 bps so historic proportional tests remain intact `[committed HEAD]`.
4. **Cap-Surplus Custody Repair (Codex Working Tree)**: The cap path now keeps capped matching surplus patient-bound in `recycledMatchingPool` rather than treating it as ordinary council-refundable dust; covered by new regression tests `[working tree]`.

## 3. Parked Candidate Items for `.next` Roadmap Prioritization

### Item 1: Dispute Tolling & Retraction Policy Framing
- *Objective*: Formalize dispute timeout tolling, stale claim recovery windows, and multi-signature retraction bounds in treasury settlement logic.
- *Primary Files*: `contracts/PBMRebateTreasury.sol`, `test/PBMRebateTreasury.dispute-timeout.test.js`, `test/PBMRebateTreasuryStaleRecovery.test.js`.
- *Invariants*: Prevent premature rebate distribution during active disputes; ensure non-reclaimed allocations revert to patient fund after 30-day PBM recall delay (`RECALL_DELAY`). Verify treasury domain variables (`totalFlaggedNormal`, `epochEscrow`, `totalEscrowed`, `patientFund`, `distributionPool`) remain consistent.

### Item 2: Remote RPC Verification Gate & Client Witness Isolation
- *Objective*: Build client-side witness preparation adapters that isolate local Circom inputs while enforcing strict host-facing verifier interfaces without adding third-party RPC dependencies.
- *Primary Files*: `circuits/vote_nullifier.circom`, `test/ZKNullifierFixtureGate.test.js`, `IDENTITY_NULLIFIER_DESIGN.md`.
- *Invariants*: Enforce mock/schema public-boundary constraints by proving forbidden metadata (timestamps, RPC IP headers, raw wallet keys) remains outside fixture public signals and packet schemas. Production witness preparation and unlinkability remain spec-only and unimplemented.
- *Current Priority*: Start only after the cap-surplus custody repair is reviewed, committed, and master-stamped.

### Item 3: Patient Fund Quadratic Matching Cap Policy & Solvency Debt Bounds
- *Objective*: Implement explicit per-project quadratic matching caps and shortfall-aware round lifecycle notices in participatory budgeting contracts (with 90-day `MATCH_RECLAIM_GRACE_PERIOD`).
- *Primary Files*: `contracts/PatientFundParticipatoryBudgeting.sol`, `test/foundry/PatientFundInvariants.t.sol`, `SOLVENCY_DEBT_SEMANTICS.md`.
- *Invariants*: Maintain non-negative PatientFund debt counters (`totalDebt`, `roundDeficit`) and bounded matching obligations; never treat observed shortfall reduction as guaranteed liquidity repayment; preserve Ostrom-commons governance bounds.
- *Current Status*: Implemented at committed HEAD, then repaired in the working tree so cap surplus remains patient-bound. Do not advance to Item 2 until this repair has a clean receipt.

## 4. Specific Council Review Instructions `[live verification just run]`

As the Senior Review Council (Grok / Strategist / Skeptic / Advocate):
1. **Next-Slice Prioritization**: Evaluate and rank Items 1, 2, and 3 in exact execution order for `.next`. `[generated cache]`
2. **Under-Asked Questions**: Identify the top 3 critical, under-asked questions that could derail the chosen priority item or create hidden solvency/privacy vulnerabilities. `[generated cache]`
3. **Smallest Proof-Bounded Test Slice**: Define the minimal test assertion to implement first before writing production code for the top-ranked item. `[generated cache]`

### Slither Triage Rationale (Lineage Entry 019 Supplement) `[external reviewer claim]`
*   **High Finding**: `depositRebate()` state-deferral
*   **Description**: Slither flags `totalEscrowed += amount` occurring after the ERC20 `transferFrom` call as a reentrancy risk (CEI violation).
*   **Triage Rationale**: FALSE POSITIVE (Intentional Design). The state deferral is explicitly intentional. By interacting with the potentially untrusted or hooked `rebateToken` *before* incrementing `totalEscrowed`, the contract guarantees that malicious token hooks cannot read an inflated `totalEscrowed` balance to manipulate nested views before the transfer fully clears. The `nonReentrant` mutex prevents actual state-mutating reentrancy.
*   **Status**: Dismissed / Verified. `[external reviewer claim]`

## 5. Contract Reference Excerpt: `PBMRebateTreasury.sol` (Dispute Handling & Settlement)

This excerpt is orientation-only. Reviewers must inspect the live target files before making line-specific or implementation-specific claims.

```solidity
    // DISPUTE RESOLUTION EXCERPT FROM PBMRebateTreasury.sol (lines 827-950)

    function flagClaim(
        uint256 epoch,
        uint256 amount,
        uint256 eligibleCap,
        bytes32[] calldata proof,
        bytes32 evidenceHash
    ) external whenNotPaused {
        if (evidenceHash == bytes32(0)) revert ZeroEvidenceHash();
        if (epoch != currentEpoch)                revert CanOnlyFlagCurrentEpoch();
        if (sanctioned[msg.sender])               revert Sanctioned();
        if (hasClaimed[epoch][msg.sender])        revert AlreadyClaimed();
        if (flaggedAmount[epoch][msg.sender] != 0) revert AlreadyFlagged();
        if (amount == 0)                          revert ZeroAmount();
        if (epochEscrow[epoch] < amount)          revert DistributionPoolDepleted();

        bytes32 root = epochMerkleRoot[epoch];
        if (root == bytes32(0)) revert NoRootForEpoch();
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encodePacked(msg.sender, amount, eligibleCap))));
        if (!MerkleProof.verify(proof, root, leaf)) revert InvalidProof();

        uint256 alreadyClaimed = pharmacyClaimedThisEpoch[epoch][msg.sender];
        if (alreadyClaimed + amount > eligibleCap) revert PharmacyCapExceeded();

        uint256 newVolume = epochVolume + amount;
        if (newVolume > dailyVolumeCap)        revert DailyCapExceeded();
        if (newVolume > hardAbsoluteVolumeCap) revert HardCapExceeded();
        if (newVolume > epochRootTotal[epoch]) revert RootTotalExceeded();

        hasClaimed[epoch][msg.sender]                = true;
        pharmacyClaimedThisEpoch[epoch][msg.sender] += amount;
        epochVolume                                   = newVolume;
        epochClaimedTotal[epoch]                    += amount;
        epochRootClaimedTotal[epoch]                += amount;
        flaggedAmount[epoch][msg.sender]             = amount;
        disputeFlaggedTimestamp[epoch][msg.sender]   = block.timestamp;
        epochEscrow[epoch]                           -= amount;
        totalEscrowed                                -= amount;
        totalFlaggedNormal                           += amount;

        emit ClaimFlagged(epoch, msg.sender, amount, evidenceHash);
    }

    function flagExclusion(uint256 epoch, uint256 amount, bytes32 evidenceHash) external whenNotPaused {
        if (evidenceHash == bytes32(0)) revert ZeroEvidenceHash();
        if (epoch != currentEpoch)                 revert CanOnlyFlagCurrentEpoch();
        if (sanctioned[msg.sender])                revert Sanctioned();
        if (hasClaimed[epoch][msg.sender])         revert AlreadyClaimed();
        if (flaggedAmount[epoch][msg.sender] != 0) revert AlreadyFlagged();
        if (amount == 0)                           revert ZeroAmount();
        if (epochMerkleRoot[epoch] == bytes32(0))  revert NoRootForEpoch();
        if (amount > dailyVolumeCap)               revert DailyCapExceeded();
        if (amount > hardAbsoluteVolumeCap)        revert HardCapExceeded();

        hasClaimed[epoch][msg.sender]         = true;
        flaggedAmount[epoch][msg.sender]      = amount;
        disputeFlaggedTimestamp[epoch][msg.sender] = block.timestamp;
        isExclusionDispute[epoch][msg.sender] = true;
        totalFlaggedExclusion                += amount;

        emit ExclusionClaimFlagged(epoch, msg.sender, amount, evidenceHash);
    }

    function retractClaimDispute(uint256 epoch) external nonReentrant whenNotPaused {
        address pharmacy = msg.sender;
        uint256 amount = flaggedAmount[epoch][pharmacy];
        if (amount == 0) revert NoFlaggedClaim();

        uint256 flaggedAt = disputeFlaggedTimestamp[epoch][pharmacy];
        if (!_hasReachedDelay(flaggedAt, DISPUTE_TIMEOUT)) revert DisputeTimeoutNotElapsed();

        bool isExclusion = isExclusionDispute[epoch][pharmacy];
        hasClaimed[epoch][pharmacy] = false;
        flaggedAmount[epoch][pharmacy] = 0;
        // ... Reverses volume accounting or channels quarantined funds upon epoch recall ...
    }
```
