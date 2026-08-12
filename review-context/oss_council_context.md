# OSS Council Review Context - Pharmacy Fiduciary Commons

Status: Active context for multi-agent council review of `.next` roadmap sorting and under-asked question discovery.

## 1. Repository State & Evidence Lineage
- Local Path: `C:\Users\Josh\Desktop\PBMRebateTreasuryFinal`
- Active Branch: `feature/db-proxy` at `c227c039bf24e516e833f07dda1558d455b70b0e` `[committed HEAD]`
- Remote Sync: local branch is 1 commit ahead of `origin/feature/db-proxy`; push remains an explicit operator approval gate `[dirty working tree]`
- Test Suite Health: 282 passing unit, security, EIP-191/712 server, Circom circuit, ZK fixture, dashboard credibility, and continuity tests via the offline multimodal harness `[generated cache]`
- Master Receipt: `cache/verification_master_receipt.json` **PASSED (5/5 steps)** `[generated cache]`
- Exclusions: Local pre-commit guardrail artifacts (`reviews/guardrail-review.txt` and `reviews/guardrail-router-metadata.json`) are local-only review evidence and excluded from protocol state claims.

## 2. Recently Implemented & Verified Milestones
1. **Database Proxy & RLS Hardening (`server/createApp.js`)**: Rate-limiting headers (`X-RateLimit-*`), correlation tracing (`X-Request-ID`), EIP-191/712 signature verification, and 15s row-locked request ledger idempotency.
2. **Circom VoteNullifier Circuit (`circuits/vote_nullifier.circom`)**: Poseidon Merkle membership constraints, project/round-scoped nullifier derivation.
3. **ZK Fixture Gate & Leakage Matrix (`test/ZKNullifierFixtureGate.test.js`)**: 18-step schema validation, semantic wallet-linkable vs unlinkable path bounds, metadata leakage budget, and verifier governance.
4. **Offline Continuity Nullifier Deduplication (`tools/resilience/continuity-engine.mjs`)**: `validateGlobalNullifierCache` dry-run intake check preventing duplicate nullifier relay within epoch.

## 3. Parked Candidate Items for `.next` Roadmap Prioritization

### Item 1: Dispute Tolling & Retraction Policy Framing
- *Objective*: Formalize dispute timeout tolling, stale claim recovery windows, and multi-signature retraction bounds in treasury settlement logic.
- *Primary Files*: `contracts/PBMRebateTreasury.sol`, `test/PBMRebateTreasury.dispute-timeout.test.js`, `test/PBMRebateTreasuryStaleRecovery.test.js`.
- *Invariants*: Prevent premature rebate distribution during active disputes; ensure non-reclaimed allocations revert to patient fund after 30-day PBM recall delay (`RECALL_DELAY`). Verify treasury domain variables (`totalFlaggedNormal`, `epochEscrow`, `totalEscrowed`, `patientFund`, `distributionPool`) remain consistent.

### Item 2: Remote RPC Verification Gate & Client Witness Isolation
- *Objective*: Build client-side witness preparation adapters that isolate local Circom inputs while enforcing strict host-facing verifier interfaces without adding third-party RPC dependencies.
- *Primary Files*: `circuits/vote_nullifier.circom`, `test/ZKNullifierFixtureGate.test.js`, `IDENTITY_NULLIFIER_DESIGN.md`.
- *Invariants*: Enforce mock/schema public-boundary constraints by proving forbidden metadata (timestamps, RPC IP headers, raw wallet keys) remains outside fixture public signals and packet schemas. Production witness preparation and unlinkability remain spec-only and unimplemented.

### Item 3: Patient Fund Quadratic Matching Cap Policy & Solvency Debt Bounds
- *Objective*: Implement explicit per-project quadratic matching caps and shortfall-aware round lifecycle notices in participatory budgeting contracts (with 90-day `MATCH_RECLAIM_GRACE_PERIOD`).
- *Primary Files*: `contracts/PatientFundParticipatoryBudgeting.sol`, `test/foundry/PatientFundInvariants.t.sol`, `SOLVENCY_DEBT_SEMANTICS.md`.
- *Invariants*: Maintain non-negative PatientFund debt counters (`totalDebt`, `roundDeficit`) and bounded matching obligations; never treat observed shortfall reduction as guaranteed liquidity repayment; preserve Ostrom-commons governance bounds.

## 4. Specific Council Review Instructions

As the Senior Review Council (Grok / Strategist / Skeptic / Advocate):
1. **Next-Slice Prioritization**: Evaluate and rank Items 1, 2, and 3 in exact execution order for `.next`.
2. **Under-Asked Questions**: Identify the top 3 critical, under-asked questions that could derail the chosen priority item or create hidden solvency/privacy vulnerabilities.
3. **Smallest Proof-Bounded Test Slice**: Define the minimal test assertion to implement first before writing production code for the top-ranked item.

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
