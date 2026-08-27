const { expect } = require("chai");
const { ethers } = require("hardhat");

/**
 * @title PBMRebateTreasury Stateful Multi-Epoch Fuzzing & Invariant Suite
 * @notice Validates multi-epoch state transitions and proves zero-delta solvency,
 *         balance-to-bucket conservation, total escrow integrity, and normal dispute totals.
 */
describe("PBMRebateTreasury stateful invariant fuzzing", function () {
  this.timeout(300000);

  const toWei = (value) => ethers.parseEther(String(value));
  const MIN_EPOCH_DURATION = 24 * 60 * 60; // 1 day
  const RECALL_DELAY = 30 * 24 * 60 * 60;   // 30 days
  const DISPUTE_TIMEOUT = 30 * 24 * 60 * 60; // 30 days
  const DisputeResolution = { RELEASE_TO_PHARMACY: 0, SEND_TO_PATIENT_FUND: 1, DISMISS: 2 };

  let token;
  let treasury;
  let timelock;
  let council;
  let rootConfirmer;
  let guardian;
  let patientFund;
  let environmentalFund;
  let depositor;
  let pharmacies;

  function evidenceHash(label) {
    return ethers.keccak256(ethers.toUtf8Bytes(label));
  }

  function merkleLeaf(pharmacyAddress, amount, eligibleCap) {
    const inner = ethers.solidityPackedKeccak256(
      ["address", "uint256", "uint256"],
      [pharmacyAddress, amount, eligibleCap]
    );
    return ethers.keccak256(ethers.solidityPacked(["bytes32"], [inner]));
  }

  function buildTree(leafEntries) {
    const leaves = leafEntries.map((e) => merkleLeaf(e.pharmacy, e.amount, e.cap));
    if (leaves.length === 1) {
      return {
        root: leaves[0],
        getProof: () => [],
      };
    }

    let currentLayer = leaves;
    const layers = [currentLayer];

    while (currentLayer.length > 1) {
      const nextLayer = [];
      for (let i = 0; i < currentLayer.length; i += 2) {
        if (i + 1 < currentLayer.length) {
          const a = currentLayer[i];
          const b = currentLayer[i + 1];
          const combined =
            BigInt(a) <= BigInt(b)
              ? ethers.solidityPackedKeccak256(["bytes32", "bytes32"], [a, b])
              : ethers.solidityPackedKeccak256(["bytes32", "bytes32"], [b, a]);
          nextLayer.push(combined);
        } else {
          const a = currentLayer[i];
          const combined = ethers.solidityPackedKeccak256(["bytes32", "bytes32"], [a, a]);
          nextLayer.push(combined);
        }
      }
      currentLayer = nextLayer;
      layers.push(currentLayer);
    }

    const root = layers[layers.length - 1][0];

    function getProof(index) {
      const proof = [];
      let idx = index;
      for (let l = 0; l < layers.length - 1; l++) {
        const layer = layers[l];
        let siblingIdx;
        if (idx % 2 === 0) {
          siblingIdx = idx + 1 < layer.length ? idx + 1 : idx;
        } else {
          siblingIdx = idx - 1;
        }
        proof.push(layer[siblingIdx]);
        idx = Math.floor(idx / 2);
      }
      return proof;
    }

    return { root, getProof };
  }

  async function increaseTime(seconds) {
    await ethers.provider.send("evm_increaseTime", [Number(seconds)]);
    await ethers.provider.send("evm_mine", []);
  }

  /**
   * @notice Asserts all 4 core mathematical and accounting invariants.
   */
  async function assertInvariants(actionDescription = "") {
    const currentEpoch = Number(await treasury.currentEpoch());

    // 1. solvencyCheck() returns isSolvent == true and delta == 0
    const [isSolvent, delta, expectedBalance, actualBalance] = await treasury.solvencyCheck();
    expect(isSolvent, `[Invariant 1 Failed] Insolvent after ${actionDescription}`).to.be.true;
    expect(delta, `[Invariant 1 Failed] Non-zero delta (${delta}) after ${actionDescription}`).to.equal(0n);
    expect(expectedBalance, `[Invariant 1 Failed] Balance mismatch after ${actionDescription}`).to.equal(actualBalance);

    // 2. contractBalance == distributionPool + governanceReserve + exclusionRemediationReserve + totalEscrowed + totalFlaggedNormal
    const contractBalance = await token.balanceOf(await treasury.getAddress());
    const distributionPool = await treasury.distributionPool();
    const governanceReserve = await treasury.governanceReserve();
    const exclusionRemediationReserve = await treasury.exclusionRemediationReserve();
    const totalEscrowed = await treasury.totalEscrowed();
    const totalFlaggedNormal = await treasury.totalFlaggedNormal();

    const sumBuckets =
      distributionPool +
      governanceReserve +
      exclusionRemediationReserve +
      totalEscrowed +
      totalFlaggedNormal;

    expect(
      contractBalance,
      `[Invariant 2 Failed] Token balance ${contractBalance} != sum of buckets ${sumBuckets} after ${actionDescription}`
    ).to.equal(sumBuckets);

    // 3. totalEscrowed == sum(epochEscrow)
    let calculatedSumEscrow = 0n;
    for (let e = 0; e <= currentEpoch; e++) {
      calculatedSumEscrow += await treasury.epochEscrow(e);
    }
    expect(
      totalEscrowed,
      `[Invariant 3 Failed] totalEscrowed ${totalEscrowed} != sum(epochEscrow) ${calculatedSumEscrow} after ${actionDescription}`
    ).to.equal(calculatedSumEscrow);

    // 4. totalFlaggedNormal == sum(flaggedNormal)
    let calculatedSumFlaggedNormal = 0n;
    for (let e = 0; e <= currentEpoch; e++) {
      for (const p of pharmacies) {
        const isExclusion = await treasury.isExclusionDispute(e, p.address);
        if (!isExclusion) {
          const amt = await treasury.flaggedAmount(e, p.address);
          calculatedSumFlaggedNormal += amt;
        }
      }
    }
    expect(
      totalFlaggedNormal,
      `[Invariant 4 Failed] totalFlaggedNormal ${totalFlaggedNormal} != sum(flaggedNormal) ${calculatedSumFlaggedNormal} after ${actionDescription}`
    ).to.equal(calculatedSumFlaggedNormal);
  }

  beforeEach(async function () {
    const signers = await ethers.getSigners();
    council = signers[0];
    rootConfirmer = signers[1];
    guardian = signers[2];
    patientFund = signers[3];
    environmentalFund = signers[4];
    depositor = signers[5];
    pharmacies = signers.slice(6, 12); // 6 pharmacies

    const MockERC20 = await ethers.getContractFactory("MockERC20");
    token = await MockERC20.deploy("Mock Payout DAI", "mDAI", 18);
    await token.waitForDeployment();

    const Timelock = await ethers.getContractFactory("TimelockController");
    timelock = await Timelock.deploy(
      1n,
      [council.address],
      [ethers.ZeroAddress],
      council.address
    );
    await timelock.waitForDeployment();

    const Treasury = await ethers.getContractFactory("PBMRebateTreasury");
    treasury = await Treasury.deploy(
      await token.getAddress(),
      patientFund.address,
      environmentalFund.address,
      toWei("500000"), // daily cap
      toWei("50"),     // minimum epoch volume
      council.address,
      rootConfirmer.address,
      await timelock.getAddress(),
      guardian.address
    );
    await treasury.waitForDeployment();

    // Fund depositor and council with ample tokens
    await token.mint(depositor.address, toWei("5000000"));
    await token.mint(council.address, toWei("1000000"));
    await token.connect(depositor).approve(await treasury.getAddress(), ethers.MaxUint256);
    await token.connect(council).approve(await treasury.getAddress(), ethers.MaxUint256);
  });

  it("maintains all 4 solvency & conservation invariants across initial deployment", async function () {
    await assertInvariants("Deployment");
  });

  it("maintains invariants across random multi-epoch stateful fuzz sequences (Run 1)", async function () {
    await runFuzzEngine(1337, 40);
  });

  it("maintains invariants across random multi-epoch stateful fuzz sequences (Run 2)", async function () {
    await runFuzzEngine(4242, 40);
  });

  it("maintains invariants across random multi-epoch stateful fuzz sequences (Run 3)", async function () {
    await runFuzzEngine(9999, 40);
  });

  it("maintains invariants through full dispute retraction lifecycle before and after recall", async function () {
    // 1. Deposit and propose/confirm root
    await treasury.connect(depositor).depositRebate(toWei("10000"), "Q1 2026 Batch");
    await assertInvariants("Deposit");

    const allocA = toWei("200");
    const allocB = toWei("300");
    const entries = [
      { pharmacy: pharmacies[0].address, amount: allocA, cap: allocA },
      { pharmacy: pharmacies[1].address, amount: allocB, cap: allocB },
    ];
    const tree = buildTree(entries);
    await treasury.connect(council).proposeRoot(tree.root, allocA + allocB);
    await treasury.connect(rootConfirmer).confirmRoot(0);
    await assertInvariants("Root Confirmed");

    // 2. Pharmacy 0 flags normal dispute
    const proof0 = tree.getProof(0);
    await treasury.connect(pharmacies[0]).flagClaim(0, allocA, allocA, proof0, evidenceHash("dispute-normal-retract"));
    await assertInvariants("Flag Claim Normal");

    // 3. Pharmacy 1 flags exclusion dispute
    await treasury.connect(pharmacies[1]).flagExclusion(0, toWei("150"), evidenceHash("dispute-exclusion-retract"));
    await assertInvariants("Flag Exclusion");

    // 4. Pharmacy 1 retracts exclusion dispute after timeout
    await increaseTime(DISPUTE_TIMEOUT + 10);
    await treasury.connect(pharmacies[1]).retractClaimDispute(0);
    await assertInvariants("Retract Exclusion Dispute");

    // 5. Finalize epoch 0 (volume meets minimum from normal flag)
    await increaseTime(RECALL_DELAY + 10);
    await treasury.connect(council).finalizeEpoch();
    await assertInvariants("Finalize Epoch 0");

    // 6. Recall unclaimed epoch 0
    await treasury.connect(council).recallUnclaimed(0);
    await assertInvariants("Recall Unclaimed Epoch 0");

    // 7. Retract Pharmacy 0 normal dispute AFTER epoch was already recalled (diverts to patient fund)
    await treasury.connect(pharmacies[0]).retractClaimDispute(0);
    await assertInvariants("Retract Normal Dispute After Recall");
  });

  it("maintains invariants across all 3 dispute resolution paths (RELEASE, PATIENT_FUND, DISMISS)", async function () {
    // Seed and publish root
    await treasury.connect(depositor).depositRebate(toWei("20000"), "Resolution Test Seed");
    await treasury.connect(council).fundExclusionRemediation(toWei("5000"));
    await assertInvariants("Seed and Fund Exclusion Reserve");

    const a0 = toWei("100");
    const a1 = toWei("120");
    const a2 = toWei("140");
    const a3 = toWei("160");
    const entries = [
      { pharmacy: pharmacies[0].address, amount: a0, cap: a0 },
      { pharmacy: pharmacies[1].address, amount: a1, cap: a1 },
      { pharmacy: pharmacies[2].address, amount: a2, cap: a2 },
      { pharmacy: pharmacies[3].address, amount: a3, cap: a3 },
    ];
    const tree = buildTree(entries);
    const total = a0 + a1 + a2 + a3;

    await treasury.connect(council).proposeRoot(tree.root, total);
    await treasury.connect(rootConfirmer).confirmRoot(0);
    await assertInvariants("Root Confirmed");

    // Pharmacy 0 flags normal dispute -> RELEASE_TO_PHARMACY
    await treasury.connect(pharmacies[0]).flagClaim(0, a0, a0, tree.getProof(0), evidenceHash("p0-flag"));
    await assertInvariants("Pharmacy 0 Flagged");
    await treasury.connect(council).resolveClaim(0, pharmacies[0].address, DisputeResolution.RELEASE_TO_PHARMACY, evidenceHash("p0-release"));
    await assertInvariants("Pharmacy 0 Resolved (RELEASE_TO_PHARMACY)");

    // Pharmacy 1 flags normal dispute -> SEND_TO_PATIENT_FUND
    await treasury.connect(pharmacies[1]).flagClaim(0, a1, a1, tree.getProof(1), evidenceHash("p1-flag"));
    await assertInvariants("Pharmacy 1 Flagged");
    await treasury.connect(council).resolveClaim(0, pharmacies[1].address, DisputeResolution.SEND_TO_PATIENT_FUND, evidenceHash("p1-patient-fund"));
    await assertInvariants("Pharmacy 1 Resolved (SEND_TO_PATIENT_FUND)");

    // Pharmacy 2 flags normal dispute -> DISMISS before recall (returns to epoch escrow)
    await treasury.connect(pharmacies[2]).flagClaim(0, a2, a2, tree.getProof(2), evidenceHash("p2-flag"));
    await assertInvariants("Pharmacy 2 Flagged");
    await treasury.connect(council).resolveClaim(0, pharmacies[2].address, DisputeResolution.DISMISS, evidenceHash("p2-dismiss"));
    await assertInvariants("Pharmacy 2 Resolved (DISMISS before recall)");

    // Pharmacy 4 flags exclusion dispute -> approved -> RELEASE_TO_PHARMACY
    const exclAmt = toWei("250");
    await treasury.connect(pharmacies[4]).flagExclusion(0, exclAmt, evidenceHash("p4-exclusion-flag"));
    await assertInvariants("Pharmacy 4 Exclusion Flagged");
    await treasury.connect(rootConfirmer).approveExclusionClaim(0, pharmacies[4].address);
    await assertInvariants("Pharmacy 4 Exclusion Approved");
    await treasury.connect(council).resolveClaim(0, pharmacies[4].address, DisputeResolution.RELEASE_TO_PHARMACY, evidenceHash("p4-exclusion-release"));
    await assertInvariants("Pharmacy 4 Exclusion Resolved (RELEASE_TO_PHARMACY)");

    // Pharmacy 5 flags exclusion dispute -> DISMISS
    await treasury.connect(pharmacies[5]).flagExclusion(0, toWei("300"), evidenceHash("p5-exclusion-flag"));
    await assertInvariants("Pharmacy 5 Exclusion Flagged");
    await treasury.connect(council).resolveClaim(0, pharmacies[5].address, DisputeResolution.DISMISS, evidenceHash("p5-exclusion-dismiss"));
    await assertInvariants("Pharmacy 5 Exclusion Resolved (DISMISS)");
  });

  /**
   * Deterministic PRNG and stateful test engine for multi-epoch fuzzing.
   */
  async function runFuzzEngine(seed, numSteps) {
    let rngState = seed;
    function nextRandom() {
      // Mulberry32 PRNG
      rngState |= 0;
      rngState = (rngState + 0x6d2b79f5) | 0;
      let t = Math.imul(rngState ^ (rngState >>> 15), 1 | rngState);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    }

    function randInt(min, max) {
      return Math.floor(nextRandom() * (max - min + 1)) + min;
    }

    // State tracking across epochs
    const epochData = {};

    for (let step = 0; step < numSteps; step++) {
      const currentEpoch = Number(await treasury.currentEpoch());
      if (!epochData[currentEpoch]) {
        epochData[currentEpoch] = {
          hasRoot: false,
          rootTotal: 0n,
          tree: null,
          entries: [],
          claimedOrFlagged: new Set(),
          disputes: {}, // pharmacyAddress -> { type: 'normal' | 'exclusion', amount: bigint, approved: bool, flaggedAt: number }
        };
      }

      const current = epochData[currentEpoch];
      const distributionPool = await treasury.distributionPool();
      const exclusionReserve = await treasury.exclusionRemediationReserve();
      const actionType = randInt(0, 8);

      switch (actionType) {
        case 0: {
          // Action: depositRebate()
          const amount = toWei(randInt(500, 20000));
          await treasury.connect(depositor).depositRebate(amount, `Fuzz Deposit step ${step}`);
          await assertInvariants(`Step ${step}: depositRebate(${amount})`);
          break;
        }

        case 1: {
          // Action: fundExclusionRemediation()
          const amount = toWei(randInt(100, 5000));
          await treasury.connect(council).fundExclusionRemediation(amount);
          await assertInvariants(`Step ${step}: fundExclusionRemediation(${amount})`);
          break;
        }

        case 2: {
          // Action: proposeRoot() & confirmRoot() if not yet published
          if (!current.hasRoot && distributionPool >= toWei("300")) {
            const numLeaves = randInt(2, pharmacies.length);
            const selectedPharmacies = pharmacies.slice(0, numLeaves);
            const poolBudget = Number(ethers.formatEther(distributionPool)) * 0.7;
            const perPharmBudget = Math.floor(poolBudget / numLeaves);
            const entries = [];
            let total = 0n;

            for (let i = 0; i < selectedPharmacies.length; i++) {
              const amt = toWei(Math.max(10, randInt(10, Math.max(10, perPharmBudget))));
              const cap = amt + toWei(10);
              entries.push({ pharmacy: selectedPharmacies[i].address, amount: amt, cap, index: i });
              total += amt;
            }

            if (total <= distributionPool && total > 0n) {
              const tree = buildTree(entries);
              await treasury.connect(council).proposeRoot(tree.root, total);
              await treasury.connect(rootConfirmer).confirmRoot(currentEpoch);

              current.hasRoot = true;
              current.rootTotal = total;
              current.tree = tree;
              current.entries = entries;

              await assertInvariants(`Step ${step}: proposeRoot + confirmRoot for epoch ${currentEpoch}`);
            }
          }
          break;
        }

        case 3: {
          // Action: claim()
          if (current.hasRoot && current.entries.length > 0) {
            const available = current.entries.filter((e) => !current.claimedOrFlagged.has(e.pharmacy));
            if (available.length > 0) {
              const pick = available[randInt(0, available.length - 1)];
              const signer = pharmacies.find((p) => p.address.toLowerCase() === pick.pharmacy.toLowerCase());
              const proof = current.tree.getProof(pick.index);

              await treasury.connect(signer).claim(pick.amount, pick.cap, proof);
              current.claimedOrFlagged.add(pick.pharmacy);

              await assertInvariants(`Step ${step}: claim() by pharmacy ${pick.pharmacy} in epoch ${currentEpoch}`);
            }
          }
          break;
        }

        case 4: {
          // Action: flagClaim() (Proof-backed normal dispute)
          if (current.hasRoot && current.entries.length > 0) {
            const available = current.entries.filter((e) => !current.claimedOrFlagged.has(e.pharmacy));
            if (available.length > 0) {
              const pick = available[randInt(0, available.length - 1)];
              const signer = pharmacies.find((p) => p.address.toLowerCase() === pick.pharmacy.toLowerCase());
              const proof = current.tree.getProof(pick.index);

              await treasury.connect(signer).flagClaim(
                currentEpoch,
                pick.amount,
                pick.cap,
                proof,
                evidenceHash(`fuzz-normal-dispute-${step}`)
              );
              current.claimedOrFlagged.add(pick.pharmacy);
              current.disputes[pick.pharmacy] = {
                type: "normal",
                amount: pick.amount,
                approved: false,
                epoch: currentEpoch,
              };

              await assertInvariants(`Step ${step}: flagClaim() by pharmacy ${pick.pharmacy} in epoch ${currentEpoch}`);
            }
          }
          break;
        }

        case 5: {
          // Action: flagExclusion() (No-proof exclusion dispute)
          if (current.hasRoot) {
            const available = pharmacies.filter((p) => !current.claimedOrFlagged.has(p.address));
            if (available.length > 0) {
              const signer = available[randInt(0, available.length - 1)];
              const amount = toWei(randInt(20, 200));

              await treasury.connect(signer).flagExclusion(
                currentEpoch,
                amount,
                evidenceHash(`fuzz-exclusion-dispute-${step}`)
              );
              current.claimedOrFlagged.add(signer.address);
              current.disputes[signer.address] = {
                type: "exclusion",
                amount,
                approved: false,
                epoch: currentEpoch,
              };

              await assertInvariants(`Step ${step}: flagExclusion() by pharmacy ${signer.address} in epoch ${currentEpoch}`);
            }
          }
          break;
        }

        case 6: {
          // Action: approveExclusionClaim() or resolveClaim() or retractClaimDispute()
          // Pick any active dispute across known epochs
          const allOpenDisputes = [];
          for (const [ep, data] of Object.entries(epochData)) {
            for (const [pharm, d] of Object.entries(data.disputes)) {
              if (d) allOpenDisputes.push({ ...d, epoch: Number(ep), pharmacy: pharm });
            }
          }

          if (allOpenDisputes.length > 0) {
            const chosen = allOpenDisputes[randInt(0, allOpenDisputes.length - 1)];
            const signer = pharmacies.find((p) => p.address.toLowerCase() === chosen.pharmacy.toLowerCase());
            const subChoice = randInt(0, 3);

            if (subChoice === 0 && chosen.type === "exclusion" && !chosen.approved) {
              // Approve exclusion dispute
              await treasury.connect(rootConfirmer).approveExclusionClaim(chosen.epoch, chosen.pharmacy);
              epochData[chosen.epoch].disputes[chosen.pharmacy].approved = true;
              await assertInvariants(`Step ${step}: approveExclusionClaim() epoch ${chosen.epoch}`);
            } else if (subChoice === 1) {
              // Retract dispute after timeout
              await increaseTime(DISPUTE_TIMEOUT + 5);
              await treasury.connect(signer).retractClaimDispute(chosen.epoch);
              delete epochData[chosen.epoch].disputes[chosen.pharmacy];
              await assertInvariants(`Step ${step}: retractClaimDispute() epoch ${chosen.epoch}`);
            } else {
              // Resolve dispute
              let resolution = randInt(0, 2);
              if (chosen.type === "exclusion") {
                // Exclusion disputes cannot be SEND_TO_PATIENT_FUND
                // RELEASE requires approval and sufficient reserve
                if (!chosen.approved || exclusionReserve < chosen.amount) {
                  resolution = DisputeResolution.DISMISS;
                } else {
                  resolution = randInt(0, 1) === 0 ? DisputeResolution.RELEASE_TO_PHARMACY : DisputeResolution.DISMISS;
                }
              }

              await treasury.connect(council).resolveClaim(
                chosen.epoch,
                chosen.pharmacy,
                resolution,
                evidenceHash(`resolve-${step}`)
              );
              delete epochData[chosen.epoch].disputes[chosen.pharmacy];
              await assertInvariants(`Step ${step}: resolveClaim(${chosen.epoch}, ${chosen.pharmacy}, res=${resolution})`);
            }
          }
          break;
        }

        case 7: {
          // Action: finalizeEpoch()
          if (current.hasRoot) {
            const epochVolume = await treasury.epochVolume();
            const minVolume = await treasury.minimumEpochVolume();

            if (epochVolume >= minVolume) {
              await increaseTime(MIN_EPOCH_DURATION + 10);
              await treasury.connect(council).finalizeEpoch();
              await assertInvariants(`Step ${step}: finalizeEpoch() -> epoch ${currentEpoch + 1}`);
            } else {
              // Finalize stale epoch after recall delay
              await increaseTime(RECALL_DELAY + 10);
              await treasury.connect(council).finalizeStaleEpochForRecall();
              await assertInvariants(`Step ${step}: finalizeStaleEpochForRecall() -> epoch ${currentEpoch + 1}`);
            }
          }
          break;
        }

        case 8: {
          // Action: recallUnclaimed() for past finalized epochs
          for (let ep = 0; ep < currentEpoch; ep++) {
            const escrow = await treasury.epochEscrow(ep);
            const recalled = await treasury.epochRecalled(ep);
            if (escrow > 0n && !recalled) {
              await increaseTime(RECALL_DELAY + 10);
              await treasury.connect(council).recallUnclaimed(ep);
              await assertInvariants(`Step ${step}: recallUnclaimed(${ep})`);
              break;
            }
          }
          break;
        }
      }
    }
  }

  it("proves Multi-Asset and Forced Transfer Contamination Immunity (Invariant 5)", async function () {
    // 1. Initial deposit and verification
    await treasury.connect(depositor).depositRebate(toWei("25000"), "Batch Alpha");
    await assertInvariants("Initial Deposit");

    // 2. Deploy foreign token and force transfer into treasury
    const MockERC20 = await ethers.getContractFactory("MockERC20");
    const spamToken = await MockERC20.deploy("Spam Airdrop", "SPAM", 18);
    await spamToken.waitForDeployment();
    await spamToken.mint(depositor.address, toWei("1000000"));
    await spamToken.connect(depositor).transfer(await treasury.getAddress(), toWei("500000"));

    // 3. Force ETH transfer into treasury
    const ForceETH = await ethers.getContractFactory("ForceETH");
    const forceETH = await ForceETH.deploy({ value: toWei("5") });
    await forceETH.waitForDeployment();
    await forceETH.forceSend(await treasury.getAddress());

    // 4. Assert primary token solvency and buckets remain 100% uncontaminated
    const [isSolvent, delta, expected, actual] = await treasury.solvencyCheck();
    expect(isSolvent).to.be.true;
    expect(delta).to.equal(0n);
    expect(expected).to.equal(toWei("25000"));
    expect(actual).to.equal(toWei("25000"));
    await assertInvariants("Post Forced Transfers");

    // 5. Recover extraneous assets via council sweep (ERC20 -> patientFund) and timelock (ETH -> environmentalFund)
    await treasury.connect(council).sweep(await spamToken.getAddress(), toWei("500000"));
    expect(await spamToken.balanceOf(patientFund.address)).to.equal(toWei("500000"));

    const sweepETHData = treasury.interface.encodeFunctionData("sweepETH", []);
    await timelock.connect(council).schedule(await treasury.getAddress(), 0, sweepETHData, ethers.ZeroHash, ethers.ZeroHash, 1);
    await increaseTime(2);
    await timelock.connect(council).execute(await treasury.getAddress(), 0, sweepETHData, ethers.ZeroHash, ethers.ZeroHash);
    expect(await ethers.provider.getBalance(environmentalFund.address)).to.be.greaterThan(toWei("4.9"));

    // 6. Solvency remains strictly zero-delta
    await assertInvariants("Post Sweep Recovery");
  });

  it("proves Exclusion Remediation & Bounded Historical Conservation (Invariant 6)", async function () {
    // 1. Fund initial remediation reserve
    await treasury.connect(council).fundExclusionRemediation(toWei("5000"));
    expect(await treasury.exclusionRemediationReserve()).to.equal(toWei("5000"));
    await assertInvariants("Fund Exclusion Remediation 5000");

    // 2. Setup epoch with active allocation
    await treasury.connect(depositor).depositRebate(toWei("10000"), "Remediation Batch");
    const alloc = toWei("1000");
    const entries = [{ pharmacy: pharmacies[0].address, amount: alloc, cap: alloc }];
    const tree = buildTree(entries);
    await treasury.connect(council).proposeRoot(tree.root, alloc);
    await treasury.connect(rootConfirmer).confirmRoot(0);

    // 3. Flag exclusion claims against epoch 0
    await treasury.connect(pharmacies[1]).flagExclusion(0, toWei("1200"), evidenceHash("ex-claim-1"));
    await treasury.connect(pharmacies[2]).flagExclusion(0, toWei("800"), evidenceHash("ex-claim-2"));
    await assertInvariants("Flag 2 Exclusion Claims");

    // 4. Approve only pharmacy 1
    await treasury.connect(rootConfirmer).approveExclusionClaim(0, pharmacies[1].address);
    await assertInvariants("Approve Exclusion Claim 1");

    // 5. Resolve pharmacy 1 (Release from exclusion reserve -> 90% pharmacy, 10% gov reserve)
    await treasury.connect(council).resolveClaim(
      0,
      pharmacies[1].address,
      DisputeResolution.RELEASE_TO_PHARMACY,
      evidenceHash("resolve-release-1")
    );
    expect(await treasury.exclusionRemediationReserve()).to.equal(toWei("3800"));
    expect(await token.balanceOf(pharmacies[1].address)).to.equal(toWei("1080"));
    await assertInvariants("Resolve Exclusion Claim 1 (Release)");

    // 6. Resolve pharmacy 2 (Dismissed)
    await treasury.connect(council).resolveClaim(
      0,
      pharmacies[2].address,
      DisputeResolution.DISMISS,
      evidenceHash("resolve-dismiss-2")
    );
    expect(await treasury.exclusionRemediationReserve()).to.equal(toWei("3800"));
    await assertInvariants("Resolve Exclusion Claim 2 (Dismiss)");
  });
});
