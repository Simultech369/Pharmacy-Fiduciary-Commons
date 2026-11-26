const { expect } = require("chai");
const { ethers } = require("hardhat");

/**
 * Dedicated regression suite locking down previously discovered and fixed defects
 * across PBMRebateTreasury and PatientFundParticipatoryBudgeting.
 */
describe("Smart Contract Bug Regressions", function () {
  const toWei = (v) => ethers.parseEther(String(v));
  const MIN_EPOCH_DURATION = 24 * 60 * 60;
  const RECALL_DELAY = 30 * 24 * 60 * 60;
  const STALE_RECOVERY_DELAY = 180 * 24 * 60 * 60;
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

  function buildTwoLeafTree(e0, e1) {
    const l0 = merkleLeaf(e0.pharmacy, e0.amount, e0.cap);
    const l1 = merkleLeaf(e1.pharmacy, e1.amount, e1.cap);
    const root =
      BigInt(l0) <= BigInt(l1)
        ? ethers.solidityPackedKeccak256(["bytes32", "bytes32"], [l0, l1])
        : ethers.solidityPackedKeccak256(["bytes32", "bytes32"], [l1, l0]);
    return {
      root,
      proof0: [l1],
      proof1: [l0]
    };
  }

  async function increaseTime(seconds) {
    await ethers.provider.send("evm_increaseTime", [Number(seconds)]);
    await ethers.provider.send("evm_mine", []);
  }

  async function execViaTimelock(calldata, saltLabel) {
    const target = await treasury.getAddress();
    const salt = ethers.keccak256(ethers.toUtf8Bytes(saltLabel));
    await timelock.connect(council).schedule(target, 0, calldata, ethers.ZeroHash, salt, 1);
    await increaseTime(2);
    await timelock.connect(council).execute(target, 0, calldata, ethers.ZeroHash, salt);
  }

  beforeEach(async function () {
    const signers = await ethers.getSigners();
    council = signers[0];
    rootConfirmer = signers[1];
    guardian = signers[2];
    patientFund = signers[3];
    environmentalFund = signers[4];
    depositor = signers[5];
    pharmacies = signers.slice(6, 11);

    const MockERC20 = await ethers.getContractFactory("MockERC20");
    token = await MockERC20.deploy("Mock DAI", "mDAI", 18);
    await token.waitForDeployment();

    const Timelock = await ethers.getContractFactory("TimelockController");
    timelock = await Timelock.deploy(1n, [council.address], [ethers.ZeroAddress], council.address);
    await timelock.waitForDeployment();

    const Treasury = await ethers.getContractFactory("PBMRebateTreasury");
    treasury = await Treasury.deploy(
      await token.getAddress(),
      patientFund.address,
      environmentalFund.address,
      toWei("10000"), // dailyVolumeCap (hardAbsoluteVolumeCap = 100,000)
      toWei("50"),
      council.address,
      rootConfirmer.address,
      await timelock.getAddress(),
      guardian.address
    );
    await treasury.waitForDeployment();

    await token.mint(depositor.address, toWei("500000"));
    await token.mint(council.address, toWei("100000"));
    await token.connect(depositor).approve(await treasury.getAddress(), ethers.MaxUint256);
    await token.connect(council).approve(await treasury.getAddress(), ethers.MaxUint256);
  });

  it("Regression (85f1149): exclusion remediation payout does not falsely trip RootTotalExceeded on Merkle claims", async function () {
    await treasury.connect(depositor).depositRebate(toWei("20000"), "Q1 Rebates");
    await treasury.connect(council).fundExclusionRemediation(toWei("5000"));

    const a0 = toWei("1000");
    const a1 = toWei("1500");
    const tree = buildTwoLeafTree(
      { pharmacy: pharmacies[0].address, amount: a0, cap: a0 },
      { pharmacy: pharmacies[1].address, amount: a1, cap: a1 }
    );

    await treasury.connect(council).proposeRoot(tree.root, a0 + a1);
    await treasury.connect(rootConfirmer).confirmRoot(0);

    // Omitted pharmacy[2] gets a 1,200-token exclusion payout first, raising epochVolume to 1,200.
    // Under the prior bug (`newVolume > epochRootTotal`), the second legitimate root claim would revert!
    await treasury.connect(pharmacies[2]).flagExclusion(0, toWei("1200"), evidenceHash("excl-reg"));
    await treasury.connect(rootConfirmer).approveExclusionClaim(0, pharmacies[2].address);
    await treasury.connect(council).resolveClaim(
      0,
      pharmacies[2].address,
      DisputeResolution.RELEASE_TO_PHARMACY,
      evidenceHash("excl-resolved")
    );

    expect(await treasury.epochVolume()).to.equal(toWei("1200"));
    expect(await treasury.epochRootClaimedTotal(0)).to.equal(0n);

    // Both Merkle-root claimants can still claim or flag their full 2,500 root total
    await treasury.connect(pharmacies[0]).claim(a0, a0, tree.proof0);
    await treasury.connect(pharmacies[1]).flagClaim(0, a1, a1, tree.proof1, evidenceHash("p1-flag"));

    expect(await treasury.epochRootClaimedTotal(0)).to.equal(a0 + a1);
    expect(await treasury.epochEscrow(0)).to.equal(0n);

    const [isSolvent, delta] = await treasury.solvencyCheck();
    expect(isSolvent).to.be.true;
    expect(delta).to.equal(0n);
  });

  async function expectRevert(promise, expectedSubstring) {
    let reverted = false;
    try {
      await promise;
    } catch (err) {
      reverted = true;
      if (expectedSubstring) {
        expect(err.message).to.include(expectedSubstring);
      }
    }
    expect(reverted, `Expected revert (${expectedSubstring || "any"})`).to.be.true;
  }

  it("Regression: 1-wei dust deposit on day 179 cannot reset the 180-day stale recovery clock or divert from patientFund", async function () {
    await treasury.connect(depositor).depositRebate(toWei("5000"), "Unrooted Epoch");

    await increaseTime(STALE_RECOVERY_DELAY - 3600);
    // Attacker/depositor sends 1 wei just before day 180 hoping to extend recovery delay
    await treasury.connect(depositor).depositRebate(1n, "dust-poke");

    await increaseTime(7200);
    const recoverable = await treasury.getRecoverableStaleAmount();
    expect(recoverable).to.be.greaterThan(toWei("4900"));

    // Diverting stale recovery to council or depositor reverts
    const badCalldata = treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [
      council.address,
      recoverable
    ]);
    await timelock.connect(council).schedule(
      await treasury.getAddress(),
      0,
      badCalldata,
      ethers.ZeroHash,
      evidenceHash("bad-recipient"),
      1
    );
    await increaseTime(2);
    await expectRevert(
      timelock.connect(council).execute(
        await treasury.getAddress(),
        0,
        badCalldata,
        ethers.ZeroHash,
        evidenceHash("bad-recipient")
      )
    );

    // Routing to immutable patientFund succeeds
    const pfBefore = await token.balanceOf(patientFund.address);
    await execViaTimelock(
      treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [patientFund.address, recoverable]),
      "good-stale-recovery"
    );
    expect(await token.balanceOf(patientFund.address) - pfBefore).to.equal(recoverable);
  });

  it("Regression: hardAbsoluteVolumeCap is strictly downward-only and permanently bounds dailyVolumeCap", async function () {
    const initialHardCap = await treasury.hardAbsoluteVolumeCap();
    expect(initialHardCap).to.equal(toWei("100000"));

    // Equal or higher hard cap reverts
    const increaseData = treasury.interface.encodeFunctionData("reduceHardCap", [toWei("100000")]);
    await timelock.connect(council).schedule(
      await treasury.getAddress(),
      0,
      increaseData,
      ethers.ZeroHash,
      evidenceHash("no-increase"),
      1
    );
    await increaseTime(2);
    await expectRevert(
      timelock.connect(council).execute(
        await treasury.getAddress(),
        0,
        increaseData,
        ethers.ZeroHash,
        evidenceHash("no-increase")
      )
    );

    // Ratchet hard cap down to 25,000
    await execViaTimelock(
      treasury.interface.encodeFunctionData("reduceHardCap", [toWei("25000")]),
      "ratchet-25k"
    );
    expect(await treasury.hardAbsoluteVolumeCap()).to.equal(toWei("25000"));

    // Updating dailyVolumeCap above the lowered 25,000 ceiling reverts
    const exceedDailyData = treasury.interface.encodeFunctionData("updateDailyCap", [toWei("25001")]);
    await timelock.connect(council).schedule(
      await treasury.getAddress(),
      0,
      exceedDailyData,
      ethers.ZeroHash,
      evidenceHash("exceed-daily"),
      1
    );
    await increaseTime(2);
    await expectRevert(
      timelock.connect(council).execute(
        await treasury.getAddress(),
        0,
        exceedDailyData,
        ethers.ZeroHash,
        evidenceHash("exceed-daily")
      )
    );
  });

  it("Regression: dismissing a quarantined normal dispute after epoch recall routes released escrow to patientFund", async function () {
    await treasury.connect(depositor).depositRebate(toWei("10000"), "Post-Recall Dismiss Batch");
    const a0 = toWei("400");
    const a1 = toWei("600");
    const tree = buildTwoLeafTree(
      { pharmacy: pharmacies[0].address, amount: a0, cap: a0 },
      { pharmacy: pharmacies[1].address, amount: a1, cap: a1 }
    );

    await treasury.connect(council).proposeRoot(tree.root, a0 + a1);
    await treasury.connect(rootConfirmer).confirmRoot(0);

    // Pharmacy 0 flags normal dispute (400 quarantined); Pharmacy 1 leaves 600 unclaimed
    await treasury.connect(pharmacies[0]).flagClaim(0, a0, a0, tree.proof0, evidenceHash("quarantine-a0"));

    await increaseTime(MIN_EPOCH_DURATION + 10);
    await treasury.connect(council).finalizeEpoch();

    await increaseTime(RECALL_DELAY + 10);
    const pfBeforeRecall = await token.balanceOf(patientFund.address);
    await treasury.connect(council).recallUnclaimed(0);
    // Only unclaimed 600 is recalled; quarantined 400 remains in totalFlaggedNormal
    expect(await token.balanceOf(patientFund.address) - pfBeforeRecall).to.equal(a1);
    expect(await treasury.totalFlaggedNormal()).to.equal(a0);

    // Dismissing the dispute after recall must send the 400 to patientFund rather than stranding it
    const pfBeforeDismiss = await token.balanceOf(patientFund.address);
    await treasury.connect(council).resolveClaim(
      0,
      pharmacies[0].address,
      DisputeResolution.DISMISS,
      evidenceHash("dismiss-post-recall")
    );
    expect(await token.balanceOf(patientFund.address) - pfBeforeDismiss).to.equal(a0);
    expect(await treasury.totalFlaggedNormal()).to.equal(0n);

    const [isSolvent, delta] = await treasury.solvencyCheck();
    expect(isSolvent).to.be.true;
    expect(delta).to.equal(0n);
  });

  it("Regression (083836e): capped quadratic matching surplus stays in patient-bound recycled pool across rounds", async function () {
    const PB = await ethers.getContractFactory("PatientFundParticipatoryBudgeting");
    const pb = await PB.deploy(await token.getAddress(), council.address, guardian.address);
    await pb.waitForDeployment();

    await token.connect(council).approve(await pb.getAddress(), ethers.MaxUint256);
    await pb.connect(council).updateProjectMatchingCap(4000n); // 40% cap per project
    await pb.connect(council).startRound(toWei("1000"));

    for (let i = 0; i < 4; i++) {
      await pb.connect(council).registerVoter(1n, pharmacies[i].address, true);
    }
    await pb.connect(council).registerProject(1n, "Community Insulin Fridge", pharmacies[4].address);
    await pb.connect(council).registerProject(1n, "Rural Delivery Co-op", depositor.address);

    // 3 votes on Project 0 (weight 9) vs 1 vote on Project 1 (weight 1): raw shares 900 and 100.
    // 40% cap restricts Project 0 to 400, Project 1 gets 100, and 500 surplus stays in recycledMatchingPool.
    await pb.connect(pharmacies[0]).castVote(1n, 0n);
    await pb.connect(pharmacies[1]).castVote(1n, 0n);
    await pb.connect(pharmacies[2]).castVote(1n, 0n);
    await pb.connect(pharmacies[3]).castVote(1n, 1n);

    const councilBefore = await token.balanceOf(council.address);
    await pb.connect(council).finalizeRound(1n);

    expect(await token.balanceOf(council.address)).to.equal(councilBefore);
    expect(await pb.recycledMatchingPool()).to.equal(toWei("500"));
    expect(await pb.roundProjectShares(1n, 0n)).to.equal(toWei("400"));
    expect(await pb.roundProjectShares(1n, 1n)).to.equal(toWei("100"));
  });
});
