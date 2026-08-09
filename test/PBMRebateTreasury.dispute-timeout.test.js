const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("PBMRebateTreasury dispute timeout retraction", function () {
  const toWei = (value) => ethers.parseEther(value);
  const MIN_EPOCH_DURATION = 24 * 60 * 60;
  const RECALL_DELAY = 30 * 24 * 60 * 60;

  let token;
  let treasury;
  let timelock;
  let council;
  let council2;
  let guardian;
  let patientFund;
  let pharmacy;
  let depositor;
  let attacker;
  let environmentalFund;

  function merkleLeaf(pharmacyAddress, amount, eligibleCap) {
    const inner = ethers.solidityPackedKeccak256(
      ["address", "uint256", "uint256"],
      [pharmacyAddress, amount, eligibleCap]
    );
    return ethers.keccak256(ethers.solidityPacked(["bytes32"], [inner]));
  }

  function makeTwoLeafTree(addrA, amountA, capA, addrB, amountB, capB) {
    const leafA = merkleLeaf(addrA, amountA, capA);
    const leafB = merkleLeaf(addrB, amountB, capB);
    const sorted = [leafA, leafB].sort();
    const root = ethers.keccak256(ethers.solidityPacked(["bytes32", "bytes32"], [sorted[0], sorted[1]]));
    const proofA = sorted[0] === leafA ? [sorted[1]] : [sorted[0]];
    const proofB = sorted[0] === leafB ? [sorted[1]] : [sorted[0]];
    return { root, proofA, proofB };
  }

  function evidenceHash(label) {
    return ethers.keccak256(ethers.toUtf8Bytes(label));
  }

  function errorText(err) {
    return [
      err?.message,
      err?.shortMessage,
      err?.errorName,
      err?.error?.message,
      err?.data?.message,
    ]
      .filter(Boolean)
      .join(" | ");
  }

  async function expectRevert(promise, expectedSnippet) {
    let reverted = false;
    try {
      await promise;
    } catch (err) {
      reverted = true;
      const text = errorText(err);
      expect(text).to.contain(expectedSnippet);
    }

    if (!reverted) {
      expect.fail(`Expected revert containing '${expectedSnippet}'`);
    }
  }

  async function increaseTime(seconds) {
    await ethers.provider.send("evm_increaseTime", [Number(seconds)]);
    await ethers.provider.send("evm_mine", []);
  }

  async function disputeTimeout() {
    return Number(await treasury.DISPUTE_TIMEOUT());
  }

  async function seedDeposit(amount = toWei("1000")) {
    await token.connect(depositor).approve(await treasury.getAddress(), amount);
    await treasury.connect(depositor).depositRebate(amount, "Q1 2026 seed");
  }

  async function publishSingleLeafRoot(grossAmount, eligibleCap) {
    const leaf = merkleLeaf(pharmacy.address, grossAmount, eligibleCap);
    await treasury.connect(council).proposeRoot(leaf, grossAmount);
    await treasury.connect(council2).confirmRoot(0);
    return { root: leaf, proof: [] };
  }

  beforeEach(async function () {
    [
      ,
      council,
      council2,
      guardian,
      patientFund,
      pharmacy,
      depositor,
      attacker,
      environmentalFund,
    ] = await ethers.getSigners();

    const MockERC20 = await ethers.getContractFactory("MockERC20");
    token = await MockERC20.deploy("Mock DAI", "mDAI", 18);
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
      toWei("1000"),
      toWei("1"),
      council.address,
      council2.address,
      await timelock.getAddress(),
      guardian.address
    );
    await treasury.waitForDeployment();

    await token.mint(depositor.address, toWei("5000"));
  });

  it("retracts a current-epoch normal dispute and restores caps, escrow, and claim eligibility", async function () {
    await seedDeposit();
    const gross = toWei("100");
    const { proof } = await publishSingleLeafRoot(gross, gross);

    await treasury.connect(pharmacy).flagClaim(0, gross, gross, proof, evidenceHash("normal-current-timeout"));
    expect(await treasury.disputeFlaggedTimestamp(0, pharmacy.address)).to.be.gt(0n);
    expect(await treasury.epochVolume()).to.equal(gross);
    expect(await treasury.epochClaimedTotal(0)).to.equal(gross);
    expect(await treasury.epochRootClaimedTotal(0)).to.equal(gross);
    expect(await treasury.pharmacyClaimedThisEpoch(0, pharmacy.address)).to.equal(gross);
    expect(await treasury.epochEscrow(0)).to.equal(0n);
    expect(await treasury.totalEscrowed()).to.equal(0n);
    expect(await treasury.totalFlaggedNormal()).to.equal(gross);

    await expectRevert(
      treasury.connect(attacker).retractClaimDispute(0),
      "NoFlaggedClaim"
    );
    await expectRevert(
      treasury.connect(pharmacy).retractClaimDispute(0),
      "DisputeTimeoutNotElapsed"
    );

    await increaseTime(await disputeTimeout());

    await treasury.connect(pharmacy).retractClaimDispute(0);

    expect(await treasury.hasClaimed(0, pharmacy.address)).to.equal(false);
    expect(await treasury.flaggedAmount(0, pharmacy.address)).to.equal(0n);
    expect(await treasury.disputeFlaggedTimestamp(0, pharmacy.address)).to.equal(0n);
    expect(await treasury.epochVolume()).to.equal(0n);
    expect(await treasury.epochClaimedTotal(0)).to.equal(0n);
    expect(await treasury.epochRootClaimedTotal(0)).to.equal(0n);
    expect(await treasury.pharmacyClaimedThisEpoch(0, pharmacy.address)).to.equal(0n);
    expect(await treasury.epochEscrow(0)).to.equal(gross);
    expect(await treasury.totalEscrowed()).to.equal(gross);
    expect(await treasury.totalFlaggedNormal()).to.equal(0n);

    await treasury.connect(pharmacy).claim(gross, gross, proof);
    expect(await treasury.hasClaimed(0, pharmacy.address)).to.equal(true);
  });

  it("retracts a finalized unrecalled normal dispute without touching the new epoch volume", async function () {
    await seedDeposit();
    const gross = toWei("100");
    const { proof } = await publishSingleLeafRoot(gross, gross);

    await treasury.connect(pharmacy).flagClaim(0, gross, gross, proof, evidenceHash("normal-finalized-timeout"));
    await increaseTime(MIN_EPOCH_DURATION);
    await treasury.connect(council).finalizeEpoch();

    expect(await treasury.currentEpoch()).to.equal(1n);
    expect(await treasury.epochVolume()).to.equal(0n);
    expect(await treasury.epochEscrow(0)).to.equal(0n);
    expect(await treasury.totalEscrowed()).to.equal(0n);

    await increaseTime(await disputeTimeout());
    await treasury.connect(pharmacy).retractClaimDispute(0);

    expect(await treasury.currentEpoch()).to.equal(1n);
    expect(await treasury.epochVolume()).to.equal(0n);
    expect(await treasury.hasClaimed(0, pharmacy.address)).to.equal(false);
    expect(await treasury.flaggedAmount(0, pharmacy.address)).to.equal(0n);
    expect(await treasury.epochClaimedTotal(0)).to.equal(0n);
    expect(await treasury.epochRootClaimedTotal(0)).to.equal(0n);
    expect(await treasury.pharmacyClaimedThisEpoch(0, pharmacy.address)).to.equal(0n);
    expect(await treasury.epochEscrow(0)).to.equal(gross);
    expect(await treasury.totalEscrowed()).to.equal(gross);
    expect(await treasury.totalFlaggedNormal()).to.equal(0n);
  });

  it("routes a retracted recalled-epoch normal dispute to the patient fund", async function () {
    await seedDeposit();
    const amtA = toWei("80");
    const amtB = toWei("20");
    const { root, proofA } = makeTwoLeafTree(
      pharmacy.address, amtA, amtA,
      council2.address, amtB, amtB
    );

    await treasury.connect(council).proposeRoot(root, toWei("100"));
    await treasury.connect(council2).confirmRoot(0);
    await treasury.connect(pharmacy).flagClaim(0, amtA, amtA, proofA, evidenceHash("normal-recalled-timeout"));

    expect(await treasury.epochEscrow(0)).to.equal(amtB);
    expect(await treasury.totalEscrowed()).to.equal(amtB);
    expect(await treasury.totalFlaggedNormal()).to.equal(amtA);
    const distributionPoolAfterFlag = await treasury.distributionPool();

    await increaseTime(MIN_EPOCH_DURATION);
    await treasury.connect(council).finalizeEpoch();
    await increaseTime(RECALL_DELAY);

    const patientBeforeRecall = await token.balanceOf(patientFund.address);
    await treasury.connect(council).recallUnclaimed(0);
    expect(await token.balanceOf(patientFund.address) - patientBeforeRecall).to.equal(amtB);
    expect(await treasury.epochRecalled(0)).to.equal(true);
    expect(await treasury.epochEscrow(0)).to.equal(0n);
    expect(await treasury.totalEscrowed()).to.equal(0n);
    expect(await treasury.distributionPool()).to.equal(distributionPoolAfterFlag);

    const patientBeforeRetract = await token.balanceOf(patientFund.address);
    await treasury.connect(pharmacy).retractClaimDispute(0);

    expect(await token.balanceOf(patientFund.address) - patientBeforeRetract).to.equal(amtA);
    expect(await treasury.hasClaimed(0, pharmacy.address)).to.equal(false);
    expect(await treasury.flaggedAmount(0, pharmacy.address)).to.equal(0n);
    expect(await treasury.disputeFlaggedTimestamp(0, pharmacy.address)).to.equal(0n);
    expect(await treasury.epochEscrow(0)).to.equal(0n);
    expect(await treasury.totalEscrowed()).to.equal(0n);
    expect(await treasury.epochClaimedTotal(0)).to.equal(0n);
    expect(await treasury.epochRootClaimedTotal(0)).to.equal(0n);
    expect(await treasury.pharmacyClaimedThisEpoch(0, pharmacy.address)).to.equal(0n);
    expect(await treasury.totalFlaggedNormal()).to.equal(0n);
    expect(await treasury.distributionPool()).to.equal(distributionPoolAfterFlag);
  });

  it("retracts an approved exclusion dispute without moving tokens", async function () {
    await seedDeposit();
    const gross = toWei("100");
    await publishSingleLeafRoot(gross, gross);
    const omissionAmount = toWei("50");

    await treasury.connect(pharmacy).flagExclusion(0, omissionAmount, evidenceHash("exclusion-timeout"));
    await treasury.connect(council2).approveExclusionClaim(0, pharmacy.address);

    expect(await treasury.disputeFlaggedTimestamp(0, pharmacy.address)).to.be.gt(0n);
    expect(await treasury.hasClaimed(0, pharmacy.address)).to.equal(true);
    expect(await treasury.flaggedAmount(0, pharmacy.address)).to.equal(omissionAmount);
    expect(await treasury.isExclusionDispute(0, pharmacy.address)).to.equal(true);
    expect(await treasury.exclusionApproved(0, pharmacy.address)).to.equal(true);
    expect(await treasury.totalFlaggedExclusion()).to.equal(omissionAmount);

    const contractBefore = await token.balanceOf(await treasury.getAddress());
    const patientBefore = await token.balanceOf(patientFund.address);

    await increaseTime(await disputeTimeout());
    await treasury.connect(pharmacy).retractClaimDispute(0);

    expect(await token.balanceOf(await treasury.getAddress())).to.equal(contractBefore);
    expect(await token.balanceOf(patientFund.address)).to.equal(patientBefore);
    expect(await treasury.hasClaimed(0, pharmacy.address)).to.equal(false);
    expect(await treasury.flaggedAmount(0, pharmacy.address)).to.equal(0n);
    expect(await treasury.disputeFlaggedTimestamp(0, pharmacy.address)).to.equal(0n);
    expect(await treasury.isExclusionDispute(0, pharmacy.address)).to.equal(false);
    expect(await treasury.exclusionApproved(0, pharmacy.address)).to.equal(false);
    expect(await treasury.totalFlaggedExclusion()).to.equal(0n);
  });

  it("blocks dispute retraction while paused and permits it after council unpauses", async function () {
    await seedDeposit();
    const gross = toWei("100");
    const { proof } = await publishSingleLeafRoot(gross, gross);

    await treasury.connect(pharmacy).flagClaim(0, gross, gross, proof, evidenceHash("normal-paused-timeout"));
    await increaseTime(await disputeTimeout());

    await treasury.connect(guardian).pause();
    await expectRevert(
      treasury.connect(pharmacy).retractClaimDispute(0),
      "Pausable: paused"
    );

    await treasury.connect(council).unpause();
    await treasury.connect(pharmacy).retractClaimDispute(0);

    expect(await treasury.hasClaimed(0, pharmacy.address)).to.equal(false);
    expect(await treasury.flaggedAmount(0, pharmacy.address)).to.equal(0n);
    expect(await treasury.epochEscrow(0)).to.equal(gross);
    expect(await treasury.totalFlaggedNormal()).to.equal(0n);
  });

  it("clears dispute timestamps when council resolves before the timeout", async function () {
    await seedDeposit();
    const gross = toWei("100");
    const { proof } = await publishSingleLeafRoot(gross, gross);

    await treasury.connect(pharmacy).flagClaim(0, gross, gross, proof, evidenceHash("normal-council-resolution"));
    expect(await treasury.disputeFlaggedTimestamp(0, pharmacy.address)).to.be.gt(0n);

    await treasury.connect(council).resolveClaim(0, pharmacy.address, 2, evidenceHash("dismiss-before-timeout"));

    expect(await treasury.flaggedAmount(0, pharmacy.address)).to.equal(0n);
    expect(await treasury.disputeFlaggedTimestamp(0, pharmacy.address)).to.equal(0n);
    await expectRevert(
      treasury.connect(pharmacy).retractClaimDispute(0),
      "NoFlaggedClaim"
    );
  });
});
