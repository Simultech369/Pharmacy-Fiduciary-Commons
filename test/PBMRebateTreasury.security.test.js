const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("PBMRebateTreasury security baseline", function () {
  const toWei = (value) => ethers.parseEther(value);

  let token;
  let treasury;
  let timelock;
  let timelockDelay;
  let council;
  let council2;
  let guardian;
  let patientFund;
  let pharmacy;
  let depositor;
  let attacker;
  let environmentalFund;
  let timelockSaltNonce;

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
    return { root, leafA, leafB, proofA, proofB };
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

  function nextTimelockSalt() {
    timelockSaltNonce += 1n;
    return ethers.keccak256(ethers.solidityPacked(["uint256"], [timelockSaltNonce]));
  }

  async function timelockExecute(target, data, value = 0n) {
    const predecessor = ethers.ZeroHash;
    const salt = nextTimelockSalt();

    await timelock
      .connect(council)
      .schedule(target, value, data, predecessor, salt, timelockDelay);

    if (timelockDelay > 0n) {
      await ethers.provider.send("evm_increaseTime", [Number(timelockDelay)]);
      await ethers.provider.send("evm_mine", []);
    }

    return timelock.connect(council).execute(target, value, data, predecessor, salt);
  }

  async function seedDeposit(amount = toWei("1000")) {
    await token.connect(depositor).approve(await treasury.getAddress(), amount);
    await treasury.connect(depositor).depositRebate(amount, "Q1 2026 seed");
  }

  async function publishSingleLeafRoot(grossAmount, eligibleCap) {
    const leaf = merkleLeaf(pharmacy.address, grossAmount, eligibleCap);
    await treasury.connect(council).proposeRoot(leaf, grossAmount);
    return leaf;
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

    timelockDelay = 1n;
    timelockSaltNonce = 0n;

    const Timelock = await ethers.getContractFactory("TimelockController");
    timelock = await Timelock.deploy(
      timelockDelay,
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

  it("rejects constructor setup when guardian equals council", async function () {
    const Treasury = await ethers.getContractFactory("PBMRebateTreasury");
    await expectRevert(
      Treasury.deploy(
        await token.getAddress(),
        patientFund.address,
        environmentalFund.address,
        toWei("1000"),
        toWei("1"),
        council.address,
        council2.address,
        await timelock.getAddress(),
        council.address
      ),
      "GuardianMustDifferFromCouncil"
    );
  });

  it("rejects constructor setup when root confirmer equals council", async function () {
    const Treasury = await ethers.getContractFactory("PBMRebateTreasury");
    await expectRevert(
      Treasury.deploy(
        await token.getAddress(),
        patientFund.address,
        environmentalFund.address,
        toWei("1000"),
        toWei("1"),
        council.address,
        council.address,
        await timelock.getAddress(),
        guardian.address
      ),
      "RootConfirmerMustDifferFromCouncil"
    );
  });

  it("rejects a minimum epoch volume above the initial daily cap", async function () {
    const Treasury = await ethers.getContractFactory("PBMRebateTreasury");
    await expectRevert(
      Treasury.deploy(
        await token.getAddress(),
        patientFund.address,
        environmentalFund.address,
        toWei("1000"),
        toWei("1001"),
        council.address,
        council2.address,
        await timelock.getAddress(),
        guardian.address
      ),
      "MinimumEpochVolumeExceedsDailyCap"
    );
  });

  it("finalizes realistic epochs for a six-decimal payout token", async function () {
    const usdcUnits = (value) => ethers.parseUnits(value, 6);
    const MockUSDC = await ethers.getContractFactory("MockERC20");
    const usdc = await MockUSDC.deploy("Mock USDC", "mUSDC", 6);
    await usdc.waitForDeployment();

    const Treasury = await ethers.getContractFactory("PBMRebateTreasury");
    const usdcTreasury = await Treasury.deploy(
      await usdc.getAddress(),
      patientFund.address,
      environmentalFund.address,
      usdcUnits("1000"),
      usdcUnits("1"),
      council.address,
      council2.address,
      await timelock.getAddress(),
      guardian.address
    );
    await usdcTreasury.waitForDeployment();

    await usdc.mint(depositor.address, usdcUnits("100"));
    await usdc.connect(depositor).approve(await usdcTreasury.getAddress(), usdcUnits("100"));
    await usdcTreasury.connect(depositor).depositRebate(usdcUnits("100"), "USDC epoch");

    const gross = usdcUnits("1");
    const leaf = merkleLeaf(pharmacy.address, gross, gross);
    await usdcTreasury.connect(council).proposeRoot(leaf, gross);
    await usdcTreasury.connect(council2).confirmRoot(0);
    await usdcTreasury.connect(pharmacy).claim(gross, gross, []);

    await ethers.provider.send("evm_increaseTime", [24 * 60 * 60]);
    await ethers.provider.send("evm_mine", []);
    await usdcTreasury.connect(council).finalizeEpoch();

    expect(await usdcTreasury.currentEpoch()).to.equal(1n);
    expect(await usdcTreasury.minimumEpochVolume()).to.equal(usdcUnits("1"));
  });

  it("allows stale below-minimum epochs to close for unclaimed recall after the recall delay", async function () {
    await seedDeposit(toWei("1000"));

    const gross = toWei("0.5");
    await publishSingleLeafRoot(gross, gross);
    await treasury.connect(council2).confirmRoot(0);

    await ethers.provider.send("evm_increaseTime", [24 * 60 * 60 + 1]);
    await ethers.provider.send("evm_mine", []);

    await expectRevert(
      treasury.connect(council).finalizeEpoch(),
      "EpochVolumeTooLow"
    );

    await expectRevert(
      treasury.connect(council).finalizeStaleEpochForRecall(),
      "RecallDelayNotElapsed"
    );

    await ethers.provider.send("evm_increaseTime", [29 * 24 * 60 * 60 + 1]);
    await ethers.provider.send("evm_mine", []);

    await treasury.connect(council).finalizeStaleEpochForRecall();
    expect(await treasury.currentEpoch()).to.equal(1n);

    const patientBefore = await token.balanceOf(patientFund.address);
    await treasury.connect(council).recallUnclaimed(0);
    const patientAfter = await token.balanceOf(patientFund.address);

    expect(patientAfter - patientBefore).to.equal(gross);
    expect(await treasury.epochRecalled(0)).to.equal(true);
    expect(await treasury.epochEscrow(0)).to.equal(0n);
  });

  it("splits deposits 99 percent distribution and 1 percent governance", async function () {
    await seedDeposit(toWei("1000"));

    expect(await treasury.distributionPool()).to.equal(toWei("990"));
    expect(await treasury.governanceReserve()).to.equal(toWei("10"));
    expect(await treasury.totalRebateDeposited()).to.equal(toWei("1000"));
  });

  it("recovers stale unallocated distribution liquidity only through timelock after long inactivity", async function () {
    await seedDeposit(toWei("1000"));

    await expectRevert(
      timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [patientFund.address, toWei("100")])
      ),
      "underlying transaction reverted"
    );

    await ethers.provider.send("evm_increaseTime", [180 * 24 * 60 * 60 + 1]);
    await ethers.provider.send("evm_mine", []);

    // Assert recovery fails if recipient is not patientFund
    await expectRevert(
      timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [attacker.address, toWei("100")])
      ),
      "underlying transaction reverted"
    );

    const patientBefore = await token.balanceOf(patientFund.address);
    await timelockExecute(
      await treasury.getAddress(),
      treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [patientFund.address, toWei("100")])
    );

    expect(await treasury.distributionPool()).to.equal(toWei("890"));
    expect((await token.balanceOf(patientFund.address)) - patientBefore).to.equal(toWei("100"));
  });

  it("blocks stale distribution recovery when an active pending root exists", async function () {
    await seedDeposit(toWei("1000"));

    // Fast forward 180 days (recovery delay elapsed)
    await ethers.provider.send("evm_increaseTime", [180 * 24 * 60 * 60 + 1]);
    await ethers.provider.send("evm_mine", []);

    // Propose a root (proposedAt is block.timestamp, active for 3 days)
    const gross = toWei("100");
    await publishSingleLeafRoot(gross, gross);

    // Recovery should revert because the pending root is active
    await expectRevert(
      timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [patientFund.address, toWei("100")])
      ),
      "underlying transaction reverted"
    );

    // Fast forward 3 more days + 1 second (pending root expires)
    await ethers.provider.send("evm_increaseTime", [3 * 24 * 60 * 60 + 1]);
    await ethers.provider.send("evm_mine", []);

    // Recovery should now succeed because the pending root is expired
    await timelockExecute(
      await treasury.getAddress(),
      treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [patientFund.address, toWei("100")])
    );

    expect(await treasury.distributionPool()).to.equal(toWei("890"));
  });

  it("blocks stale distribution recovery after a root is confirmed", async function () {
    await seedDeposit(toWei("1000"));
    const gross = toWei("100");
    await publishSingleLeafRoot(gross, gross);
    await treasury.connect(council2).confirmRoot(0);

    await ethers.provider.send("evm_increaseTime", [180 * 24 * 60 * 60 + 1]);
    await ethers.provider.send("evm_mine", []);

    await expectRevert(
      timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [patientFund.address, toWei("100")])
      ),
      "underlying transaction reverted"
    );
  });

  it("requires root approval from the separately configured confirmer", async function () {
    await seedDeposit(toWei("1000"));

    const gross = toWei("100");
    await publishSingleLeafRoot(gross, gross);

    await expectRevert(
      treasury.connect(council).confirmRoot(0),
      "AccessControl"
    );

    await treasury.connect(council2).confirmRoot(0);

    expect(await treasury.epochRootTotal(0)).to.equal(gross);
    expect(await treasury.epochMerkleRoot(0)).to.not.equal(ethers.ZeroHash);
  });

  it("prevents council from granting itself root confirmation authority", async function () {
    const rootConfirmerRole = await treasury.rootConfirmerRole();

    await expectRevert(
      treasury.connect(council).grantRole(rootConfirmerRole, council.address),
      "AccessControl"
    );

    await expectRevert(
      treasury.connect(council2).grantRole(rootConfirmerRole, council.address),
      "AccessControl"
    );
  });

  it("preserves council/confirmer separation during timelocked role rotation", async function () {
    const councilRole = await treasury.councilRole();
    const rootConfirmerRole = await treasury.rootConfirmerRole();
    const executorRole = await treasury.executorRole();

    await expectRevert(
      treasury.connect(council).grantRole(councilRole, council2.address),
      "GovernanceRoleSeparationViolation"
    );
    await expectRevert(
      treasury.connect(council).grantRole(executorRole, council.address),
      "AccessControl"
    );
    await expectRevert(
      timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("grantRole", [rootConfirmerRole, council.address])
      ),
      "underlying transaction reverted"
    );

    await timelockExecute(
      await treasury.getAddress(),
      treasury.interface.encodeFunctionData("grantRole", [rootConfirmerRole, attacker.address])
    );
    await timelockExecute(
      await treasury.getAddress(),
      treasury.interface.encodeFunctionData("revokeRole", [rootConfirmerRole, council2.address])
    );

    expect(await treasury.hasRole(rootConfirmerRole, attacker.address)).to.be.true;
    expect(await treasury.hasRole(rootConfirmerRole, council2.address)).to.be.false;

    await seedDeposit(toWei("1000"));
    const gross = toWei("100");
    await publishSingleLeafRoot(gross, gross);
    await treasury.connect(attacker).confirmRoot(0);
    expect(await treasury.epochRootTotal(0)).to.equal(gross);
  });

  it("routes claims 90/10 and blocks double claim", async function () {
    await seedDeposit(toWei("1000"));

    const gross = toWei("100");
    await publishSingleLeafRoot(gross, gross);
    await treasury.connect(council2).confirmRoot(0);

    const patientBefore = await token.balanceOf(patientFund.address);
    const pharmacyBefore = await token.balanceOf(pharmacy.address);

    await treasury.connect(pharmacy).claim(gross, gross, []);

    const patientAfter = await token.balanceOf(patientFund.address);
    const pharmacyAfter = await token.balanceOf(pharmacy.address);

    expect(patientAfter - patientBefore).to.equal(toWei("10"));
    expect(pharmacyAfter - pharmacyBefore).to.equal(toWei("90"));
    expect(await treasury.pharmacyEpochClaimed(0, pharmacy.address)).to.equal(gross);

    await expectRevert(
      treasury.connect(pharmacy).claim(gross, gross, []),
      "AlreadyClaimed"
    );
  });

  it("enforces guardian pause and council-only unpause", async function () {
    await expectRevert(treasury.connect(attacker).pause(), "AccessControl");

    await treasury.connect(guardian).pause();

    await token.connect(depositor).approve(await treasury.getAddress(), toWei("1"));
    await expectRevert(
      treasury.connect(depositor).depositRebate(toWei("1"), "pause-check"),
      "Pausable: paused"
    );

    await expectRevert(treasury.connect(guardian).unpause(), "AccessControl");

    await treasury.connect(council).unpause();
    await treasury.connect(depositor).depositRebate(toWei("1"), "post-unpause");
  });

  it("restricts cap governance to executor and enforces bounds", async function () {
    await expectRevert(
      treasury.connect(attacker).updateDailyCap(toWei("1")),
      "AccessControl"
    );

    const hardCap = await treasury.hardAbsoluteVolumeCap();
    await expectRevert(
      timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("updateDailyCap", [hardCap + 1n])
      ),
      "underlying transaction reverted"
    );

    const dailyCap = await treasury.dailyVolumeCap();
    await expectRevert(
      timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("updateDailyCap", [toWei("0.5")])
      ),
      "underlying transaction reverted"
    );

    await expectRevert(
      timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("reduceHardCap", [dailyCap - 1n])
      ),
      "underlying transaction reverted"
    );

    const newHardCap = dailyCap + toWei("1");
    await timelockExecute(
      await treasury.getAddress(),
      treasury.interface.encodeFunctionData("reduceHardCap", [newHardCap])
    );

    expect(await treasury.hardAbsoluteVolumeCap()).to.equal(newHardCap);
  });

  it("partitions distribution pool into epoch escrow at root confirmation", async function () {
    await seedDeposit(toWei("1000"));
    const gross = toWei("200");
    await publishSingleLeafRoot(gross, gross);
    
    const poolBefore = await treasury.distributionPool();
    await treasury.connect(council2).confirmRoot(0);
    const poolAfter = await treasury.distributionPool();
    const escrow = await treasury.epochEscrow(0);

    expect(poolBefore - poolAfter).to.equal(gross);
    expect(escrow).to.equal(gross);
  });

  it("handles flagExclusion and resolveClaim appropriately", async function () {
    await seedDeposit(toWei("1000"));
    const gross = toWei("100");
    await publishSingleLeafRoot(gross, gross);
    await treasury.connect(council2).confirmRoot(0);

    // 1. Flag exclusion (no pool/escrow change at flag time)
    const poolBefore = await treasury.distributionPool();
    await treasury.connect(attacker).flagExclusion(0, toWei("50"), evidenceHash("exclusion-attacker"));
    const poolAfter = await treasury.distributionPool();
    expect(poolBefore).to.equal(poolAfter);
    expect(await treasury.flaggedAmount(0, attacker.address)).to.equal(toWei("50"));
    expect(await treasury.isExclusionDispute(0, attacker.address)).to.be.true;

    // 2. Resolve claim as DISMISS (flag cleared, no transfers)
    await treasury.connect(council).resolveClaim(0, attacker.address, 2, evidenceHash("dismiss-attacker")); // DISMISS is enum val 2
    expect(await treasury.flaggedAmount(0, attacker.address)).to.equal(0n);
    expect(await treasury.isExclusionDispute(0, attacker.address)).to.be.false;

    // 3. Flag exclusion again; council cannot pay it without independent approval.
    await treasury.connect(depositor).flagExclusion(0, toWei("50"), evidenceHash("exclusion-depositor"));
    await expectRevert(
      treasury.connect(council).resolveClaim(0, depositor.address, 0, evidenceHash("release-without-approval")),
      "ExclusionApprovalRequired"
    );
    await expectRevert(
      treasury.connect(council).approveExclusionClaim(0, depositor.address),
      "AccessControl"
    );

    // 4. The configured confirmer approves, then council releases the bounded claim.
    await treasury.connect(council2).approveExclusionClaim(0, depositor.address);
    await token.connect(depositor).approve(await treasury.getAddress(), toWei("50"));
    await treasury.connect(depositor).fundExclusionRemediation(toWei("50"));
    const balanceBefore = await token.balanceOf(depositor.address);
    await treasury.connect(council).resolveClaim(0, depositor.address, 0, evidenceHash("release-depositor")); // RELEASE_TO_PHARMACY is 0
    const balanceAfter = await token.balanceOf(depositor.address);
    // Net transfer is 90% of 50 = 45 (using initial 10% patientClaimBP)
    expect(balanceAfter - balanceBefore).to.equal(toWei("45"));
    expect(await treasury.epochVolume()).to.equal(toWei("50"));
    expect(await treasury.epochClaimedTotal(0)).to.equal(toWei("50"));
    expect(await treasury.epochRootClaimedTotal(0)).to.equal(0n);
    expect(await treasury.epochExclusionPaidTotal(0)).to.equal(toWei("50"));
    expect(await treasury.unclaimedForEpoch(0)).to.equal(gross);
    expect(await treasury.epochEscrow(0)).to.equal(gross);

    const accounting = await treasury.epochAccounting(0);
    expect(accounting.rootAllocated).to.equal(gross);
    expect(accounting.rootClaimed).to.equal(0n);
    expect(accounting.exclusionPaid).to.equal(toWei("50"));
    expect(accounting.escrowUnclaimed).to.equal(gross);
    expect(accounting.totalClaimed).to.equal(toWei("50"));
    expect(await token.balanceOf(await treasury.getAddress())).to.equal(
      (await treasury.distributionPool()) +
      (await treasury.governanceReserve()) +
      (await treasury.epochEscrow(0))
    );
    expect(await treasury.exclusionApproved(0, depositor.address)).to.be.false;
  });

  it("keeps root unclaimed reporting independent from exclusion payouts", async function () {
    await seedDeposit(toWei("1000"));
    const gross = toWei("100");
    await publishSingleLeafRoot(gross, gross);
    await treasury.connect(council2).confirmRoot(0);

    await treasury.connect(attacker).flagExclusion(0, gross, evidenceHash("exclusion-unclaimed-reporting"));
    await treasury.connect(council2).approveExclusionClaim(0, attacker.address);
    await token.connect(depositor).approve(await treasury.getAddress(), gross);
    await treasury.connect(depositor).fundExclusionRemediation(gross);
    await treasury.connect(council).resolveClaim(0, attacker.address, 0, evidenceHash("release-unclaimed-reporting"));

    expect(await treasury.epochClaimedTotal(0)).to.equal(gross);
    expect(await treasury.epochRootClaimedTotal(0)).to.equal(0n);
    expect(await treasury.epochExclusionPaidTotal(0)).to.equal(gross);
    expect(await treasury.epochEscrow(0)).to.equal(gross);
    expect(await treasury.unclaimedForEpoch(0)).to.equal(gross);

    const stats = await treasury.epochStats(0);
    expect(stats.rootTotal).to.equal(gross);
    expect(stats.claimed).to.equal(0n);
    expect(stats.unclaimed).to.equal(gross);
  });

  it("rejects exclusion claims that exceed epoch caps or request a treasury-funded penalty", async function () {
    await seedDeposit(toWei("2000"));
    const gross = toWei("900");
    await publishSingleLeafRoot(gross, gross);
    await treasury.connect(council2).confirmRoot(0);
    await treasury.connect(pharmacy).claim(gross, gross, []);

    await treasury.connect(attacker).flagExclusion(0, toWei("200"), evidenceHash("exclusion-cap-check"));
    await treasury.connect(council2).approveExclusionClaim(0, attacker.address);
    await token.connect(depositor).approve(await treasury.getAddress(), toWei("200"));
    await treasury.connect(depositor).fundExclusionRemediation(toWei("200"));

    await expectRevert(
      treasury.connect(council).resolveClaim(0, attacker.address, 0, evidenceHash("release-cap-check")),
      "DailyCapExceeded"
    );
    await expectRevert(
      treasury.connect(council).resolveClaim(0, attacker.address, 1, evidenceHash("invalid-exclusion-resolution")),
      "InvalidExclusionResolution"
    );

    expect(await treasury.flaggedAmount(0, attacker.address)).to.equal(toWei("200"));
  });

  it("funds exclusion remediation explicitly without consuming future distribution liquidity", async function () {
    await seedDeposit(toWei("1000"));
    const gross = toWei("100");
    await publishSingleLeafRoot(gross, gross);
    await treasury.connect(council2).confirmRoot(0);

    await treasury.connect(attacker).flagExclusion(0, toWei("50"), evidenceHash("exclusion-reserve-check"));
    await treasury.connect(council2).approveExclusionClaim(0, attacker.address);
    const distributionBefore = await treasury.distributionPool();

    await expectRevert(
      treasury.connect(council).resolveClaim(0, attacker.address, 0, evidenceHash("release-no-reserve")),
      "InsufficientExclusionReserve"
    );

    await token.connect(depositor).approve(await treasury.getAddress(), toWei("50"));
    await treasury.connect(depositor).fundExclusionRemediation(toWei("50"));
    expect(await treasury.exclusionRemediationReserve()).to.equal(toWei("50"));

    await treasury.connect(council).resolveClaim(0, attacker.address, 0, evidenceHash("release-with-reserve"));

    expect(await treasury.exclusionRemediationReserve()).to.equal(0n);
    expect(await treasury.distributionPool()).to.equal(distributionBefore);
    expect(await treasury.epochEscrow(0)).to.equal(gross);
  });

  it("allows sanctioned address to submit an on-chain appeal", async function () {
    await treasury.connect(council).updateSanction(attacker.address, true, "spamming claims");
    expect(await treasury.sanctioned(attacker.address)).to.be.true;

    const appealEvidence = evidenceHash("appeal-sanction");
    const tx = await treasury.connect(attacker).appealSanction("i am a valid pharmacy", appealEvidence);
    const receipt = await tx.wait();
    const event = receipt.logs.find(x => x.fragment && x.fragment.name === "SanctionAppealed");
    expect(event).to.not.be.undefined;
    expect(event.args[0]).to.equal(attacker.address);
    expect(event.args[1]).to.equal("i am a valid pharmacy");
    expect(event.args[2]).to.equal(appealEvidence);
  });

  it("rejects zero evidence hashes for dispute flags, resolutions, and appeals", async function () {
    await seedDeposit(toWei("1000"));
    const gross = toWei("100");
    await publishSingleLeafRoot(gross, gross);
    await treasury.connect(council2).confirmRoot(0);

    await expectRevert(
      treasury.connect(pharmacy).flagClaim(0, gross, gross, [], ethers.ZeroHash),
      "ZeroEvidenceHash"
    );
    await expectRevert(
      treasury.connect(attacker).flagExclusion(0, toWei("50"), ethers.ZeroHash),
      "ZeroEvidenceHash"
    );

    await treasury.connect(pharmacy).flagClaim(0, gross, gross, [], evidenceHash("valid-flag-before-zero-resolution"));
    await expectRevert(
      treasury.connect(council).resolveClaim(0, pharmacy.address, 2, ethers.ZeroHash),
      "ZeroEvidenceHash"
    );

    await treasury.connect(council).updateSanction(attacker.address, true, "spamming claims");
    await expectRevert(
      treasury.connect(attacker).appealSanction("i am a valid pharmacy", ethers.ZeroHash),
      "ZeroEvidenceHash"
    );
  });

  it("enforces parameter setters and executor limits", async function () {
    // 1. BPs update by executor
    await timelockExecute(
      await treasury.getAddress(),
      treasury.interface.encodeFunctionData("updatePatientClaimBP", [1500n]) // 15%
    );
    expect(await treasury.patientClaimBP()).to.equal(1500n);

    // 2. Out of bounds check
    await expectRevert(
      timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("updatePatientClaimBP", [4000n])
      ),
      "underlying transaction reverted"
    );
  });

  it("resolves dismissed dispute by sending funds to patientFund if recall has already occurred", async function () {
    // 1. Setup deposits
    await seedDeposit(toWei("1000"));

    // 2. Deploy a 2-leaf Merkle root
    // Leaf 1: pharmacy (80)
    // Leaf 2: council2 (20)
    // Total Root Amount = 100
    const amtA = toWei("80");
    const amtB = toWei("20");
    const { root, proofA } = makeTwoLeafTree(
      pharmacy.address, amtA, amtA,
      council2.address, amtB, amtB
    );

    await treasury.connect(council).proposeRoot(root, toWei("100"));
    await treasury.connect(council2).confirmRoot(0);

    // Initial escrow should be 100
    expect(await treasury.epochEscrow(0)).to.equal(toWei("100"));

    // 3. Pharmacy flags a dispute of its 80 tokens allocation
    await treasury.connect(pharmacy).flagClaim(0, amtA, amtA, proofA, evidenceHash("normal-flag-recalled"));

    // Escrow should decrease by 80 to 20
    expect(await treasury.epochEscrow(0)).to.equal(toWei("20"));
    expect(await treasury.flaggedAmount(0, pharmacy.address)).to.equal(amtA);

    // 4. Finalize epoch 0
    const minDuration = 24 * 60 * 60; // 1 day
    await ethers.provider.send("evm_increaseTime", [minDuration]);
    await ethers.provider.send("evm_mine", []);

    await treasury.connect(council).finalizeEpoch();
    expect(await treasury.currentEpoch()).to.equal(1n);

    // 5. 30 days pass (RECALL_DELAY)
    const recallDelay = 30 * 24 * 60 * 60;
    await ethers.provider.send("evm_increaseTime", [recallDelay]);
    await ethers.provider.send("evm_mine", []);

    // 6. Council recalls unclaimed funds from epoch 0 (the remaining 20 tokens)
    const patientBefore = await token.balanceOf(patientFund.address);
    await treasury.connect(council).recallUnclaimed(0);
    const patientAfter = await token.balanceOf(patientFund.address);

    expect(patientAfter - patientBefore).to.equal(amtB); // 20 tokens recalled
    expect(await treasury.epochRecalled(0)).to.be.true;
    expect(await treasury.epochEscrow(0)).to.equal(0n);

    // 7. Council resolves the dispute as DISMISS
    // Instead of locking, it should directly transfer the 80 tokens to the patientFund.
    const patientBeforeDismiss = await token.balanceOf(patientFund.address);
    await treasury.connect(council).resolveClaim(0, pharmacy.address, 2, evidenceHash("dismiss-after-recall")); // 2 is DISMISS
    const patientAfterDismiss = await token.balanceOf(patientFund.address);

    // The patientFund should receive the 80 tokens directly
    expect(patientAfterDismiss - patientBeforeDismiss).to.equal(amtA);

    // Escrow should remain 0, the flag should clear, and every claim metric
    // should be reversed before the dismissed funds leave for patientFund.
    expect(await treasury.epochEscrow(0)).to.equal(0n);
    expect(await treasury.flaggedAmount(0, pharmacy.address)).to.equal(0n);
    expect(await treasury.epochClaimedTotal(0)).to.equal(0n);
    expect(await treasury.epochRootClaimedTotal(0)).to.equal(0n);
    expect(await treasury.pharmacyClaimedThisEpoch(0, pharmacy.address)).to.equal(0n);
  });

  it("frees volume caps and updates claimed totals when a dispute is dismissed in the active epoch", async function () {
    await seedDeposit(toWei("1000"));
    const gross = toWei("100");
    const leaf = await publishSingleLeafRoot(gross, gross);
    await treasury.connect(council2).confirmRoot(0);

    // Flag the claim
    await treasury.connect(pharmacy).flagClaim(0, gross, gross, [], evidenceHash("normal-active-dismiss"));

    // Caps and totals should be updated as if claimed
    expect(await treasury.epochVolume()).to.equal(gross);
    expect(await treasury.epochClaimedTotal(0)).to.equal(gross);

    // Dismiss the claim
    await treasury.connect(council).resolveClaim(0, pharmacy.address, 2, evidenceHash("dismiss-active")); // 2 is DISMISS

    // epochVolume and epochClaimedTotal should be reset to 0
    expect(await treasury.epochVolume()).to.equal(0n);
    expect(await treasury.epochClaimedTotal(0)).to.equal(0n);
    expect(await treasury.pharmacyClaimedThisEpoch(0, pharmacy.address)).to.equal(0n);
    expect(await treasury.epochEscrow(0)).to.equal(gross); // returned to escrow
    expect(await token.balanceOf(await treasury.getAddress())).to.equal(
      (await treasury.distributionPool()) +
      (await treasury.governanceReserve()) +
      (await treasury.epochEscrow(0))
    );
  });

  it("reports correct bucketBalances including exclusionRemediationReserve", async function () {
    const balancesBefore = await treasury.bucketBalances();
    expect(balancesBefore.distribution).to.equal(0n);
    expect(balancesBefore.governance).to.equal(0n);
    expect(balancesBefore.exclusion).to.equal(0n);
    expect(balancesBefore.totalDeposited).to.equal(0n);

    await seedDeposit(toWei("1000"));
    await token.connect(depositor).approve(await treasury.getAddress(), toWei("50"));
    await treasury.connect(depositor).fundExclusionRemediation(toWei("50"));

    const balancesAfter = await treasury.bucketBalances();
    expect(balancesAfter.distribution).to.equal(toWei("990"));
    expect(balancesAfter.governance).to.equal(toWei("10"));
    expect(balancesAfter.exclusion).to.equal(toWei("50"));
    expect(balancesAfter.totalDeposited).to.equal(toWei("1000"));
  });

  it("enforces the core accounting invariant under a complex multi-epoch lifecycle with claims, normal/exclusion disputes, and recalls", async function () {
    const signers = await ethers.getSigners();
    const pharmacyA = pharmacy;
    const pharmacyB = signers[9];
    const pharmacyC = attacker;

    const listPharmacies = [pharmacyA, pharmacyB, pharmacyC];

    async function checkInvariant(epochsList) {
      const contractBalance = await token.balanceOf(await treasury.getAddress());
      const distPool = await treasury.distributionPool();
      const govRes = await treasury.governanceReserve();
      const exclRes = await treasury.exclusionRemediationReserve();

      let totalEscrow = 0n;
      let totalFlaggedNorm = 0n;
      let totalFlaggedExcl = 0n;

      for (const ep of epochsList) {
        totalEscrow += await treasury.epochEscrow(ep);
        for (const pharm of listPharmacies) {
          const flagged = await treasury.flaggedAmount(ep, pharm.address);
          const isExcl = await treasury.isExclusionDispute(ep, pharm.address);
          if (flagged > 0n) {
            if (isExcl) {
              totalFlaggedExcl += flagged;
            } else {
              totalFlaggedNorm += flagged;
            }
          }
        }
      }

      const expectedBalance = distPool + govRes + exclRes + totalEscrow + totalFlaggedNorm;
      expect(contractBalance).to.equal(expectedBalance);

      // Verify global aggregate variables match
      expect(await treasury.totalEscrowed()).to.equal(totalEscrow);
      expect(await treasury.totalFlaggedNormal()).to.equal(totalFlaggedNorm);
      expect(await treasury.totalFlaggedExclusion()).to.equal(totalFlaggedExcl);
    }

    // 1. Initial State Check
    await checkInvariant([0n]);

    // 2. Deposit Rebate
    await seedDeposit(toWei("1000"));
    await checkInvariant([0n]);

    // 3. Setup Merkle root with two leaves: pharmacyA (100) and pharmacyB (50)
    const leafA = merkleLeaf(pharmacyA.address, toWei("100"), toWei("100"));
    const leafB = merkleLeaf(pharmacyB.address, toWei("50"), toWei("50"));
    const sorted = [leafA, leafB].sort();
    const root = ethers.keccak256(ethers.solidityPacked(["bytes32", "bytes32"], [sorted[0], sorted[1]]));
    const proofA = sorted[0] === leafA ? [sorted[1]] : [sorted[0]];
    const proofB = sorted[0] === leafB ? [sorted[1]] : [sorted[0]];

    await treasury.connect(council).proposeRoot(root, toWei("150"));
    await treasury.connect(council2).confirmRoot(0n);
    await checkInvariant([0n]);

    // 4. Pharmacy A claims 100
    await treasury.connect(pharmacyA).claim(toWei("100"), toWei("100"), proofA);
    await checkInvariant([0n]);

    // 5. Pharmacy B flags a normal claim dispute for 50
    await treasury.connect(pharmacyB).flagClaim(0n, toWei("50"), toWei("50"), proofB, evidenceHash("normal-b"));
    await checkInvariant([0n]);

    // 6. Pharmacy C flags an exclusion dispute for 80
    await treasury.connect(pharmacyC).flagExclusion(0n, toWei("80"), evidenceHash("exclusion-c"));
    await checkInvariant([0n]);

    // 7. Fund Exclusion Remediation Reserve
    await token.connect(depositor).approve(await treasury.getAddress(), toWei("100"));
    await treasury.connect(depositor).fundExclusionRemediation(toWei("100"));
    await checkInvariant([0n]);

    // 8. Confirmer approves Pharmacy C's exclusion, and Council resolves it as RELEASE
    await treasury.connect(council2).approveExclusionClaim(0n, pharmacyC.address);
    const txExcl = await treasury.connect(council).resolveClaim(0n, pharmacyC.address, 0, evidenceHash("release-c")); // 0 is RELEASE
    const receiptExcl = await txExcl.wait();
    const eventExcl = receiptExcl.logs.find(x => x.fragment && x.fragment.name === "ClaimResolved");
    expect(eventExcl).to.not.be.undefined;
    expect(eventExcl.args[4]).to.be.true; // isExclusion parameter is true
    await checkInvariant([0n]);

    // 9. Finalize Epoch 0 and move to Epoch 1
    await ethers.provider.send("evm_increaseTime", [24 * 60 * 60]);
    await ethers.provider.send("evm_mine", []);
    await treasury.connect(council).finalizeEpoch();
    await checkInvariant([0n, 1n]);

    // 10. Deposit in Epoch 1
    await seedDeposit(toWei("500"));
    await checkInvariant([0n, 1n]);

    // 11. 30 days pass (RECALL_DELAY) to recall Epoch 0
    await ethers.provider.send("evm_increaseTime", [30 * 24 * 60 * 60]);
    await ethers.provider.send("evm_mine", []);

    // Recall unclaimed from Epoch 0 (escrow is 0, but check invariant)
    // Wait, escrow was 150 - 100 (claim) - 50 (flagged) = 0. So nothing to recall.
    await expectRevert(
      treasury.connect(council).recallUnclaimed(0n),
      "NothingToRecall"
    );

    // Let's dismiss Pharmacy B's dispute (since it is flagged, it is held in flaggedAmount, and epoch 0 is finalized)
    // Let's set epochRecalled manually or recall it by having some positive escrow.
    // Wait, let's check: was epoch 0 recalled? No, because unclaimed escrow was 0.
    // Let's check the invariant before dismissal
    await checkInvariant([0n, 1n]);

    // Dismiss Pharmacy B's dispute. Since epochRecalled is false, it returns to escrow.
    const txNorm = await treasury.connect(council).resolveClaim(0n, pharmacyB.address, 2, evidenceHash("dismiss-b")); // 2 is DISMISS
    const receiptNorm = await txNorm.wait();
    const eventNorm = receiptNorm.logs.find(x => x.fragment && x.fragment.name === "ClaimResolved");
    expect(eventNorm).to.not.be.undefined;
    expect(eventNorm.args[4]).to.be.false; // isExclusion parameter is false
    await checkInvariant([0n, 1n]);

    // Now escrow has 50 tokens. Let's recall it!
    await treasury.connect(council).recallUnclaimed(0n);
    await checkInvariant([0n, 1n]);

    // 12. Withdraw some governance reserve
    await timelockExecute(
      await treasury.getAddress(),
      treasury.interface.encodeFunctionData("withdrawGovernanceReserve", [signers[6].address, toWei("5")])
    );
    await checkInvariant([0n, 1n]);
  });

  describe("Global accounting aggregates & scenario fuzzer", function () {
    it("correctly updates totalEscrowed, totalFlaggedNormal, and totalFlaggedExclusion through standard flows", async function () {
      // Initially all should be 0
      let acc = await treasury.globalAccounting();
      expect(acc.escrowed).to.equal(0n);
      expect(acc.flaggedNormal).to.equal(0n);
      expect(acc.flaggedExclusion).to.equal(0n);

      // Deposit and confirm root
      await seedDeposit(toWei("1000"));
      const amtA = toWei("100");
      const amtB = toWei("50");
      const { root, proofA, proofB } = makeTwoLeafTree(
        pharmacy.address, amtA, amtA,
        council2.address, amtB, amtB
      );

      await treasury.connect(council).proposeRoot(root, toWei("150"));
      await treasury.connect(council2).confirmRoot(0n);

      acc = await treasury.globalAccounting();
      expect(acc.escrowed).to.equal(toWei("150"));
      expect(acc.flaggedNormal).to.equal(0n);
      expect(acc.flaggedExclusion).to.equal(0n);

      // Claim A
      await treasury.connect(pharmacy).claim(amtA, amtA, proofA);
      acc = await treasury.globalAccounting();
      expect(acc.escrowed).to.equal(toWei("50"));
      expect(acc.flaggedNormal).to.equal(0n);
      expect(acc.flaggedExclusion).to.equal(0n);

      // Flag B (normal claim)
      await treasury.connect(council2).flagClaim(0n, amtB, amtB, proofB, evidenceHash("normal-global-b"));
      acc = await treasury.globalAccounting();
      expect(acc.escrowed).to.equal(0n);
      expect(acc.flaggedNormal).to.equal(amtB);
      expect(acc.flaggedExclusion).to.equal(0n);

      // Flag C (exclusion claim) - need to use another pharmacy
      const signers = await ethers.getSigners();
      const pharmacyC = signers[8];
      await treasury.connect(pharmacyC).flagExclusion(0n, toWei("80"), evidenceHash("exclusion-global-c"));
      acc = await treasury.globalAccounting();
      expect(acc.escrowed).to.equal(0n);
      expect(acc.flaggedNormal).to.equal(amtB);
      expect(acc.flaggedExclusion).to.equal(toWei("80"));

      // Resolve B as DISMISS (since epochRecalled is false, it returns to escrow)
      await treasury.connect(council).resolveClaim(0n, council2.address, 2, evidenceHash("dismiss-global-b")); // DISMISS
      acc = await treasury.globalAccounting();
      expect(acc.escrowed).to.equal(amtB);
      expect(acc.flaggedNormal).to.equal(0n);
      expect(acc.flaggedExclusion).to.equal(toWei("80"));

      // Resolve C as DISMISS (exclusion)
      await treasury.connect(council).resolveClaim(0n, pharmacyC.address, 2, evidenceHash("dismiss-global-c")); // DISMISS
      acc = await treasury.globalAccounting();
      expect(acc.escrowed).to.equal(amtB);
      expect(acc.flaggedNormal).to.equal(0n);
      expect(acc.flaggedExclusion).to.equal(0n);

      // Finalize epoch 0
      const minDuration = 24 * 60 * 60; // 1 day
      await ethers.provider.send("evm_increaseTime", [minDuration]);
      await ethers.provider.send("evm_mine", []);
      await treasury.connect(council).finalizeEpoch();

      // 30 days pass to recall
      const recallDelay = 30 * 24 * 60 * 60;
      await ethers.provider.send("evm_increaseTime", [recallDelay]);
      await ethers.provider.send("evm_mine", []);

      // Recall unclaimed
      await treasury.connect(council).recallUnclaimed(0n);
      acc = await treasury.globalAccounting();
      expect(acc.escrowed).to.equal(0n);
      expect(acc.flaggedNormal).to.equal(0n);
      expect(acc.flaggedExclusion).to.equal(0n);
    });

    it("runs 100+ randomized state transitions and asserts the core balance invariant and global accounting matching at every step", async function () {
      const signers = await ethers.getSigners();
      // Use signers 12 to 20 for fuzzed pharmacies to prevent collisions
      const pharmacies = signers.slice(12, 20);

      // Pre-fund the pharmacies
      for (const p of pharmacies) {
        await token.mint(p.address, toWei("1000"));
      }

      // Mint plenty of tokens to depositor for the fuzzed deposits
      await token.mint(depositor.address, toWei("10000000"));

      // We will track the expected values off-chain to compare with the contract's public state variables
      let expectedEscrowed = 0n;
      let expectedFlaggedNormal = 0n;
      let expectedFlaggedExclusion = 0n;

      // Ensure we have some base deposits
      await seedDeposit(toWei("50000"));

      let activeEpoch = 0n;
      let epochRootAmount = 0n;

      // Track active disputes: epoch -> pharmacyAddress -> { amount, isExclusion, approved }
      const activeDisputes = {};

      // Helper to generate Merkle proofs for active pharmacies in activeEpoch
      const allocation = toWei("100");
      const leaves = pharmacies.map(p => merkleLeaf(p.address, allocation, allocation));

      function buildTree(leavesArray) {
        let level = [...leavesArray];
        const tree = [level];
        while (level.length > 1) {
          const nextLevel = [];
          for (let i = 0; i < level.length; i += 2) {
            if (i + 1 < level.length) {
              const sorted = [level[i], level[i+1]].sort();
              nextLevel.push(ethers.keccak256(ethers.solidityPacked(["bytes32", "bytes32"], [sorted[0], sorted[1]])));
            } else {
              nextLevel.push(level[i]);
            }
          }
          level = nextLevel;
          tree.push(level);
        }
        return tree;
      }

      function getProof(tree, index) {
        const proof = [];
        let idx = index;
        for (let i = 0; i < tree.length - 1; i++) {
          const level = tree[i];
          const isRight = idx % 2 === 1;
          const sibIdx = isRight ? idx - 1 : idx + 1;
          if (sibIdx < level.length) {
            proof.push(level[sibIdx]);
          }
          idx = Math.floor(idx / 2);
        }
        return proof;
      }

      const tree = buildTree(leaves);
      const root = tree[tree.length - 1][0];
      const proofs = pharmacies.map((_, i) => getProof(tree, i));

      // We will perform 105 randomized actions
      const actionsCount = 105;
      for (let step = 0; step < actionsCount; step++) {
        const possibleActions = [];
        
        const hasRoot = (await treasury.epochMerkleRoot(activeEpoch)) !== ethers.ZeroHash;
        const pending = await treasury.getPendingRoot(activeEpoch);
        const hasPending = pending.proposedAt !== 0n;

        if (!hasRoot && !hasPending) {
          possibleActions.push("PROPOSE_ROOT");
        } else if (!hasRoot && hasPending) {
          possibleActions.push("CONFIRM_ROOT");
        }

        if (hasRoot) {
          possibleActions.push("CLAIM");
          possibleActions.push("FLAG_CLAIM");
          possibleActions.push("FLAG_EXCLUSION");
        }

        let hasUnapprovedExclusion = false;
        let hasAnyDispute = false;

        const epDisputes = activeDisputes[Number(activeEpoch)] || {};
        for (const pAddr of Object.keys(epDisputes)) {
          const disp = epDisputes[pAddr];
          if (disp && disp.amount > 0) {
            hasAnyDispute = true;
            if (disp.isExclusion && !disp.approved) {
              hasUnapprovedExclusion = true;
            }
          }
        }

        if (hasUnapprovedExclusion) {
          possibleActions.push("APPROVE_EXCLUSION");
        }
        if (hasAnyDispute) {
          possibleActions.push("RESOLVE_DISPUTE");
        }

        if (hasRoot && !hasPending) {
          possibleActions.push("FINALIZE_EPOCH");
        }

        let canRecallAny = false;
        for (let ep = 0n; ep < activeEpoch; ep++) {
          const recalled = await treasury.epochRecalled(ep);
          const escrow = await treasury.epochEscrow(ep);
          if (!recalled && escrow > 0n) {
            canRecallAny = true;
            break;
          }
        }
        if (canRecallAny && !hasPending) {
          possibleActions.push("RECALL_UNCLAIMED");
        }

        if (possibleActions.length === 0) {
          possibleActions.push("DEPOSIT");
        }

        const action = possibleActions[Math.floor(Math.random() * possibleActions.length)];

        switch (action) {
          case "PROPOSE_ROOT": {
            epochRootAmount = allocation * BigInt(pharmacies.length);
            await treasury.connect(council).proposeRoot(root, epochRootAmount);
            break;
          }
          case "CONFIRM_ROOT": {
            await treasury.connect(council2).confirmRoot(activeEpoch);
            expectedEscrowed += epochRootAmount;
            break;
          }
          case "CLAIM": {
            const pIdx = Math.floor(Math.random() * pharmacies.length);
            const pharm = pharmacies[pIdx];
            const hasCl = await treasury.hasClaimed(activeEpoch, pharm.address);
            const flAmount = await treasury.flaggedAmount(activeEpoch, pharm.address);
            if (!hasCl && flAmount === 0n) {
              const dailyCap = await treasury.dailyVolumeCap();
              const epochVol = await treasury.epochVolume();
              if (epochVol + allocation <= dailyCap) {
                await treasury.connect(pharm).claim(allocation, allocation, proofs[pIdx]);
                expectedEscrowed -= allocation;
              }
            }
            break;
          }
          case "FLAG_CLAIM": {
            const pIdx = Math.floor(Math.random() * pharmacies.length);
            const pharm = pharmacies[pIdx];
            const hasCl = await treasury.hasClaimed(activeEpoch, pharm.address);
            const flAmount = await treasury.flaggedAmount(activeEpoch, pharm.address);
            if (!hasCl && flAmount === 0n) {
              const dailyCap = await treasury.dailyVolumeCap();
              const epochVol = await treasury.epochVolume();
              if (epochVol + allocation <= dailyCap) {
                await treasury.connect(pharm).flagClaim(activeEpoch, allocation, allocation, proofs[pIdx], evidenceHash(`fuzzer-normal-${step}-${pIdx}`));
                expectedEscrowed -= allocation;
                expectedFlaggedNormal += allocation;
                if (!activeDisputes[Number(activeEpoch)]) activeDisputes[Number(activeEpoch)] = {};
                activeDisputes[Number(activeEpoch)][pharm.address] = {
                  amount: allocation,
                  isExclusion: false,
                  approved: false
                };
              }
            }
            break;
          }
          case "FLAG_EXCLUSION": {
            const pIdx = Math.floor(Math.random() * pharmacies.length);
            const pharm = pharmacies[pIdx];
            const hasCl = await treasury.hasClaimed(activeEpoch, pharm.address);
            const flAmount = await treasury.flaggedAmount(activeEpoch, pharm.address);
            if (!hasCl && flAmount === 0n) {
              await treasury.connect(pharm).flagExclusion(activeEpoch, allocation, evidenceHash(`fuzzer-exclusion-${step}-${pIdx}`));
              expectedFlaggedExclusion += allocation;
              if (!activeDisputes[Number(activeEpoch)]) activeDisputes[Number(activeEpoch)] = {};
              activeDisputes[Number(activeEpoch)][pharm.address] = {
                amount: allocation,
                isExclusion: true,
                approved: false
              };
            }
            break;
          }
          case "APPROVE_EXCLUSION": {
            for (const pAddr of Object.keys(epDisputes)) {
              const disp = epDisputes[pAddr];
              if (disp && disp.isExclusion && !disp.approved) {
                await treasury.connect(council2).approveExclusionClaim(activeEpoch, pAddr);
                disp.approved = true;
                break;
              }
            }
            break;
          }
          case "RESOLVE_DISPUTE": {
            for (const pAddr of Object.keys(epDisputes)) {
              const disp = epDisputes[pAddr];
              if (disp && disp.amount > 0) {
                let res;
                if (disp.isExclusion) {
                  if (disp.approved) {
                    res = Math.random() < 0.5 ? 0 : 2;
                    await token.connect(depositor).approve(await treasury.getAddress(), disp.amount);
                    await treasury.connect(depositor).fundExclusionRemediation(disp.amount);
                    await treasury.connect(council).resolveClaim(activeEpoch, pAddr, res, evidenceHash(`fuzzer-resolve-exclusion-${step}`));
                    expectedFlaggedExclusion -= disp.amount;
                    disp.amount = 0n;
                  }
                } else {
                  res = [0, 1, 2][Math.floor(Math.random() * 3)];
                  await treasury.connect(council).resolveClaim(activeEpoch, pAddr, res, evidenceHash(`fuzzer-resolve-normal-${step}`));
                  expectedFlaggedNormal -= disp.amount;
                  if (res === 2) {
                    expectedEscrowed += disp.amount;
                  }
                  disp.amount = 0n;
                }
                break;
              }
            }
            break;
          }
          case "FINALIZE_EPOCH": {
            await ethers.provider.send("evm_increaseTime", [24 * 60 * 60 + 1]);
            await ethers.provider.send("evm_mine", []);
            const minVol = await treasury.minimumEpochVolume();
            const currentVol = await treasury.epochVolume();
            if (currentVol >= minVol) {
              await treasury.connect(council).finalizeEpoch();
              activeEpoch += 1n;
            }
            break;
          }
          case "RECALL_UNCLAIMED": {
            for (let ep = 0n; ep < activeEpoch; ep++) {
              const recalled = await treasury.epochRecalled(ep);
              const escrow = await treasury.epochEscrow(ep);
              if (!recalled && escrow > 0n) {
                await ethers.provider.send("evm_increaseTime", [30 * 24 * 60 * 60 + 1]);
                await ethers.provider.send("evm_mine", []);
                await treasury.connect(council).recallUnclaimed(ep);
                expectedEscrowed -= escrow;
                break;
              }
            }
            break;
          }
          case "DEPOSIT": {
            await seedDeposit(toWei("1000"));
            break;
          }
        }

        // Compare actual contract state variables with expected values
        const actualEscrowed = await treasury.totalEscrowed();
        const actualFlaggedNormal = await treasury.totalFlaggedNormal();
        const actualFlaggedExclusion = await treasury.totalFlaggedExclusion();

        expect(actualEscrowed).to.equal(expectedEscrowed, `Step ${step}: escrowed mismatch`);
        expect(actualFlaggedNormal).to.equal(expectedFlaggedNormal, `Step ${step}: flaggedNormal mismatch`);
        expect(actualFlaggedExclusion).to.equal(expectedFlaggedExclusion, `Step ${step}: flaggedExclusion mismatch`);

        // Assert globalAccounting view outputs match
        const acc = await treasury.globalAccounting();
        expect(acc.escrowed).to.equal(expectedEscrowed, `Step ${step}: view escrowed mismatch`);
        expect(acc.flaggedNormal).to.equal(expectedFlaggedNormal, `Step ${step}: view flaggedNormal mismatch`);
        expect(acc.flaggedExclusion).to.equal(expectedFlaggedExclusion, `Step ${step}: view flaggedExclusion mismatch`);

        // Check overall contract balance invariant
        const contractBalance = await token.balanceOf(await treasury.getAddress());
        const distPool = await treasury.distributionPool();
        const govRes = await treasury.governanceReserve();
        const exclRes = await treasury.exclusionRemediationReserve();

        let contractEscrowsAndFlags = 0n;
        for (let ep = 0n; ep <= activeEpoch; ep++) {
          contractEscrowsAndFlags += await treasury.epochEscrow(ep);
          for (const p of pharmacies) {
            const isEx = await treasury.isExclusionDispute(ep, p.address);
            if (!isEx) {
              contractEscrowsAndFlags += await treasury.flaggedAmount(ep, p.address);
            }
          }
        }

        const expectedBalance = distPool + govRes + exclRes + contractEscrowsAndFlags;
        expect(contractBalance).to.equal(expectedBalance, `Step ${step}: overall balance invariant broken`);
      }
    });
  });
});
