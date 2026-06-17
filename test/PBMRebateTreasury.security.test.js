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

  it("splits deposits 99 percent distribution and 1 percent governance", async function () {
    await seedDeposit(toWei("1000"));

    expect(await treasury.distributionPool()).to.equal(toWei("990"));
    expect(await treasury.governanceReserve()).to.equal(toWei("10"));
    expect(await treasury.totalRebateDeposited()).to.equal(toWei("1000"));
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
    await treasury.connect(attacker).flagExclusion(0, toWei("50"));
    const poolAfter = await treasury.distributionPool();
    expect(poolBefore).to.equal(poolAfter);
    expect(await treasury.flaggedAmount(0, attacker.address)).to.equal(toWei("50"));
    expect(await treasury.isExclusionDispute(0, attacker.address)).to.be.true;

    // 2. Resolve claim as DISMISS (flag cleared, no transfers)
    await treasury.connect(council).resolveClaim(0, attacker.address, 2); // DISMISS is enum val 2
    expect(await treasury.flaggedAmount(0, attacker.address)).to.equal(0n);
    expect(await treasury.isExclusionDispute(0, attacker.address)).to.be.false;

    // 3. Flag exclusion again; council cannot pay it without independent approval.
    await treasury.connect(depositor).flagExclusion(0, toWei("50"));
    await expectRevert(
      treasury.connect(council).resolveClaim(0, depositor.address, 0),
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
    await treasury.connect(council).resolveClaim(0, depositor.address, 0); // RELEASE_TO_PHARMACY is 0
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

    await treasury.connect(attacker).flagExclusion(0, gross);
    await treasury.connect(council2).approveExclusionClaim(0, attacker.address);
    await token.connect(depositor).approve(await treasury.getAddress(), gross);
    await treasury.connect(depositor).fundExclusionRemediation(gross);
    await treasury.connect(council).resolveClaim(0, attacker.address, 0);

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

    await treasury.connect(attacker).flagExclusion(0, toWei("200"));
    await treasury.connect(council2).approveExclusionClaim(0, attacker.address);
    await token.connect(depositor).approve(await treasury.getAddress(), toWei("200"));
    await treasury.connect(depositor).fundExclusionRemediation(toWei("200"));

    await expectRevert(
      treasury.connect(council).resolveClaim(0, attacker.address, 0),
      "DailyCapExceeded"
    );
    await expectRevert(
      treasury.connect(council).resolveClaim(0, attacker.address, 1),
      "InvalidExclusionResolution"
    );

    expect(await treasury.flaggedAmount(0, attacker.address)).to.equal(toWei("200"));
  });

  it("funds exclusion remediation explicitly without consuming future distribution liquidity", async function () {
    await seedDeposit(toWei("1000"));
    const gross = toWei("100");
    await publishSingleLeafRoot(gross, gross);
    await treasury.connect(council2).confirmRoot(0);

    await treasury.connect(attacker).flagExclusion(0, toWei("50"));
    await treasury.connect(council2).approveExclusionClaim(0, attacker.address);
    const distributionBefore = await treasury.distributionPool();

    await expectRevert(
      treasury.connect(council).resolveClaim(0, attacker.address, 0),
      "InsufficientExclusionReserve"
    );

    await token.connect(depositor).approve(await treasury.getAddress(), toWei("50"));
    await treasury.connect(depositor).fundExclusionRemediation(toWei("50"));
    expect(await treasury.exclusionRemediationReserve()).to.equal(toWei("50"));

    await treasury.connect(council).resolveClaim(0, attacker.address, 0);

    expect(await treasury.exclusionRemediationReserve()).to.equal(0n);
    expect(await treasury.distributionPool()).to.equal(distributionBefore);
    expect(await treasury.epochEscrow(0)).to.equal(gross);
  });

  it("allows sanctioned address to submit an on-chain appeal", async function () {
    await treasury.connect(council).updateSanction(attacker.address, true, "spamming claims");
    expect(await treasury.sanctioned(attacker.address)).to.be.true;

    const tx = await treasury.connect(attacker).appealSanction("i am a valid pharmacy");
    const receipt = await tx.wait();
    const event = receipt.logs.find(x => x.fragment && x.fragment.name === "SanctionAppealed");
    expect(event).to.not.be.undefined;
    expect(event.args[0]).to.equal(attacker.address);
    expect(event.args[1]).to.equal("i am a valid pharmacy");
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
    await treasury.connect(pharmacy).flagClaim(0, amtA, amtA, proofA);

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
    await treasury.connect(council).resolveClaim(0, pharmacy.address, 2); // 2 is DISMISS
    const patientAfterDismiss = await token.balanceOf(patientFund.address);

    // The patientFund should receive the 80 tokens directly
    expect(patientAfterDismiss - patientBeforeDismiss).to.equal(amtA);

    // Escrow should remain 0, and flaggedAmount cleared
    expect(await treasury.epochEscrow(0)).to.equal(0n);
    expect(await treasury.flaggedAmount(0, pharmacy.address)).to.equal(0n);
  });

  it("frees volume caps and updates claimed totals when a dispute is dismissed in the active epoch", async function () {
    await seedDeposit(toWei("1000"));
    const gross = toWei("100");
    const leaf = await publishSingleLeafRoot(gross, gross);
    await treasury.connect(council2).confirmRoot(0);

    // Flag the claim
    await treasury.connect(pharmacy).flagClaim(0, gross, gross, []);

    // Caps and totals should be updated as if claimed
    expect(await treasury.epochVolume()).to.equal(gross);
    expect(await treasury.epochClaimedTotal(0)).to.equal(gross);

    // Dismiss the claim
    await treasury.connect(council).resolveClaim(0, pharmacy.address, 2); // 2 is DISMISS

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
});
