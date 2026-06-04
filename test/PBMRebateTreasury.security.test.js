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
    const councilRole = await treasury.councilRole();
    await treasury.connect(council).grantRole(councilRole, council2.address);

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
    token = await MockERC20.deploy("Mock DAI", "mDAI");
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
      council.address,
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
        council.address,
        await timelock.getAddress(),
        council.address
      ),
      "GuardianMustDifferFromCouncil"
    );
  });

  it("splits deposits 99 percent distribution and 1 percent governance", async function () {
    await seedDeposit(toWei("1000"));

    expect(await treasury.distributionPool()).to.equal(toWei("990"));
    expect(await treasury.governanceReserve()).to.equal(toWei("10"));
    expect(await treasury.totalRebateDeposited()).to.equal(toWei("1000"));
  });

  it("requires root co-sign from a distinct council member", async function () {
    await seedDeposit(toWei("1000"));

    const gross = toWei("100");
    await publishSingleLeafRoot(gross, gross);

    await expectRevert(
      treasury.connect(council).confirmRoot(0),
      "ProposerCannotConfirm"
    );

    await treasury.connect(council2).confirmRoot(0);

    expect(await treasury.epochRootTotal(0)).to.equal(gross);
    expect(await treasury.epochMerkleRoot(0)).to.not.equal(ethers.ZeroHash);
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

    // 3. Flag exclusion again and resolve as RELEASE_TO_PHARMACY (withdraws from distributionPool)
    await treasury.connect(depositor).flagExclusion(0, toWei("50"));
    const balanceBefore = await token.balanceOf(depositor.address);
    await treasury.connect(council).resolveClaim(0, depositor.address, 0); // RELEASE_TO_PHARMACY is 0
    const balanceAfter = await token.balanceOf(depositor.address);
    // Net transfer is 90% of 50 = 45 (using initial 10% patientClaimBP)
    expect(balanceAfter - balanceBefore).to.equal(toWei("45"));
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

  it("EXPLOIT PoC: locks dismissed dispute funds permanently if recall happens first", async function () {
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

    const councilRole = await treasury.councilRole();
    await treasury.connect(council).grantRole(councilRole, council2.address);

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

    // 7. Council resolves the dispute as DISMISS (returning 80 tokens to escrow)
    await treasury.connect(council).resolveClaim(0, pharmacy.address, 2); // 2 is DISMISS

    // 80 tokens are now returned to escrow
    expect(await treasury.epochEscrow(0)).to.equal(amtA);
    expect(await treasury.flaggedAmount(0, pharmacy.address)).to.equal(0n);

    // 8. Trying to recall these funds again fails because epochRecalled[0] is true!
    await expectRevert(
      treasury.connect(council).recallUnclaimed(0),
      "AlreadyRecalled"
    );

    // The funds are now permanently stuck in the contract's epochEscrow[0]!
    expect(await treasury.epochEscrow(0)).to.equal(amtA);
  });
});
