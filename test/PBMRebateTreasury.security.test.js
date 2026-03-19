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

  function errorText(err) {
    return [
      err?.message,
      err?.shortMessage,
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
        executor.address,
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
      "ExceedsHardCap"
    );

    const dailyCap = await treasury.dailyVolumeCap();
    await expectRevert(
      timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("reduceHardCap", [dailyCap - 1n])
      ),
      "BelowDailyCap"
    );

    const newHardCap = dailyCap + toWei("1");
    await timelockExecute(
      await treasury.getAddress(),
      treasury.interface.encodeFunctionData("reduceHardCap", [newHardCap])
    );

    expect(await treasury.hardAbsoluteVolumeCap()).to.equal(newHardCap);
  });
});
