const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("PBMRebateTreasury Stale Recovery & Timer Checks", function () {
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

  it("blocks stale distribution recovery if 180 days have not elapsed since the current epoch began", async function () {
    await seedDeposit(toWei("1000"));

    // Fast forward 179 days
    await ethers.provider.send("evm_increaseTime", [179 * 24 * 60 * 60]);
    await ethers.provider.send("evm_mine", []);

    // Recovery should fail
    await expectRevert(
      timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [patientFund.address, toWei("100")])
      ),
      "underlying transaction reverted"
    );

    // Fast forward 2 more days -> now it's 181 days since epoch start
    await ethers.provider.send("evm_increaseTime", [2 * 24 * 60 * 60]);
    await ethers.provider.send("evm_mine", []);

    // Recovery should succeed
    await timelockExecute(
      await treasury.getAddress(),
      treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [patientFund.address, toWei("100")])
    );
    expect(await treasury.distributionPool()).to.equal(toWei("890"));
  });

  it("does not let a dust deposit extend the epoch-start recovery delay", async function () {
    await seedDeposit(toWei("1000"));
    const firstDepositTimestamp = await treasury.lastDepositTimestamp();

    // Fast forward 179 days
    await ethers.provider.send("evm_increaseTime", [179 * 24 * 60 * 60]);
    await ethers.provider.send("evm_mine", []);

    // Dust deposit of 1 wei
    await token.mint(depositor.address, 1n);
    await token.connect(depositor).approve(await treasury.getAddress(), 1n);
    await treasury.connect(depositor).depositRebate(1n, "Dust deposit");
    const dustDepositTimestamp = await treasury.lastDepositTimestamp();
    expect(dustDepositTimestamp).to.be.gt(firstDepositTimestamp);

    // Fast forward 2 more days (total 181 days since epoch start, but only 2 days since dust deposit)
    await ethers.provider.send("evm_increaseTime", [2 * 24 * 60 * 60]);
    await ethers.provider.send("evm_mine", []);

    // Recovery should succeed because the delay is measured from epochStartTimestamp, not lastDepositTimestamp.
    await timelockExecute(
      await treasury.getAddress(),
      treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [patientFund.address, toWei("100")])
    );
    expect(await treasury.distributionPool()).to.equal(toWei("890") + 1n);
  });

  it("treats late legitimate unrooted deposits as recoverable once the epoch itself is stale", async function () {
    await seedDeposit(toWei("1000"));
    const firstDepositTimestamp = await treasury.lastDepositTimestamp();

    await ethers.provider.send("evm_increaseTime", [179 * 24 * 60 * 60]);
    await ethers.provider.send("evm_mine", []);

    await token.connect(depositor).approve(await treasury.getAddress(), toWei("500"));
    await treasury.connect(depositor).depositRebate(toWei("500"), "Late unrooted legitimate deposit");
    const lateDepositTimestamp = await treasury.lastDepositTimestamp();
    expect(lateDepositTimestamp).to.be.gt(firstDepositTimestamp);
    expect(await treasury.distributionPool()).to.equal(toWei("1485"));
    expect(await treasury.getRecoverableStaleAmount()).to.equal(0n);

    await ethers.provider.send("evm_increaseTime", [2 * 24 * 60 * 60]);
    await ethers.provider.send("evm_mine", []);

    expect(await treasury.getRecoverableStaleAmount()).to.equal(toWei("1485"));

    await timelockExecute(
      await treasury.getAddress(),
      treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [patientFund.address, toWei("1400")])
    );
    expect(await treasury.distributionPool()).to.equal(toWei("85"));
  });

  it("still blocks stale recovery while a current root is live", async function () {
    await seedDeposit(toWei("1000"));

    const root = merkleLeaf(pharmacy.address, toWei("100"), toWei("100"));
    await treasury.connect(council).proposeRoot(root, toWei("100"));
    await treasury.connect(council2).confirmRoot(0);

    await ethers.provider.send("evm_increaseTime", [180 * 24 * 60 * 60 + 1]);
    await ethers.provider.send("evm_mine", []);

    expect(await treasury.getRecoverableStaleAmount()).to.equal(0n);

    await expectRevert(
      timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [patientFund.address, toWei("100")])
      ),
      "underlying transaction reverted"
    );
  });

  it("still blocks stale recovery while a pending root proposal has not expired", async function () {
    await seedDeposit(toWei("1000"));

    await ethers.provider.send("evm_increaseTime", [180 * 24 * 60 * 60 + 1]);
    await ethers.provider.send("evm_mine", []);

    const root = merkleLeaf(pharmacy.address, toWei("100"), toWei("100"));
    await treasury.connect(council).proposeRoot(root, toWei("100"));

    expect(await treasury.getRecoverableStaleAmount()).to.equal(0n);

    await expectRevert(
      timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [patientFund.address, toWei("100")])
      ),
      "underlying transaction reverted"
    );

    await ethers.provider.send("evm_increaseTime", [4 * 24 * 60 * 60]);
    await ethers.provider.send("evm_mine", []);

    expect(await treasury.getRecoverableStaleAmount()).to.equal(await treasury.distributionPool());

    await timelockExecute(
      await treasury.getAddress(),
      treasury.interface.encodeFunctionData("recoverStaleDistributionPool", [patientFund.address, toWei("100")])
    );
    expect(await treasury.distributionPool()).to.equal(toWei("890"));
  });

  it("reports correct getRecoverableStaleAmount view values", async function () {
    await seedDeposit(toWei("1000"));
    expect(await treasury.getRecoverableStaleAmount()).to.equal(0n);

    await ethers.provider.send("evm_increaseTime", [180 * 24 * 60 * 60 + 1]);
    await ethers.provider.send("evm_mine", []);

    const expectedDist = await treasury.distributionPool();
    expect(await treasury.getRecoverableStaleAmount()).to.equal(expectedDist);
  });

  describe("skipStaleUnrootedEpoch", function () {
    it("reverts if called by non-executor role", async function () {
      await expectRevert(
        treasury.connect(council).skipStaleUnrootedEpoch(),
        "AccessControl"
      );
    });

    it("reverts if 180 days have not elapsed", async function () {
      await seedDeposit(toWei("1000"));

      // Fast forward 179 days
      await ethers.provider.send("evm_increaseTime", [179 * 24 * 60 * 60]);
      await ethers.provider.send("evm_mine", []);

      await expectRevert(
        timelockExecute(
          await treasury.getAddress(),
          treasury.interface.encodeFunctionData("skipStaleUnrootedEpoch", [])
        ),
        "underlying transaction reverted"
      );
    });

    it("succeeds after 180 days and transitions state correctly", async function () {
      await seedDeposit(toWei("1000"));

      // Fast forward 181 days
      await ethers.provider.send("evm_increaseTime", [181 * 24 * 60 * 60]);
      await ethers.provider.send("evm_mine", []);

      const prevEpoch = await treasury.currentEpoch();
      expect(prevEpoch).to.equal(0n);

      const tx = await timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("skipStaleUnrootedEpoch", [])
      );
      
      // Check state transitions
      expect(await treasury.currentEpoch()).to.equal(1n);
      expect(await treasury.epochVolume()).to.equal(0n);
      
      // Verify events from transaction receipt
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt.blockNumber);
      expect(await treasury.epochStartTimestamp()).to.equal(BigInt(block.timestamp));
    });

    it("reverts if a Merkle root is already live for the current epoch", async function () {
      await seedDeposit(toWei("1000"));

      const root = merkleLeaf(pharmacy.address, toWei("100"), toWei("100"));
      await treasury.connect(council).proposeRoot(root, toWei("100"));
      await treasury.connect(council2).confirmRoot(0);

      // Fast forward 181 days
      await ethers.provider.send("evm_increaseTime", [181 * 24 * 60 * 60]);
      await ethers.provider.send("evm_mine", []);

      await expectRevert(
        timelockExecute(
          await treasury.getAddress(),
          treasury.interface.encodeFunctionData("skipStaleUnrootedEpoch", [])
        ),
        "underlying transaction reverted"
      );
    });

    it("reverts if a proposal is pending and unexpired, but succeeds and deletes it once expired", async function () {
      await seedDeposit(toWei("1000"));

      // Fast forward 181 days
      await ethers.provider.send("evm_increaseTime", [181 * 24 * 60 * 60]);
      await ethers.provider.send("evm_mine", []);

      const root = merkleLeaf(pharmacy.address, toWei("100"), toWei("100"));
      await treasury.connect(council).proposeRoot(root, toWei("100"));

      // Proposal is active, should revert
      await expectRevert(
        timelockExecute(
          await treasury.getAddress(),
          treasury.interface.encodeFunctionData("skipStaleUnrootedEpoch", [])
        ),
        "underlying transaction reverted"
      );

      // Fast forward 4 more days -> proposal expired
      await ethers.provider.send("evm_increaseTime", [4 * 24 * 60 * 60]);
      await ethers.provider.send("evm_mine", []);

      // Now it should succeed
      await timelockExecute(
        await treasury.getAddress(),
        treasury.interface.encodeFunctionData("skipStaleUnrootedEpoch", [])
      );

      expect(await treasury.currentEpoch()).to.equal(1n);

      // Verify proposal was deleted
      const pending = await treasury.pendingRoot(0);
      expect(pending.proposer).to.equal(ethers.ZeroAddress);
      expect(pending.proposedAt).to.equal(0n);
    });
  });
});
