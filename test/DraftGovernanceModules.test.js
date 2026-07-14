const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Draft governance modules", function () {
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
      expect(errorText(err)).to.contain(expectedSnippet);
    }

    if (!reverted) {
      expect.fail(`Expected revert containing '${expectedSnippet}'`);
    }
  }

  it("requires enough cooperative bootstrap participants to avoid attestation deadlock", async function () {
    const [bootstrapA, bootstrapB, bootstrapC, target] = await ethers.getSigners();
    const CooperativeParticipatoryBudgeting = await ethers.getContractFactory("CooperativeParticipatoryBudgeting");

    await expectRevert(
      CooperativeParticipatoryBudgeting.deploy([bootstrapA.address]),
      "ThresholdNotMet"
    );

    const cooperative = await CooperativeParticipatoryBudgeting.deploy([
      bootstrapA.address,
      bootstrapB.address,
      bootstrapC.address,
    ]);
    await cooperative.waitForDeployment();
    expect(await cooperative.attestationThreshold()).to.equal(3n);

    await cooperative.connect(bootstrapA).attestParticipant(target.address);
    await cooperative.connect(bootstrapB).attestParticipant(target.address);
    expect((await cooperative.participants(target.address)).registered).to.equal(false);

    await cooperative.connect(bootstrapC).attestParticipant(target.address);
    expect((await cooperative.participants(target.address)).registered).to.equal(true);
  });

  it("rejects peer attestations for the zero address", async function () {
    const [bootstrapA, bootstrapB, bootstrapC] = await ethers.getSigners();
    const CooperativeParticipatoryBudgeting = await ethers.getContractFactory("CooperativeParticipatoryBudgeting");
    const cooperative = await CooperativeParticipatoryBudgeting.deploy([
      bootstrapA.address,
      bootstrapB.address,
      bootstrapC.address,
    ]);
    await cooperative.waitForDeployment();

    await expectRevert(
      cooperative.connect(bootstrapA).attestParticipant(ethers.ZeroAddress),
      "InvalidParticipant"
    );
  });

  it("keeps reflexive PID mutation controller-only and handles zero matching targets", async function () {
    const [controller, attacker] = await ethers.getSigners();
    const ReflexiveFiduciaryManifold = await ethers.getContractFactory("ReflexiveFiduciaryManifold");
    const manifold = await ReflexiveFiduciaryManifold.deploy(1n, 1n, 1n);
    await manifold.waitForDeployment();

    expect(await manifold.computeDynamicRebateScale(0n, 100n, 0n)).to.equal(0n);

    await ethers.provider.send("evm_increaseTime", [1]);
    await ethers.provider.send("evm_mine", []);

    await expectRevert(
      manifold.connect(attacker).computeCapacityAdjustment(100n, 90n),
      "UnauthorizedController"
    );

    const tx = await manifold.connect(controller).computeCapacityAdjustment(100n, 90n);
    await tx.wait();

    expect((await manifold.creditLimitPID()).integral).to.not.equal(0n);
  });

  it("bounds reflexive rebate scaling without signed casts or multiplication overflow", async function () {
    const ReflexiveFiduciaryManifold = await ethers.getContractFactory("ReflexiveFiduciaryManifold");
    const manifold = await ReflexiveFiduciaryManifold.deploy(1n, 1n, 1n);
    await manifold.waitForDeployment();

    const scale = await manifold.REBATE_SCALE_DECIMALS();
    const max = ethers.MaxUint256;

    expect(await manifold.computeDynamicRebateScale(100n, 100n, 1n)).to.equal(0n);
    expect(await manifold.computeDynamicRebateScale(200n, 100n, 1n)).to.equal(0n);
    expect(await manifold.computeDynamicRebateScale(0n, 100n, 200n)).to.equal(scale / 2n);
    expect(await manifold.computeDynamicRebateScale(0n, max, max)).to.equal(scale);

    const nearFullScale = await manifold.computeDynamicRebateScale(0n, max - 1n, max);
    expect(nearFullScale).to.be.greaterThan(0n);
    expect(nearFullScale).to.be.lessThan(scale);
  });

  it("preserves fractional PID derivative precision before applying Kd", async function () {
    const [controller] = await ethers.getSigners();
    const ReflexiveFiduciaryManifold = await ethers.getContractFactory("ReflexiveFiduciaryManifold");
    const manifold = await ReflexiveFiduciaryManifold.deploy(0n, 0n, 100000000n);
    await manifold.waitForDeployment();

    const latestBlock = await ethers.provider.getBlock("latest");
    await ethers.provider.send("evm_setNextBlockTimestamp", [latestBlock.timestamp + 10]);

    const tx = await manifold.connect(controller).computeCapacityAdjustment(1n, 0n);
    const receipt = await tx.wait();
    const parsedEvent = receipt.logs
      .map((log) => {
        try {
          return manifold.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((log) => log?.name === "FiduciaryManifoldAdjusted");

    expect(parsedEvent.args.derivative).to.equal(10000000n);
    expect(parsedEvent.args.controlOutput).to.equal(10000000n);
  });
});
