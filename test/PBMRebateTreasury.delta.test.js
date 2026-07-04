const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("PBMRebateTreasury delta checks", function () {
  const toWei = (value) => ethers.parseEther(value);

  let feeToken;
  let treasury;
  let council;
  let guardian;
  let rootConfirmer;

  async function expectRevert(promise, expectedSnippet) {
    let reverted = false;
    try {
      await promise;
    } catch (err) {
      reverted = true;
      const text = [
        err?.message,
        err?.shortMessage,
        err?.errorName,
        err?.error?.message,
        err?.data?.message,
      ]
        .filter(Boolean)
        .join(" | ");
      expect(text).to.contain(expectedSnippet);
    }
    if (!reverted) {
      expect.fail(`Expected revert containing '${expectedSnippet}'`);
    }
  }

  beforeEach(async function () {
    const signers = await ethers.getSigners();
    council = signers[0];
    guardian = signers[1];
    rootConfirmer = signers[2];

    const MockFeeOnTransfer = await ethers.getContractFactory("MockFeeOnTransferERC20");
    feeToken = await MockFeeOnTransfer.deploy();
    await feeToken.waitForDeployment();

    const Treasury = await ethers.getContractFactory("PBMRebateTreasury");
    treasury = await Treasury.deploy(
      await feeToken.getAddress(),
      council.address,           // patientFund
      council.address,           // environmentalFund
      toWei("10000"),            // initialDailyCap
      toWei("100"),              // minimumEpochVolume
      council.address,           // council
      rootConfirmer.address,     // rootConfirmer
      council.address,           // executor
      guardian.address           // guardian
    );
    await treasury.waitForDeployment();

    await feeToken.mint(council.address, toWei("1000"));
    await feeToken.connect(council).approve(await treasury.getAddress(), toWei("1000"));
  });

  it("reverts depositRebate when actual transfer is less than amount", async function () {
    await expectRevert(
      treasury.connect(council).depositRebate(toWei("100"), "test source"),
      "TokenTransferAmountMismatch"
    );
  });

  it("reverts fundExclusionRemediation when actual transfer is less than amount", async function () {
    await expectRevert(
      treasury.connect(council).fundExclusionRemediation(toWei("100")),
      "TokenTransferAmountMismatch"
    );
  });
});
