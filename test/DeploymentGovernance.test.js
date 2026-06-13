const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Deployment governance lifecycle", function () {
  it("can remove the temporary human timelock admin while preserving self-administration", async function () {
    const [setupAdmin, proposer] = await ethers.getSigners();
    const Timelock = await ethers.getContractFactory("TimelockController");
    const timelock = await Timelock.deploy(
      172800n,
      [proposer.address],
      [ethers.ZeroAddress],
      setupAdmin.address
    );
    await timelock.waitForDeployment();

    const adminRole = await timelock.TIMELOCK_ADMIN_ROLE();
    const timelockAddress = await timelock.getAddress();
    expect(await timelock.hasRole(adminRole, timelockAddress)).to.be.true;
    expect(await timelock.hasRole(adminRole, setupAdmin.address)).to.be.true;

    await timelock.connect(setupAdmin).renounceRole(adminRole, setupAdmin.address);

    expect(await timelock.hasRole(adminRole, setupAdmin.address)).to.be.false;
    expect(await timelock.hasRole(adminRole, timelockAddress)).to.be.true;
  });
});
