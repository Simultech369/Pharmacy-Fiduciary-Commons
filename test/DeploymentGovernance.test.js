const { expect } = require("chai");
const { ethers } = require("hardhat");
const { assertDeploymentPreflight } = require("../scripts/deployment-policy");

describe("Deployment governance lifecycle", function () {
  const nonzeroExecutor = "0x0000000000000000000000000000000000000001";
  const deployerAddress = "0x0000000000000000000000000000000000000002";
  const timelockAdmin = deployerAddress;

  function basePreflight(overrides = {}) {
    return {
      deployerAddress,
      isLocalNetwork: false,
      minDelaySeconds: 172800n,
      renounceSetupAdmin: true,
      timelockAdmin,
      timelockExecutors: [nonzeroExecutor],
      zeroAddress: ethers.ZeroAddress,
      initialDailyCap: 1000n,
      minimumEpochVolume: 100n,
      council: "0x0000000000000000000000000000000000000010",
      rootConfirmer: "0x0000000000000000000000000000000000000011",
      guardian: "0x0000000000000000000000000000000000000012",
      ...overrides,
    };
  }

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

  it("allows open timelock execution only on local networks", function () {
    expect(() => assertDeploymentPreflight(basePreflight({
      isLocalNetwork: true,
      timelockExecutors: [ethers.ZeroAddress],
    }))).to.not.throw();

    const originalDeploymentEnv = process.env.DEPLOYMENT_ENV;
    try {
      for (const deploymentEnv of [undefined, "local", "demo", "production"]) {
        if (deploymentEnv === undefined) {
          delete process.env.DEPLOYMENT_ENV;
        } else {
          process.env.DEPLOYMENT_ENV = deploymentEnv;
        }

        expect(() => assertDeploymentPreflight(basePreflight({
          isLocalNetwork: false,
          timelockExecutors: [ethers.ZeroAddress],
        }))).to.throw("Open execution (ZeroAddress executor) is not allowed on non-local networks.");
      }
    } finally {
      if (originalDeploymentEnv === undefined) {
        delete process.env.DEPLOYMENT_ENV;
      } else {
        process.env.DEPLOYMENT_ENV = originalDeploymentEnv;
      }
    }
  });

  it("allows non-local deployments with configured nonzero executors", function () {
    expect(() => assertDeploymentPreflight(basePreflight())).to.not.throw();
  });

  it("rejects non-local deployment policy violations before deployment", function () {
    expect(() => assertDeploymentPreflight(basePreflight({
      renounceSetupAdmin: false,
    }))).to.throw("RENOUNCE_TIMELOCK_ADMIN=true must be specified");

    expect(() => assertDeploymentPreflight(basePreflight({
      minDelaySeconds: 60n,
    }))).to.throw("TIMELOCK_MIN_DELAY_SECONDS must be at least 86400");

    expect(() => assertDeploymentPreflight(basePreflight({
      timelockAdmin: "0x0000000000000000000000000000000000000003",
    }))).to.throw("RENOUNCE_TIMELOCK_ADMIN=true requires TIMELOCK_ADMIN to equal the deployer.");
  });

  it("rejects invalid cap, volume, or matching role identities before deployment", function () {
    expect(() => assertDeploymentPreflight(basePreflight({
      initialDailyCap: 0n,
    }))).to.throw("INITIAL_DAILY_CAP must be a non-zero integer");

    expect(() => assertDeploymentPreflight(basePreflight({
      minimumEpochVolume: 0n,
    }))).to.throw("MINIMUM_EPOCH_VOLUME must be a non-zero integer");

    expect(() => assertDeploymentPreflight(basePreflight({
      council: "0x0000000000000000000000000000000000000010",
      rootConfirmer: "0x0000000000000000000000000000000000000010",
    }))).to.throw("Council cannot be confirmer");

    expect(() => assertDeploymentPreflight(basePreflight({
      council: "0x0000000000000000000000000000000000000010",
      guardian: "0x0000000000000000000000000000000000000010",
    }))).to.throw("Council cannot be guardian");
  });
});
