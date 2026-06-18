/* eslint-disable no-console */

const hre = require("hardhat");

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required env var: ${name}`);
  }
  return value;
}

function parseAddressList(value) {
  if (!value) return [];
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function resolveTimelockExecutors() {
  if (process.env.TIMELOCK_EXECUTORS) {
    return parseAddressList(process.env.TIMELOCK_EXECUTORS);
  }
  if (process.env.ALLOW_OPEN_TIMELOCK_EXECUTOR === "true") {
    return [hre.ethers.ZeroAddress];
  }
  throw new Error(
    "TIMELOCK_EXECUTORS is required. Set ALLOW_OPEN_TIMELOCK_EXECUTOR=true only if open timelock execution is intentional."
  );
}

async function main() {
  const [deployer] = await hre.ethers.getSigners();

  const token = requireEnv("TOKEN");
  const patientFund = requireEnv("PATIENT_FUND");
  const environmentalFund = requireEnv("ENVIRONMENTAL_FUND");
  const council = requireEnv("COUNCIL");
  const rootConfirmer = requireEnv("ROOT_CONFIRMER");
  const guardian = requireEnv("GUARDIAN");

  const initialDailyCap = BigInt(process.env.INITIAL_DAILY_CAP ?? "0");
  if (initialDailyCap === 0n) {
    throw new Error("INITIAL_DAILY_CAP must be a non-zero integer (as a string).");
  }
  const minimumEpochVolume = BigInt(process.env.MINIMUM_EPOCH_VOLUME ?? "0");
  if (minimumEpochVolume === 0n) {
    throw new Error("MINIMUM_EPOCH_VOLUME must be a non-zero integer in token base units.");
  }

  const minDelaySeconds = BigInt(process.env.TIMELOCK_MIN_DELAY_SECONDS ?? "172800"); // 2 days
  const timelockProposers = parseAddressList(process.env.TIMELOCK_PROPOSERS ?? council);
  const timelockExecutors = resolveTimelockExecutors();
  const timelockAdmin = requireEnv("TIMELOCK_ADMIN");
  const renounceSetupAdmin = process.env.RENOUNCE_TIMELOCK_ADMIN === "true";

  console.log("Deployer:", deployer.address);
  console.log("Token:", token);
  console.log("Patient fund:", patientFund);
  console.log("Environmental fund:", environmentalFund);
  console.log("Council:", council);
  console.log("Root confirmer:", rootConfirmer);
  console.log("Guardian:", guardian);
  console.log("Initial daily cap:", initialDailyCap.toString());
  console.log("Minimum epoch volume:", minimumEpochVolume.toString());
  console.log("Timelock min delay (s):", minDelaySeconds.toString());
  console.log("Timelock proposers:", timelockProposers);
  console.log("Timelock executors:", timelockExecutors);
  console.log("Timelock admin:", timelockAdmin);

  const Timelock = await hre.ethers.getContractFactory("TimelockController");
  const timelock = await Timelock.deploy(
    minDelaySeconds,
    timelockProposers,
    timelockExecutors,
    timelockAdmin
  );
  await timelock.waitForDeployment();
  const timelockAddress = await timelock.getAddress();
  console.log("TimelockController deployed:", timelockAddress);

  const timelockAdminRole = await timelock.TIMELOCK_ADMIN_ROLE();
  if (!(await timelock.hasRole(timelockAdminRole, timelockAddress))) {
    throw new Error("Timelock is not self-administered after deployment.");
  }

  const Treasury = await hre.ethers.getContractFactory("PBMRebateTreasury");
  const treasury = await Treasury.deploy(
    token,
    patientFund,
    environmentalFund,
    initialDailyCap,
    minimumEpochVolume,
    council,
    rootConfirmer,
    timelockAddress,
    guardian
  );
  await treasury.waitForDeployment();
  console.log("PBMRebateTreasury deployed:", await treasury.getAddress());

  if (renounceSetupAdmin) {
    if (timelockAdmin.toLowerCase() !== deployer.address.toLowerCase()) {
      throw new Error("RENOUNCE_TIMELOCK_ADMIN=true requires TIMELOCK_ADMIN to equal the deployer.");
    }
    await (await timelock.renounceRole(timelockAdminRole, deployer.address)).wait();
    if (await timelock.hasRole(timelockAdminRole, deployer.address)) {
      throw new Error("Temporary timelock setup admin was not renounced.");
    }
    console.log("Temporary timelock setup admin renounced:", deployer.address);
  } else {
    console.warn("Temporary/external timelock admin retained intentionally:", timelockAdmin);
  }

  console.log("Final timelock self-admin:", await timelock.hasRole(timelockAdminRole, timelockAddress));
  console.log("Final external admin retained:", await timelock.hasRole(timelockAdminRole, timelockAdmin));
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
