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

async function main() {
  const [deployer] = await hre.ethers.getSigners();

  const token = requireEnv("TOKEN");
  const patientFund = requireEnv("PATIENT_FUND");
  const environmentalFund = requireEnv("ENVIRONMENTAL_FUND");
  const council = requireEnv("COUNCIL");
  const guardian = requireEnv("GUARDIAN");

  const initialDailyCap = BigInt(process.env.INITIAL_DAILY_CAP ?? "0");
  if (initialDailyCap === 0n) {
    throw new Error("INITIAL_DAILY_CAP must be a non-zero integer (as a string).");
  }

  const minDelaySeconds = BigInt(process.env.TIMELOCK_MIN_DELAY_SECONDS ?? "172800"); // 2 days
  const timelockProposers = parseAddressList(process.env.TIMELOCK_PROPOSERS ?? council);
  const timelockExecutors = parseAddressList(process.env.TIMELOCK_EXECUTORS ?? hre.ethers.ZeroAddress);
  const timelockAdmin = process.env.TIMELOCK_ADMIN ?? council;

  console.log("Deployer:", deployer.address);
  console.log("Token:", token);
  console.log("Patient fund:", patientFund);
  console.log("Environmental fund:", environmentalFund);
  console.log("Council:", council);
  console.log("Guardian:", guardian);
  console.log("Initial daily cap:", initialDailyCap.toString());
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

  const Treasury = await hre.ethers.getContractFactory("PBMRebateTreasury");
  const treasury = await Treasury.deploy(
    token,
    patientFund,
    environmentalFund,
    initialDailyCap,
    council,
    timelockAddress,
    guardian
  );
  await treasury.waitForDeployment();
  console.log("PBMRebateTreasury deployed:", await treasury.getAddress());
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});

