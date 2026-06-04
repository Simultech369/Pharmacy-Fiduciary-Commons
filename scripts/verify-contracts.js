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
  const timelockAddress = requireEnv("TIMELOCK_ADDRESS");
  const treasuryAddress = requireEnv("TREASURY_ADDRESS");

  const token = requireEnv("TOKEN");
  const patientFund = requireEnv("PATIENT_FUND");
  const environmentalFund = requireEnv("ENVIRONMENTAL_FUND");
  const council = requireEnv("COUNCIL");
  const guardian = requireEnv("GUARDIAN");

  const initialDailyCap = BigInt(process.env.INITIAL_DAILY_CAP ?? "0");
  if (initialDailyCap === 0n) {
    throw new Error("INITIAL_DAILY_CAP must be a non-zero integer.");
  }

  const minDelaySeconds = BigInt(process.env.TIMELOCK_MIN_DELAY_SECONDS ?? "172800");
  const timelockProposers = parseAddressList(process.env.TIMELOCK_PROPOSERS ?? council);
  const timelockExecutors = parseAddressList(process.env.TIMELOCK_EXECUTORS ?? hre.ethers.ZeroAddress);
  const timelockAdmin = process.env.TIMELOCK_ADMIN ?? council;

  console.log("Verifying TimelockController at:", timelockAddress);
  try {
    await hre.run("verify:verify", {
      address: timelockAddress,
      constructorArguments: [
        minDelaySeconds.toString(),
        timelockProposers,
        timelockExecutors,
        timelockAdmin,
      ],
    });
    console.log("TimelockController verification complete.");
  } catch (error) {
    console.warn("TimelockController verification failed or already verified:", error.message);
  }

  console.log("Verifying PBMRebateTreasury at:", treasuryAddress);
  try {
    await hre.run("verify:verify", {
      address: treasuryAddress,
      constructorArguments: [
        token,
        patientFund,
        environmentalFund,
        initialDailyCap.toString(),
        council,
        timelockAddress,
        guardian,
      ],
    });
    console.log("PBMRebateTreasury verification complete.");
  } catch (error) {
    console.warn("PBMRebateTreasury verification failed or already verified:", error.message);
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
