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
  const timelockExecutors = resolveTimelockExecutors();

  // Enforce deployment security validations for non-local networks
  const networkConfig = await hre.ethers.provider.getNetwork();
  const chainId = networkConfig.chainId;
  const isLocalNetwork = chainId === 31337n || chainId === 1337n;
  if (!isLocalNetwork) {
    const renounceSetupAdmin = process.env.RENOUNCE_TIMELOCK_ADMIN === "true";
    const allowRetainedAdmin = process.env.ALLOW_RETAINED_TIMELOCK_ADMIN === "true";
    if (!renounceSetupAdmin && !allowRetainedAdmin) {
      throw new Error("Safety violation: RENOUNCE_TIMELOCK_ADMIN=true must be specified for non-local network deployments, or ALLOW_RETAINED_TIMELOCK_ADMIN=true to retain external admin.");
    }

    const hasOpenExecutor = timelockExecutors.some(
      executor => executor.toLowerCase() === hre.ethers.ZeroAddress.toLowerCase()
    );
    if (hasOpenExecutor && process.env.DEPLOYMENT_ENV !== "demo" && process.env.DEPLOYMENT_ENV !== "local") {
      throw new Error("Safety violation: Open execution (ZeroAddress executor) is not allowed on non-local networks unless DEPLOYMENT_ENV=demo or DEPLOYMENT_ENV=local is set.");
    }
  }

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

  // Post-deployment check assertions
  console.log("Running post-deployment sanity checks...");

  const DEFAULT_ADMIN_ROLE = "0x0000000000000000000000000000000000000000000000000000000000000000";
  const COUNCIL_ROLE = hre.ethers.solidityPackedKeccak256(["string"], ["COUNCIL_ROLE"]);
  const ROOT_CONFIRMER_ROLE = hre.ethers.solidityPackedKeccak256(["string"], ["ROOT_CONFIRMER_ROLE"]);
  const EXECUTOR_ROLE = hre.ethers.solidityPackedKeccak256(["string"], ["EXECUTOR_ROLE"]);
  const GUARDIAN_ROLE = hre.ethers.solidityPackedKeccak256(["string"], ["GUARDIAN_ROLE"]);

  if (!(await treasury.hasRole(DEFAULT_ADMIN_ROLE, council))) throw new Error("Sanity check failed: Council does not have DEFAULT_ADMIN_ROLE");
  if (!(await treasury.hasRole(COUNCIL_ROLE, council))) throw new Error("Sanity check failed: Council does not have COUNCIL_ROLE");
  if (!(await treasury.hasRole(ROOT_CONFIRMER_ROLE, rootConfirmer))) throw new Error("Sanity check failed: Root confirmer does not have ROOT_CONFIRMER_ROLE");
  if (!(await treasury.hasRole(EXECUTOR_ROLE, timelockAddress))) throw new Error("Sanity check failed: Timelock is not the EXECUTOR_ROLE");
  if (!(await treasury.hasRole(GUARDIAN_ROLE, guardian))) throw new Error("Sanity check failed: Guardian does not have GUARDIAN_ROLE");

  if (council.toLowerCase() === rootConfirmer.toLowerCase()) throw new Error("Sanity check failed: Council cannot be confirmer");
  if (council.toLowerCase() === guardian.toLowerCase()) throw new Error("Sanity check failed: Council cannot be guardian");

  const PROPOSER_ROLE = await timelock.PROPOSER_ROLE();
  const TIMELOCK_EXECUTOR_ROLE = await timelock.EXECUTOR_ROLE();
  for (const proposer of timelockProposers) {
    if (!(await timelock.hasRole(PROPOSER_ROLE, proposer))) {
      throw new Error(`Sanity check failed: Configured proposer is missing PROPOSER_ROLE: ${proposer}`);
    }
  }

  for (const executor of timelockExecutors) {
    if (!(await timelock.hasRole(TIMELOCK_EXECUTOR_ROLE, executor))) {
      throw new Error(`Sanity check failed: Configured executor is missing EXECUTOR_ROLE: ${executor}`);
    }
  }

  const hasOpenExecution = await timelock.hasRole(TIMELOCK_EXECUTOR_ROLE, hre.ethers.ZeroAddress);
  if (hasOpenExecution && !isLocalNetwork && process.env.DEPLOYMENT_ENV !== "demo") {
    throw new Error("Sanity check failed: Open executor (ZeroAddress) enabled on production network");
  }

  console.log("✅ All post-deployment sanity checks passed.");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
