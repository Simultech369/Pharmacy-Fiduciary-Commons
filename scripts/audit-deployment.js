/* eslint-disable no-console */

const hre = require("hardhat");

const SAFE_ABI = [
  "function getOwners() view returns (address[])",
  "function getThreshold() view returns (uint256)",
];

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required env var: ${name}`);
  return value;
}

function parseAddressList(value) {
  if (!value) return [];
  return value.split(",").map((entry) => entry.trim()).filter(Boolean);
}

function resolveExpectedExecutors() {
  if (process.env.TIMELOCK_EXECUTORS) return parseAddressList(process.env.TIMELOCK_EXECUTORS);
  if (process.env.ALLOW_OPEN_TIMELOCK_EXECUTOR === "true") return [hre.ethers.ZeroAddress];
  throw new Error(
    "TIMELOCK_EXECUTORS is required. Set ALLOW_OPEN_TIMELOCK_EXECUTOR=true only if open execution is intentional."
  );
}

function normalized(address) {
  return hre.ethers.getAddress(address);
}

function normalizeList(items) {
  return items.map(normalized);
}

async function main() {
  const expected = {
    timelock: normalized(requireEnv("TIMELOCK_ADDRESS")),
    treasury: normalized(requireEnv("TREASURY_ADDRESS")),
    token: normalized(requireEnv("TOKEN")),
    patientFund: normalized(requireEnv("PATIENT_FUND")),
    environmentalFund: normalized(requireEnv("ENVIRONMENTAL_FUND")),
    council: normalized(requireEnv("COUNCIL")),
    rootConfirmer: normalized(requireEnv("ROOT_CONFIRMER")),
    guardian: normalized(requireEnv("GUARDIAN")),
    dailyCap: BigInt(process.env.EXPECTED_DAILY_VOLUME_CAP ?? requireEnv("INITIAL_DAILY_CAP")),
    hardCap: BigInt(
      process.env.EXPECTED_HARD_ABSOLUTE_VOLUME_CAP ??
      (BigInt(process.env.EXPECTED_DAILY_VOLUME_CAP ?? requireEnv("INITIAL_DAILY_CAP")) * 10n).toString()
    ),
    minimumEpochVolume: BigInt(requireEnv("MINIMUM_EPOCH_VOLUME")),
    timelockDelay: BigInt(process.env.TIMELOCK_MIN_DELAY_SECONDS ?? "172800"),
    proposers: parseAddressList(process.env.TIMELOCK_PROPOSERS ?? requireEnv("COUNCIL")).map(normalized),
    executors: resolveExpectedExecutors().map(normalized),
    defaultAdmins: normalizeList(parseAddressList(process.env.EXPECTED_DEFAULT_ADMINS ?? requireEnv("COUNCIL"))),
    councilMembers: normalizeList(parseAddressList(process.env.EXPECTED_COUNCIL_MEMBERS ?? requireEnv("COUNCIL"))),
    rootConfirmers: normalizeList(parseAddressList(process.env.EXPECTED_ROOT_CONFIRMERS ?? requireEnv("ROOT_CONFIRMER"))),
    treasuryExecutors: normalizeList(parseAddressList(process.env.EXPECTED_TREASURY_EXECUTORS ?? requireEnv("TIMELOCK_ADDRESS"))),
    guardians: normalizeList(parseAddressList(process.env.EXPECTED_GUARDIANS ?? requireEnv("GUARDIAN"))),
    councilSafeOwners: normalizeList(parseAddressList(process.env.COUNCIL_SAFE_OWNERS ?? "")),
    councilSafeThreshold: Number(process.env.COUNCIL_SAFE_THRESHOLD ?? "3"),
  };

  const provider = hre.ethers.provider;
  const network = await provider.getNetwork();
  const isLocalNetwork = network.chainId === 31337n || network.chainId === 1337n;
  const strictDeployment = !isLocalNetwork && process.env.DEPLOYMENT_ENV !== "demo";
  const timelock = await hre.ethers.getContractAt("TimelockController", expected.timelock);
  const treasury = await hre.ethers.getContractAt("PBMRebateTreasury", expected.treasury);

  let auditFailed = false;
  function fail(message) {
    console.error(`[AUDIT FAIL] ${message}`);
    auditFailed = true;
  }
  function pass(message) {
    console.log(`[AUDIT PASS] ${message}`);
  }
  function compare(label, actual, wanted) {
    if (String(actual).toLowerCase() !== String(wanted).toLowerCase()) {
      fail(`${label}: expected ${wanted}, found ${actual}`);
    } else {
      pass(`${label}: ${actual}`);
    }
  }
  async function requireRole(contract, role, member, label) {
    if (await contract.hasRole(role, member)) pass(`${label}: ${member}`);
    else fail(`${label} missing: ${member}`);
  }
  function compareAddressSet(label, actualMembers, expectedMembers) {
    const actual = actualMembers.map(normalized).sort((a, b) => a.localeCompare(b));
    const wanted = expectedMembers.map(normalized).sort((a, b) => a.localeCompare(b));
    if (actual.length !== wanted.length || actual.some((item, index) => item !== wanted[index])) {
      fail(`${label}: expected exactly [${wanted.join(", ")}], found [${actual.join(", ")}]`);
    } else {
      pass(`${label}: exact membership [${actual.join(", ")}]`);
    }
  }
  async function requireExactEnumerableRole(contract, role, expectedMembers, label) {
    const count = Number(await contract.getRoleMemberCount(role));
    const actual = [];
    for (let i = 0; i < count; i++) {
      actual.push(await contract.getRoleMember(role, i));
    }
    compareAddressSet(label, actual, expectedMembers);
  }
  async function auditCouncilSafe() {
    const code = await provider.getCode(expected.council);
    if (code === "0x") {
      fail("Council is not a contract wallet/Safe");
      return;
    }

    const safe = new hre.ethers.Contract(expected.council, SAFE_ABI, provider);
    try {
      const owners = await safe.getOwners();
      const threshold = Number(await safe.getThreshold());
      if (threshold !== expected.councilSafeThreshold) {
        fail(`Council Safe threshold: expected ${expected.councilSafeThreshold}, found ${threshold}`);
      } else {
        pass(`Council Safe threshold: ${threshold}`);
      }

      if (expected.councilSafeOwners.length > 0) {
        compareAddressSet("Council Safe owners", owners, expected.councilSafeOwners);
      } else if (owners.length !== 5 || threshold !== 3) {
        fail(`Council Safe must be 3/5 when COUNCIL_SAFE_OWNERS is not supplied; found ${threshold}/${owners.length}`);
      } else {
        pass("Council Safe shape: 3/5");
      }
    } catch (error) {
      fail(`Council address does not expose Safe owner/threshold interface: ${error.message}`);
    }
  }

  console.log("==================================================");
  console.log("RUNNING ON-CHAIN DEPLOYMENT AUDIT");
  console.log(`Network: ${hre.network.name} (${network.chainId})`);
  console.log(`Timelock: ${expected.timelock}`);
  console.log(`Treasury: ${expected.treasury}`);
  console.log("==================================================");

  try {
    compare("Treasury token", await treasury.token(), expected.token);
    compare("Treasury patient fund", await treasury.patientFund(), expected.patientFund);
    compare("Treasury environmental fund", await treasury.environmentalFund(), expected.environmentalFund);
    compare("Treasury epoch volume cap (dailyVolumeCap legacy variable)", await treasury.dailyVolumeCap(), expected.dailyCap);
    compare("Treasury hard cap", await treasury.hardAbsoluteVolumeCap(), expected.hardCap);
    compare("Treasury minimum epoch volume", await treasury.minimumEpochVolume(), expected.minimumEpochVolume);

    const DEFAULT_ADMIN_ROLE = hre.ethers.ZeroHash;
    const COUNCIL_ROLE = await treasury.councilRole();
    const ROOT_CONFIRMER_ROLE = await treasury.rootConfirmerRole();
    const EXECUTOR_ROLE = await treasury.executorRole();
    const GUARDIAN_ROLE = await treasury.guardianRole();

    await requireExactEnumerableRole(treasury, DEFAULT_ADMIN_ROLE, expected.defaultAdmins, "Treasury default admins");
    await requireExactEnumerableRole(treasury, COUNCIL_ROLE, expected.councilMembers, "Treasury council members");
    await requireExactEnumerableRole(treasury, ROOT_CONFIRMER_ROLE, expected.rootConfirmers, "Treasury root confirmers");
    await requireExactEnumerableRole(treasury, EXECUTOR_ROLE, expected.treasuryExecutors, "Treasury executors");
    await requireExactEnumerableRole(treasury, GUARDIAN_ROLE, expected.guardians, "Treasury guardians");

    compare("EXECUTOR_ROLE administrator", await treasury.getRoleAdmin(EXECUTOR_ROLE), EXECUTOR_ROLE);
    compare("ROOT_CONFIRMER_ROLE administrator", await treasury.getRoleAdmin(ROOT_CONFIRMER_ROLE), EXECUTOR_ROLE);

    if (expected.council === expected.rootConfirmer) fail("Council and root confirmer are identical");
    else pass("Council and root confirmer are separate");
    if (expected.council === expected.guardian) fail("Council and guardian are identical");
    else pass("Council and guardian are separate");
    if (expected.rootConfirmer === expected.guardian) fail("Root confirmer and guardian are identical");
    else pass("Root confirmer and guardian are separate");

    if (strictDeployment) {
      await auditCouncilSafe();
    } else {
      pass("Council Safe owner/threshold audit skipped outside strict deployment mode");
    }
  } catch (error) {
    fail(`Treasury audit could not complete: ${error.message}`);
  }

  try {
    const TIMELOCK_ADMIN_ROLE = await timelock.TIMELOCK_ADMIN_ROLE();
    const PROPOSER_ROLE = await timelock.PROPOSER_ROLE();
    const EXECUTOR_ROLE = await timelock.EXECUTOR_ROLE();

    const actualDelay = await timelock.getMinDelay();
    compare("Timelock minimum delay", actualDelay, expected.timelockDelay);
    if (strictDeployment && actualDelay < 86400n) {
      fail(`Timelock minimum delay must be at least 86400 seconds for strict deployments, found ${actualDelay}`);
    }
    await requireRole(timelock, TIMELOCK_ADMIN_ROLE, expected.timelock, "Timelock self-administrator");
    for (const proposer of expected.proposers) {
      await requireRole(timelock, PROPOSER_ROLE, proposer, "Timelock proposer");
    }
    for (const executor of expected.executors) {
      await requireRole(timelock, EXECUTOR_ROLE, executor, "Timelock executor");
    }

    const isOpenExecutor = await timelock.hasRole(EXECUTOR_ROLE, hre.ethers.ZeroAddress);
    if (isOpenExecutor && !isLocalNetwork && process.env.DEPLOYMENT_ENV !== "demo") {
      fail("Open timelock execution is enabled on a non-local, non-demo network");
    } else {
      pass(`Open executor policy is acceptable for this environment: ${isOpenExecutor}`);
    }

    if (strictDeployment && process.env.RENOUNCE_TIMELOCK_ADMIN !== "true") {
      fail("Strict deployments must set RENOUNCE_TIMELOCK_ADMIN=true");
    }
    if (strictDeployment && !process.env.TIMELOCK_ADMIN) {
      fail("Strict deployments must provide TIMELOCK_ADMIN so retained setup-admin state can be audited");
    }
    if (process.env.TIMELOCK_ADMIN) {
      const externalAdmin = normalized(process.env.TIMELOCK_ADMIN);
      const retained = await timelock.hasRole(TIMELOCK_ADMIN_ROLE, externalAdmin);
      if (strictDeployment && retained) {
        fail(`Temporary timelock administrator was retained in strict deployment: ${externalAdmin}`);
      } else if (process.env.RENOUNCE_TIMELOCK_ADMIN === "true" && retained) {
        fail(`Temporary timelock administrator was not renounced: ${externalAdmin}`);
      } else if (process.env.RENOUNCE_TIMELOCK_ADMIN !== "true" && !retained) {
        fail(`Expected retained timelock administrator is missing: ${externalAdmin}`);
      } else {
        pass(`External timelock administrator state matches configuration: ${retained}`);
      }
    }
  } catch (error) {
    fail(`Timelock audit could not complete: ${error.message}`);
  }

  console.log("==================================================");
  if (auditFailed) {
    console.error("AUDIT FAILED - DEPLOYMENT DOES NOT MATCH EXPECTED CONFIGURATION");
    process.exitCode = 1;
  } else {
    console.log("AUDIT PASSED - CHECKED DEPLOYMENT STATE MATCHES EXPECTED CONFIGURATION");
  }
  console.log("==================================================");
}

main().catch((error) => {
  console.error("Audit script failed to execute:", error.message);
  process.exitCode = 1;
});
