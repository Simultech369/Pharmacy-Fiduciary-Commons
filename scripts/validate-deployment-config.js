/* eslint-disable no-console */

const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const ZERO = ethers.ZeroAddress.toLowerCase();

function usage() {
  console.log(`
Usage:
  node scripts/validate-deployment-config.js --parameters <json> --governance <json> [--allow-placeholders]

Validates parameter calibration, Merkle distribution boundaries, 3/5 Safe council
shape, role separation, and timelock settings. Placeholder mode validates template
shape only; real deployment configs must omit --allow-placeholders.
`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    if (key === "allow-placeholders") {
      args[key] = true;
    } else {
      args[key] = argv[i + 1];
      i++;
    }
  }
  return args;
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(path.resolve(filePath), "utf8"));
}

function isPlaceholder(value) {
  return typeof value === "string" && /^<[^>]+>$/.test(value);
}

function requireField(value, label) {
  if (value === undefined || value === null || value === "") {
    throw new Error(`Missing required field: ${label}`);
  }
}

function address(value, label, allowPlaceholders) {
  requireField(value, label);
  if (allowPlaceholders && isPlaceholder(value)) return value;
  const normalized = ethers.getAddress(value);
  if (normalized.toLowerCase() === ZERO) {
    throw new Error(`${label} cannot be the zero address`);
  }
  return normalized;
}

function assertUnique(addresses, label) {
  const normalized = addresses.map((item) => item.toLowerCase());
  if (new Set(normalized).size !== normalized.length) {
    throw new Error(`${label} must be unique`);
  }
}

function parseUnitsHuman(value, decimals, label, allowPlaceholders) {
  requireField(value, label);
  if (allowPlaceholders && isPlaceholder(value)) return null;
  return ethers.parseUnits(String(value), decimals);
}

function validateParameters(parameters, allowPlaceholders) {
  const token = parameters.payoutToken ?? {};
  const treasury = parameters.treasuryParameters ?? {};
  const merkle = parameters.merkleProofDistribution ?? {};

  const decimals = Number(token.decimals);
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) {
    throw new Error("payoutToken.decimals must be an integer from 0 to 36");
  }
  address(token.address, "payoutToken.address", allowPlaceholders);

  if (!allowPlaceholders && treasury.initialDailyCapHuman !== undefined) {
    throw new Error("treasuryParameters.initialDailyCapHuman is legacy wording; use initialEpochVolumeCapHuman for real deployment configs");
  }
  const epochVolumeCapHuman = treasury.initialEpochVolumeCapHuman ?? treasury.initialDailyCapHuman;
  const initialEpochVolumeCap = parseUnitsHuman(epochVolumeCapHuman, decimals, "treasuryParameters.initialEpochVolumeCapHuman", allowPlaceholders);
  const minimumEpochVolume = parseUnitsHuman(treasury.minimumEpochVolumeHuman, decimals, "treasuryParameters.minimumEpochVolumeHuman", allowPlaceholders);
  if (initialEpochVolumeCap !== null && minimumEpochVolume !== null && initialEpochVolumeCap < minimumEpochVolume) {
    throw new Error("initialEpochVolumeCapHuman must be greater than or equal to minimumEpochVolumeHuman");
  }

  const governanceBP = Number(treasury.governanceBP);
  if (!Number.isInteger(governanceBP) || governanceBP < 0 || governanceBP > 500) {
    throw new Error("governanceBP must be an integer from 0 to 500");
  }

  const patientClaimBP = Number(treasury.patientClaimBP);
  if (!Number.isInteger(patientClaimBP) || patientClaimBP < 500 || patientClaimBP > 3000) {
    throw new Error("patientClaimBP must be an integer from 500 to 3000");
  }

  if (Number(treasury.recallDelaySeconds) !== 2592000) {
    throw new Error("recallDelaySeconds must match the contract constant: 2592000");
  }
  if (Number(treasury.rootProposalExpirySeconds) !== 259200) {
    throw new Error("rootProposalExpirySeconds must match the contract constant: 259200");
  }
  if (Number(treasury.staleDistributionRecoveryDelaySeconds) !== 15552000) {
    throw new Error("staleDistributionRecoveryDelaySeconds must match the contract constant: 15552000");
  }

  for (const field of ["rootPublisher", "rootConfirmer", "proofTransport", "pharmacyIdentityBinding"]) {
    requireField(merkle[field], `merkleProofDistribution.${field}`);
  }
  if (!Array.isArray(merkle.prePublicationChecks) || merkle.prePublicationChecks.length < 3) {
    throw new Error("merkleProofDistribution.prePublicationChecks must list concrete checks");
  }

  return { initialEpochVolumeCap, minimumEpochVolume };
}

function validateGovernance(governance, allowPlaceholders) {
  const roles = governance.roles ?? {};
  const safe = roles.councilSafe ?? {};
  const timelock = governance.timelock ?? {};

  const council = address(safe.address, "roles.councilSafe.address", allowPlaceholders);
  const owners = safe.owners ?? [];
  if (safe.threshold !== 3 || owners.length !== 5) {
    throw new Error("roles.councilSafe must be a 3/5 Safe shape");
  }
  const normalizedOwners = owners.map((owner, index) => address(owner, `roles.councilSafe.owners[${index}]`, allowPlaceholders));
  if (!allowPlaceholders) assertUnique(normalizedOwners, "council Safe owners");

  const rootConfirmer = address(roles.rootConfirmer, "roles.rootConfirmer", allowPlaceholders);
  const guardian = address(roles.guardian, "roles.guardian", allowPlaceholders);
  address(roles.environmentalFund, "roles.environmentalFund", allowPlaceholders);
  address(roles.patientFund, "roles.patientFund", allowPlaceholders);

  if (!allowPlaceholders) {
    assertUnique([council, rootConfirmer, guardian], "council, rootConfirmer, and guardian");
  }

  const minDelay = Number(timelock.minDelaySeconds);
  if (!Number.isInteger(minDelay) || minDelay < 86400) {
    throw new Error("timelock.minDelaySeconds must be at least 86400 seconds");
  }
  if (timelock.allowOpenExecutor === true) {
    throw new Error("timelock.allowOpenExecutor must be false for public/testnet deployment configs");
  }
  if (timelock.renounceSetupAdmin !== true) {
    throw new Error("timelock.renounceSetupAdmin must be true unless an explicit retained-admin exception is documented elsewhere");
  }

  address(timelock.admin, "timelock.admin", allowPlaceholders);
  const proposers = timelock.proposers ?? [];
  const executors = timelock.executors ?? [];
  if (proposers.length === 0 || executors.length === 0) {
    throw new Error("timelock.proposers and timelock.executors must be non-empty");
  }
  proposers.forEach((proposer, index) => address(proposer, `timelock.proposers[${index}]`, allowPlaceholders));
  executors.forEach((executor, index) => address(executor, `timelock.executors[${index}]`, allowPlaceholders));

  return { council, rootConfirmer, guardian, minDelay };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.parameters || !args.governance) {
    usage();
    process.exitCode = 1;
    return;
  }

  const allowPlaceholders = Boolean(args["allow-placeholders"]);
  const parameters = readJson(args.parameters);
  const governance = readJson(args.governance);

  const derived = validateParameters(parameters, allowPlaceholders);
  validateGovernance(governance, allowPlaceholders);

  console.log("Deployment configuration validation passed.");
  if (!allowPlaceholders) {
    console.log("Derived deployment environment values:");
    console.log(`INITIAL_DAILY_CAP=${derived.initialEpochVolumeCap.toString()} # legacy contract env; epoch-volume cap`);
    console.log(`MINIMUM_EPOCH_VOLUME=${derived.minimumEpochVolume.toString()}`);
    console.log(`GOVERNANCE_BP=${parameters.treasuryParameters.governanceBP}`);
    console.log(`RECALL_DELAY_SECONDS=${parameters.treasuryParameters.recallDelaySeconds}`);
  } else {
    console.log("Placeholder mode used: replace placeholders and rerun without --allow-placeholders before deployment.");
  }
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
