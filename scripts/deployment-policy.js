const DEFAULT_ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const MIN_NON_LOCAL_TIMELOCK_DELAY_SECONDS = 86400n;

function normalizeAddress(address) {
  return String(address ?? "").toLowerCase();
}

function hasOpenTimelockExecutor(timelockExecutors, zeroAddress = DEFAULT_ZERO_ADDRESS) {
  const normalizedZero = normalizeAddress(zeroAddress);
  return timelockExecutors.some((executor) => normalizeAddress(executor) === normalizedZero);
}

function assertDeploymentPreflight({
  deployerAddress,
  isLocalNetwork,
  minDelaySeconds,
  renounceSetupAdmin,
  timelockAdmin,
  timelockExecutors,
  zeroAddress = DEFAULT_ZERO_ADDRESS,
  initialDailyCap,
  minimumEpochVolume,
  council,
  rootConfirmer,
  guardian,
}) {
  if (initialDailyCap !== undefined && BigInt(initialDailyCap) === 0n) {
    throw new Error("INITIAL_DAILY_CAP must be a non-zero integer (as a string).");
  }
  if (minimumEpochVolume !== undefined && BigInt(minimumEpochVolume) === 0n) {
    throw new Error("MINIMUM_EPOCH_VOLUME must be a non-zero integer in token base units.");
  }

  if (council && rootConfirmer && normalizeAddress(council) === normalizeAddress(rootConfirmer)) {
    throw new Error("Sanity check failed: Council cannot be confirmer");
  }
  if (council && guardian && normalizeAddress(council) === normalizeAddress(guardian)) {
    throw new Error("Sanity check failed: Council cannot be guardian");
  }

  if (renounceSetupAdmin && normalizeAddress(timelockAdmin) !== normalizeAddress(deployerAddress)) {
    throw new Error("RENOUNCE_TIMELOCK_ADMIN=true requires TIMELOCK_ADMIN to equal the deployer.");
  }

  if (isLocalNetwork) {
    return;
  }

  if (!renounceSetupAdmin) {
    throw new Error("Safety violation: RENOUNCE_TIMELOCK_ADMIN=true must be specified for non-local network deployments.");
  }

  if (BigInt(minDelaySeconds) < MIN_NON_LOCAL_TIMELOCK_DELAY_SECONDS) {
    throw new Error("Safety violation: TIMELOCK_MIN_DELAY_SECONDS must be at least 86400 for non-local deployments.");
  }

  if (hasOpenTimelockExecutor(timelockExecutors, zeroAddress)) {
    throw new Error("Safety violation: Open execution (ZeroAddress executor) is not allowed on non-local networks.");
  }
}

module.exports = {
  assertDeploymentPreflight,
  hasOpenTimelockExecutor,
};
