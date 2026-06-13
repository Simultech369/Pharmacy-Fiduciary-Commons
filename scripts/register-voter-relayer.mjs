import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { canonicalize, verifyCredential } from "../tools/credentials/credential-policy.mjs";

export const CREDENTIAL_POLICY_VERSION = ethers.keccak256(
  ethers.toUtf8Bytes("fiduciary-credential-policy-v1")
);

export const REGISTRATION_DOMAIN_NAME = "Pharmacy Fiduciary Commons";
export const REGISTRATION_DOMAIN_VERSION = "1";
export const REGISTRATION_TYPES = {
  VoterRegistration: [
    { name: "roundId", type: "uint256" },
    { name: "voter", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "credentialHash", type: "bytes32" },
    { name: "policyVersion", type: "bytes32" },
    { name: "deadline", type: "uint256" }
  ]
};

function usage() {
  console.log(`
Usage:
  RELAYER_PRIVATE_KEY=<key> node scripts/register-voter-relayer.mjs --credential <vc_json_file> --voter <address> --round <id> --contract <address> --chain-id <id> --nonce <nonce> --issuer-key <public_key_file> [--deadline <unix_seconds>] [--revocations <file>]
`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) args[argv[i].slice(2)] = argv[i + 1];
  }
  return args;
}

export async function createRegistrationAuthorization({
  credential,
  publicKeyPem,
  voter,
  roundId,
  contractAddress,
  chainId,
  nonce,
  relayerPrivateKey,
  revokedCredentialIds = new Set(),
  trustedIssuerKeys,
  now,
  deadline
}) {
  const normalizedVoter = ethers.getAddress(voter);
  verifyCredential({
    credential,
    publicKeyPem,
    expectedVoter: normalizedVoter,
    revokedCredentialIds,
    trustedIssuerKeys,
    now
  });

  const nowMs = now ? new Date(now).getTime() : Date.now();
  const credentialExpiry = Math.floor(Date.parse(credential.expirationDate) / 1000);
  const authorizationDeadline = deadline === undefined
    ? Math.min(Math.floor(nowMs / 1000) + 3600, credentialExpiry)
    : Number(deadline);
  if (!Number.isSafeInteger(authorizationDeadline) || authorizationDeadline <= Math.floor(nowMs / 1000)) {
    throw new Error("Authorization deadline must be a future Unix timestamp.");
  }

  const credentialHash = ethers.keccak256(ethers.toUtf8Bytes(canonicalize(credential)));

  const wallet = new ethers.Wallet(relayerPrivateKey);
  const domain = {
    name: REGISTRATION_DOMAIN_NAME,
    version: REGISTRATION_DOMAIN_VERSION,
    chainId: BigInt(chainId),
    verifyingContract: ethers.getAddress(contractAddress)
  };
  const value = {
    roundId: BigInt(roundId),
    voter: normalizedVoter,
    nonce: BigInt(nonce),
    credentialHash,
    policyVersion: CREDENTIAL_POLICY_VERSION,
    deadline: BigInt(authorizationDeadline)
  };
  const signature = await wallet.signTypedData(domain, REGISTRATION_TYPES, value);

  return {
    signature,
    relayerAddress: wallet.address,
    voter: normalizedVoter,
    credentialHash,
    policyVersion: CREDENTIAL_POLICY_VERSION,
    deadline: authorizationDeadline
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const relayerPrivateKey = process.env.RELAYER_PRIVATE_KEY
    || (args["key-file"] ? fs.readFileSync(path.resolve(args["key-file"]), "utf8").trim() : "");

  if (!args.credential || !args.voter || !args.round || !args.contract || !args["chain-id"] || args.nonce === undefined || !args["issuer-key"] || !relayerPrivateKey) {
    usage();
    process.exitCode = 1;
    return;
  }

  const credential = JSON.parse(fs.readFileSync(path.resolve(args.credential), "utf8"));
  const publicKeyPem = fs.readFileSync(path.resolve(args["issuer-key"]), "utf8");
  const revocationsPath = path.resolve(
    args.revocations ?? "tools/credentials/revoked_credentials.json"
  );
  const revocations = JSON.parse(fs.readFileSync(revocationsPath, "utf8"));

  const result = await createRegistrationAuthorization({
    credential,
    publicKeyPem,
    voter: args.voter,
    roundId: args.round,
    contractAddress: args.contract,
    chainId: args["chain-id"],
    nonce: args.nonce,
    deadline: args.deadline,
    relayerPrivateKey,
    revokedCredentialIds: new Set(revocations.revokedCredentialIds ?? [])
  });

  console.log("Credential policy verification passed.");
  console.log(`Relayer Address: ${result.relayerAddress}`);
  console.log(`Voter Address:   ${result.voter}`);
  console.log(`Round ID:        ${args.round}`);
  console.log(`Contract:        ${ethers.getAddress(args.contract)}`);
  console.log(`Chain ID:        ${args["chain-id"]}`);
  console.log(`Nonce:           ${args.nonce}`);
  console.log(`Credential Hash: ${result.credentialHash}`);
  console.log(`Policy Version:  ${result.policyVersion}`);
  console.log(`Deadline:        ${result.deadline}`);
  console.log(`Signature:       ${result.signature}`);
  console.log(`Authorization:   ${JSON.stringify({
    credentialHash: result.credentialHash,
    policyVersion: result.policyVersion,
    deadline: result.deadline,
    signature: result.signature
  })}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error("Registration authorization failed:", error.message);
    process.exitCode = 1;
  });
}
