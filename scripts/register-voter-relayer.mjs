import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { ethers } from "ethers";

function usage() {
  console.log(`
Usage:
  RELAYER_PRIVATE_KEY=<relayer_eth_private_key> node scripts/register-voter-relayer.mjs --credential <vc_json_file> --voter <ethereum_address> --round <id> --contract <address> --issuer-key <issuer_public_key_file>
  node scripts/register-voter-relayer.mjs --credential <vc_json_file> --voter <ethereum_address> --round <id> --contract <address> --key-file <relayer_private_key_file> --issuer-key <issuer_public_key_file>

Example:
  RELAYER_PRIVATE_KEY=0x... node scripts/register-voter-relayer.mjs --credential tools/credentials/signed_pharmacy.json --voter 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --round 1 --contract 0x5FbDB2315678afecb367f032d93F642f64180aa3 --issuer-key tools/credentials/issuer_public.key
`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      args[arg.slice(2)] = argv[i + 1];
    }
  }
  return args;
}

function canonicalize(obj) {
  function sortKeys(value) {
    if (value === null || typeof value !== "object") {
      return value;
    }
    if (Array.isArray(value)) {
      return value.map(sortKeys);
    }
    const sorted = {};
    const keys = Object.keys(value).sort();
    for (const key of keys) {
      sorted[key] = sortKeys(value[key]);
    }
    return sorted;
  }
  return JSON.stringify(sortKeys(obj));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const credFile = args["credential"];
  const voterAddr = args["voter"];
  const roundIdRaw = args["round"];
  const contractAddr = args["contract"];
  const relayerKeyFile = args["key-file"];
  const issuerKeyFile = args["issuer-key"];
  const relayerPrivateKey = process.env.RELAYER_PRIVATE_KEY
    || (relayerKeyFile ? fs.readFileSync(path.resolve(process.cwd(), relayerKeyFile), "utf8").trim() : "");

  if (!credFile || !voterAddr || !roundIdRaw || !contractAddr || !relayerPrivateKey || !issuerKeyFile) {
    usage();
    process.exitCode = 1;
    return;
  }

  const roundId = BigInt(roundIdRaw);

  // 1. Verify W3C Verifiable Credential Ed25519 signature
  console.log("Loading Verifiable Credential and public key...");
  const vc = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), credFile), "utf8"));
  const publicKeyPem = fs.readFileSync(path.resolve(process.cwd(), issuerKeyFile), "utf8");

  if (!vc.proof || !vc.proof.proofValue) {
    console.error("Verification Failed: Missing cryptographic proof signature!");
    process.exitCode = 1;
    return;
  }

  const signatureHex = vc.proof.proofValue;
  const vcToVerify = { ...vc };
  delete vcToVerify.proof;

  const payload = canonicalize(vcToVerify);
  const signatureBuffer = Buffer.from(signatureHex, "hex");

  console.log("Validating cryptographic credential signature...");
  const isValid = crypto.verify(null, Buffer.from(payload), publicKeyPem, signatureBuffer);

  if (!isValid) {
    console.error("Verification Failed: Invalid credential signature or modified payload!");
    process.exitCode = 1;
    return;
  }

  console.log("✅ Credential verified successfully.");
  console.log(`  Subject ID: ${vc.credentialSubject.id}`);
  console.log(`  Role Type:  ${vc.type.join(", ")}`);

  // 2. Generate on-chain registration ECDSA signature using relayer key
  console.log("\nGenerating on-chain voter registration signature...");
  const wallet = new ethers.Wallet(relayerPrivateKey);

  const messageHash = ethers.solidityPackedKeccak256(
    ["uint256", "address", "address"],
    [roundId, voterAddr, contractAddr]
  );
  
  const messageHashBytes = ethers.toBeArray(messageHash);
  const signature = await wallet.signMessage(messageHashBytes);

  console.log("\n==================================================");
  console.log("✅ ON-CHAIN REGISTRATION SIGNATURE GENERATED");
  console.log("==================================================");
  console.log(`Relayer Address:  ${wallet.address}`);
  console.log(`Voter Address:    ${voterAddr}`);
  console.log(`Round ID:         ${roundId}`);
  console.log(`Contract:         ${contractAddr}`);
  console.log(`Signature:        ${signature}`);
  console.log("==================================================\n");
  console.log("Call `registerVoterWithSignature` on-chain with:");
  console.log(`  roundId:   ${roundId}`);
  console.log(`  voter:     ${voterAddr}`);
  console.log(`  signature: ${signature}`);
}

main().catch(err => {
  console.error("Error:", err.message);
  process.exitCode = 1;
});
