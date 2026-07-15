#!/usr/bin/env node
/* eslint-disable no-console */

const fs = require("node:fs");
const path = require("node:path");

const allowedFields = new Set(["roundId", "nullifier", "proofRequired"]);
const forbiddenFields = new Set([
  "address",
  "gasPayer",
  "ipAddress",
  "mac",
  "metadata",
  "mockZKProof",
  "pharmacyAddress",
  "preimage",
  "proof",
  "rawRpcIdentifier",
  "signature",
  "timestamp",
  "userAgent",
  "voter",
  "voterAddress",
  "voucherPreimage",
  "voucherPreimageHash",
  "wallet"
]);

function usage() {
  console.log(`
Proxy Intake Draft / Validator
==============================
Usage:
  node tools/resilience/proxy-validator.js <relayBatchFileOrDirectory> [...]

Validates packaged relay-intake JSON. This does not submit, sign, or authorize
on-chain registration. It checks duplicate nullifiers and rejects sensitive
metadata fields in review batches.
`);
  process.exit(1);
}

function collectJsonFiles(target) {
  const resolved = path.resolve(target);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Path not found: ${target}`);
  }

  const stat = fs.statSync(resolved);
  if (stat.isFile()) return [resolved];

  const files = [];
  for (const entry of fs.readdirSync(resolved)) {
    const fullPath = path.join(resolved, entry);
    const entryStat = fs.statSync(fullPath);
    if (entryStat.isDirectory()) {
      files.push(...collectJsonFiles(fullPath));
    } else if (entry.endsWith(".json")) {
      files.push(fullPath);
    }
  }
  return files;
}

function readBatch(file) {
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed.entries)) return parsed.entries;
  throw new Error(`${file} must contain a relay batch array or { "entries": [...] }`);
}

function assertRelayEntry(entry, file, index) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    throw new Error(`${file} entry ${index} must be an object`);
  }

  for (const key of Object.keys(entry)) {
    if (forbiddenFields.has(key) || !allowedFields.has(key)) {
      throw new Error(`${file} entry ${index} contains forbidden or unsupported field: ${key}`);
    }
  }

  const roundId = Number(entry.roundId);
  if (!Number.isInteger(roundId) || roundId < 0) {
    throw new Error(`${file} entry ${index} has invalid roundId`);
  }

  if (!/^0x[0-9a-fA-F]{64}$/.test(String(entry.nullifier))) {
    throw new Error(`${file} entry ${index} has invalid nullifier`);
  }

  if (
    typeof entry.proofRequired !== "string" ||
    !entry.proofRequired.includes("verifier-signed mock ZK attestation")
  ) {
    throw new Error(`${file} entry ${index} must declare verifier-signed mock ZK attestation requirement`);
  }
}

function main() {
  const targets = process.argv.slice(2);
  if (targets.length === 0) usage();

  const files = targets.flatMap(collectJsonFiles).sort();
  if (files.length === 0) {
    throw new Error("No JSON relay batch files found");
  }

  const nullifiers = new Map();
  let entriesChecked = 0;

  for (const file of files) {
    const entries = readBatch(file);
    entries.forEach((entry, index) => {
      assertRelayEntry(entry, file, index);
      const nullifier = String(entry.nullifier).toLowerCase();
      if (nullifiers.has(nullifier)) {
        throw new Error(`Duplicate nullifier detected across relay batches: ${entry.nullifier} in ${file} and ${nullifiers.get(nullifier)}`);
      }
      nullifiers.set(nullifier, file);
      entriesChecked++;
    });
  }

  console.log("PROXY INTAKE VALIDATION PASSED");
  console.log(`Files checked: ${files.length}`);
  console.log(`Entries checked: ${entriesChecked}`);
  console.log("Boundary: relay batches remain review/intake artifacts, not on-chain submission authority.");
}

try {
  main();
} catch (error) {
  console.error(`PROXY INTAKE VALIDATION FAILED: ${error.message}`);
  process.exitCode = 1;
}
