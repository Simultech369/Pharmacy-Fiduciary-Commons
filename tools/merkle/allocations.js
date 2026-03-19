/* eslint-disable no-console */

const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

function usage() {
  // Intentionally short; this is internal tooling.
  console.log(
    "Usage: node tools/merkle/allocations.js --in <allocations.json> [--out <merkle.json>]"
  );
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function asBigInt(value, field) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(value);
  if (typeof value === "string") {
    if (!value.length) throw new Error(`${field} must be a non-empty string`);
    return BigInt(value);
  }
  throw new Error(`${field} must be an integer string`);
}

function normalizeAddress(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${field} must be a non-empty string`);
  }
  return ethers.getAddress(value);
}

function hashLeaf(pharmacy, grossAmount, eligibleCap) {
  const inner = ethers.solidityPackedKeccak256(
    ["address", "uint256", "uint256"],
    [pharmacy, grossAmount, eligibleCap]
  );
  return ethers.keccak256(ethers.solidityPacked(["bytes32"], [inner]));
}

function hashPairOZ(a, b) {
  const ai = BigInt(a);
  const bi = BigInt(b);
  const left = ai < bi ? a : b;
  const right = ai < bi ? b : a;
  return ethers.keccak256(ethers.solidityPacked(["bytes32", "bytes32"], [left, right]));
}

function buildTree(leaves) {
  if (leaves.length === 0) return [[ethers.ZeroHash]];

  const levels = [leaves.slice()];
  while (levels[levels.length - 1].length > 1) {
    const prev = levels[levels.length - 1];
    const next = [];

    for (let i = 0; i < prev.length; i += 2) {
      const left = prev[i];
      const right = i + 1 < prev.length ? prev[i + 1] : prev[i];
      next.push(hashPairOZ(left, right));
    }

    levels.push(next);
  }
  return levels;
}

function buildProof(levels, index) {
  const proof = [];
  let idx = index;

  for (let level = 0; level < levels.length - 1; level += 1) {
    const nodes = levels[level];
    const siblingIdx = idx ^ 1;
    const sibling = siblingIdx < nodes.length ? nodes[siblingIdx] : nodes[idx];
    proof.push(sibling);
    idx = Math.floor(idx / 2);
  }

  return proof;
}

function processProof(leaf, proof) {
  let computed = leaf;
  for (const sibling of proof) {
    computed = hashPairOZ(computed, sibling);
  }
  return computed;
}

function parseArgs(argv) {
  const args = { inFile: null, outFile: null };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--in") args.inFile = argv[i + 1];
    if (arg === "--out") args.outFile = argv[i + 1];
  }

  return args;
}

async function main() {
  const { inFile, outFile } = parseArgs(process.argv.slice(2));
  if (!inFile) {
    usage();
    process.exitCode = 2;
    return;
  }

  const inputPath = path.resolve(process.cwd(), inFile);
  const raw = readJson(inputPath);
  const entries = Array.isArray(raw) ? raw : raw?.entries;
  if (!Array.isArray(entries)) {
    throw new Error("Input must be an array or an object with an 'entries' array.");
  }

  const normalized = entries.map((entry, index) => {
    const pharmacy = normalizeAddress(entry.pharmacy, `entries[${index}].pharmacy`);
    const grossAmount = asBigInt(entry.grossAmount, `entries[${index}].grossAmount`);
    const eligibleCap = asBigInt(entry.eligibleCap, `entries[${index}].eligibleCap`);

    return { pharmacy, grossAmount, eligibleCap };
  });

  const leaves = normalized.map((e) => hashLeaf(e.pharmacy, e.grossAmount, e.eligibleCap));
  const levels = buildTree(leaves);
  const root = levels[levels.length - 1][0];

  let totalAmount = 0n;
  for (const e of normalized) totalAmount += e.grossAmount;

  const outputEntries = normalized.map((e, index) => {
    const leaf = leaves[index];
    const proof = buildProof(levels, index);

    return {
      index,
      pharmacy: e.pharmacy,
      grossAmount: e.grossAmount.toString(),
      eligibleCap: e.eligibleCap.toString(),
      leaf,
      proof,
    };
  });

  for (const item of outputEntries) {
    const computed = processProof(item.leaf, item.proof);
    if (computed !== root) {
      throw new Error(`Proof mismatch at index ${item.index}: computed ${computed} != root ${root}`);
    }
  }

  const out = {
    leafEncoding: "keccak256(bytes.concat(keccak256(abi.encodePacked(pharmacy,grossAmount,eligibleCap))))",
    root,
    totalAmount: totalAmount.toString(),
    entries: outputEntries,
  };

  const json = JSON.stringify(out, null, 2);
  if (outFile) {
    const outPath = path.resolve(process.cwd(), outFile);
    fs.writeFileSync(outPath, json + "\n");
    console.log("Wrote:", outPath);
  } else {
    process.stdout.write(json + "\n");
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});

