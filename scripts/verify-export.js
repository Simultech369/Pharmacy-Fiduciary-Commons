const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

function usage() {
  console.log(`
Usage:
  node scripts/verify-export.js --file <export_json_file>
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

function fail(errors, message) {
  errors.push(message);
}

function merkleLeaf(pharmacyAddress, amount, eligibleCap) {
  const inner = ethers.solidityPackedKeccak256(
    ["address", "uint256", "uint256"],
    [pharmacyAddress, amount, eligibleCap]
  );
  return ethers.keccak256(ethers.solidityPacked(["bytes32"], [inner]));
}

function processProof(proof, leaf) {
  let computedHash = leaf;
  for (const proofElement of proof) {
    if (!ethers.isHexString(proofElement, 32)) {
      throw new Error(`Invalid proof element: ${proofElement}`);
    }
    const pair = [computedHash, proofElement].sort();
    computedHash = ethers.keccak256(ethers.solidityPacked(["bytes32", "bytes32"], pair));
  }
  return computedHash;
}

function verifyMerkleProof(proof, root, leaf) {
  return processProof(proof, leaf).toLowerCase() === root.toLowerCase();
}

function verifyPayload(payload) {
  const errors = [];
  const warnings = [];

  if (!payload || typeof payload !== "object") {
    return { ok: false, errors: ["Payload must be a JSON object."], warnings };
  }

  let exporter;
  try {
    exporter = ethers.getAddress(payload.exporter);
  } catch {
    fail(errors, "Missing or invalid exporter address.");
  }

  if (!payload.exported_at || Number.isNaN(Date.parse(payload.exported_at))) {
    fail(errors, "Missing or invalid exported_at timestamp.");
  }

  for (const field of ["claims", "merkle_proofs", "votes", "receipts"]) {
    if (!Array.isArray(payload[field])) {
      fail(errors, `${field} must be an array.`);
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors, warnings };
  }

  const receiptsByHash = new Map();
  for (const receipt of payload.receipts) {
    if (!receipt.hash || !ethers.isHexString(receipt.hash, 32)) {
      fail(errors, `Receipt has invalid hash: ${receipt.hash}`);
      continue;
    }
    receiptsByHash.set(receipt.hash.toLowerCase(), receipt);
  }

  for (const claim of payload.claims) {
    let pharmacy;
    try {
      pharmacy = ethers.getAddress(claim.pharmacyAddress);
    } catch {
      fail(errors, `Claim ${claim.claimId || "(unknown)"} has invalid pharmacyAddress.`);
      continue;
    }

    if (pharmacy !== exporter) {
      fail(errors, `Claim ${claim.claimId || "(unknown)"} pharmacyAddress does not match exporter.`);
    }

    if (!receiptsByHash.has(String(claim.transactionHash || "").toLowerCase())) {
      fail(errors, `Claim ${claim.claimId || "(unknown)"} is missing a matching receipt.`);
    }

    if (claim.metadataProvenance !== "synthetic-placeholder" && claim.ndc === "unavailable-off-chain") {
      fail(errors, `Claim ${claim.claimId || "(unknown)"} has unavailable clinical metadata without synthetic provenance.`);
    }
  }

  for (const proof of payload.merkle_proofs) {
    if (!ethers.isHexString(proof.claimRoot, 32)) {
      fail(errors, `Merkle proof at index ${proof.leafIndex} has invalid claimRoot.`);
      continue;
    }

    try {
      const pharmacy = ethers.getAddress(proof.pharmacy);
      if (pharmacy !== exporter) {
        fail(errors, `Merkle proof at index ${proof.leafIndex} pharmacy does not match exporter.`);
      }

      const leaf = merkleLeaf(pharmacy, BigInt(proof.grossAmount), BigInt(proof.eligibleCap));
      const proofItems = Array.isArray(proof.proof) ? proof.proof : [];
      const valid = verifyMerkleProof(proofItems, proof.claimRoot, leaf);
      if (!valid) {
        fail(errors, `Merkle proof at index ${proof.leafIndex} does not verify against claimRoot.`);
      }
    } catch (err) {
      fail(errors, `Merkle proof at index ${proof.leafIndex} is malformed: ${err.message}`);
    }
  }

  for (const vote of payload.votes) {
    try {
      const voter = ethers.getAddress(vote.voter);
      if (voter !== exporter) {
        fail(errors, `Vote for project ${vote.project || "(unknown)"} voter does not match exporter.`);
      }
    } catch {
      fail(errors, `Vote for project ${vote.project || "(unknown)"} has invalid voter address.`);
    }
  }

  if (payload.merkle_proofs.length === 0 && payload.claims.length > 0) {
    warnings.push("Claims exist without Merkle proof material; export is not independently claim-verifiable.");
  }

  return { ok: errors.length === 0, errors, warnings };
}

async function main(opts = {}) {
  const args = parseArgs(process.argv.slice(2));
  const filePath = opts.file || args.file;

  if (!filePath) {
    usage();
    process.exitCode = 1;
    return;
  }

  const payload = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), filePath), "utf8"));
  const result = verifyPayload(payload);

  if (result.ok) {
    console.log("Portability export verification passed.");
    for (const warning of result.warnings) {
      console.log(`Warning: ${warning}`);
    }
  } else {
    console.error("Portability export verification failed.");
    for (const error of result.errors) {
      console.error(`- ${error}`);
    }
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main().catch(err => {
    console.error("Verification script failed:", err.message);
    process.exitCode = 1;
  });
}

module.exports = {
  merkleLeaf,
  processProof,
  verifyPayload,
  verifyMerkleProof,
  main
};
