const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

function usage() {
  console.log(`
Usage:
  node scripts/verify-export.js --file <export_json_file> [options]

Options:
  --rpc <url>               Ethereum JSON-RPC URL
  --confirmations <count>   Minimum confirmations required (default: 1)
  --allow-incomplete        Allow verifying exports that are missing Merkle proof material
  --allow-partial           Allow verifying exports that are marked as partial
`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      if (key === "allow-incomplete") {
        args.allowIncomplete = true;
      } else if (key === "allow-partial") {
        args.allowPartial = true;
      } else {
        args[key] = argv[i + 1];
      }
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

function verifyPayload(payload, options = {}) {
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

  if (payload.schema_version === undefined) {
    fail(errors, "Completeness field schema_version is missing.");
  } else {
    if (payload.schema_version !== "1.1.0") {
      fail(errors, "Unsupported schema_version; expected 1.1.0.");
    }
    if (payload.is_partial === undefined) {
      fail(errors, "Completeness field is_partial is missing.");
    } else if (typeof payload.is_partial !== "boolean") {
      fail(errors, "is_partial must be a boolean.");
    }
    if (payload.warnings === undefined) {
      fail(errors, "Completeness field warnings is missing.");
    } else if (!Array.isArray(payload.warnings)) {
      fail(errors, "warnings must be an array.");
    } else if (payload.warnings.some((warning) => typeof warning !== "string")) {
      fail(errors, "warnings entries must be strings.");
    }
  }

  if (payload.is_partial === false && Array.isArray(payload.warnings) && payload.warnings.length > 0) {
    fail(errors, "A complete export cannot contain partial-export warnings.");
  }

  if (payload.is_partial === true) {
    if (options.allowPartial) {
      if (Array.isArray(payload.warnings)) {
        for (const w of payload.warnings) {
          warnings.push(`[Partial Export Warning] ${w}`);
        }
      } else {
        warnings.push("Export is marked as partial.");
      }
    } else {
      fail(errors, "Export is marked as partial (contains query failures). Use --allow-partial to override.");
      if (Array.isArray(payload.warnings)) {
        for (const w of payload.warnings) {
          fail(errors, `[Partial Export Error] ${w}`);
        }
      }
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

  if (payload.claims.length > 0 || payload.votes.length > 0 || payload.receipts.length > 0) {
    warnings.push("Offline mode checks untrusted export self-consistency only; use --rpc and confirmed roots for chain provenance.");
  }

  for (const claim of payload.claims) {
    const demoFields = claim.syntheticDemoFields || claim;
    const receipt = receiptsByHash.get(String(claim.transactionHash || "").toLowerCase());
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

    if (!receipt) {
      fail(errors, `Claim ${claim.claimId || "(unknown)"} is missing a matching receipt.`);
    } else if (receipt.details?.type !== "Claimed") {
      fail(errors, `Claim ${claim.claimId || "(unknown)"} matching receipt is not a Claimed event.`);
    }

    if (demoFields.metadataProvenance !== "synthetic-placeholder" && demoFields.ndc === "unavailable-off-chain") {
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

  for (const claim of payload.claims) {
    const receipt = receiptsByHash.get(String(claim.transactionHash || "").toLowerCase());
    if (!receipt || receipt.details?.type !== "Claimed") continue;
    const matchingProofs = payload.merkle_proofs.filter((proof) => {
      try {
        return (
          Number(proof.blockNumber) === Number(receipt.blockNumber) &&
          ethers.getAddress(proof.pharmacy) === ethers.getAddress(claim.pharmacyAddress)
        );
      } catch {
        return false;
      }
    });
    if (matchingProofs.length !== 1) {
      if (options.allowIncomplete && payload.merkle_proofs.length === 0) {
        continue;
      }
      fail(errors, `Claim ${claim.claimId || "(unknown)"} must have exactly one matching Merkle proof for its receipt block and pharmacy.`);
      continue;
    }
    const proof = matchingProofs[0];
    if (String(proof.grossAmount) !== String(receipt.details.grossAmount)) {
      fail(errors, `Claim ${claim.claimId || "(unknown)"} proof grossAmount does not match receipt details.`);
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
    if (options.allowIncomplete) {
      warnings.push("Claims exist without Merkle proof material; export is not independently claim-verifiable.");
    } else {
      fail(errors, "Claims exist without Merkle proof material; export is not independently claim-verifiable (use --allow-incomplete to override).");
    }
  }

  return { ok: errors.length === 0, errors, warnings };
}

const TREASURY_ABI = [
  "event Claimed(uint256 indexed epoch, address indexed pharmacy, uint256 grossAmount, uint256 netToPharmacy, uint256 patientShare)",
  "function epochMerkleRoot(uint256 epoch) view returns (bytes32)"
];
const PB_ABI = [
  "event VoteCast(uint256 indexed roundId, uint256 indexed projectId, address indexed voter)"
];

async function verifyPayloadOnChain(payload, options = {}) {
  const errors = [];
  const warnings = [];
  const provider = options.provider || new ethers.JsonRpcProvider(options.rpc);
  const confirmations = Number(options.confirmations ?? 1);
  const network = await provider.getNetwork();
  const latestBlock = await provider.getBlockNumber();

  if (!payload.chain || BigInt(payload.chain.chainId) !== network.chainId) {
    fail(errors, "Export chainId does not match the connected network.");
    return { ok: false, errors, warnings };
  }

  let treasuryAddress;
  let pbAddress;
  try {
    treasuryAddress = ethers.getAddress(payload.chain.treasuryAddress);
    pbAddress = ethers.getAddress(payload.chain.participatoryBudgetingAddress);
  } catch {
    return { ok: false, errors: ["Export contains invalid contract provenance addresses."], warnings };
  }

  const treasuryInterface = new ethers.Interface(TREASURY_ABI);
  const pbInterface = new ethers.Interface(PB_ABI);
  const treasury = new ethers.Contract(treasuryAddress, TREASURY_ABI, provider);

  for (const exportedReceipt of payload.receipts) {
    const receipt = await provider.getTransactionReceipt(exportedReceipt.hash);
    if (!receipt) {
      fail(errors, `Transaction ${exportedReceipt.hash} does not exist on the connected chain.`);
      continue;
    }
    if (receipt.status !== 1) fail(errors, `Transaction ${exportedReceipt.hash} was not successful.`);
    if (receipt.blockHash.toLowerCase() !== String(exportedReceipt.blockHash).toLowerCase()) {
      fail(errors, `Transaction ${exportedReceipt.hash} block hash does not match export provenance.`);
    }
    if (latestBlock - receipt.blockNumber + 1 < confirmations) {
      fail(errors, `Transaction ${exportedReceipt.hash} lacks ${confirmations} confirmations.`);
    }

    const expectedAddress = exportedReceipt.details?.type === "Claimed" ? treasuryAddress : pbAddress;
    if (ethers.getAddress(exportedReceipt.contractAddress) !== expectedAddress) {
      fail(errors, `Transaction ${exportedReceipt.hash} has the wrong exported contract address.`);
      continue;
    }

    const log = receipt.logs.find(item =>
      item.index === exportedReceipt.logIndex && ethers.getAddress(item.address) === expectedAddress
    );
    if (!log) {
      fail(errors, `Transaction ${exportedReceipt.hash} is missing the exported event log.`);
      continue;
    }

    try {
      const parsed = (expectedAddress === treasuryAddress ? treasuryInterface : pbInterface).parseLog(log);
      if (parsed.name !== exportedReceipt.details.type) {
        fail(errors, `Transaction ${exportedReceipt.hash} event type does not match export.`);
      } else if (parsed.name === "Claimed") {
        const claim = payload.claims.find(item => item.transactionHash.toLowerCase() === exportedReceipt.hash.toLowerCase());
        if (!claim || ethers.getAddress(parsed.args.pharmacy) !== ethers.getAddress(claim.pharmacyAddress)) {
          fail(errors, `Transaction ${exportedReceipt.hash} claim participant does not match the on-chain event.`);
        }
        if (
          String(parsed.args.grossAmount) !== String(exportedReceipt.details.grossAmount) ||
          String(parsed.args.netToPharmacy) !== String(exportedReceipt.details.netToPharmacy) ||
          String(parsed.args.patientShare) !== String(exportedReceipt.details.patientShare)
        ) {
          fail(errors, `Transaction ${exportedReceipt.hash} claim amounts do not match the on-chain event.`);
        }
        const matchingProofs = payload.merkle_proofs.filter((item) => {
          try {
            return (
              Number(item.blockNumber) === receipt.blockNumber &&
              ethers.getAddress(item.pharmacy) === ethers.getAddress(parsed.args.pharmacy)
            );
          } catch {
            return false;
          }
        });
        if (matchingProofs.length !== 1) {
          fail(errors, `Transaction ${exportedReceipt.hash} must have exactly one matching Merkle proof.`);
        } else {
          const proof = matchingProofs[0];
          const onChainRoot = await treasury.epochMerkleRoot(parsed.args.epoch);
          if (onChainRoot.toLowerCase() !== proof.claimRoot.toLowerCase()) {
            fail(errors, `Epoch ${parsed.args.epoch} Merkle root does not match the confirmed on-chain root.`);
          }
        }
      } else if (parsed.name === "VoteCast") {
        if (ethers.getAddress(parsed.args.voter) !== ethers.getAddress(payload.exporter)) {
          fail(errors, `Transaction ${exportedReceipt.hash} voter does not match exporter.`);
        }
        if (
          Number(parsed.args.roundId) !== Number(exportedReceipt.details.roundId) ||
          Number(parsed.args.projectId) !== Number(exportedReceipt.details.projectId)
        ) {
          fail(errors, `Transaction ${exportedReceipt.hash} vote round/project does not match the on-chain event.`);
        }
      }
    } catch (err) {
      fail(errors, `Transaction ${exportedReceipt.hash} event could not be decoded: ${err.message}`);
    }
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
  const result = verifyPayload(payload, {
    allowIncomplete: Boolean(opts.allowIncomplete || args.allowIncomplete),
    allowPartial: Boolean(opts.allowPartial || args.allowPartial)
  });

  if (result.ok && (opts.provider || opts.rpc || args.rpc)) {
    const chainResult = await verifyPayloadOnChain(payload, {
      provider: opts.provider,
      rpc: opts.rpc || args.rpc,
      confirmations: opts.confirmations || args.confirmations
    });
    result.ok = chainResult.ok;
    result.errors.push(...chainResult.errors);
    result.warnings.push(...chainResult.warnings);
  } else if (result.ok) {
    result.warnings.push("Offline mode verifies structure and Merkle math only; use --rpc for chain provenance.");
  }

  if (result.ok) {
    if (payload.is_partial === true) {
      console.log("partial accepted with override");
    } else {
      const rpcEnabled = Boolean(opts.provider || opts.rpc || args.rpc);
      console.log(
        rpcEnabled
          ? "RPC provenance verification passed."
          : "OFFLINE STRUCTURE CHECK PASSED - NOT CHAIN PROVENANCE."
      );
    }
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
  verifyPayloadOnChain,
  main
};
