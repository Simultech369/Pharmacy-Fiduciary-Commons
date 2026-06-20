const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

function sanitizeWarning(msg) {
  if (!msg) return "";
  let sanitized = msg;
  // 1. Redact http/https URLs (with or without credentials) before scanning
  //    key/value patterns so URL path segments such as `/mykey:` are not
  //    mistaken for standalone credential fields.
  sanitized = sanitized.replace(/https?:\/\/[^\s'"\(\)\[\]]+/gi, (url) => {
    const trailing = url.match(/[.,:;!]+$/);
    return "[URL_REDACTED]" + (trailing ? trailing[0] : "");
  });
  // 2. Redact credentials or auth tokens in standard key/value patterns.
  sanitized = sanitized.replace(/(key|auth|api-key|secret|password|pass|token|credential)\s*[=:]\s*[^\s,;]+/gi, "$1=[REDACTED]");
  sanitized = sanitized.replace(/\bauthorization\s*:\s*(?:bearer\s+)?[^\s,;]+/gi, "authorization: [REDACTED]");
  // 3. Redact Windows absolute paths
  sanitized = sanitized.replace(/[a-zA-Z]:\\[^\s'"\(\)\[\]]+/g, (pathStr) => {
    const trailing = pathStr.match(/[.,:;!]+$/);
    return "[PATH_REDACTED]" + (trailing ? trailing[0] : "");
  });
  // 4. Redact Unix absolute paths that look user-specific or system-specific
  sanitized = sanitized.replace(/\/[^\s'"\(\)\[\]]*\/(?:home|users|desktop|documents|downloads|appdata)\/[^\s'"\(\)\[\]]*/gi, (pathStr) => {
    const trailing = pathStr.match(/[.,:;!]+$/);
    return "[PATH_REDACTED]" + (trailing ? trailing[0] : "");
  });
  sanitized = sanitized.replace(/\/(?:home|users)\/[^\s'"\(\)\[\]]*/gi, (pathStr) => {
    const trailing = pathStr.match(/[.,:;!]+$/);
    return "[PATH_REDACTED]" + (trailing ? trailing[0] : "");
  });
  return sanitized;
}

function usage() {
  console.log(`
Usage:
  node scripts/export-portability.js --exporter <address> [options]

Options:
  --rpc <url>               Ethereum JSON-RPC URL (default: http://127.0.0.1:8545)
  --pb <address>             PatientFundParticipatoryBudgeting address (default: 0x5FbDB2315678afecb367f032d93F642f64180aa3)
  --treasury <address>       PBMRebateTreasury address (default: 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0)
  --merkle <path>           Path to allocations Merkle tree file (default: merkle.json)
  --out <path>              Path to write JSON export (default: exports/<exporter>.json)
  --from-block <num>        Start block for historical event queries (default: 0)
  --to-block <num>          End block for historical event queries (default: latest)
  --allow-partial           Allow script to proceed and export even if queries/files fail
  --allow-unbounded-query   Allow query from block 0 on public networks
`);
}

function parseArgs(argv) {
  const args = {
    exporter: null,
    rpc: "http://127.0.0.1:8545",
    pb: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    treasury: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
    merkle: "merkle.json",
    out: null,
    fromBlock: "0",
    toBlock: "latest",
    allowPartial: false,
    allowUnboundedQuery: false
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--exporter") args.exporter = argv[i + 1];
    else if (arg === "--rpc") args.rpc = argv[i + 1];
    else if (arg === "--pb") args.pb = argv[i + 1];
    else if (arg === "--treasury") args.treasury = argv[i + 1];
    else if (arg === "--merkle") args.merkle = argv[i + 1];
    else if (arg === "--out") args.out = argv[i + 1];
    else if (arg === "--from-block") args.fromBlock = argv[i + 1];
    else if (arg === "--to-block") args.toBlock = argv[i + 1];
    else if (arg === "--allow-partial") args.allowPartial = true;
    else if (arg === "--allow-unbounded-query") args.allowUnboundedQuery = true;
  }

  return args;
}

const TREASURY_ABI = [
  "event Claimed(uint256 indexed epoch, address indexed pharmacy, uint256 grossAmount, uint256 netToPharmacy, uint256 patientShare)",
  "function isExclusionDispute(uint256 epoch, address pharmacy) view returns (bool)",
  "function epochMerkleRoot(uint256 epoch) view returns (bytes32)"
];

const PB_ABI = [
  "event VoteCast(uint256 indexed roundId, uint256 indexed projectId, address indexed voter)",
  "function roundProjects(uint256 roundId, uint256 projectId) view returns (string title, address recipient, uint256 voteCount, bool active)"
];


async function queryFilterChunked(contract, filter, fromBlock, toBlock) {
  const events = [];
  const chunkLimit = 50000n;
  let current = fromBlock;
  while (current <= toBlock) {
    let end = current + chunkLimit - 1n;
    if (end > toBlock) end = toBlock;
    console.log(`Querying events from block ${current} to ${end}...`);
    const batch = await contract.queryFilter(filter, current, end);
    events.push(...batch);
    current = end + 1n;
  }
  return events;
}

async function main(opts = {}) {
  const args = parseArgs(process.argv.slice(2));
  let isPartialExport = false;
  const exportWarnings = [];

  const exporterAddress = opts.exporter || args.exporter;
  const rpcUrl = opts.rpc || args.rpc;
  const treasuryAddress = opts.treasury || args.treasury;
  const pbAddress = opts.pb || args.pb;
  const merklePathInput = opts.merkle || args.merkle;
  const outPathInput = opts.out || args.out;
  const fromBlockInput = opts.fromBlock || args.fromBlock || "0";
  const toBlockInput = opts.toBlock || args.toBlock || "latest";

  if (!exporterAddress) {
    usage();
    process.exitCode = 1;
    return;
  }

  const exporter = ethers.getAddress(exporterAddress);
  console.log(`Starting portability export for participant: ${exporter}`);

  const provider = opts.provider || new ethers.JsonRpcProvider(rpcUrl);
  const treasury = new ethers.Contract(treasuryAddress, TREASURY_ABI, provider);
  const pb = new ethers.Contract(pbAddress, PB_ABI, provider);
  const network = await provider.getNetwork();

  const latestBlock = BigInt(await provider.getBlockNumber());
  const fromBlock = BigInt(fromBlockInput);
  const toBlock = toBlockInput === "latest" ? latestBlock : BigInt(toBlockInput);

  // Enforce explicit from-block for non-local networks after numeric parsing so
  // equivalent zero forms such as 0x0 cannot bypass the guard.
  const isLocalNetwork = network.chainId === 31337n || network.chainId === 1337n;
  if (!isLocalNetwork && fromBlock === 0n && !args.allowUnboundedQuery && !opts.allowUnboundedQuery) {
    throw new Error("Safety violation: A non-zero --from-block must be specified for non-local networks (or use --allow-unbounded-query to override).");
  }

  if (fromBlock > toBlock) {
    throw new Error(`Invalid block range: from-block (${fromBlock}) is greater than to-block (${toBlock}).`);
  }

  // 1. Fetch claims from PBMRebateTreasury Claimed events
  console.log("Fetching claimed events...");
  const claimFilter = treasury.filters.Claimed(null, exporter);
  let claimEvents = [];
  try {
    claimEvents = await queryFilterChunked(treasury, claimFilter, fromBlock, toBlock);
  } catch (err) {
    if (!args.allowPartial && !opts.allowPartial) {
      throw err;
    }
    isPartialExport = true;
    exportWarnings.push(sanitizeWarning(`Could not fetch Claimed events: ${err.message}`));
    console.log("Warning:", exportWarnings.at(-1));
  }

  const claims = [];
  const receipts = [];

  for (const event of claimEvents) {
    const [epoch, pharmacy, grossAmount, netToPharmacy, patientShare] = event.args;
    
    // Get transaction for signature/block details
    let claimedAt = new Date().toISOString();
    let txSignature = "0x";
    try {
      const block = await provider.getBlock(event.blockHash);
      if (block) {
        claimedAt = new Date(Number(block.timestamp) * 1000).toISOString();
      }
      const tx = await provider.getTransaction(event.transactionHash);
      if (tx && tx.signature) {
        txSignature = tx.signature.serialized;
      }
    } catch (err) {
      if (!args.allowPartial && !opts.allowPartial) {
        throw err;
      }
      isPartialExport = true;
      exportWarnings.push(sanitizeWarning(`Could not fetch tx details for ${event.transactionHash}: ${err.message}`));
      console.log("Warning:", exportWarnings.at(-1));
    }

    // Determine status: check if flagged via exclusion dispute
    let status = "resolved";
    try {
      const isFlagged = await treasury.isExclusionDispute(epoch, pharmacy);
      if (isFlagged) status = "flagged";
    } catch (err) {
      if (!args.allowPartial && !opts.allowPartial) {
        throw err;
      }
      isPartialExport = true;
      exportWarnings.push(sanitizeWarning(`Could not check exclusion dispute status: ${err.message}`));
      console.log("Warning:", exportWarnings.at(-1));
    }

    const claimId = `claim-${epoch}-${pharmacy}`;
    claims.push({
      claimId,
      pharmacyAddress: pharmacy,
      syntheticDemoFields: {
        patientId: `patient-epoch-${epoch.toString()}`,
        ndc: "unavailable-off-chain",
        quantity: 1,
        metadataProvenance: "synthetic-placeholder"
      },
      claimedAt,
      status,
      transactionHash: event.transactionHash
    });

    receipts.push({
      receiptId: `receipt-${event.transactionHash}`,
      hash: event.transactionHash,
      signature: txSignature,
      chainId: network.chainId.toString(),
      contractAddress: ethers.getAddress(treasuryAddress),
      blockNumber: event.blockNumber,
      blockHash: event.blockHash,
      logIndex: event.index,
      details: {
        type: "Claimed",
        epoch: Number(epoch),
        grossAmount: grossAmount.toString(),
        netToPharmacy: netToPharmacy.toString(),
        patientShare: patientShare.toString()
      }
    });
  }

  // 2. Fetch Merkle Proofs from local Merkle tree allocations file
  console.log("Reading Merkle allocations file...");
  const merkleProofs = [];
  const merklePath = path.resolve(process.cwd(), merklePathInput);
  let hasMerkleEntry = false;
  if (fs.existsSync(merklePath)) {
    try {
      const merkleData = JSON.parse(fs.readFileSync(merklePath, "utf8"));
      const root = merkleData.root || "";
      const entries = merkleData.entries || [];
      const entry = entries.find(e => ethers.getAddress(e.pharmacy) === exporter);
      
      if (entry) {
        // Find block number of first claim event or fallback to 0
        const blockNumber = claimEvents.length > 0 ? claimEvents[0].blockNumber : 0;
        merkleProofs.push({
          claimRoot: root,
          proof: entry.proof,
          leafIndex: entry.index,
          pharmacy: ethers.getAddress(entry.pharmacy),
          grossAmount: entry.grossAmount.toString(),
          eligibleCap: entry.eligibleCap.toString(),
          blockNumber
        });
        hasMerkleEntry = true;
        console.log("✅ Found Merkle proof allocation entry.");
      }
    } catch (err) {
      if (!args.allowPartial && !opts.allowPartial) {
        throw new Error(`Failed to parse Merkle allocations file: ${err.message}`);
      }
      isPartialExport = true;
      exportWarnings.push(sanitizeWarning(`Failed to parse Merkle allocations file: ${err.message}`));
      console.log("Warning:", exportWarnings.at(-1));
    }
  } else {
    if (!args.allowPartial && !opts.allowPartial) {
      throw new Error(`Merkle tree file not found at ${merklePathInput}.`);
    }
    isPartialExport = true;
    exportWarnings.push(sanitizeWarning(`Merkle tree file not found at ${merklePathInput}. Skipping proof export.`));
    console.log("Warning:", exportWarnings.at(-1));
  }

  if (claims.length > 0 && !hasMerkleEntry) {
    if (!args.allowPartial && !opts.allowPartial) {
      throw new Error("Safety violation: Claims exist in export but no matching Merkle proof was found in allocations file.");
    }
    isPartialExport = true;
    exportWarnings.push("Safety violation: Claims exist in export but no matching Merkle proof was found in allocations file.");
  }

  // 3. Fetch Votes from PatientFundParticipatoryBudgeting VoteCast events
  console.log("Fetching vote cast events...");
  const voteFilter = pb.filters.VoteCast(null, null, exporter);
  let voteEvents = [];
  try {
    voteEvents = await queryFilterChunked(pb, voteFilter, fromBlock, toBlock);
  } catch (err) {
    if (!args.allowPartial && !opts.allowPartial) {
      throw err;
    }
    isPartialExport = true;
    exportWarnings.push(sanitizeWarning(`Could not fetch VoteCast events: ${err.message}`));
    console.log("Warning:", exportWarnings.at(-1));
  }

  const votes = [];

  for (const event of voteEvents) {
    const [roundId, projectId, voter] = event.args;

    // Get project title
    let projectTitle = `Project #${projectId}`;
    try {
      const proj = await pb.roundProjects(roundId, projectId);
      if (proj && proj.title) {
        projectTitle = proj.title;
      }
    } catch (err) {
      if (!args.allowPartial && !opts.allowPartial) {
        throw err;
      }
      isPartialExport = true;
      exportWarnings.push(sanitizeWarning(`Could not fetch project details for project ${projectId} in round ${roundId}: ${err.message}`));
      console.log("Warning:", exportWarnings.at(-1));
    }

    // Get tx details
    let txSignature = "0x";
    try {
      const tx = await provider.getTransaction(event.transactionHash);
      if (tx && tx.signature) {
        txSignature = tx.signature.serialized;
      }
    } catch (err) {
      if (!args.allowPartial && !opts.allowPartial) {
        throw err;
      }
      isPartialExport = true;
      exportWarnings.push(sanitizeWarning(`Could not fetch transaction details for ${event.transactionHash}: ${err.message}`));
      console.log("Warning:", exportWarnings.at(-1));
    }

    votes.push({
      voter,
      project: projectTitle,
      weight: "1", // quadratic matching vote weight increments by 1 unit
      signature: txSignature,
      epoch: Number(roundId)
    });

    receipts.push({
      receiptId: `receipt-${event.transactionHash}`,
      hash: event.transactionHash,
      signature: txSignature,
      chainId: network.chainId.toString(),
      contractAddress: ethers.getAddress(pbAddress),
      blockNumber: event.blockNumber,
      blockHash: event.blockHash,
      logIndex: event.index,
      details: {
        type: "VoteCast",
        roundId: Number(roundId),
        projectId: Number(projectId),
        projectTitle
      }
    });
  }

  // 4. Assemble payload
  const payload = {
    schema_version: "1.1.0",
    is_partial: isPartialExport,
    warnings: exportWarnings,
    exporter,
    exported_at: new Date().toISOString(),
    chain: {
      chainId: network.chainId.toString(),
      treasuryAddress: ethers.getAddress(treasuryAddress),
      participatoryBudgetingAddress: ethers.getAddress(pbAddress)
    },
    claims,
    merkle_proofs: merkleProofs,
    votes,
    receipts
  };

  const outputJson = JSON.stringify(payload, null, 2);

  // Write payload
  const outPath = outPathInput
    ? path.resolve(process.cwd(), outPathInput)
    : path.resolve(process.cwd(), "exports", `${exporter}.json`);

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, outputJson + "\n", "utf8");
  console.log(`\n==================================================`);
  console.log(`✅ PORTABILITY EXPORT GENERATED SUCCESSFULLY`);
  console.log(`==================================================`);
  console.log(`Output:      ${outPath}`);
  console.log(`Claims:      ${claims.length}`);
  console.log(`Proofs:      ${merkleProofs.length}`);
  console.log(`Votes:       ${votes.length}`);
  console.log(`Receipts:    ${receipts.length}`);
  console.log(`Note:        Off-chain clinical fields are nested under syntheticDemoFields unless independently supplied.`);
  console.log(`==================================================\n`);
}

if (require.main === module) {
  main().catch(err => {
    console.error("Export script failed:", err);
    process.exitCode = 1;
  });
}

module.exports = {
  TREASURY_ABI,
  PB_ABI,
  sanitizeWarning,
  main
};
