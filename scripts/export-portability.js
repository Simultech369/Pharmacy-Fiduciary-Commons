const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

function usage() {
  console.log(`
Usage:
  node scripts/export-portability.js --exporter <address> [options]

Options:
  --rpc <url>         Ethereum JSON-RPC URL (default: http://127.0.0.1:8545)
  --pb <address>       PatientFundParticipatoryBudgeting address (default: 0x5FbDB2315678afecb367f032d93F642f64180aa3)
  --treasury <address> PBMRebateTreasury address (default: 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0)
  --merkle <path>     Path to allocations Merkle tree file (default: merkle.json)
  --out <path>        Path to write JSON export (default: exports/<exporter>.json)
`);
}

function parseArgs(argv) {
  const args = {
    exporter: null,
    rpc: "http://127.0.0.1:8545",
    pb: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    treasury: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
    merkle: "merkle.json",
    out: null
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--exporter") args.exporter = argv[i + 1];
    else if (arg === "--rpc") args.rpc = argv[i + 1];
    else if (arg === "--pb") args.pb = argv[i + 1];
    else if (arg === "--treasury") args.treasury = argv[i + 1];
    else if (arg === "--merkle") args.merkle = argv[i + 1];
    else if (arg === "--out") args.out = argv[i + 1];
  }

  return args;
}

// Contract ABIs
const TREASURY_ABI = [
  "event Claimed(uint256 indexed epoch, address indexed pharmacy, uint256 grossAmount, uint256 netToPharmacy, uint256 patientShare)",
  "function isExclusionDispute(uint256 epoch, address pharmacy) view returns (bool)"
];

const PB_ABI = [
  "event VoteCast(uint256 indexed roundId, uint256 indexed projectId, address indexed voter)",
  "function roundProjects(uint256 roundId, uint256 projectId) view returns (string title, address recipient, uint256 voteCount, bool active)"
];

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.exporter) {
    usage();
    process.exitCode = 1;
    return;
  }

  const exporter = ethers.getAddress(args.exporter);
  console.log(`Starting portability export for participant: ${exporter}`);

  const provider = new ethers.JsonRpcProvider(args.rpc);
  const treasury = new ethers.Contract(args.treasury, TREASURY_ABI, provider);
  const pb = new ethers.Contract(args.pb, PB_ABI, provider);

  // 1. Fetch claims from PBMRebateTreasury Claimed events
  console.log("Fetching claimed events...");
  const claimFilter = treasury.filters.Claimed(null, exporter);
  let claimEvents = [];
  try {
    claimEvents = await treasury.queryFilter(claimFilter, 0, "latest");
  } catch (err) {
    console.log("Warning: Could not fetch Claimed events:", err.message);
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
      console.log(`Warning: Could not fetch tx details for ${event.transactionHash}:`, err.message);
    }

    // Determine status: check if flagged via exclusion dispute
    let status = "resolved";
    try {
      const isFlagged = await treasury.isExclusionDispute(epoch, pharmacy);
      if (isFlagged) status = "flagged";
    } catch (err) {
      console.log("Warning: Could not check exclusion dispute status:", err.message);
    }

    const claimId = `claim-${epoch}-${pharmacy}`;
    claims.push({
      claimId,
      patientId: `patient-epoch-${epoch.toString()}`,
      pharmacyAddress: pharmacy,
      ndc: "99999-999-99", // placeholder as NDC is off-chain metadata
      quantity: 1,
      claimedAt,
      status,
      transactionHash: event.transactionHash
    });

    receipts.push({
      receiptId: `receipt-${event.transactionHash}`,
      hash: event.transactionHash,
      signature: txSignature,
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
  const merklePath = path.resolve(process.cwd(), args.merkle);
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
          blockNumber
        });
        console.log("✅ Found Merkle proof allocation entry.");
      }
    } catch (err) {
      console.log("Warning: Failed to parse Merkle allocations file:", err.message);
    }
  } else {
    console.log(`Warning: Merkle tree file not found at ${args.merkle}. Skipping proof export.`);
  }

  // 3. Fetch Votes from PatientFundParticipatoryBudgeting VoteCast events
  console.log("Fetching vote cast events...");
  const voteFilter = pb.filters.VoteCast(null, null, exporter);
  let voteEvents = [];
  try {
    voteEvents = await pb.queryFilter(voteFilter, 0, "latest");
  } catch (err) {
    console.log("Warning: Could not fetch VoteCast events:", err.message);
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
      console.log(`Warning: Could not fetch project details for ${projectId}:`, err.message);
    }

    // Get tx details
    let txSignature = "0x";
    try {
      const tx = await provider.getTransaction(event.transactionHash);
      if (tx && tx.signature) {
        txSignature = tx.signature.serialized;
      }
    } catch (err) {
      console.log(`Warning: Could not fetch transaction details for ${event.transactionHash}:`, err.message);
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
    exporter,
    exported_at: new Date().toISOString(),
    claims,
    merkle_proofs: merkleProofs,
    votes,
    receipts
  };

  const outputJson = JSON.stringify(payload, null, 2);

  // Write payload
  const outPath = args.out
    ? path.resolve(process.cwd(), args.out)
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
  main
};
