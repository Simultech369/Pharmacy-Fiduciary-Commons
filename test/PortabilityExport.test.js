const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("node:fs");
const path = require("node:path");
const { main } = require("../scripts/export-portability");
const { verifyPayload, verifyPayloadOnChain } = require("../scripts/verify-export");

describe("Portability Export Tool", function () {
  const toWei = (value) => ethers.parseEther(value);

  let token;
  let treasury;
  let pb;
  let council;
  let council2;
  let guardian;
  let patientFund;
  let environmentalFund;
  let pharmacy;
  let timelock;

  const merkleLeaf = (pharmacyAddress, amount, eligibleCap) => {
    const inner = ethers.solidityPackedKeccak256(
      ["address", "uint256", "uint256"],
      [pharmacyAddress, amount, eligibleCap]
    );
    return ethers.keccak256(ethers.solidityPacked(["bytes32"], [inner]));
  };

  beforeEach(async function () {
    const signers = await ethers.getSigners();
    council = signers[0];
    council2 = signers[1];
    guardian = signers[2];
    patientFund = signers[3];
    environmentalFund = signers[4];
    pharmacy = signers[5];

    // Deploy ERC20 Token
    const MockERC20 = await ethers.getContractFactory("MockERC20");
    token = await MockERC20.deploy("Mock DAI", "mDAI", 18);
    await token.waitForDeployment();

    // Deploy Timelock Controller
    const Timelock = await ethers.getContractFactory("TimelockController");
    timelock = await Timelock.deploy(1n, [council.address], [ethers.ZeroAddress], council.address);
    await timelock.waitForDeployment();

    // Deploy Rebate Treasury
    const Treasury = await ethers.getContractFactory("PBMRebateTreasury");
    treasury = await Treasury.deploy(
      await token.getAddress(),
      patientFund.address,
      environmentalFund.address,
      toWei("1000"),
      toWei("1"),
      council.address,
      council2.address,
      await timelock.getAddress(),
      guardian.address
    );
    await treasury.waitForDeployment();

    // Deploy Participatory Budgeting
    const PB = await ethers.getContractFactory("PatientFundParticipatoryBudgeting");
    pb = await PB.deploy(await token.getAddress(), council.address, guardian.address);
    await pb.waitForDeployment();

    // Mint tokens to council and approve PB contract
    await token.mint(council.address, toWei("50000"));
    await token.connect(council).approve(await pb.getAddress(), toWei("50000"));
  });

  it("exports participant records and complies with PORTABILITY.md JSON schema", async function () {
    const gross = toWei("100");
    
    // 1. Prepare rebate deposit
    await token.mint(council.address, toWei("1000"));
    await token.connect(council).approve(await treasury.getAddress(), toWei("1000"));
    await treasury.connect(council).depositRebate(toWei("1000"), "Q1 2026 deposit");

    // 2. Set up Merkle root on PBMRebateTreasury
    const leaf = merkleLeaf(pharmacy.address, gross, gross);
    await treasury.connect(council).proposeRoot(leaf, gross);
    await treasury.connect(council2).confirmRoot(0);

    // 3. Pharmacy claims the rebate
    const claimTx = await treasury.connect(pharmacy).claim(gross, gross, []);
    const claimReceipt = await claimTx.wait();

    // 4. Start round, register project, register voter and vote in Participatory Budgeting
    await pb.connect(council).startRound(toWei("10000"));
    await pb.connect(council).registerProject(1n, "Free Solar Power", council.address);
    await pb.connect(council).registerVoter(1n, pharmacy.address, true);
    
    const voteTx = await pb.connect(pharmacy).castVote(1n, 0n);
    await voteTx.wait();

    // 5. Write mock merkle allocations file matching the leaf
    const merklePath = path.resolve(process.cwd(), "test-merkle-portability.json");
    const mockMerkle = {
      root: leaf,
      totalAmount: gross.toString(),
      entries: [
        {
          index: 0,
          pharmacy: pharmacy.address,
          grossAmount: gross.toString(),
          eligibleCap: gross.toString(),
          proof: []
        }
      ]
    };
    fs.writeFileSync(merklePath, JSON.stringify(mockMerkle, null, 2), "utf8");

    // 6. Run export script passing the Hardhat provider and paths directly in the options
    const outputPath = path.resolve(process.cwd(), "test-export-out.json");
    fs.rmSync(outputPath, { force: true });

    try {
      await main({
        exporter: pharmacy.address,
        provider: ethers.provider,
        pb: await pb.getAddress(),
        treasury: await treasury.getAddress(),
        merkle: merklePath,
        out: outputPath
      });
    } finally {
      fs.rmSync(merklePath, { force: true });
    }

    // 7. Verify exported file structure and correctness
    expect(fs.existsSync(outputPath)).to.be.true;
    const payload = JSON.parse(fs.readFileSync(outputPath, "utf8"));
    fs.rmSync(outputPath, { force: true });

    // Validate main schema components
    expect(payload.exporter).to.equal(pharmacy.address);
    expect(payload.exported_at).to.not.be.undefined;
    expect(new Date(payload.exported_at).toString()).to.not.equal("Invalid Date");
    expect(payload.chain.chainId).to.equal("31337");
    expect(payload.chain.treasuryAddress).to.equal(await treasury.getAddress());
    expect(payload.chain.participatoryBudgetingAddress).to.equal(await pb.getAddress());

    // Validate claims array
    expect(payload.claims).to.have.lengthOf(1);
    const c = payload.claims[0];
    expect(c.claimId).to.equal(`claim-0-${pharmacy.address}`);
    expect(c.pharmacyAddress).to.equal(pharmacy.address);
    expect(c.syntheticDemoFields).to.deep.equal({
      patientId: "patient-epoch-0",
      ndc: "unavailable-off-chain",
      quantity: 1,
      metadataProvenance: "synthetic-placeholder"
    });
    expect(c.patientId).to.equal(undefined);
    expect(c.ndc).to.equal(undefined);
    expect(c.quantity).to.equal(undefined);
    expect(c.metadataProvenance).to.equal(undefined);
    expect(c.status).to.equal("resolved");
    expect(c.transactionHash).to.equal(claimReceipt.hash);

    // Validate Merkle proofs
    expect(payload.merkle_proofs).to.have.lengthOf(1);
    const p = payload.merkle_proofs[0];
    expect(p.claimRoot).to.equal(leaf);
    expect(p.proof).to.deep.equal([]);
    expect(p.leafIndex).to.equal(0);
    expect(p.pharmacy).to.equal(pharmacy.address);
    expect(p.grossAmount).to.equal(gross.toString());
    expect(p.eligibleCap).to.equal(gross.toString());
    expect(p.blockNumber).to.equal(claimReceipt.blockNumber);

    // Validate votes array
    expect(payload.votes).to.have.lengthOf(1);
    const v = payload.votes[0];
    expect(v.voter).to.equal(pharmacy.address);
    expect(v.project).to.equal("Free Solar Power");
    expect(v.weight).to.equal("1");
    expect(v.signature).to.not.equal("0x");
    expect(v.epoch).to.equal(1);

    // Validate receipts
    expect(payload.receipts).to.have.lengthOf(2);
    expect(payload.receipts[0].hash).to.equal(claimReceipt.hash);
    expect(payload.receipts[1].hash).to.equal(voteTx.hash);
    expect(payload.receipts[0].blockHash).to.equal(claimReceipt.blockHash);
    expect(payload.receipts[0].contractAddress).to.equal(await treasury.getAddress());

    const verification = verifyPayload(payload);
    expect(verification.ok).to.be.true;
    expect(verification.errors).to.deep.equal([]);

    const tampered = structuredClone(payload);
    tampered.merkle_proofs[0].eligibleCap = toWei("101").toString();
    const tamperedVerification = verifyPayload(tampered);
    expect(tamperedVerification.ok).to.be.false;
    expect(tamperedVerification.errors.join(" | ")).to.contain("does not verify");

    const chainVerification = await verifyPayloadOnChain(payload, { provider: ethers.provider });
    expect(chainVerification.ok).to.be.true;

    const fabricated = structuredClone(payload);
    fabricated.receipts[0].blockHash = ethers.ZeroHash;
    const fabricatedVerification = await verifyPayloadOnChain(fabricated, { provider: ethers.provider });
    expect(fabricatedVerification.ok).to.be.false;
    expect(fabricatedVerification.errors.join(" | ")).to.contain("block hash does not match");

    // Additional offline verifier error branch tests
    const badPharmacy = structuredClone(payload);
    badPharmacy.claims[0].pharmacyAddress = ethers.ZeroAddress;
    const badPharmacyVerification = verifyPayload(badPharmacy);
    expect(badPharmacyVerification.ok).to.be.false;
    expect(badPharmacyVerification.errors.join(" | ")).to.contain("does not match exporter");

    const badVoter = structuredClone(payload);
    badVoter.votes[0].voter = ethers.ZeroAddress;
    const badVoterVerification = verifyPayload(badVoter);
    expect(badVoterVerification.ok).to.be.false;
    expect(badVoterVerification.errors.join(" | ")).to.contain("voter does not match exporter");

    const missingReceipt = structuredClone(payload);
    missingReceipt.receipts = [];
    const missingReceiptVerification = verifyPayload(missingReceipt);
    expect(missingReceiptVerification.ok).to.be.false;
    expect(missingReceiptVerification.errors.join(" | ")).to.contain("missing a matching receipt");

    const invalidHash = structuredClone(payload);
    invalidHash.receipts[0].hash = "0x123";
    const invalidHashVerification = verifyPayload(invalidHash);
    expect(invalidHashVerification.ok).to.be.false;
    expect(invalidHashVerification.errors.join(" | ")).to.contain("Receipt has invalid hash");

    // Test: verifyPayload fails without Merkle proofs unless allowIncomplete is true
    const noProofs = structuredClone(payload);
    noProofs.merkle_proofs = [];
    const noProofsVerification = verifyPayload(noProofs);
    expect(noProofsVerification.ok).to.be.false;
    expect(noProofsVerification.errors.join(" | ")).to.contain("Claims exist without Merkle proof material");

    const noProofsAllowedVerification = verifyPayload(noProofs, { allowIncomplete: true });
    expect(noProofsAllowedVerification.ok).to.be.true;
    expect(noProofsAllowedVerification.warnings.join(" | ")).to.contain("Claims exist without Merkle proof material");
  });

  it("enforces strict validation of missing/malformed completeness fields", function () {
    const validPayload = {
      schema_version: "1.1.0",
      is_partial: false,
      warnings: [],
      exporter: pharmacy.address,
      exported_at: new Date().toISOString(),
      claims: [],
      merkle_proofs: [],
      votes: [],
      receipts: []
    };

    // 1. Missing schema_version
    const missingSchema = structuredClone(validPayload);
    delete missingSchema.schema_version;
    const missingSchemaResult = verifyPayload(missingSchema);
    expect(missingSchemaResult.ok).to.be.false;
    expect(missingSchemaResult.errors.join(" | ")).to.contain("Completeness field schema_version is missing");

    // 2. Missing is_partial
    const missingIsPartial = structuredClone(validPayload);
    delete missingIsPartial.is_partial;
    const v1 = verifyPayload(missingIsPartial);
    expect(v1.ok).to.be.false;
    expect(v1.errors.join(" | ")).to.contain("Completeness field is_partial is missing");

    // 3. Malformed is_partial
    const malformedIsPartial = structuredClone(validPayload);
    malformedIsPartial.is_partial = "false";
    const v2 = verifyPayload(malformedIsPartial);
    expect(v2.ok).to.be.false;
    expect(v2.errors.join(" | ")).to.contain("is_partial must be a boolean");

    // 4. Missing warnings
    const missingWarnings = structuredClone(validPayload);
    delete missingWarnings.warnings;
    const v3 = verifyPayload(missingWarnings);
    expect(v3.ok).to.be.false;
    expect(v3.errors.join(" | ")).to.contain("Completeness field warnings is missing");

    // 5. Malformed warnings
    const malformedWarnings = structuredClone(validPayload);
    malformedWarnings.warnings = "none";
    const v4 = verifyPayload(malformedWarnings);
    expect(v4.ok).to.be.false;
    expect(v4.errors.join(" | ")).to.contain("warnings must be an array");

    // 6. Unsupported schema_version
    const malformedSchema = structuredClone(validPayload);
    malformedSchema.schema_version = true;
    const v5 = verifyPayload(malformedSchema);
    expect(v5.ok).to.be.false;
    expect(v5.errors.join(" | ")).to.contain("Unsupported schema_version");

    // 7. Non-string warning entries
    const malformedWarningEntry = structuredClone(validPayload);
    malformedWarningEntry.warnings = [{ message: "query failed" }];
    const v6 = verifyPayload(malformedWarningEntry);
    expect(v6.ok).to.be.false;
    expect(v6.errors.join(" | ")).to.contain("warnings entries must be strings");

    // 8. A payload cannot claim completeness while carrying partial warnings
    const contradictoryCompleteness = structuredClone(validPayload);
    contradictoryCompleteness.warnings = ["query failed"];
    const v7 = verifyPayload(contradictoryCompleteness);
    expect(v7.ok).to.be.false;
    expect(v7.errors.join(" | ")).to.contain("complete export cannot contain partial-export warnings");
  });

  it("sanitizes warning messages, redacting RPC URLs, credentials, and absolute paths", function () {
    const { sanitizeWarning } = require("../scripts/export-portability");

    // Test URL with api key
    const urlWarning = "Failed to fetch from https://apikey:secret-token@rpc.mainnet.com/v3/mykey: network error";
    expect(sanitizeWarning(urlWarning)).to.equal("Failed to fetch from [URL_REDACTED]: network error");

    // Test key-value credential pattern
    const credentialWarning = "Connection refused with api-key=mySecretPassword123 and secret=supersecret";
    expect(sanitizeWarning(credentialWarning)).to.equal("Connection refused with api-key=[REDACTED] and secret=[REDACTED]");

    const authorizationWarning = "Request failed with Authorization: Bearer abc.def-123";
    expect(sanitizeWarning(authorizationWarning)).to.equal("Request failed with authorization: [REDACTED]");

    // Test Windows path
    const winPathWarning = "File not found at D:\\Users\\Administrator\\Desktop\\PharmacyApp\\merkle.json";
    expect(sanitizeWarning(winPathWarning)).to.equal("File not found at [PATH_REDACTED]");

    // Test Unix path with home
    const unixHomeWarning = "Failed to load /home/ubuntu/project/config.json: read error";
    expect(sanitizeWarning(unixHomeWarning)).to.equal("Failed to load [PATH_REDACTED]: read error");

    // Test Unix path with users
    const unixUsersWarning = "Permission denied for /Users/josh/Desktop/contracts/PBM.sol";
    expect(sanitizeWarning(unixUsersWarning)).to.equal("Permission denied for [PATH_REDACTED]");
  });

  it("enforces chain-ID network classification safety rules during export and verification", async function () {
    const mockNetwork = { chainId: 1n };
    const mockProvider = {
      getNetwork: async () => mockNetwork,
      getBlockNumber: async () => 1000n,
      getSigner: async () => {}
    };

    let threw = false;
    try {
      await main({
        exporter: pharmacy.address,
        provider: mockProvider,
        pb: await pb.getAddress(),
        treasury: await treasury.getAddress(),
        merkle: "merkle.json",
        fromBlock: "0",
        allowUnboundedQuery: false
      });
    } catch (err) {
      threw = true;
      expect(err.message).to.contain("Safety violation: A non-zero --from-block must be specified for non-local networks");
    }
    expect(threw).to.be.true;

    const payload = {
      schema_version: "1.1.0",
      is_partial: false,
      warnings: [],
      exporter: pharmacy.address,
      exported_at: new Date().toISOString(),
      chain: {
        chainId: "1",
        treasuryAddress: await treasury.getAddress(),
        participatoryBudgetingAddress: await pb.getAddress()
      },
      claims: [],
      merkle_proofs: [],
      votes: [],
      receipts: []
    };

    const chainVerification = await verifyPayloadOnChain(payload, { provider: ethers.provider });
    expect(chainVerification.ok).to.be.false;
    expect(chainVerification.errors.join(" | ")).to.contain("Export chainId does not match the connected network");
  });

  it("CLI verifier output for partial export accepted with override", async function () {
    const { main: verifyMain } = require("../scripts/verify-export");
    const testFile = path.resolve(process.cwd(), "test-partial-export-temp.json");

    const payload = {
      schema_version: "1.1.0",
      is_partial: true,
      warnings: ["RPC query failed"],
      exporter: pharmacy.address,
      exported_at: new Date().toISOString(),
      chain: {
        chainId: "31337",
        treasuryAddress: await treasury.getAddress(),
        participatoryBudgetingAddress: await pb.getAddress()
      },
      claims: [],
      merkle_proofs: [],
      votes: [],
      receipts: []
    };

    fs.writeFileSync(testFile, JSON.stringify(payload, null, 2), "utf8");

    const logLines = [];
    const originalLog = console.log;
    console.log = (msg) => { logLines.push(msg); };

    try {
      await verifyMain({
        file: testFile,
        allowPartial: true
      });
    } finally {
      console.log = originalLog;
      fs.rmSync(testFile, { force: true });
    }

    const combinedLogs = logLines.join("\n");
    expect(combinedLogs).to.contain("partial accepted with override");
    expect(combinedLogs).to.not.contain("RPC provenance verification passed");
    expect(combinedLogs).to.not.contain("OFFLINE STRUCTURE CHECK PASSED");
  });
});
