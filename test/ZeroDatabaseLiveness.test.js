const { expect } = require("chai");
const { ethers } = require("hardhat");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

describe("Zero-Database Resilience & Offline Continuity Liveness Test Suite", function () {
  this.timeout(120000);

  const toWei = (value) => ethers.parseEther(String(value));
  const repoRoot = path.resolve(__dirname, "..");
  const drillToolPath = path.join(repoRoot, "tools", "resilience", "zero-database-drill.mjs");
  const testSecret = "secure-zero-database-drill-local-secret-369";

  let drillEngine;
  let token;
  let treasury;
  let timelock;
  let council;
  let rootConfirmer;
  let guardian;
  let patientFund;
  let environmentalFund;
  let depositor;
  let pharmacy1;
  let pharmacy2;
  let pharmacy3;
  let attacker;

  function errorText(err) {
    return [
      err?.message,
      err?.shortMessage,
      err?.errorName,
      err?.error?.message,
      err?.data?.message,
    ]
      .filter(Boolean)
      .join(" | ");
  }

  async function expectRevert(promise, expectedSnippet) {
    let reverted = false;
    try {
      await promise;
    } catch (err) {
      reverted = true;
      const text = errorText(err);
      expect(text).to.contain(expectedSnippet);
    }

    if (!reverted) {
      expect.fail(`Expected revert containing '${expectedSnippet}'`);
    }
  }

  before(async function () {
    // Dynamic import of ES Module
    const drillUrl = pathToFileURL(drillToolPath).href;
    drillEngine = await import(drillUrl);
  });

  beforeEach(async function () {
    [
      depositor,
      council,
      rootConfirmer,
      guardian,
      patientFund,
      environmentalFund,
      pharmacy1,
      pharmacy2,
      pharmacy3,
      attacker
    ] = await ethers.getSigners();

    const MockERC20 = await ethers.getContractFactory("MockERC20");
    token = await MockERC20.deploy("Mock DAI", "mDAI", 18);
    await token.waitForDeployment();

    const Timelock = await ethers.getContractFactory("TimelockController");
    timelock = await Timelock.deploy(
      1n, // 1 second delay
      [council.address],
      [ethers.ZeroAddress],
      council.address
    );
    await timelock.waitForDeployment();

    const initialDailyCap = toWei("10000");
    const minimumEpochVolume = toWei("100");

    const Treasury = await ethers.getContractFactory("PBMRebateTreasury");
    treasury = await Treasury.deploy(
      await token.getAddress(),
      patientFund.address,
      environmentalFund.address,
      initialDailyCap,
      minimumEpochVolume,
      council.address,
      rootConfirmer.address,
      await timelock.getAddress(),
      guardian.address
    );
    await treasury.waitForDeployment();

    // Mint tokens to depositor and seed treasury with initial deposit
    await token.mint(depositor.address, toWei("50000"));
    await token.connect(depositor).approve(await treasury.getAddress(), toWei("20000"));
    await treasury.connect(depositor).depositRebate(toWei("20000"), "Offline Resilience Seed Deposit");
  });

  describe("1. Total Database Outage Simulation", function () {
    it("simulates database disconnection and verifies all operations fail closed", async function () {
      const mockDb = drillEngine.createDatabaseOutageSimulator();
      expect(mockDb.isOutage).to.be.true;

      let caughtSelect = false;
      try {
        await mockDb.from("voter_profiles").select("*");
      } catch (err) {
        caughtSelect = true;
        expect(err.message).to.include("DATABASE_CONNECTION_REFUSED");
        expect(err.code).to.equal("ECONNREFUSED");
      }
      expect(caughtSelect).to.be.true;

      let caughtInsert = false;
      try {
        await mockDb.from("offline_vouchers").insert({ id: 1 });
      } catch (err) {
        caughtInsert = true;
        expect(err.message).to.include("DATABASE_CONNECTION_REFUSED");
      }
      expect(caughtInsert).to.be.true;

      let caughtAuth = false;
      try {
        await mockDb.auth.admin.createUser({ email: "test@example.com" });
      } catch (err) {
        caughtAuth = true;
        expect(err.message).to.include("DATABASE_CONNECTION_REFUSED");
      }
      expect(caughtAuth).to.be.true;
    });

    it("ensures offline voucher generation and verification execute with 0 database dependencies", function () {
      // Generate voucher entirely in-memory with local HMAC secret
      const voucher = drillEngine.generateOfflineVoucher({
        roundId: 1,
        pharmacy: pharmacy1.address,
        grossAmount: toWei("500").toString(),
        eligibleCap: toWei("1000").toString(),
        secret: testSecret
      });

      expect(voucher).to.be.an("object");
      expect(voucher.status).to.equal(drillEngine.OFFLINE_VOUCHER_STATES.ISSUED);

      // Verify client-side without any DB connection
      const verified = drillEngine.verifyOfflineVoucherClientSide(voucher, testSecret);
      expect(verified.valid).to.be.true;
      expect(verified.status).to.equal(drillEngine.OFFLINE_VOUCHER_STATES.CACHE_VERIFIED);
      expect(verified.pharmacy).to.equal(ethers.getAddress(pharmacy1.address));
    });
  });

  describe("2. Offline Community Health Voucher Generation & Verification", function () {
    it("generates structured offline vouchers with HMAC-SHA256 and nonces", function () {
      const nonce = "custom-offline-nonce-12345";
      const voucher = drillEngine.generateOfflineVoucher({
        roundId: 1,
        pharmacy: pharmacy1.address,
        grossAmount: toWei("250").toString(),
        eligibleCap: toWei("1000").toString(),
        nonce,
        secret: testSecret
      });

      expect(voucher.voucherId).to.include("voucher-1-");
      expect(voucher.roundId).to.equal(1);
      expect(voucher.pharmacy).to.equal(ethers.getAddress(pharmacy1.address));
      expect(voucher.grossAmount).to.equal(toWei("250").toString());
      expect(voucher.eligibleCap).to.equal(toWei("1000").toString());
      expect(voucher.nonce).to.equal(nonce);
      expect(voucher.mac).to.match(/^0x[0-9a-fA-F]{64}$/);
      expect(voucher.preimage).to.match(/^0x[0-9a-fA-F]{64}$/);
      expect(voucher.nullifier).to.match(/^0x[0-9a-fA-F]{64}$/);
      expect(voucher.warning).to.include("Bearer recovery material");
    });

    it("rejects invalid voucher schemas (missing fields, invalid addresses, negative caps)", function () {
      // Missing field
      const badVoucher1 = { roundId: 1, pharmacy: pharmacy1.address };
      expect(() => drillEngine.assertVoucherSchema(badVoucher1)).to.throw("Schema validation failed: missing field");

      // Invalid address
      expect(() => {
        drillEngine.generateOfflineVoucher({
          roundId: 1,
          pharmacy: "not-an-address",
          grossAmount: "100",
          eligibleCap: "200",
          secret: testSecret
        });
      }).to.throw("Invalid pharmacy address");

      // Amount exceeds cap
      expect(() => {
        drillEngine.generateOfflineVoucher({
          roundId: 1,
          pharmacy: pharmacy1.address,
          grossAmount: "500",
          eligibleCap: "100",
          secret: testSecret
        });
      }).to.throw("grossAmount cannot exceed eligibleCap");

      // Secret too short
      expect(() => {
        drillEngine.generateOfflineVoucher({
          roundId: 1,
          pharmacy: pharmacy1.address,
          grossAmount: "100",
          eligibleCap: "200",
          secret: "short"
        });
      }).to.throw("LOCAL_MAC_SECRET must be at least 16 characters");
    });
  });

  describe("3. Local Static Snapshot Merkle Tree Reconstruction", function () {
    let snapshotEntries;
    let localTree;

    beforeEach(function () {
      snapshotEntries = [
        { pharmacy: pharmacy1.address, grossAmount: toWei("500").toString(), eligibleCap: toWei("2000").toString() },
        { pharmacy: pharmacy2.address, grossAmount: toWei("1200").toString(), eligibleCap: toWei("3000").toString() },
        { pharmacy: pharmacy3.address, grossAmount: toWei("800").toString(), eligibleCap: toWei("2500").toString() }
      ];

      localTree = drillEngine.buildLocalSnapshotTree(snapshotEntries);
    });

    it("reconstructs Merkle root and proofs locally without network or database calls", function () {
      expect(localTree.root).to.match(/^0x[0-9a-fA-F]{64}$/);
      expect(localTree.entries).to.have.lengthOf(3);
      expect(localTree.totalAmount).to.equal(toWei("2500").toString());

      // Extract proof for pharmacy 1
      const proofObj1 = localTree.getProofForPharmacy(pharmacy1.address);
      expect(proofObj1.entry.pharmacy).to.equal(ethers.getAddress(pharmacy1.address));
      expect(proofObj1.proof).to.be.an("array");

      // Verify proof locally
      const valid1 = drillEngine.verifyProofLocally(proofObj1.leaf, proofObj1.proof, localTree.root);
      expect(valid1).to.be.true;

      // Extract proof for pharmacy 2
      const proofObj2 = localTree.getProofForPharmacy(pharmacy2.address);
      const valid2 = drillEngine.verifyProofLocally(proofObj2.leaf, proofObj2.proof, localTree.root);
      expect(valid2).to.be.true;
    });

    it("throws when extracting proof for an unlisted pharmacy address", function () {
      expect(() => {
        localTree.getProofForPharmacy(attacker.address);
      }).to.throw("not found in static snapshot");
    });
  });

  describe("4. On-Chain Claim Verification against PBMRebateTreasury.sol", function () {
    let snapshotEntries;
    let localTree;

    beforeEach(async function () {
      snapshotEntries = [
        { pharmacy: pharmacy1.address, grossAmount: toWei("500").toString(), eligibleCap: toWei("2000").toString() },
        { pharmacy: pharmacy2.address, grossAmount: toWei("1200").toString(), eligibleCap: toWei("3000").toString() },
        { pharmacy: pharmacy3.address, grossAmount: toWei("800").toString(), eligibleCap: toWei("2500").toString() }
      ];

      localTree = drillEngine.buildLocalSnapshotTree(snapshotEntries);

      // Propose and confirm Merkle root from local snapshot
      const epoch = await treasury.currentEpoch();
      await treasury.connect(council).proposeRoot(localTree.root, BigInt(localTree.totalAmount));
      await treasury.connect(rootConfirmer).confirmRoot(epoch);
    });

    it("executes claim on-chain using offline reconstructed proof with exact 90/10 split", async function () {
      const proofObj1 = localTree.getProofForPharmacy(pharmacy1.address);
      const grossAmount = BigInt(proofObj1.entry.grossAmount);
      const eligibleCap = BigInt(proofObj1.entry.eligibleCap);

      const patientFundBefore = await token.balanceOf(patientFund.address);
      const pharmacyBefore = await token.balanceOf(pharmacy1.address);
      const escrowBefore = await treasury.epochEscrow(0);

      // Pharmacy 1 claims on-chain
      await treasury.connect(pharmacy1).claim(grossAmount, eligibleCap, proofObj1.proof);

      const patientFundAfter = await token.balanceOf(patientFund.address);
      const pharmacyAfter = await token.balanceOf(pharmacy1.address);
      const escrowAfter = await treasury.epochEscrow(0);

      // 10% patient share, 90% net to pharmacy
      const expectedPatientShare = (grossAmount * 1000n) / 10000n; // 10%
      const expectedNetToPharmacy = grossAmount - expectedPatientShare;

      expect(patientFundAfter - patientFundBefore).to.equal(expectedPatientShare);
      expect(pharmacyAfter - pharmacyBefore).to.equal(expectedNetToPharmacy);
      expect(escrowBefore - escrowAfter).to.equal(grossAmount);

      // Check on-chain state variables
      expect(await treasury.hasClaimed(0, pharmacy1.address)).to.be.true;
      expect(await treasury.epochClaimedTotal(0)).to.equal(grossAmount);
      expect(await treasury.pharmacyClaimedThisEpoch(0, pharmacy1.address)).to.equal(grossAmount);
    });

    it("allows multiple distinct pharmacies to claim their offline allocations independently", async function () {
      const proof1 = localTree.getProofForPharmacy(pharmacy1.address);
      const proof2 = localTree.getProofForPharmacy(pharmacy2.address);

      await treasury.connect(pharmacy1).claim(BigInt(proof1.entry.grossAmount), BigInt(proof1.entry.eligibleCap), proof1.proof);
      await treasury.connect(pharmacy2).claim(BigInt(proof2.entry.grossAmount), BigInt(proof2.entry.eligibleCap), proof2.proof);

      expect(await treasury.hasClaimed(0, pharmacy1.address)).to.be.true;
      expect(await treasury.hasClaimed(0, pharmacy2.address)).to.be.true;
      expect(await treasury.hasClaimed(0, pharmacy3.address)).to.be.false;

      const totalClaimed = BigInt(proof1.entry.grossAmount) + BigInt(proof2.entry.grossAmount);
      expect(await treasury.epochClaimedTotal(0)).to.equal(totalClaimed);
    });
  });

  describe("5. Adversarial Attacks & Fail-Closed Guardrails", function () {
    let snapshotEntries;
    let localTree;

    beforeEach(async function () {
      snapshotEntries = [
        { pharmacy: pharmacy1.address, grossAmount: toWei("500").toString(), eligibleCap: toWei("2000").toString() },
        { pharmacy: pharmacy2.address, grossAmount: toWei("1200").toString(), eligibleCap: toWei("3000").toString() }
      ];

      localTree = drillEngine.buildLocalSnapshotTree(snapshotEntries);
      const epoch = await treasury.currentEpoch();
      await treasury.connect(council).proposeRoot(localTree.root, BigInt(localTree.totalAmount));
      await treasury.connect(rootConfirmer).confirmRoot(epoch);
    });

    it("blocks client-side replay attacks with duplicate nonce or nullifier", function () {
      const seenNullifiers = new Set();
      const seenNonces = new Set();

      const voucher1 = drillEngine.generateOfflineVoucher({
        roundId: 1,
        pharmacy: pharmacy1.address,
        grossAmount: "500",
        eligibleCap: "2000",
        secret: testSecret
      });

      // First verification succeeds
      const res1 = drillEngine.verifyOfflineVoucherClientSide(voucher1, testSecret, { seenNullifiers, seenNonces });
      expect(res1.valid).to.be.true;

      // Replaying the exact same voucher fails
      expect(() => {
        drillEngine.verifyOfflineVoucherClientSide(voucher1, testSecret, { seenNullifiers, seenNonces });
      }).to.throw(/DUPLICATE_NONCE|REPLAY_ATTACK_DETECTED/);

      // Reusing the same nonce in a new voucher fails
      const duplicateNonceVoucher = drillEngine.generateOfflineVoucher({
        roundId: 1,
        pharmacy: pharmacy2.address,
        grossAmount: "1200",
        eligibleCap: "3000",
        nonce: voucher1.nonce,
        secret: testSecret
      });

      expect(() => {
        drillEngine.verifyOfflineVoucherClientSide(duplicateNonceVoucher, testSecret, { seenNullifiers, seenNonces });
      }).to.throw(/DUPLICATE_NONCE/);
    });

    it("blocks signature tampering attacks (altered amount, recipient, or HMAC)", function () {
      const voucher = drillEngine.generateOfflineVoucher({
        roundId: 1,
        pharmacy: pharmacy1.address,
        grossAmount: "500",
        eligibleCap: "2000",
        secret: testSecret
      });

      // Tamper amount
      const tamperedAmount = { ...voucher, grossAmount: "999999" };
      expect(() => {
        drillEngine.verifyOfflineVoucherClientSide(tamperedAmount, testSecret);
      }).to.throw("INVALID_HMAC_SIGNATURE");

      // Tamper pharmacy address
      const tamperedPharmacy = { ...voucher, pharmacy: pharmacy2.address };
      expect(() => {
        drillEngine.verifyOfflineVoucherClientSide(tamperedPharmacy, testSecret);
      }).to.throw("INVALID_HMAC_SIGNATURE");

      // Tamper MAC string
      const tamperedMac = { ...voucher, mac: `0x${"0".repeat(64)}` };
      expect(() => {
        drillEngine.verifyOfflineVoucherClientSide(tamperedMac, testSecret);
      }).to.throw("INVALID_HMAC_SIGNATURE");
    });

    it("blocks expired vouchers past their expiration deadline", function () {
      const expiredVoucher = drillEngine.generateOfflineVoucher({
        roundId: 1,
        pharmacy: pharmacy1.address,
        grossAmount: "500",
        eligibleCap: "2000",
        secret: testSecret,
        expiryMs: -5000 // already expired
      });

      expect(() => {
        drillEngine.verifyOfflineVoucherClientSide(expiredVoucher, testSecret);
      }).to.throw("VOUCHER_EXPIRED");
    });

    it("reverts on-chain double-claim replay attempts with AlreadyClaimed", async function () {
      const proofObj = localTree.getProofForPharmacy(pharmacy1.address);
      const grossAmount = BigInt(proofObj.entry.grossAmount);
      const eligibleCap = BigInt(proofObj.entry.eligibleCap);

      // First claim succeeds
      await treasury.connect(pharmacy1).claim(grossAmount, eligibleCap, proofObj.proof);

      // Replay attempt reverts with AlreadyClaimed
      await expectRevert(
        treasury.connect(pharmacy1).claim(grossAmount, eligibleCap, proofObj.proof),
        "AlreadyClaimed"
      );
    });

    it("reverts on-chain claims with forged or tampered Merkle amounts with InvalidProof", async function () {
      const proofObj = localTree.getProofForPharmacy(pharmacy1.address);
      const grossAmount = BigInt(proofObj.entry.grossAmount);
      const eligibleCap = BigInt(proofObj.entry.eligibleCap);

      // Tampered amount (attempting to claim more)
      await expectRevert(
        treasury.connect(pharmacy1).claim(grossAmount + toWei("100"), eligibleCap, proofObj.proof),
        "InvalidProof"
      );

      // Tampered cap
      await expectRevert(
        treasury.connect(pharmacy1).claim(grossAmount, eligibleCap + toWei("500"), proofObj.proof),
        "InvalidProof"
      );

      // Attacker attempting to use pharmacy1's proof
      await expectRevert(
        treasury.connect(attacker).claim(grossAmount, eligibleCap, proofObj.proof),
        "InvalidProof"
      );
    });

    it("reverts on-chain claims from sanctioned addresses with Sanctioned", async function () {
      const proofObj = localTree.getProofForPharmacy(pharmacy1.address);
      const grossAmount = BigInt(proofObj.entry.grossAmount);
      const eligibleCap = BigInt(proofObj.entry.eligibleCap);

      // Council sanctions pharmacy1
      await treasury.connect(council).updateSanction(pharmacy1.address, true, "Regulatory suspension");

      await expectRevert(
        treasury.connect(pharmacy1).claim(grossAmount, eligibleCap, proofObj.proof),
        "Sanctioned"
      );
    });
  });

  describe("6. Complete Zero-Database Drill Execution & CLI Tool", function () {
    it("executes the full programmatic drill runner and returns DRILL_PASSED", function () {
      const drillResult = drillEngine.runZeroDatabaseDrill({
        secret: testSecret,
        roundId: 1,
        pharmacies: [
          { pharmacy: pharmacy1.address, grossAmount: "1000", eligibleCap: "5000" },
          { pharmacy: pharmacy2.address, grossAmount: "2000", eligibleCap: "5000" }
        ]
      });

      expect(drillResult.status).to.equal("DRILL_PASSED");
      expect(drillResult.databaseOutageSimulated).to.be.true;
      expect(drillResult.vouchersGenerated).to.equal(2);
      expect(drillResult.vouchersVerifiedOffline).to.equal(2);
      expect(drillResult.merkleReconstructionPassed).to.be.true;
      expect(drillResult.adversarialReplayBlocked).to.be.true;
      expect(drillResult.adversarialTamperingBlocked).to.be.true;
      expect(drillResult.adversarialExpirationBlocked).to.be.true;
    });

    it("executes the CLI script via child_process and verifies exit code 0 and JSON output", function () {
      const res = spawnSync(process.execPath, [drillToolPath, "run"], {
        cwd: repoRoot,
        encoding: "utf8",
        env: { ...process.env, LOCAL_MAC_SECRET: testSecret }
      });

      expect(res.status).to.equal(0);
      expect(res.stdout).to.include("Starting Zero-Database Resilience & Continuity Drill");
      expect(res.stdout).to.include("DRILL_PASSED");

      const lines = res.stdout.trim().split("\n");
      const jsonStr = lines.slice(1).join("\n");
      const parsed = JSON.parse(jsonStr);

      expect(parsed.status).to.equal("DRILL_PASSED");
      expect(parsed.databaseOutageSimulated).to.be.true;
      expect(parsed.merkleReconstructionPassed).to.be.true;
    });
  });
});
