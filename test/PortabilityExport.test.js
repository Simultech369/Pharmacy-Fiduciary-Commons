const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("node:fs");
const path = require("node:path");
const { main } = require("../scripts/export-portability");
const { verifyPayload } = require("../scripts/verify-export");

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
    token = await MockERC20.deploy("Mock DAI", "mDAI");
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
      council.address,
      await timelock.getAddress(),
      guardian.address
    );
    await treasury.waitForDeployment();

    // Deploy Participatory Budgeting
    const PB = await ethers.getContractFactory("PatientFundParticipatoryBudgeting");
    pb = await PB.deploy(await token.getAddress(), council.address);
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
    const councilRole = await treasury.councilRole();
    await treasury.connect(council).grantRole(councilRole, council2.address);
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

    // Validate claims array
    expect(payload.claims).to.have.lengthOf(1);
    const c = payload.claims[0];
    expect(c.claimId).to.equal(`claim-0-${pharmacy.address}`);
    expect(c.patientId).to.equal("patient-epoch-0");
    expect(c.pharmacyAddress).to.equal(pharmacy.address);
    expect(c.ndc).to.equal("unavailable-off-chain");
    expect(c.quantity).to.equal(1);
    expect(c.metadataProvenance).to.equal("synthetic-placeholder");
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

    const verification = verifyPayload(payload);
    expect(verification.ok).to.be.true;
    expect(verification.errors).to.deep.equal([]);

    const tampered = structuredClone(payload);
    tampered.merkle_proofs[0].eligibleCap = toWei("101").toString();
    const tamperedVerification = verifyPayload(tampered);
    expect(tamperedVerification.ok).to.be.false;
    expect(tamperedVerification.errors.join(" | ")).to.contain("does not verify");
  });
});
