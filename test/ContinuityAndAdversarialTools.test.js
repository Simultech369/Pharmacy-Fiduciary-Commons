const { expect } = require("chai");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

describe("Continuity and adversarial draft tools", function () {
  const repoRoot = path.resolve(__dirname, "..");
  const continuityTool = path.join(repoRoot, "tools", "resilience", "continuity-engine.mjs");
  const adversarialTool = path.join(repoRoot, "tools", "security", "adversarial-guard.mjs");

  function nodeTool(args, options = {}) {
    return spawnSync(process.execPath, args, {
      cwd: options.cwd || repoRoot,
      encoding: "utf8",
      env: { ...process.env, ...options.env }
    });
  }

  function voucherMac(voucher, secret) {
    const message = `${voucher.roundId}:${voucher.nullifier.replace("0x", "")}`;
    return `0x${crypto.createHmac("sha256", secret).update(message).digest("hex").slice(0, 16)}`;
  }

  it("generates offline vouchers without storing voter addresses", function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "continuity-generate-"));
    const result = nodeTool([continuityTool, "generate-voucher", "7"], {
      cwd: tempDir,
      env: { LOCAL_MAC_SECRET: "test-secret-for-continuity" }
    });

    const exportsDir = path.join(tempDir, "exports");
    const generatedFile = fs.readdirSync(exportsDir).find((file) => file.startsWith("voucher-7-"));
    const voucher = JSON.parse(fs.readFileSync(path.join(exportsDir, generatedFile), "utf8"));

    expect(result.status).to.equal(0);
    expect(result.stdout).to.include("Voter:      not stored");
    expect(voucher).to.not.have.property("voter");
    expect(voucher.warning).to.include("voter identity is intentionally not stored");

    const verifyResult = nodeTool([continuityTool, "verify-offline", path.join(exportsDir, generatedFile)], {
      env: { LOCAL_MAC_SECRET: "test-secret-for-continuity" }
    });
    expect(verifyResult.status).to.equal(0);
    expect(verifyResult.stdout).to.include("Voter Address:      not stored");
  });

  it("fails closed when offline voucher MAC verification fails", function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "continuity-tool-"));
    const voucherPath = path.join(tempDir, "voucher-bad.json");

    fs.writeFileSync(
      voucherPath,
      JSON.stringify(
        {
          roundId: 1,
          preimage: "0x1111111111111111111111111111111111111111111111111111111111111111",
          nullifier: "0x2222222222222222222222222222222222222222222222222222222222222222",
          mac: "0xdeadbeefdeadbeef"
        },
        null,
        2
      )
    );

    const result = nodeTool([continuityTool, "verify-offline", voucherPath], {
      env: { LOCAL_MAC_SECRET: "test-secret-for-continuity" }
    });

    expect(result.status).to.equal(1);
    expect(result.stderr).to.include("OFFLINE VERIFICATION FAILED");
    expect(result.stdout).to.not.include("OFFLINE SCHEMA VERIFICATION RESULT: PASSED");
    expect(result.stdout).to.not.include("Verified Status:    TRUE");
  });

  it("packages relay intake without exporting voucher preimages as mock ZK proofs", function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "continuity-relay-"));
    const voucherPath = path.join(tempDir, "voucher-1-deadbeef.json");
    const outputPath = path.join(tempDir, "relay-batch.json");
    const secret = "test-secret-for-continuity";
    const preimage = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const voter = "0x0000000000000000000000000000000000000001";
    const voucher = {
      roundId: 1,
      preimage,
      nullifier: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      status: "pending_sync"
    };
    voucher.mac = voucherMac(voucher, secret);

    fs.writeFileSync(voucherPath, JSON.stringify(voucher, null, 2));

    const result = nodeTool([continuityTool, "package-relay", tempDir, outputPath], {
      env: { LOCAL_MAC_SECRET: secret }
    });
    const batch = JSON.parse(fs.readFileSync(outputPath, "utf8"));

    expect(result.status).to.equal(0);
    expect(result.stdout).to.include("NOT READY FOR ON-CHAIN SUBMISSION");
    expect(batch).to.have.lengthOf(1);
    expect(batch[0]).to.not.have.property("voter");
    expect(batch[0]).to.not.have.property("proof");
    expect(batch[0]).to.not.have.property("voucherPreimageHash");
    expect(JSON.stringify(batch)).to.not.include(preimage);
    expect(JSON.stringify(batch)).to.not.include(voter);
    expect(batch[0].proofRequired).to.include("verifier-signed mock ZK attestation");
  });

  it("refuses to package duplicate relay nullifiers", function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "continuity-relay-duplicate-"));
    const outputPath = path.join(tempDir, "relay-batch.json");
    const secret = "test-secret-for-continuity";
    const nullifier = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    for (const filename of ["voucher-1-first.json", "voucher-1-second.json"]) {
      const voucher = {
        roundId: 1,
        preimage: `0x${filename.includes("first") ? "a" : "c"}`.padEnd(66, filename.includes("first") ? "a" : "c"),
        nullifier,
        status: "pending_sync"
      };
      voucher.mac = voucherMac(voucher, secret);
      fs.writeFileSync(path.join(tempDir, filename), JSON.stringify(voucher, null, 2));
    }

    const result = nodeTool([continuityTool, "package-relay", tempDir, outputPath], {
      env: { LOCAL_MAC_SECRET: secret }
    });

    expect(result.status).to.equal(1);
    expect(result.stderr).to.include("Duplicate nullifier detected");
    expect(fs.existsSync(outputPath)).to.equal(false);
  });

  it("refuses to package relay batches when voucher MAC validation fails", function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "continuity-relay-bad-"));
    const voucherPath = path.join(tempDir, "voucher-1-deadbeef.json");
    const outputPath = path.join(tempDir, "relay-batch.json");

    fs.writeFileSync(
      voucherPath,
      JSON.stringify(
        {
          roundId: 1,
          preimage: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          nullifier: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          mac: "0x1234567890abcdef",
          status: "pending_sync"
        },
        null,
        2
      )
    );

    const result = nodeTool([continuityTool, "package-relay", tempDir, outputPath], {
      env: { LOCAL_MAC_SECRET: "test-secret-for-continuity" }
    });

    expect(result.status).to.equal(1);
    expect(result.stderr).to.include("OFFLINE VERIFICATION FAILED");
    expect(fs.existsSync(outputPath)).to.equal(false);
  });

  it("labels tempest-fuzz as simulation-only and does not claim live target defense", function () {
    const result = nodeTool([adversarialTool, "tempest-fuzz", "http://127.0.0.1:9"]);

    expect(result.status).to.equal(0);
    expect(result.stdout).to.include("SIMULATION ONLY");
    expect(result.stdout).to.include("Local classifier result");
    expect(result.stdout).to.not.include("Target Defense: BLOCK SUCCESSFUL");
  });

  it("flags synthetic BIP-39 mnemonic leakage in support logs", function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "adversarial-leakage-"));
    const logPath = path.join(tempDir, "support.log");
    fs.writeFileSync(
      logPath,
      "seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n"
    );

    const result = nodeTool([adversarialTool, "scan-leakage", logPath]);

    expect(result.status).to.equal(1);
    expect(result.stderr).to.include("possibleMnemonic");
  });
});
