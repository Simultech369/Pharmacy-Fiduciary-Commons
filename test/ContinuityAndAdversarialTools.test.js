const { expect } = require("chai");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

describe("Continuity and adversarial draft tools", function () {
  const repoRoot = path.resolve(__dirname, "..");
  const continuityTool = path.join(repoRoot, "tools", "resilience", "continuity-engine.mjs");
  const offlineKit = path.join(repoRoot, "tools", "offline", "continuity-kit.html");
  const proxyValidator = path.join(repoRoot, "tools", "resilience", "proxy-validator.js");
  const adversarialTool = path.join(repoRoot, "tools", "security", "adversarial-guard.mjs");

  function nodeTool(args, options = {}) {
    return spawnSync(process.execPath, args, {
      cwd: options.cwd || repoRoot,
      encoding: "utf8",
      env: { ...process.env, ...options.env }
    });
  }

  function voucherMac(voucher, secret) {
    const sortedKeys = Object.keys(voucher).filter(key => key !== 'mac').sort();
    const signedFields = {};
    for (const key of sortedKeys) {
      signedFields[key] = voucher[key] ?? null;
    }
    const message = JSON.stringify(signedFields);
    return `0x${crypto.createHmac("sha256", secret).update(message).digest("hex").slice(0, 16)}`;
  }

  function makeVoucher(overrides = {}) {
    const voucher = {
      roundId: 1,
      preimage: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      nullifier: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      generatedAt: "2026-07-15T00:00:00.000Z",
      status: "pending_sync",
      proofFormat: "offline-voucher-v1-not-zk-proof",
      warning: "preimage is bearer recovery material; it is not an on-chain mock ZK proof; voter identity is intentionally not stored",
      ...overrides
    };
    voucher.mac = voucherMac(voucher, "test-secret-for-continuity");
    return voucher;
  }

  function writeJson(filePath, value) {
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2), "utf8");
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
    expect(verifyResult.stdout).to.include("LOCAL INTEGRITY ONLY");
    expect(verifyResult.stdout).to.include("NOT A ZK PROOF");
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
          generatedAt: "2026-07-15T00:00:00.000Z",
          status: "pending_sync",
          proofFormat: "offline-voucher-v1-not-zk-proof",
          warning: "preimage is bearer recovery material; it is not an on-chain mock ZK proof; voter identity is intentionally not stored",
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
    expect(result.stdout).to.not.include("LOCAL INTEGRITY ONLY");
  });

  it("fails closed when offline voucher bearer fields are mutated after MAC generation", function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "continuity-mutation-"));
    const secret = "test-secret-for-continuity";

    const mutations = [
      ["roundId", 9],
      ["preimage", "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],
      ["nullifier", "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],
      ["generatedAt", "2026-07-16T00:00:00.000Z"],
      ["status", "approved_without_sync"],
      ["proofFormat", "offline-voucher-v2-not-zk-proof"],
      ["warning", "modified warning text"]
    ];

    for (const [field, value] of mutations) {
      const voucher = makeVoucher();
      voucher[field] = value;
      const voucherPath = path.join(tempDir, `voucher-mutated-${field}.json`);
      writeJson(voucherPath, voucher);

      const result = nodeTool([continuityTool, "verify-offline", voucherPath], {
        env: { LOCAL_MAC_SECRET: secret }
      });

      expect(result.status).to.equal(1);
      expect(result.stderr).to.include("OFFLINE VERIFICATION FAILED");
      expect(result.stdout).to.not.include("LOCAL INTEGRITY ONLY");
    }
  });

  it("packages relay intake without exporting voucher preimages as mock ZK proofs", function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "continuity-relay-"));
    const voucherPath = path.join(tempDir, "voucher-1-deadbeef.json");
    const outputPath = path.join(tempDir, "relay-batch.json");
    const secret = "test-secret-for-continuity";
    const preimage = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const voter = "0x0000000000000000000000000000000000000001";
    const voucher = makeVoucher({ preimage });

    fs.writeFileSync(voucherPath, JSON.stringify(voucher, null, 2));

    const globalCachePath = path.join(tempDir, "global-nullifier-cache.json");

    const result = nodeTool([continuityTool, "package-relay", tempDir, outputPath, globalCachePath], {
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

    expect(fs.existsSync(globalCachePath)).to.equal(true);
    const persistedCache = JSON.parse(fs.readFileSync(globalCachePath, "utf8"));
    expect(persistedCache).to.include(voucher.nullifier.toLowerCase());

    const validation = nodeTool([proxyValidator, outputPath]);
    expect(validation.status).to.equal(0);
    expect(validation.stdout).to.include("PROXY INTAKE VALIDATION PASSED");
  });

  it("fails closed in a secondary process run when referencing the persisted nullifier cache file", function () {
    const secret = "test-secret-for-continuity";
    const tempDir1 = fs.mkdtempSync(path.join(os.tmpdir(), "pbm-continuity-proc1-"));
    const tempDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "pbm-continuity-proc2-"));
    const globalCachePath = path.join(tempDir1, "global-nullifier-cache.json");
    const outputPath1 = path.join(tempDir1, "relay-batch-1.json");
    const outputPath2 = path.join(tempDir2, "relay-batch-2.json");

    const preimage = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const voucher = makeVoucher({ preimage });

    // Process 1: Write voucher to tempDir1 and package relay with globalCachePath
    fs.writeFileSync(path.join(tempDir1, "voucher-001.json"), JSON.stringify(voucher, null, 2));
    const proc1Result = nodeTool([continuityTool, "package-relay", tempDir1, outputPath1, globalCachePath], {
      env: { LOCAL_MAC_SECRET: secret }
    });
    expect(proc1Result.status).to.equal(0);
    expect(fs.existsSync(globalCachePath)).to.equal(true);

    // Process 2: Write distinct voucher file in tempDir2 with SAME nullifier, package with SAME globalCachePath
    fs.writeFileSync(path.join(tempDir2, "voucher-002.json"), JSON.stringify(voucher, null, 2));
    const proc2Result = nodeTool([continuityTool, "package-relay", tempDir2, outputPath2, globalCachePath], {
      env: { LOCAL_MAC_SECRET: secret }
    });

    expect(proc2Result.status).to.not.equal(0);
    expect(proc2Result.stderr).to.include("Duplicate nullifier detected");
  });

  it("fails closed when global nullifier cache file exists but is malformed", function () {
    const secret = "test-secret-for-continuity";
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pbm-continuity-malformed-cache-"));
    const globalCachePath = path.join(tempDir, "global-nullifier-cache.json");
    const outputPath = path.join(tempDir, "relay-batch.json");

    const voucher = makeVoucher({ preimage: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" });
    fs.writeFileSync(path.join(tempDir, "voucher-001.json"), JSON.stringify(voucher, null, 2));
    fs.writeFileSync(globalCachePath, "INVALID_JSON_CONTENT");

    const result = nodeTool([continuityTool, "package-relay", tempDir, outputPath, globalCachePath], {
      env: { LOCAL_MAC_SECRET: secret }
    });

    expect(result.status).to.not.equal(0);
    expect(result.stderr).to.include("Failed to parse global nullifier cache");
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
        generatedAt: "2026-07-15T00:00:00.000Z",
        status: "pending_sync",
        proofFormat: "offline-voucher-v1-not-zk-proof",
        warning: "preimage is bearer recovery material; it is not an on-chain mock ZK proof; voter identity is intentionally not stored"
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
          generatedAt: "2026-07-15T00:00:00.000Z",
          status: "pending_sync",
          proofFormat: "offline-voucher-v1-not-zk-proof",
          warning: "preimage is bearer recovery material; it is not an on-chain mock ZK proof; voter identity is intentionally not stored",
          mac: "0x1234567890abcdef"
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

  it("ships a standalone browser continuity kit without remote resources or Node dependencies", function () {
    const html = fs.readFileSync(offlineKit, "utf8");

    expect(html).to.include("Offline Verifier Prototype / Draft");
    expect(html).to.include("crypto.subtle");
    expect(html).to.include("local integrity evidence only");
    expect(html).to.not.match(/https?:\/\//i);
    expect(html).to.not.match(/<script[^>]+src=/i);
    expect(html).to.not.include("require(");
    expect(html).to.not.include("node:");
  });

  it("validates global nullifier cache dry-run rejection on duplicate cross-batch nullifiers", async function () {
    const { pathToFileURL } = require("node:url");
    const { validateGlobalNullifierCache } = await import(pathToFileURL(continuityTool).href);
    const secret = "test-secret-for-continuity";
    process.env.LOCAL_MAC_SECRET = secret;

    const v1 = makeVoucher({ nullifier: "0x1111111111111111111111111111111111111111111111111111111111111111" });
    const globalCache = new Set(["0x1111111111111111111111111111111111111111111111111111111111111111"]);

    expect(() => validateGlobalNullifierCache([v1], globalCache)).to.throw("DUPLICATE_NULLIFIER");

    const v2 = makeVoucher({ nullifier: "0x2222222222222222222222222222222222222222222222222222222222222222" });
    expect(validateGlobalNullifierCache([v2], new Set())).to.be.true;
  });

  it("validates proxy relay batches across files as review artifacts", function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "proxy-validator-ok-"));
    writeJson(path.join(tempDir, "relay-a.json"), [
      {
        roundId: 1,
        nullifier: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        proofRequired: "verifier-signed mock ZK attestation required before registerVoterWithMockZK"
      }
    ]);
    writeJson(path.join(tempDir, "relay-b.json"), {
      entries: [
        {
          roundId: 2,
          nullifier: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          proofRequired: "verifier-signed mock ZK attestation required before registerVoterWithMockZK"
        }
      ]
    });

    const result = nodeTool([proxyValidator, tempDir]);

    expect(result.status).to.equal(0);
    expect(result.stdout).to.include("PROXY INTAKE VALIDATION PASSED");
    expect(result.stdout).to.include("not on-chain submission authority");
  });

  it("rejects duplicate nullifiers across proxy relay batch files", function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "proxy-validator-duplicate-"));
    const duplicate = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    for (const file of ["relay-a.json", "relay-b.json"]) {
      writeJson(path.join(tempDir, file), [
        {
          roundId: 1,
          nullifier: duplicate,
          proofRequired: "verifier-signed mock ZK attestation required before registerVoterWithMockZK"
        }
      ]);
    }

    const result = nodeTool([proxyValidator, tempDir]);

    expect(result.status).to.equal(1);
    expect(result.stderr).to.include("Duplicate nullifier detected");
  });

  it("rejects proxy relay batches that leak voucher preimages or wallet metadata", function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "proxy-validator-leak-"));
    writeJson(path.join(tempDir, "relay-leaky.json"), [
      {
        roundId: 1,
        nullifier: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        proofRequired: "verifier-signed mock ZK attestation required before registerVoterWithMockZK",
        preimage: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        voter: "0x0000000000000000000000000000000000000001"
      }
    ]);

    const result = nodeTool([proxyValidator, tempDir]);

    expect(result.status).to.equal(1);
    expect(result.stderr).to.include("forbidden or unsupported field");
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

  it("reconciles and classifies offline vouchers deterministically", async function () {
    const { reconcileVouchers } = await import("../tools/resilience/reconcile-vouchers.mjs");

    const vouchers = [
      { roundId: 1, nullifier: "0xaaaa" + "0".repeat(60) }, // Will be reconciled
      { roundId: 1, nullifier: "0xbbbb" + "0".repeat(60) }, // Will be duplicate_conflict
      { roundId: 1, nullifier: "0xbbbb" + "0".repeat(60) }, // Will be duplicate_conflict
      { roundId: 1, nullifier: "0xcccc" + "0".repeat(60) }, // Will be unresolved
      { roundId: 2, nullifier: "0xaaaa" + "0".repeat(60) }  // Will be unresolved (different round)
    ];

    const onChainEvents = [
      { roundId: 1, nullifier: "0xaaaa" + "0".repeat(60) },
      { roundId: 2, nullifier: "0xdddd" + "0".repeat(60) }
    ];

    const results = reconcileVouchers(vouchers, onChainEvents);

    expect(results).to.have.lengthOf(5);

    // 0xaaaa on round 1 should be reconciled
    expect(results[0].roundId).to.equal(1);
    expect(results[0].nullifier).to.equal("0xaaaa" + "0".repeat(60));
    expect(results[0].classification).to.equal("reconciled");
    expect(results[0].detail).to.include("Successfully matched");

    // 0xbbbb on round 1 should be duplicate_conflict
    expect(results[1].classification).to.equal("duplicate_conflict");
    expect(results[1].detail).to.include("Duplicate nullifier");
    expect(results[2].classification).to.equal("duplicate_conflict");

    // 0xcccc on round 1 should be unresolved
    expect(results[3].classification).to.equal("unresolved");
    expect(results[3].detail).to.include("local-only");

    // 0xaaaa on round 2 should be unresolved (since event was on round 1)
    expect(results[4].classification).to.equal("unresolved");
  });

  it("runs the reconciliation CLI tool and prints JSON report", function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "reconcile-cli-"));
    const reconcileTool = path.join(repoRoot, "tools", "resilience", "reconcile-vouchers.mjs");

    const vouchers = [
      { roundId: 1, nullifier: "0x1111" + "0".repeat(60) },
      { roundId: 1, nullifier: "0x2222" + "0".repeat(60) }
    ];
    const events = [
      { roundId: 1, nullifier: "0x1111" + "0".repeat(60) }
    ];

    const vouchersFile = path.join(tempDir, "vouchers.json");
    const eventsFile = path.join(tempDir, "events.json");

    fs.writeFileSync(vouchersFile, JSON.stringify(vouchers, null, 2));
    fs.writeFileSync(eventsFile, JSON.stringify(events, null, 2));

    const result = nodeTool([reconcileTool, vouchersFile, eventsFile]);

    expect(result.status).to.equal(0);
    const parsed = JSON.parse(result.stdout);
    expect(parsed).to.have.lengthOf(2);
    expect(parsed[0].classification).to.equal("reconciled");
    expect(parsed[1].classification).to.equal("unresolved");
  });

  it("accepts wrapped entries for reconciliation event exports", function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "reconcile-wrapped-events-"));
    const reconcileTool = path.join(repoRoot, "tools", "resilience", "reconcile-vouchers.mjs");

    const vouchersFile = path.join(tempDir, "vouchers.json");
    const eventsFile = path.join(tempDir, "events.json");
    const nullifier = "0x3333" + "0".repeat(60);

    fs.writeFileSync(
      vouchersFile,
      JSON.stringify({ entries: [{ roundId: 1, nullifier }] }, null, 2)
    );
    fs.writeFileSync(
      eventsFile,
      JSON.stringify({ entries: [{ roundId: 1, nullifier }] }, null, 2)
    );

    const result = nodeTool([reconcileTool, vouchersFile, eventsFile]);

    expect(result.status).to.equal(0);
    const parsed = JSON.parse(result.stdout);
    expect(parsed).to.have.lengthOf(1);
    expect(parsed[0].classification).to.equal("reconciled");
  });

  describe("Care Continuity & Human Capabilities Metric Calculator", function () {
    const careMetrics = path.join(repoRoot, "tools", "resilience", "care-continuity-metrics.mjs");

    it("calculates Continuous Refill Ratio (CRR) and triggers advisory alert when below 90%", async function () {
      const { calculateCRR } = await import(`file://${careMetrics}`);

      const records = [
        { patientHash: "0x1", varianceDays: 1 },
        { patientHash: "0x2", varianceDays: 2 },
        { patientHash: "0x3", varianceDays: 5 }, // non-compliant (> 3 days)
        { patientHash: "0x4", varianceDays: 7 }, // non-compliant
      ];

      const res = calculateCRR(records);
      expect(res.crr).to.equal(50.0);
      expect(res.total).to.equal(4);
      expect(res.compliantCount).to.equal(2);
      expect(res.advisoryAlert).to.equal(true);
      expect(res.targetMet).to.equal(false);
    });

    it("calculates Emergency Fill Access (EFA) ratio and target completion", async function () {
      const { calculateEFA } = await import(`file://${careMetrics}`);

      const records = [
        { pharmacyId: "0xPh1", currentCreditLimit: 5000, thirtyDayDemand: 3000 },
        { pharmacyId: "0xPh2", currentCreditLimit: 2000, thirtyDayDemand: 4000 }, // under capacity
      ];

      const res = calculateEFA(records);
      expect(res.efaRatio).to.equal(50.0);
      expect(res.total).to.equal(2);
      expect(res.compliantCount).to.equal(1);
      expect(res.targetMet).to.equal(false);
    });

    it("calculates Non-Digital Workflow Adoption (NDWA) ratio against 20% target", async function () {
      const { calculateNDWA } = await import(`file://${careMetrics}`);

      const records = [
        { id: "tx1", channel: "web_wallet" },
        { id: "tx2", channel: "web_wallet" },
        { id: "tx3", channel: "offline_voucher" },
        { id: "tx4", channel: "sms" }
      ];

      const res = calculateNDWA(records);
      expect(res.ndwaRatio).to.equal(50.0);
      expect(res.offlineCount).to.equal(2);
      expect(res.targetMet).to.equal(true);
    });

    it("generates complete care continuity report", async function () {
      const { generateCareContinuityReport } = await import(`file://${careMetrics}`);

      const report = generateCareContinuityReport(
        [{ patientHash: "0x1", varianceDays: 0 }],
        [{ pharmacyId: "0x1", currentCreditLimit: 1000, thirtyDayDemand: 1000 }],
        [{ id: "1", channel: "offline_voucher" }]
      );

      expect(report.metrics.continuousRefillRatio.crr).to.equal(100.0);
      expect(report.metrics.continuousRefillRatio.targetMet).to.equal(true);
      expect(report.advisoryActionRequired).to.equal(false);
      expect(report.provenance).to.include("Synthetic / Hashed Local Care Continuity Calculator");
    });
  });

  describe("Native State Machine Verifier", function () {
    const verifierPath = path.resolve(__dirname, "../tools/resilience/state-machine-verifier.mjs");

    it("validates valid debt queue transitions and rejects forbidden jumps", async function () {
      const { transitionDebtState, DEBT_QUEUE_STATES } = await import(`file://${verifierPath}`);

      expect(transitionDebtState(DEBT_QUEUE_STATES.UNFUNDED, DEBT_QUEUE_STATES.ALLOCATED)).to.equal(DEBT_QUEUE_STATES.ALLOCATED);
      expect(transitionDebtState(DEBT_QUEUE_STATES.ALLOCATED, DEBT_QUEUE_STATES.DISBURSED)).to.equal(DEBT_QUEUE_STATES.DISBURSED);
      expect(transitionDebtState(DEBT_QUEUE_STATES.DISBURSED, DEBT_QUEUE_STATES.RECALLED)).to.equal(DEBT_QUEUE_STATES.RECALLED);

      expect(() => transitionDebtState(DEBT_QUEUE_STATES.UNFUNDED, DEBT_QUEUE_STATES.RECALLED))
        .to.throw(/Forbidden state transition/);
    });

    it("validates valid budgeting round transitions and rejects invalid jumps", async function () {
      const { transitionBudgetingRound, BUDGETING_ROUND_STATES } = await import(`file://${verifierPath}`);

      expect(transitionBudgetingRound(BUDGETING_ROUND_STATES.INACTIVE, BUDGETING_ROUND_STATES.PROPOSAL_SUBMISSION)).to.equal(BUDGETING_ROUND_STATES.PROPOSAL_SUBMISSION);
      expect(() => transitionBudgetingRound(BUDGETING_ROUND_STATES.INACTIVE, BUDGETING_ROUND_STATES.FINALIZED))
        .to.throw(/Forbidden state transition/);
    });

    it("validates offline voucher lifecycle transitions", async function () {
      const { transitionOfflineVoucher, OFFLINE_VOUCHER_STATES } = await import(`file://${verifierPath}`);

      expect(transitionOfflineVoucher(OFFLINE_VOUCHER_STATES.ISSUED, OFFLINE_VOUCHER_STATES.CACHE_VERIFIED)).to.equal(OFFLINE_VOUCHER_STATES.CACHE_VERIFIED);
      expect(() => transitionOfflineVoucher(OFFLINE_VOUCHER_STATES.ISSUED, OFFLINE_VOUCHER_STATES.SETTLED))
        .to.throw(/Forbidden state transition/);
    });
  });
});
