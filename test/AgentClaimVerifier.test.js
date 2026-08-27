const { expect } = require("chai");
const { execSync, execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

describe("Agent Claim Lie Detector & Receipt Cross-Auditor", () => {
  const repoRoot = path.resolve(__dirname, "..");
  const verifierScript = path.join(repoRoot, "scripts", "verify_agent_claims.py");
  const tempDir = path.join(repoRoot, "cache");
  let activeTempFiles = [];


  function createTempDossier(content) {
    fs.mkdirSync(tempDir, { recursive: true });
    const tempFile = path.join(tempDir, `temp_test_dossier_${process.pid}_${Date.now()}_${Math.random().toString(36).substring(7)}.md`);
    fs.writeFileSync(tempFile, content, "utf-8");
    activeTempFiles.push(tempFile);
    return tempFile;
  }

  function createTempReceipt(overrides = {}) {
    fs.mkdirSync(tempDir, { recursive: true });
    const tempFile = path.join(tempDir, `temp_test_receipt_${process.pid}_${Date.now()}_${Math.random().toString(36).substring(7)}.json`);
    const receipt = {
      timestamp: "2026-08-27T00:00:00Z",
      overall_status: "PASSED",
      expected_step_count: 9,
      steps_executed: 9,
      git_lineage: {
        head_commit: "4a892575d1ef15486baedcc4012a7ec87c0d3838",
        branch: "main",
        is_dirty: true,
        dirty_file_count: 0,
        lineage_tag: "[dirty working tree]"
      },
      steps: [],
      ...overrides
    };
    fs.writeFileSync(tempFile, JSON.stringify(receipt, null, 2), "utf-8");
    activeTempFiles.push(tempFile);
    return tempFile;
  }

  afterEach(() => {
    for (const f of activeTempFiles) {
      if (fs.existsSync(f)) {
        try { fs.unlinkSync(f); } catch (e) {}
      }
    }
    activeTempFiles = [];
  });


  it("passes genuine rotational swarm review dossier with 0 violations", () => {
    const targetPath = path.join(repoRoot, "reviews", "rotational_swarm_review_dossier.md");
    const receiptPath = createTempReceipt();
    const output = execFileSync("python", ["-B", verifierScript, "--target", targetPath, "--receipt", receiptPath, "--json"], {
      cwd: repoRoot,
      encoding: "utf-8"
    });

    const report = JSON.parse(output);
    expect(report.status).to.equal("PASSED");
    expect(report.total_violations).to.equal(0);
    expect(report.violations).to.be.an("array").that.is.empty;
    expect(report.total_claims_checked).to.be.greaterThan(0);
    expect(report.receipt_cross_audit.receipt_found).to.be.true;
  });

  it("passes constructed genuine dossier with valid git commit HEAD and line citations", () => {
    const validDossier = `# Genuine Multi-Agent Verification Dossier
> Synthesis generated with empirical proofs.
> - Git Baseline: [committed HEAD]
> - Test Execution: [live verification just run]

## Invariant Checks
- **Invariant 1**: Treasury dispute window is protected in \`contracts/PBMRebateTreasury.sol:190\` [committed HEAD].
- **Invariant 2**: Circuit signals isolated in \`circuits/vote_nullifier.circom\` (lines 18-40) [dirty working tree].
- **Finding**: Hardhat test suite passes 280/280 tests [live verification just run].
- **Finding**: Fixture gate tests in \`test/ZKNullifierCircuit.test.js\` (lines 1-9) pass cleanly [live verification just run].

Commit under test: \`4a892575d1ef15486baedcc4012a7ec87c0d3838\` [committed HEAD].
`;
    const tempFile = createTempDossier(validDossier);



    const output = execSync(`python "${verifierScript}" --target "${tempFile}" --json`, {
      cwd: repoRoot,
      encoding: "utf-8"
    });

    const report = JSON.parse(output);
    expect(report.status).to.equal("PASSED");
    expect(report.total_violations).to.equal(0);
    expect(report.violations).to.be.empty;
  });

  it("rejects hostile dossier with hallucinated line numbers exceeding file bounds", () => {
    const hostileDossier = `# Hostile Dossier With Hallucinated Lines
- **Finding**: Treasury line 9999 contains secret backdoor in \`contracts/PBMRebateTreasury.sol:9999\` [live verification just run].
- **Finding**: Circuit line 500 contains flaw in \`circuits/vote_nullifier.circom\` (lines 500-600) [dirty working tree].
`;
    const tempFile = createTempDossier(hostileDossier);

    try {
      execSync(`python "${verifierScript}" --target "${tempFile}" --json`, {
        cwd: repoRoot,
        encoding: "utf-8",
        stdio: "pipe"
      });
      expect.fail("Should have thrown error on hallucinated line numbers");
    } catch (err) {
      const output = err.stdout.toString() + err.stderr.toString();
      const jsonStart = output.indexOf("{");
      const report = JSON.parse(output.substring(jsonStart));
      expect(report.status).to.equal("REJECTED");
      expect(report.total_violations).to.be.greaterThan(0);
      
      const categories = report.violations.map(v => v.category);
      expect(categories).to.include("hallucinated_line_number");
    }
  });

  it("rejects hostile dossier citing non-existent files in workspace", () => {
    const hostileDossier = `# Hostile Dossier With Non-Existent Files
- **Finding**: Audited ghost contract \`contracts/FakeGhostTreasury.sol:25\` [live verification just run].
- **Finding**: Audited phantom test in \`test/PhantomCircuitExploit.test.js\` (lines 1-10) [dirty working tree].
`;
    const tempFile = createTempDossier(hostileDossier);

    try {
      execSync(`python "${verifierScript}" --target "${tempFile}" --json`, {
        cwd: repoRoot,
        encoding: "utf-8",
        stdio: "pipe"
      });
      expect.fail("Should have thrown error on non-existent files");
    } catch (err) {
      const output = err.stdout.toString() + err.stderr.toString();
      const jsonStart = output.indexOf("{");
      const report = JSON.parse(output.substring(jsonStart));
      expect(report.status).to.equal("REJECTED");
      
      const categories = report.violations.map(v => v.category);
      expect(categories).to.include("missing_cited_file");
    }
  });

  it("rejects hostile dossier citing fake/hallucinated git commit hashes", () => {
    const hostileDossier = `# Hostile Dossier With Fake Git Commit
HEAD Baseline Commit: \`deadbeef1234567890deadbeef1234567890\` [committed HEAD]
- **Invariant**: Validated against fake commit hash deadbeef1234567890deadbeef1234567890 [committed HEAD].
`;
    const tempFile = createTempDossier(hostileDossier);

    try {
      execSync(`python "${verifierScript}" --target "${tempFile}" --json`, {
        cwd: repoRoot,
        encoding: "utf-8",
        stdio: "pipe"
      });
      expect.fail("Should have thrown error on fake git commit hash");
    } catch (err) {
      const output = err.stdout.toString() + err.stderr.toString();
      const jsonStart = output.indexOf("{");
      const report = JSON.parse(output.substring(jsonStart));
      expect(report.status).to.equal("REJECTED");
      
      const categories = report.violations.map(v => v.category);
      expect(categories).to.include("fake_commit_hash");
    }
  });

  it("rejects hostile dossier with fake/hallucinated test counts and step count tampering", () => {
    const hostileDossier = `# Hostile Dossier With Fake Test Counts
- **Finding**: Hardhat test suite passes 9999/9999 unit tests [live verification just run].
- **Finding**: Expected master steps expected_step_count: 99 [generated cache].
`;
    const tempFile = createTempDossier(hostileDossier);

    try {
      execSync(`python "${verifierScript}" --target "${tempFile}" --json`, {
        cwd: repoRoot,
        encoding: "utf-8",
        stdio: "pipe"
      });
      expect.fail("Should have thrown error on fake test counts");
    } catch (err) {
      const output = err.stdout.toString() + err.stderr.toString();
      const jsonStart = output.indexOf("{");
      const report = JSON.parse(output.substring(jsonStart));
      expect(report.status).to.equal("REJECTED");
      
      const categories = report.violations.map(v => v.category);
      expect(categories).to.satisfy(cats => 
        cats.includes("fake_test_count") || cats.includes("test_count_mismatch")
      );
    }
  });

  it("rejects ungrounded claims and invalid lineage tags", () => {
    const hostileDossier = `# Hostile Dossier With Invalid Lineage Tags
- **Invariant**: Treasury is completely safe and unbreakable [hallucinated lineage tag].
- **Finding**: Database proxy has 0 bugs and verified clean.
`;
    const tempFile = createTempDossier(hostileDossier);


    try {
      execSync(`python "${verifierScript}" --target "${tempFile}" --json`, {
        cwd: repoRoot,
        encoding: "utf-8",
        stdio: "pipe"
      });
      expect.fail("Should have thrown error on ungrounded claims and invalid tags");
    } catch (err) {
      const output = err.stdout.toString() + err.stderr.toString();
      const jsonStart = output.indexOf("{");
      const report = JSON.parse(output.substring(jsonStart));
      expect(report.status).to.equal("REJECTED");
      
      const categories = report.violations.map(v => v.category);
      expect(categories).to.satisfy(cats =>
        cats.includes("invalid_lineage_tag") || cats.includes("ungrounded_claim")
      );
    }
  });

  it("supports reading review dossier content via standard input (stdin)", () => {
    const validDossier = `# Genuine Stdin Dossier
- **Invariant**: PBM Rebate Treasury dispute appeal window \`contracts/PBMRebateTreasury.sol:190\` [committed HEAD].
`;
    const output = execFileSync("python", ["-B", verifierScript, "--json"], {

      cwd: repoRoot,
      input: validDossier,
      encoding: "utf-8"
    });


    const report = JSON.parse(output);
    expect(report.status).to.equal("PASSED");
    expect(report.verified_targets).to.include("<stdin>");
  });
});
