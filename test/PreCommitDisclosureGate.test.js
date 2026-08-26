const { expect } = require("chai");
const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

describe("Pre-commit disclosure gate", () => {
  const repoRoot = path.join(__dirname, "..");
  const auditScript = path.join(repoRoot, "scripts", "pre_commit_audit.py");
  const cacheDir = path.join(repoRoot, "cache", "precommit-test");
  const filesManifest = path.join(cacheDir, "files.txt");
  const diffFile = path.join(cacheDir, "diff.patch");
  const fakeReviewer = path.join(cacheDir, "fake_openrouter_review.py");
  const argvCapture = path.join(cacheDir, "reviewer-argv.json");
  const tempDiff = path.join(repoRoot, "reviews", "temp-pre-commit-diff.txt");
  const guardrailReview = path.join(repoRoot, "reviews", "guardrail-review.txt");
  const guardrailMetadata = path.join(repoRoot, "reviews", "guardrail-router-metadata.json");
  const disclosureReceipt = path.join(repoRoot, "reviews", "pre-commit-disclosure-receipt.json");
  const reviewArtifacts = [guardrailReview, guardrailMetadata, disclosureReceipt];
  let reviewArtifactSnapshot;

  function ensureHarness() {
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(fakeReviewer, [
      "import json",
      "import os",
      "import sys",
      `repo_root = ${JSON.stringify(repoRoot)}`,
      `argv_capture = ${JSON.stringify(argvCapture)}`,
      "os.makedirs(os.path.dirname(argv_capture), exist_ok=True)",
      "with open(argv_capture, 'w', encoding='utf-8') as handle:",
      "    json.dump(sys.argv[1:], handle, indent=2)",
      "reviews_dir = os.path.join(repo_root, 'reviews')",
      "os.makedirs(reviews_dir, exist_ok=True)",
      "mode = os.environ.get('PBM_PRE_COMMIT_REVIEWER_MODE', 'pass')",
      "with open(os.path.join(reviews_dir, 'guardrail-review.txt'), 'w', encoding='utf-8') as handle:",
      "    handle.write('FAIL\\n' if mode == 'fail' else 'PASS\\n')",
      "with open(os.path.join(reviews_dir, 'guardrail-router-metadata.json'), 'w', encoding='utf-8') as handle:",
      "    json.dump({'provider': 'local_stub', 'network_dispatch_attempted': False}, handle, indent=2)",
      "sys.exit(0)",
      ""
    ].join("\n"), "utf-8");
  }

  function cleanupHarness() {
    for (const file of [
      filesManifest,
      diffFile,
      fakeReviewer,
      argvCapture,
      tempDiff
    ]) {
      if (fs.existsSync(file)) fs.unlinkSync(file);
    }
  }

  function snapshotReviewArtifacts() {
    return new Map(reviewArtifacts.map((file) => [
      file,
      fs.existsSync(file) ? fs.readFileSync(file, "utf-8") : null
    ]));
  }

  function restoreReviewArtifacts(snapshot) {
    for (const [file, content] of snapshot.entries()) {
      if (content === null) {
        if (fs.existsSync(file)) fs.unlinkSync(file);
      } else {
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, content, "utf-8");
      }
    }
  }

  function runAudit({ files, diff, approval, mode = "pass", expectFailure = false }) {
    ensureHarness();
    fs.writeFileSync(filesManifest, files.join("\n") + "\n", "utf-8");
    fs.writeFileSync(diffFile, diff, "utf-8");

    const env = {
      ...process.env,
      PBM_PRE_COMMIT_STAGED_FILES_MANIFEST: filesManifest,
      PBM_PRE_COMMIT_STAGED_DIFF_FILE: diffFile,
      PBM_PRE_COMMIT_REVIEWER_SCRIPT: fakeReviewer,
      PBM_PRE_COMMIT_REVIEWER_MODE: mode
    };
    delete env.PBM_APPROVE_EXTERNAL_REVIEW;
    delete env.PBM_APPROVED_DISCLOSURE_CLASS;
    if (approval) env.PBM_APPROVE_EXTERNAL_REVIEW = approval;

    try {
      const output = execFileSync("python", [auditScript], {
        cwd: repoRoot,
        env,
        encoding: "utf-8",
        stdio: ["ignore", "pipe", "pipe"]
      });
      if (expectFailure) expect.fail("pre_commit_audit.py should have failed");
      return { output, code: 0 };
    } catch (err) {
      const output = `${err.stdout ? err.stdout.toString() : ""}${err.stderr ? err.stderr.toString() : ""}`;
      if (!expectFailure) expect.fail(output);
      return { output, code: err.status };
    }
  }

  beforeEach(() => {
    cleanupHarness();
    reviewArtifactSnapshot = snapshotReviewArtifacts();
  });

  afterEach(() => {
    cleanupHarness();
    restoreReviewArtifacts(reviewArtifactSnapshot);
  });

  it("skips external review without exact PUBLIC_SAFE approval but allows local commit", () => {
    const result = runAudit({
      files: ["docs/ops/KNOWN_FAILURE_POSTMORTEMS.md"],
      diff: "diff --git a/docs/ops/KNOWN_FAILURE_POSTMORTEMS.md b/docs/ops/KNOWN_FAILURE_POSTMORTEMS.md\n+public doc edit\n"
    });

    expect(result.output).to.include("Packet tier: PUBLIC_SAFE");
    expect(result.output).to.include("missing approval");
    expect(result.output).to.include("Local pre-commit disclosure gate passed without external review");
    expect(fs.existsSync(argvCapture)).to.equal(false);
    expect(fs.existsSync(tempDiff)).to.equal(false);
  });

  it("routes only approved PUBLIC_SAFE staged diffs to the reviewer stub", () => {
    const result = runAudit({
      files: ["docs/ops/KNOWN_FAILURE_POSTMORTEMS.md"],
      diff: "diff --git a/docs/ops/KNOWN_FAILURE_POSTMORTEMS.md b/docs/ops/KNOWN_FAILURE_POSTMORTEMS.md\n+public doc edit\n",
      approval: "PUBLIC_SAFE"
    });

    expect(result.output).to.include("AI Guardrail Review: PASS");
    const argv = JSON.parse(fs.readFileSync(argvCapture, "utf-8"));
    expect(argv).to.include("--context");
    expect(argv).to.include("--disclosure-class");
    expect(argv[argv.indexOf("--disclosure-class") + 1]).to.equal("PUBLIC_SAFE");
    expect(argv[argv.indexOf("--approve-disclosure") + 1]).to.equal("PUBLIC_SAFE");
    expect(fs.existsSync(tempDiff)).to.equal(false);
  });

  it("keeps internal code local-only even with legacy LOCAL_CODE_DIRTY approval", () => {
    const result = runAudit({
      files: ["scripts/pre_commit_audit.py"],
      diff: "diff --git a/scripts/pre_commit_audit.py b/scripts/pre_commit_audit.py\n+print('local code')\n",
      approval: "LOCAL_CODE_DIRTY"
    });

    expect(result.output).to.include("Packet tier: INTERNAL_NO_TRAIN_OK");
    expect(result.output).to.include("missing approval");
    expect(result.output).to.include("packet tier INTERNAL_NO_TRAIN_OK is not externally reviewable");
    expect(result.output).to.include("Local pre-commit disclosure gate passed without external review");
    expect(fs.existsSync(argvCapture)).to.equal(false);
  });

  it("keeps cache and reviews paths local-only even when content exists", () => {
    const result = runAudit({
      files: ["cache/verification_master_receipt.json", "reviews/guardrail-review.txt"],
      diff: "diff --git a/cache/verification_master_receipt.json b/cache/verification_master_receipt.json\n+{}\n",
      approval: "PUBLIC_SAFE"
    });

    expect(result.output).to.include("path prefix blocked from external pre-commit review");
    expect(result.output).to.include("cache/verification_master_receipt.json");
    expect(result.output).to.include("reviews/guardrail-review.txt");
    expect(result.output).to.include("Local pre-commit disclosure gate passed without external review");
    expect(fs.existsSync(argvCapture)).to.equal(false);
  });

  it("blocks local-only markers before reviewer dispatch", () => {
    const markerName = ["api", "_", "key"].join("");
    const fakeValue = ["sk", "live", "redacted", "fixture", "12345"].join("_");
    const addedCredentialLine = `+${markerName} = '${fakeValue}'`;
    const result = runAudit({
      files: ["docs/ops/KNOWN_FAILURE_POSTMORTEMS.md"],
      diff: [
        "diff --git a/docs/ops/KNOWN_FAILURE_POSTMORTEMS.md b/docs/ops/KNOWN_FAILURE_POSTMORTEMS.md",
        "deleted file mode 100644",
        "--- a/docs/ops/KNOWN_FAILURE_POSTMORTEMS.md",
        "+++ /dev/null",
        addedCredentialLine
      ].join("\n"),
      approval: "PUBLIC_SAFE",
      expectFailure: true
    });

    expect(result.output).to.include("staged deletions are blocked");
    expect(result.output).to.include("credential_assignment");
    expect(result.output).to.include("Local pre-commit disclosure gate blocked this commit");
    expect(fs.existsSync(argvCapture)).to.equal(false);
    expect(fs.existsSync(tempDiff)).to.equal(false);
  });

  it("blocks local-only paths before reviewer dispatch", () => {
    const result = runAudit({
      files: [".env.local"],
      diff: "diff --git a/.env.local b/.env.local\n+PBM_SECRET=redacted-placeholder\n",
      approval: "PUBLIC_SAFE",
      expectFailure: true
    });

    expect(result.output).to.include("Packet tier: LOCAL_ONLY_REQUIRED");
    expect(result.output).to.include("LOCAL_ONLY_REQUIRED cannot pass");
    expect(fs.existsSync(argvCapture)).to.equal(false);
    expect(fs.existsSync(tempDiff)).to.equal(false);
  });

  it("propagates reviewer FAIL without network", () => {
    const result = runAudit({
      files: ["docs/ops/KNOWN_FAILURE_POSTMORTEMS.md"],
      diff: "diff --git a/docs/ops/KNOWN_FAILURE_POSTMORTEMS.md b/docs/ops/KNOWN_FAILURE_POSTMORTEMS.md\n+public doc edit\n",
      approval: "PUBLIC_SAFE",
      mode: "fail",
      expectFailure: true
    });

    expect(result.output).to.include("AI Guardrail Review: FAIL");
    const metadata = JSON.parse(fs.readFileSync(guardrailMetadata, "utf-8"));
    expect(metadata.network_dispatch_attempted).to.equal(false);
    expect(fs.existsSync(tempDiff)).to.equal(false);
  });
});
