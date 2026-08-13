const { expect } = require("chai");
const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

describe("Swarm observability dashboard", function () {
  const repoRoot = path.resolve(__dirname, "..");
  const dashboardScript = path.join(repoRoot, "scripts", "observability_dashboard.py");
  const summaryPath = path.join(repoRoot, "cache", "observability_summary.json");
  const localRawPath = path.join(repoRoot, "reviews", "tmp-local-raw-router-metadata.json");

  afterEach(function () {
    if (fs.existsSync(localRawPath)) {
      fs.unlinkSync(localRawPath);
    }
  });

  it("skips ignored local raw router metadata without failing the evidence gate", function () {
    fs.writeFileSync(
      localRawPath,
      JSON.stringify({
        recorded_at_utc: "2026-08-12T00:00:00Z",
        role: "local_raw_probe",
        model: "openrouter/free",
        provider: "openrouter",
        launcher: "scripts/openrouter_review.py",
        packet_path: null,
        output_path: "reviews/local-raw-probe.txt",
        disclosure_class: "LOCAL_CODE_DIRTY",
        approved_disclosure_class: "LOCAL_CODE_DIRTY",
        error_status: null,
        truncation_status: "not_reported",
        reconciliation_status: "unreconciled_raw_output"
      }, null, 2),
      "utf8"
    );

    const output = execFileSync("python", [dashboardScript], {
      cwd: repoRoot,
      encoding: "utf8"
    });
    const summary = JSON.parse(fs.readFileSync(summaryPath, "utf8"));

    expect(output).to.include("Evidence Gate: PASSED");
    expect(summary.evidence_gate_passed).to.equal(true);
    expect(summary.skipped_local_artifacts_count).to.be.greaterThanOrEqual(1);
    expect(summary.skipped_local_artifacts.map((item) => item.file)).to.include(
      "tmp-local-raw-router-metadata.json"
    );
    expect(summary.violations).to.deep.equal([]);
  });
});
