const { expect } = require("chai");
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

describe("Rehearsal Gate & Authority Guardrail Tests", function () {
  const repoRoot = path.resolve(__dirname, "..");
  const rehearseScript = path.join(repoRoot, "scripts", "rehearse_proposal.py");
  const gitignorePath = path.join(repoRoot, ".gitignore");

  it("should assert that reviews/outcome_memory.json is ignored in .gitignore", function () {
    const gitignoreContent = fs.readFileSync(gitignorePath, "utf8");
    expect(gitignoreContent).to.include("reviews/outcome_memory.json");
    expect(gitignoreContent).to.include("reviews/*receipt*.json");
  });

  it("should generate dizzy.rehearsal_receipt.v1 receipt with execution_claimed: false", function () {
    const output = execSync(`python "${rehearseScript}" --sample`, {
      cwd: repoRoot,
      encoding: "utf8"
    });

    expect(output).to.include("REHEARSAL GATE: PRE-EXECUTION RISK EVALUATION");
    expect(output).to.include("dizzy.rehearsal_receipt.v1");
    expect(output).to.include("automation-recommends-user-approves");
    expect(output).to.include("Execution Claimed: False");
  });

  it("should exit with code 2 when all candidates are REJECTED_HIGH_RISK", function () {
    const highRiskPayload = JSON.stringify([
      {
        title: "Fake telemetry and overclaimed ZK bounds",
        action: "hardcoded_zero_debt and guarantee_exactly_once",
        keywords: ["fake_telemetry", "guarantee_exactly_once"]
      }
    ]);

    try {
      const { execFileSync } = require("child_process");
      execFileSync("python", [rehearseScript, "--candidates", "-"], {
        cwd: repoRoot,
        input: highRiskPayload,
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"]
      });
      expect.fail("Should have thrown non-zero exit code");
    } catch (err) {
      expect(err.status).to.equal(2);
    }
  });
});
