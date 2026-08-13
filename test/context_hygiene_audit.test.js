const { expect } = require("chai");
const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

describe("Context hygiene deterministic audit", function () {
  const repoRoot = path.resolve(__dirname, "..");
  const auditScript = path.join(repoRoot, "scripts", "context_hygiene_audit.py");

  it("passes and classifies standing brief, memory, workflow, and deterministic gate surfaces", function () {
    const output = execFileSync("python", [auditScript], {
      cwd: repoRoot,
      encoding: "utf8"
    });
    const audit = JSON.parse(output);

    expect(audit.schema_version).to.equal("pbm.context_hygiene_audit.v1");
    expect(audit.status).to.equal("PASSED");
    expect(audit.category_counts).to.include.keys(
      "standing_brief",
      "memory_reference",
      "workflow_skill",
      "deterministic_gate"
    );
    expect(audit.surfaces.map(surface => surface.path)).to.include("test/VoucherSagaQueue.test.js");
    expect(audit.issues).to.deep.equal([]);
  });

  it("keeps the Phase 5 plan free of brittle line-count and prompt-hygiene overclaims", function () {
    const plan = fs.readFileSync(
      path.join(repoRoot, "docs", "plans", "phase_5_context_hygiene_and_instruction_pruning_plan.md"),
      "utf8"
    );

    expect(plan).to.include("standing_brief");
    expect(plan).to.include("memory_reference");
    expect(plan).to.include("workflow_skill");
    expect(plan).to.include("deterministic_gate");
    expect(plan).to.include("test/VoucherSagaQueue.test.js");
    expect(plan).to.not.include("strictly under 46 lines");
    expect(plan).to.not.include("100% PASS");
  });
});
