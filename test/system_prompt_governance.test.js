const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

describe("System prompt pruning governance", function () {
  const repoRoot = path.resolve(__dirname, "..");
  const agentsPath = path.join(repoRoot, ".agents", "AGENTS.md");
  const governancePath = path.join(repoRoot, "docs", "design", "system_prompt_pruning_and_governance.md");

  it("keeps AGENTS.md below the local standing-brief line budget", function () {
    const lines = fs.readFileSync(agentsPath, "utf8").split(/\r?\n/);

    expect(lines.length).to.be.lessThan(200);
  });

  it("preserves fiduciary truth rules and Level 3 approval boundaries", function () {
    const agents = fs.readFileSync(agentsPath, "utf8");

    expect(agents).to.include("Data Freshness & Lineage Protocol");
    expect(agents).to.include("[live verification just run]");
    expect(agents).to.include("[committed HEAD]");
    expect(agents).to.include("[dirty working tree]");
    expect(agents).to.include("L3 (Explicit Permission Gate)");
    expect(agents).to.include("Git commit/push");
  });

  it("keeps the prompt governance doc scoped to local audit evidence", function () {
    const governance = fs.readFileSync(governancePath, "utf8");

    expect(governance).to.include("External Anthropic guidance is not independently verified");
    expect(governance).to.include("45 raw lines / 30 nonblank lines");
    expect(governance).to.not.include("100% PASS");
    expect(governance).to.not.include("Zero Token Waste");
  });
});
