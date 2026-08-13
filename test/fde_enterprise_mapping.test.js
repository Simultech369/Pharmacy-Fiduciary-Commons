const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

describe("FDE enterprise reliability mapping proof boundaries", function () {
  const repoRoot = path.resolve(__dirname, "..");
  const mappingPath = path.join(repoRoot, "docs", "plans", "fde_enterprise_reliability_mapping.md");
  const mapping = fs.readFileSync(mappingPath, "utf8");

  it("keeps FDE mapping framed as a proof-bounded roadmap rather than production enterprise claims", function () {
    expect(mapping).to.include("DESIGN MAP / PROOF-BOUNDED ROADMAP");
    expect(mapping).to.include("Current local proof");
    expect(mapping).to.include("Explicit Non-Claim");
    expect(mapping).to.include("Current proof is local and prototype-scoped.");
    expect(mapping).to.include("guarded by explicit non-claim tests");
  });

  it("records explicit non-claims for enterprise surfaces that are not implemented", function () {
    expect(mapping).to.include("No OAuth2, SAML, SCIM, or enterprise SSO implementation is claimed.");
    expect(mapping).to.include("No Salesforce, Slack, HubSpot, Google Workspace, or customer connector pack is claimed.");
    expect(mapping).to.include("No self-service admin portal is implemented.");
    expect(mapping).to.include("No IaC provisioning engine, automated customer environment setup, or go-live automation is claimed.");
  });

  it("does not call the focused control-plane slice a full Hardhat suite or production RAG system", function () {
    expect(mapping).to.include("Focused control-plane and voucher-saga guardrail slice.");
    expect(mapping).to.include("Not a production RAG system");
    expect(mapping).to.include("Phase 4 voucher saga implementation precedes Phase 6 FDE-grade operationalization.");
    expect(mapping).to.not.include("40-test Hardhat suite");
    expect(mapping).to.not.include("production RAG benchmark");
  });
});
