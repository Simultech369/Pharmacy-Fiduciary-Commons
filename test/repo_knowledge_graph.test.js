const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

describe("Repo Knowledge Graph Control Plane", function () {
  const repoRoot = path.resolve(__dirname, "..");
  const graphPath = path.join(repoRoot, "review-context", "repo_knowledge_graph.json");
  const graph = JSON.parse(fs.readFileSync(graphPath, "utf8"));

  it("defines unique node ids and only references existing nodes from edges", function () {
    expect(graph).to.have.property("$schema");
    expect(graph.nodes).to.be.an("array").and.not.empty;
    expect(graph.edges).to.be.an("array").and.not.empty;

    const nodeIds = graph.nodes.map(node => node.id);
    expect(new Set(nodeIds).size).to.equal(nodeIds.length);

    for (const edge of graph.edges) {
      expect(nodeIds).to.include(edge.from);
      expect(nodeIds).to.include(edge.to);
      expect(edge.relationship).to.be.a("string").and.not.empty;
      expect(edge.verification_cmd).to.be.a("string").and.not.empty;
    }
  });

  it("keeps voucher saga runtime enforcement marked as design-only until implemented", function () {
    const sagaEdge = graph.edges.find(edge => edge.from === "db_proxy" && edge.to === "voucher_saga");

    expect(sagaEdge).to.exist;
    expect(sagaEdge.relationship).to.equal("SPECIFIES_SETTLEMENT_SAGA_LEASES");
    expect(sagaEdge.proof_status).to.equal("design_only");
  });

  it("keeps rehearsal gate authority advisory instead of executable", function () {
    const rehearsalGate = graph.nodes.find(node => node.id === "rehearsal_gate");

    expect(rehearsalGate).to.exist;
    expect(rehearsalGate.invariants).to.include("dizzy.rehearsal_receipt.v1 schema compliance");
    expect(rehearsalGate.invariants).to.include("automation-recommends-user-approves authority boundary");
    expect(rehearsalGate.invariants).to.include("execution_claimed: false explicit advisory constraint");
  });
});
