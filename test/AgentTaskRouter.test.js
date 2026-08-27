const { expect } = require("chai");
const { execFileSync, execSync } = require("child_process");
const path = require("path");

describe("Agent Task Router bounded delegation", function () {
  this.timeout(60000);
  const repoRoot = path.resolve(__dirname, "..");

  function runPython(code) {
    return execFileSync("python", ["-B", "-"], {
      cwd: repoRoot,
      input: code,
      encoding: "utf-8"
    });
  }

  it("runs the task router Python unit suite", () => {
    const cmd = "python -B -m unittest tools/council/test_task_router.py 2>&1";
    const output = execSync(cmd, { cwd: repoRoot, encoding: "utf-8" });
    expect(output).to.match(/Ran 4 tests/);
    expect(output).to.include("OK");
  });

  it("routes high-level solvency work into bounded specialist lanes", () => {
    const script = `
import sys, os
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from council_verifier import CouncilReceiptVerifier
from task_router import AgentTaskRouter, AgentTaskRouteReceipt

router = AgentTaskRouter()
receipt_env = router.route_task(
    "Make sure our mutual credit clearinghouse is safe and prove solvency invariants",
    candidate_files=[
        "contracts/PharmacyMutualCredit.sol",
        "test/PharmacyMutualCredit.test.js",
        "test/foundry/TreasurySolvencyInvariant.t.sol",
    ],
)
CouncilReceiptVerifier.verify_envelope(receipt_env, AgentTaskRouteReceipt)
roles = [assignment.role_id for assignment in receipt_env.payload.assignments]
assert "FORMAL_PROVER" in roles
assert "SOLIDITY_SEMANTICS_REVIEWER" in roles
assert "TEST_WRITER" in roles
assert receipt_env.payload.higher_review_recommended is True
assert receipt_env.payload.final_decision_owner == "HumanOwner"
print("TASK_ROUTER_SOLVENCY_ROUTE_VERIFIED")
`;
    const output = runPython(script);
    expect(output).to.include("TASK_ROUTER_SOLVENCY_ROUTE_VERIFIED");
  });

  it("keeps external A2A routing read-only and non-executing", () => {
    const script = `
import sys, os
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from task_router import AgentTaskRouter

router = AgentTaskRouter()
receipt_env = router.route_task(
    "Add external A2A Agent Card JSON-RPC adapter with read-only redaction",
    candidate_files=[
        "tools/council/external_a2a_adapter.py",
        "tools/council/test_external_a2a_adapter.py",
        "test/A2AProtocolEngine.test.js",
    ],
)
a2a_assignment = next(
    assignment for assignment in receipt_env.payload.assignments
    if assignment.role_id == "A2A_PROTOCOL_REVIEWER"
)
assert a2a_assignment.can_mutate_files is False
assert a2a_assignment.external_disclosure_allowed is False
assert "Do not grant remote execution authority." in a2a_assignment.non_scope
print("TASK_ROUTER_A2A_BOUNDARY_VERIFIED")
`;
    const output = runPython(script);
    expect(output).to.include("TASK_ROUTER_A2A_BOUNDARY_VERIFIED");
  });
});

