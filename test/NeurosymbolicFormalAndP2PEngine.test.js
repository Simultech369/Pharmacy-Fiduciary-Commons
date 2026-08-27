const { expect } = require("chai");
const { execSync, execFileSync } = require("child_process");
const path = require("path");

describe("Neurosymbolic Formal Prover, Multilingual AST & P2P Gossip Engine", function () {
  this.timeout(60000);
  const repoRoot = path.resolve(__dirname, "..");

  function runPython(code) {
    return execFileSync("python", ["-B", "-"], {
      cwd: repoRoot,
      input: code,
      encoding: "utf-8"
    });
  }

  it("runs the full neurosymbolic, formal prover, AST, RLVR dataset, and P2P gossip unit tests (21 tests)", () => {
    const cmd = 'python -B -m unittest tools/council/test_multilingual_ast_engine.py tools/council/test_formal_theorem_prover_engine.py tools/council/test_neurosymbolic_proof_planner.py tools/council/test_rlvr_dataset_exporter.py tools/council/test_p2p_gossip_transport.py 2>&1';
    const output = execSync(cmd, { cwd: repoRoot, encoding: "utf-8" });
    expect(output).to.match(/Ran \d+ tests/);
    expect(output).to.include("OK");
  });

  it("verifies MultilingualASTEngine extracts polyglot symbols and computes blast radius subgraphs", () => {
    const script = `
import sys, os
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from multilingual_ast_engine import MultilingualASTEngine, DependencyEdge

engine = MultilingualASTEngine()
py_code = "def calculate_payout(amount): pass"
ts_code = "export function invokePayout() {}"

py_symbols = engine.extract_symbols_from_python("src/treasury.py", py_code)
ts_symbols = engine.extract_symbols_from_typescript("src/api.ts", ts_code)

assert len(py_symbols) == 1
assert len(ts_symbols) == 1
assert py_symbols[0].symbol_name == "calculate_payout"

all_changed = py_symbols + ts_symbols
edges = [
    DependencyEdge(source_symbol_id=ts_symbols[0].symbol_id, target_symbol_id=py_symbols[0].symbol_id, edge_type="calls")
]

blast = engine.compute_blast_radius(all_changed, edges)
assert blast.impacted_symbols_count == 2
assert blast.cross_language_boundary is True
assert blast.smt_invariant_verified is True

print("MULTILINGUAL_AST_VERIFIED")
`;
    const output = runPython(script);
    expect(output).to.include("MULTILINGUAL_AST_VERIFIED");
  });

  it("verifies FormalTheoremProverEngine synthesizes Dafny method contracts and Lean 4 certificates", () => {
    const script = `
import sys, os
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from formal_theorem_prover_engine import FormalTheoremProverEngine, DafnyMethodContract, Lean4ProofCertificate

prover = FormalTheoremProverEngine()
dafny = prover.synthesize_dafny_contract(
    method_name="SumFirstN",
    parameters=["n: int"],
    returns=["sum: int"],
    preconditions=["n >= 0"],
    postconditions=["sum == (n * (n + 1)) / 2"]
)
assert isinstance(dafny, DafnyMethodContract)
assert dafny.method_name == "SumFirstN"
assert dafny.verification_status == "VERIFIED"
assert len(dafny.invariants) >= 1

lean = prover.generate_lean4_proof_certificate(
    theorem_name="solvency_non_negative",
    premises=["Nat.succ_eq_add_one", "linarith"]
)
assert isinstance(lean, Lean4ProofCertificate)
assert lean.theorem_name == "solvency_non_negative"
assert lean.kernel_typecheck_verified is True
assert len(lean.certificate_sha256) == 64

print("FORMAL_PROVER_VERIFIED")
`;
    const output = runPython(script);
    expect(output).to.include("FORMAL_PROVER_VERIFIED");
  });

  it("verifies NeuroSymbolicProofPlanner generates joint program plans and evaluates SMT assertions", () => {
    const script = `
import sys, os
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from neurosymbolic_proof_planner import NeuroSymbolicProofPlanner, JointProgramAndProofPlan

planner = NeuroSymbolicProofPlanner()
plan = planner.synthesize_joint_plan(
    target_module="pricing",
    function_name="calculate_total",
    input_variables=["base_price", "tax", "shipping"],
    invariants=[
        {"name": "non_negativity", "type": "bound"},
        {"name": "sum_monotonicity", "type": "ordering"}
    ]
)
assert isinstance(plan, JointProgramAndProofPlan)
assert plan.proof_verified is True
assert len(plan.smt_clauses) == 2
assert "def calculate_total" in plan.synthesized_code

valid_tiers = [(0.0, 100.0, 0.05), (100.0, 500.0, 0.10), (500.0, 1000.0, 0.15)]
ok, err = planner.verify_smt_clause_monotonicity(valid_tiers)
assert ok is True
assert err is None

print("NEUROSYMBOLIC_PLANNER_VERIFIED")
`;
    const output = runPython(script);
    expect(output).to.include("NEUROSYMBOLIC_PLANNER_VERIFIED");
  });

  it("verifies RLVRDatasetExporter exports JSONL message reward preference pairs", () => {
    const script = `
import sys, os, json
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from rlvr_dataset_exporter import RLVRDatasetExporter, RLVRDatasetExportReceipt
from rlvr_ruler_reward_engine import CouncilRLVRRewardEngine

reward_engine = CouncilRLVRRewardEngine()
good = reward_engine.score_verifiable_signals(
    trajectory_id="traj_good",
    objective_id="obj_patch",
    system_prompt="Fix and verify.",
    trajectory_text="Tests passed.",
    checks=[{"name": "tests_passed", "verifier_kind": "TEST_EXIT_CODE", "passed": True}]
)
weak = reward_engine.score_verifiable_signals(
    trajectory_id="traj_weak",
    objective_id="obj_patch",
    system_prompt="Fix and verify.",
    trajectory_text="Tests failed.",
    checks=[{"name": "tests_passed", "verifier_kind": "TEST_EXIT_CODE", "passed": False}]
)

jsonl_text, receipt_env = RLVRDatasetExporter().export_jsonl(
    reward_receipt_envs=[weak, good],
    messages_by_trajectory_id={
        "traj_good": [{"role": "user", "content": "Fix bug"}, {"role": "assistant", "content": "Done"}],
        "traj_weak": [{"role": "user", "content": "Fix bug"}, {"role": "assistant", "content": "Failed"}],
    },
    min_reward_threshold=0.8
)

lines = [json.loads(line) for line in jsonl_text.splitlines()]
assert len(lines) == 1
assert lines[0]["reward"] == 1.0
assert isinstance(receipt_env.payload, RLVRDatasetExportReceipt)
assert receipt_env.payload.accepted_count == 1
assert receipt_env.payload.rejected_count == 1

print("RLVR_DATASET_EXPORTER_VERIFIED")
`;
    const output = runPython(script);
    expect(output).to.include("RLVR_DATASET_EXPORTER_VERIFIED");
  });
});

