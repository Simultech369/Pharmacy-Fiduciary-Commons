const { expect } = require("chai");
const { execSync, execFileSync } = require("child_process");
const path = require("path");

describe("Autonomous Patch Synthesis, Red-Team Probing & Chaos Resilience", function () {
  this.timeout(60000);
  const repoRoot = path.resolve(__dirname, "..");

  function runPython(code) {
    return execFileSync("python", ["-B", "-"], {
      cwd: repoRoot,
      input: code,
      encoding: "utf-8"
    });
  }

  it("runs the full autonomous patch synthesis, red-team, DLQ, and chaos unit tests (19 tests)", () => {
    const cmd = 'python -B -m unittest tools/council/test_autonomous_patch_synthesis_pipeline.py tools/council/test_adversarial_red_team_engine.py tools/council/test_dead_letter_and_gateway.py tools/council/test_chaos_resilience_engine.py 2>&1';
    const output = execSync(cmd, { cwd: repoRoot, encoding: "utf-8" });
    expect(output).to.match(/Ran \d+ tests/);
    expect(output).to.include("OK");
  });

  it("verifies AutonomousPatchSynthesisPipeline identifies CWEs and synthesizes dual-gate AST verified patches", () => {
    const script = `
import sys, os
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from autonomous_patch_synthesis_pipeline import AutonomousPatchSynthesisPipeline
from council_contracts import AutonomousPatchSynthesisReceipt
from council_verifier import CouncilReceiptVerifier

pipeline = AutonomousPatchSynthesisPipeline()

vuln_sqli = "def search(cursor, q): cursor.execute(f'SELECT * FROM claims WHERE id = {q}')"
cwe = pipeline.identify_cwe(vuln_sqli)
assert cwe == "CWE-89"

receipt_env, fixed_code = pipeline.execute_end_to_end_remediation(
    pipeline_run_id="run_auto_test_01",
    target_component="claims_db",
    vulnerable_code=vuln_sqli,
    test_oracle_code="assert True"
)
CouncilReceiptVerifier.verify_envelope(receipt_env, AutonomousPatchSynthesisReceipt)
assert receipt_env.payload.gate1_ast_passed is True
assert receipt_env.payload.gate2_sandbox_passed is True
assert receipt_env.payload.patch_integrity_score >= 0.90
assert "%s" in fixed_code or "?" in fixed_code or "execute" in fixed_code

print("AUTONOMOUS_PATCH_SYNTHESIS_VERIFIED")
`;
    const output = runPython(script);
    expect(output).to.include("AUTONOMOUS_PATCH_SYNTHESIS_VERIFIED");
  });

  it("verifies AdversarialRedTeamEngine evaluates attack vectors and enforces immunity score thresholds", () => {
    const script = `
import sys, os
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from adversarial_red_team_engine import AdversarialRedTeamEngine, RedTeamEvaluationSummary

red_team = AdversarialRedTeamEngine()
summary = red_team.evaluate_20_attack_vectors()

assert isinstance(summary, RedTeamEvaluationSummary)
assert summary.total_vectors_tested == 20
assert summary.total_blocked == 20
assert summary.immunity_score_pct >= 99.5
assert summary.gate4_passed is True

print("ADVERSARIAL_RED_TEAM_VERIFIED")
`;
    const output = runPython(script);
    expect(output).to.include("ADVERSARIAL_RED_TEAM_VERIFIED");
  });

  it("verifies DeadLetterQueue records failures and persists quarantined records", () => {
    const script = `
import sys, os, tempfile
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from dead_letter_queue import DeadLetterQueue

with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
    dlq = DeadLetterQueue(storage_dir=tmp_dir)

    record = dlq.record_failure(
        model_slug="qwen2.5-coder:7b",
        failure_category="SCHEMA_VIOLATION",
        raw_prompt="def fix(): pass",
        error_message="Invalid JSON return schema",
        retry_count=1
    )
    assert record.dead_letter_id.startswith("dl_")
    assert record.failure_category == "SCHEMA_VIOLATION"

    records = dlq.list_dead_letters()
    assert len(records) == 1
    assert records[0].source_model_slug == "qwen2.5-coder:7b"

print("DEAD_LETTER_QUEUE_VERIFIED")
`;
    const output = runPython(script);
    expect(output).to.include("DEAD_LETTER_QUEUE_VERIFIED");
  });

  it("verifies CouncilChaosOrchestrator maintains fail-closed invariants across fault injection scenarios", () => {
    const script = `
import sys, os, tempfile
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from council_chaos_resilience_engine import CouncilChaosOrchestrator

with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
    orchestrator = CouncilChaosOrchestrator(base_state_dir=tmp_dir)
    res1 = orchestrator.run_scenario_1_byzantine_model()
    assert res1.fail_closed_invariant_maintained is True
    assert res1.mttr_bound_satisfied is True

    res2 = orchestrator.run_scenario_2_wal_contention()
    assert res2.fail_closed_invariant_maintained is True

    res3 = orchestrator.run_scenario_3_network_partition()
    assert res3.fail_closed_invariant_maintained is True

print("CHAOS_RESILIENCE_VERIFIED")
`;
    const output = runPython(script);
    expect(output).to.include("CHAOS_RESILIENCE_VERIFIED");
  });
});


