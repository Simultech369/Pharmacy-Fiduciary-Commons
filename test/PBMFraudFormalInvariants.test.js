const { expect } = require("chai");
const { execFileSync, execSync } = require("child_process");
const path = require("path");

describe("PBM fraud formal invariants", function () {
  this.timeout(60000);
  const repoRoot = path.resolve(__dirname, "..");

  function runPython(code) {
    return execFileSync("python", ["-B", "-"], {
      cwd: repoRoot,
      input: code,
      encoding: "utf-8"
    });
  }

  it("runs the PBM fraud detector and formal invariant Python suites", () => {
    const cmd = "python -B -m unittest tools/council/test_pbm_fraud_detector.py tools/council/test_pbm_fraud_formal_invariants.py 2>&1";
    const output = execSync(cmd, { cwd: repoRoot, encoding: "utf-8" });
    expect(output).to.match(/Ran 10 tests/);
    expect(output).to.include("OK");
  });

  it("seals a formal invariant receipt for all fraud rule domains", () => {
    const script = `
import sys, os
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from council_verifier import CouncilReceiptVerifier
from pbm_fraud_formal_invariants import PBMFraudFormalInvariantEngine, PBMFraudFormalInvariantReceipt

receipt_env = PBMFraudFormalInvariantEngine().prove_all()
CouncilReceiptVerifier.verify_envelope(receipt_env, PBMFraudFormalInvariantReceipt)
receipt = receipt_env.payload
domains = {proof.domain for proof in receipt.invariants}
assert receipt.all_invariants_proved is True
assert receipt.benford_output_contract == "ANOMALY_REVIEW_REQUIRED_ONLY"
assert receipt.fraud_proof_claimed is False
assert receipt.external_business_truth_proven is False
assert domains == {"MME", "REFILL_TOO_SOON", "DUPLICATE_THERAPY", "HHI", "BENFORD"}
print("PBM_FRAUD_FORMAL_INVARIANTS_VERIFIED")
`;
    const output = runPython(script);
    expect(output).to.include("PBM_FRAUD_FORMAL_INVARIANTS_VERIFIED");
  });
});

