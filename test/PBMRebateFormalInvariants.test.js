const { expect } = require("chai");
const { execFileSync, execSync } = require("child_process");
const path = require("path");

describe("PBM rebate formal invariants (SMT Z3 Bridge)", function () {
  this.timeout(60000);
  const repoRoot = path.resolve(__dirname, "..");

  function runPython(code) {
    return execFileSync("python", ["-B", "-"], {
      cwd: repoRoot,
      input: code,
      encoding: "utf-8"
    });
  }

  it("runs the PBM rebate formal invariant Python test suite", () => {
    const cmd = "python -B -m unittest tools/council/test_pbm_rebate_formal_invariants.py 2>&1";
    const output = execSync(cmd, { cwd: repoRoot, encoding: "utf-8" });
    expect(output).to.match(/Ran 7 tests/);
    expect(output).to.include("OK");
  });

  it("seals and verifies a formal invariant receipt for all five treasury arithmetic domains", () => {
    const script = `
import sys, os
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from council_verifier import CouncilReceiptVerifier
from pbm_rebate_formal_invariants import PBMRebateFormalInvariantEngine, PBMRebateFormalInvariantReceipt

receipt_env = PBMRebateFormalInvariantEngine().prove_all()
CouncilReceiptVerifier.verify_envelope(receipt_env, PBMRebateFormalInvariantReceipt)
receipt = receipt_env.payload
domains = {proof.domain for proof in receipt.invariants}

assert receipt.all_invariants_proved is True
assert receipt.audit_replacement_claimed is False
assert receipt.market_truth_claimed is False
assert len(receipt.invariants) == 5
assert domains == {
    "GROSS_NET_NON_NEGATIVE",
    "SOLVENCY_DEBT_CONSERVATION",
    "DISPUTE_ESCROW_CAP",
    "MUTUAL_CREDIT_ZERO_SUM",
    "FEE_ON_TRANSFER_INTEGRITY",
}
print("PBM_REBATE_FORMAL_INVARIANTS_VERIFIED")
`;
    const output = runPython(script);
    expect(output).to.include("PBM_REBATE_FORMAL_INVARIANTS_VERIFIED");
  });
});
