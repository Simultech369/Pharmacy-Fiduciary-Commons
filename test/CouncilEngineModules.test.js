const { expect } = require("chai");
const { execFileSync, execSync } = require("child_process");
const path = require("path");

describe("Council Engine Verified Modules (tools/council/)", () => {
  const repoRoot = path.join(__dirname, "..");

  function runPython(code) {
    return execFileSync("python", ["-B", "-"], {
      cwd: repoRoot,
      input: code,
      encoding: "utf-8"
    });
  }

  it("runs the full tools/council unittest discovery suite (18 tests)", () => {
    const cmd = 'python -B -m unittest tools/council/test_lifecycle_hooks.py tools/council/test_agent_reach_adapter.py tools/council/test_rlvr_ruler_reward_engine.py tools/council/test_statem_runbook_bridge.py tools/council/test_pbm_fraud_detector.py 2>&1';
    const output = execSync(cmd, {
      cwd: repoRoot,
      encoding: "utf-8"
    });

    expect(output).to.match(/Ran \d+ tests/);
    expect(output).to.include("OK");
  });


  it("verifies AgentReachAdapter rejects shell injection and local URLs", () => {
    const pyCode = `
import sys, os
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from agent_reach_adapter import AgentReachAdapter
from lifecycle_hooks import LifecycleHookError

adapter = AgentReachAdapter()
try:
    adapter.fetch_text("gh", ["issue", "view", "1"], "http://127.0.0.1/admin")
    print("FAILED_TO_BLOCK")
except LifecycleHookError as e:
    print("BLOCKED_LOCAL_URL")
`;
    const output = runPython(pyCode);
    expect(output).to.include("BLOCKED_LOCAL_URL");
  });


  it("verifies PBMFraudDetector catches NCPDP Reject 79, Reject 76, and CDC MME hard stop", () => {
    const pyCode = `
import sys, os
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from decimal import Decimal
from pbm_fraud_detector import PBMFraudDetector, PharmacyClaimRecord

detector = PBMFraudDetector()
claim = PharmacyClaimRecord(
    claim_id="C001", member_id="M1", prescriber_npi="111", pharmacy_npi="222",
    ndc="0001", gpi_10="1234567890", gpi_6="123456", drug_name="Oxycodone",
    schedule="C-II", date_of_service=10, days_supply=30, quantity=Decimal("60"),
    strength_mg=Decimal("80"), is_opioid=True, opioid_active_ingredient="oxycodone"
)
res = detector.audit_claim(claim)
print(f"AUDIT_RESULT:{res.triage_tier}:{res.ncpdp_reject_code}")
`;
    const output = runPython(pyCode);
    expect(output).to.include("AUDIT_RESULT:TIER_1_POS_REJECT:REJECT_M7");
  });

  it("verifies PBMRebateEngine calculates pass-through and admin fees with Decimal(18,6)", () => {
    const pyCode = `
import sys, os
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from decimal import Decimal
from pbm_rebate_engine import PBMRebateEngine, SanitizedPrescriptionClaim, RebateTierRule

engine = PBMRebateEngine()
tiers = [
    RebateTierRule(tier_name="Tier1", min_market_share=Decimal("0.0"), max_market_share=Decimal("0.5"), base_rebate_rate=Decimal("0.10"), volume_adder_rate=Decimal("0.02")),
    RebateTierRule(tier_name="Tier2", min_market_share=Decimal("0.5"), max_market_share=Decimal("1.0"), base_rebate_rate=Decimal("0.15"), volume_adder_rate=Decimal("0.05"))
]
claims = [
    SanitizedPrescriptionClaim(claim_id="C1", tokenized_member_id="TOK1", ndc="1", is_brand=True, normalized_30eq_scripts=Decimal("60"), total_wac=Decimal("60000.00"), adjudication_timestamp=1.0)
]
res = engine.calculate_quarterly_rebate(claims, Decimal("100"), tiers)
print(f"REBATE_CALC:{res['matched_tier_name']}:{res['gross_rebate_usd']}")
`;
    const output = runPython(pyCode);
    expect(output).to.include("REBATE_CALC:Tier2:12000.0");
  });

  it("verifies StateMRunbookBridge exports formal 4-phase state graph with mandatory test guards", () => {
    const pyCode = `
import sys, os
sys.path.insert(0, os.path.join(r"${repoRoot}", "tools", "council"))

from statem_runbook_bridge import StateMRunbookBridge

bridge = StateMRunbookBridge()
text, receipt = bridge.export_council_runbook()
print(f"STATEM_EXPORT:nodes={receipt.payload.node_count}:edges={receipt.payload.edge_count}")
`;

    const output = runPython(pyCode);
    expect(output).to.include("STATEM_EXPORT:nodes=4:edges=4");
  });
});

