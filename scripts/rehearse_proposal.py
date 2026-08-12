#!/usr/bin/env python3
"""
rehearse_proposal.py - Rehearsal Gate & Pre-Execution Risk Evaluator

Implements the Rehearse paradigm (arXiv:2607.27687):
1. Accepts K candidate implementation actions.
2. Evaluates candidates against historical attempt memories & failure patterns.
3. Predicts likely failure modes (e.g. overclaimed ZK privacy, fake live telemetry, raw output staging).
4. Selects the safest candidate and records the decision in cache/rehearsal_ledger.jsonl.
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
REHEARSAL_LEDGER_PATH = REPO_ROOT / "cache" / "rehearsal_ledger.jsonl"

HISTORICAL_FAILURE_MEMORIES = [
  {
    "id": "MEM-001",
    "pattern": "fake_live_telemetry",
    "lesson": "Never report fake '0' or 'zero_debt' live metrics before RPC readers exist. Use scoped envelope: live_contract_reads: false, debt_queue_status: 'not_live_instrumented', null financial fields.",
    "risk_keywords": ["fake_telemetry", "hardcoded_zero_debt", "mock_live_metric"]
  },
  {
    "id": "MEM-002",
    "pattern": "overclaimed_proof_boundary",
    "lesson": "Do not claim 'exactly-once settlement' or 'production ZK unlinkability'. Frame as 'idempotent target' and 'local_schema_gate'.",
    "risk_keywords": ["guarantee_exactly_once", "production_unlinkable", "full_solvency_proof"]
  },
  {
    "id": "MEM-003",
    "pattern": "stale_payload_test_mismatch",
    "lesson": "Disaster recovery / proxy tests must use exact top-level parameter names (walletAddress, chainId, roundId, signature, issuerSignature, relayerNonce, relayerDeadline).",
    "risk_keywords": ["nested_relayer_auth", "missing_top_level_sig", "mock_sig_400"]
  },
  {
    "id": "MEM-004",
    "pattern": "external_guardrail_privacy_block",
    "lesson": "Do not send raw private/dirty working tree diffs to external LLM providers (OpenRouter). Use local Ollama or deterministic rule checks first.",
    "risk_keywords": ["openrouter_private_diff", "external_guardrail_dirty", "leak_raw_diff"]
  },
  {
    "id": "MEM-005",
    "pattern": "raw_ledger_staging_leak",
    "lesson": "reviews/model_attempt_ledger.jsonl contains raw error strings and user IDs. Ensure it is ignored in .gitignore and unstaged before commit.",
    "risk_keywords": ["stage_raw_ledger", "commit_user_id", "unmasked_error_log"]
  },
  {
    "id": "MEM-006",
    "pattern": "stale_branch_dossier_claim",
    "lesson": "Reconcile SINGLE_REPO_STATE_LEDGER.md and AI_SYSTEMS_CONCEPT_COVERAGE.md headers when main branch advances.",
    "risk_keywords": ["stale_branch_header", "feature_db_proxy_on_main", "contradictory_dossier_claim"]
  }
]

SAMPLE_CANDIDATES = [
    {
        "title": "Hardcode fake zero solvency debt in telemetry response",
        "action": "Return solvency_debt_total: '0' in /api/health/observability to pass test quickly",
        "keywords": ["fake_telemetry", "hardcoded_zero_debt"]
    },
    {
        "title": "Scoped observability telemetry envelope with null financial fields",
        "action": "Return live_contract_reads: false, debt_queue_status: 'not_live_instrumented', solvency_debt_total: null in /api/health/observability",
        "keywords": ["scoped_envelope", "not_live_instrumented"]
    },
    {
        "title": "Claim production ZK unlinkability guarantee in plan",
        "action": "Write plan stating proxy guarantees production ZK unlinkability and exactly-once settlement",
        "keywords": ["guarantee_exactly_once", "production_unlinkable"]
    }
]

def normalize_blob(value):
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")

def load_candidates(source):
    if source == "-":
        raw = sys.stdin.read()
    else:
        with open(source, "r", encoding="utf-8") as f:
            raw = f.read()

    payload = json.loads(raw)
    candidates = payload.get("candidates") if isinstance(payload, dict) else payload
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("candidate payload must be a non-empty JSON list or an object with a non-empty candidates list")

    for idx, candidate in enumerate(candidates, 1):
        if not isinstance(candidate, dict):
            raise ValueError(f"candidate {idx} must be a JSON object")
        if not candidate.get("title") or not candidate.get("action"):
            raise ValueError(f"candidate {idx} must include title and action")
    return candidates

def detect_risks(candidate):
    action_desc = str(candidate.get("action", ""))
    keywords = {normalize_blob(keyword) for keyword in candidate.get("keywords", [])}
    action_lower = action_desc.lower()
    action_normalized = normalize_blob(action_desc)

    detected_risks = []
    for mem in HISTORICAL_FAILURE_MEMORIES:
        for risk_keyword in mem["risk_keywords"]:
            normalized_risk = normalize_blob(risk_keyword)
            spaced_risk = normalized_risk.replace("_", " ")
            if (
                normalized_risk in keywords
                or normalized_risk in action_normalized
                or spaced_risk in action_lower
            ):
                detected_risks.append(mem)
                break
    return detected_risks

def evaluate_candidates(candidates, ledger_path=None):
    print("=" * 60)
    print("REHEARSAL GATE: PRE-EXECUTION RISK EVALUATION")
    print("=" * 60)
    print(f"* Candidates Submitted: {len(candidates)}")
    print(f"* Historical Memories Loaded: {len(HISTORICAL_FAILURE_MEMORIES)}")
    print("-" * 60)

    evaluated_candidates = []

    for idx, candidate in enumerate(candidates, 1):
        title = candidate.get("title", f"Candidate {idx}")
        action_desc = candidate.get("action", "")
        detected_risks = detect_risks(candidate)

        risk_score = len(detected_risks)
        status = "REJECTED_HIGH_RISK" if risk_score >= 2 else ("ACCEPTED_RECOMMENDED" if risk_score == 0 else "CONDITIONALLY_ACCEPTED")

        evaluated = {
            "candidate_id": f"CAND-{idx:02d}",
            "title": title,
            "action": action_desc,
            "risk_score": risk_score,
            "detected_risks": detected_risks,
            "recommendation": status
        }
        evaluated_candidates.append(evaluated)

        print(f"\n[{evaluated['candidate_id']}] {title}")
        print(f"  Status: {status}")
        print(f"  Risk Score: {risk_score}")
        if detected_risks:
            print("  Predicted Failure Risks:")
            for r in detected_risks:
                print(f"    - [{r['id']}] Pattern: {r['pattern']} | Lesson: {r['lesson']}")
        else:
            print("  Predicted Failure Risks: None detected. Passes historical rehearsal gate.")

    evaluated_candidates.sort(key=lambda x: x["risk_score"])
    winner = evaluated_candidates[0]

    print("\n" + "=" * 60)
    print(f"WINNING CANDIDATE: {winner['candidate_id']} - {winner['title']}")
    print("=" * 60)

    if ledger_path:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "winning_candidate": winner,
            "all_candidates": evaluated_candidates
        }
        with open(ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        print(f"* Rehearsal Decision Recorded: {ledger_path.relative_to(REPO_ROOT)}")
    else:
        print("* Rehearsal Decision Not Recorded: no ledger path requested")
    return winner

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate candidate implementation actions against PBM project rehearsal memories.")
    parser.add_argument("--candidates", "-c", help="JSON file containing a candidate list, an object with candidates, or '-' for stdin.")
    parser.add_argument("--sample", action="store_true", help="Run the built-in sample candidates as a dry-run smoke test.")
    parser.add_argument("--write-ledger", action="store_true", help="Append the evaluation result to cache/rehearsal_ledger.jsonl.")
    args = parser.parse_args()

    if args.candidates and args.sample:
        parser.error("use either --candidates or --sample, not both")
    if args.candidates:
        selected_candidates = load_candidates(args.candidates)
    elif args.sample:
        selected_candidates = SAMPLE_CANDIDATES
    else:
        parser.error("provide --candidates JSON or run --sample")

    ledger = REHEARSAL_LEDGER_PATH if args.write_ledger else None
    winning_candidate = evaluate_candidates(selected_candidates, ledger_path=ledger)
    if winning_candidate["recommendation"] == "REJECTED_HIGH_RISK":
        sys.exit(2)
