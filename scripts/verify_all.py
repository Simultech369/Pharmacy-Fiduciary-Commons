#!/usr/bin/env python3
"""
Pharmacy Fiduciary Commons — Master Verification Runner (Principle 3)

Executes unified, fail-closed verification across the entire repository:
1. Hardhat EVM Contract & State Machine Test Suite (`npx hardhat test`)
2. Brand Gate B & Impeccable Visual Compliance Linter (`npm run check:frontend`)
3. PageIndex Status Auditor & Dossier Indexer (`python scripts/index_dossier_tree.py`)
4. Local Dossier Retrieval Eval (`python scripts/eval_dossier_rag.py`)
5. Context Hygiene Auditor (`python scripts/context_hygiene_audit.py`)
6. Constitutional Rubric Evaluator (`python scripts/eval_constitutional_rubric.py`)
7. Swarm Observability Dashboard (`python scripts/observability_dashboard.py`)
8. Simulated 11-Receipt Dual-Chain Council Verifier (`python scripts/council_orchestrator.py --demo`)
9. Agent Claim Lie Detector & Cross-Auditor (`python scripts/verify_agent_claims.py`)

Outputs a single execution receipt: `cache/verification_master_receipt.json`
"""

import os
import sys
import json
import time
import re
import subprocess

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECEIPT_PATH = os.path.join(ROOT_DIR, "cache", "verification_master_receipt.json")
DOSSIER_REVIEW_FILE = os.path.join(ROOT_DIR, "reviews", "rotational_swarm_review_dossier.md")

def sanitize_receipt_arg(arg):
    base = os.path.basename(arg).lower()
    if base in ("npx", "npx.cmd", "npx.bat"):
        return "npx"
    if base in ("npm", "npm.cmd", "npm.bat"):
        return "npm"
    if arg == sys.executable or base.startswith("python"):
        return "python"

    try:
        abs_arg = os.path.abspath(arg)
        root_prefix = ROOT_DIR + os.sep
        if abs_arg == ROOT_DIR:
            return "."
        if abs_arg.startswith(root_prefix):
            return os.path.relpath(abs_arg, ROOT_DIR).replace(os.sep, "/")
    except Exception:
        pass

    return arg

def format_receipt_command(command_args):
    return " ".join(sanitize_receipt_arg(arg) for arg in command_args)

def extract_observed_counts(stdout_text):
    observed = {}

    passing_matches = re.findall(r"\b(\d+)\s+passing\b", stdout_text or "", flags=re.IGNORECASE)
    if passing_matches:
        observed["passing_tests"] = int(passing_matches[-1])

    pageindex_dirty = re.search(r"Git Working Tree Dirty/Untracked Files Detected:\s*(\d+)", stdout_text or "")
    if pageindex_dirty:
        observed["dirty_untracked_files_detected"] = int(pageindex_dirty.group(1))

    pageindex_contradictions = re.search(
        r"Contradictory / Stale / Mismatched Claims Identified:\s*(\d+)",
        stdout_text or ""
    )
    if pageindex_contradictions:
        observed["contradictory_claims_identified"] = int(pageindex_contradictions.group(1))

    rag_positive = re.search(r"Positive cases:\s*(\d+)", stdout_text or "")
    if rag_positive:
        observed["positive_cases"] = int(rag_positive.group(1))
    rag_no_hit = re.search(r"Adversarial no-hit cases:\s*(\d+)", stdout_text or "")
    if rag_no_hit:
        observed["adversarial_no_hit_cases"] = int(rag_no_hit.group(1))

    claims_audited = re.search(r"Total Claims Audited:\s*(\d+)", stdout_text or "")
    if claims_audited:
        observed["claims_audited"] = int(claims_audited.group(1))
    claim_violations = re.search(r"Total Violations:\s*(\d+)", stdout_text or "")
    if claim_violations:
        observed["claim_violations"] = int(claim_violations.group(1))

    return observed

def run_step(step_name, command_args, cwd=ROOT_DIR):
    print(f"\n==================================================")
    print(f"RUNNING STEP: {step_name}")
    print(f"Command: {' '.join(command_args)}")
    print(f"==================================================")
    start_time = time.time()
    res = subprocess.run(command_args, cwd=cwd, text=True, capture_output=True)
    duration_ms = int((time.time() - start_time) * 1000)

    if res.stdout:
        print(res.stdout)
    if res.stderr and res.returncode != 0:
        print(res.stderr, file=sys.stderr)

    step_receipt = {
        "step_name": step_name,
        "command": format_receipt_command(command_args),
        "return_code": res.returncode,
        "status": "PASSED" if res.returncode == 0 else "FAILED",
        "duration_ms": duration_ms
    }
    observed_counts = extract_observed_counts(res.stdout)
    if observed_counts:
        step_receipt["observed_counts"] = observed_counts
    return step_receipt

import shutil

def resolve_cmd(cmd_name):
    if os.name == "nt":
        cmd_win = shutil.which(f"{cmd_name}.cmd") or shutil.which(f"{cmd_name}.bat")
        if cmd_win:
            return cmd_win
    return shutil.which(cmd_name) or cmd_name

def get_git_lineage():
    try:
        head_res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT_DIR, text=True, capture_output=True)
        head_sha = head_res.stdout.strip() if head_res.returncode == 0 else "UNKNOWN"

        branch_res = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=ROOT_DIR, text=True, capture_output=True)
        branch_name = branch_res.stdout.strip() if branch_res.returncode == 0 else "UNKNOWN"

        status_res = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT_DIR, text=True, capture_output=True)
        dirty_lines = [line.strip() for line in status_res.stdout.splitlines() if line.strip()] if status_res.returncode == 0 else []

        is_dirty = len(dirty_lines) > 0
        lineage_tag = "[dirty working tree]" if is_dirty else "[committed HEAD]"

        return {
            "head_commit": head_sha,
            "branch": branch_name,
            "is_dirty": is_dirty,
            "dirty_file_count": len(dirty_lines),
            "lineage_tag": lineage_tag
        }
    except Exception as e:
        return {
            "head_commit": "UNKNOWN",
            "branch": "UNKNOWN",
            "is_dirty": True,
            "dirty_file_count": 0,
            "lineage_tag": "[dirty working tree]",
            "error": str(e)
        }

def main():
    print("==================================================")
    print("PHARMACY FIDUCIARY COMMONS MASTER VERIFICATION")
    print("==================================================")

    npx_bin = resolve_cmd("npx")
    npm_bin = resolve_cmd("npm")

    steps = [
        ("1. Hardhat Unit & State Machine Tests", [npx_bin, "--no-install", "hardhat", "test"]),
        ("2. Brand Gate B & Impeccable Linter", [npm_bin, "run", "check:frontend"]),
        ("3. PageIndex Status Auditor", [sys.executable, os.path.join(ROOT_DIR, "scripts", "index_dossier_tree.py")]),
        ("4. Local Dossier Retrieval Eval", [sys.executable, os.path.join(ROOT_DIR, "scripts", "eval_dossier_rag.py")]),
        ("5. Context Hygiene Auditor", [sys.executable, os.path.join(ROOT_DIR, "scripts", "context_hygiene_audit.py")]),
    ]

    if not os.path.exists(DOSSIER_REVIEW_FILE):
        print(f"[FAIL] Missing mandatory proof dependency: {DOSSIER_REVIEW_FILE}", file=sys.stderr)
        sys.exit(1)

    steps.append(("6. Constitutional Rubric Evaluator", [sys.executable, os.path.join(ROOT_DIR, "scripts", "eval_constitutional_rubric.py"), "--target", DOSSIER_REVIEW_FILE]))
    steps.append(("7. Swarm Observability Dashboard", [sys.executable, os.path.join(ROOT_DIR, "scripts", "observability_dashboard.py")]))
    steps.append(("8. Simulated 11-Receipt Dual-Chain Council Verifier", [sys.executable, os.path.join(ROOT_DIR, "scripts", "council_orchestrator.py"), "--demo"]))
    steps.append(("9. Agent Claim Lie Detector & Cross-Auditor", [sys.executable, os.path.join(ROOT_DIR, "scripts", "verify_agent_claims.py"), "--target", DOSSIER_REVIEW_FILE]))
    steps.append(("10. Support/Docs Privacy Leak Scanner", [sys.executable, os.path.join(ROOT_DIR, "scripts", "privacy_leak_scanner.py")]))

    expected_step_count = len(steps)
    results = []
    overall_success = True

    for name, cmd in steps:
        step_result = run_step(name, cmd)
        results.append(step_result)
        if step_result["return_code"] != 0:
            overall_success = False
            print(f"\n[FAIL] Step '{name}' failed with exit code {step_result['return_code']}.")
            break

    if overall_success and len(results) != expected_step_count:
        overall_success = False
        print(f"\n[FAIL] Step count assertion failed! Executed {len(results)} of expected {expected_step_count} steps.")

    git_lineage = get_git_lineage()

    receipt = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "overall_status": "PASSED" if overall_success else "FAILED",
        "expected_step_count": expected_step_count,
        "steps_executed": len(results),
        "git_lineage": git_lineage,
        "steps": results
    }

    os.makedirs(os.path.dirname(RECEIPT_PATH), exist_ok=True)
    with open(RECEIPT_PATH, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2)

    print("\n==================================================")
    print(f"MASTER VERIFICATION RESULT: {receipt['overall_status']}")
    print(f"Executed Steps: {len(results)} / {expected_step_count}")
    print(f"Git Lineage Tag: {git_lineage['lineage_tag']} ({git_lineage['branch']}@{git_lineage['head_commit'][:7]})")
    print(f"Receipt written to: {RECEIPT_PATH}")
    print("==================================================")

    sys.exit(0 if overall_success else 1)

if __name__ == "__main__":
    main()
