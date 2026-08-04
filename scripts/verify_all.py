#!/usr/bin/env python3
"""
Pharmacy Fiduciary Commons — Master Verification Runner (Principle 3)

Executes unified, fail-closed verification across the entire repository:
1. Hardhat EVM Contract & State Machine Test Suite (`npx hardhat test`)
2. Brand Gate B & Impeccable Visual Compliance Linter (`npm run check:frontend`)
3. PageIndex Status Auditor & Dossier Indexer (`python scripts/index_dossier_tree.py`)
4. Constitutional Rubric Evaluator (`python scripts/eval_constitutional_rubric.py`)

Outputs a single execution receipt: `cache/verification_master_receipt.json`
"""

import os
import sys
import json
import time
import subprocess

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECEIPT_PATH = os.path.join(ROOT_DIR, "cache", "verification_master_receipt.json")
DOSSIER_REVIEW_FILE = os.path.join(ROOT_DIR, "reviews", "rotational_swarm_review_dossier.md")

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
        
    return {
        "step_name": step_name,
        "command": " ".join(command_args),
        "return_code": res.returncode,
        "status": "PASSED" if res.returncode == 0 else "FAILED",
        "duration_ms": duration_ms
    }

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
    ]
    
    if not os.path.exists(DOSSIER_REVIEW_FILE):
        print(f"[FAIL] Missing mandatory proof dependency: {DOSSIER_REVIEW_FILE}", file=sys.stderr)
        sys.exit(1)
        
    steps.append(("4. Constitutional Rubric Evaluator", [sys.executable, os.path.join(ROOT_DIR, "scripts", "eval_constitutional_rubric.py"), "--target", DOSSIER_REVIEW_FILE]))
    steps.append(("5. Swarm Observability Dashboard", [sys.executable, os.path.join(ROOT_DIR, "scripts", "observability_dashboard.py")]))
        
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
