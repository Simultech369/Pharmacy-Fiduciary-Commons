#!/usr/bin/env python3
"""
Fail-closed Slither static analysis CI gate for Pharmacy Fiduciary Commons.

Runs Slither against Hardhat compilation artifacts using .slither.config.json,
verifies every High and Medium detector result against the documented baseline
in docs/ops/SCANNER_TRIAGE.md, writes a Markdown summary (and appends to
GITHUB_STEP_SUMMARY when set), and exits 1 on any untriaged High/Medium finding.
"""

import json
import os
import shutil
import subprocess
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, ".slither.config.json")
REPORT_PATH = os.path.join(ROOT_DIR, "cache", "slither-ci-report.json")

# Explicitly triaged High/Medium findings documented in docs/ops/SCANNER_TRIAGE.md.
# Format: (impact, check, contract_name, element_name)
TRIAGED_HIGH_MEDIUM = {
    ("High", "arbitrary-send-eth", "PBMRebateTreasury", "sweepETH"),
    ("High", "reentrancy-balance", "PBMRebateTreasury", "depositRebate"),
    ("High", "reentrancy-balance", "PBMRebateTreasury", "fundExclusionRemediation"),
    ("High", "reentrancy-balance", "PatientFundParticipatoryBudgeting", "_startRound"),
    ("High", "uninitialized-state", "CooperativeParticipatoryBudgeting", "projectSupport"),
    ("Medium", "reentrancy-no-eth", "PatientFundParticipatoryBudgeting", "_startRound"),
    ("Medium", "incorrect-equality", "PBMRebateTreasury", "recallEligible"),
    ("Medium", "incorrect-equality", "PBMRebateTreasury", "sweepETH"),
    ("Medium", "incorrect-equality", "PatientFundParticipatoryBudgeting", "_startRound"),
    ("Medium", "incorrect-equality", "PatientFundParticipatoryBudgeting", "requiredSolvencyBalance"),
    ("Medium", "divide-before-multiply", "ReflexiveFiduciaryManifold", "computeCapacityAdjustment"),
    ("Medium", "incorrect-equality", "ReflexiveFiduciaryManifold", "computeCapacityAdjustment"),
}


def find_slither():
    env_bin = os.environ.get("SLITHER_BIN")
    if env_bin and os.path.exists(env_bin):
        return env_bin
    which_bin = shutil.which("slither") or shutil.which("slither.exe")
    if which_bin:
        return which_bin
    venv_candidate = "/tmp/pbm-venv/bin/slither"
    if os.path.exists(venv_candidate):
        return venv_candidate
    return None


def extract_key(finding):
    impact = finding.get("impact", "Informational")
    check = finding.get("check", "unknown")
    contract_name = ""
    target_name = ""
    for elem in finding.get("elements", []):
        etype = elem.get("type")
        if etype in ("function", "variable") and not target_name:
            target_name = elem.get("name", "")
            parent = elem.get("type_specific_fields", {}).get("parent", {})
            if parent.get("type") == "contract":
                contract_name = parent.get("name", "")
        elif etype == "contract" and not contract_name:
            contract_name = elem.get("name", "")
    return (impact, check, contract_name, target_name)


def main():
    slither_bin = find_slither()
    if not slither_bin:
        print("ERROR: slither binary not found on PATH (or SLITHER_BIN).", file=sys.stderr)
        sys.exit(1)

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    if os.path.exists(REPORT_PATH):
        os.remove(REPORT_PATH)

    cmd = [
        slither_bin,
        ".",
        "--config-file",
        CONFIG_PATH,
        "--hardhat-ignore-compile",
        "--json",
        REPORT_PATH,
    ]
    print(f"Running Slither CI gate: {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True)

    if not os.path.exists(REPORT_PATH) or os.path.getsize(REPORT_PATH) == 0:
        print(f"ERROR: Slither failed to emit JSON report (exit {proc.returncode}).", file=sys.stderr)
        print(proc.stderr[:1000], file=sys.stderr)
        sys.exit(1)

    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        report = json.load(f)

    detectors = report.get("results", {}).get("detectors", [])
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Optimization": 0}
    untriaged = []
    triaged_seen = []

    for item in detectors:
        impact = item.get("impact", "Informational")
        counts[impact] = counts.get(impact, 0) + 1
        if impact in ("High", "Medium"):
            key = extract_key(item)
            if key in TRIAGED_HIGH_MEDIUM:
                triaged_seen.append(key)
            else:
                first_line = (item.get("description") or "").strip().splitlines()[0] if item.get("description") else ""
                untriaged.append((key, first_line))

    summary_lines = [
        "### Slither Static Analysis Gate",
        "",
        "| Severity | Raw Count | Untriaged Blocking |",
        "| :--- | ---: | ---: |",
        f"| High | {counts['High']} | {sum(1 for k, _ in untriaged if k[0] == 'High')} |",
        f"| Medium | {counts['Medium']} | {sum(1 for k, _ in untriaged if k[0] == 'Medium')} |",
        f"| Low | {counts['Low']} | 0 |",
        f"| Informational | {counts['Informational']} | 0 |",
        "",
        f"Triaged baseline matches (`docs/ops/SCANNER_TRIAGE.md`): {len(triaged_seen)}",
    ]

    summary_md = "\n".join(summary_lines) + "\n"
    print(summary_md)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as sf:
            sf.write(summary_md + "\n")

    if untriaged:
        print("FAILED: Untriaged High/Medium Slither findings detected:", file=sys.stderr)
        for key, desc in untriaged:
            print(f"  - [{key[0]}] {key[1]} in {key[2]}.{key[3]}: {desc}", file=sys.stderr)
        sys.exit(1)

    print("PASSED: Zero untriaged High/Medium Slither findings.")


if __name__ == "__main__":
    main()
