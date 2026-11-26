#!/usr/bin/env python3
"""
Bounded Mythril runtime-bytecode symbolic execution gate for core contracts.

Extracts deployedBytecode from Hardhat compilation artifacts for:
  - PBMRebateTreasury
  - PatientFundParticipatoryBudgeting
  - PharmacyMutualCredit

Runs `myth analyze --bin-runtime` (via local `myth` binary or `mythril/myth` Docker
image) and fails closed if any High or Medium severity SWC issue is reported.
Pass `--verify-extraction-only` to validate artifact extraction without running Mythril.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT_DIR, "cache", "mythril")

CORE_CONTRACTS = [
    ("PBMRebateTreasury", "artifacts/contracts/PBMRebateTreasury.sol/PBMRebateTreasury.json"),
    (
        "PatientFundParticipatoryBudgeting",
        "artifacts/contracts/PatientFundParticipatoryBudgeting.sol/PatientFundParticipatoryBudgeting.json",
    ),
    ("PharmacyMutualCredit", "artifacts/contracts/PharmacyMutualCredit.sol/PharmacyMutualCredit.json"),
]


def extract_runtime_hex(contract_name, rel_artifact_path):
    artifact_path = os.path.join(ROOT_DIR, rel_artifact_path)
    if not os.path.exists(artifact_path):
        raise FileNotFoundError(f"Missing Hardhat artifact: {rel_artifact_path}. Run npm run compile first.")

    with open(artifact_path, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    bytecode = (artifact.get("deployedBytecode") or "").strip()
    if bytecode.startswith("0x"):
        bytecode = bytecode[2:]
    if len(bytecode) < 64:
        raise ValueError(f"Empty or invalid deployedBytecode for {contract_name}")

    os.makedirs(OUT_DIR, exist_ok=True)
    hex_path = os.path.join(OUT_DIR, f"{contract_name}.runtime.hex")
    with open(hex_path, "w", encoding="utf-8") as out:
        out.write(bytecode)
    return hex_path, len(bytecode) // 2


def run_mythril(contract_name, hex_path, timeout_sec):
    myth_bin = shutil.which("myth")
    if myth_bin:
        cmd = [
            myth_bin,
            "analyze",
            "-f",
            hex_path,
            "--bin-runtime",
            "-o",
            "json",
            "-t",
            "2",
            "--execution-timeout",
            str(timeout_sec),
            "--solver-timeout",
            "10000",
            "--no-onchain-data",
        ]
    elif shutil.which("docker"):
        rel_hex = os.path.relpath(hex_path, ROOT_DIR).replace("\\", "/")
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{ROOT_DIR}:/workspace",
            "mythril/myth:latest",
            "analyze",
            "-f",
            f"/workspace/{rel_hex}",
            "--bin-runtime",
            "-o",
            "json",
            "-t",
            "2",
            "--execution-timeout",
            str(timeout_sec),
            "--solver-timeout",
            "10000",
            "--no-onchain-data",
        ]
    else:
        raise RuntimeError("Neither `myth` nor `docker` is available on PATH.")

    proc = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True)
    report_path = os.path.join(OUT_DIR, f"{contract_name}.mythril.json")
    raw_out = (proc.stdout or "").strip()
    with open(report_path, "w", encoding="utf-8") as rf:
        rf.write(raw_out + "\n")

    if not raw_out:
        raise RuntimeError(f"Mythril produced empty output for {contract_name}: {proc.stderr[:500]}")

    payload = json.loads(raw_out)
    if not payload.get("success", True):
        raise RuntimeError(f"Mythril reported error on {contract_name}: {payload.get('error')}")

    return payload.get("issues", [])


def main():
    parser = argparse.ArgumentParser(description="Bounded Mythril runtime-bytecode symbolic execution gate.")
    parser.add_argument("--verify-extraction-only", action="store_true", help="Only verify runtime bytecode extraction.")
    parser.add_argument("--execution-timeout", type=int, default=180, help="Mythril execution timeout per contract (s).")
    args = parser.parse_args()

    extracted = []
    for name, artifact in CORE_CONTRACTS:
        hex_path, byte_len = extract_runtime_hex(name, artifact)
        if byte_len > 24576:
            print(f"FAILED: {name} runtime bytecode ({byte_len} bytes) exceeds EIP-170 24,576-byte limit!", file=sys.stderr)
            sys.exit(1)
        extracted.append((name, hex_path, byte_len))

    if args.verify_extraction_only:
        for name, _, byte_len in extracted:
            print(f"[OK] {name}: {byte_len} bytes runtime bytecode (<= 24,576 EIP-170 limit)")
        return

    blocking = []
    summary_rows = [
        "### Mythril Symbolic Bytecode Gate",
        "",
        "| Contract | Runtime Bytes | High | Medium | Low |",
        "| :--- | ---: | ---: | ---: | ---: |",
    ]

    for name, hex_path, byte_len in extracted:
        print(f"Analyzing {name} ({byte_len} bytes)...")
        issues = run_mythril(name, hex_path, args.execution_timeout)
        sev = {"High": 0, "Medium": 0, "Low": 0}
        for issue in issues:
            s = issue.get("severity", "Low")
            sev[s] = sev.get(s, 0) + 1
            if s in ("High", "Medium"):
                blocking.append((name, s, issue.get("swc-id", ""), issue.get("title", "")))
        summary_rows.append(f"| `{name}` | {byte_len} | {sev['High']} | {sev['Medium']} | {sev['Low']} |")

    summary_md = "\n".join(summary_rows) + "\n"
    print("\n" + summary_md)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as sf:
            sf.write(summary_md + "\n")

    if blocking:
        print("FAILED: High/Medium Mythril symbolic execution findings detected:", file=sys.stderr)
        for cname, sev, swc, title in blocking:
            print(f"  - [{sev}] {cname} ({swc}): {title}", file=sys.stderr)
        sys.exit(1)

    print("PASSED: Zero High/Medium Mythril findings across all core contracts.")


if __name__ == "__main__":
    main()
