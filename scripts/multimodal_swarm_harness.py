#!/usr/bin/env python3
"""
Pharmacy Fiduciary Commons - Multi-Modal Swarm Harness & Rotational Loop Orchestrator

This v1 harness coordinates review packets, deterministic checks, optional
read-only reviewer dispatch, and disagreement-matrix reporting. It never edits
source files, stages changes, commits, pushes, deploys, signs, grants roles, or
moves funds.
"""

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
import time

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(ROOT_DIR, "cache")
REVIEWS_DIR = os.path.join(ROOT_DIR, "reviews")
ROSTER_PATH = os.path.join(ROOT_DIR, "review-context", "MULTIMODAL_ROSTER_LOOPS.md")
RECEIPT_PATH = os.path.join(CACHE_DIR, "multimodal_harness_receipt.json")
DEFAULT_MATRIX_PATH = os.path.join(REVIEWS_DIR, "multimodal_swarm_disagreement_matrix.json")
DEFAULT_REPORT_PATH = os.path.join(REVIEWS_DIR, "multimodal_swarm_disagreement_matrix.md")

DISCLOSURE_CLASSES = [
    "PUBLIC_COMMITTED",
    "LOCAL_PLANNING",
    "LOCAL_CODE_DIRTY",
    "SECRET_OR_SENSITIVE",
    "LIVE_PRIVILEGED",
]

HARNESS_COMBOS = {
    "aider-qwen": {
        "framework": "Aider (git_diff_engine)",
        "model": "qwen-2.5-coder-32b",
        "fallback_model": "openrouter/free",
        "description": "Surgical multi-file diff generation and clean commit formatting",
        "check_label": "Hardhat contract suite",
        "check_command": ["npx", "--no-install", "hardhat", "test"],
    },
    "dspy-deepseek": {
        "framework": "DSPy (prompt_compiler)",
        "model": "deepseek-r1",
        "fallback_model": "deepseek/deepseek-r1:free",
        "description": "Compiles and stress-tests review prompts from execution traces",
        "check_label": "Constitutional rubric evaluator",
        "check_command": [sys.executable, "scripts/eval_constitutional_rubric.py"],
    },
    "sweagent-codestral": {
        "framework": "SWE-agent (github_issue_resolver)",
        "model": "codestral-22b",
        "fallback_model": "meta-llama/llama-3.3-70b-instruct:free",
        "description": "Repo navigation, issue resolution, and static build checks",
        "check_label": "Brand Gate frontend check",
        "check_command": ["npm", "run", "check:frontend"],
    },
    "openhands-gemma3": {
        "framework": "OpenHands (sandbox_executor)",
        "model": "gemma3:4b",
        "fallback_model": "http://localhost:11434",
        "description": "Local isolated dry-run simulation and lineage indexing",
        "check_label": "PageIndex status auditor",
        "check_command": [sys.executable, "scripts/index_dossier_tree.py"],
    },
}

MULTIMODAL_ROLES = [
    "visual_ui_auditor",
    "diagram_architecture_critic",
    "adversarial_redteam_probe",
    "formal_contract_checker",
    "privacy_zk_validator",
]

ROLE_TO_REVIEW_LANE = {
    "visual_ui_auditor": "open_claude",
    "diagram_architecture_critic": "kimi_long_context",
    "adversarial_redteam_probe": "laguna_xs",
    "formal_contract_checker": "qwen_coder",
    "privacy_zk_validator": "zero_zk",
}

REVIEW_LANES = [
    "grok_council",
    "strategist",
    "skeptic",
    "advocate",
    "guardrail",
    "zk_privacy",
    "codex_5_6",
    "open_claude",
    "free_code",
    "zero_zk",
    "kimi_long_context",
    "qwen_coder",
    "deepseek_reasoner",
    "laguna_xs",
    "solvency_debt",
]

BOUNDARY_RULES = [
    "Review and verification only.",
    "No source edits are performed by this harness.",
    "No staging, commits, pushes, branches, deploys, signing, fund movement, or role changes.",
    "External reviewer dispatch is disabled unless --run-reviewers and exact --approve-disclosure are supplied.",
    "Reviewer output remains unreconciled raw signal until checked against live repo files and tests.",
]

BUCKET_PATTERNS = {
    "reviewer_confirmed_defect_claim": re.compile(r"\b(confirmed defect|bug|breaks|revert|underflow|overflow|loss of funds)\b", re.I),
    "design_risk": re.compile(r"\b(design risk|risk|attack|grief|race|capture|liveness|solvency|privacy)\b", re.I),
    "missing_test": re.compile(r"\b(missing test|test gap|coverage gap|not tested|needs a test)\b", re.I),
    "policy_decision": re.compile(r"\b(policy|governance|owner decision|approval|co-attestation|fee|toll|timelock)\b", re.I),
    "stale_claim": re.compile(r"\b(stale|outdated|wrong commit|does not match|overclaim|unsupported|false)\b", re.I),
    "needs_verification": re.compile(r"\b(needs verification|verify|unclear|question|unknown|assumption)\b", re.I),
}


def relpath(path):
    return os.path.relpath(path, ROOT_DIR).replace("\\", "/")


def safe_repo_path(path):
    if os.path.isabs(path):
        abs_path = os.path.abspath(path)
    else:
        abs_path = os.path.abspath(os.path.join(ROOT_DIR, path))
    if os.path.commonpath([ROOT_DIR, abs_path]) != ROOT_DIR:
        raise SystemExit(f"Path escapes repository boundary: {path}")
    return abs_path


def resolve_cmd(command):
    if not command:
        return command
    if os.name == "nt":
        for suffix in (".cmd", ".bat", ".exe"):
            resolved = shutil.which(f"{command}{suffix}")
            if resolved:
                return resolved
    return shutil.which(command) or command


def command_for_platform(command):
    if not command:
        return command
    result = list(command)
    result[0] = resolve_cmd(result[0])
    return result


def run_command(label, command, timeout_seconds):
    start = time.time()
    command = command_for_platform(command)
    try:
        res = subprocess.run(
            command,
            cwd=ROOT_DIR,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
        )
        duration_ms = int((time.time() - start) * 1000)
        return {
            "label": label,
            "command": " ".join(command),
            "return_code": res.returncode,
            "status": "PASSED" if res.returncode == 0 else "FAILED",
            "duration_ms": duration_ms,
            "stdout_tail": tail_text(res.stdout),
            "stderr_tail": tail_text(res.stderr),
        }
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.time() - start) * 1000)
        return {
            "label": label,
            "command": " ".join(command),
            "return_code": None,
            "status": "TIMEOUT",
            "duration_ms": duration_ms,
            "stdout_tail": tail_text(exc.stdout or ""),
            "stderr_tail": tail_text(exc.stderr or ""),
        }


def tail_text(text, max_chars=4000):
    if not text:
        return ""
    text = str(text)
    return text[-max_chars:]


def git(args, default=""):
    try:
        res = subprocess.run(["git", *args], cwd=ROOT_DIR, text=True, capture_output=True, timeout=20)
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return default


def git_lineage():
    status_short = git(["status", "--short"], default="")
    upstream = git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], default="UNKNOWN")
    divergence = ""
    if upstream != "UNKNOWN":
        divergence = git(["rev-list", "--left-right", "--count", f"{upstream}...HEAD"], default="")
    return {
        "branch": git(["branch", "--show-current"], default="UNKNOWN"),
        "head": git(["rev-parse", "HEAD"], default="UNKNOWN"),
        "upstream": upstream,
        "divergence_upstream": divergence,
        "is_dirty": bool(status_short.strip()),
        "status_short": status_short,
    }


def selected_harnesses(args):
    if args.all_harnesses:
        return list(HARNESS_COMBOS)
    return [args.harness]


def deterministic_command_for(harness_name, args):
    combo = HARNESS_COMBOS[harness_name]
    command = list(combo["check_command"])
    if harness_name == "dspy-deepseek":
        target = args.packet or args.rubric_target
        if target:
            command.extend(["--target", target])
        else:
            command.extend(["--target", "review-context/oss_council_context.md"])
    return command


def compile_packet(args, review_lane):
    if not args.question:
        return None

    packet_out = args.packet_out
    command = [
        sys.executable,
        "scripts/index_dossier_tree.py",
        "--mode",
        "compile-packet",
        "--question",
        args.question,
        "--lane",
        review_lane,
        "--budget",
        str(args.budget),
        "--out",
        packet_out,
    ]
    if args.files:
        command.append("--files")
        command.extend(args.files)

    result = run_command("Compile review packet", command, args.timeout_seconds)
    packet_abs = safe_repo_path(packet_out)
    packet = None
    if result["status"] == "PASSED" and os.path.exists(packet_abs):
        with open(packet_abs, "r", encoding="utf-8") as f:
            packet = json.load(f)

    return {
        "path": relpath(packet_abs),
        "result": result,
        "packet": packet_summary(packet) if packet else None,
    }


def packet_summary(packet):
    return {
        "packet_id": packet.get("packet_id"),
        "question": packet.get("question"),
        "lane": packet.get("lane"),
        "disclosure_class": packet.get("disclosure_class"),
        "estimated_packet_tokens": packet.get("estimated_packet_tokens"),
        "file_count": len(packet.get("files", [])),
        "head": packet.get("source_snapshot", {}).get("head"),
        "branch": packet.get("source_snapshot", {}).get("branch"),
    }


def packet_disclosure(packet_path):
    packet_abs = safe_repo_path(packet_path)
    with open(packet_abs, "r", encoding="utf-8") as f:
        packet = json.load(f)
    return packet.get("disclosure_class", "LOCAL_CODE_DIRTY")


def review_lanes_for(args):
    if args.review_lanes:
        return args.review_lanes
    mapped = ROLE_TO_REVIEW_LANE.get(args.role)
    return [mapped] if mapped else []


def dispatch_reviewers(args, packet_path, lanes):
    if not args.run_reviewers:
        return []
    if args.offline:
        raise SystemExit("Refusing external reviewer dispatch while --offline is set.")
    if not packet_path:
        raise SystemExit("--run-reviewers requires --packet or --question with --packet-out.")

    disclosure = packet_disclosure(packet_path)
    if disclosure in {"SECRET_OR_SENSITIVE", "LIVE_PRIVILEGED"}:
        raise SystemExit(f"Refusing to dispatch reviewer for {disclosure} packet.")
    if args.approve_disclosure != disclosure:
        raise SystemExit(
            f"Reviewer dispatch requires exact --approve-disclosure {disclosure}; "
            f"received {args.approve_disclosure or 'none'}."
        )

    dispatches = []
    for lane in lanes:
        command = [
            sys.executable,
            "scripts/openrouter_review.py",
            "--role",
            lane,
            "--packet",
            packet_path,
            "--approve-disclosure",
            disclosure,
        ]
        if args.challenger:
            command.append("--challenger")
        if args.permute_order:
            command.append("--permute-order")
        dispatches.append(run_command(f"Reviewer dispatch: {lane}", command, args.timeout_seconds))
    return dispatches


def known_review_output_paths(lanes, packet_path):
    paths = []
    if packet_path and os.path.exists(safe_repo_path(packet_path)):
        with open(safe_repo_path(packet_path), "r", encoding="utf-8") as f:
            packet = json.load(f)
        output_template = packet.get("output_paths", {}).get("review_output_template")
        metadata_template = packet.get("output_paths", {}).get("router_metadata_template")
        if output_template:
            paths.append(output_template)
        if metadata_template:
            paths.append(metadata_template)

    for lane in lanes:
        paths.append(f"reviews/{lane}-packet-review.md")
        paths.append(f"reviews/{lane}-packet-router-metadata.json")
        paths.append(f"reviews/{lane}-review.txt")
        paths.append(f"reviews/{lane}-router-metadata.json")
    return sorted(set(paths))


def existing_review_files(lanes, packet_path):
    files = []
    for candidate in known_review_output_paths(lanes, packet_path):
        abs_path = safe_repo_path(candidate)
        if os.path.exists(abs_path) and os.path.isfile(abs_path) and not abs_path.lower().endswith(".json"):
            files.append(abs_path)
    return files


def classify_line(line):
    buckets = []
    for bucket, pattern in BUCKET_PATTERNS.items():
        if pattern.search(line):
            buckets.append(bucket)
    return buckets


def normalize_review_text(text):
    replacements = {
        "\u00e2\u20ac\u201d": "-",
        "\u00e2\u20ac\u201c": "-",
        "\u00e2\u20ac\u2018": "-",
        "\u00e2\u20ac\u0153": '"',
        "\u00e2\u20ac\u009d": '"',
        "\u00e2\u20ac\u2122": "'",
        "\u00e2\u20ac\u02dc": "'",
        "\u00e2\u20ac\u00a6": "...",
        "\u00e2\u2020\u2019": "->",
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return text


def extract_review_claims(review_file, max_claims=30):
    if review_file.lower().endswith(".json"):
        return []
    with open(review_file, "r", encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    claims = []
    for idx, line in enumerate(lines, 1):
        clean = normalize_review_text(line.strip())
        if not clean or len(clean) < 8:
            continue
        buckets = classify_line(clean)
        if not buckets:
            continue
        claims.append({
            "file": relpath(review_file),
            "line": idx,
            "buckets": buckets,
            "text": clean[:700],
        })
        if len(claims) >= max_claims:
            break
    return claims


def build_disagreement_matrix(review_files):
    claims = []
    bucket_counts = {bucket: 0 for bucket in BUCKET_PATTERNS}
    for review_file in review_files:
        for claim in extract_review_claims(review_file):
            claims.append(claim)
            for bucket in claim["buckets"]:
                bucket_counts[bucket] += 1

    return {
        "schema_version": "pbm-disagreement-matrix/v1.0",
        "generated_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "review_files_scanned": [relpath(path) for path in review_files],
        "bucket_counts": bucket_counts,
        "claims": claims,
        "reconciliation_required": bool(claims),
        "claim_status": "unreconciled_raw_output",
    }


def write_json(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")


def write_report(path, receipt, matrix):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = [
        "# Multi-Modal Swarm Disagreement Matrix",
        "",
        f"Generated: `{matrix['generated_at_utc']}`",
        f"Branch: `{receipt['git_lineage']['branch']}`",
        f"HEAD: `{receipt['git_lineage']['head']}`",
        f"Mode: `{receipt['mode']}`",
        f"Status: `{receipt['overall_status']}`",
        "",
        "## Boundaries",
        "",
    ]
    lines.extend(f"- {rule}" for rule in BOUNDARY_RULES)
    lines.extend(["", "## Bucket Counts", ""])
    for bucket, count in matrix["bucket_counts"].items():
        lines.append(f"- `{bucket}`: {count}")
    lines.extend(["", "## Claims For Reconciliation", ""])
    if matrix["claims"]:
        for claim in matrix["claims"]:
            bucket_text = ", ".join(claim["buckets"])
            lines.append(f"- `{bucket_text}` {claim['file']}:L{claim['line']} - {claim['text']}")
    else:
        lines.append("- No existing reviewer claims matched the v1 disagreement patterns.")
    lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def parse_args():
    parser = argparse.ArgumentParser(description="Multi-modal swarm review and verification harness")
    parser.add_argument("--harness", choices=list(HARNESS_COMBOS), default="aider-qwen", help="Target harness combo")
    parser.add_argument("--all-harnesses", action="store_true", help="Run or plan all configured deterministic harnesses")
    parser.add_argument("--role", choices=MULTIMODAL_ROLES, default="formal_contract_checker", help="Primary reviewer persona")
    parser.add_argument("--mode", choices=["dry-run", "execute"], default="dry-run", help="dry-run plans only; execute runs checks and optional reviewers")
    parser.add_argument("--offline", action="store_true", help="Forbid external reviewer dispatch")
    parser.add_argument("--question", help="Compile a review packet for this question before review dispatch")
    parser.add_argument("--packet", help="Existing packet JSON to review or scan")
    parser.add_argument("--packet-out", default="review-context/packet-multimodal-swarm.json", help="Packet output path when --question is supplied")
    parser.add_argument("--files", nargs="*", help="Repo-relative files for packet compilation")
    parser.add_argument("--budget", type=int, default=12000, help="Packet token budget")
    parser.add_argument("--rubric-target", help="Target for dspy-deepseek rubric execution when no packet is supplied")
    parser.add_argument("--run-reviewers", action="store_true", help="Dispatch read-only external reviewers through scripts/openrouter_review.py")
    parser.add_argument("--review-lanes", nargs="*", choices=REVIEW_LANES, help="Reviewer lanes to dispatch or scan")
    parser.add_argument("--approve-disclosure", choices=DISCLOSURE_CLASSES, help="Exact disclosure class approval required for reviewer dispatch")
    parser.add_argument("--challenger", action="store_true", help="Enable challenger mode for dispatched reviewers")
    parser.add_argument("--permute-order", action="store_true", help="Reverse packet order for reviewer position-bias check")
    parser.add_argument("--timeout-seconds", type=int, default=180, help="Per-command timeout")
    parser.add_argument("--matrix-out", default=relpath(DEFAULT_MATRIX_PATH), help="JSON disagreement matrix output path")
    parser.add_argument("--report-out", default=relpath(DEFAULT_REPORT_PATH), help="Markdown disagreement report output path")
    return parser.parse_args()


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    args = parse_args()
    review_lanes = review_lanes_for(args)
    packet_path = args.packet
    packet_compile = None

    if args.question and args.mode == "execute":
        packet_compile = compile_packet(args, review_lanes[0] if review_lanes else "qwen_coder")
        packet_path = packet_compile["path"]
    elif args.question:
        packet_compile = {
            "path": args.packet_out,
            "result": {
                "label": "Compile review packet",
                "command": "planned dry-run",
                "return_code": None,
                "status": "PLANNED_DRY_RUN",
                "duration_ms": 0,
                "stdout_tail": "",
                "stderr_tail": "",
            },
            "packet": None,
        }

    deterministic_results = []
    planned_harnesses = selected_harnesses(args)
    if args.mode == "execute":
        for harness_name in planned_harnesses:
            combo = HARNESS_COMBOS[harness_name]
            command = deterministic_command_for(harness_name, args)
            deterministic_results.append(run_command(combo["check_label"], command, args.timeout_seconds))
    else:
        for harness_name in planned_harnesses:
            combo = HARNESS_COMBOS[harness_name]
            deterministic_results.append({
                "label": combo["check_label"],
                "command": " ".join(command_for_platform(deterministic_command_for(harness_name, args))),
                "status": "PLANNED_DRY_RUN",
                "return_code": None,
                "duration_ms": 0,
                "stdout_tail": "",
                "stderr_tail": "",
            })

    reviewer_dispatches = dispatch_reviewers(args, packet_path, review_lanes)
    review_files = existing_review_files(review_lanes, packet_path)
    matrix = build_disagreement_matrix(review_files)

    packet_failed = (
        packet_compile
        and packet_compile["result"]["status"] not in {"PASSED", "PLANNED_DRY_RUN"}
    )
    failed_checks = [item for item in deterministic_results if item["status"] not in {"PASSED", "PLANNED_DRY_RUN"}]
    failed_reviews = [item for item in reviewer_dispatches if item["status"] != "PASSED"]
    overall_status = "PASSED"
    if failed_checks or failed_reviews or packet_failed:
        overall_status = "FAILED"
    if args.mode == "dry-run":
        overall_status = "PLANNED_DRY_RUN"

    receipt = {
        "schema_version": "pbm-multimodal-harness-receipt/v1.0",
        "recorded_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "mode": args.mode,
        "offline": args.offline,
        "overall_status": overall_status,
        "git_lineage": git_lineage(),
        "roster_path": relpath(ROSTER_PATH),
        "boundaries": BOUNDARY_RULES,
        "selected_harnesses": [
            {
                "id": name,
                "framework": HARNESS_COMBOS[name]["framework"],
                "model": HARNESS_COMBOS[name]["model"],
                "fallback_model": HARNESS_COMBOS[name]["fallback_model"],
                "description": HARNESS_COMBOS[name]["description"],
            }
            for name in planned_harnesses
        ],
        "role": args.role,
        "review_lanes": review_lanes,
        "packet": packet_path,
        "packet_compile": packet_compile,
        "deterministic_results": deterministic_results,
        "reviewer_dispatches": reviewer_dispatches,
        "disagreement_matrix": relpath(safe_repo_path(args.matrix_out)),
        "disagreement_report": relpath(safe_repo_path(args.report_out)),
    }

    write_json(safe_repo_path(args.matrix_out), matrix)
    write_report(safe_repo_path(args.report_out), receipt, matrix)
    write_json(RECEIPT_PATH, receipt)

    print("==================================================")
    print("MULTI-MODAL OSS SWARM HARNESS")
    print("==================================================")
    print(f"* Mode: {args.mode}")
    print(f"* Overall Status: {overall_status}")
    print(f"* Branch: {receipt['git_lineage']['branch']}")
    print(f"* HEAD: {receipt['git_lineage']['head'][:12]}")
    print(f"* Dirty Tree: {receipt['git_lineage']['is_dirty']}")
    print(f"* Harnesses: {', '.join(planned_harnesses)}")
    print(f"* Review Lanes: {', '.join(review_lanes) if review_lanes else 'none'}")
    print(f"* Review Files Scanned: {len(review_files)}")
    print(f"* Candidate Claims: {len(matrix['claims'])}")
    print(f"* Receipt: {relpath(RECEIPT_PATH)}")
    print(f"* Matrix: {receipt['disagreement_matrix']}")
    print(f"* Report: {receipt['disagreement_report']}")
    print("==================================================")

    if failed_checks or failed_reviews:
        sys.exit(1)


if __name__ == "__main__":
    main()
