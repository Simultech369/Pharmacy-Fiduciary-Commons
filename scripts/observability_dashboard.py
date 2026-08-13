#!/usr/bin/env python3
"""
Pharmacy Fiduciary Commons - Swarm Observatory Dashboard & Inconsistency Meter

Aggregates review router metadata across OSS model runs:
- Latency, token consumption, estimated cost, and error rates.
- Fail-closed evidence checks for reconciled review receipts.
- Generates cache/observability_summary.json.
"""

import glob
import json
import os
import subprocess
import sys
import time

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REVIEWS_DIR = os.path.join(ROOT_DIR, "reviews")
CACHE_DIR = os.path.join(ROOT_DIR, "cache")
SUMMARY_PATH = os.path.join(CACHE_DIR, "observability_summary.json")

REQUIRED_FIELDS = [
    "recorded_at_utc",
    "role",
    "model",
    "provider",
    "launcher",
    "packet_path",
    "output_path",
    "disclosure_class",
    "approved_disclosure_class",
    "error_status",
    "truncation_status",
    "reconciliation_status",
]


def to_repo_path(filepath):
    return os.path.relpath(filepath, ROOT_DIR).replace(os.sep, "/")


def is_git_tracked(filepath):
    result = subprocess.run(
        ["git", "-C", ROOT_DIR, "ls-files", "--error-unmatch", "--", to_repo_path(filepath)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def is_git_ignored(filepath):
    result = subprocess.run(
        ["git", "-C", ROOT_DIR, "check-ignore", "-q", "--", to_repo_path(filepath)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def load_router_metadata():
    pattern = os.path.join(REVIEWS_DIR, "*-router-metadata.json")
    files = glob.glob(pattern)
    metadata_records = []
    parse_errors = []
    skipped_local_artifacts = []

    for filepath in sorted(files):
        source_file = os.path.basename(filepath)
        if not is_git_tracked(filepath):
            if is_git_ignored(filepath):
                skipped_local_artifacts.append({
                    "file": source_file,
                    "reason": "ignored_local_generated_evidence",
                })
                continue
            parse_errors.append(f"{source_file}: untracked router metadata is not ignored")
            continue

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                data["_file"] = source_file
                metadata_records.append(data)
        except Exception as exc:
            parse_errors.append(f"{source_file}: {exc}")

    return metadata_records, parse_errors, skipped_local_artifacts


def compute_observability_metrics(records, parse_errors, skipped_local_artifacts):
    total_runs = len(records)
    total_prompt_tokens = 0
    total_completion_tokens = 0
    total_cost_usd = 0.0
    models_used = set()
    roles_executed = set()
    error_count = 0
    violations = []
    seen_receipts = {}

    for parse_error in parse_errors:
        violations.append({
            "file": "router_metadata",
            "code": "metadata_parse_error",
            "detail": parse_error,
        })

    if total_runs == 0:
        violations.append({
            "file": "router_metadata",
            "code": "no_router_metadata",
            "detail": "No router metadata files were found.",
        })

    for record in records:
        source_file = record.get("_file", "unknown")
        models_used.add(record.get("model", "unknown"))
        roles_executed.add(record.get("role", "unknown"))

        if record.get("error_status"):
            error_count += 1

        for field in REQUIRED_FIELDS:
            if field not in record:
                violations.append({
                    "file": source_file,
                    "code": "missing_required_field",
                    "detail": field,
                })
            elif field != "error_status" and record.get(field) in (None, ""):
                violations.append({
                    "file": source_file,
                    "code": "empty_required_field",
                    "detail": field,
                })

        receipt_key = (
            record.get("role"),
            record.get("model"),
            record.get("packet_path"),
            record.get("output_path"),
        )
        if receipt_key in seen_receipts:
            violations.append({
                "file": source_file,
                "code": "duplicate_router_receipt",
                "detail": f"duplicates {seen_receipts[receipt_key]}",
            })
        else:
            seen_receipts[receipt_key] = source_file

        if record.get("error_status"):
            violations.append({
                "file": source_file,
                "code": "router_error_status_present",
                "detail": str(record.get("error_status")),
            })

        reconciliation_status = str(record.get("reconciliation_status", ""))
        if not reconciliation_status.startswith("reconciled_"):
            violations.append({
                "file": source_file,
                "code": "unreconciled_router_output",
                "detail": reconciliation_status or "missing",
            })

        truncation_status = str(record.get("truncation_status", ""))
        if (
            truncation_status == "possible_truncation"
            and "truncation_acknowledged" not in reconciliation_status
        ):
            violations.append({
                "file": source_file,
                "code": "unacknowledged_possible_truncation",
                "detail": reconciliation_status or "missing",
            })

        tokens = record.get("estimated_packet_tokens", 6000)
        total_prompt_tokens += tokens
        total_completion_tokens += 800

        if "free" in str(record.get("model", "")).lower():
            total_cost_usd += 0.0
        else:
            total_cost_usd += (tokens / 1000.0) * 0.0015

    inconsistency_score = round((len(violations) / max(total_runs, 1)) * 100.0, 2)
    evidence_gate_passed = len(violations) == 0

    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_runs": total_runs,
        "successful_runs": total_runs - error_count,
        "failed_runs": error_count,
        "models_count": len(models_used),
        "models": sorted(models_used),
        "roles_count": len(roles_executed),
        "total_prompt_tokens": total_prompt_tokens,
        "total_completion_tokens": total_completion_tokens,
        "estimated_total_cost_usd": round(total_cost_usd, 4),
        "inconsistency_score_pct": inconsistency_score,
        "target_inconsistency_met": evidence_gate_passed and inconsistency_score <= 10.0,
        "evidence_gate_passed": evidence_gate_passed,
        "violations_count": len(violations),
        "violations": violations,
        "skipped_local_artifacts_count": len(skipped_local_artifacts),
        "skipped_local_artifacts": skipped_local_artifacts,
    }


def main():
    print("==================================================")
    print("SWARM OBSERVATORY METRICS & INCONSISTENCY DASHBOARD")
    print("==================================================")

    records, parse_errors, skipped_local_artifacts = load_router_metadata()
    summary = compute_observability_metrics(records, parse_errors, skipped_local_artifacts)

    print(f"* Total Swarm Review Runs: {summary['total_runs']}")
    print(f"* Skipped Local Router Artifacts: {summary['skipped_local_artifacts_count']}")
    print(f"* Successful / Failed Runs: {summary['successful_runs']} / {summary['failed_runs']}")
    print(f"* Models Evaluated: {', '.join(summary['models'])}")
    print(f"* Estimated Total Prompt Tokens: {summary['total_prompt_tokens']}")
    print(f"* Estimated Total USD Cost: ${summary['estimated_total_cost_usd']:.4f}")
    print(f"* Evidence Gate: {'PASSED' if summary['evidence_gate_passed'] else 'FAILED'}")
    print(
        "* Swarm Inconsistency Score: "
        f"{summary['inconsistency_score_pct']}% "
        f"(Target <= 10.0%: {'PASSED' if summary['target_inconsistency_met'] else 'NEEDS_WORK'})"
    )

    if summary["violations"]:
        print("* Violations:")
        for violation in summary["violations"]:
            print(f"  - {violation['file']}: {violation['code']} ({violation['detail']})")

    print("==================================================")

    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(SUMMARY_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")

    print(f"Observability summary written to: {SUMMARY_PATH}")
    if not summary["target_inconsistency_met"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
