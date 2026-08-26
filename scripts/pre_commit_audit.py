#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from compile_review_packet import canonical_json_digest, compile_review_packet, sha256_digest  # noqa: E402

DISCLOSURE_RECEIPT_SCHEMA_VERSION = "pbm.pre_commit_disclosure_receipt.v1"
REQUIRED_EXTERNAL_DISCLOSURE_APPROVAL = "PUBLIC_SAFE"
EXTERNALLY_REVIEWABLE_PACKET_TIERS = {"PUBLIC_SAFE"}
BLOCKED_EXTERNAL_PATH_PREFIXES = ("cache/", "reviews/", ".env", "secrets/", "private/", "circuits/", "proofs/")

FORBIDDEN_DIFF_PATTERNS = [
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE)),
    (
        "credential_assignment",
        re.compile(
            r"(api[_-]?key|secret[_-]?key|private[_-]?key|password|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_./+\-=]{12,}",
            re.IGNORECASE,
        ),
    ),
    ("bearer_token", re.compile(r"authorization:\s*bearer\s+[A-Za-z0-9._\-]{12,}", re.IGNORECASE)),
    ("seed_phrase", re.compile(r"(seed phrase|mnemonic)\s*[:=]", re.IGNORECASE)),
    ("ssn", re.compile(r"(ssn|social security)\s*[:=]", re.IGNORECASE)),
    ("date_of_birth", re.compile(r"(date of birth|dob)\s*[:=]", re.IGNORECASE)),
    ("raw_claim_identifier", re.compile(r"(raw pharmacy claim|unredacted claim|member id)\s*[:=]", re.IGNORECASE)),
]


def run_command(args, check=True):
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=check, encoding="utf-8")
        return result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        print(f"Error running command {' '.join(args)}: {exc.stderr}", file=sys.stderr)
        sys.exit(1)


def read_text_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def split_changed_files(files_changed: str) -> list[str]:
    return [line.strip() for line in files_changed.splitlines() if line.strip()]


def iter_added_diff_lines(diff_content: str) -> list[str]:
    return [line[1:] for line in diff_content.splitlines() if line.startswith("+") and not line.startswith("+++")]


def find_forbidden_diff_markers(diff_content: str) -> list[str]:
    added_content = "\n".join(iter_added_diff_lines(diff_content))
    markers = []
    for label, pattern in FORBIDDEN_DIFF_PATTERNS:
        if pattern.search(added_content):
            markers.append(label)
    return markers


def normalize_repo_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def find_blocked_external_paths(staged_files: list[str]) -> list[str]:
    blocked = []
    for path in staged_files:
        normalized = normalize_repo_path(path)
        if any(normalized.startswith(prefix) for prefix in BLOCKED_EXTERNAL_PATH_PREFIXES):
            blocked.append(normalized)
    return sorted(blocked)


def diff_contains_deletion(diff_content: str) -> bool:
    return any(
        line.startswith("deleted file mode ") or line == "+++ /dev/null"
        for line in diff_content.splitlines()
    )


def build_pre_commit_disclosure_receipt(
    staged_files: list[str],
    diff_content: str,
    approved_disclosure: str | None,
) -> dict:
    packet = compile_review_packet(
        staged_files,
        snapshot_composite_state_sha256=sha256_digest(diff_content),
    )
    forbidden_markers = find_forbidden_diff_markers(diff_content)
    blocked_paths = find_blocked_external_paths(staged_files)
    external_block_reasons = []
    local_block_reasons = []

    if approved_disclosure != REQUIRED_EXTERNAL_DISCLOSURE_APPROVAL:
        external_block_reasons.append(
            f"missing approval: set PBM_APPROVE_EXTERNAL_REVIEW={REQUIRED_EXTERNAL_DISCLOSURE_APPROVAL}"
        )

    if packet["sensitivity_tier"] not in EXTERNALLY_REVIEWABLE_PACKET_TIERS:
        external_block_reasons.append(
            f"packet tier {packet['sensitivity_tier']} is not externally reviewable by the pre-commit hook"
        )

    if blocked_paths:
        external_block_reasons.append(
            "path prefix blocked from external pre-commit review: " + ", ".join(blocked_paths)
        )

    if diff_contains_deletion(diff_content):
        external_block_reasons.append("staged deletions are blocked from external pre-commit review")

    unverified = [
        artifact["path_or_identifier"]
        for artifact in packet["artifacts"]
        if artifact["provenance_verified"] is not True
    ]
    if unverified:
        external_block_reasons.append(
            "staged files with unverified working-tree provenance: " + ", ".join(sorted(unverified))
        )

    if forbidden_markers:
        external_block_reasons.append(
            "staged diff matched local-only secret/PII markers: " + ", ".join(forbidden_markers)
        )
        local_block_reasons.append(
            "staged diff matched local-only secret/PII markers: " + ", ".join(forbidden_markers)
        )

    if packet["sensitivity_tier"] == "LOCAL_ONLY_REQUIRED":
        local_block_reasons.append(
            "packet tier LOCAL_ONLY_REQUIRED cannot pass the pre-commit hook"
        )

    receipt = {
        "receipt_type": "PreCommitDisclosureReceipt",
        "schema_version": DISCLOSURE_RECEIPT_SCHEMA_VERSION,
        "external_review_policy": "REQUIRE_PUBLIC_SAFE_PACKET_AND_EXACT_APPROVAL",
        "local_commit_policy": "ALLOW_LOCAL_COMMIT_UNLESS_LOCAL_ONLY_OR_SECRET_MARKER",
        "required_approval_class": REQUIRED_EXTERNAL_DISCLOSURE_APPROVAL,
        "approved_disclosure_class": approved_disclosure,
        "external_review_allowed": len(external_block_reasons) == 0,
        "external_review_block_reasons": external_block_reasons,
        "local_commit_allowed": len(local_block_reasons) == 0,
        "local_commit_block_reasons": local_block_reasons,
        "allowed_packet_tiers": sorted(EXTERNALLY_REVIEWABLE_PACKET_TIERS),
        "blocked_external_path_prefixes": list(BLOCKED_EXTERNAL_PATH_PREFIXES),
        "blocked_external_paths": blocked_paths,
        "forbidden_diff_markers": forbidden_markers,
        "staged_file_count": len(staged_files),
        "staged_diff_sha256": sha256_digest(diff_content),
        "packet_sensitivity_receipt": packet,
    }
    receipt["payload_digest"] = canonical_json_digest(receipt)
    return receipt


def write_json(path: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def parse_args():
    parser = argparse.ArgumentParser(description="Pre-commit AI guardrail audit")
    parser.add_argument(
        "--policy-check-only",
        action="store_true",
        help="Evaluate the external disclosure policy without invoking git or OpenRouter",
    )
    parser.add_argument("--files", nargs="*", default=[], help="Files to include in --policy-check-only")
    parser.add_argument("--diff-file", help="Diff file to evaluate in --policy-check-only")
    parser.add_argument("--approved-disclosure", help="Explicit approval class for --policy-check-only")
    parser.add_argument("--output", help="Optional JSON receipt output path for --policy-check-only")
    return parser.parse_args()


def read_policy_diff(args) -> str:
    if not args.diff_file:
        return ""
    with open(args.diff_file, "r", encoding="utf-8") as handle:
        return handle.read()


def run_policy_check_only(args) -> None:
    receipt = build_pre_commit_disclosure_receipt(
        staged_files=args.files,
        diff_content=read_policy_diff(args),
        approved_disclosure=args.approved_disclosure,
    )
    if args.output:
        write_json(args.output, receipt)
    print(json.dumps(receipt, indent=2))
    sys.exit(0 if receipt["external_review_allowed"] else 1)


def main():
    args = parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    if args.policy_check_only:
        run_policy_check_only(args)

    print("Running pre-commit AI guardrail audit...")

    staged_files_manifest = os.environ.get("PBM_PRE_COMMIT_STAGED_FILES_MANIFEST")
    staged_diff_file = os.environ.get("PBM_PRE_COMMIT_STAGED_DIFF_FILE")

    if staged_files_manifest:
        files_changed = read_text_file(staged_files_manifest).strip()
    else:
        files_changed = run_command(["git", "diff", "--cached", "--name-only"])

    if not files_changed:
        print("No staged changes found. Skipping audit.")
        sys.exit(0)

    staged_files = split_changed_files(files_changed)
    print(f"Staged files for review:\n{files_changed}")

    if staged_diff_file:
        diff_content = read_text_file(staged_diff_file)
    else:
        diff_content = run_command(["git", "diff", "--cached"])

    if not diff_content.strip():
        print("Staged diff is empty. Skipping audit.")
        sys.exit(0)

    reviews_dir = os.path.join(ROOT_DIR, "reviews")
    os.makedirs(reviews_dir, exist_ok=True)

    temp_diff_path = os.path.join(reviews_dir, "temp-pre-commit-diff.txt")
    with open(temp_diff_path, "w", encoding="utf-8") as handle:
        handle.write(diff_content)

    print(f"Stored staged diff at {temp_diff_path}")

    approved_disclosure = (
        os.environ.get("PBM_APPROVE_EXTERNAL_REVIEW")
        or os.environ.get("PBM_APPROVED_DISCLOSURE_CLASS")
    )
    disclosure_receipt = build_pre_commit_disclosure_receipt(
        staged_files=staged_files,
        diff_content=diff_content,
        approved_disclosure=approved_disclosure,
    )
    disclosure_receipt_path = os.path.join(reviews_dir, "pre-commit-disclosure-receipt.json")
    write_json(disclosure_receipt_path, disclosure_receipt)
    packet = disclosure_receipt["packet_sensitivity_receipt"]
    print(f"Disclosure receipt written to: {disclosure_receipt_path}")
    print(
        "Packet tier: "
        f"{packet['sensitivity_tier']} | unique content groups: {packet['unique_content_artifact_count']} "
        f"| duplicates: {packet['duplicate_artifact_count']}"
    )

    if not disclosure_receipt["external_review_allowed"]:
        print("External pre-commit review is blocked by the packet-backed disclosure gate.")
        for reason in disclosure_receipt["external_review_block_reasons"]:
            print(f"  - {reason}")
        if os.path.exists(temp_diff_path):
            os.remove(temp_diff_path)
        if disclosure_receipt["local_commit_allowed"]:
            print("Local pre-commit disclosure gate passed without external review.")
            print(
                "Set PBM_APPROVE_EXTERNAL_REVIEW=PUBLIC_SAFE only for packet-proven "
                "public-safe staged diffs that may be sent externally."
            )
            sys.exit(0)
        print("Local pre-commit disclosure gate blocked this commit.")
        for reason in disclosure_receipt["local_commit_block_reasons"]:
            print(f"  - {reason}")
        sys.exit(1)

    openrouter_script = os.environ.get("PBM_PRE_COMMIT_REVIEWER_SCRIPT") or os.path.join(
        SCRIPT_DIR,
        "openrouter_review.py",
    )
    review_cmd = [
        sys.executable,
        openrouter_script,
        "--role",
        "guardrail",
        "--context",
        temp_diff_path,
        "--disclosure-class",
        REQUIRED_EXTERNAL_DISCLOSURE_APPROVAL,
        "--approve-disclosure",
        approved_disclosure,
    ]

    print("Calling AI Auditor via OpenRouter...")
    try:
        subprocess.run(review_cmd, check=True)
    except subprocess.CalledProcessError as exc:
        print(f"OpenRouter review script failed to execute successfully: {exc}")
        if os.path.exists(temp_diff_path):
            os.remove(temp_diff_path)
        sys.exit(1)

    review_output_path = os.path.join(reviews_dir, "guardrail-review.txt")
    if not os.path.exists(review_output_path):
        print(f"Error: expected review output file not found at {review_output_path}")
        if os.path.exists(temp_diff_path):
            os.remove(temp_diff_path)
        sys.exit(1)

    with open(review_output_path, "r", encoding="utf-8") as handle:
        review_content = handle.read()

    if os.path.exists(temp_diff_path):
        os.remove(temp_diff_path)

    if "FAIL" in review_content:
        print("\nAI Guardrail Review: FAIL")
        print("Please resolve the issues listed in the review before committing.")
        sys.exit(1)
    if "PASS" in review_content:
        print("\nAI Guardrail Review: PASS")
        sys.exit(0)

    print("\nAI Guardrail Review: no clear PASS or FAIL found. Blocking for safety.")
    sys.exit(1)


if __name__ == "__main__":
    main()
