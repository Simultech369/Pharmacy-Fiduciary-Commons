#!/usr/bin/env python3
"""
Fail-closed constitutional rubric evaluator for PBM review packets and dossiers.

The evaluator checks advisory review artifacts for authority, readiness,
patient-fund, privacy, evidence-label, and governance-boundary overclaims.
"""

import argparse
import json
import os
import re
import sys


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

FRESHNESS_LABELS = {
    "[committed HEAD]",
    "[dirty working tree]",
    "[generated cache]",
    "[external reviewer claim]",
    "[live verification just run]",
}

VALID_DISCLOSURE_CLASSES = {
    "PUBLIC_COMMITTED",
    "LOCAL_PLANNING",
    "LOCAL_CODE_DIRTY",
    "SECRET_OR_SENSITIVE",
    "LIVE_PRIVILEGED",
}

NEGATION_TERMS = [
    "never",
    "no ",
    "not ",
    "do not",
    "cannot",
    "can't",
    "must not",
    "without approval",
    "without explicit",
    "does not",
    "not authorize",
    "strictly advisory",
    "forbidden",
    "non-claim",
    "prototype",
    "docs-only",
]

CLAIM_TERMS = [
    "verified",
    "green",
    "safe",
    "proof",
    "production",
    "mainnet",
    "private",
    "privacy",
    "unlinkable",
    "solvent",
    "authority",
    "consensus",
    "ready",
    "passed",
    "0 contradictions",
    "100%",
]

RULES = [
    {
        "category": "authority_overclaim",
        "pattern": re.compile(
            r"\b(ai|agent|model|reviewer|observatory|router)\b.*\b(sign|deploy|move funds|publish roots|grant|revoke|execute governance|submit claims|autonomous action|authorize)\b",
            re.IGNORECASE,
        ),
        "reason": "AI/reviewer authority claims must remain strictly advisory.",
    },
    {
        "category": "production_readiness_overclaim",
        "pattern": re.compile(
            r"\b(production ready|mainnet ready|launch ready|audit ready|fully audited|deployment ready)\b",
            re.IGNORECASE,
        ),
        "reason": "Production or mainnet readiness requires explicit evidence and release approval.",
    },
    {
        "category": "patient_fund_risk",
        "pattern": re.compile(
            r"\b(bypass|override|skip|ignore)\b.*\b(multisig|multi-sig|fiduciary|patient fund|council refund|funds?)\b",
            re.IGNORECASE,
        ),
        "reason": "Patient Fund and fiduciary controls cannot be bypassed by review tooling.",
    },
    {
        "category": "privacy_zk_overclaim",
        "pattern": re.compile(
            r"\b(100% private|fully private|complete privacy|fully unlinkable|perfect unlinkability|eliminates metadata|metadata cannot link|safe against replay and identity leakage)\b",
            re.IGNORECASE,
        ),
        "reason": "ZK/privacy claims must preserve metadata, relayer, issuer, support-flow, and gas-payer non-claims.",
    },
    {
        "category": "governance_boundary_violation",
        "pattern": re.compile(
            r"\b(override|supersede|replace|bypass|ignore)\b.*\b(COMMONS_CONSTITUTION|PATIENT_FUND_POLICY|constitution|patient fund policy)\b",
            re.IGNORECASE,
        ),
        "reason": "Review artifacts cannot override governance baselines.",
    },
]


def has_negation(line):
    lowered = line.lower()
    return any(term in lowered for term in NEGATION_TERMS)


def has_scoped_negation(line, match):
    """Return true only when negation appears in the same clause as a rule hit."""
    clause_boundaries = ".;:|"
    start = match.start()
    end = match.end()

    clause_start = 0
    for boundary in clause_boundaries:
        boundary_index = line.rfind(boundary, 0, start)
        if boundary_index >= clause_start:
            clause_start = boundary_index + 1

    clause_end = len(line)
    for boundary in clause_boundaries:
        boundary_index = line.find(boundary, end)
        if boundary_index != -1:
            clause_end = min(clause_end, boundary_index)

    clause = line[clause_start:clause_end].lower()
    return any(term in clause for term in NEGATION_TERMS)


def has_freshness_label(line):
    return any(label in line for label in FRESHNESS_LABELS)


def is_claim_line(line):
    lowered = line.lower()
    return any(term in lowered for term in CLAIM_TERMS)


def target_relpath(path):
    abs_path = os.path.abspath(path)
    try:
        return os.path.relpath(abs_path, REPO_ROOT).replace("\\", "/")
    except ValueError:
        return path


def add_violation(violations, path, line, category, reason, snippet):
    violations.append({
        "file": target_relpath(path),
        "line": line,
        "category": category,
        "reason": reason,
        "snippet": snippet.strip()[:240],
    })


def line_number_for_key(raw_lines, key):
    needle = f'"{key}"'
    for index, line in enumerate(raw_lines, 1):
        if needle in line:
            return index
    return 1


def evaluate_packet_json(path):
    violations = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    raw_lines = raw.splitlines()
    try:
        packet = json.loads(raw)
    except json.JSONDecodeError as exc:
        add_violation(violations, path, exc.lineno, "invalid_json", "Target JSON could not be parsed.", exc.msg)
        return violations

    if packet.get("schema_version") != "pbm-review-packet/v0.1":
        return evaluate_text_lines(path, raw_lines)

    disclosure_class = packet.get("disclosure_class")
    if disclosure_class not in VALID_DISCLOSURE_CLASSES:
        add_violation(
            violations,
            path,
            line_number_for_key(raw_lines, "disclosure_class"),
            "invalid_disclosure_class",
            "Packet must declare a valid disclosure class.",
            str(disclosure_class),
        )

    if disclosure_class in {"SECRET_OR_SENSITIVE", "LIVE_PRIVILEGED"}:
        add_violation(
            violations,
            path,
            line_number_for_key(raw_lines, "disclosure_class"),
            "forbidden_disclosure_class",
            "Secret/sensitive or live privileged packets cannot be routed for model review.",
            disclosure_class,
        )

    for key in ["forbidden_inputs", "known_boundaries", "tests_to_run", "files"]:
        if not packet.get(key):
            add_violation(
                violations,
                path,
                line_number_for_key(raw_lines, key),
                "missing_packet_field",
                f"Packet is missing required advisory field: {key}.",
                key,
            )

    for index, file_entry in enumerate(packet.get("files", []), 1):
        label = file_entry.get("freshness_label")
        if label not in FRESHNESS_LABELS:
            add_violation(
                violations,
                path,
                line_number_for_key(raw_lines, "freshness_label"),
                "missing_evidence_label",
                "Each packet file must carry a canonical freshness/evidence label.",
                f"file entry {index}: {file_entry.get('path')}",
            )
        if not file_entry.get("snippets"):
            add_violation(
                violations,
                path,
                line_number_for_key(raw_lines, "snippets"),
                "missing_line_anchors",
                "Each packet file must include line-anchored snippets.",
                f"file entry {index}: {file_entry.get('path')}",
            )

    metadata_lines = []
    for key in ["lane", "disclosure_class"]:
        if key in packet:
            metadata_lines.append((line_number_for_key(raw_lines, key), f"{key}: {packet[key]}"))
    for key in ["known_boundaries", "review_instructions"]:
        for item in packet.get(key, []):
            metadata_lines.append((line_number_for_key(raw_lines, key), str(item)))

    for line_no, text in metadata_lines:
        for rule in RULES:
            match = rule["pattern"].search(text)
            if match and not has_scoped_negation(text, match):
                add_violation(violations, path, line_no, rule["category"], rule["reason"], text)

    return violations


def evaluate_text_lines(path, lines):
    violations = []
    in_code_fence = False

    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code_fence = not in_code_fence
            continue
        if in_code_fence or not stripped:
            continue

        for rule in RULES:
            match = rule["pattern"].search(line)
            if match and not has_scoped_negation(line, match):
                add_violation(violations, path, line_no, rule["category"], rule["reason"], line)

        ext = os.path.splitext(path)[1].lower()
        if ext in {".md", ".txt"} and is_claim_line(line) and not has_freshness_label(line):
            if not has_negation(line) and not stripped.startswith("|"):
                add_violation(
                    violations,
                    path,
                    line_no,
                    "missing_evidence_label",
                    "Status, proof, readiness, privacy, or safety claims should carry a canonical evidence label.",
                    line,
                )

    return violations


def evaluate_target(path):
    if not os.path.exists(path):
        return [{
            "file": target_relpath(path),
            "line": 0,
            "category": "missing_target",
            "reason": "Target file does not exist.",
            "snippet": path,
        }]

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw_lines = f.read().splitlines()

    if path.lower().endswith(".json"):
        return evaluate_packet_json(path)
    return evaluate_text_lines(path, raw_lines)


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate PBM review artifacts against fail-closed constitutional rubric")
    parser.add_argument("--target", nargs="+", required=True, help="Packet, dossier, or review file(s) to evaluate")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    return parser.parse_args()


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    args = parse_args()
    violations = []
    for target in args.target:
        path = target if os.path.isabs(target) else os.path.join(REPO_ROOT, target)
        violations.extend(evaluate_target(path))

    if args.json:
        print(json.dumps({"violation_count": len(violations), "violations": violations}, indent=2))
    elif violations:
        print("[FAIL] Constitutional rubric violations detected:")
        for item in violations:
            print(f"- {item['file']}:L{item['line']} [{item['category']}] {item['reason']}")
            print(f"  Snippet: {item['snippet']}")
    else:
        print("[OK] No constitutional rubric violations detected.")

    sys.exit(1 if violations else 0)


if __name__ == "__main__":
    main()
