#!/usr/bin/env python3
"""
PageIndex Dossier Tree Indexer and PBM Review Observatory packet compiler.

Default mode preserves the read-only documentation status scanner and writes
cache/dossier_tree_index.json. The compile-packet mode builds a bounded,
line-anchored advisory review packet for a specific reviewer question.
"""

import argparse
import datetime as _dt
import hashlib
import json
import math
import os
import re
import subprocess
import sys


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CACHE_DIR = os.path.join(REPO_ROOT, "cache")
REVIEW_CONTEXT_DIR = os.path.join(REPO_ROOT, "review-context")
OUTPUT_JSON = os.path.join(CACHE_DIR, "dossier_tree_index.json")
LINEAGE_BENCHMARK_JSONL = os.path.join(CACHE_DIR, "lineage_eval_benchmark.jsonl")

FRESHNESS_LABELS = [
    "[committed HEAD]",
    "[dirty working tree]",
    "[generated cache]",
    "[external reviewer claim]",
    "[live verification just run]",
]

FORBIDDEN_PACKET_PATH_PARTS = {
    ".env",
    ".git",
    "node_modules",
    "artifacts",
    "cache",
    "dist",
    "coverage",
}

PACKET_FORBIDDEN_INPUTS = [
    "API keys, private keys, seed phrases, deployment keys, or signer material",
    "PHI, patient identity, pharmacy identity, support-ticket identifiers, or raw credential data",
    "real witness material, credential secrets, Merkle witnesses from production, or private nullifier inputs",
    "live privileged RPC endpoints, production database service roles, multisig approvals, or live-chain action payloads",
]

PACKET_KNOWN_BOUNDARIES = [
    "The review packet is strictly advisory and cannot authorize deployment, signing, fund movement, governance execution, or role changes.",
    "Reviewer output remains an external claim until reconciled against local files, tests, commands, and the lineage ledger.",
    "ZK/nullifier claims are limited to the included evidence; relayer gas-payer, timing, RPC, support-flow, and issuer-custody metadata remain explicit non-claims unless separately proven.",
    "Dirty or untracked files require explicit operator approval before any external reviewer route.",
]

DEFAULT_TESTS_TO_RUN = [
    "python scripts/index_dossier_tree.py",
    "python scripts/eval_constitutional_rubric.py --target review-context/packet-zk-nullifier-replay.json",
    "npx.cmd --no-install hardhat test --no-compile test/ZKNullifierFixtureGate.test.js test/ZKNullifierCircuit.test.js",
    "git diff --check",
]

FIRST_PACKET_FILES = [
    "contracts/PBMRebateTreasury.sol",
    "SOLVENCY_DEBT_SEMANTICS.md",
    "circuits/vote_nullifier.circom",
    "contracts/PatientFundParticipatoryBudgeting.sol",
    "test/ZKNullifierFixtureGate.test.js",
    "test/ZKNullifierCircuit.test.js",
    "IDENTITY_NULLIFIER_DESIGN.md",
    "ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md",
    "COMMONS_CONSTITUTION.md",
    "PATIENT_FUND_POLICY.md",
    "MECHANISM_COVERAGE.md",
    "AGENT_REVIEW_ORCHESTRATION.md",
    ".agents/AGENTS.md",
    ".agents/memory/MEMORY.md",
    ".agents/memory/WAITING_ON_ME.md",
    ".agents/memory/LEARNINGS_QUEUE.md",
    "review-context/agent_work_lineage_ledger.md",
]

TARGET_DOCS = [
    "AGENT_REVIEW_ORCHESTRATION.md",
    "ONBOARDING.md",
    "README.md",
    "PRODUCTION_READINESS_CHECKLIST.md",
    "MECHANISM_COVERAGE.md",
    "GOVERNANCE.md",
    "COMMONS_CONSTITUTION.md",
    "PATIENT_FUND_POLICY.md",
    "SECURITY.md",
    "ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md",
    "NEXT_REVIEW_HANDOFF.md",
    "review-context/SINGLE_REPO_STATE_LEDGER.md",
    "review-context/agent_work_lineage_ledger.md",
    "review-context/SWARM_ROSTER_40_MODELS.md",
    "review-context/MULTIMODAL_ROSTER_LOOPS.md",
    "reviews/rotational_swarm_review_dossier.md",
    "reviews/solidity-security-audit-report.md",
]

VERIFIED_STATE = {
    "hardhat_tests": {
        "passing_tests": 280,
        "evidence": "npm.cmd test",
    },
    "brand_gate_b": {
        "status": "GREEN",
        "inline_styles_remaining": 0,
        "entry_id": "Entry 012 / Entry 014",
    },
    "db_proxy_rls": {
        "status": "GREEN",
        "gate": "Gate DB1",
        "test_file": "test/server.test.js",
        "passing_tests": 20,
        "entry_id": "Entry 015",
    },
    "ui_slice_b3": {
        "status": "GREEN",
        "entry_id": "Entry 014",
    },
}


def run_git(args, default=""):
    try:
        return subprocess.check_output(["git", *args], cwd=REPO_ROOT, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return default


def get_git_status_map():
    status_map = {}
    out = run_git(["status", "--porcelain"], default="")
    for line in out.splitlines():
        if len(line) >= 4:
            code = line[:2].strip() or "M"
            filepath = line[3:].strip().replace("\\", "/")
            status_map[filepath] = code
    return status_map


def safe_relpath(path):
    normalized = path.replace("\\", "/").strip()
    if not normalized:
        raise ValueError("Empty packet file path")

    if os.path.isabs(normalized):
        abs_path = os.path.abspath(normalized)
    else:
        abs_path = os.path.abspath(os.path.join(REPO_ROOT, normalized))

    try:
        common = os.path.commonpath([REPO_ROOT, abs_path])
    except ValueError as exc:
        raise ValueError(f"Packet file is outside repository: {path}") from exc

    if os.path.normcase(common) != os.path.normcase(REPO_ROOT):
        raise ValueError(f"Packet file is outside repository: {path}")

    rel_path = os.path.relpath(abs_path, REPO_ROOT).replace("\\", "/")
    lowered_parts = {part.lower() for part in rel_path.split("/")}
    lowered_path = rel_path.lower()
    if any(part in lowered_parts or lowered_path.endswith(part) for part in FORBIDDEN_PACKET_PATH_PARTS):
        raise ValueError(f"Refusing to include forbidden packet path: {rel_path}")

    return rel_path


def read_lines(rel_path):
    abs_path = os.path.join(REPO_ROOT, rel_path)
    with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
        return f.readlines()


def normalize_space(value):
    return re.sub(r"\s+", " ", value or "").strip()


def extract_yaml_scalar(body, key):
    pattern = re.compile(rf"^\s*{re.escape(key)}:\s*(.*)$", re.MULTILINE)
    match = pattern.search(body)
    if not match:
        return ""
    value = match.group(1).strip()
    if value in {">", "|"}:
        start = match.end()
        following = []
        for line in body[start:].splitlines():
            if re.match(r"^\S", line):
                break
            if line.strip():
                following.append(line.strip())
        return normalize_space(" ".join(following))
    return value.strip().strip('"').strip("'")


def extract_yaml_list(body, key):
    key_match = re.search(rf"^\s*{re.escape(key)}:\s*$", body, re.MULTILINE)
    if not key_match:
        return []
    items = []
    for line in body[key_match.end():].splitlines():
        if re.match(r"^\S", line):
            break
        item_match = re.match(r"^\s*-\s+\"?(.*?)\"?\s*$", line)
        if item_match:
            items.append(item_match.group(1).strip())
    return items


def assess_lineage_status(status):
    normalized = (status or "").lower()
    if "verified" in normalized or "closed" in normalized:
        return "good"
    if "rejected" in normalized or "false" in normalized:
        return "rejected"
    if "narrow" in normalized:
        return "narrowed"
    if "stale" in normalized:
        return "stale"
    if "risk" in normalized or "blocker" in normalized or "open" in normalized:
        return "risky"
    return "risky"


def parse_lineage_ledger():
    ledger_path = os.path.join(REVIEW_CONTEXT_DIR, "agent_work_lineage_ledger.md")
    entries = []
    if not os.path.exists(ledger_path):
        return entries

    with open(ledger_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    raw_entries = re.findall(r"### Entry\s+(\d+):\s*(.*?)\n```yaml(.*?)```", content, re.DOTALL)
    for number, title, body in raw_entries:
        status = extract_yaml_scalar(body, "status")
        evidence = extract_yaml_scalar(body, "evidence")
        actual_proof = extract_yaml_scalar(body, "actual_proof")
        dependent_artifacts = extract_yaml_list(body, "dependent_artifacts")
        entry_id = extract_yaml_scalar(body, "entry_id") or f"entry-{int(number):03d}"
        record = {
            "number": int(number),
            "title": normalize_space(title),
            "entry_id": entry_id,
            "source_model": extract_yaml_scalar(body, "source_model"),
            "source_claim": extract_yaml_scalar(body, "source_claim"),
            "claim": extract_yaml_scalar(body, "source_claim"),
            "human_readable_claim": extract_yaml_scalar(body, "human_readable_claim"),
            "implied_claim": extract_yaml_scalar(body, "implied_claim"),
            "actual_proof": actual_proof,
            "evidence": evidence,
            "status": status or "UNKNOWN",
            "invalidation_criteria": extract_yaml_scalar(body, "invalidation_criteria"),
            "dependent_artifacts": dependent_artifacts,
            "assessment": assess_lineage_status(status),
            "body": body.strip(),
        }
        entries.append(record)
    return entries


def write_lineage_benchmark(entries):
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(LINEAGE_BENCHMARK_JSONL, "w", encoding="utf-8") as f:
        for entry in entries:
            payload = {
                "entry_id": entry["entry_id"],
                "claim": entry["claim"],
                "human_readable_claim": entry["human_readable_claim"],
                "implied_claim": entry["implied_claim"],
                "actual_proof": entry["actual_proof"],
                "evidence": entry["evidence"],
                "status": entry["status"],
                "invalidation_criteria": entry["invalidation_criteria"],
                "dependent_artifacts": entry["dependent_artifacts"],
                "assessment": entry["assessment"],
            }
            f.write(json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n")


def scan_document(rel_path, git_status_map, total_scanned_count, current_branch):
    abs_path = os.path.join(REPO_ROOT, rel_path)
    if not os.path.exists(abs_path):
        return None

    lines = read_lines(rel_path)
    doc_tree = {
        "file": rel_path.replace("\\", "/"),
        "sections": [],
        "findings": [],
        "line_count": len(lines),
    }

    current_section = "Preamble"

    for idx, line in enumerate(lines, 1):
        header_match = re.match(r"^(#{1,4})\s+(.*)", line)
        if header_match:
            current_section = header_match.group(2).strip()
            doc_tree["sections"].append({
                "line": idx,
                "title": current_section,
                "level": len(header_match.group(1)),
            })

        line_lower = line.lower()
        expected_hardhat_tests = VERIFIED_STATE["hardhat_tests"]["passing_tests"]

        branch_match = re.search(r"(?:branch|current branch/head)[^`]*`([^`]+)`", line, re.IGNORECASE)
        if branch_match and current_branch:
            claimed_branch = branch_match.group(1)
            if claimed_branch != current_branch:
                doc_tree["findings"].append({
                    "line": idx,
                    "type": "BRANCH_LABEL_MISMATCH",
                    "category": "git_truth",
                    "section": current_section,
                    "text": line.strip(),
                    "reason": f"Claims branch '{claimed_branch}', contradicting live Git branch '{current_branch}'.",
                })

        test_count_context = (
            "hardhat" in line_lower or
            "active test suite" in line_lower or
            "tests run locally" in line_lower or
            "test suite execution" in line_lower or
            "unit test suite" in line_lower
        )
        if test_count_context:
            count_matches = []
            count_matches.extend(int(m.group(1)) for m in re.finditer(r"(\d+)\s*/\s*\d+\s+passing\s+(?:unit\s+)?tests?", line, re.IGNORECASE))
            count_matches.extend(int(m.group(1)) for m in re.finditer(r"passes\s+(\d+)\s+tests?", line, re.IGNORECASE))
            count_matches.extend(int(m.group(1)) for m in re.finditer(r"(\d+)-test\s+suite", line, re.IGNORECASE))
            count_matches.extend(int(m.group(1)) for m in re.finditer(r"active\s+test\s+suite:\s*\*?\*?(\d+)", line, re.IGNORECASE))
            for claimed_tests in count_matches:
                if claimed_tests != expected_hardhat_tests:
                    doc_tree["findings"].append({
                        "line": idx,
                        "type": "STALE_TEST_COUNT_CLAIM",
                        "category": "test_suite_truth",
                        "section": current_section,
                        "text": line.strip(),
                        "reason": f"Claims {claimed_tests} Hardhat tests, contradicting current expected suite count of {expected_hardhat_tests}.",
                    })
                    break

        if any(term in line_lower for term in ["db proxy", "supabase", "rls", "database security", "voter_profiles"]):
            if any(stale in line_lower for stale in ["not present", "unresolved", "mocked only", "not implemented", "missing", "60 remaining", "38 remaining"]):
                if "agent_work_lineage_ledger.md" not in rel_path and "full_repo_oss_swarm_review_dossier.md" not in rel_path:
                    doc_tree["findings"].append({
                        "line": idx,
                        "type": "STALE_CONTRADICTION",
                        "category": "db_proxy_rls",
                        "section": current_section,
                        "text": line.strip(),
                        "reason": "Claims DB/RLS is unresolved/missing, contradicting verified Gate DB1 (Entry 015, 19/19 passing tests in test/server.test.js).",
                    })

        if "inline style" in line_lower:
            match = re.search(r"(\d+)\s+remaining\s+inline\s+style", line, re.IGNORECASE)
            if match:
                count = int(match.group(1))
                if count > 0:
                    if "brand_gate_b2_low_credit_handoff.md" in rel_path or "PRODUCTION_READINESS_CHECKLIST.md" in rel_path or "README.md" in rel_path:
                        doc_tree["findings"].append({
                            "line": idx,
                            "type": "STALE_CONTRADICTION",
                            "category": "brand_gate_b",
                            "section": current_section,
                            "text": line.strip(),
                            "reason": f"Claims {count} inline styles remain, contradicting Entry 012/014 (0 inline styles remaining, 100% compliant).",
                        })

        if ("scanned" in line_lower or "audits" in line_lower) and ("doc" in line_lower or "target" in line_lower):
            match = re.search(r"(?:scanned|audits)\s+\*?\*?(\d+)\*?\*?\s+(?:bounded\s+)?(?:PageIndex\s+)?(?:target\s+)?(?:documentation\s+)?(?:target\s+)?documents?", line, re.IGNORECASE)
            if match:
                claimed_count = int(match.group(1))
                if claimed_count != total_scanned_count and "agent_work_lineage_ledger.md" not in rel_path and "full_repo_oss_swarm_review_dossier.md" not in rel_path:
                    doc_tree["findings"].append({
                        "line": idx,
                        "type": "STALE_COUNT_CLAIM",
                        "category": "pageindex_scope",
                        "section": current_section,
                        "text": line.strip(),
                        "reason": f"Claims PageIndex scanned {claimed_count} docs, contradicting current PageIndex target set count of {total_scanned_count}.",
                    })

        if "[committed HEAD]" in line:
            links = re.findall(r"\[([^\]]+)\]\(([^)]+)\)", line)
            code_span_targets = []
            for code_target in re.findall(r"`([^`]+)`", line):
                if "/" in code_target or "\\" in code_target or re.search(r"\.(?:js|mjs|py|md|sol|circom|json|sql|yml)$", code_target):
                    code_span_targets.append(code_target)
            if not links:
                links = [(target, target) for target in code_span_targets]
            for _link_text, link_target in links:
                target_path = link_target.replace("file:///", "").replace("file://", "").replace("%20", " ")
                repo_root_norm = REPO_ROOT.replace("\\", "/")
                target_norm = target_path.replace("\\", "/")

                if target_norm.lower().startswith(repo_root_norm.lower()):
                    rel_target = target_norm[len(repo_root_norm):].lstrip("/")
                else:
                    rel_target = target_norm.lstrip("/")

                is_dirty = False
                dirty_reason = ""
                for git_p, git_code in git_status_map.items():
                    if git_p == rel_target or git_p.startswith(rel_target.rstrip("/") + "/"):
                        is_dirty = True
                        dirty_reason = f"git status '{git_code}' ({git_p})"
                        break

                if is_dirty:
                    doc_tree["findings"].append({
                        "line": idx,
                        "type": "FRESHNESS_LABEL_MISMATCH",
                        "category": "freshness_label",
                        "section": current_section,
                        "text": line.strip(),
                        "reason": f"Claims [committed HEAD] for '{rel_target}', but file is dirty/untracked in working tree ({dirty_reason}).",
                    })

    return doc_tree


def keyword_set(question, lane):
    terms = {
        "zk",
        "nullifier",
        "replay",
        "identity",
        "leak",
        "privacy",
        "unlink",
        "credential",
        "membership",
        "round",
        "project",
        "domain",
        "vote",
        "verifier",
        "root",
    }
    for token in re.findall(r"[A-Za-z0-9_]+", f"{question} {lane}".lower()):
        if len(token) >= 4:
            terms.add(token)
    return terms


def merge_ranges(ranges):
    if not ranges:
        return []
    ranges = sorted(ranges)
    merged = [list(ranges[0])]
    for start, end in ranges[1:]:
        last = merged[-1]
        if start <= last[1] + 1:
            last[1] = max(last[1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


def line_numbered(lines, start_line):
    return "".join(f"{start_line + offset}: {line}" for offset, line in enumerate(lines))


def build_file_snippets(rel_path, question, lane, per_file_char_budget):
    lines = read_lines(rel_path)
    joined = "".join(lines)
    total_chars = len(joined)
    line_count = len(lines)

    if total_chars <= per_file_char_budget:
        return [{
            "start_line": 1,
            "end_line": line_count,
            "line_count": line_count,
            "char_count": total_chars,
            "content": line_numbered(lines, 1),
        }]

    terms = keyword_set(question, lane)
    ranges = []
    for index, line in enumerate(lines, 1):
        lower_line = line.lower()
        if any(term in lower_line for term in terms):
            ranges.append((max(1, index - 6), min(line_count, index + 6)))

    if not ranges:
        ranges = [(1, min(line_count, 80))]

    snippets = []
    used_chars = 0
    for start, end in merge_ranges(ranges):
        snippet_lines = lines[start - 1:end]
        content = line_numbered(snippet_lines, start)
        if used_chars + len(content) > per_file_char_budget and snippets:
            break
        if len(content) > per_file_char_budget:
            max_chars = max(1200, per_file_char_budget - used_chars)
            content = content[:max_chars].rstrip() + "\n[TRUNCATED]\n"
            end = min(end, start + content.count("\n"))
        snippets.append({
            "start_line": start,
            "end_line": end,
            "line_count": max(0, end - start + 1),
            "char_count": len(content),
            "content": content,
        })
        used_chars += len(content)
        if used_chars >= per_file_char_budget:
            break

    return snippets


def classify_disclosure(files, git_status_map):
    dirty_files = [rel for rel in files if rel in git_status_map]
    if dirty_files:
        return "LOCAL_CODE_DIRTY"
    return "PUBLIC_COMMITTED"


def relevant_lineage_entries(entries, question, lane, files):
    haystack_terms = keyword_set(question, lane)
    file_terms = {os.path.basename(path).lower() for path in files}
    selected = []
    for entry in entries:
        text = " ".join([
            entry.get("title", ""),
            entry.get("entry_id", ""),
            entry.get("source_claim", ""),
            entry.get("human_readable_claim", ""),
            entry.get("implied_claim", ""),
            entry.get("actual_proof", ""),
            entry.get("evidence", ""),
            " ".join(entry.get("dependent_artifacts", [])),
        ]).lower()
        if any(term in text for term in haystack_terms) or any(term in text for term in file_terms):
            selected.append({key: entry[key] for key in [
                "number",
                "title",
                "entry_id",
                "source_claim",
                "human_readable_claim",
                "implied_claim",
                "actual_proof",
                "evidence",
                "status",
                "assessment",
                "dependent_artifacts",
                "invalidation_criteria",
            ]})
    return selected


def sha256_file(rel_path):
    digest = hashlib.sha256()
    with open(os.path.join(REPO_ROOT, rel_path), "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def packet_files_from_args(args):
    if args.files:
        raw_files = []
        for item in args.files:
            raw_files.extend(part for part in item.split(",") if part.strip())
    else:
        raw_files = FIRST_PACKET_FILES

    files = []
    missing = []
    for raw in raw_files:
        rel_path = safe_relpath(raw)
        if os.path.exists(os.path.join(REPO_ROOT, rel_path)):
            files.append(rel_path)
        else:
            missing.append(rel_path)

    return files, missing


def compile_packet(args):
    git_status_map = get_git_status_map()
    current_branch = run_git(["branch", "--show-current"])
    lineage_entries = parse_lineage_ledger()
    write_lineage_benchmark(lineage_entries)

    files, missing_files = packet_files_from_args(args)
    if not files:
        raise SystemExit("No existing files available for packet compilation.")

    budget_tokens = max(2000, int(args.budget))
    per_file_budget = max(1600, int((budget_tokens * 4 * 0.72) / max(1, len(files))))
    packet_file_entries = []
    included_chars = 0
    total_chars = 0

    for rel_path in files:
        lines = read_lines(rel_path)
        char_count = len("".join(lines))
        total_chars += char_count
        snippets = build_file_snippets(rel_path, args.question, args.lane, per_file_budget)
        snippet_chars = sum(snippet["char_count"] for snippet in snippets)
        included_chars += snippet_chars
        packet_file_entries.append({
            "path": rel_path,
            "freshness_label": "[dirty working tree]" if rel_path in git_status_map else "[committed HEAD]",
            "git_status": git_status_map.get(rel_path, "CLEAN"),
            "sha256": sha256_file(rel_path),
            "line_count": len(lines),
            "char_count": char_count,
            "estimated_total_tokens": math.ceil(char_count / 4),
            "included_snippet_count": len(snippets),
            "included_char_count": snippet_chars,
            "content_truncated": snippet_chars < char_count,
            "snippets": snippets,
        })

    disclosure_class = classify_disclosure(files, git_status_map)
    relevant_entries = relevant_lineage_entries(lineage_entries, args.question, args.lane, files)

    output_rel = safe_relpath(args.out)
    output_abs = os.path.join(REPO_ROOT, output_rel)
    os.makedirs(os.path.dirname(output_abs), exist_ok=True)

    packet = {
        "schema_version": "pbm-review-packet/v0.1",
        "packet_id": os.path.splitext(os.path.basename(output_rel))[0],
        "generated_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "repo_root": REPO_ROOT,
        "question": args.question,
        "lane": args.lane,
        "budget_tokens": budget_tokens,
        "estimated_source_tokens": math.ceil(total_chars / 4),
        "estimated_packet_tokens": math.ceil(included_chars / 4),
        "disclosure_class": disclosure_class,
        "freshness_labels": FRESHNESS_LABELS,
        "forbidden_inputs": PACKET_FORBIDDEN_INPUTS,
        "known_boundaries": PACKET_KNOWN_BOUNDARIES,
        "review_instructions": [
            "Treat this packet as evidence plus claims, not as protocol truth.",
            "Return file/path and line-anchored findings only.",
            "Classify each finding as confirmed defect, design risk, stale claim, needs verification, or false/unsupported.",
            "Do not propose edits that require governance, signing, deployment, funds movement, live endpoints, credentials, or secret material.",
        ],
        "tests_to_run": DEFAULT_TESTS_TO_RUN,
        "source_snapshot": {
            "branch": run_git(["branch", "--show-current"], default="UNKNOWN"),
            "head": run_git(["rev-parse", "HEAD"], default="UNKNOWN"),
            "git_status_short": run_git(["status", "--short"], default=""),
        },
        "output_paths": {
            "packet": output_rel,
            "lineage_benchmark": os.path.relpath(LINEAGE_BENCHMARK_JSONL, REPO_ROOT).replace("\\", "/"),
            "router_metadata_template": f"reviews/{args.lane}-packet-router-metadata.json",
            "review_output_template": f"reviews/{args.lane}-packet-review.md",
        },
        "missing_files": missing_files,
        "lineage_entries": relevant_entries,
        "files": packet_file_entries,
    }

    with open(output_abs, "w", encoding="utf-8") as f:
        json.dump(packet, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print("==================================================")
    print("PBM REVIEW OBSERVATORY PACKET COMPILER")
    print("==================================================")
    print(f"* Question: {args.question}")
    print(f"* Lane: {args.lane}")
    print(f"* Files Included: {len(files)}")
    print(f"* Disclosure Class: {disclosure_class}")
    print(f"* Estimated Packet Tokens: {packet['estimated_packet_tokens']} / {budget_tokens}")
    print(f"* Relevant Lineage Entries: {len(relevant_entries)}")
    print(f"* Packet Written: {output_rel}")
    print(f"* Lineage Benchmark Written: {os.path.relpath(LINEAGE_BENCHMARK_JSONL, REPO_ROOT)}")
    if missing_files:
        print(f"* Missing Files Skipped: {', '.join(missing_files)}")
    print("==================================================")


def run_indexer():
    print("==================================================")
    print("PAGEINDEX DOSSIER TREE INDEXER & STATUS AUDITOR")
    print("==================================================")

    git_status_map = get_git_status_map()
    current_branch = run_git(["branch", "--show-current"], default="")
    lineage_entries = parse_lineage_ledger()
    write_lineage_benchmark(lineage_entries)
    print(f"* Verified Lineage Entries Loaded: {len(lineage_entries)}")
    print(f"* Git Working Tree Dirty/Untracked Files Detected: {len(git_status_map)}")

    files_to_scan = list(TARGET_DOCS)

    all_trees = []
    total_findings = 0
    stale_findings = []

    for rel_p in files_to_scan:
        tree = scan_document(rel_p, git_status_map, len(files_to_scan), current_branch)
        if tree:
            all_trees.append(tree)
            if tree["findings"]:
                total_findings += len(tree["findings"])
                for finding in tree["findings"]:
                    stale_findings.append({
                        "file": tree["file"],
                        "line": finding["line"],
                        "category": finding["category"],
                        "text": finding["text"],
                        "reason": finding["reason"],
                    })

    os.makedirs(CACHE_DIR, exist_ok=True)
    out_payload = {
        "repo_root": REPO_ROOT,
        "verified_ground_truth": VERIFIED_STATE,
        "lineage_entries_count": len(lineage_entries),
        "scanned_documents_count": len(all_trees),
        "total_contradictions_found": total_findings,
        "contradictions": stale_findings,
        "trees": all_trees,
        "output_paths": {
            "dossier_tree_index": os.path.relpath(OUTPUT_JSON, REPO_ROOT).replace("\\", "/"),
            "lineage_eval_benchmark": os.path.relpath(LINEAGE_BENCHMARK_JSONL, REPO_ROOT).replace("\\", "/"),
        },
    }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(out_payload, f, indent=2)

    print(f"* Documents Scanned (PageIndex Target Set): {len(all_trees)}")
    print(f"* Contradictory / Stale / Mismatched Claims Identified: {total_findings}")
    print(f"* Dossier Tree Index Written: {os.path.relpath(OUTPUT_JSON, REPO_ROOT)}")
    print(f"* Lineage Benchmark Written: {os.path.relpath(LINEAGE_BENCHMARK_JSONL, REPO_ROOT)}")
    print("==================================================")

    if stale_findings:
        print("\n[STALE / CONTRADICTORY / MISMATCHED STATUS CLAIMS DETECTED]\n")
        for idx, item in enumerate(stale_findings, 1):
            print(f"  {idx}. [{item['category'].upper()}] {item['file']}:L{item['line']}")
            print(f"     Snippet: \"{item['text']}\"")
            print(f"     Reason:  {item['reason']}\n")
        sys.exit(1)

    print("\n[OK] All document status claims & freshness labels are verified against Git truth.")
    sys.exit(0)


def parse_args():
    parser = argparse.ArgumentParser(description="PageIndex scanner and PBM Review Observatory packet compiler")
    parser.add_argument("--mode", choices=["index", "compile-packet"], default="index")
    parser.add_argument("--question", default="")
    parser.add_argument("--lane", default="zk_privacy")
    parser.add_argument("--budget", type=int, default=12000)
    parser.add_argument("--out", default="review-context/packet-zk-nullifier-replay.json")
    parser.add_argument("--files", nargs="*", help="Optional repo-relative packet files; comma-separated values are also accepted")
    return parser.parse_args()


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    args = parse_args()
    if args.mode == "compile-packet":
        if not args.question.strip():
            raise SystemExit("--question is required for --mode compile-packet")
        compile_packet(args)
    else:
        run_indexer()


if __name__ == "__main__":
    main()
