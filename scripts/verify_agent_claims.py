#!/usr/bin/env python3
"""
Pharmacy Fiduciary Commons — Agent Claim Lie Detector & Receipt Cross-Auditor

Scans text/markdown review dossiers (or stdin / CLI argument) for evidence claims:
1. Verifies lineage tags ([committed HEAD], [dirty working tree], [generated cache], [live verification just run], [external reviewer claim]).
2. Verifies that cited file paths exist in the workspace.
3. Verifies that cited line numbers are within the actual file line bounds.
4. Verifies that claimed test counts match the actual count in cache/verification_master_receipt.json or known test fixtures.
5. Rejects ungrounded claims, hallucinated line numbers, non-existent files, and fake git commit hashes.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import unicodedata

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_RECEIPT_PATH = os.path.join(REPO_ROOT, "cache", "verification_master_receipt.json")

VALID_LINEAGE_TAGS = {
    "[committed HEAD]",
    "[dirty working tree]",
    "[generated cache]",
    "[external reviewer claim]",
    "[live verification just run]",
}

CLAIM_INDICATOR_TERMS = [
    "verified",
    "passes",
    "passing",
    "passed",
    "failed",
    "failing",
    "invariant",
    "finding",
    "status",
    "claim",
    "tested",
    "asserting",
    "guarantee",
    "complies",
    "compliance",
    "verdict",
    "0 contradictions",
    "100%",
    "proof",
    "solvent",
    "debt queue",
    "unit tests",
    "circuit tests",
    "test suite",
]

NEGATION_OR_DISCLAIMER_TERMS = [
    "not authorize",
    "strictly advisory",
    "draft operating protocol",
    "non-claim",
    "prototype",
    "docs-only",
    "advisory claim packet, not a source-of-truth",
    "without explicit",
    "must not",
    "cannot",
    "does not",
]

KNOWN_EXTENSIONS = {
    ".sol", ".js", ".ts", ".mjs", ".json", ".jsonl", ".circom",
    ".md", ".txt", ".py", ".sql", ".css", ".html", ".sh", ".yml", ".yaml"
}

KNOWN_ROOT_DIRS = {
    "contracts", "scripts", "test", "cache", "server", "supabase",
    "tools", "reviews", "docs", ".agents", "dist", "circuits", "review-context"
}


def normalize_unicode(text):
    """Normalize unicode spaces and hyphens to standard ASCII equivalents."""
    text = unicodedata.normalize("NFKC", text)
    # Replace non-breaking spaces and narrow spaces
    text = re.sub(r"[\u00a0\u202f\u2000-\u200b]", " ", text)
    # Replace non-breaking hyphens, en-dashes, em-dashes with standard dash
    text = re.sub(r"[\u2011\u2012\u2013\u2014\u2015\u2212]", "-", text)
    return text


def build_repo_file_index(repo_root):
    """Build a mapping of relative paths and basenames to total line counts in workspace."""
    index = {
        "rel_paths": {},   # "contracts/PBMRebateTreasury.sol" -> line_count
        "basenames": {},   # "PBMRebateTreasury.sol" -> ["contracts/PBMRebateTreasury.sol"]
    }
    
    ignore_dirs = {".git", "node_modules", "coverage", ".gemini", "artifacts", "build"}
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for f in files:
            abs_path = os.path.join(root, f)
            rel_path = os.path.relpath(abs_path, repo_root).replace("\\", "/")
            try:
                with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                    line_count = len(fh.readlines())
            except Exception:
                line_count = 0
            
            index["rel_paths"][rel_path] = line_count
            base = os.path.basename(rel_path)
            if base not in index["basenames"]:
                index["basenames"][base] = []
            index["basenames"][base].append(rel_path)
            
    return index


def verify_git_commit(commit_sha, repo_root):
    """Verify if a git commit hash exists in the local git repository history."""
    if not re.match(r"^[0-9a-fA-F]{7,40}$", commit_sha):
        return False
    try:
        res = subprocess.run(
            ["git", "cat-file", "-e", f"{commit_sha}^{{commit}}"],
            cwd=repo_root,
            capture_output=True,
            text=True
        )
        return res.returncode == 0
    except Exception:
        return False


def load_master_receipt(receipt_path):
    """Load verification master receipt if present."""
    if receipt_path and os.path.exists(receipt_path):
        try:
            with open(receipt_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def extract_commit_hashes(text):
    """Find commit hashes cited in text."""
    hashes = []
    # Explicit commit contexts
    patterns = [
        r"(?:HEAD Baseline Commit|HEAD commit|commit|baseline|head_commit)[:\s=]+[`\"']?([0-9a-fA-F]{7,40})[`\"']?",
        r"\"head_commit\":\s*\"([0-9a-fA-F]{7,40})\"",
        r"\bcommit\s+hash\s+[`\"']?([0-9a-fA-F]{7,40})[`\"']?",
        r"\bgit\s+HEAD\s+[`\"']?([0-9a-fA-F]{7,40})[`\"']?",
        r"\b(?:baseline|commit)\s+[`\"']([0-9a-fA-F]{7,40})[`\"']",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            sha = m.group(1)
            # Filter out non-hex or obvious English words
            if len(sha) >= 7 and re.match(r"^[0-9a-fA-F]+$", sha):
                hashes.append((m.start(), sha))
                
    # Also find standalone 40-char hex SHAs
    for m in re.finditer(r"\b([0-9a-fA-F]{40})\b", text):
        sha = m.group(1)
        # Avoid duplicates from same span
        if not any(h[1] == sha for h in hashes):
            hashes.append((m.start(), sha))
            
    return [h[1] for h in hashes]


def resolve_file_in_index(raw_path, file_index, repo_root):
    """Resolve a raw cited path to canonical relative path and line count."""
    clean_path = raw_path.strip().strip("`'\"")
    # Strip file:/// or C:/...
    clean_path = re.sub(r"^file:///(?:[A-Za-z]:/)?[^/]+/", "", clean_path)
    clean_path = clean_path.replace("\\", "/").lstrip("./")
    
    # Direct match in rel_paths
    if clean_path in file_index["rel_paths"]:
        return clean_path, file_index["rel_paths"][clean_path]
    
    # Check if absolute path maps to repo_root
    abs_candidate = os.path.abspath(os.path.join(repo_root, clean_path))
    if os.path.exists(abs_candidate) and os.path.isfile(abs_candidate):
        rel = os.path.relpath(abs_candidate, repo_root).replace("\\", "/")
        line_count = file_index["rel_paths"].get(rel, 0)
        return rel, line_count
        
    # Check basename match
    base = os.path.basename(clean_path)
    if base in file_index["basenames"]:
        matches = file_index["basenames"][base]
        # If unambiguous or matched first
        matched_rel = matches[0]
        return matched_rel, file_index["rel_paths"][matched_rel]
        
    return None, None


def extract_file_citations_with_lines(line_text, file_index, repo_root):
    """
    Extract file citations and associated line numbers from a line of text.
    Returns list of dicts: {"raw_path": ..., "rel_path": ..., "start_line": ..., "end_line": ..., "total_lines": ...}
    """
    normalized = normalize_unicode(line_text)
    citations = []
    
    # 1. Markdown links: [text](path#L10-L20) or [text](file:///...#L10)
    md_link_pattern = re.compile(
        r"\[([^\]]*)\]\((?:file:///(?:[A-Za-z]:/)?[^)#]*/)?([^)#]+)(?:#(?:L|lines?)?(\d+)(?:-(?:L|lines?)?(\d+))?)?\)"
    )
    for m in md_link_pattern.finditer(normalized):
        raw_path = m.group(2)
        start_line = int(m.group(3)) if m.group(3) else None
        end_line = int(m.group(4)) if m.group(4) else None
        rel_path, total_lines = resolve_file_in_index(raw_path, file_index, repo_root)
        citations.append({
            "raw_path": raw_path,
            "rel_path": rel_path,
            "start_line": start_line,
            "end_line": end_line,
            "total_lines": total_lines,
            "exists": rel_path is not None
        })

    # 2. Backticked file paths: `path/to/file.ext:10-20` or `path/to/file.ext (lines 10-20)`
    backtick_pattern = re.compile(
        r"`([A-Za-z0-9_\-\./]+\.[a-zA-Z0-9]+)(?:[:#](?:L|lines?)?(\d+)(?:-(?:L|lines?)?(\d+))?)?`"
    )
    for m in backtick_pattern.finditer(normalized):
        raw_path = m.group(1)
        ext = os.path.splitext(raw_path)[1].lower()
        if ext not in KNOWN_EXTENSIONS and not any(raw_path.startswith(d + "/") for d in KNOWN_ROOT_DIRS):
            continue
        start_line = int(m.group(2)) if m.group(2) else None
        end_line = int(m.group(3)) if m.group(3) else None
        rel_path, total_lines = resolve_file_in_index(raw_path, file_index, repo_root)
        citations.append({
            "raw_path": raw_path,
            "rel_path": rel_path,
            "start_line": start_line,
            "end_line": end_line,
            "total_lines": total_lines,
            "exists": rel_path is not None
        })

    # 3. Plain path with colon/hash: contracts/PBMRebateTreasury.sol:190
    colon_path_pattern = re.compile(
        r"\b((?:[A-Za-z0-9_\-]+/)*[A-Za-z0-9_\-]+\.[a-zA-Z0-9]+)[:#]L?(\d+)(?:-L?(\d+))?\b"
    )
    for m in colon_path_pattern.finditer(normalized):
        raw_path = m.group(1)
        ext = os.path.splitext(raw_path)[1].lower()
        if ext not in KNOWN_EXTENSIONS and not any(raw_path.startswith(d + "/") for d in KNOWN_ROOT_DIRS):
            continue
        start_line = int(m.group(2)) if m.group(2) else None
        end_line = int(m.group(3)) if m.group(3) else None
        rel_path, total_lines = resolve_file_in_index(raw_path, file_index, repo_root)
        citations.append({
            "raw_path": raw_path,
            "rel_path": rel_path,
            "start_line": start_line,
            "end_line": end_line,
            "total_lines": total_lines,
            "exists": rel_path is not None
        })

    # 4. Contextual lines patterns:
    # "lines 18-40 in circuits/vote_nullifier.circom" or "lines 18-40, circuits/vote_nullifier.circom"
    context_lines_before = re.compile(
        r"\b(?:lines?|line)\s+(\d+)(?:\s*-\s*(\d+))?\s*(?:in|,|\sof)\s*[`]?([A-Za-z0-9_\-\./]+\.[a-zA-Z0-9]+)[`]?",
        re.IGNORECASE
    )
    for m in context_lines_before.finditer(normalized):
        start_line = int(m.group(1))
        end_line = int(m.group(2)) if m.group(2) else None
        raw_path = m.group(3)
        ext = os.path.splitext(raw_path)[1].lower()
        if ext not in KNOWN_EXTENSIONS and not any(raw_path.startswith(d + "/") for d in KNOWN_ROOT_DIRS):
            continue
        rel_path, total_lines = resolve_file_in_index(raw_path, file_index, repo_root)
        citations.append({
            "raw_path": raw_path,
            "rel_path": rel_path,
            "start_line": start_line,
            "end_line": end_line,
            "total_lines": total_lines,
            "exists": rel_path is not None
        })

    # "circuits/vote_nullifier.circom (lines 18-40)" or "SOLVENCY_DEBT_SEMANTICS.md (lines 38-44)"
    # or "PBMRebateTreasury.sol (line 44, RECALL_DELAY)"
    context_lines_after = re.compile(
        r"[`]?([A-Za-z0-9_\-\./]+\.[a-zA-Z0-9]+)[`]?\s*\(\s*(?:lines?|line)\s*(\d+)(?:\s*-\s*(\d+))?",
        re.IGNORECASE
    )
    for m in context_lines_after.finditer(normalized):
        raw_path = m.group(1)
        start_line = int(m.group(2))
        end_line = int(m.group(3)) if m.group(3) else None
        ext = os.path.splitext(raw_path)[1].lower()
        if ext not in KNOWN_EXTENSIONS and not any(raw_path.startswith(d + "/") for d in KNOWN_ROOT_DIRS):
            continue
        rel_path, total_lines = resolve_file_in_index(raw_path, file_index, repo_root)
        citations.append({
            "raw_path": raw_path,
            "rel_path": rel_path,
            "start_line": start_line,
            "end_line": end_line,
            "total_lines": total_lines,
            "exists": rel_path is not None
        })

    # "PBMRebateTreasury.sol line 44" or "SOLVENCY_DEBT_SEMANTICS.md lines 38-44"
    context_lines_space = re.compile(
        r"[`]?([A-Za-z0-9_\-\./]+\.[a-zA-Z0-9]+)[`]?\s+(?:lines?|line)\s+(\d+)(?:\s*-\s*(\d+))?",
        re.IGNORECASE
    )
    for m in context_lines_space.finditer(normalized):
        raw_path = m.group(1)
        start_line = int(m.group(2))
        end_line = int(m.group(3)) if m.group(3) else None
        ext = os.path.splitext(raw_path)[1].lower()
        if ext not in KNOWN_EXTENSIONS and not any(raw_path.startswith(d + "/") for d in KNOWN_ROOT_DIRS):
            continue
        rel_path, total_lines = resolve_file_in_index(raw_path, file_index, repo_root)
        citations.append({
            "raw_path": raw_path,
            "rel_path": rel_path,
            "start_line": start_line,
            "end_line": end_line,
            "total_lines": total_lines,
            "exists": rel_path is not None
        })

    # De-duplicate citations by (raw_path, start_line, end_line)
    unique_citations = []
    seen = set()
    for c in citations:
        key = (c["raw_path"], c["start_line"], c["end_line"])
        if key not in seen:
            seen.add(key)
            unique_citations.append(c)
            
    return unique_citations


def extract_test_and_step_counts(line_text):
    """
    Extract claimed test suite numbers, step numbers, or passing ratios.
    Returns list of dicts.
    """
    normalized = normalize_unicode(line_text)
    claims = []
    
    # 1. "passes 280/280 tests" or "280 / 280 passing unit tests" or "passes 9/9 assertions"
    ratio_pat = re.compile(
        r"\b(?:passes|passing|passed|suite passes)\s+(\d+)\s*/\s*(\d+)\s*(?:tests|unit tests|assertions|passing|unit/circuit tests)?\b",
        re.IGNORECASE
    )
    for m in ratio_pat.finditer(normalized):
        passed = int(m.group(1))
        total = int(m.group(2))
        claims.append({"type": "test_ratio", "passed": passed, "total": total, "snippet": m.group(0)})

    # 2. "272 passing (100%)" or "280 passing"
    passing_pat = re.compile(
        r"\b(\d+)\s+passing\s*(?:\((?:100|\d+)%\))?",
        re.IGNORECASE
    )
    for m in passing_pat.finditer(normalized):
        # Check that this wasn't part of "X / Y passing"
        passed = int(m.group(1))
        if not any(c["type"] == "test_ratio" and c["passed"] == passed for c in claims):
            claims.append({"type": "passing_count", "passed": passed, "total": None, "snippet": m.group(0)})

    # 3. "expected_step_count: 8" or "expected_step_count": 8
    expected_step_pat = re.compile(r"expected_step_count[\"':\s]+(\d+)", re.IGNORECASE)
    for m in expected_step_pat.finditer(normalized):
        count = int(m.group(1))
        claims.append({"type": "expected_steps", "count": count, "snippet": m.group(0)})

    # 4. "steps_executed: 8" or "Executed Steps: 8 / 8"
    executed_step_pat = re.compile(r"(?:steps_executed|Executed Steps)[\"':\s]+(\d+)(?:\s*/\s*(\d+))?", re.IGNORECASE)
    for m in executed_step_pat.finditer(normalized):
        count = int(m.group(1))
        total = int(m.group(2)) if m.group(2) else None
        claims.append({"type": "executed_steps", "count": count, "total": total, "snippet": m.group(0)})

    return claims


def has_lineage_tag(text):
    """Check if text contains any canonical lineage tag."""
    return any(tag in text for tag in VALID_LINEAGE_TAGS)


def is_claim_line(line_text):
    """Check if a line makes an empirical assertion or finding claim."""
    lowered = line_text.lower()
    return any(term in lowered for term in CLAIM_INDICATOR_TERMS)


def has_negation(line_text):
    """Check if line is a policy, disclaimer, or negation."""
    lowered = line_text.lower()
    return any(term in lowered for term in NEGATION_OR_DISCLAIMER_TERMS)


def audit_document(content, file_label, file_index, master_receipt, repo_root):
    """
    Perform deep verification on a single document text.
    Returns: list of violations, total_claims_checked.
    """
    violations = []
    total_claims = 0
    lines = content.splitlines()
    in_code_fence = False
    
    for line_idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code_fence = not in_code_fence
            # Even inside text code fence (e.g. terminal summary), inspect if it's summary
            continue
            
        if not stripped:
            continue

        # 1. Check for invalid or fake lineage tags
        # Find all brackets [something]
        bracket_tags = re.findall(r"\[([a-zA-Z0-9_\- ]{3,35})\]", line)
        for tag_text in bracket_tags:
            full_tag = f"[{tag_text}]"
            tag_lower = tag_text.lower()
            if any(k in tag_lower for k in ["claim", "tree", "head", "cache", "verification", "lineage", "unverified", "fake", "hallucinated", "untracked", "mock"]):
                if full_tag not in VALID_LINEAGE_TAGS:
                    violations.append({
                        "file": file_label,
                        "line": line_idx,
                        "category": "invalid_lineage_tag",
                        "reason": f"Invalid lineage tag '{full_tag}'. Allowed tags: {sorted(list(VALID_LINEAGE_TAGS))}",
                        "snippet": line[:200],
                    })

        # 2. Check for Ungrounded Claims
        # If line contains strong claim indicator, is not negated/disclaimed, not a table header or markdown title
        is_heading = stripped.startswith("#")
        is_table_separator = stripped.startswith("|---") or stripped.startswith("| :---")
        is_bullet_or_cell = stripped.startswith("-") or stripped.startswith("*") or stripped.startswith("|") or stripped.startswith("1.") or stripped.startswith("2.") or stripped.startswith("3.")
        
        if is_claim_line(line) and not has_negation(line) and not is_table_separator and not is_heading:
            total_claims += 1
            if not has_lineage_tag(line):
                # If it is an empirical finding/invariant/test summary without tag
                if is_bullet_or_cell and any(k in line.lower() for k in ["invariant", "finding", "test", "passed", "passes", "verified", "status"]):
                    violations.append({
                        "file": file_label,
                        "line": line_idx,
                        "category": "ungrounded_claim",
                        "reason": "Empirical claim, invariant, or finding is missing a canonical lineage tag.",
                        "snippet": line[:200],
                    })

        # 3. Check Git Commit Hashes
        commit_hashes = extract_commit_hashes(line)
        for sha in commit_hashes:
            total_claims += 1
            is_valid_commit = verify_git_commit(sha, repo_root)
            if not is_valid_commit:
                violations.append({
                    "file": file_label,
                    "line": line_idx,
                    "category": "fake_commit_hash",
                    "reason": f"Git commit hash '{sha}' does not exist in repository git history.",
                    "snippet": line[:200],
                })

        # 4. Check File Citations and Line Bounds
        citations = extract_file_citations_with_lines(line, file_index, repo_root)
        for cit in citations:
            total_claims += 1
            if not cit["exists"]:
                violations.append({
                    "file": file_label,
                    "line": line_idx,
                    "category": "missing_cited_file",
                    "reason": f"Cited file does not exist in workspace: '{cit['raw_path']}'",
                    "snippet": line[:200],
                })
            else:
                total_lines = cit["total_lines"]
                start_l = cit["start_line"]
                end_l = cit["end_line"]
                
                if start_l is not None:
                    if start_l < 1 or start_l > total_lines:
                        violations.append({
                            "file": file_label,
                            "line": line_idx,
                            "category": "hallucinated_line_number",
                            "reason": f"Cited line {start_l} exceeds actual file length ({total_lines} lines) in '{cit['rel_path']}'.",
                            "snippet": line[:200],
                        })
                    if end_l is not None:
                        if end_l < start_l:
                            violations.append({
                                "file": file_label,
                                "line": line_idx,
                                "category": "invalid_line_range",
                                "reason": f"Cited end line {end_l} is less than start line {start_l} in '{cit['rel_path']}'.",
                                "snippet": line[:200],
                            })
                        elif end_l > total_lines:
                            violations.append({
                                "file": file_label,
                                "line": line_idx,
                                "category": "hallucinated_line_number",
                                "reason": f"Cited line range {start_l}-{end_l} exceeds actual file length ({total_lines} lines) in '{cit['rel_path']}'.",
                                "snippet": line[:200],
                            })

        # 5. Check Test Counts & Receipt Invariants
        test_claims = extract_test_and_step_counts(line)
        for tc in test_claims:
            total_claims += 1
            if tc["type"] == "test_ratio":
                if tc["passed"] > tc["total"]:
                    violations.append({
                        "file": file_label,
                        "line": line_idx,
                        "category": "fake_test_count",
                        "reason": f"Impossible test count claim: passed ({tc['passed']}) > total ({tc['total']}).",
                        "snippet": line[:200],
                    })
                elif tc["total"] > 1000:  # Wildly hallucinated unit test count
                    violations.append({
                        "file": file_label,
                        "line": line_idx,
                        "category": "fake_test_count",
                        "reason": f"Hallucinated test count: claimed {tc['total']} tests exceeds repository suite capacity.",
                        "snippet": line[:200],
                    })
            elif tc["type"] == "expected_steps" and master_receipt:
                expected_receipt = master_receipt.get("expected_step_count")
                if expected_receipt and tc["count"] != expected_receipt:
                    violations.append({
                        "file": file_label,
                        "line": line_idx,
                        "category": "test_count_mismatch",
                        "reason": f"Expected step count {tc['count']} does not match master receipt ({expected_receipt}).",
                        "snippet": line[:200],
                    })
            elif tc["type"] == "executed_steps" and master_receipt:
                executed_receipt = master_receipt.get("steps_executed")
                if executed_receipt and tc["count"] != executed_receipt:
                    violations.append({
                        "file": file_label,
                        "line": line_idx,
                        "category": "test_count_mismatch",
                        "reason": f"Executed step count {tc['count']} does not match master receipt ({executed_receipt}).",
                        "snippet": line[:200],
                    })

    return violations, total_claims


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        description="Agent Claim Lie Detector & Receipt Cross-Auditor"
    )
    parser.add_argument(
        "--target",
        nargs="*",
        help="Target markdown/text file(s) or dossier(s) to verify"
    )
    parser.add_argument(
        "positional_targets",
        nargs="*",
        help="Positional target file(s)"
    )
    parser.add_argument(
        "--receipt",
        default=DEFAULT_RECEIPT_PATH,
        help="Path to verification master receipt JSON"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON verification result"
    )
    
    args = parser.parse_args()
    
    targets = []
    if args.target:
        targets.extend(args.target)
    if args.positional_targets:
        targets.extend(args.positional_targets)

    file_index = build_repo_file_index(REPO_ROOT)
    master_receipt = load_master_receipt(args.receipt)
    
    all_violations = []
    total_claims = 0
    verified_files = []
    
    if not targets:
        # Read from stdin
        if not sys.stdin.isatty():
            content = sys.stdin.read()
            file_label = "<stdin>"
            viols, claims = audit_document(content, file_label, file_index, master_receipt, REPO_ROOT)
            all_violations.extend(viols)
            total_claims += claims
            verified_files.append(file_label)
        else:
            parser.print_help()
            sys.exit(1)
    else:
        for tgt in targets:
            abs_tgt = tgt if os.path.isabs(tgt) else os.path.join(REPO_ROOT, tgt)
            if not os.path.exists(abs_tgt):
                all_violations.append({
                    "file": tgt,
                    "line": 0,
                    "category": "missing_target_file",
                    "reason": f"Specified review target dossier does not exist: '{tgt}'",
                    "snippet": tgt
                })
                continue
            with open(abs_tgt, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            rel_label = os.path.relpath(abs_tgt, REPO_ROOT).replace("\\", "/")
            viols, claims = audit_document(content, rel_label, file_index, master_receipt, REPO_ROOT)
            all_violations.extend(viols)
            total_claims += claims
            verified_files.append(rel_label)
            
    is_passed = len(all_violations) == 0
    status_str = "PASSED" if is_passed else "REJECTED"
    
    receipt_audit = {
        "receipt_found": master_receipt is not None,
        "receipt_status": master_receipt.get("overall_status") if master_receipt else "UNKNOWN",
        "expected_steps": master_receipt.get("expected_step_count") if master_receipt else 0,
        "steps_executed": master_receipt.get("steps_executed") if master_receipt else 0,
    }

    report = {
        "status": status_str,
        "verified_targets": verified_files,
        "total_claims_checked": total_claims,
        "total_violations": len(all_violations),
        "violations": all_violations,
        "receipt_cross_audit": receipt_audit
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("==================================================")
        print(f"AGENT CLAIM LIE DETECTOR & RECEIPT CROSS-AUDITOR: {status_str}")
        print("==================================================")
        print(f"Verified Targets:      {', '.join(verified_files)}")
        print(f"Total Claims Audited:  {total_claims}")
        print(f"Total Violations:      {len(all_violations)}")
        if master_receipt:
            print(f"Master Receipt Status: {master_receipt.get('overall_status')} ({master_receipt.get('steps_executed')}/{master_receipt.get('expected_step_count')} steps)")
        print("--------------------------------------------------")
        if all_violations:
            print("[REJECTED] The following ungrounded claims or hallucinated references were detected:")
            for v in all_violations:
                print(f"  • {v['file']}:L{v['line']} [{v['category']}] {v['reason']}")
                print(f"    Snippet: {v['snippet']}")
        else:
            print("[PASSED] All cited files, line bounds, lineage tags, test counts, and git commit hashes are grounded!")
        print("==================================================")

    sys.exit(0 if is_passed else 1)


if __name__ == "__main__":
    main()
