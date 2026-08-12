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
DEFAULT_MODEL_ATTEMPT_LEDGER = os.path.join(REVIEWS_DIR, "model_attempt_ledger.jsonl")
MODEL_ATTEMPT_DIR = os.path.join(REVIEWS_DIR, "model_attempts")
DEFAULT_PARTIAL_RECEIPT_PATH = os.path.join(CACHE_DIR, "multimodal_harness_partial_receipt.json")

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

MODEL_EXPERIMENT_REGISTRY = [
    {
        "id": "gemma3:4b",
        "status": "available_local_user_reported",
        "suggested_lens": "local/offline sanity pass and cheap regression triage",
    },
    {
        "id": "qwen2.5-coder:7b",
        "status": "available_local_user_reported",
        "suggested_lens": "local code-path review and implementation-diff criticism",
    },
    {
        "id": "mistral",
        "status": "available_local_user_reported",
        "suggested_lens": "fast local second-opinion and regression triage",
    },
    {
        "id": "llama-audit",
        "status": "available_local_user_reported",
        "suggested_lens": "local security and audit-focused critic",
    },
    {
        "id": "deepseek-r1:1.5b",
        "status": "available_local_user_reported",
        "suggested_lens": "local small reasoning sanity pass and invariant spot-checking",
    },
    {
        "id": "deepseek-r1:7b",
        "status": "candidate_needs_local_install_confirmation",
        "suggested_lens": "reasoning model JSON adapter experiment",
    },
    {
        "id": "glm4:latest",
        "status": "available_local_user_reported",
        "suggested_lens": "local OpenAI-compatible generalist and governance synthesis pass",
    },
    {
        "id": "claude-3-7-sonnet",
        "status": "candidate",
        "suggested_lens": "governance wording calibration and overclaim detection",
    },
    {
        "id": "smaug-72b",
        "status": "candidate_needs_backend_or_route",
        "suggested_lens": "broad open-weight critic and alternate reasoning pass",
    },
    {
        "id": "x-ai/grok-2",
        "status": "candidate",
        "suggested_lens": "adversarial disagreement hunting and edge-case pressure",
    },
    {
        "id": "nvidia/nemotron-70b",
        "status": "candidate_routed_to_current_catalog_alternative",
        "suggested_lens": "structured security and enterprise risk review",
    },
    {
        "id": "deepseek-r1",
        "status": "candidate",
        "suggested_lens": "formal reasoning, invariants, and proof-step criticism",
    },
    {
        "id": "gemini-2.5-pro",
        "status": "candidate",
        "suggested_lens": "long-context synthesis, diagrams, and multimodal review",
    },
    {
        "id": "inclusion-ai",
        "status": "candidate_needs_exact_model",
        "suggested_lens": "alternate policy and stakeholder-impact lens",
    },
    {
        "id": "moonshot-k2",
        "status": "candidate_routed_to_current_catalog_alternative",
        "suggested_lens": "long-context document contradiction mining",
    },
    {
        "id": "moonshotai/kimi-k2.7-code",
        "status": "candidate",
        "suggested_lens": "Kimi code-focused review and patch critique",
    },
    {
        "id": "moonshotai/kimi-k3",
        "status": "candidate",
        "suggested_lens": "Kimi long-context synthesis and contradiction mining",
    },
    {
        "id": "moonshotai/kimi-k2-thinking",
        "status": "candidate",
        "suggested_lens": "Kimi reasoning pass for proof-step disagreement",
    },
    {
        "id": "liquid-ai/lfm-40b",
        "status": "candidate",
        "suggested_lens": "efficient generalist second-opinion pass",
    },
    {
        "id": "magic-dev",
        "status": "candidate_needs_exact_model",
        "suggested_lens": "implementation-diff proposal and code rewrite lane",
    },
    {
        "id": "minimax-abab6.5t",
        "status": "candidate_needs_exact_model",
        "suggested_lens": "planning, synthesis, and handoff clarity pass",
    },
]

MODEL_ROUTE_ALIASES = {
    "gemma3:4b": "gemma3:4b",
    "qwen2.5-coder:7b": "qwen2.5-coder:7b",
    "mistral": "mistral",
    "llama-audit": "llama-audit",
    "deepseek-r1:1.5b": "deepseek-r1:1.5b",
    "deepseek-r1:7b": "deepseek-r1:7b",
    "glm4:latest": "glm4:latest",
    "claude-3-7-sonnet": "~anthropic/claude-sonnet-latest",
    "smaug-72b": None,
    "x-ai/grok-2": "~x-ai/grok-latest",
    "nvidia/nemotron-70b": "nvidia/nemotron-3-super-120b-a12b",
    "deepseek-r1": "deepseek/deepseek-r1",
    "gemini-2.5-pro": "google/gemini-2.5-pro",
    "inclusion-ai": None,
    "moonshot-k2": "moonshotai/kimi-k2",
    "moonshotai/kimi-k2.7-code": "moonshotai/kimi-k2.7-code",
    "moonshotai/kimi-k3": "moonshotai/kimi-k3",
    "moonshotai/kimi-k2-thinking": "moonshotai/kimi-k2-thinking",
    "liquid-ai/lfm-40b": "liquid/lfm-40b",
    "magic-dev": None,
    "minimax-abab6.5t": None,
}

MODEL_REVIEW_LANE_DEFAULTS = {
    "gemma3:4b": "skeptic",
    "qwen2.5-coder:7b": "qwen_coder",
    "mistral": "free_code",
    "llama-audit": "guardrail",
    "deepseek-r1:1.5b": "deepseek_reasoner",
    "deepseek-r1:7b": "deepseek_reasoner",
    "glm4:latest": "strategist",
    "claude-3-7-sonnet": "open_claude",
    "smaug-72b": "skeptic",
    "x-ai/grok-2": "grok_council",
    "nvidia/nemotron-70b": "guardrail",
    "deepseek-r1": "deepseek_reasoner",
    "gemini-2.5-pro": "strategist",
    "moonshot-k2": "kimi_long_context",
    "moonshotai/kimi-k2.7-code": "qwen_coder",
    "moonshotai/kimi-k3": "kimi_long_context",
    "moonshotai/kimi-k2-thinking": "deepseek_reasoner",
    "liquid-ai/lfm-40b": "strategist",
    "magic-dev": "qwen_coder",
    "minimax-abab6.5t": "strategist",
    "inclusion-ai": "advocate",
}

MODEL_BACKEND_DEFAULTS = {
    "gemma3:4b": "local-openai",
    "qwen2.5-coder:7b": "local-openai",
    "mistral": "local-openai",
    "llama-audit": "local-openai",
    "deepseek-r1:1.5b": "local-openai",
    "glm4:latest": "local-openai",
    "deepseek-r1:7b": "local-openai",
}

LOCAL_FAST_MODEL_IDS = [
    "gemma3:4b",
    "qwen2.5-coder:7b",
    "llama-audit",
    "glm4:latest",
]

MODEL_EXECUTION_PROFILES = {
    "gemma3:4b": {
        "review_usable": "experimental",
        "json_reliability": "unknown",
        "expected_latency_band": "local_cpu_medium",
        "preferred_lens": "cheap regression triage and sanity review",
        "avoid_for": "long-context whole-repo synthesis",
    },
    "qwen2.5-coder:7b": {
        "review_usable": "experimental",
        "json_reliability": "unknown",
        "expected_latency_band": "local_cpu_medium",
        "preferred_lens": "code-path review and patch criticism",
        "avoid_for": "governance prose calibration",
    },
    "mistral": {
        "review_usable": "experimental",
        "json_reliability": "unknown",
        "expected_latency_band": "local_cpu_fast",
        "preferred_lens": "fast second-opinion triage",
        "avoid_for": "formal invariant proof",
    },
    "llama-audit": {
        "review_usable": "experimental",
        "json_reliability": "unknown",
        "expected_latency_band": "local_cpu_medium",
        "preferred_lens": "security/audit critique",
        "avoid_for": "large packet synthesis",
    },
    "deepseek-r1:1.5b": {
        "review_usable": "callable_but_not_review_usable_until_json_proven",
        "json_reliability": "experimental_low",
        "expected_latency_band": "local_cpu_medium",
        "preferred_lens": "small reasoning spot-check",
        "avoid_for": "structured council quorum until adapter passes",
    },
    "deepseek-r1:7b": {
        "review_usable": "candidate_needs_local_install_confirmation",
        "json_reliability": "experimental_low",
        "expected_latency_band": "local_cpu_slow",
        "preferred_lens": "reasoning adapter experiment",
        "avoid_for": "routine review loop until two valid JSON trials pass",
    },
    "glm4:latest": {
        "review_usable": "experimental",
        "json_reliability": "user_reported_usable_content",
        "expected_latency_band": "local_cpu_medium",
        "preferred_lens": "generalist synthesis and governance review",
        "avoid_for": "proof-heavy contract invariants without verifier",
    },
    "openrouter/free": {
        "review_usable": "yes_with_reconciliation",
        "json_reliability": "not_required",
        "expected_latency_band": "cloud_slow_free",
        "preferred_lens": "free fallback disagreement mining",
        "avoid_for": "latency-sensitive local council loops",
    },
}

DEFAULT_EXECUTION_PROFILE = {
    "review_usable": "unknown",
    "json_reliability": "unknown",
    "expected_latency_band": "unknown",
    "preferred_lens": "operator-supplied ad hoc model",
    "avoid_for": "unprofiled routing decisions",
}

BOUNDARY_RULES = [
    "Review and verification only.",
    "No source edits are performed by this harness.",
    "No staging, commits, pushes, branches, deploys, signing, fund movement, or role changes.",
    "External reviewer dispatch is disabled unless --run-reviewers and exact --approve-disclosure are supplied.",
    "External model attempts are disabled unless --attempt-models uses --model-backend openrouter and exact --approve-disclosure is supplied.",
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
            encoding="utf-8",
            errors="replace",
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


def slugify_model_id(model_id):
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", model_id).strip("_")
    return slug or "model"


def registry_entry_for_model(model_id):
    for entry in MODEL_EXPERIMENT_REGISTRY:
        if entry["id"] == model_id:
            return entry
    return {
        "id": model_id,
        "status": "ad_hoc",
        "suggested_lens": "operator-supplied ad hoc model",
    }


def execution_profile_for_model(model_id):
    profile = dict(DEFAULT_EXECUTION_PROFILE)
    profile.update(MODEL_EXECUTION_PROFILES.get(model_id, {}))
    return profile


def model_registry_with_profiles():
    result = []
    for entry in MODEL_EXPERIMENT_REGISTRY:
        enriched = dict(entry)
        enriched["execution_profile"] = execution_profile_for_model(entry["id"])
        result.append(enriched)
    return result


def backend_for_model(args, model_id):
    if args.model_backend != "auto":
        return args.model_backend
    return MODEL_BACKEND_DEFAULTS.get(model_id, "openrouter")


def review_lane_for_model(args, model_id):
    return args.attempt_role or MODEL_REVIEW_LANE_DEFAULTS.get(model_id, "skeptic")


def routed_model_id(model_id):
    return MODEL_ROUTE_ALIASES.get(model_id, model_id)


def append_jsonl(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False))
        f.write("\n")


def read_json_if_exists(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        return {"metadata_read_error": str(exc)}


def extract_json_object_text(text):
    clean = re.sub(r"<think>.*?</think>", "", text, flags=re.I | re.S).strip()
    if clean.startswith("```"):
        clean = re.sub(r"^```(?:json)?", "", clean, flags=re.I).strip()
        clean = re.sub(r"```$", "", clean).strip()
    if clean.startswith("{") and clean.endswith("}"):
        return clean
    start = clean.find("{")
    end = clean.rfind("}")
    if start >= 0 and end > start:
        return clean[start:end + 1]
    return clean


def parse_review_json_output(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    return json.loads(extract_json_object_text(raw))


def validate_review_json_output(path, max_findings=None):
    if not os.path.exists(path):
        return {
            "json_valid": False,
            "json_error": "output_file_missing",
            "json_finding_count": 0,
        }
    try:
        payload = parse_review_json_output(path)
    except Exception as exc:
        return {
            "json_valid": False,
            "json_error": str(exc)[:500],
            "json_finding_count": 0,
        }
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return {
            "json_valid": False,
            "json_error": "missing_findings_array",
            "json_finding_count": 0,
        }
    if max_findings is not None and len(findings) > max_findings:
        return {
            "json_valid": False,
            "json_error": f"too_many_findings:{len(findings)}>{max_findings}",
            "json_finding_count": len(findings),
        }
    return {
        "json_valid": True,
        "json_error": None,
        "json_finding_count": len(findings),
    }


LINE_RANGE_PATTERNS = [
    re.compile(r"\b(?:line|lines|l)\s*[:#]?\s*(\d{1,6})(?:\s*[-–]\s*(\d{1,6}))?\b", re.I),
    re.compile(r":(\d{1,6})(?:\s*[-–]\s*(\d{1,6}))?\b"),
]

IDENTIFIER_STOPWORDS = {
    "and", "are", "but", "can", "cannot", "claim", "code", "contract", "critical",
    "defect", "design", "evidence", "file", "finding", "function", "high", "issue",
    "line", "lines", "low", "medium", "missing", "next", "packet", "path", "risk",
    "sol", "step", "test", "the", "this", "with",
}


def packet_quality_context(packet_path):
    packet_abs = safe_repo_path(packet_path)
    with open(packet_abs, "r", encoding="utf-8") as f:
        packet = json.load(f)
    files = {}
    for item in packet.get("files", []):
        path = item.get("path")
        content = item.get("content")
        if not path or not isinstance(content, str):
            continue
        lines = content.splitlines()
        files[path] = {
            "line_count": len(lines),
            "lines": lines,
            "content": content,
            "path_terms": set(re.split(r"[^A-Za-z0-9_]+", path)),
        }
    return {
        "packet_id": packet.get("packet_id"),
        "files": files,
    }


def normalize_path_text(text):
    return (text or "").replace("\\", "/")


def finding_text_blob(finding):
    fields = [
        finding.get("claim"),
        finding.get("evidence"),
        finding.get("evidence_path"),
        finding.get("evidence_lines"),
        finding.get("recommended_next_step"),
    ]
    return " ".join(str(item) for item in fields if item is not None)


def cited_packet_paths(finding, context):
    blob = normalize_path_text(finding_text_blob(finding))
    cited = []
    for path in context["files"]:
        if normalize_path_text(path) in blob:
            cited.append(path)
    evidence_path = normalize_path_text(str(finding.get("evidence_path") or ""))
    for path in context["files"]:
        if evidence_path and evidence_path == normalize_path_text(path) and path not in cited:
            cited.append(path)
    return cited


def extract_line_ranges(text):
    ranges = []
    for pattern in LINE_RANGE_PATTERNS:
        for match in pattern.finditer(str(text or "")):
            start = int(match.group(1))
            end = int(match.group(2) or start)
            if end < start:
                start, end = end, start
            ranges.append((start, end))
    return ranges[:5]


def important_identifiers(finding, cited_paths, context):
    blob = finding_text_blob(finding)
    backticked = re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", blob)
    candidates = backticked + re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b", blob)
    path_terms = set()
    for path in cited_paths:
        path_terms.update(term for term in context["files"].get(path, {}).get("path_terms", set()) if term)
    result = []
    for token in candidates:
        token_lower = token.lower()
        if token_lower in IDENTIFIER_STOPWORDS:
            continue
        if token in path_terms or token_lower in {term.lower() for term in path_terms}:
            continue
        # Favor symbols and contract/code identifiers over ordinary prose.
        if token not in backticked and "_" not in token and not any(ch.isupper() for ch in token[1:]):
            continue
        if token not in result:
            result.append(token)
    return result[:8]


def cited_line_excerpt(path_info, line_ranges):
    excerpts = []
    for start, end in line_ranges:
        bounded_start = max(1, start)
        bounded_end = min(path_info["line_count"], end)
        if bounded_start > bounded_end:
            continue
        excerpts.extend(path_info["lines"][bounded_start - 1:bounded_end])
    return "\n".join(excerpts)


def validate_review_quality_output(path, packet_path):
    if not os.path.exists(path):
        return {
            "quality_valid": False,
            "quality_score": 0,
            "quality_error": "output_file_missing",
            "quality_blockers": ["output_file_missing"],
            "quality_warnings": [],
            "actionable_finding_count": 0,
        }
    try:
        payload = parse_review_json_output(path)
        context = packet_quality_context(packet_path)
    except Exception as exc:
        return {
            "quality_valid": False,
            "quality_score": 0,
            "quality_error": str(exc)[:500],
            "quality_blockers": ["quality_parse_or_packet_error"],
            "quality_warnings": [],
            "actionable_finding_count": 0,
        }

    findings = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(findings, list):
        return {
            "quality_valid": False,
            "quality_score": 0,
            "quality_error": "missing_findings_array",
            "quality_blockers": ["missing_findings_array"],
            "quality_warnings": [],
            "actionable_finding_count": 0,
        }

    blockers = []
    warnings = []
    actionable_count = 0

    for idx, finding in enumerate(findings, 1):
        if not isinstance(finding, dict):
            blockers.append(f"finding_{idx}:not_an_object")
            continue
        classification = str(finding.get("classification") or "").lower()
        severity = str(finding.get("severity") or "").lower()
        evidence_text = " ".join(
            str(item)
            for item in [
                finding.get("evidence"),
                finding.get("evidence_path"),
                finding.get("evidence_lines"),
            ]
            if item is not None
        )
        cited_paths = cited_packet_paths(finding, context)
        high_risk = classification == "confirmed_defect" or severity in {"critical", "high"}
        uncertain_words = re.search(r"\b(may|might|possibly|unclear|not visible|needs verification|assumption)\b", finding_text_blob(finding), re.I)

        if not cited_paths:
            blockers.append(f"finding_{idx}:missing_packet_file_evidence")
            continue

        line_ranges = extract_line_ranges(evidence_text)
        if high_risk and not line_ranges:
            blockers.append(f"finding_{idx}:high_risk_missing_line_evidence")
        if classification == "confirmed_defect" and uncertain_words:
            blockers.append(f"finding_{idx}:confirmed_defect_uses_uncertain_language")

        identifiers = important_identifiers(finding, cited_paths, context)
        if identifiers and line_ranges:
            matched_identifier_on_cited_lines = False
            for cited_path in cited_paths:
                path_info = context["files"][cited_path]
                for start, end in line_ranges:
                    if start < 1 or end > path_info["line_count"]:
                        blockers.append(f"finding_{idx}:line_range_out_of_packet_bounds:{cited_path}:{start}-{end}")
                excerpt = cited_line_excerpt(path_info, line_ranges)
                if any(identifier in excerpt for identifier in identifiers):
                    matched_identifier_on_cited_lines = True
            if high_risk and not matched_identifier_on_cited_lines:
                blockers.append(f"finding_{idx}:evidence_line_identifier_mismatch")

        missing_identifiers = []
        for identifier in identifiers:
            if not any(identifier in context["files"][cited_path]["content"] for cited_path in cited_paths):
                missing_identifiers.append(identifier)
        if missing_identifiers:
            warnings.append(f"finding_{idx}:identifier_not_found_in_cited_packet_file:{','.join(missing_identifiers[:3])}")
            if high_risk:
                blockers.append(f"finding_{idx}:high_risk_identifier_not_found_in_cited_packet_file")

        if not high_risk or (cited_paths and line_ranges and not missing_identifiers):
            actionable_count += 1

    quality_score = max(0, 100 - 30 * len(blockers) - 10 * len(warnings))
    return {
        "quality_valid": not blockers and quality_score >= 70,
        "quality_score": quality_score,
        "quality_error": None if not blockers else "; ".join(blockers[:5]),
        "quality_blockers": blockers,
        "quality_warnings": warnings,
        "actionable_finding_count": actionable_count,
    }


def deepseek_r1_adapter_status(attempts):
    r1_attempts = [
        attempt
        for attempt in attempts
        if attempt.get("model_id") == "deepseek-r1:7b"
        and attempt.get("reasoning_json_adapter")
    ]
    if not r1_attempts:
        return "not_run"
    if any(attempt.get("status") == "attempt_started" for attempt in r1_attempts):
        return "attempt_in_progress"
    if any(attempt.get("status") == "planned_dry_run" for attempt in r1_attempts):
        return "planned_not_evaluated"
    valid_trials = [
        attempt
        for attempt in r1_attempts
        if attempt.get("status") == "review_passed" and attempt.get("json_valid")
    ]
    if len(valid_trials) >= 2:
        return "json_review_usable_candidate_two_valid_trials"
    if valid_trials:
        return "needs_second_valid_json_trial"
    if any(
        attempt.get("status") == "attempt_failed"
        and attempt.get("error_status") in {
            "local_openai_connection_or_transport_error",
            "ollama_connection_or_transport_error",
        }
        for attempt in r1_attempts
    ):
        return "not_callable_or_not_installed_quarantined"
    return "callable_but_not_review_usable_quarantined"


def load_completed_model_attempts(ledger_path, packet_path):
    completed = {}
    if not os.path.exists(ledger_path):
        return completed
    with open(ledger_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("packet") != packet_path:
                continue
            if record.get("status") != "review_passed":
                continue
            key = (
                record.get("model_id"),
                record.get("backend"),
                record.get("role"),
                record.get("disclosure_class"),
            )
            completed.setdefault(key, []).append(record)
    return completed


def write_partial_model_receipt(args, packet_path, attempts, run_stamp, status="PARTIAL_IN_PROGRESS"):
    payload = {
        "schema_version": "pbm-model-attempt-partial-receipt/v1.0",
        "recorded_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "status": status,
        "run_stamp": run_stamp,
        "mode": args.mode,
        "packet": packet_path,
        "git_lineage": git_lineage(),
        "local_fast": args.local_fast,
        "reasoning_json_adapter": args.reasoning_json_adapter,
        "json_required": args.require_json_reviews or args.local_fast or args.reasoning_json_adapter,
        "quality_required": args.require_quality_gate and (args.require_json_reviews or args.local_fast or args.reasoning_json_adapter),
        "local_fast_profile": {
            "max_packet_files": args.local_fast_max_packet_files,
            "max_file_chars": args.local_fast_max_file_chars,
            "max_output_tokens": args.local_fast_max_output_tokens,
            "max_findings": args.local_fast_max_findings,
            "per_call_timeout_seconds": args.local_fast_timeout_seconds,
        },
        "deepseek_r1_adapter_status": deepseek_r1_adapter_status(attempts),
        "attempt_count": len(attempts),
        "model_success_count": len([
            attempt
            for attempt in attempts
            if attempt.get("status") in {"review_passed", "skipped_completed"}
        ]),
        "min_model_successes": args.min_model_successes,
        "model_attempts": attempts,
    }
    write_json(safe_repo_path(args.partial_receipt_out), payload)


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


def blocked_model_attempt(args, model_id, routed_model, backend, role, packet_path, disclosure, reason):
    registry_entry = registry_entry_for_model(model_id)
    execution_profile = execution_profile_for_model(model_id)
    return {
        "recorded_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "model_id": model_id,
        "routed_model_id": routed_model,
        "registry_status": registry_entry["status"],
        "suggested_lens": registry_entry["suggested_lens"],
        "execution_profile": execution_profile,
        "review_usable": execution_profile["review_usable"],
        "json_reliability": execution_profile["json_reliability"],
        "expected_latency_band": execution_profile["expected_latency_band"],
        "preferred_lens": execution_profile["preferred_lens"],
        "avoid_for": execution_profile["avoid_for"],
        "backend": backend,
        "role": role,
        "packet": packet_path,
        "disclosure_class": disclosure,
        "status": "blocked",
        "reason": reason,
        "output_path": None,
        "metadata_path": None,
        "claim_count": 0,
        "json_required": args.require_json_reviews or args.local_fast or args.reasoning_json_adapter,
        "json_valid": False,
        "json_error": reason,
        "json_finding_count": 0,
        "quality_required": args.require_quality_gate and (args.require_json_reviews or args.local_fast or args.reasoning_json_adapter),
        "quality_valid": False,
        "quality_score": 0,
        "quality_error": reason,
        "quality_blockers": [reason],
        "quality_warnings": [],
        "actionable_finding_count": 0,
        "local_fast": args.local_fast,
        "reasoning_json_adapter": args.reasoning_json_adapter,
        "result": None,
    }


def dispatch_model_attempts(args, packet_path):
    if not args.attempt_models:
        return []
    if not packet_path:
        raise SystemExit("--attempt-models requires --packet or --question with --packet-out.")

    disclosure = packet_disclosure(packet_path)
    attempts = []
    ledger_path = safe_repo_path(args.ledger_out)
    run_stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_required = args.require_json_reviews or args.local_fast or args.reasoning_json_adapter
    quality_required = args.require_quality_gate and json_required
    review_max_findings = args.local_fast_max_findings if json_required else None
    local_model_ids = [
        entry["id"]
        for entry in MODEL_EXPERIMENT_REGISTRY
        if MODEL_BACKEND_DEFAULTS.get(entry["id"]) in {"ollama", "local-openai"}
    ]
    cloud_model_ids = [
        entry["id"]
        for entry in MODEL_EXPERIMENT_REGISTRY
        if MODEL_BACKEND_DEFAULTS.get(entry["id"]) not in {"ollama", "local-openai"}
    ]
    requested_models = []
    for item in args.attempt_models:
        if item == "all":
            requested_models.extend(entry["id"] for entry in MODEL_EXPERIMENT_REGISTRY)
        elif item == "local":
            requested_models.extend(local_model_ids)
        elif item in {"local-fast", "local_fast"}:
            requested_models.extend(LOCAL_FAST_MODEL_IDS)
        elif item == "cloud":
            requested_models.extend(cloud_model_ids)
        elif item in {"r1-json", "deepseek-r1-json"}:
            requested_models.append("deepseek-r1:7b")
        else:
            requested_models.append(item)
    requested_models = list(dict.fromkeys(requested_models))
    completed_attempts = load_completed_model_attempts(ledger_path, packet_path) if args.resume_model_attempts else {}

    def record_attempt(attempt):
        attempts.append(attempt)
        if args.mode == "execute":
            append_jsonl(ledger_path, attempt)
        write_partial_model_receipt(args, packet_path, attempts, run_stamp)

    write_partial_model_receipt(
        args,
        packet_path,
        attempts,
        run_stamp,
        status="PARTIAL_DRY_RUN" if args.mode != "execute" else "PARTIAL_IN_PROGRESS",
    )

    for model_id in requested_models:
        for trial_index in range(1, max(1, args.repeat_attempts) + 1):
            role = review_lane_for_model(args, model_id)
            backend = backend_for_model(args, model_id)
            routed_model = routed_model_id(model_id)
            registry_entry = registry_entry_for_model(model_id)
            execution_profile = execution_profile_for_model(model_id)
            model_slug = slugify_model_id(model_id)
            trial_suffix = f"-trial{trial_index}" if args.repeat_attempts > 1 else ""
            output_rel = relpath(os.path.join(MODEL_ATTEMPT_DIR, f"{run_stamp}-{model_slug}-{role}{trial_suffix}-review.md"))
            metadata_rel = relpath(os.path.join(MODEL_ATTEMPT_DIR, f"{run_stamp}-{model_slug}-{role}{trial_suffix}-router-metadata.json"))
            output_abs = safe_repo_path(output_rel)
            metadata_abs = safe_repo_path(metadata_rel)
            resume_key = (model_id, backend, role, disclosure)
            prior_records = completed_attempts.get(resume_key, [])
            eligible_prior_records = [
                record
                for record in prior_records
                if not json_required or record.get("json_valid")
            ]
            if quality_required:
                eligible_prior_records = [
                    record
                    for record in eligible_prior_records
                    if record.get("quality_valid")
                ]

            if args.resume_model_attempts and trial_index <= len(eligible_prior_records):
                prior = dict(eligible_prior_records[trial_index - 1])
                prior.update({
                    "recorded_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                    "status": "skipped_completed",
                    "resume_source_status": "review_passed",
                    "trial_index": trial_index,
                    "trial_count": max(1, args.repeat_attempts),
                    "execution_profile": execution_profile,
                    "review_usable": execution_profile["review_usable"],
                    "json_reliability": execution_profile["json_reliability"],
                    "expected_latency_band": execution_profile["expected_latency_band"],
                    "preferred_lens": execution_profile["preferred_lens"],
                    "avoid_for": execution_profile["avoid_for"],
                    "json_required": json_required,
                    "quality_required": quality_required,
                    "local_fast": args.local_fast,
                    "reasoning_json_adapter": args.reasoning_json_adapter,
                })
                record_attempt(prior)
                continue

            if registry_entry["status"] == "candidate_needs_exact_model" or (backend == "openrouter" and not routed_model):
                attempt = blocked_model_attempt(
                    args,
                    model_id,
                    routed_model,
                    backend,
                    role,
                    packet_path,
                    disclosure,
                    "exact_model_identity_required" if registry_entry["status"] == "candidate_needs_exact_model" else "openrouter_route_identity_required",
                )
                attempt["trial_index"] = trial_index
                attempt["trial_count"] = max(1, args.repeat_attempts)
                record_attempt(attempt)
                continue

            if disclosure in {"SECRET_OR_SENSITIVE", "LIVE_PRIVILEGED"}:
                attempt = blocked_model_attempt(
                    args,
                    model_id,
                    routed_model,
                    backend,
                    role,
                    packet_path,
                    disclosure,
                    f"refusing_{disclosure.lower()}_packet",
                )
                attempt["trial_index"] = trial_index
                attempt["trial_count"] = max(1, args.repeat_attempts)
                record_attempt(attempt)
                continue

            if backend == "openrouter" and args.offline:
                attempt = blocked_model_attempt(
                    args,
                    model_id,
                    routed_model,
                    backend,
                    role,
                    packet_path,
                    disclosure,
                    "offline_mode_blocks_external_model_dispatch",
                )
                attempt["trial_index"] = trial_index
                attempt["trial_count"] = max(1, args.repeat_attempts)
                record_attempt(attempt)
                continue

            if backend == "openrouter" and disclosure != "PUBLIC_COMMITTED" and args.approve_disclosure != disclosure:
                attempt = blocked_model_attempt(
                    args,
                    model_id,
                    routed_model,
                    backend,
                    role,
                    packet_path,
                    disclosure,
                    f"awaiting_exact_disclosure_approval_{disclosure}",
                )
                attempt["trial_index"] = trial_index
                attempt["trial_count"] = max(1, args.repeat_attempts)
                record_attempt(attempt)
                continue

            command = [
                sys.executable,
                "scripts/openrouter_review.py",
                "--role",
                role,
                "--model",
                routed_model,
                "--packet",
                packet_path,
                "--approve-disclosure",
                disclosure,
                "--output-file",
                output_rel,
                "--metadata-file",
                metadata_rel,
            ]
            if backend == "ollama":
                command.append("--ollama")
                command.extend(["--ollama-host", args.ollama_host])
            elif backend == "local-openai":
                command.append("--local-openai")
                command.extend(["--local-openai-base-url", args.local_openai_base_url])
            if args.challenger:
                command.append("--challenger")
            if args.permute_order:
                command.append("--permute-order")
            if json_required:
                command.append("--json-review")
                command.extend(["--max-findings", str(review_max_findings)])
            if args.local_fast:
                command.append("--local-fast")
            if args.reasoning_json_adapter:
                command.append("--reasoning-json-adapter")
            if args.local_fast or args.reasoning_json_adapter:
                command.extend(["--max-packet-files", str(args.local_fast_max_packet_files)])
                command.extend(["--max-file-chars", str(args.local_fast_max_file_chars)])
                command.extend(["--max-output-tokens", str(args.local_fast_max_output_tokens)])
            if backend in {"ollama", "local-openai"} and (args.local_fast or args.reasoning_json_adapter):
                command.extend(["--request-timeout-seconds", str(args.local_fast_timeout_seconds)])

            attempt_timeout = args.timeout_seconds
            if backend in {"ollama", "local-openai"} and (args.local_fast or args.reasoning_json_adapter):
                attempt_timeout = max(args.timeout_seconds, args.local_fast_timeout_seconds)

            started_attempt_index = None
            if args.mode == "execute":
                started_attempt_index = len(attempts)
                attempts.append({
                    "recorded_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                    "model_id": model_id,
                    "routed_model_id": routed_model,
                    "registry_status": registry_entry["status"],
                    "suggested_lens": registry_entry["suggested_lens"],
                    "execution_profile": execution_profile,
                    "review_usable": execution_profile["review_usable"],
                    "json_reliability": execution_profile["json_reliability"],
                    "expected_latency_band": execution_profile["expected_latency_band"],
                    "preferred_lens": execution_profile["preferred_lens"],
                    "avoid_for": execution_profile["avoid_for"],
                    "backend": backend,
                    "role": role,
                    "packet": packet_path,
                    "disclosure_class": disclosure,
                    "trial_index": trial_index,
                    "trial_count": max(1, args.repeat_attempts),
                    "status": "attempt_started",
                    "error_status": None,
                    "output_path": output_rel,
                    "metadata_path": metadata_rel,
                    "claim_count": 0,
                    "json_required": json_required,
                    "json_valid": None,
                    "json_error": "attempt_in_progress",
                    "json_finding_count": None,
                    "quality_required": quality_required,
                    "quality_valid": None,
                    "quality_score": None,
                    "quality_error": "attempt_in_progress",
                    "quality_blockers": [],
                    "quality_warnings": [],
                    "actionable_finding_count": 0,
                    "local_fast": args.local_fast,
                    "reasoning_json_adapter": args.reasoning_json_adapter,
                    "attempt_timeout_seconds": attempt_timeout,
                    "reconciliation_status": "unreconciled_raw_output",
                    "result": None,
                })
                write_partial_model_receipt(args, packet_path, attempts, run_stamp)

            if args.mode != "execute":
                result = {
                    "label": f"Model review attempt: {model_id} ({role}/{backend})",
                    "command": " ".join(command_for_platform(command)),
                    "return_code": None,
                    "status": "PLANNED_DRY_RUN",
                    "duration_ms": 0,
                    "stdout_tail": "",
                    "stderr_tail": "",
                }
            else:
                result = run_command(
                    f"Model review attempt: {model_id} ({role}/{backend})",
                    command,
                    attempt_timeout,
                )

            metadata = read_json_if_exists(metadata_abs)
            claim_count = len(extract_review_claims(output_abs)) if os.path.exists(output_abs) else 0
            json_validation = validate_review_json_output(output_abs, review_max_findings) if json_required and args.mode == "execute" else {
                "json_valid": None,
                "json_error": "not_run_dry_run" if json_required and args.mode != "execute" else None,
                "json_finding_count": None,
            }
            quality_validation = (
                validate_review_quality_output(output_abs, packet_path)
                if quality_required and args.mode == "execute" and json_validation["json_valid"]
                else {
                    "quality_valid": None,
                    "quality_score": None,
                    "quality_error": "not_run_dry_run" if quality_required and args.mode != "execute" else None,
                    "quality_blockers": [],
                    "quality_warnings": [],
                    "actionable_finding_count": None,
                }
            )
            status = "planned_dry_run"
            if args.mode == "execute":
                if result["status"] == "PASSED" and os.path.exists(output_abs):
                    status = "review_passed"
                    if json_required and not json_validation["json_valid"]:
                        status = "review_failed_invalid_json"
                    elif quality_required and not quality_validation["quality_valid"]:
                        status = "review_failed_quality_gate"
                else:
                    status = "attempt_failed"

            attempt = {
                "recorded_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                "model_id": model_id,
                "routed_model_id": routed_model,
                "registry_status": registry_entry["status"],
                "suggested_lens": registry_entry["suggested_lens"],
                "execution_profile": execution_profile,
                "review_usable": execution_profile["review_usable"],
                "json_reliability": execution_profile["json_reliability"],
                "expected_latency_band": execution_profile["expected_latency_band"],
                "preferred_lens": execution_profile["preferred_lens"],
                "avoid_for": execution_profile["avoid_for"],
                "backend": backend,
                "role": role,
                "packet": packet_path,
                "disclosure_class": disclosure,
                "trial_index": trial_index,
                "trial_count": max(1, args.repeat_attempts),
                "status": status,
                "error_status": metadata.get("error_status"),
                "output_path": output_rel,
                "metadata_path": metadata_rel,
                "claim_count": claim_count,
                "json_required": json_required,
                "json_valid": json_validation["json_valid"],
                "json_error": json_validation["json_error"],
                "json_finding_count": json_validation["json_finding_count"],
                "quality_required": quality_required,
                "quality_valid": quality_validation["quality_valid"],
                "quality_score": quality_validation["quality_score"],
                "quality_error": quality_validation["quality_error"],
                "quality_blockers": quality_validation["quality_blockers"],
                "quality_warnings": quality_validation["quality_warnings"],
                "actionable_finding_count": quality_validation["actionable_finding_count"],
                "local_fast": args.local_fast,
                "reasoning_json_adapter": args.reasoning_json_adapter,
                "attempt_timeout_seconds": attempt_timeout,
                "reconciliation_status": metadata.get("reconciliation_status", "unreconciled_raw_output"),
                "result": result,
            }
            if started_attempt_index is not None:
                attempts[started_attempt_index] = attempt
                append_jsonl(ledger_path, attempt)
                write_partial_model_receipt(args, packet_path, attempts, run_stamp)
            else:
                record_attempt(attempt)

    write_partial_model_receipt(args, packet_path, attempts, run_stamp, status="PARTIAL_COMPLETE")
    return attempts


def lane_name_variants(lane):
    return sorted({lane, lane.replace("_", "-"), lane.replace("-", "_")})


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
        for lane_variant in lane_name_variants(lane):
            paths.append(f"reviews/{lane_variant}-packet-review.md")
            paths.append(f"reviews/{lane_variant}-packet-router-metadata.json")
            paths.append(f"reviews/{lane_variant}-review.txt")
            paths.append(f"reviews/{lane_variant}-router-metadata.json")
    return sorted(set(paths))


def existing_review_files(lanes, packet_path):
    files = []
    for candidate in known_review_output_paths(lanes, packet_path):
        abs_path = safe_repo_path(candidate)
        if os.path.exists(abs_path) and os.path.isfile(abs_path) and not abs_path.lower().endswith(".json"):
            files.append(abs_path)
    return files


def review_file_scan_summary(lanes, review_files):
    scanned_files = [relpath(path) for path in review_files]
    missing_lanes = []
    for lane in lanes:
        lane_files = existing_review_files([lane], None)
        if not lane_files:
            missing_lanes.append(lane)
    return {
        "requested_lanes": lanes,
        "scanned_files": scanned_files,
        "missing_lanes": missing_lanes,
    }


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
    if receipt.get("model_attempts"):
        lines.extend(["", "## Model Attempts", ""])
        lines.append(
            f"Model success quorum: {receipt.get('model_success_count', 0)} / {receipt.get('min_model_successes', 0)}"
        )
        lines.append("")
        for attempt in receipt["model_attempts"]:
            detail = attempt.get("error_status") or attempt.get("reason") or "no_error"
            routed = attempt.get("routed_model_id") or "unresolved"
            json_detail = ""
            if attempt.get("json_required"):
                json_detail = f"; json: {attempt.get('json_valid')} ({attempt.get('json_error') or 'ok'})"
            quality_detail = ""
            if attempt.get("quality_required"):
                quality_detail = (
                    f"; quality: {attempt.get('quality_valid')} "
                    f"(score {attempt.get('quality_score')}; {attempt.get('quality_error') or 'ok'})"
                )
            lines.append(
                f"- `{attempt['status']}` `{attempt['model_id']}` -> `{routed}` via `{attempt['backend']}` "
                f"as `{attempt['role']}`; claims: {attempt.get('claim_count', 0)}"
                f"{json_detail}{quality_detail}; detail: `{detail}`"
            )
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
    parser.add_argument("--attempt-models", nargs="+", help="Empirically dispatch selected model IDs, or 'local-fast', 'local', 'cloud', 'r1-json', or 'all', and record model-specific artifacts")
    parser.add_argument("--model-backend", choices=["auto", "ollama", "local-openai", "openrouter"], default="auto", help="Backend for --attempt-models; auto uses local defaults when known")
    parser.add_argument("--attempt-role", choices=REVIEW_LANES, help="Force one reviewer role for all --attempt-models")
    parser.add_argument("--ollama-host", default="http://localhost:11434", help="Local Ollama endpoint for local model attempts")
    parser.add_argument("--local-openai-base-url", default="http://localhost:11434/v1", help="Local OpenAI-compatible base URL for local model attempts")
    parser.add_argument("--ledger-out", default=relpath(DEFAULT_MODEL_ATTEMPT_LEDGER), help="JSONL ledger path for model attempt receipts")
    parser.add_argument("--partial-receipt-out", default=relpath(DEFAULT_PARTIAL_RECEIPT_PATH), help="JSON receipt updated after each model attempt")
    parser.add_argument("--local-fast", action="store_true", help="Use compact local CPU JSON review profile for model attempts")
    parser.add_argument("--local-fast-timeout-seconds", type=int, default=900, help="Per-local-model timeout used by --local-fast and reasoning JSON adapter runs")
    parser.add_argument("--local-fast-max-packet-files", type=int, default=4, help="Maximum packet files sent in local-fast model context")
    parser.add_argument("--local-fast-max-file-chars", type=int, default=3500, help="Maximum characters per packet file in local-fast context")
    parser.add_argument("--local-fast-max-output-tokens", type=int, default=900, help="Maximum output tokens requested from local-fast model attempts")
    parser.add_argument("--local-fast-max-findings", type=int, default=2, help="Maximum JSON findings requested and accepted in local-fast model attempts")
    parser.add_argument("--require-json-reviews", action="store_true", help="Require attempted model outputs to parse as JSON reviews")
    parser.add_argument("--require-quality-gate", dest="require_quality_gate", action="store_true", default=True, help="Require grounded packet evidence for JSON review success")
    parser.add_argument("--no-quality-gate", dest="require_quality_gate", action="store_false", help="Disable grounded-evidence quality gate for transport/JSON diagnostics")
    parser.add_argument("--reasoning-json-adapter", action="store_true", help="Use stricter final-JSON adapter prompt for reasoning models")
    parser.add_argument("--repeat-attempts", type=int, default=1, help="Repeat each model attempt this many times for reliability experiments")
    parser.add_argument("--resume-model-attempts", action="store_true", help="Skip previously passed matching model attempts from the model attempt ledger")
    parser.add_argument("--require-model-success", action="store_true", help="Fail the harness if any --attempt-models run does not produce review output")
    parser.add_argument("--min-model-successes", type=int, default=0, help="Fail the harness unless at least this many model attempts are review_passed or skipped_completed")
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
    model_attempts = dispatch_model_attempts(args, packet_path)
    model_review_files = [
        safe_repo_path(attempt["output_path"])
        for attempt in model_attempts
        if attempt.get("status") in {"review_passed", "skipped_completed"} and attempt.get("output_path")
    ]
    review_files = existing_review_files(review_lanes, packet_path) + model_review_files
    matrix = build_disagreement_matrix(review_files)

    packet_failed = (
        packet_compile
        and packet_compile["result"]["status"] not in {"PASSED", "PLANNED_DRY_RUN"}
    )
    failed_checks = [item for item in deterministic_results if item["status"] not in {"PASSED", "PLANNED_DRY_RUN"}]
    failed_reviews = [item for item in reviewer_dispatches if item["status"] != "PASSED"]
    failed_model_attempts = [
        item
        for item in model_attempts
        if item["status"] not in {"review_passed", "planned_dry_run", "skipped_completed"}
    ]
    successful_model_attempts = [
        item
        for item in model_attempts
        if item["status"] in {"review_passed", "skipped_completed"}
    ]
    model_quorum_failed = bool(args.min_model_successes) and len(successful_model_attempts) < args.min_model_successes
    overall_status = "PASSED"
    if failed_checks or failed_reviews or packet_failed or (args.require_model_success and failed_model_attempts) or model_quorum_failed:
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
        "candidate_model_registry": model_registry_with_profiles(),
        "local_fast": args.local_fast,
        "local_fast_profile": {
            "max_packet_files": args.local_fast_max_packet_files,
            "max_file_chars": args.local_fast_max_file_chars,
            "max_output_tokens": args.local_fast_max_output_tokens,
            "max_findings": args.local_fast_max_findings,
            "per_call_timeout_seconds": args.local_fast_timeout_seconds,
        },
        "json_required_for_model_attempts": args.require_json_reviews or args.local_fast or args.reasoning_json_adapter,
        "quality_required_for_model_attempts": args.require_quality_gate and (args.require_json_reviews or args.local_fast or args.reasoning_json_adapter),
        "reasoning_json_adapter": args.reasoning_json_adapter,
        "deepseek_r1_adapter_status": deepseek_r1_adapter_status(model_attempts),
        "model_success_count": len(successful_model_attempts),
        "min_model_successes": args.min_model_successes,
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
        "model_attempt_ledger": relpath(safe_repo_path(args.ledger_out)),
        "partial_model_attempt_receipt": relpath(safe_repo_path(args.partial_receipt_out)),
        "model_attempts": model_attempts,
        "review_file_scan": review_file_scan_summary(review_lanes, review_files),
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
    print(f"* Model Attempts: {len(model_attempts)}")
    print(f"* Candidate Claims: {len(matrix['claims'])}")
    print(f"* Receipt: {relpath(RECEIPT_PATH)}")
    print(f"* Matrix: {receipt['disagreement_matrix']}")
    print(f"* Report: {receipt['disagreement_report']}")
    print("==================================================")

    if args.mode != "dry-run" and (
        failed_checks
        or failed_reviews
        or (args.require_model_success and failed_model_attempts)
        or model_quorum_failed
    ):
        sys.exit(1)


if __name__ == "__main__":
    main()
