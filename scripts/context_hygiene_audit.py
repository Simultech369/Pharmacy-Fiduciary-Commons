#!/usr/bin/env python3
"""
context_hygiene_audit.py - deterministic audit for standing prompt bloat,
context-surface classification, and proof-boundary phrasing.

The audit is intentionally narrow: it does not judge model quality or external
prompting guidance. It checks local repo invariants that should not rely on an
LLM remembering them.
"""

import argparse
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
STANDING_BRIEF_LINE_BUDGET = 200

CONTEXT_SURFACES = [
    {
        "path": ".agents/AGENTS.md",
        "category": "standing_brief",
        "role": "Always-loaded operating brief and approval boundary.",
        "required": True,
    },
    {
        "path": ".agents/memory/MEMORY.md",
        "category": "memory_reference",
        "role": "Searchable local agent memory index.",
        "required": True,
    },
    {
        "path": ".agents/memory/LEARNINGS_QUEUE.md",
        "category": "memory_reference",
        "role": "Candidate operating rules pending owner promotion.",
        "required": True,
    },
    {
        "path": "docs/ops/KNOWN_FAILURE_POSTMORTEMS.md",
        "category": "memory_reference",
        "role": "Historical failure memory used by rehearsal gates.",
        "required": True,
    },
    {
        "path": "review-context/repo_knowledge_graph.json",
        "category": "memory_reference",
        "role": "Machine-readable graph for bounded context loading.",
        "required": True,
    },
    {
        "path": "scripts/rehearse_proposal.py",
        "category": "workflow_skill",
        "role": "Repeatable rehearsal proposal scoring workflow.",
        "required": True,
    },
    {
        "path": "scripts/index_dossier_tree.py",
        "category": "workflow_skill",
        "role": "Repeatable PageIndex status and dossier audit workflow.",
        "required": True,
    },
    {
        "path": "scripts/context_hygiene_audit.py",
        "category": "deterministic_gate",
        "role": "This deterministic context hygiene gate.",
        "required": True,
    },
    {
        "path": "scripts/eval_dossier_rag.py",
        "category": "deterministic_gate",
        "role": "Local retrieval quality threshold gate.",
        "required": True,
    },
    {
        "path": "test/system_prompt_governance.test.js",
        "category": "deterministic_gate",
        "role": "Standing prompt budget and truth-rule regression tests.",
        "required": True,
    },
    {
        "path": "test/context_hygiene_audit.test.js",
        "category": "deterministic_gate",
        "role": "Context hygiene audit regression tests.",
        "required": True,
    },
    {
        "path": "test/repo_knowledge_graph.test.js",
        "category": "deterministic_gate",
        "role": "Knowledge graph referential integrity and proof-boundary tests.",
        "required": True,
    },
    {
        "path": "test/fde_enterprise_mapping.test.js",
        "category": "deterministic_gate",
        "role": "FDE roadmap non-claim and proof-boundary regression tests.",
        "required": True,
    },
    {
        "path": "test/observability_dashboard.test.js",
        "category": "deterministic_gate",
        "role": "Swarm observability evidence-boundary regression tests.",
        "required": True,
    },
    {
        "path": "test/advanced_rag_mapping.test.js",
        "category": "deterministic_gate",
        "role": "Advanced RAG roadmap non-claim regression tests.",
        "required": True,
    },
    {
        "path": "test/VoucherSagaQueue.test.js",
        "category": "deterministic_gate",
        "role": "Phase 4 voucher saga idempotency, lease, retry, DLQ, and RLS regression tests.",
        "required": True,
    },
    {
        "path": "test/Phase6Operationalization.test.js",
        "category": "deterministic_gate",
        "role": "Phase 6 operationalization saga telemetry and identity redaction regression tests.",
        "required": True,
    },
    {
        "path": "test/RateLimitingContracts.test.js",
        "category": "deterministic_gate",
        "role": "FDE rate-limiting contract and bucket isolation regression tests.",
        "required": True,
    },
    {
        "path": "scripts/compile_review_packet.py",
        "category": "deterministic_gate",
        "role": "Permission-aware review packet compiler and sensitivity classifier.",
        "required": True,
    },
    {
        "path": "scripts/verify_agent_claims.py",
        "category": "deterministic_gate",
        "role": "Agent claim lie detector and receipt cross-auditor.",
        "required": True,
    },
    {
        "path": "test/ReviewPacketCompiler.test.js",
        "category": "deterministic_gate",
        "role": "Permission-aware review packet compiler regression tests.",
        "required": True,
    },
    {
        "path": "test/ZeroDatabaseLiveness.test.js",
        "category": "deterministic_gate",
        "role": "Zero-database resilience and offline continuity liveness tests.",
        "required": True,
    },
    {
        "path": "test/AgentClaimVerifier.test.js",
        "category": "deterministic_gate",
        "role": "Agent claim lie detector regression tests.",
        "required": True,
    },
]

REQUIRED_AGENT_TOKENS = [
    "Data Freshness & Lineage Protocol",
    "[live verification just run]",
    "[committed HEAD]",
    "[dirty working tree]",
    "L3 (Explicit Permission Gate)",
    "Git commit/push",
]

BANNED_HYGIENE_DOC_PHRASES = [
    "100% PASS",
    "Zero Token Waste",
    "High Reasoning Accuracy",
    "strictly under 46 lines",
]


def read_text(relative_path):
    return (ROOT_DIR / relative_path).read_text(encoding="utf-8")


def raw_line_count(text):
    return len(text.splitlines())


def add_issue(issues, severity, path, message):
    issues.append({
        "severity": severity,
        "path": path,
        "message": message,
    })


def audit_context_hygiene():
    issues = []
    surfaces = []
    category_counts = {}

    for surface in CONTEXT_SURFACES:
        abs_path = ROOT_DIR / surface["path"]
        exists = abs_path.exists()
        category_counts[surface["category"]] = category_counts.get(surface["category"], 0) + 1

        entry = {
            "path": surface["path"],
            "category": surface["category"],
            "role": surface["role"],
            "exists": exists,
        }
        if exists and abs_path.is_file():
            entry["line_count"] = raw_line_count(abs_path.read_text(encoding="utf-8"))
        surfaces.append(entry)

        if surface["required"] and not exists:
            add_issue(issues, "error", surface["path"], "Required context surface is missing.")

    agents_path = ".agents/AGENTS.md"
    if (ROOT_DIR / agents_path).exists():
        agents = read_text(agents_path)
        line_count = raw_line_count(agents)
        if line_count >= STANDING_BRIEF_LINE_BUDGET:
            add_issue(
                issues,
                "error",
                agents_path,
                f"Standing brief has {line_count} lines; budget is under {STANDING_BRIEF_LINE_BUDGET}.",
            )
        for token in REQUIRED_AGENT_TOKENS:
            if token not in agents:
                add_issue(issues, "error", agents_path, f"Missing required standing brief token: {token}")

    graph_path = "review-context/repo_knowledge_graph.json"
    if (ROOT_DIR / graph_path).exists():
        try:
            graph = json.loads(read_text(graph_path))
            node_ids = {node.get("id") for node in graph.get("nodes", [])}
            for edge in graph.get("edges", []):
                if edge.get("from") not in node_ids:
                    add_issue(issues, "error", graph_path, f"Edge source missing node: {edge.get('from')}")
                if edge.get("to") not in node_ids:
                    add_issue(issues, "error", graph_path, f"Edge target missing node: {edge.get('to')}")
        except json.JSONDecodeError as exc:
            add_issue(issues, "error", graph_path, f"Invalid JSON: {exc}")

    hygiene_docs = [
        "docs/design/system_prompt_pruning_and_governance.md",
        "docs/plans/phase_5_context_hygiene_and_instruction_pruning_plan.md",
        "docs/plans/fde_enterprise_reliability_mapping.md",
        "docs/plans/advanced_rag_retrieval_mapping.md",
    ]
    for doc_path in hygiene_docs:
        if not (ROOT_DIR / doc_path).exists():
            continue
        text = read_text(doc_path)
        for phrase in BANNED_HYGIENE_DOC_PHRASES:
            if phrase in text:
                add_issue(issues, "error", doc_path, f"Overclaim or brittle prompt-hygiene phrase found: {phrase}")

    gitignore_path = ".gitignore"
    if (ROOT_DIR / gitignore_path).exists():
        gitignore = read_text(gitignore_path)
        if "reviews/outcome_memory.json" not in gitignore:
            add_issue(issues, "error", gitignore_path, "reviews/outcome_memory.json must remain local-only.")

    required_categories = {"standing_brief", "memory_reference", "workflow_skill", "deterministic_gate"}
    for category in sorted(required_categories):
        if category_counts.get(category, 0) == 0:
            add_issue(issues, "error", "context_surface_registry", f"Missing category: {category}")

    failed = any(issue["severity"] == "error" for issue in issues)
    return {
        "schema_version": "pbm.context_hygiene_audit.v1",
        "status": "FAILED" if failed else "PASSED",
        "standing_brief_line_budget": STANDING_BRIEF_LINE_BUDGET,
        "category_counts": category_counts,
        "surfaces": surfaces,
        "issues": issues,
    }


def main():
    parser = argparse.ArgumentParser(description="Audit PBM context hygiene and instruction-pruning boundaries.")
    parser.add_argument("--pretty", action="store_true", help="Print pretty JSON.")
    args = parser.parse_args()

    result = audit_context_hygiene()
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    raise SystemExit(0 if result["status"] == "PASSED" else 1)


if __name__ == "__main__":
    main()
