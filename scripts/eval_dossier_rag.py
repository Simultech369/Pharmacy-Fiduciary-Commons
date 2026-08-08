#!/usr/bin/env python3
"""
Evaluate local dossier retrieval against golden and adversarial queries.

This measures whether the local retrieval harness returns the expected source
documents for repo-specific governance questions. It is intentionally small and
dependency-free; it is not a production RAG benchmark.
"""

import json
import math
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
CACHE_DIR = os.path.join(REPO_ROOT, "cache")
SUMMARY_PATH = os.path.join(CACHE_DIR, "dossier_rag_eval_summary.json")

sys.path.insert(0, SCRIPT_DIR)
from dossier_rag_retrieval import rag_query  # noqa: E402


GOLDEN_CASES = [
    {
        "query": "What does an evidenceHash prove and not prove?",
        "expected_files": ["EVIDENCE_METADATA.md"],
    },
    {
        "query": "Who can see the evidence preimage?",
        "expected_files": ["EVIDENCE_METADATA.md"],
    },
    {
        "query": "Does this prototype provide production zero knowledge privacy?",
        "expected_files": ["README.md", "MECHANISM_COVERAGE.md", "ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md", "IDENTITY_NULLIFIER_DESIGN.md"],
    },
    {
        "query": "What does previewFinalize isSufficient mean under underfunding?",
        "expected_files": ["SOLVENCY_DEBT_SEMANTICS.md", "MECHANISM_COVERAGE.md"],
    },
    {
        "query": "Can underfunded finalization continue while recording shortfall?",
        "expected_files": ["SOLVENCY_DEBT_SEMANTICS.md", "MECHANISM_COVERAGE.md"],
    },
    {
        "query": "Where are public launch and production readiness blockers tracked?",
        "expected_files": ["PRODUCTION_READINESS_CHECKLIST.md", "ROADMAP.md", "README.md"],
    },
    {
        "query": "Which provider and auth candidates are not active architecture?",
        "expected_files": ["PROVIDER_SELECTION.md", "ROADMAP.md"],
    },
    {
        "query": "How should model reviewer findings be treated before humans authorize action?",
        "expected_files": ["REVIEW_ITERATION_PROCESS.md", "AGENT_REVIEW_ORCHESTRATION.md"],
    },
    {
        "query": "What is the non-digital or offline continuity boundary?",
        "expected_files": ["CARE_CONTINUITY.md", "ROADMAP.md", "PRODUCTION_READINESS_CHECKLIST.md"],
    },
    {
        "query": "What is the retaliation or payer metadata threat model?",
        "expected_files": ["RETALIATION_AND_PRIVACY_THREAT_MODEL.md", "PROVIDER_SELECTION.md"],
    },
    {
        "query": "Where are unresolved policy choices and open design decisions tracked?",
        "expected_files": ["OPEN_DESIGN_DECISIONS.md", "ROADMAP.md"],
    },
    {
        "query": "What are the Supabase RLS and tenant isolation boundaries?",
        "expected_files": ["MECHANISM_COVERAGE.md", "PRODUCTION_READINESS_CHECKLIST.md", "PROVIDER_SELECTION.md"],
    },
]

ADVERSARIAL_NO_HIT_CASES = [
    "banana orchestra dragon spaceship",
    "mars colony weather forecast chess opening",
    "celebrity gossip movie release schedule",
    "espresso machine grinder burr alignment",
]


def dcg(relevance):
    return sum((2 ** rel - 1) / math.log2(index + 2) for index, rel in enumerate(relevance))


def evaluate_case(case, top_k):
    results = rag_query(case["query"], top_k=top_k)
    expected = set(case["expected_files"])
    relevance = [1 if result["file"] in expected else 0 for result in results]
    hit_rank = next((index + 1 for index, rel in enumerate(relevance) if rel), None)
    ideal_relevance = sorted(relevance, reverse=True)
    ndcg = dcg(relevance) / dcg(ideal_relevance) if any(ideal_relevance) else 0.0

    return {
        "query": case["query"],
        "expected_files": sorted(expected),
        "top_files": [result["file"] for result in results],
        "hit": hit_rank is not None,
        "rank": hit_rank,
        "reciprocal_rank": 1.0 / hit_rank if hit_rank else 0.0,
        "ndcg": round(ndcg, 4),
    }


def evaluate_no_hit(query, top_k):
    results = rag_query(query, top_k=top_k)
    return {
        "query": query,
        "result_count": len(results),
        "top_files": [result["file"] for result in results],
        "passed": len(results) == 0,
    }


def main():
    top_k = 5
    golden_results = [evaluate_case(case, top_k) for case in GOLDEN_CASES]
    no_hit_results = [evaluate_no_hit(query, top_k) for query in ADVERSARIAL_NO_HIT_CASES]

    positive_count = len(golden_results)
    hit_count = sum(1 for result in golden_results if result["hit"])
    hit_rate = hit_count / positive_count if positive_count else 0.0
    mrr = sum(result["reciprocal_rank"] for result in golden_results) / positive_count if positive_count else 0.0
    mean_ndcg = sum(result["ndcg"] for result in golden_results) / positive_count if positive_count else 0.0
    no_hit_accuracy = sum(1 for result in no_hit_results if result["passed"]) / len(no_hit_results)

    pass_thresholds = {
        "hit_rate_at_5_min": 0.80,
        "mrr_min": 0.45,
        "ndcg_at_5_min": 0.70,
        "no_hit_accuracy_min": 1.00,
    }

    passed = (
        hit_rate >= pass_thresholds["hit_rate_at_5_min"]
        and mrr >= pass_thresholds["mrr_min"]
        and mean_ndcg >= pass_thresholds["ndcg_at_5_min"]
        and no_hit_accuracy >= pass_thresholds["no_hit_accuracy_min"]
    )

    summary = {
        "status": "PASSED" if passed else "FAILED",
        "top_k": top_k,
        "positive_cases": positive_count,
        "adversarial_no_hit_cases": len(no_hit_results),
        "metrics": {
            "hit_rate_at_5": round(hit_rate, 4),
            "mrr": round(mrr, 4),
            "ndcg_at_5": round(mean_ndcg, 4),
            "no_hit_accuracy": round(no_hit_accuracy, 4),
        },
        "thresholds": pass_thresholds,
        "golden_results": golden_results,
        "no_hit_results": no_hit_results,
    }

    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(SUMMARY_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")

    print("==================================================")
    print("LOCAL DOSSIER RETRIEVAL EVAL")
    print("==================================================")
    print(f"* Positive cases: {positive_count}")
    print(f"* Adversarial no-hit cases: {len(no_hit_results)}")
    print(f"* Hit rate@5: {summary['metrics']['hit_rate_at_5']}")
    print(f"* MRR: {summary['metrics']['mrr']}")
    print(f"* NDCG@5: {summary['metrics']['ndcg_at_5']}")
    print(f"* No-hit accuracy: {summary['metrics']['no_hit_accuracy']}")
    print(f"* Status: {summary['status']}")
    print(f"* Summary written: {SUMMARY_PATH}")
    print("==================================================")

    if not passed:
        print("[FAIL] Retrieval eval thresholds were not met.", file=sys.stderr)
        for result in golden_results:
            if not result["hit"]:
                print(f"- Miss: {result['query']} -> {result['top_files']}", file=sys.stderr)
        for result in no_hit_results:
            if not result["passed"]:
                print(f"- False positive: {result['query']} -> {result['top_files']}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
