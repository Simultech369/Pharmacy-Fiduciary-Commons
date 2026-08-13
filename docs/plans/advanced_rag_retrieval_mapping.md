# Advanced RAG Techniques and PageIndex Retrieval Mapping

> **Status**: DESIGN MAP / PROOF-BOUNDED ROADMAP
> **Domain**: PageIndex dossier auditing, local retrieval, context density, and lineage evals
> **Evidence Lineage**: `[dirty working tree]`

This document maps advanced RAG ideas onto the current Pharmacy-Fiduciary-Commons repository without turning adjacent prototypes into production claims.

Current local proof: `scripts/dossier_rag_retrieval.py` is a dependency-free lexical retrieval harness with Markdown section chunking, simple query expansion, TF-IDF-like lexical vector scoring, sparse overlap scoring, deterministic bonus reranking, and line-anchored citations. `scripts/eval_dossier_rag.py` evaluates 12 golden repo questions and 4 adversarial no-hit queries. This is useful local evidence, not production RAG infrastructure.

## 1. Useful Borrow

The most useful borrow is the implementation order, not the whole catalogue:

1. Strengthen semantic-ish section chunking and lexical hybrid retrieval first.
2. Add reranking and parent-document return behavior after the retrieval baseline is measurable.
3. Add query decomposition and HyDE only for hard, multi-hop review questions.
4. Add corrective retrieval and larger evals before adding any production-facing retrieval surface.

For this repo, the RAG lane should remain subordinate to the single-agent control plane: deterministic tools detect proof signals, the knowledge graph bounds traversal, models act as narrow sensors, and human approval gates decide promotion.

## 2. Calibrated Technique Matrix

| # | Technique | Current PBM Surface | Calibrated Status |
| :--- | :--- | :--- | :--- |
| 1 | Contextual Retrieval | `scripts/dossier_rag_retrieval.py`, `cache/dossier_tree_index.json` | **Partial local analogue**: chunks include file, section, and line metadata. No LLM-generated per-chunk context preamble is claimed. |
| 2 | Hybrid Search + RRF | `scripts/dossier_rag_retrieval.py` | **Partial local analogue**: lexical vector score, sparse overlap, title, and phrase bonuses are combined deterministically. No BM25 library, dense embedding index, or reciprocal rank fusion is claimed. |
| 3 | Cross-Encoder Reranking | `scripts/dossier_rag_retrieval.py`, `scripts/rehearse_proposal.py` | **Not implemented**: deterministic scoring and failure-memory ranking exist, but no cross-encoder or external reranker is used. |
| 4 | HyDE | `review-context/packet-*.json` | **Design candidate**: hypothetical proof-state prompts could be generated for hard queries. No HyDE embedding flow is implemented. |
| 5 | Query Decomposition | `docs/plans/single_agent_control_plane_review_loop.md` | **Design candidate**: the control-plane plan supports decomposed investigations. No automated decomposition-and-merge retriever is implemented. |
| 6 | Small-to-Big / Parent Document Retrieval | Markdown sections and line citations | **Partial local analogue**: retrieval returns section spans with citations. No explicit child-embedding to parent-document retrieval layer is claimed. |
| 7 | Late Chunking | None | **Out of scope**: no long-context encoder or pooled chunk embeddings. |
| 8 | ColBERT / Late Interaction | None | **Out of scope**: no token-level neural retrieval. |
| 9 | Semantic Chunking | Markdown header section parser | **Partial local analogue**: chunks follow document structure, not embedding breakpoint clustering. |
| 10 | Contextual Compression | `best_snippet()` in `scripts/dossier_rag_retrieval.py` | **Partial local analogue**: result snippets select the best matching line. No learned or LLM-based sentence compression is claimed. |
| 11 | Corrective RAG / CRAG | `scripts/eval_dossier_rag.py`, `scripts/context_hygiene_audit.py` | **Design candidate / adjacent gate**: evals and audits can fail closed. No retrieval confidence grader that rewrites queries or searches the web is implemented. |
| 12 | GraphRAG | `review-context/repo_knowledge_graph.json` | **Prototype control-plane graph**: repo nodes and proof edges bound investigation paths. No corpus-wide entity extraction, community detection, or community summaries are claimed. |
| 13 | RAPTOR | None | **Not implemented**: no recursive clustering, summary tree, or multi-level retrieval. |
| 14 | Lost-in-the-Middle Ordering | `.agents/AGENTS.md`, context hygiene plan | **Guidance only**: standing-brief pruning follows attention-density principles. No measured context ordering benchmark is claimed. |
| 15 | Retrieval Evals | `scripts/eval_dossier_rag.py`, `cache/dossier_rag_eval_summary.json` | **Implemented local eval**: 12 golden questions, 4 adversarial no-hit queries, hit-rate, MRR, and NDCG thresholds. Not a production benchmark. |

## 3. Explicit Non-Claims

- No neural embedding index, vector database, BM25 library, or reciprocal rank fusion implementation is claimed.
- No cross-encoder, ColBERT, late-interaction model, or learned reranker is claimed.
- No HyDE embedding workflow, automated query decomposition pipeline, CRAG web fallback, or production retrieval self-healing loop is claimed.
- No RAPTOR recursive clustering or GraphRAG community-summary pipeline is claimed.
- No production RAG deployment, PHI retrieval system, external document ingestion pipeline, or customer-facing knowledge infrastructure is claimed.

## 4. Staged PBM Retrieval Roadmap

**RAG-1: Baseline And Evals**

Keep the current local lexical retriever small and auditable. Expand `scripts/eval_dossier_rag.py` from 12 golden questions to 50 repo-specific cases before adding heavier infrastructure.

**RAG-2: Parent Sections And Disclosure Filters**

Add explicit parent-section return behavior and metadata filters for disclosure class, file freshness, and proof scope. This pairs naturally with PageIndex and the repo knowledge graph.

**RAG-3: True Hybrid Retrieval**

If retrieval becomes a real user-facing or reviewer-facing subsystem, add BM25 plus embeddings and compare fusion strategies against the expanded eval set.

**RAG-4: Hard-Query Techniques**

Only after RAG-3 passes evals, add HyDE, query decomposition, and corrective retrieval for multi-hop review questions. These should remain bounded by `review-context/repo_knowledge_graph.json`.

**RAG-5: Advanced Neural Retrieval**

Treat ColBERT, late chunking, cross-encoders, RAPTOR, and full GraphRAG as optional experiments, not default dependencies. They should earn their place by improving measured retrieval quality under a known runtime and disclosure budget.
