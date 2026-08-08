# AI Systems Concept Coverage

Status: planning and review-control surface. This file maps recent AI-systems topic lists into repo-local evidence and gaps. It is not production architecture, provider approval, or a claim that these systems are fully implemented.

Snapshot for this coverage pass:

- Repo: `C:\Users\Josh\Desktop\PBMRebateTreasuryFinal`
- Branch / HEAD when prepared: `feature/db-proxy` @ `6dc01cb81a859e18eaed520c40b51c9622a04937`
- Worktree after this pass: expected dirty until the retrieval-eval slice is committed or reverted

## Weakest Valid Claim Rule

The useful lesson from Michael Timothy Bennett's paper, "The Optimal Choice of Hypothesis Is the Weakest, Not the Shortest" (`https://arxiv.org/abs/2301.12987`), is operational rather than mystical: when a review loop learns from execution feedback, it should prefer the weakest valid claim supported by evidence.

For this repo, that means:

- "line-cited local dossier retrieval with a small eval" is valid;
- "production RAG with page-number citations" is not yet valid;
- "advisory review harness" is valid;
- "autonomous agent governance" is not valid;
- "local benchmark harness" is valid;
- "10k RPS production service" is not valid.

## Coverage Matrix

| Topic | Current repo coverage | Gap before stronger claim | Next useful slice |
|---|---|---|---|
| Production RAG with citations | Partial local prototype: `scripts/dossier_rag_retrieval.py` retrieves Markdown passages with line citations. `scripts/eval_dossier_rag.py` measures 12 golden questions and 4 adversarial no-hit queries. | No PDF parsing, page numbers, neural embeddings, true cross-encoder reranker, parent-document retrieval, web fallback, or 50+ golden cases. | Expand retrieval eval to 50 repo-specific cases and add metadata filter tests before naming it production RAG. |
| Hybrid search | Partial local lexical hybrid: TF-IDF cosine plus sparse token overlap and deterministic reranking. | No dense embedding index, BM25 library, SQLite-vec, Qdrant, Weaviate, ColBERT, or late interaction. | Keep dependency-free local retrieval for governance docs; add vector DB only if retrieval becomes user-facing infrastructure. |
| Query expansion and rewriting | Small deterministic PBM synonym expansion in `scripts/dossier_rag_retrieval.py`. | No LLM query rewrite, ambiguity classifier, or learned expansion model. | Add fixed ambiguity fixtures first; avoid model-based rewriting until adversarial no-hit tests are strong. |
| Citation grounding | Local line-anchored citations and JSON output with `source_url`, `section_title`, and line range. | No answer generator validates that every sentence is supported by cited passages. | Add a citation-grounding checker if generated answers are introduced. |
| Retrieval metrics | `scripts/eval_dossier_rag.py` reports hit rate@5, MRR, NDCG@5, and no-hit accuracy. | Golden set is small and local-doc-only. | Grow the golden set; keep thresholds modest until coverage broadens. |
| Cost-optimized model router | Review router metadata and provider receipts exist in `reviews/*-router-metadata.json`. | No live cost/latency/quality router, spend budget, model fallback policy, or per-request accounting. | Keep as review-only until provider credentials, disclosure class, and cost ceilings are explicit. |
| Multi-agent research system | Review packet compiler, PageIndex, observability dashboard, and external reviewer lanes exist. | No autonomous merge, no multi-agent supervisor, no durable task queue, and no model output as truth. | Preserve the human-gated council pattern; add structural effects only to reject/quarantine handoffs, not to act on-chain. |
| Automated eval harness | Strong for contracts and control surfaces: Hardhat, frontend linter, PageIndex, constitutional rubric, observability gate, and local RAG eval. | Not a general DeepEval/RAGAS/LangSmith setup. | Add only evals tied to active repo claims. |
| Real-time observability | Local receipts, summary JSON, and benchmark reports. | No OpenTelemetry, Prometheus, Grafana, alerting, or hosted tracing. | Keep local JSON receipts until there is a real service boundary. |
| Security guardrail middleware | Public-form threat tests, packet forbidden-input rules, credential parser checks, and review-rubric gates exist. | No Promptfoo suite, WAF, hosted moderation, or runtime prompt-injection proxy. | Add hostile artifact fixtures before external prompt injection tooling. |
| Local-first development | Local scripts, Hardhat, static dashboard, offline continuity tools, and no-cost retrieval eval. | No Ollama + SQLite-vec/FastAPI/LanceDB/Docker mirror. | Use local-first only where it reduces disclosure or cost; avoid new stacks for resume value alone. |
| Streaming copilot UI | Dashboard has local completed-response RAG API support through `scripts/serve-dashboard.js`. | No token streaming, optimistic UI, or streaming error recovery. | Do not add streaming until the dashboard has a real user workflow needing it. |
| Fine-tuning with LoRA | Not addressed. | No dataset, training objective, before/after eval, DPO, or forgetting checks. | Park. This repo needs deterministic proof and privacy boundaries more than fine-tuning. |
| Multi-tenant SaaS agent | Supabase schema/RLS and JS policy simulation cover part of tenant isolation. | No Stripe billing, per-tenant usage accounting, production PostgREST exercise, or SaaS auth flow. | Finish production RLS/PostgREST verification before billing or SaaS agent work. |
| CI/CD for AI systems | GitHub Actions and local `scripts/verify_all.py` cover deterministic gates. | No canary, rollback, ArgoCD, feature flags, or quality-drop deployment rollback. | Do not add deployment automation until production readiness gates pass. |
| Vector DB at scale | Not implemented. | No million-vector index, metadata filters, backup/recovery, or shard planning. | Park until actual retrieval corpus size demands it. |
| Agent memory system | Review/process docs describe claim memory discipline. | No Redis/vector memory, eviction policy, or cross-session app memory. | Keep memory as explicit docs and receipts; avoid hidden agent memory for fiduciary claims. |
| Production inference server | Not implemented. | No vLLM/SGLang/Kubernetes/KV cache/quantization/load balancing. | Park unless the review swarm itself becomes a sustained inference service. |
| Human-in-the-loop workflow | Strong process coverage in `REVIEW_ITERATION_PROCESS.md` and `AGENT_REVIEW_ORCHESTRATION.md`. | No approval UI or durable pause/resume workflow engine. | Good enough for now; humans remain the merge/governance gate. |
| Agentic automation pipeline | Local dry-run scripts exist. | No Celery, dead-letter queue, webhook intake, or async retry engine. | Only add queues for a real recurring operation such as voucher cleanup monitoring. |
| Domain benchmark / public leaderboard | Contract tests, PageIndex, and local RAG eval are repo-specific benchmarks. | No public leaderboard or standardized external benchmark. | Publish only after claims are stable and the benchmark cannot leak sensitive context. |
| Open-source contribution workflow | Review-only process and clean-room intake rule exist. | No external PR workflow for LangGraph/CrewAI/LlamaIndex/etc. | Treat external skill extraction as a separate repo/workflow, not PBM readiness. |

## Council Role Mapping For External Skill Intake

The scout/filter/reader/extractor/score/generator/reviewer/publisher pattern is useful for external tools, skills, and repository lessons. It should remain separate from PBM readiness:

- `scout`: finds candidate repositories or papers.
- `filter`: rejects hype, unclear licenses, unsafe scope, or no local fit before any model spends context.
- `reader`: reads docs and intent before source code.
- `extractor`: pulls a reusable workflow pattern, not copied code.
- `score`: checks objective criteria and kills weak candidates.
- `generator`: packages a repo-local skill or prompt with examples, commands, and tests.
- `reviewer`: asks whether an experienced engineer would install it without editing.
- `publisher`: opens a PR only after human approval.

Automation proposes. Humans approve. Nothing merges automatically.

## Model Roster Boundary

The 45-model roster in `review-context/SWARM_ROSTER_40_MODELS.md` is a planning map, not an availability guarantee. A model may be listed only as a possible reviewer/harness role until a live route proves:

- provider availability;
- model identifier;
- disclosure class allowed for the packet;
- cost and rate-limit ceiling;
- receipt metadata;
- output reconciliation against local evidence.

