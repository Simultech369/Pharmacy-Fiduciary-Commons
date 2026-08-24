# AI Systems Concept Coverage

Status: planning and review-control surface. This file maps recent AI-systems topic lists into repo-local evidence and gaps. It is not production architecture, provider approval, or a claim that these systems are fully implemented.

Snapshot for this coverage pass:

- Repo: `C:\Users\Josh\Desktop\PBMRebateTreasuryFinal`
- Branch / HEAD baseline when prepared: `main` (`[dirty working tree]`)
- Worktree after this pass: dirty; latest local check on 2026-08-24 showed
  `34` visible `git status --short` entries (`21` modified, `13` untracked).
- 2026-08-24 reconciliation note: after the repo-local gateway/Gate 0 promotion
  slice, `python scripts\verify_all.py` passed `9/9` and refreshed
  `cache\verification_master_receipt.json` at `2026-08-24T13:21:33Z`. That
  receipt recorded Hardhat `387 passing`, PageIndex `34` dirty/untracked with
  `0` contradictions, RAG eval `26` positive cases and `8` adversarial no-hit
  cases, and Agent Claim Lie Detector `40` claims with `0` violations.
- Scratch council engine note: later on 2026-08-24, the expanded scratch suite
  passed `208` tests in `113.826s`; current scratch count was `56` non-test
  Python files and `47` `test_*.py` suites.

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
| Production RAG with citations | Partial local prototype: `scripts/dossier_rag_retrieval.py` retrieves Markdown passages with line citations. Latest receipt-backed eval observed 26 positive cases and 8 adversarial no-hit queries. | No PDF parsing, page numbers, neural embeddings, true cross-encoder reranker, parent-document retrieval, web fallback, or 50+ golden cases. | Expand retrieval eval to 50 repo-specific cases and add metadata filter tests before naming it production RAG. |
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
| Streaming copilot UI | Local prototype dashboard has completed-response RAG API support through `scripts/serve-dashboard.js`. | No token streaming, optimistic UI, or streaming error recovery. | Do not add streaming until the dashboard has a real user workflow needing it. |
| Fine-tuning with LoRA | Not addressed. | No dataset, training objective, before/after eval, DPO, or forgetting checks. | Park. This repo needs deterministic proof and privacy boundaries more than fine-tuning. |
| Multi-tenant SaaS agent | Local Supabase schema/RLS policy simulation and tests cover part of tenant isolation. | No Stripe billing, per-tenant usage accounting, production PostgREST exercise, or SaaS auth flow. | Finish production RLS/PostgREST verification before billing or SaaS agent work. |
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

## 2026-08-24 LLM Engineering Roadmap Reconciliation

Source posture: user-supplied Antigravity matrix over two AI-engineering topic
lists. This section records a local calibration against the PBM repo and the
external scratch council engine. It is a roadmap and proof-depth map, not a
production-readiness claim.

### Immediate Build Order

1. **Verify and extend the repo-local gateway, context assembly, and guardrail
   slice.**
   `scripts\council_orchestrator.py` now has a deterministic no-network
   `ModelGateway.invoke_with_resilience()` simulation, Gate 0 preflight, and
   log-derived wire-payload reconstruction for qualification probes. The next
   step is full receipt refresh, then only later live routing, retries, circuit
   breakers, hosted ZDR evidence, and disclosure-class policy.

2. **Finish proof-boundary cleanup before new product surface.**
   Keep strengthening `ExecutionSandboxReceipt`, `ApplyAuthorizationReceipt`,
   route attestation, and generated receipt wording. Live production apply must
   require container-enforced isolation plus real interactive HMAC approval
   evidence.

3. **Add deterministic cache and deduplication before neural semantic cache.**
   The repo already chunks and evaluates local dossier retrieval. The next
   useful cost-saving layer is stable content hashes, prompt hashes, and
   no-repeat review packet reuse. Embedding similarity cache can follow only
   after access-control and false-positive tests exist.

4. **Start multimodal document intake as a bounded proof slice.**
   Vision-language adapters apply to scanned PBM tables, formulary grids,
   invoices, and PDFs. Start with deterministic extraction fixtures and
   redaction checks; do not route real PHI/PII or private claims through hosted
   vision models.

5. **Treat streaming and async queues as operator-experience hardening, not the
   next proof primitive.**
   Scratch `council_api_server.py` has SSE formatting and the scratch runtime has
   DLQ/checkpoint primitives. Promote them after the proof-boundary and gateway
   slices, when the dashboard has a real long-running council workflow to show.

### First Topic List Calibration

| Topic bucket | Project status | Calibration |
| --- | --- | --- |
| Tokenizer, RoPE/ALiBi, hand-wired attention, MHA, Transformer blocks, mini-former training | Park | These are base-model internals. They do not improve fiduciary proof, Solidity solvency, or receipt truthfulness right now. |
| Embeddings | Implement further | Retrieval applies, but the repo currently uses deterministic lexical/TF-IDF-style retrieval rather than a durable neural embedding lifecycle. Add dense embeddings only behind metadata-filter and no-hit tests. |
| Objective comparison, SFT/DPO/RLHF/GRPO | Narrowly apply | Scratch `rlvr_ruler_reward_engine.py` models RLVR/RULER-style rewards. Use RLVR only for verifiable invariant breaking, compiler/proof checks, or formal verification. Park SFT/RLHF on auditor seats to preserve independent dissent. |
| Sampling, KV cache, speculative decoding, quantization, serving stacks, hardware budgets | Implement selectively | Gateway sampling controls and local quantized model inventory are relevant. Speculative decoding and KV-cache work should wait for measured local inference bottlenecks; prompt/content dedup is cheaper and safer first. |
| Long context | Partial / planning | Roster docs name long-context lanes, but a roster entry is not proof. Count this only when a live route produces receipt-backed review output on an allowed disclosure class. |
| Data pipelines and synthetic data | Addressed / implement further | Repo dossier indexing and review-packet compilation are real. Scratch red-team and PBM fraud specs add synthetic fixtures. Promote only tests tied to active PBM claims. |
| Eval harnesses, RAG, tool use / agents, red-team suite | Core pillar | These are the strongest fit: `scripts\verify_all.py`, `scripts\verify_agent_claims.py`, `scripts\dossier_rag_retrieval.py`, `scripts\eval_dossier_rag.py`, repo `scripts\council_orchestrator.py`, and scratch council/red-team modules. |
| Vision-language adapters | Start | Needed for scanned PBM evidence, but must begin with sanitized fixtures, OCR/table extraction proof, and prompt-injection gates. |
| Interpretability | Limited scratch utility | Scratch reasoning-trace extraction can help debug reviewer outputs, but hidden chain-of-thought should not become governance proof. Use only structured, admissible explanations and receipt-backed findings. |
| Full capstone model system | Prototype / control plane | The PBM Treasury plus scratch Council Engine is a capstone-style integrated system, but production status still depends on proof-boundary, deployment, data-retention, and approval-gate completion. |

### Fifteen Backend Systems Calibration

| # | System | Current status | Next implementation action |
| --- | --- | --- | --- |
| 1 | LLM gateway / proxy | Scratch implemented; repo-local partial/no-network promotion | Keep the new `ModelGateway.invoke_with_resilience()` simulation receipt-backed, then add retries, circuit breakers, route attestation, and ZDR boundaries only with live provider evidence. |
| 2 | Token metering / billing | Budget metering scratch; billing parked | Keep SQLite-style budget reservations for paid model dispatch. Do not add Stripe billing unless this becomes a tenant SaaS product. |
| 3 | Streaming response infrastructure | Scratch prototype | Add SSE/WebSocket backpressure only after dashboard workflows need real-time jury traces. |
| 4 | RAG serving pipeline | Repo local prototype | Add incremental indexing, metadata filters, larger evals, and scanned-doc fixtures before calling it production RAG. |
| 5 | Semantic cache layer | Not yet production | Start with deterministic prompt/content-hash cache and duplicate packet suppression; add embedding cache later. |
| 6 | Async agent job queue | Scratch implemented | Promote checkpoint + DLQ semantics for long-running council jobs only after gateway proof is repo-local. |
| 7 | Tool execution sandbox | Scratch implemented; repo proof boundary hardened | Keep negative tests for mock/live isolation, then require live Docker/Podman evidence for production apply. |
| 8 | Multi-tenant knowledge base | Partial / scratch | Do not overclaim. Add row-level metadata filtering tests before storing tenant-specific vectors or claims. |
| 9 | Prompt and config versioning | Partial | Convert prompt/model/config hashes into a small registry with rollback and receipt linkage. |
| 10 | Eval pipeline backend | Repo core pillar | Maintain `verify_all.py` as the master gate; keep durable observed counts in receipts. |
| 11 | Observability for LLM traffic | Repo and scratch local | Keep local receipts and JSON summaries now; add OpenTelemetry-style traces only at service boundaries. |
| 12 | Webhook and event fan-out | Scratch transport only | Add signed external webhooks later. Current TCP/Merkle gossip is not Ed25519-authenticated webhook infrastructure. |
| 13 | Context assembly service | Scratch implemented; repo-local partial/no-network promotion | Log-derived reconstruction checks now guard the local gateway demo and qualification probes; extend them before any external model dispatch from repo workflows. |
| 14 | Guardrails middleware | Scratch implemented; repo-local Gate 0 partial promotion | Gate 0 prompt-injection rejection is covered locally; PII/PHI redaction, domain policy, and L3 lifecycle hooks still need repo CLI/runtime promotion. |
| 15 | Model fallback and routing | Scratch implemented; repo fallback not proven | Keep fallback/routing as future work behind disclosure-class and budget checks. No live provider dispatch, hosted ZDR attestation, or paid model call is proven by the repo-local gateway simulation. |

### Parked By Default

Do not spend PBM implementation cycles on custom tokenizer construction,
from-scratch Transformer internals, CUDA/Triton/FlashAttention, toy MoE routing,
state-space architecture experiments, diffusion language models, scaling-law
research, or SFT/RLHF of governance auditor seats. These may be useful learning
projects, but they are not the current fiduciary control-plane bottleneck.
