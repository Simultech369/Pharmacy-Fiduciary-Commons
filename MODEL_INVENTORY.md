# Master Model Roster & Classification Catalog (v4.4.1)

This catalog maintains the active/candidate model roster, execution harnesses, provider routes, sensitivity compliance tiers, and qualification statuses under the Council receipt verification architecture.

**Last live upstream refresh:** 2026-08-24 (post-internet-restore refresh; SuperQwen3.8 candidate added)  
**Operator rule:** A model or harness entry is not promoted to dispatch merely because upstream exists. It must still clear the local `ModelQualificationReceipt`, route-attestation, spend, privacy, and lifecycle-hook gates.

---

## Tier Summary Matrix

| Tier | Category | Count | Primary Role | Routing & Policy |
| :--- | :--- | :---: | :--- | :--- |
| **Tier 0** | **Apex Paid Judges** | 5 | Escalation, tie-breaking, high-stakes arbitration | `APEX_PAID`, SQLite Ledger reservation required |
| **Tier 1** | **Frontier Cloud & SOTA Specialists** | 12 | Primary synthesis, cybersecurity audit, 1M context | `HOSTED_NO_TRAIN` / `PUBLIC_SAFE`, SiliconFlow/Groq/Google |
| **Tier 2** | **Local OSS Fast Workers & Reasoners** | 14 | Rapid local audit, syntax verification, local quorum | `LOCAL_ONLY_VERIFIED`, Air-gapped Ollama |
| **Tier 3** | **Uncensored Adversarial Scouts** | 8 | Pre-dispatch red-teaming, hostile fuzzing, refusal-boundary probing | `LOCAL_ONLY_VERIFIED` / `CANDIDATE_LOCAL_VLLM`, Jiunsong, OrcaRouter & Hermes lineages |
| **Tier 4** | **Quarantined / Defunct Legacy** | 5 | Archived / Purged (Non-models or obsolete weights) | `QUARANTINED`, Blocked from council dispatch |

---

## Detailed Model Catalog

### 👑 Tier 0: Apex Paid Judges (Escalation & Arbitration)
*Requires `PaidBudgetReservationReceipt` + human apply confirmation.*

1. **`openai/gpt-5.6-sol`** — *OpenAI API / Azure* | Apex Reasoning Judge & Final Synthesizer (`APEX_PAID`, ZDR)
2. **`openai/gpt-5.3-codex`** — *OpenAI API* | Apex Code AST & Formal Verification (`APEX_PAID`, ZDR)
3. **`anthropic/claude-3.7-sonnet-thought`** — *Anthropic Bedrock* | Deep Hybrid Thinking & Refactor Arbiter (`APEX_PAID`, ZDR)
4. **`google/gemini-3.1-pro-preview`** — *Google AI Studio / Vertex* | 2M Context Complex Architecture Judge (`APEX_PAID`, ZDR)
5. **`openai/o3-high`** — *OpenAI API* | Mathematical & Security Proof Specialist (`APEX_PAID`, ZDR)

---

### 🚀 Tier 1: Frontier Cloud & SOTA Open Models (Zero-Cost / High Rate-Limit)
*Cloud endpoints via SiliconFlow, Groq LPU, OpenRouter, and Google AI Studio.*

6. **`qwen/qwen-3.8-coder`** — *SiliconFlow / OpenRouter* | **Frontier SOTA**: Multi-turn patch synthesis & complex reasoning (`HOSTED_NO_TRAIN`, ZDR)
7. **`qwen/qwen3.6-27b`** — *Groq LPU / SiliconFlow* | Ultra-fast LPU inference (600+ tok/s), high-speed voter (`HOSTED_NO_TRAIN`, ZDR)
8. **`zhipu/glm-5.3`** — *SiliconFlow* | **Cybersecurity & Vulnerability SOTA**: Critical finding veto seat (`HOSTED_NO_TRAIN`, ZDR)
9. **`zhipu/glm-4.7-flash`** — *SiliconFlow / OpenRouter* | 200k context high-throughput reviewer (`HOSTED_NO_TRAIN`, ZDR)
10. **`google/gemini-3.6-flash`** — *Google AI Studio* | 1M Context repo-wide diff & artifact slicer (`PUBLIC_PROVENANCE_ONLY`)
11. **`google/gemini-3.5-flash-lite`** — *Google AI Studio* | Low-latency preliminary triage & classifier (`PUBLIC_PROVENANCE_ONLY`)
12. **`deepseek/deepseek-v3`** — *SiliconFlow* | 671B MoE Frontier Generalist (`HOSTED_NO_TRAIN`, ZDR)
13. **`deepseek/deepseek-v4-flash`** — *SiliconFlow* | High-density fast code reviewer (`HOSTED_NO_TRAIN`, ZDR)
14. **`openai/gpt-oss-120b`** — *Groq LPU* | Open-weight frontier transformer (`HOSTED_NO_TRAIN`, ZDR)
15. **`mistralai/mistral-large-2411`** — *Mistral API* | European multi-lingual symbolic reasoning (`HOSTED_NO_TRAIN`, ZDR)
16. **`stepfun/step-3.5-flash-2603`** — *StepFun API* | Fast multi-step logic & tool call validation (`HOSTED_NO_TRAIN`)
17. **`moonshot/kimi-k1.5-preview`** — *Moonshot API* | Long-context repo reasoning (`HOSTED_NO_TRAIN`)

---

### 💻 Tier 2: Local OSS Fast Workers & Reasoners (Air-Gapped Ollama / Localhost)
*Air-gapped local execution on Windows GPU/CPU with zero data leakage.*

18. **`qwen2.5-coder:7b`** — *Ollama Local* | Qualified Tier-2 Voter (Passed Gates 2 & 3) (`LOCAL_ONLY_VERIFIED`)
19. **`qwen2.5-coder:14b`** — *Ollama Local* | Intermediate local coder (`LOCAL_ONLY_VERIFIED`)
20. **`qwen2.5-coder:32b`** — *Ollama Local* | Heavyweight local code synthesizer (`LOCAL_ONLY_VERIFIED`)
21. **`deepseek-r1:7b`** — *Ollama Local* | Local reasoning with `<think>` trace extraction (`LOCAL_ONLY_VERIFIED`)
22. **`deepseek-r1:1.5b`** — *Ollama Local* | Ultra-fast local scout & triage (`LOCAL_ONLY_VERIFIED`)
23. **`deepseek-r1:14b`** — *Ollama Local* | Deep reasoning local auditor (`LOCAL_ONLY_VERIFIED`)
24. **`glm4:latest`** — *Ollama Local* | Qualified Tier-2 Voter (Passed Gates 2 & 3) (`LOCAL_ONLY_VERIFIED`)
25. **`mistral:latest`** — *Ollama Local* | Qualified Tier-2 Voter (Passed Gates 2 & 3) (`LOCAL_ONLY_VERIFIED`)
26. **`mistral-nemo:12b`** — *Ollama Local* | Tekken tokenizer symbolic code auditor (`LOCAL_ONLY_VERIFIED`)
27. **`gemma3:4b`** — *Ollama Local* | Google local lightweight scout (`LOCAL_ONLY_VERIFIED`)
28. **`gemma3:12b`** — *Ollama Local* | Google local mid-weight auditor (`LOCAL_ONLY_VERIFIED`)
29. **`llama3.1:8b`** — *Ollama Local* | Meta standard instruction follower (`LOCAL_ONLY_VERIFIED`)
30. **`microsoft/phi-4:14b`** — *Ollama Local* | High-density synthetic math & formal logic reasoner (`LOCAL_ONLY_VERIFIED`)
31. **`ibm/granite3.1-dense:8b`** — *Ollama Local* | Enterprise contract & governance auditor (`LOCAL_ONLY_VERIFIED`)

---

### 🎭 Tier 3: Uncensored Adversarial Red-Team Scouts (Jiunsong & Hermes Lineages)
*Uncensored local/vLLM candidates built specifically to generate hostile payloads and fuzz verifiers without relying on RLHF refusals.*

32. **`Jiunsong/SuperGemma-4-12b-abliterated-gguf`** — *Local GGUF* | Uncensored vulnerability prober (`LOCAL_ONLY_VERIFIED`)
33. **`Jiunsong/supergemma4-26b-uncensored-gguf-v2`** — *Local GGUF* | Heavyweight uncensored agent fuzzer (`LOCAL_ONLY_VERIFIED`)
34. **`Jiunsong/SuperDeepseek-V4-Flash-abliterated`** — *Local GGUF* | DeepSeek abliterated red-teamer (`LOCAL_ONLY_VERIFIED`)
35. **`Jiunsong/SuperQwen-AgentWorld-35B-abliterated`** — *Local GGUF* | Qwen MoE abliterated tool tester (`LOCAL_ONLY_VERIFIED`)
36. **`Jiunsong/SuperQwen3.8-27b-abliterated`** — *HF Safetensors / vLLM-SGLang Candidate* | Full-BF16 Qwen3.8-derived multimodal, tool-capable, 1M-context-tested, refusal-reduced adversarial scout (`CANDIDATE_LOCAL_VLLM`, Apache-2.0; not deployed by HF Inference Providers)
37. **`orcarouter/Qwen3.8-27B-Uncensored`** — *HF / GGUF / FP8 / MLX Candidate* | Qwen3.8-derived 131-tensor edited uncensored model; rich quantization ecosystem with GGUF/FP8/MLX variants and hosted API path (`CANDIDATE_LOCAL_OR_HOSTED`, Apache-2.0; HF gated access form)
38. **`nousresearch/hermes3:8b`** — *Ollama Local* | Agentic steering & rule loophole specialist (`LOCAL_ONLY_VERIFIED`)
39. **`allenai/tulu3:8b`** — *Ollama Local* | Open-science unbiased adversarial evaluator (`LOCAL_ONLY_VERIFIED`)

---

### 🚫 Tier 4: Archived / Superseded Weights
*Legacy 2023 weights purged from active council rotation.*

39. **`WizardCoder-33B`** — *2023 Obsolete* (Superseded by Qwen 2.5/3.8 Coder)
40. **`Phind-CodeLlama-34B`** — *2023 Obsolete* (Superseded by modern base models)
41. **`StarCoder2-15B`** — *2023 Obsolete* (Superseded by Gemma/Mistral)
42. **`DBRX-Instruct`** — *Defunct Endpoint* (Inaccessible)
43. **`Snowflake-Arctic`** — *Defunct Endpoint* (Unmaintained)

---

## Agent Execution Harnesses & Universal Runtime Layer

These tools are not LLM voters; they form the **Execution & Tooling Shell** that orchestrates, drives, and connects our 38 active/candidate models to codebases and terminal execution.

| Harness / Tool | Upstream / Version Evidence | Role & Architectural Specialty | Council Integration Pattern |
| :--- | :--- | :--- | :--- |
| **`openclaude`** | [`Gitlawb/openclaude`](https://github.com/Gitlawb/openclaude); latest release checked: `v0.29.1` (GitHub 2026-08-19; npm `latest` 0.29.1 published 2026-08-20); local Windows launcher: `openclaude.cmd 0.29.1` | **Universal Provider Bridge**: one terminal-first CLI across OpenAI-compatible APIs, Gemini, GitHub Models, Codex OAuth/Codex, Ollama, Atomic Chat, and provider profiles. Current provider surface includes Gitlawb Opengateway, Z.AI GLM Coding Plan, AI/ML API, Concentrate, ApiSmart, Hicap, Fireworks, LongCat, ClinePass, OpenCode Zen/Go, Xiaomi MiMo, NEAR AI, Cloudflare Workers AI, and Bedrock/Vertex/Foundry. | Preferred Windows launcher is `openclaude.cmd` because `.ps1` is blocked by execution policy. Use as a provider/harness bridge for independent review, background sessions, repo-map context, web search/fetch, and headless gRPC experiments. |
| **`zero`** | [`Gitlawb/zero`](https://github.com/Gitlawb/zero); latest release checked: `v0.8.0` (GitHub 2026-08-21; npm `latest`/`platform` 0.8.0) | **Go Headless Runner / Agent Workbench**: current upstream has `zero exec`, `zero models`, `zero providers`, `zero doctor`, `zero context`, deterministic `repo-map`, sessions/fork/rewind, spec mode, specialists, skills/plugins, lifecycle hooks, MCP serving, sandbox inspection, worktrees, verification, changes/commit, usage, cron, update, and upgrade. | Use for no-edits review passes, proof-vs-theater disruption reviews, isolated worktree tasks, and fast provider/model inventory checks. Current upstream release also added live model lists for OpenRouter and OpenGateway and hardened sandbox/credential handling. |
| **`agent-reach`** | [`Panniantong/Agent-Reach`](https://github.com/Panniantong/agent-reach); latest release checked: `v1.5.0` (2026-06-11) | **Zero-API-Cost Evidence Reach**: CLI capability layer for GitHub, YouTube, Reddit, web/Jina, RSS, Exa, and social/video channels with `doctor` diagnostics and primary/fallback backend routing. | Wrapped by `agent_reach_adapter.py`; all acquired content must pass lifecycle hooks, domain guards, and prompt-injection sanitization before RAG/council context admission. Local `agent-reach` CLI was not found on PATH in this pass, so adapter tests remain the current proof surface. |
| **`OpenPipe ART / RULER`** | [`OpenPipe/ART`](https://github.com/OpenPipe/ART), RULER docs, and PyPI `openpipe-art==0.5.18` (uploaded 2026-05-23) | **Training Harness**: GRPO agent training with trajectory rewards; RULER ranks grouped trajectories with an LLM judge and returns 0..1 rewards for GRPO. | Bridged by `rlvr_ruler_reward_engine.py`; Council emits deterministic RLVR rewards or validates externally supplied RULER-style grouped judge scores, then seals one scalar reward receipt per trajectory. |
| **`StateM`** | [`henryqin1997/statem`](https://github.com/henryqin1997/statem) and PyPI `statem==0.2.0` (uploaded 2026-08-01; repo pushed 2026-08-20) | **Long-Run State Machine**: checked transitions, durable runtime history, dynamic checks, resume/compaction prompts, and explicit plan/execute/verify/handoff phases. | Bridged by `statem_runbook_bridge.py`; exports a StateM-compatible Council implementation loop with verification gates and sealed export receipt. Local `statem` CLI was not found on PATH in this pass. |
| **`aeon`** | [`aeonfun/aeon`](https://github.com/aeonfun/aeon); docs at [`aeon.fun/docs`](https://www.aeon.fun/docs) | **Pattern Source Only**: GitHub-Actions-backed autonomous skill runner with `aeon.yml` schedules, skill health checks, self-improvement loops, dashboard control plane, repo memory, and GitHub-as-API fleet model. | `PATTERN_SOURCE_ONLY`, MIT-style low-friction candidate if license confirmed in local clone. Borrow ideas for scheduled skill config, health/doctor loops, two-repo public-template/private-instance separation, and operator dashboard UX. Do not vendor or depend on it without a clone review. |
| **`MiroShark`** | [`MiroShark/MiroShark`](https://github.com/MiroShark/MiroShark) | **Pattern Source Only**: Universal swarm simulation engine using grounded personas, Neo4j graph memory, OpenAI-compatible or local Ollama inference, Docker/Compose setup, and report/cached-analysis loops. | `PATTERN_SOURCE_ONLY`, AGPL-3.0. Study architecture for persona-grounded simulations, graph-backed agent memory, pause/resume/report flows, and swarm dashboards. Do not copy code into Council without explicit license review and clean-room notes. |
| **`free-code`** | [`freecodexyz/free-code`](https://github.com/freecodexyz/free-code) | **Unshackled CLI Harness**: telemetry-minimal independent coding-agent shell for external review and bounty sprints. | Keep as an optional reviewer lane; use only with explicit no-edit/no-push prompts and receipt-backed reconciliation. |
| **`InclusionAI / Ling-V2`** | [`inclusionAI`](https://github.com/inclusionAI) | **Domain Specialist / AWorld**: Deep MoE architectures (`Ling-V2`, `GroveMoE`) and multi-agent world environments. | Candidate Tier 1/2 MoE reasoning seats and environment benchmarks; requires fresh qualification before dispatch. |
| **`Promptfoo`** | `promptfoo` | **Red-Team & Qualification Harness**: automated assertion evaluation for Model Qualification Gates 1, 2, and 3. | Test runner driving `ModelQualificationRunner`. |
| **`Aider` / `OpenHands`** | `aider` / `openhands` | **Interactive Pair-Programming & Benchmark Shells**: Git-aware diff generation and multi-agent benchmark replay. | Evaluation shell for patch generation comparison. |

### Local Harness Update Snapshot (Windows, 2026-08-24)

| Tool | Local command checked | Local version | Latest upstream checked | Status | Safe update / verify lane |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `openclaude` | `openclaude.cmd --version`; npm metadata refresh | `0.29.1` | GitHub `v0.29.1`; npm `latest` 0.29.1 | **VERSION CURRENT** | Verified `openclaude.cmd --version`; continue using `.cmd` instead of `.ps1` on this Windows machine. |
| `zero` | `zero.cmd --version`; `zero.cmd doctor`; npm metadata refresh | `0.8.0` | GitHub `v0.8.0`; npm `latest`/`platform` 0.8.0 | **VERSION CURRENT; DOCTOR FAIL** | `zero doctor` currently fails because ChatGPT provider credentials are not configured. It also warns that Windows sandbox setup is missing/out of date and that `gopls`, `pyright-langserver`, and `typescript-language-server` are missing from PATH. Remediation: run `zero sandbox setup` from an elevated shell, `npm install -g pyright typescript typescript-language-server`, and `go install golang.org/x/tools/gopls@latest` with `$GOBIN` on `PATH`. |
| `agent-reach` | `where.exe agent-reach`; prior `agent-reach --version` probe | Not found on PATH / version probe timed out | GitHub `v1.5.0` | **TRACKED; LOCAL CLI ABSENT** | Keep using `agent_reach_adapter.py` only with explicit CLI paths or mocked commands until `agent-reach doctor` passes locally. |
| `OpenPipe ART` | `where.exe art`; PyPI metadata refresh | Not found on PATH | PyPI `openpipe-art==0.5.18` | **TRACKED; LOCAL PACKAGE/CLI ABSENT** | Council bridge currently validates deterministic RLVR and externally supplied RULER-style grouped judge scores; install/package qualification is separate from receipt validation. |
| `StateM` | `where.exe statem`; PyPI metadata refresh | Not found on PATH | PyPI `statem==0.2.0` | **TRACKED; LOCAL CLI ABSENT** | `statem_runbook_bridge.py` exports StateM-compatible YAML without requiring the CLI. A real `statem` execution gate is still candidate-only until installed and qualified. |
| `Ollama` | `ollama --version`; `ollama list` | Client `0.30.10`; daemon not reachable | Local runtime only | **CLIENT PRESENT; LOCAL CATALOG BLOCKED** | `ollama list` did not complete because the client could not write/read its local log path. Do not refresh or promote local model seats until the daemon/log permission issue is resolved and a fresh qualification receipt exists. |

### External Pattern Repos To Clone For Borrowable Ideas

These are **not dependencies** and **not dispatch seats**. Clone them only into an isolated scratch path, inspect licenses, and translate patterns into Council-native code or specs. Apply `LICENSE_BORROWING_POLICY.md` before copying or closely adapting any external code, config, prompt, schema, asset, or model-serving artifact.

| Repo | Suggested clone path | Borrowable patterns | Guardrail |
| :--- | :--- | :--- | :--- |
| [`aeonfun/aeon`](https://github.com/aeonfun/aeon) | `C:\tmp\council-pattern-scouts\aeon` | Scheduled skill registry, GitHub Actions runner economy, `aeon-doctor` config linter, self-improvement/audit loops, dashboard-driven config edits, GitHub-as-control-plane/fleet API. | Verify license in local clone before reuse; prefer pattern translation over imports. |
| [`MiroShark/MiroShark`](https://github.com/MiroShark/MiroShark) | `C:\tmp\council-pattern-scouts\MiroShark` | Grounded persona generation, Neo4j graph memory, simulated social reaction swarms, pause/resume/restart lifecycle, cached report agents, Docker/Ollama deployment profiles. | AGPL-3.0: study architecture only unless Council explicitly adopts compatible licensing or clean-room reimplementation notes. |

### Live OSS Model Watch Findings (2026-08-24)

Upstream model availability remains **candidate-only** until route attestation, privacy classification, qualification receipts, and lifecycle-hook coverage pass locally.

| Family | Fresh upstream signal | Council action |
| :--- | :--- | :--- |
| Qwen | Qwen3-Coder includes `Qwen3-Coder-480B-A35B-Instruct`, `Qwen3-Coder-30B-A3B-Instruct`, and `Qwen3-Coder-Next`; Alibaba Model Studio also lists `qwen3-coder-plus`, `qwen3-coder-flash`, and `qwen3-max`. | Keep `qwen/qwen-3.8-coder` as historical/provider slug until a live provider catalog maps it to the current Qwen3-Coder route. Add Qwen3-Coder-Next / 480B / 30B as candidate routes. |
| Jiunsong / SuperQwen | `Jiunsong/SuperQwen3.8-27b-abliterated` is Apache-2.0, full BF16 safetensors, about 52 GB, 28B params, multimodal `image-text-to-text`, vLLM/SGLang-served, refusal-reduced, and reports tool/vision/1M-context evidence hashes. HF currently lists no Inference Provider deployment. | Added as Tier 3 `CANDIDATE_LOCAL_VLLM` for adversarial scout rotation. Require local vLLM/SGLang load proof, prompt-injection/safety gate, cost/runtime budget receipt, and qualification receipts before dispatch. Consider the NVFP4 2xDGX variant separately only if suitable hardware/runtime exists. |
| DeepSeek | Hugging Face upstream confirms `deepseek-ai/DeepSeek-V3.2`, `DeepSeek-V3.2-Exp`, and `DeepSeek-V3.2-Speciale` open-weight/research routes. | Keep `deepseek/deepseek-v4-flash` only as a provider-declared candidate route until a live provider catalog attests it; queue V3.2-family candidates for qualification where license/runtime fit. |
| Z.AI / GLM | Hugging Face upstream confirms the `zai-org/GLM-4.5` and `GLM-4.5-Air` family; no public `zai-org/GLM-5.3` artifact was found in this pass. | Keep `zhipu/glm-5.3` as a high-priority provider-declared cyber veto candidate, but require live provider catalog confirmation before dispatch. |
| Mistral | Mistral docs show Mistral Large 3, Mistral Medium 3.5, Mistral Small 4, Devstral 2, Codestral, and Leanstral 1.5 as active model families; `mistral-large-2411` is now an older Large 2.1-era slug. | Add `mistral-large-2512`, `mistral-medium-2604`, `mistral-small-2603`, `devstral-2512`, and `labs-leanstral-1-5` to candidate qualification backlog. |
| Gemma | Google released Gemma 4 with E2B/E4B, 12B, 26B MoE, and 31B dense variants; Gemma 4 12B is explicitly laptop/local oriented. | Treat `gemma3:*` seats as stale but not deleted; queue Gemma 4 12B and 26B/31B local qualification once Ollama is healthy. |
| Llama | Meta's current public Llama docs highlight Llama 4 Scout, Maverick, and Llama Guard 4. | Treat `llama3.1:8b` as legacy local seat; queue Llama 4 Scout/Maverick only if local/provider availability and policy fit are confirmed. |
| Phi | Microsoft Phi-4 mini/reasoning/multimodal variants remain relevant small-model candidates. | Keep `microsoft/phi-4:14b`; add Phi-4-mini-instruct and reasoning variants as cheap local scout candidates if available. |
| Granite | IBM Granite 4.0 replaces the Granite 3.1 line for enterprise agentic/RAG/function-calling workloads, with Ollama/Hugging Face availability. | Treat `ibm/granite3.1-dense:8b` as stale but stable; queue Granite 4.0 H Tiny/Small once Ollama or vLLM is healthy. |
| gpt-oss | OpenAI lists `gpt-oss-120b` and `gpt-oss-20b`, plus `gpt-oss-safeguard` variants, as Apache-2.0 open-weight reasoning/safety models for self-managed runtimes. | Keep `openai/gpt-oss-120b`; add `gpt-oss-20b` as a practical local/edge scout and `gpt-oss-safeguard-20b/120b` as safety-judge candidates. |

### OSS Model & Harness Refresh Cadence

Run this check whenever a model/harness result will affect a handoff, review route, or paid/cloud dispatch:

1. **Harness versions**: `openclaude.cmd --version`, `zero.cmd --version`, `zero.cmd update --check`, `zero.cmd doctor`.
2. **Provider catalogs**: `zero.cmd models`, `zero.cmd providers`, OpenClaude `/provider`, and provider-native model endpoints where credentials are present.
3. **Local models**: `ollama list`, `ollama ps`, and one focused `ModelQualificationRunner` benign/grounded-bug probe before promotion.
4. **Primary upstreams to watch**: Qwen coder/reasoning, DeepSeek coder/reasoning, GLM/Z.AI coding, Gemini flash/pro, Kimi/Moonshot, Mistral/Devstral, Gemma, Llama, Phi, Granite, Hermes/Tulu, Fireworks catalog, OpenRouter catalog, Gitlawb Opengateway, OpenCode Zen/Go, NEAR AI, Cloudflare Workers AI, Agent-Reach, ART/RULER, and StateM.
5. **Promotion rule**: New upstream availability only creates a candidate. Dispatch requires fresh route attestation, privacy classification, qualification receipt, lifecycle-hook coverage, and a passing focused review-quality probe.
