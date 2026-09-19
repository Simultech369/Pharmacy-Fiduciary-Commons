# Anti-Wrapper Theatre, Dead-Code & ΔLOC Audit Report
**Target**: `C:\Users\Josh\Desktop\PBMRebateTreasuryFinal`  
**Python Files Scanned**: 162  

## 1. ΔLOC & Volume Breakdown

| Layer | Files | Total Lines | Code Lines (SLOC) | Comments | Blanks |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Production** | 95 | 27073 | 23217 | 564 | 3292 |
| **Tests** | 67 | 9057 | 7609 | 222 | 1226 |
| **Total** | **162** | **36130** | **30826** | **786** | **4518** |

**Test-to-Production Code Ratio**: `0.328` (Target: >= 0.50)

## 2. Dead-Code & Unused Helper Audit
Total unreferenced internal helpers detected: **0**

✅ **Zero unreferenced internal helpers detected.** All defined private symbols have active call sites.

## 3. Wrapper Theatre & Compatibility Shims Audit
- Naked Wrappers (no contract/invariants): **36**
- Documented Compatibility Shims: **1**

| File | Function | Target Called | Classification | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `scripts/auto_merge_dependabot.py` | `run_git` | `run` | `NAKED_WRAPPER` | `` |
| `scripts/context_hygiene_audit.py` | `read_text` | `read_text` | `NAKED_WRAPPER` | `` |
| `scripts/context_hygiene_audit.py` | `raw_line_count` | `len` | `NAKED_WRAPPER` | `` |
| `scripts/context_hygiene_audit.py` | `add_issue` | `append` | `NAKED_WRAPPER` | `` |
| `scripts/council_orchestrator.py` | `utc_now_iso` | `replace` | `NAKED_WRAPPER` | `` |
| `scripts/dossier_rag_retrieval.py` | `original_overlap_count` | `len` | `NAKED_WRAPPER` | `` |
| `scripts/eval_constitutional_rubric.py` | `has_freshness_label` | `any` | `NAKED_WRAPPER` | `` |
| `scripts/eval_constitutional_rubric.py` | `add_violation` | `append` | `NAKED_WRAPPER` | `` |
| `scripts/eval_dossier_rag.py` | `dcg` | `sum` | `NAKED_WRAPPER` | `` |
| `scripts/index_dossier_tree.py` | `normalize_space` | `strip` | `NAKED_WRAPPER` | `` |
| `scripts/index_dossier_tree.py` | `line_numbered` | `join` | `NAKED_WRAPPER` | `` |
| `scripts/multimodal_swarm_harness.py` | `relpath` | `replace` | `NAKED_WRAPPER` | `` |
| `scripts/multimodal_swarm_harness.py` | `routed_model_id` | `get` | `NAKED_WRAPPER` | `` |
| `scripts/multimodal_swarm_harness.py` | `normalize_path_text` | `replace` | `NAKED_WRAPPER` | `` |
| `scripts/multimodal_swarm_harness.py` | `lane_name_variants` | `sorted` | `NAKED_WRAPPER` | `` |
| `scripts/observability_dashboard.py` | `to_repo_path` | `replace` | `NAKED_WRAPPER` | `` |
| `scripts/pre_commit_audit.py` | `diff_contains_deletion` | `any` | `NAKED_WRAPPER` | `` |
| `scripts/rehearse_proposal.py` | `normalize_blob` | `strip` | `NAKED_WRAPPER` | `` |
| `scripts/verify_agent_claims.py` | `has_lineage_tag` | `any` | `NAKED_WRAPPER` | `Check if text contains any canonical lineage tag.` |
| `tools/council/a2a_protocol_engine.py` | `get_public_key` | `get` | `NAKED_WRAPPER` | `` |
| `tools/council/a2a_protocol_engine.py` | `list_agents` | `sorted` | `NAKED_WRAPPER` | `` |
| `tools/council/a2a_protocol_engine.py` | `get_mailbox` | `get` | `NAKED_WRAPPER` | `` |
| `tools/council/council_api_server.py` | `_safe_sse_token` | `replace` | `NAKED_WRAPPER` | `Keeps SSE metadata single-line so event boundaries remain unambiguous.` |
| `tools/council/distributed_merkle_state_sync.py` | `get_merkle_root_cid` | `get_merkle_root` | `NAKED_WRAPPER` | `Alias for get_merkle_root to provide consistent CID retrieval.` |
| `tools/council/dizzy_runtime_engine.py` | `append_turn` | `append` | `NAKED_WRAPPER` | `` |
| `tools/council/dizzy_runtime_engine.py` | `emit_streaming_event_ndjson` | `format_ndjson_event` | `NAKED_WRAPPER` | `` |
| `tools/council/external_a2a_adapter.py` | `create_agent_card` | `AgentCard` | `NAKED_WRAPPER` | `Constructs a certified read-only Agent Card.` |
| `tools/council/lifecycle_hooks.py` | `_record_webhook_dispatch` | `extend` | `NAKED_WRAPPER` | `` |
| `tools/council/model_gateway.py` | `dispatch_call` | `invoke_with_resilience` | `COMPATIBILITY_SHIM` | `Backward-compatible adapter. New production callers should use
invoke_with_resilience so the gateway` |
| `tools/council/p2p_gossip_transport.py` | `add_peer` | `add` | `NAKED_WRAPPER` | `Registers a known peer address for gossip replication.` |
| `tools/council/p2p_gossip_transport.py` | `_canonical_message_bytes` | `encode` | `NAKED_WRAPPER` | `` |
| `tools/council/shared_memory.py` | `record_learned_invariant` | `record_working_practice` | `NAKED_WRAPPER` | `Adds a working best practice or triggers rule proposal.` |
| `tools/council/shared_memory.py` | `get_invariants_prompt_context` | `get_complete_invariants_and_practices_context` | `NAKED_WRAPPER` | `Returns the clearly partitioned context containing Formal Rules & Working Practices.` |
| `tools/council/sovereign_swebench_batch_runner.py` | `_bounded_ref` | `_hashed_ref` | `NAKED_WRAPPER` | `Return a redacted reference for untrusted operator metadata.

The current runner treats all external` |
| `tools/council/sovereign_swebench_batch_runner.py` | `_safe_path_ref` | `_hashed_ref` | `NAKED_WRAPPER` | `` |
| `tools/council/task_router.py` | `role_profiles` | `dict` | `NAKED_WRAPPER` | `` |
| `tools/council/task_router.py` | `_normalize_text` | `sub` | `NAKED_WRAPPER` | `` |
