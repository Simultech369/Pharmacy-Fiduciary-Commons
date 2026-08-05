# PBM Review Observatory v0.1

Status: [dirty working tree] advisory design note for packet-driven review tooling.

The PBM Review Observatory v0.1 is a local evidence layer for review packets,
lineage checks, and rubric evaluation. It does not authorize repository
mutation, external disclosure, deployment, signing, fund movement, governance
execution, role changes, or patient-fund operations.

## Boundary

The observatory is strictly advisory. It can compile evidence, classify claims,
prepare review packets, run fail-closed text checks, and record router metadata.
It cannot convert reviewer output into project truth. A reviewer finding becomes
usable only after live-code reconciliation and, where needed, human or
governance acceptance.

## Packet Compiler

`scripts/index_dossier_tree.py --mode compile-packet` builds a JSON packet with:

- snapshot metadata: branch, HEAD, and short working-tree status;
- disclosure class: `PUBLIC_COMMITTED` or `LOCAL_CODE_DIRTY` for v0.1 packets;
- canonical freshness labels for each included file;
- forbidden-input rules for secrets, PHI, witness material, privileged routes,
  and live-chain action payloads;
- known non-claims for ZK/privacy review;
- line-anchored snippets with file hashes, line counts, and token estimates;
- lineage entries selected from `review-context/agent_work_lineage_ledger.md`;
- verification commands the reviewer or operator should use next.

The compiler rejects paths outside the repository and skips common generated or
sensitive directories such as `.git`, `node_modules`, `artifacts`, `cache`, and
`dist`.

## Lineage Benchmark

Every index or packet compile run refreshes
`cache/lineage_eval_benchmark.jsonl`. Each JSONL record preserves the ledger
claim, human-readable claim, implied claim, actual proof, evidence, status,
dependent artifacts, invalidation criteria, and a deterministic assessment:
`good`, `rejected`, `narrowed`, `stale`, or `risky`.

The benchmark is a review dataset, not a release proof. Its records inherit the
freshness and proof boundaries of the underlying lineage ledger entries.

## Constitutional Rubric

`scripts/eval_constitutional_rubric.py` fails closed on:

- AI or reviewer authority overclaims;
- production, launch, mainnet, or audit-readiness overclaims;
- patient-fund or fiduciary bypass language;
- privacy/ZK overclaims that erase metadata, relayer, issuer, support-flow, or
  gas-payer non-claims;
- missing evidence labels on claim-like dossier text;
- claims that override the constitution or Patient Fund policy.

For JSON packets, the evaluator checks packet metadata, disclosure class,
freshness labels, required fields, and advisory instructions. It intentionally
does not treat embedded source snippets as new observatory claims.

## Reviewer Router

`scripts/openrouter_review.py --packet <packet.json>` can route an approved
packet to a named reviewer lane and writes router metadata beside the raw review
output. External routing remains blocked unless the operator explicitly approves
the packet disclosure class at invocation time.

## ZK Nullifier Replay Packet

The first v0.1 packet target is:

```powershell
python scripts/index_dossier_tree.py --mode compile-packet --question "Is the VoteNullifier path safe against replay and identity leakage?" --lane zk_privacy --budget 12000 --out review-context/packet-zk-nullifier-replay.json
```

Because the current worktree includes uncommitted changes, this packet should be
treated as `LOCAL_CODE_DIRTY` unless regenerated from a clean committed state.
