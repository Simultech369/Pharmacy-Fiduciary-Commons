# Miessler Integration Triage

Prepared against live checkout `52e6a0d8a543293fda81d9709afaa264dbc2bce7` on branch `main`.

Source artifact reviewed:

`C:\Users\Josh\.gemini\antigravity\brain\19a482d2-a057-49be-8c84-23d1b661969a\miessler_integration.md`

This file is a triage of the proposal, not approval to implement it. Treat the source artifact as a claim set. Keep the ZK/nullifier roadmap first.

## Summary

| Proposal area | Disposition | Reason |
|---------------|-------------|--------|
| Versioned prompt patterns | Defer, but keep concept | Useful for auditable review prompts, but should not become policy authority or another prompt museum before ZK design is stable |
| Local "Pharmacy OS" participant state | High caution | Local-first custody is aligned with portability and continuity, but a `USER/` folder holding private secrets would be dangerous if not encrypted, excluded from Git, and separated from repo examples |
| SecLists-style fuzzing and payload tests | Promote | Concrete, testable, high leverage for public form, support intake, credential parser, and prompt-injection resilience |
| Structured evidence graphs | Defer into schema design | Useful for evidence provenance, but should begin as `EVIDENCE_METADATA.md` schema examples and synthetic fixtures, not dashboard claims |

## 1. Versioned Prompt Patterns

### Keep

- Versioned prompt/checklist artifacts can make reviewer criteria auditable.
- A local runner could eventually apply a named review pattern to JSON exports or evidence packets.
- This aligns with `REVIEW_ITERATION_PROCESS.md` if patterns remain review-only and deterministic outputs are verified separately.

### Do Not Do Now

- Do not create a large `tools/patterns/` framework before the ZK/nullifier review is reconciled.
- Do not treat LLM prompt output as governance evidence without a signed input packet, versioned prompt, deterministic validation, and human/council review.
- Do not include raw credentials, PHI, witness material, or stable wallet-to-pharmacy mappings in prompt inputs.

### Small Safe Future Slice

If needed later, create one pattern only:

```text
tools/patterns/reconcile-review-finding/
```

It should accept a synthetic finding and emit a report requiring file/line evidence, status classification, and smallest verification step.

## 2. Local "Pharmacy OS" Client

### Keep

- Local-first portability and air-gapped continuity are already part of the project direction.
- Participant-held receipts, proof material, and offline recovery packets are useful.
- ZK witness generation should eventually be local or otherwise designed so operators/support cannot see witness secrets.

### High-Risk Boundary

Do not add a `USER/` directory to this repo that suggests participants should store real private keys, credential secrets, witness material, PHI, or support evidence in a predictable folder.

If a local participant context is ever implemented:

- it must live outside the repo by default;
- it must be excluded from Git;
- it must use encrypted storage or hardware wallet/KMS-equivalent custody where appropriate;
- it must ship with synthetic fixtures only;
- it must include recovery warnings and deletion guidance;
- it must not be required for current contract tests.

### Small Safe Future Slice

Document a synthetic local context fixture only:

```text
tools/offline/fixtures/synthetic-participant-context/
```

The fixture must contain no real secrets and should prove redaction, portability, and offline verification semantics.

## 3. Payload Fuzzing And Prompt-Injection Tests

### Promote

This is the most immediately actionable proposal.

Add focused tests or fixtures for:

- XSS-like payloads in public/support form text fields;
- SQLi-like strings in future API-bound fields;
- prompt-injection strings in evidence descriptions, support tickets, review artifacts, and copied handoffs;
- oversized JSON, deeply nested arrays, wrong types, duplicate fields, and Unicode control characters in credential parser inputs;
- malformed evidence hashes and non-hex strings where bytes32 or hash-like data is expected.

### Integration Points

- `test/PublicFormThreatModel.test.js`
- `tools/credentials/credential-policy.mjs`
- `scripts/register-voter-relayer.mjs`
- `EVIDENCE_METADATA.md`
- `PRODUCTION_READINESS_CHECKLIST.md`
- `REVIEW_ITERATION_PROCESS.md`

### Small Safe Future Slice

Add a synthetic fixture file and tests that prove hostile text remains data, not instruction:

```text
test/fixtures/hostile-intake-payloads.json
test/PublicFormThreatModel.test.js
test/CredentialPolicy.test.js
```

Do not import an external payload corpus wholesale. Use a small, repo-specific synthetic set first.

## 4. Structured Evidence Graphs

### Keep

Evidence packets should distinguish:

- claim;
- argument;
- supporting data;
- custodian;
- availability class;
- privacy class;
- verification command or artifact hash;
- dispute/review status.

This fits the existing `EVIDENCE_METADATA.md` direction and the Ledger of Omissions credibility work.

### Do Not Do Now

- Do not build dashboard graph UI before evidence schema and privacy boundaries are settled.
- Do not expose raw NCPDP records, PHI, patient identifiers, or pharmacy-identifying support context.
- Do not let narrative evidence graphs become a substitute for Merkle proofs, on-chain events, or signed evidence descriptors.

### Small Safe Future Slice

Add a synthetic example to `EVIDENCE_METADATA.md` later:

```text
claim -> argument -> data -> artifact hash -> verification command
```

This should remain docs/schema-level until a validator exists.

## Recommended Promotion Order

1. Promote payload fuzzing and prompt-injection fixtures.
2. Keep local participant context as a synthetic fixture only.
3. Defer prompt-pattern scaffolding until after the ZK/nullifier review loop.
4. Defer evidence graphs until evidence metadata schema examples are tightened.

## Antigravity Review Request

Antigravity should verify this triage against the live repo and answer:

- Is any proposal misclassified as safe, deferred, or unsafe?
- Are the proposed fuzzing tests already covered elsewhere?
- Which exact parser/public-form surfaces should receive hostile payload tests first?
- Does any local participant context language conflict with secret-handling guidance?
- Should structured evidence graphs be added to `EVIDENCE_METADATA.md` before the verifier-mock milestone, or deferred?
