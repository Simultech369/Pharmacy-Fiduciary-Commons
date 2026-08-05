# PBM Bounded Work Loop Notes

Status: optional planning note. This file translates lessons from `Forward-Future/loopy` into PBM handoff and review workflow language. It does not install Loopy, create `LOOPS.md`, schedule work, authorize implementation, or publish anything.

Reference source:

- `Forward-Future/loopy` at `75966cbd572a4185064971c9fe5e9c52e8f8456d`.

## Core Lesson

The useful idea is a bounded feedback cycle:

1. observe fresh state;
2. choose one in-scope action;
3. act or draft;
4. verify against an explicit check;
5. record what happened;
6. repeat only if the next pass can learn something new.

A loop is not permission to continue forever. It needs a stop state: success, clean no-op, blocked, approval required, exhausted, or no measurable progress.

## PBM Translation

PBM does not need a new automation system right now. It needs a few repeatable, human-readable work loops that keep Codex, reviewers, and Antigravity from drifting.

### 1. Antigravity Handoff Prep Loop

Use when preparing tomorrow night's handoff bundle.

- Observe: read `git rev-parse HEAD`, `git status --short`, and the current planning docs.
- Choose: pick one handoff gap that affects Antigravity safety or clarity.
- Act: make one docs-only correction or add one manifest entry.
- Verify: check for local path leaks, authority drift, implementation pressure, and stale policy claims.
- Record: note the changed file and why it belongs in the handoff.
- Stop when: the bundle manifest names inputs, local-only artifacts, deferred decisions, and next authorized action; or when the next gap would require owner/governance authority.

### 2. Reviewer-Cycle Loop

Use only when another model or reference repo is worth consulting.

- Observe: name the lens, disclosure packet, and intended disposition bucket.
- Choose: run only the reviewer/reference that answers a different question.
- Act: collect output or notes without granting implementation authority.
- Verify: reconcile against live repo evidence or mark as exploratory.
- Record: file only the acceptance criterion, contradiction, under-asked question, duplicate signal, wording improvement, or provider failure.
- Stop when: output repeats known gates, lacks evidence, needs restricted disclosure, or pressures implementation before policy acceptance.

### 3. Public Progress Draft Loop

Use for building-in-public copy.

- Observe: start from the committed checkpoint and current redaction rules.
- Choose: write one public-safe claim.
- Act: draft a short note.
- Verify: check for payment-liveness overclaim, `DebtSettled` misuse, local paths, model/provider metadata, dirty backlog, and implied approval.
- Record: keep the public-safe version separate from local handoff notes.
- Stop when: the note says what changed, what remains unresolved, and what will not be done yet.

### 4. Future Implementation Slice Loop

Use only after Antigravity has explicit authorization.

- Observe: verify approved base, scope, files, and policy decisions.
- Choose: select one authorized slice.
- Act: make one bounded implementation change.
- Verify: run the pre-approved local checks for that slice only.
- Record: summarize behavior, tests, side effects, and remaining deferred policy.
- Stop when: the slice passes, the check fails, a dirty-tree conflict appears, or the next change is outside the authorized file list.

## Do Not Borrow

- Do not install Loopy or depend on its live catalog for PBM handoff work.
- Do not create or edit `LOOPS.md` unless explicitly asked.
- Do not turn these loops into schedules, agents, monitors, or background jobs.
- Do not use loop language to justify repeated model reviews without a new lens.
- Do not report exhausted time, budget, quota, or context as success.
- Do not let a loop override PBM's existing non-destructive and authority boundaries.

## Antigravity Handoff Insert

For the next Antigravity handoff, use this compact loop receipt shape when reporting prep work:

```markdown
Loop: Antigravity handoff prep
Scope: PBM solvency planning docs only
Check: no local-path leak, no owner-policy overclaim, no implementation authorization implied, no unrelated backlog absorbed
Result: Success | Clean no-op | Blocked | Approval required | No progress

Evidence:
- [files checked or changed]

Next:
- [handoff-ready, or exact blocker]
```

If the result is `Approval required`, do not relabel it as progress. Carry it forward as `DEFER / DO NOT IMPLEMENT YET`.

