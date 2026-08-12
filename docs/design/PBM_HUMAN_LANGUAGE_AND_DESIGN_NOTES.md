# PBM Human Language And Design Notes

Status: optional planning note. This file translates lightweight lessons from `vibecoded-design-tells` and `stop-slop` into PBM handoff, public-progress, dashboard, and documentation guidance. It is not implementation authority, a style police checklist, or a CI gate.

Reference sources:

- `JCarterJohnson/vibecoded-design-tells` at `f7c4aefc2c797a66e55b49354a93917ab60d33ac`.
- `hardikpandya/stop-slop` at `8da1f030185bdfe8471220585162991eaeb970e9`.

## Core Lesson

The best thing to borrow is not a list of banned words or banned colors. The useful shared lesson is:

> A work product feels more human when a person made a specific choice and the artifact can explain why that choice fits the project.

For PBM, that means public updates, handoffs, and dashboard copy should sound like a person stewarding a risky prototype, not a generic product launch or an AI-generated process memo.

## Borrow Lightly

1. Pick a voice before drafting public copy.

   Use a conversational-professional voice for handoffs and public updates:

   - direct;
   - sober about risk;
   - specific about what changed;
   - clear about what remains unresolved;
   - warm enough to feel like someone is present.

   Avoid marketing voice, crisis voice, and faux-polished investor voice.

2. State the claim before decorating it.

   Public PBM progress should lead with the concrete claim:

   - a solvency-liveness checkpoint was pushed;
   - lifecycle operations can continue under underbacking;
   - payment liquidity is still not guaranteed;
   - unresolved policy choices remain deferred.

   Do not build a heroic story around the checkpoint.

3. Use "default detector" thinking, not strict bans.

   The design-tells repo warns against default looks: purple gradients, untouched Tailwind/shadcn surfaces, emoji-as-icons, hero-plus-three-cards layouts, and the newer cream/serif/sage tasteful default. PBM should use that as a question:

   - Did we choose this because it fits PBM?
   - Or did the model choose it because no one specified anything?

   A chosen color, phrase, or layout is allowed. An unchosen default should be revised.

4. Prefer operator clarity over polish.

   PBM is a treasury/governance prototype. Dashboard copy should be utilitarian and precise:

   - status;
   - risk;
   - next allowed action;
   - stop condition;
   - exact meaning of a field.

   Avoid oversized heroes, decorative cards, vague trust language, or celebratory CTAs around unresolved solvency behavior.

5. Name people and permissions when authority matters.

   Handoffs should say who can decide, who can implement, and who must stop. Avoid phrasing where "the process" decides or "the model" settles something.

6. Keep rhythm human, not overcorrected.

   The text references warn that anti-AI writing can become its own costume. For PBM, do not overcorrect into fake casualness, forced fragments, or dramatic one-liners. Plain, specific prose is enough.

## PBM Public-Progress Voice

Good public-safe shape:

```text
We pushed a patient-fund solvency checkpoint.

It restores lifecycle liveness: rounds can start and finalize even when the fund is underbacked.

It does not restore payment liveness. Claims still depend on real token liquidity, and the next work is to record the policy decisions around claim priority, council refunds, reclaim timing, and shortfall terminology before more implementation.
```

Avoid:

- "revolutionary";
- "trustless";
- "fully solved";
- "made whole";
- "debt settled" unless path-specific payment evidence exists;
- "AI agents agreed";
- "implementation is ready";
- "not just X, but Y" product framing.

## PBM Dashboard Design Bias

If dashboard copy/design is later authorized, bias toward:

- compact operational layout;
- clear labels over poetic labels;
- tables, counters, timelines, and status strips;
- restrained colors with semantic meaning;
- icons only where they clarify an action;
- no emoji-as-system-icons;
- no default gradient hero;
- no hero-plus-three-card landing page for an operational dashboard;
- no one-note purple, cream/sage, or dark-neon theme unless explicitly chosen.

The dashboard should help an operator avoid a wrong action. It does not need to look like a launch page.

## PBM Handoff Writing Bias

Handoff docs should:

- begin with current status and stop condition;
- distinguish "observed behavior" from "accepted policy";
- use `DEFER / DO NOT IMPLEMENT YET` where authority is missing;
- name the allowed slice and files before implementation;
- use placeholders like `<LOCAL_REPO_ROOT>` for shareable packets;
- keep local reviewer/provider details out of public copy;
- trim duplicate reviewer narration once the useful decision or wording has landed.

## Do Not Borrow

- Do not add anti-slop scanners or CI gates to PBM right now.
- Do not run these repos' scripts against the dirty PBM tree.
- Do not ban all adverbs, passive voice, serif fonts, purple, cream, gradients, or cards.
- Do not turn "human" into a taste mandate.
- Do not rewrite existing docs broadly just to sound more natural.
- Do not let style cleanup become a substitute for solvency policy decisions.

## Antigravity Handoff Insert

Optional voice/design check before public-facing docs or dashboard copy:

| Check | Question |
|---|---|
| Claim | What exact thing changed? |
| Boundary | What remains unresolved or deferred? |
| Authority | Who can decide, implement, publish, or stop? |
| Default | Did a model choose this phrase/layout/palette because no one specified one? |
| Operator safety | Could this wording make someone think a risky action is safe? |
| Redaction | Does this expose local paths, private reviewer details, provider routes, or dirty backlog? |
| Overcorrection | Did the cleanup become fake-casual, dramatic, or formulaic? |

If a copy/design change fails this check, revise the wording or mark it deferred. Do not expand implementation scope.

