# Surface Capability Routing Spec

Status: canonical wording for Codex, Astra, and repo prompt surfaces.
Scope: repo-local routing and prompt language only. This spec defines how to talk about capability selection; it does not claim that every surface already exposes the same registry or the same fallback stack.

## Canonical Rule

Route by capability, not by aspirational name.

## Backend Truth

- Resolve the best actually available model on the current surface.
- Treat model names as surface-local labels, not universal truth.
- If the preferred model is unavailable, choose the best supported fallback.
- Record the requested intent, the actual model selected, and the downgrade reason.
- Keep routing decisions tied to the live capability registry for that surface.

## Frontend Truth

- Show only what the current surface can really expose.
- If a fallback is active, show the fallback and say so.
- Do not present an aspirational model name as a guarantee.

## Prompt Language

Use: `use the best available model on this surface.`

Avoid hardcoding a model name unless the surface has explicitly confirmed it.

## Orchestration

- Carry both the user intent and the actual model chosen.
- Log `requested_intent`, `selected_surface`, `selected_model`, and `downgrade_reason`.
- If the capability registry changes, surface the downgrade rather than silently re-labeling it.
- Keep backend routing, frontend labels, and prompt language aligned to the same live capability registry.

## Failure Behavior

- If a preferred model 404s or is otherwise unavailable, fail over once to the best supported fallback.
- Do not keep retrying the unsupported label.
- Record the downgrade and why it happened.

## Canonical Surface Copy

- Codex: use the best available model for this surface. If the preferred model is unavailable, fall back automatically and report the actual selection.
- Astra: analyze the live capability of the current surface first. Do not assume model names transfer across surfaces.
- Repo prompts: all model references are capability-based. Only name a model when the repo has verified that surface can actually expose it.

