# Model Inventory - 2026-07-21

This inventory records what was verified from this Windows workspace on
2026-07-21. It is a live-state snapshot, not a durable guarantee.

## Hosted / Account-Backed

| Surface | Status | Evidence |
| --- | --- | --- |
| Codex CLI | Installed | `codex.cmd --version` returned `codex-cli 0.145.0-alpha.12`. |
| Codex configured default | Present | `~/.codex/config.toml` reports `model = "gpt-5.5"` and `model_reasoning_effort = "high"`. |
| OpenClaude | Launcher present, not health-verified | `Get-Command openclaude.cmd` found `C:\Users\Josh\AppData\Roaming\npm\openclaude.cmd`; `openclaude.cmd --version` timed out. |
| Goose | Launcher present, not health-verified | `Get-Command goose.exe` found `C:\Users\Josh\.local\bin\goose.exe`; version/doctor check timed out in this pass. Prior memory said Goose had no provider configured, so refresh before use. |

## Local / OSS via Ollama

`ollama list` returned:

| Model | Size | Last modified | Notes |
| --- | ---: | --- | --- |
| `mistral:latest` | 4.4 GB | 28 hours ago | `ollama show`: 7.2B, 32k context, Q4_K_M, completion + tools. |
| `llama-audit:latest` | 4.9 GB | 5 days ago | Installed; not smoke-tested in this pass. |
| `llama3.1:latest` | 4.9 GB | 5 days ago | `ollama show`: 8.0B, 131k context, Q4_K_M, completion + tools. |
| `deepseek-coder-v2:16b` | 8.9 GB | 6 days ago | `ollama show`: 15.7B, 163k context, Q4_0, completion + insert. |
| `gemma3:4b` | 3.3 GB | 4 weeks ago | Installed; not smoke-tested in this pass. |
| `gemma3:12b` | 8.1 GB | 4 weeks ago | `ollama show`: 12.2B, 131k context, Q4_K_M, completion + vision. |
| `yi:latest` | 3.5 GB | 5 weeks ago | Installed; not smoke-tested in this pass. |
| `glm4:latest` | 5.5 GB | 5 weeks ago | Installed; not smoke-tested in this pass. |
| `qwen2.5-coder:7b` | 4.7 GB | 5 weeks ago | Smoke-tested: `ollama run qwen2.5-coder:7b "Reply with exactly: OK"` returned `OK`. `ollama show`: 7.6B, 32k context, Q4_K_M, completion + tools + insert. |
| `deepseek-r1:7b` | 4.7 GB | 5 weeks ago | Installed; not smoke-tested in this pass. |
| `deepseek-r1:1.5b` | 1.1 GB | 5 weeks ago | Installed; not smoke-tested in this pass. |

`ollama ps` showed no currently loaded models after the inventory pass.

## Codex OSS Route

`codex.cmd exec --oss --local-provider ollama -m qwen2.5-coder:7b --sandbox read-only "Reply with exactly OK"` started with provider `ollama`, but timed out before returning an answer. Treat this route as present but not operationally verified.

## Operating Guidance

- Use local Ollama models for low-risk brainstorming, prompt drafts, public-code summaries, style/taste exploration, and scratch notes.
- Do not send secrets, private keys, regulated data, customer data, or sensitive vulnerability details to OSS models by default.
- Keep local-model outputs advisory. Use stronger hosted reviewers or deterministic tests before code changes, security claims, submissions, or commits.
- For OSS governance risk, distinguish local open-weight model use from hosted foreign model APIs. The IT concern is strongest for networked services, unknown licenses, telemetry, and sensitive data exposure.
