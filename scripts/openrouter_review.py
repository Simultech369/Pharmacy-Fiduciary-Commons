#!/usr/bin/env python3
import argparse
import datetime as _dt
import json
import os
import sys
import time
import urllib.error
import urllib.request


ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REVIEWS_DIR = os.path.join(ROOT_DIR, "reviews")
DEFAULT_CONTEXT_FILE = "C:/Users/Josh/.gemini/antigravity/brain/5450a484-4a05-425b-96b4-0d604544248b/llama3_review_context.md"

DISCLOSURE_CLASSES = [
    "PUBLIC_COMMITTED",
    "LOCAL_PLANNING",
    "LOCAL_CODE_DIRTY",
    "SECRET_OR_SENSITIVE",
    "LIVE_PRIVILEGED",
]

ROLE_CONFIGS = {
    "grok_council": {
        "prompt_file": "reviews/prompts/grok-council-prompt.txt",
        "default_model": "openrouter/free",
        "output_file": "reviews/grok-council-review.txt",
        "description": "Grok Council Reviewer (OpenRouter Free Router)",
    },
    "strategist": {
        "prompt_file": "reviews/prompts/strategist-prompt.txt",
        "default_model": "meta-llama/llama-3.3-70b-instruct:free",
        "output_file": "reviews/strategist-deepseek-review.txt",
        "description": "Strategist (DeepSeek/Llama 3.3)",
    },
    "skeptic": {
        "prompt_file": "reviews/prompts/skeptic-prompt.txt",
        "default_model": "google/gemma-4-31b-it:free",
        "output_file": "reviews/skeptic-gemma-review.txt",
        "description": "Skeptic (Gemma)",
    },
    "advocate": {
        "prompt_file": "reviews/prompts/advocate-prompt.txt",
        "default_model": "nousresearch/hermes-3-llama-3.1-405b:free",
        "output_file": "reviews/patient-advocate-kimi-review.txt",
        "description": "Patient Advocate",
    },
    "guardrail": {
        "prompt_file": "reviews/prompts/guardrail-prompt.txt",
        "default_model": "meta-llama/llama-3.3-70b-instruct:free",
        "output_file": "reviews/guardrail-review.txt",
        "description": "Pre-commit Security Guardrail",
    },
    "zk_privacy": {
        "default_model": None,
        "output_file": "reviews/zk-privacy-packet-review.md",
        "description": "ZK Privacy and Nullifier Replay Reviewer",
        "requires_model_override": True,
    },
    "codex_5_6": {
        "default_model": "meta-llama/llama-3.3-70b-instruct:free",
        "output_file": "reviews/codex-5-6-packet-review.md",
        "description": "Codex 5.6 Planning Critic Lane",
    },
    "open_claude": {
        "default_model": "openrouter/free",
        "output_file": "reviews/open-claude-packet-review.md",
        "description": "OpenClaude Blind-Spot Reviewer Lane",
    },
    "free_code": {
        "default_model": "openrouter/free",
        "output_file": "reviews/free-code-packet-review.md",
        "description": "FreeCode Multi-Model Coding Auditor Lane",
    },
    "zero_zk": {
        "default_model": "openrouter/free",
        "output_file": "reviews/zero-zk-packet-review.md",
        "description": "Zero Proof-vs-Theater Reviewer Lane",
    },
    "kimi_long_context": {
        "default_model": "openrouter/free",
        "output_file": "reviews/kimi-long-context-packet-review.md",
        "description": "Kimi/Hunyuan Long-Context Contradiction Reviewer Lane",
    },
    "qwen_coder": {
        "default_model": "openrouter/free",
        "output_file": "reviews/qwen-coder-packet-review.md",
        "description": "Qwen Code-Path Reviewer Lane",
    },
    "deepseek_reasoner": {
        "default_model": "openrouter/free",
        "output_file": "reviews/deepseek-reasoner-packet-review.md",
        "description": "DeepSeek Invariant Reviewer Lane",
    },
    "laguna_xs": {
        "default_model": "openrouter/free",
        "output_file": "reviews/laguna-xs-packet-review.md",
        "description": "Laguna XS Adversarial Critic Lane",
    },
    "solvency_debt": {
        "default_model": "openrouter/free",
        "output_file": "reviews/solvency-debt-packet-review.md",
        "description": "Solvency & Accounting Invariants Auditor Lane",
    },
}


SHARED_PREAMBLE = """You are a senior adversarial auditor for a high-stakes fiduciary blockchain system (Pharmacy Fiduciary Commons). 
Accuracy, solvency invariants, participant safety, privacy continuity, and auditability always override elegance or speed.
Be direct, evidence-based, and precise. Cite exact files, functions, lines, or policy sections. 
Flag any weakening of existing security properties or care-continuity guarantees.
Output structure: Summary → Positive Findings → Critical Issues (ranked) → Suggestions → Open Questions.
"""

CHALLENGER_MODE_SNIPPET = """

CHALLENGER MODE:
You are now an adversarial red-team auditor. Assume a sophisticated, well-resourced attacker (compromised council member, malicious pharmacy, PBM correlator, or external griefer) is actively trying to break the system.
Your only job is to find ways the current design can be abused, race-conditioned, or socially engineered.
Do not soften findings. Do not propose fixes unless explicitly asked. Prioritize fund-loss, privacy linkage, and continuity failure scenarios.
End every finding with: “Attack surface: [one sentence]”.
"""

DEFAULT_ROLE_PROMPTS = {
    "zk_privacy": SHARED_PREAMBLE + """Domain 3 – ZK Nullifier Circuits (Specialized Privacy Focus)
Focus on Circom/Identity nullifier code, signal ordering, Poseidon constraints, verifier ABI, and transition requirements.
Distinguish real cryptographic guarantees from “theater.” Flag any mock-only or incomplete unlinkability. Check version gating, root handling, and nullifier reuse protection.""",
    "codex_5_6": SHARED_PREAMBLE + """Domain 6 – Institutional Governance / Policy (Strategic Plan Critic)
Focus on all governance, constitution, threat-model, and policy Markdown files.
Cross-examine for internal contradictions, stale claims, gaps between policy and code, and ratification readiness. Require evidence from specific sections.""",
    "open_claude": SHARED_PREAMBLE + """Domain 5 – Frontend & Brand Governance
Focus on dashboard UI, accessibility (ARIA), visual design system (Jazz Diorama: obsidian dark, jazz cyan, warm amber), anti-slop rules, and provenance labels.
Red-team for trust signals, data density vs. clarity, synthetic vs. live data labeling, and any generic AI-vibe patterns.""",
    "zero_zk": SHARED_PREAMBLE + """Domain 3 – ZK Nullifier Circuits
Focus on Circom/Identity nullifier code, signal ordering, Poseidon constraints, verifier ABI, and transition requirements.
Distinguish real cryptographic guarantees from “theater.” Flag any mock-only or incomplete unlinkability. Check version gating, root handling, and nullifier reuse protection.""",
    "kimi_long_context": SHARED_PREAMBLE + """Domain 6 – Institutional Governance / Policy
Focus on all governance, constitution, threat-model, and policy Markdown files.
Cross-examine for internal contradictions, stale claims, gaps between policy and code, and ratification readiness. Require evidence from specific sections.""",
    "qwen_coder": SHARED_PREAMBLE + """Domain 1 – EVM Smart Contracts (Formal Code Invariants)
Focus exclusively on Solidity contracts (especially PBMRebateTreasury.sol, PatientFundParticipatoryBudgeting.sol, PharmacyMutualCredit.sol).
Check: state-transition correctness, accounting invariants, role separation, Merkle double-hash safety, caps, dispute/recall paths, pause/guardian behavior, reentrancy, and precision issues.
Treat every new change as potentially adversarial. Require explicit proof that solvency and claim accounting remain intact.""",
    "deepseek_reasoner": SHARED_PREAMBLE + """Domain 2 – DB Proxy & RLS Security
Focus on server-side code, Supabase schema, RLS policies, and any proxy/relay layer (e.g., createApp.js or equivalent).
Check: operator correlation risk, metadata leakage, under-asked privacy questions, RLS bypass paths, CSRF/admin field threats, and fail-closed behavior on missing credentials or stale data.
Assume a motivated insider or external correlator is trying to link pharmacies or patients.""",
    "laguna_xs": SHARED_PREAMBLE + """Domain 1 – EVM Smart Contracts (Adversarial Red-Team Focus)
Focus exclusively on Solidity contracts (especially PBMRebateTreasury.sol, PatientFundParticipatoryBudgeting.sol, PharmacyMutualCredit.sol).
Check: state-transition correctness, accounting invariants, role separation, Merkle double-hash safety, caps, dispute/recall paths, pause/guardian behavior, reentrancy, and precision issues.""",
    "free_code": SHARED_PREAMBLE + """Domain 4 – Offline Continuity Engine
Focus on continuity-engine.mjs, voucher reconciliation, HMAC/MAC validation, cache files, and offline→online sync.
Prioritize fail-closed behavior, strict schema validation, duplicate-nullifier detection, and recovery paths. Assume network loss, forged vouchers, and delayed settlement.""",
    "solvency_debt": SHARED_PREAMBLE + """Domain 7 – Solvency Debt Accounting
Focus on patient-fund solvency debt queuing, recycled matching custody, epoch recall, and accounting invariants.
Verify that debt cannot create phantom liquidity, that unclaimed funds and claims remain consistent, and that concurrent operations cannot break solvency. Treat every edge case as adversarial.""",
}

STRICT_ADVISORY_HEADER = """Boundary:
- Review only. Do not edit files.
- Do not stage, commit, push, branch, clean, delete, reset, deploy, sign, move funds, grant roles, revoke users, publish roots, submit claims, or use credentials.
- No reviewer output is truth until reconciled against local files, commands, tests, and the lineage ledger.
- If context is missing, ask for the smallest additional file or command instead of guessing.
"""


def load_env():
    env_path = os.path.join(ROOT_DIR, ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    os.environ[key.strip()] = val.strip().strip('"').strip("'")


def safe_repo_or_abs_path(path):
    if os.path.isabs(path):
        return os.path.abspath(path)
    return os.path.abspath(os.path.join(ROOT_DIR, path))


def load_prompt(config, role):
    prompt_file = config.get("prompt_file")
    if prompt_file:
        prompt_path = os.path.join(ROOT_DIR, prompt_file)
        if os.path.exists(prompt_path):
            with open(prompt_path, "r", encoding="utf-8") as pf:
                return pf.read()
    return DEFAULT_ROLE_PROMPTS.get(role, "You are a read-only reviewer. Cite file/path evidence and uncertainty clearly.")


def load_packet(packet_path):
    abs_path = safe_repo_or_abs_path(packet_path)
    if not os.path.exists(abs_path):
        raise SystemExit(f"Error: Packet file not found at {abs_path}")
    with open(abs_path, "r", encoding="utf-8") as f:
        packet = json.load(f)
    return abs_path, packet


def packet_output_path(packet, config):
    output_template = packet.get("output_paths", {}).get("review_output_template")
    if output_template:
        return os.path.join(ROOT_DIR, output_template)
    return os.path.join(ROOT_DIR, config["output_file"])


def packet_metadata_path(packet, role):
    metadata_template = packet.get("output_paths", {}).get("router_metadata_template")
    if metadata_template:
        return os.path.join(ROOT_DIR, metadata_template)
    return os.path.join(REVIEWS_DIR, f"{role}-packet-router-metadata.json")


def verify_disclosure(disclosure_class, approved_class, packet_path):
    if disclosure_class in {"SECRET_OR_SENSITIVE", "LIVE_PRIVILEGED"}:
        raise SystemExit(f"Refusing to route {disclosure_class} packet: {packet_path}")
    if disclosure_class != "PUBLIC_COMMITTED" and approved_class != disclosure_class:
        raise SystemExit(
            "Refusing external review without exact disclosure approval. "
            f"Packet class is {disclosure_class}; rerun with --approve-disclosure {disclosure_class} only after operator approval."
        )


def build_packet_context(packet_path, packet, permute_order=False):
    target_packet = packet
    if permute_order and isinstance(packet, dict):
        import copy
        target_packet = copy.deepcopy(packet)
        if "files" in target_packet and isinstance(target_packet["files"], list):
            target_packet["files"] = list(reversed(target_packet["files"]))
        if "lineage_entries" in target_packet and isinstance(target_packet["lineage_entries"], list):
            target_packet["lineage_entries"] = list(reversed(target_packet["lineage_entries"]))

    return (
        "Review the following PBM Review Observatory packet. Preserve the packet's disclosure, "
        "advisory, and non-claim boundaries in your answer.\n\n"
        f"PACKET_PATH: {packet_path}\n\n"
        + json.dumps(target_packet, indent=2, ensure_ascii=False)
    )


def write_metadata(path, metadata):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
        f.write("\n")


def base_metadata(args, config, model, packet_path, output_path, disclosure_class):
    return {
        "recorded_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "role": args.role,
        "description": config["description"],
        "model": model,
        "provider": "openrouter",
        "launcher": "scripts/openrouter_review.py",
        "packet_path": packet_path,
        "context_path": args.context,
        "output_path": output_path,
        "disclosure_class": disclosure_class,
        "approved_disclosure_class": args.approve_disclosure,
        "error_status": None,
        "truncation_status": "unknown",
        "reconciliation_status": "unreconciled_raw_output",
    }


def parse_args():
    parser = argparse.ArgumentParser(description="Packet-aware OpenRouter reviewer router")
    parser.add_argument("--role", "-r", choices=sorted(ROLE_CONFIGS), required=True, help="Reviewer lane/persona")
    parser.add_argument("--model", "-m", help="OpenRouter model slug. Required for lanes without a pinned default.")
    parser.add_argument("--context", "-c", help="Context file path for legacy non-packet mode")
    parser.add_argument("--packet", help="PBM Review Observatory packet JSON")
    parser.add_argument("--disclosure-class", choices=DISCLOSURE_CLASSES, default="LOCAL_PLANNING", help="Disclosure class for legacy non-packet context")
    parser.add_argument("--approve-disclosure", choices=DISCLOSURE_CLASSES, help="Exact operator-approved disclosure class for external routing")
    parser.add_argument("--challenger", action="store_true", help="Enable Challenger Mode red-team persona suffix")
    parser.add_argument("--permute-order", action="store_true", help="Invert packet items order to eliminate LLM judge position bias")
    return parser.parse_args()


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    args = parse_args()
    config = ROLE_CONFIGS[args.role]
    model = args.model or config.get("default_model")
    if not model:
        raise SystemExit(f"Error: --model is required for reviewer lane {args.role}.")

    packet_path = None
    packet = None
    disclosure_class = args.disclosure_class
    output_path = os.path.join(ROOT_DIR, config["output_file"])
    metadata_path = os.path.join(REVIEWS_DIR, f"{args.role}-router-metadata.json")

    if args.packet:
        packet_path, packet = load_packet(args.packet)
        disclosure_class = packet.get("disclosure_class", "LOCAL_CODE_DIRTY")
        output_path = packet_output_path(packet, config)
        metadata_path = packet_metadata_path(packet, args.role)
        verify_disclosure(disclosure_class, args.approve_disclosure, packet_path)
        context_content = build_packet_context(packet_path, packet, permute_order=args.permute_order)
    else:
        context_file = safe_repo_or_abs_path(args.context or DEFAULT_CONTEXT_FILE)
        verify_disclosure(disclosure_class, args.approve_disclosure, context_file)
        if not os.path.exists(context_file):
            raise SystemExit(f"Error: Context file not found at {context_file}")
        with open(context_file, "r", encoding="utf-8") as f:
            context_content = f.read()

    load_env()
    api_key = os.environ.get("OPENROUTER_API_KEY")
    metadata = base_metadata(args, config, model, packet_path, output_path, disclosure_class)
    if not api_key:
        metadata["error_status"] = "missing_openrouter_api_key"
        write_metadata(metadata_path, metadata)
        print("Error: OPENROUTER_API_KEY is not defined in the operator environment or local .env file.")
        print(f"Router metadata written to: {metadata_path}")
        sys.exit(1)

    system_prompt = STRICT_ADVISORY_HEADER + "\n" + load_prompt(config, args.role)
    if args.challenger:
        system_prompt += CHALLENGER_MODE_SNIPPET
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": context_content},
        ],
    }

    req_headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/Simultech369/Pharmacy-Fiduciary-Commons",
        "X-Title": "Pharmacy Fiduciary Commons Audit",
    }

    req_url = "https://openrouter.ai/api/v1/chat/completions"
    max_retries = 3
    retry_delay = 25
    reply = ""
    success = False

    print(f"Initializing OpenRouter review context as: {config['description']}")
    print(f"Target Model: {model}")
    print(f"Disclosure Class: {disclosure_class}")

    for attempt in range(1, max_retries + 1):
        try:
            print(f"Sending request to OpenRouter API (Attempt {attempt}/{max_retries} with {payload['model']})...")
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(req_url, data=req_data, headers=req_headers, method="POST")
            with urllib.request.urlopen(req) as response:
                res_body = response.read().decode("utf-8")
                res_json = json.loads(res_body)
                choices = res_json.get("choices", [])
                if not choices:
                    metadata["error_status"] = "empty_choices"
                    write_metadata(metadata_path, metadata)
                    print("Error: Empty choices returned in response.")
                    print(res_body)
                    sys.exit(1)
                reply = choices[0].get("message", {}).get("content", "")
                finish_reason = choices[0].get("finish_reason")
                metadata["truncation_status"] = "possible_truncation" if finish_reason == "length" else "not_reported"
                success = True
                break
        except urllib.error.HTTPError as exc:
            err_msg = exc.read().decode("utf-8", errors="replace")
            metadata["error_status"] = f"http_{exc.code}"
            metadata["error_detail"] = err_msg[:1000]
            write_metadata(metadata_path, metadata)
            print(f"API HTTP Error {exc.code}: {err_msg}")
            if exc.code == 429 and attempt < max_retries:
                print(f"Rate limited upstream. Sleeping for {retry_delay} seconds before retrying...")
                time.sleep(retry_delay)
                continue
            print(f"Unrecoverable HTTP error {exc.code}. Exiting.")
            sys.exit(1)
        except Exception as exc:
            metadata["error_status"] = "connection_or_transport_error"
            metadata["error_detail"] = str(exc)
            write_metadata(metadata_path, metadata)
            print(f"Connection/Transport Error: {exc}")
            if attempt == max_retries:
                sys.exit(1)
            print(f"Retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)

    if not success:
        metadata["error_status"] = metadata["error_status"] or "unknown_failure"
        write_metadata(metadata_path, metadata)
        print("Error: Could not generate review.")
        sys.exit(1)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as out:
        out.write(reply)

    metadata["error_status"] = None
    write_metadata(metadata_path, metadata)
    print(f"Success: {config['description']} review output written to: {output_path}")
    print(f"Router metadata written to: {metadata_path}")
    print("\n=== REVIEW OUTPUT ===")
    print(reply)
    print("=====================")


if __name__ == "__main__":
    main()
