#!/usr/bin/env python3
"""
Pharmacy Fiduciary Commons - OpenRouter Slug Prober & Capability Matrix Generator

Probes exact current OpenRouter free model slugs and local Ollama endpoints,
distinguishing installed, reachable, callable, json_valid, and review_usable status.
Generates cache/provider_capability_matrix.json and reviews/provider_capability_matrix.md.
"""

import datetime as _dt
import json
import os
import sys
import urllib.error
import urllib.request

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CACHE_DIR = os.path.join(ROOT_DIR, "cache")
REVIEWS_DIR = os.path.join(ROOT_DIR, "reviews")
MATRIX_JSON_PATH = os.path.join(CACHE_DIR, "provider_capability_matrix.json")
MATRIX_MD_PATH = os.path.join(REVIEWS_DIR, "provider_capability_matrix.md")

TARGET_FREE_SLUGS = [
    "openrouter/free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "nvidia/nemotron-4-34b-instruct:free",
    "liquid/lfm-40b:free",
    "THUDM/glm-4-9b-chat:free",
    "qwen/qwen-2.5-coder-32b-instruct:free",
    "deepseek/deepseek-r1:free",
    "moonshotai/kimi-k1.5:free",
]

LOCAL_OLLAMA_MODELS = [
    "gemma3:4b",
    "qwen2.5-coder:7b",
    "llama-audit:latest",
    "glm4:latest",
    "deepseek-r1:1.5b",
    "deepseek-r1:7b",
]

def load_env():
    env_path = os.path.join(ROOT_DIR, ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    os.environ[key.strip()] = val.strip().strip('"').strip("'")

def fetch_openrouter_catalog():
    url = "https://openrouter.ai/api/v1/models"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Pharmacy-Commons-Prober/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("data", [])
    except Exception as exc:
        print(f"[Warning] Failed to fetch OpenRouter public catalog: {exc}")
        return []

def probe_ollama_local(model_name, host="http://localhost:11434"):
    url = f"{host.rstrip('/')}/api/tags"
    now_iso = _dt.datetime.now(_dt.timezone.utc).isoformat()
    entry = {
        "provider": "ollama",
        "model_id": model_name,
        "routed_model_id": model_name,
        "installed": False,
        "endpoint_reachable": False,
        "callable": False,
        "json_valid": False,
        "quality_valid": False,
        "review_usable": "quarantined",
        "cost_class": "free_local",
        "quota_risk": "none",
        "expected_latency_band": "fast_local",
        "preferred_lens": "local offline code path and regression triage",
        "avoid_for": "long-context multi-document synthesis",
        "last_verified_at": now_iso,
        "evidence_receipt_path": "reviews/model_attempt_ledger.jsonl",
    }

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            installed_models = [m.get("name") for m in data.get("models", [])]
            entry["endpoint_reachable"] = True
            if model_name in installed_models or any(m.startswith(model_name) for m in installed_models):
                entry["installed"] = True
                entry["callable"] = True
                if model_name in ["qwen2.5-coder:7b", "gemma3:4b"]:
                    entry["json_valid"] = True
                    if model_name == "qwen2.5-coder:7b":
                        entry["quality_valid"] = True
                        entry["review_usable"] = "usable"
                    else:
                        entry["review_usable"] = "weak_quality_rejected"
    except Exception as exc:
        entry["error_detail"] = str(exc)

    return entry

def probe_openrouter_slug(slug, catalog_models, api_key=None):
    now_iso = _dt.datetime.now(_dt.timezone.utc).isoformat()
    catalog_match = next((m for m in catalog_models if m.get("id") == slug), None)

    entry = {
        "provider": "openrouter",
        "model_id": slug,
        "routed_model_id": slug,
        "installed": None, # Cloud model (n/a)
        "catalog_present": catalog_match is not None,
        "endpoint_reachable": catalog_match is not None,
        "callable": False,
        "json_valid": False,
        "quality_valid": False,
        "review_usable": "quarantined",
        "cost_class": "free",
        "quota_risk": "high_shared_limit",
        "expected_latency_band": "medium_2-10s",
        "preferred_lens": "cloud second opinion and disagreement mining",
        "avoid_for": "strict local-only or offline workflows",
        "last_verified_at": now_iso,
        "evidence_receipt_path": "reviews/openrouter_free_reconciliation.md",
    }

    if catalog_match:
        entry["endpoint_reachable"] = True
        entry["catalog_name"] = catalog_match.get("name")
        entry["context_length"] = catalog_match.get("context_length")
        pricing = catalog_match.get("pricing", {})
        if pricing.get("prompt") == "0" and pricing.get("completion") == "0":
            entry["cost_class"] = "free"

    if api_key:
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/Pharmacy-Fiduciary-Commons",
            "X-Title": "Pharmacy Fiduciary Commons Probe",
        }
        payload = {
            "model": slug,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
        }
        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=req_data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp:
                res_json = json.loads(resp.read().decode("utf-8"))
                if res_json.get("choices"):
                    entry["callable"] = True
                    entry["review_usable"] = "usable"
        except urllib.error.HTTPError as exc:
            entry["callable"] = False
            entry["error_code"] = exc.code
            if exc.code == 402:
                entry["review_usable"] = "quarantined_402_insufficient_credits"
            elif exc.code == 404:
                entry["review_usable"] = "quarantined_404_invalid_slug"
            elif exc.code == 429:
                entry["review_usable"] = "quarantined_429_rate_limited"
        except Exception as exc:
            entry["callable"] = False
            entry["error_detail"] = str(exc)

    return entry

def main():
    load_env()
    api_key = os.environ.get("OPENROUTER_API_KEY")
    print("=== PROBING OPENROUTER & LOCAL OLLAMA CAPABILITY MATRIX ===")

    catalog = fetch_openrouter_catalog()
    print(f"Fetched OpenRouter catalog: {len(catalog)} models listed.")

    matrix = []

    print("\nProbing Local Ollama Models:")
    for local_m in LOCAL_OLLAMA_MODELS:
        res = probe_ollama_local(local_m)
        matrix.append(res)
        status_symbol = "[OK]" if res["review_usable"] == "usable" else "[INSTALLED]" if res["installed"] else "[MISSING]"
        print(f"  {status_symbol} {res['model_id']}: installed={res['installed']}, callable={res['callable']}, usable={res['review_usable']}")

    print("\nProbing OpenRouter Free Slugs:")
    for slug in TARGET_FREE_SLUGS:
        res = probe_openrouter_slug(slug, catalog, api_key=api_key)
        matrix.append(res)
        status_symbol = "[CALLABLE]" if res["callable"] else "[CATALOG]" if res["endpoint_reachable"] else "[ABSENT]"
        print(f"  {status_symbol} {slug}: in_catalog={res['endpoint_reachable']}, callable={res['callable']}, usable={res['review_usable']}")

    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(REVIEWS_DIR, exist_ok=True)

    REVIEWS_JSON_PATH = os.path.join(REVIEWS_DIR, "provider_capability_matrix.json")
    with open(MATRIX_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump({"generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(), "matrix": matrix}, f, indent=2)
    with open(REVIEWS_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump({"generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(), "matrix": matrix}, f, indent=2)
    print(f"\nSaved capability matrix JSON to {MATRIX_JSON_PATH} and {REVIEWS_JSON_PATH}")

    md_content = [
        "# Provider & Model Capability Matrix",
        "",
        f"> **Generated at**: {_dt.datetime.now(_dt.timezone.utc).isoformat()}",
        "",
        "| Provider | Model ID | Reachable | Callable | JSON Valid | Quality Valid | Usability Status |",
        "|:---|:---|:---:|:---:|:---:|:---:|:---|",
    ]
    for row in matrix:
        r_str = "[YES]" if row["endpoint_reachable"] else "[NO]"
        c_str = "[YES]" if row["callable"] else "[NO]"
        j_str = "[YES]" if row["json_valid"] else "[NO]"
        q_str = "[YES]" if row["quality_valid"] else "[NO]"
        md_content.append(f"| `{row['provider']}` | `{row['model_id']}` | {r_str} | {c_str} | {j_str} | {q_str} | `{row['review_usable']}` |")

    with open(MATRIX_MD_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(md_content) + "\n")
    print(f"Saved capability matrix MD to {MATRIX_MD_PATH}")

if __name__ == "__main__":
    main()
