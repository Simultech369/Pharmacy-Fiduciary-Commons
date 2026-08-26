import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

RECEIPT_SCHEMA_VERSION = "pbm.packet_sensitivity_receipt.v2"

PUBLIC_SAFE_PREFIXES = ("docs/", "test/", "README.md", "LICENSE", "COMMONS_CONSTITUTION.md")
INTERNAL_CODE_PREFIXES = ("contracts/", "server/", "tools/", "scripts/", "dashboard/")
ZDR_REQUIRED_PREFIXES = ("circuits/", "proofs/")
LOCAL_ONLY_PREFIXES = (".env", "secrets/", "private/", ".secret")


def sha256_digest(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def canonical_json_digest(payload: dict) -> str:
    canonical_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256_digest(canonical_str)


def content_group_key(artifact: dict) -> str:
    if artifact["provenance_verified"]:
        return f"content:{artifact['content_sha256']}"
    return f"missing:{artifact['path_or_identifier']}:{artifact['content_sha256']}"


def build_packet_cache_key(
    artifacts: list[dict],
    snapshot_composite_state_sha256: str,
    missing_evidence_claims: list[str],
) -> str:
    unique_groups = {}
    for artifact in artifacts:
        group_key = content_group_key(artifact)
        group = unique_groups.setdefault(
            group_key,
            {
                "content_group_key": group_key,
                "sensitivity_tiers": set(),
                "classification_reasons": set(),
            },
        )
        group["sensitivity_tiers"].add(artifact["sensitivity_tier"])
        group["classification_reasons"].add(artifact["classification_reason"])

    artifact_content_groups = [
        {
            "content_group_key": group["content_group_key"],
            "sensitivity_tiers": sorted(group["sensitivity_tiers"]),
            "classification_reasons": sorted(group["classification_reasons"]),
        }
        for group in unique_groups.values()
    ]

    basis = {
        "deduplication_strategy": "CONTENT_SHA256_EXACT_MATCH",
        "snapshot_composite_state_sha256": snapshot_composite_state_sha256,
        "missing_evidence_claims": sorted(missing_evidence_claims),
        "artifact_content_groups": sorted(
            artifact_content_groups,
            key=lambda item: (
                item["content_group_key"],
                "|".join(item["sensitivity_tiers"]),
                "|".join(item["classification_reasons"]),
            ),
        ),
    }
    return canonical_json_digest(basis)


def classify_path_sensitivity(rel_path: str) -> tuple["str", "str"]:
    normalized = rel_path.replace("\\", "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]

    for prefix in LOCAL_ONLY_PREFIXES:
        if normalized.startswith(prefix) or prefix in normalized:
            return "LOCAL_ONLY_REQUIRED", f"Matches secret/private prefix: {prefix}"
    for prefix in ZDR_REQUIRED_PREFIXES:
        if normalized.startswith(prefix):
            return "ZDR_REQUIRED", f"Touches zero-knowledge circuit or proof: {prefix}"
    for prefix in INTERNAL_CODE_PREFIXES:
        if normalized.startswith(prefix):
            return "INTERNAL_NO_TRAIN_OK", f"Internal implementation code: {prefix}"
    for prefix in PUBLIC_SAFE_PREFIXES:
        if normalized.startswith(prefix):
            return "PUBLIC_SAFE", f"Public documentation or open test surface: {prefix}"
    return "INTERNAL_NO_TRAIN_OK", "Default internal classification"


def compile_review_packet(
    file_paths: list[str],
    snapshot_composite_state_sha256: str = "state_composite_head",
    missing_evidence_claims: list[str] = None
) -> dict:
    if missing_evidence_claims is None:
        missing_evidence_claims = []

    artifacts = []
    highest_tier = "PUBLIC_SAFE"
    tier_order = {"PUBLIC_SAFE": 0, "INTERNAL_NO_TRAIN_OK": 1, "ZDR_REQUIRED": 2, "LOCAL_ONLY_REQUIRED": 3}

    first_artifact_by_group = {}

    for path in file_paths:
        norm_path = path.replace("\\", "/")
        if norm_path.startswith("./"):
            norm_path = norm_path[2:]
        tier, reason = classify_path_sensitivity(norm_path)

        if tier_order[tier] > tier_order[highest_tier]:
            highest_tier = tier

        content_sha = "0000000000000000000000000000000000000000000000000000000000000000"
        provenance_verified = False

        if os.path.exists(path) and os.path.isfile(path):
            try:
                with open(path, "rb") as f:
                    content_sha = hashlib.sha256(f.read()).hexdigest()
                provenance_verified = True
            except Exception:
                provenance_verified = False

        artifact_record = {
            "artifact_id": f"art_{len(artifacts) + 1}",
            "path_or_identifier": norm_path,
            "content_sha256": content_sha,
            "provenance_verified": provenance_verified,
            "sensitivity_tier": tier,
            "classification_reason": reason,
        }
        group_key = content_group_key(artifact_record)
        group_id = f"cg_{sha256_digest(group_key)[:16]}"
        duplicate_of = first_artifact_by_group.get(group_key)
        if duplicate_of is None:
            first_artifact_by_group[group_key] = artifact_record["artifact_id"]

        artifact_record["content_group_id"] = group_id
        artifact_record["duplicate_of_artifact_id"] = duplicate_of
        artifacts.append(artifact_record)

    private_count = sum(1 for a in artifacts if not a["provenance_verified"] or a["sensitivity_tier"] != "PUBLIC_SAFE")
    public_safe_verified = (private_count == 0) and (len(artifacts) > 0)
    duplicate_artifact_count = sum(1 for artifact in artifacts if artifact["duplicate_of_artifact_id"] is not None)
    unique_content_artifact_count = len(first_artifact_by_group)
    review_packet_cache_key_sha256 = build_packet_cache_key(
        artifacts,
        snapshot_composite_state_sha256,
        missing_evidence_claims,
    )

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    packet = {
        "receipt_type": "PacketSensitivityReceipt",
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "snapshot_composite_state_sha256": snapshot_composite_state_sha256,
        "sensitivity_tier": highest_tier,
        "public_safe_verified": public_safe_verified,
        "private_artifact_count": private_count,
        "deduplication_strategy": "CONTENT_SHA256_EXACT_MATCH_WITH_PATH_FALLBACK_FOR_MISSING",
        "unique_content_artifact_count": unique_content_artifact_count,
        "duplicate_artifact_count": duplicate_artifact_count,
        "review_packet_cache_key_sha256": review_packet_cache_key_sha256,
        "artifacts": artifacts,
        "missing_evidence_claims": missing_evidence_claims,
        "timestamp": now_iso,
    }
    packet["payload_digest"] = canonical_json_digest(packet)
    return packet


def main():
    parser = argparse.ArgumentParser(description="Compile permission-aware review packets.")
    parser.add_argument("--files", nargs="+", help="List of file paths to inspect and classify.")
    parser.add_argument("--demo", action="store_true", help="Run a standard demo compilation.")
    parser.add_argument("--output", type=str, help="Target file to write JSON receipt to.")
    args = parser.parse_args()

    if args.demo or not args.files:
        files = [
            "contracts/PBMRebateTreasury.sol",
            "docs/ops/KNOWN_FAILURE_POSTMORTEMS.md",
            "test/PBMRebateTreasury.security.test.js"
        ]
        missing_claims = ["No uncommitted diffs outside contracts/ identified"]
    else:
        files = args.files
        missing_claims = []

    packet = compile_review_packet(files, missing_evidence_claims=missing_claims)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(packet, f, indent=2)
        print(f"[OK] PacketSensitivityReceipt written to {args.output}")
    else:
        print(json.dumps(packet, indent=2))


if __name__ == "__main__":
    main()
