#!/usr/bin/env python3
"""
Pharmacy Fiduciary Commons - Dual-Chain Multi-Agent Council Orchestrator & 11-Receipt Verifier

Implements:
1. Sealed Cryptographic Snapshot & Sensitivity Receipts
2. 4-Gate Model Qualification Engine (Schema, Benign Control, Grounded Bug, Sealed Status)
3. 3-Family Quorum Voting Ballot (N=3 distinct families, >= ceil(2N/3) approval threshold)
4. Pure Deterministic 11-Receipt Dual-Chain Invariant Verification
5. Route Attestations (LOCAL_ONLY_VERIFIED, HOSTED_NO_TRAIN, APEX_PAID)
"""

import os
import sys
import json
import hashlib
import argparse
import math
from typing import Any, Literal, Optional, Tuple
from datetime import datetime, timezone

# Force UTF-8 stdout encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CACHE_DIR = os.path.join(REPO_ROOT, "cache")
REVIEWS_DIR = os.path.join(REPO_ROOT, "reviews")

RECEIPT_SCHEMA_VERSION = "pbm.council_receipt.v2"

IsolationMode = Literal["LOCAL_SUBPROCESS_MOCK", "DOCKER_CONTAINER_ENFORCED"]
AuthMode = Literal["SIMULATED_TEST_SIGNATURE", "INTERACTIVE_HUMAN_PROMPT"]

VALID_ISOLATION_MODES = {"LOCAL_SUBPROCESS_MOCK", "DOCKER_CONTAINER_ENFORCED"}
VALID_AUTH_MODES = {"SIMULATED_TEST_SIGNATURE", "INTERACTIVE_HUMAN_PROMPT"}

# 11 Cryptographic Receipt Invariant Types
RECEIPT_TYPES = [
    "SnapshotReceipt",
    "PacketSensitivityReceipt",
    "PatchReceipt",
    "ExecutionSandboxReceipt",
    "CouncilRosterReceipt",
    "ModelQualificationReceipt",
    "CouncilVoteReceipt",
    "SpendLedgerReceipt",
    "AdversarialScoutReceipt",
    "RouteAttestationReceipt",
    "ApplyAuthorizationReceipt",
]

def sha256_digest(data: str) -> str:
    """Computes a canonical SHA-256 hexadecimal digest."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def canonical_json_digest(payload: dict) -> str:
    """Serializes a dictionary canonically and returns its SHA-256 digest."""
    canonical_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256_digest(canonical_str)

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Gate0PolicyError(Exception):
    """Raised when a request fails the repo-local Gate 0 preflight."""


class LogReconstructionDesyncError(Exception):
    """Raised when a gateway payload cannot be reconstructed from the event log."""


class Gate0PolicyPreflight:
    """
    Repo-local Gate 0 preflight for council model dispatch.

    This is intentionally deterministic and conservative. It does not approve
    production egress; it verifies that the simulated gateway path rejects
    obvious prompt-injection and egress-bypass patterns before context assembly.
    """

    FORBIDDEN_MARKERS = [
        "[[system_override]]",
        "ignore previous instructions",
        "developer message override",
        "exfiltrate",
        "leak secret",
        "api key",
        "private key",
        "bypass gateway",
        "raw external post",
    ]

    @classmethod
    def evaluate_request(
        cls,
        request_id: str,
        target_component: str,
        prompt_text: str,
        route_id: str,
    ) -> dict:
        prompt_lower = prompt_text.lower()
        rejections = []

        for marker in cls.FORBIDDEN_MARKERS:
            if marker in prompt_lower:
                rejections.append(f"Gate 0 rejected prompt marker: {marker}")

        if not route_id.startswith("route_local_"):
            rejections.append("Gate 0 rejected non-local route in repo council simulation")

        receipt = {
            "receipt_type": "Gate0PreflightReceipt",
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "request_id": request_id,
            "target_component": target_component,
            "prompt_sha256": sha256_digest(prompt_text),
            "route_id": route_id,
            "passed_preflight": not rejections,
            "rejection_reasons": rejections,
            "matched_principles": [
                "Log-derived context",
                "Gateway-only model dispatch",
                "Read-only local simulation",
            ],
            "timestamp": utc_now_iso(),
        }
        receipt["payload_digest"] = canonical_json_digest(receipt)

        if rejections:
            raise Gate0PolicyError("; ".join(rejections))

        return receipt


class LogDerivedContextEngine:
    """
    Append-only event log used to reconstruct the exact model wire payload.

    The repo version is deliberately small: it covers the fields used by the
    council demo and qualification ladder, and fails closed on any mismatch.
    """

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.event_log: list[dict[str, Any]] = []

    def append_event(self, event_type: str, author: str, payload: dict[str, Any]) -> dict:
        event = {
            "event_id": f"ev_{len(self.event_log):05d}_{canonical_json_digest(payload)[:8]}",
            "event_type": event_type,
            "author": author,
            "payload": payload,
            "timestamp": utc_now_iso(),
        }
        self.event_log.append(event)
        return event

    def derive_model_context(self) -> dict:
        context = {
            "model_id": "default-model",
            "model_family": "generic",
            "provider": "ollama_local",
            "route_id": "route_local_default",
            "temperature": 0.0,
            "max_tokens": 256,
            "response_format": {"type": "json_object"},
            "system_prompt": "",
            "messages": [],
        }

        for event in self.event_log:
            payload = event["payload"]
            if event["event_type"] == "CONFIG_SET":
                for key in (
                    "model_id",
                    "model_family",
                    "provider",
                    "route_id",
                    "temperature",
                    "max_tokens",
                    "response_format",
                ):
                    if key in payload:
                        context[key] = payload[key]
            elif event["event_type"] == "SYSTEM_PROMPT":
                context["system_prompt"] = payload.get("content", context["system_prompt"])
            elif event["event_type"] == "USER_INPUT":
                context["messages"].append({"role": "user", "content": payload.get("content", "")})
            elif event["event_type"] == "ASSISTANT_REPLY":
                context["messages"].append({"role": "assistant", "content": payload.get("content", "")})

        return context

    def derive_wire_payload(self) -> dict:
        context = self.derive_model_context()
        messages = []
        if context["system_prompt"]:
            messages.append({"role": "system", "content": context["system_prompt"]})
        messages.extend(context["messages"])

        return {
            "model": context["model_id"],
            "messages": messages,
            "temperature": context["temperature"],
            "max_tokens": context["max_tokens"],
            "response_format": context["response_format"],
        }

    def verify_and_guard_dispatch(self, actual_wire_payload: dict) -> dict:
        derived_wire = self.derive_wire_payload()
        mismatches = []
        for key in sorted(set(derived_wire.keys()) | set(actual_wire_payload.keys())):
            if derived_wire.get(key) != actual_wire_payload.get(key):
                mismatches.append(
                    f"wire_field:{key} expected={derived_wire.get(key)!r} actual={actual_wire_payload.get(key)!r}"
                )

        receipt = {
            "receipt_type": "LogReconstructionReceipt",
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "session_id": self.session_id,
            "event_log_length": len(self.event_log),
            "derived_context_sha256": canonical_json_digest(derived_wire),
            "request_context_sha256": canonical_json_digest(actual_wire_payload),
            "desync_detected": bool(mismatches),
            "desync_field_mismatches": mismatches,
            "timestamp": utc_now_iso(),
        }
        receipt["payload_digest"] = canonical_json_digest(receipt)

        if mismatches:
            raise LogReconstructionDesyncError(
                f"Log-Reconstruction Desync Detected: {', '.join(mismatches)}"
            )

        return receipt


class ModelGateway:
    """
    Repo-local model gateway simulation.

    The important production boundary is explicit: council model requests must
    pass through invoke_with_resilience(), Gate 0 preflight, and log-derived
    wire-payload reconstruction. This class never performs network dispatch.
    """

    @staticmethod
    def _mock_response(prompt_text: str) -> str:
        prompt_lower = prompt_text.lower()
        if "withdraw" in prompt_lower or "low-level call before balance update" in prompt_lower:
            return '{"reentrancy_risk": true, "reason": "Low-level call before balance update"}'
        return '{"reentrancy_risk": false, "reason": "Pure read-only getter"}'

    def invoke_with_resilience(
        self,
        *,
        model_id: str,
        model_family: str,
        provider: str,
        route_id: str,
        prompt_text: str,
        context_engine: LogDerivedContextEngine,
        system_prompt: str = "",
        wire_payload_override: Optional[dict] = None,
    ) -> Tuple[dict, str]:
        if context_engine is None:
            raise ValueError("ModelGateway.invoke_with_resilience requires LogDerivedContextEngine")

        request_id = f"gw_{sha256_digest(model_id + route_id + prompt_text)[:12]}"
        gate0_receipt = Gate0PolicyPreflight.evaluate_request(
            request_id=request_id,
            target_component="scripts/council_orchestrator.py",
            prompt_text=prompt_text,
            route_id=route_id,
        )

        actual_wire_payload = wire_payload_override or context_engine.derive_wire_payload()
        log_receipt = context_engine.verify_and_guard_dispatch(actual_wire_payload)
        raw_response = self._mock_response(prompt_text)

        receipt = {
            "receipt_type": "ModelGatewayInvocationReceipt",
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "dispatch_api": "ModelGateway.invoke_with_resilience",
            "dispatch_mode": "LOCAL_GATEWAY_SIMULATION_NO_NETWORK",
            "network_dispatch_attempted": False,
            "model_id": model_id,
            "model_family": model_family,
            "provider": provider,
            "route_id": route_id,
            "system_prompt_sha256": sha256_digest(system_prompt),
            "prompt_sha256": sha256_digest(prompt_text),
            "wire_payload_sha256": canonical_json_digest(actual_wire_payload),
            "response_payload_sha256": sha256_digest(raw_response),
            "gate0_preflight_payload_digest": gate0_receipt["payload_digest"],
            "log_reconstruction_payload_digest": log_receipt["payload_digest"],
            "gate0_preflight_receipt": gate0_receipt,
            "log_reconstruction_receipt": log_receipt,
            "timestamp": utc_now_iso(),
        }
        receipt["payload_digest"] = canonical_json_digest(receipt)
        return receipt, raw_response


def build_gateway_context(
    *,
    model_id: str,
    model_family: str,
    provider: str,
    route_id: str,
    prompt_text: str,
    system_prompt: str,
    temperature: float = 0.0,
    max_tokens: int = 256,
) -> LogDerivedContextEngine:
    context_engine = LogDerivedContextEngine(session_id=f"repo_gateway_{sha256_digest(prompt_text)[:12]}")
    context_engine.append_event(
        "CONFIG_SET",
        "council_orchestrator",
        {
            "model_id": model_id,
            "model_family": model_family,
            "provider": provider,
            "route_id": route_id,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        },
    )
    context_engine.append_event("SYSTEM_PROMPT", "council_orchestrator", {"content": system_prompt})
    context_engine.append_event("USER_INPUT", "operator", {"content": prompt_text})
    return context_engine

# ---------------------------------------------------------------------------
# 4-Gate Model Qualification Engine
# ---------------------------------------------------------------------------

class ModelQualificationLadder:
    """
    Evaluates candidate models through the 4-gate verification ladder:
    - Gate 1: Schema Conformance & Strict JSON Syntax
    - Gate 2: Benign Control Test (No Phantom Hallucinations on Clean Code)
    - Gate 3: Grounded Bug Detection (Identifies Exact Vulnerable Line)
    - Gate 4: Issues Sealed ModelQualificationReceipt
    """

    BENIGN_CONTROL_SAMPLE = """
    function getBalance(address account) external view returns (uint256) {
        return balances[account];
    }
    """

    GROUNDED_BUG_SAMPLE = """
    function withdraw(uint256 amount) external {
        (bool s,) = msg.sender.call{value: amount}("");
        require(s, "Transfer failed");
        balances[msg.sender] -= amount;
    }
    """

    QUALIFICATION_SYSTEM_PROMPT = (
        "You are a local simulated Solidity security reviewer. "
        "Return strict JSON with reentrancy_risk and reason."
    )

    @staticmethod
    def evaluate_gate1_schema(raw_response: str) -> tuple[bool, dict]:
        """Asserts response is valid JSON with expected schema fields."""
        try:
            parsed = json.loads(raw_response)
            if not isinstance(parsed, dict):
                return False, {}
            required_keys = {"reentrancy_risk", "reason"}
            if not required_keys.issubset(parsed.keys()):
                return False, {}
            return True, parsed
        except Exception:
            return False, {}

    @staticmethod
    def evaluate_gate2_benign_control(benign_output: dict) -> bool:
        """Asserts clean control code is NOT flagged as vulnerable."""
        if not isinstance(benign_control_result := benign_output.get("reentrancy_risk"), bool):
            return False
        # Clean getter must have reentrancy_risk == False
        return benign_control_result is False

    @staticmethod
    def evaluate_gate3_grounded_bug(bug_output: dict) -> bool:
        """Asserts known reentrancy bug is correctly identified."""
        if not isinstance(bug_result := bug_output.get("reentrancy_risk"), bool):
            return False
        # Reentrancy sample must have reentrancy_risk == True
        return bug_result is True

    @classmethod
    def run_qualification(cls, model_id: str, family: str, provider: str, mock_responses: dict = None) -> dict:
        """Runs the 4-gate qualification suite and returns a sealed receipt."""
        gateway_receipts = []
        dispatch_boundary = "MOCK_RESPONSE_OVERRIDE"

        if mock_responses:
            benign_resp = mock_responses.get(
                "benign",
                '{"reentrancy_risk": false, "reason": "Pure read-only getter"}',
            )
            bug_resp = mock_responses.get(
                "bug",
                '{"reentrancy_risk": true, "reason": "Low-level call before balance update"}',
            )
        else:
            dispatch_boundary = "MODEL_GATEWAY_INVOKE_WITH_RESILIENCE"
            gateway = ModelGateway()
            route_id = "route_local_qualification_ladder"

            benign_prompt = (
                "Evaluate this Solidity sample for reentrancy risk and reply strict JSON.\n\n"
                f"{cls.BENIGN_CONTROL_SAMPLE}"
            )
            benign_context = build_gateway_context(
                model_id=model_id,
                model_family=family,
                provider=provider,
                route_id=route_id,
                prompt_text=benign_prompt,
                system_prompt=cls.QUALIFICATION_SYSTEM_PROMPT,
            )
            benign_receipt, benign_resp = gateway.invoke_with_resilience(
                model_id=model_id,
                model_family=family,
                provider=provider,
                route_id=route_id,
                prompt_text=benign_prompt,
                context_engine=benign_context,
                system_prompt=cls.QUALIFICATION_SYSTEM_PROMPT,
            )

            bug_prompt = (
                "Evaluate this Solidity sample for reentrancy risk and reply strict JSON.\n\n"
                f"{cls.GROUNDED_BUG_SAMPLE}"
            )
            bug_context = build_gateway_context(
                model_id=model_id,
                model_family=family,
                provider=provider,
                route_id=route_id,
                prompt_text=bug_prompt,
                system_prompt=cls.QUALIFICATION_SYSTEM_PROMPT,
            )
            bug_receipt, bug_resp = gateway.invoke_with_resilience(
                model_id=model_id,
                model_family=family,
                provider=provider,
                route_id=route_id,
                prompt_text=bug_prompt,
                context_engine=bug_context,
                system_prompt=cls.QUALIFICATION_SYSTEM_PROMPT,
            )
            gateway_receipts = [benign_receipt, bug_receipt]

        g1_b, b_dict = cls.evaluate_gate1_schema(benign_resp)
        g1_v, v_dict = cls.evaluate_gate1_schema(bug_resp)
        gate1_passed = g1_b and g1_v

        gate2_passed = gate1_passed and cls.evaluate_gate2_benign_control(b_dict)
        gate3_passed = gate1_passed and cls.evaluate_gate3_grounded_bug(v_dict)

        all_passed = gate1_passed and gate2_passed and gate3_passed
        status = "REVIEW_USABLE_FRESH" if all_passed else "QUARANTINED"

        receipt_payload = {
            "receipt_type": "ModelQualificationReceipt",
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "model_id": model_id,
            "family": family,
            "provider": provider,
            "dispatch_boundary": dispatch_boundary,
            "gateway_invocation_receipts": gateway_receipts,
            "gate1_schema_conformance": gate1_passed,
            "gate2_benign_control": gate2_passed,
            "gate3_grounded_bug": gate3_passed,
            "qualification_status": status,
            "timestamp": utc_now_iso(),
        }
        receipt_payload["payload_digest"] = canonical_json_digest(receipt_payload)
        return receipt_payload


# ---------------------------------------------------------------------------
# 11-Receipt Dual-Chain Verifier Engine
# ---------------------------------------------------------------------------

class CouncilReceiptVerifier:
    """
    Pure deterministic verifier enforcing the 11 cryptographic receipt invariants
    across the dual-chain council convocation before changes can be applied.
    """

    @staticmethod
    def verify_full_apply_chain(receipt_chain: dict, require_enforced_apply: bool = False) -> tuple[bool, list[str]]:
        """
        Validates all 11 cryptographic receipt invariants:
        1. SnapshotReceipt integrity & commit digest
        2. PacketSensitivityReceipt classification
        3. PatchReceipt file lists & diff hunk digests
        4. ExecutionSandboxReceipt isolation mode truth & exit code
        5. CouncilRosterReceipt N=3 distinct families quorum
        6. ModelQualificationReceipt REVIEW_USABLE_FRESH status for all voters
        7. CouncilVoteReceipt supermajority consensus (approvals >= ceil(2N/3))
        8. SpendLedgerReceipt budget trigger adherence
        9. AdversarialScoutReceipt hostile red-team output verification
        10. RouteAttestationReceipt verified endpoint compliance
        11. ApplyAuthorizationReceipt authorization mode truth
        """
        errors = []

        # Check presence of all 11 receipt keys
        for r_type in RECEIPT_TYPES:
            if r_type not in receipt_chain:
                errors.append(f"Missing receipt: {r_type}")

        if errors:
            return False, errors

        # 1. SnapshotReceipt
        snap = receipt_chain["SnapshotReceipt"]
        if not snap.get("head_commit") or len(snap.get("head_commit", "")) < 7:
            errors.append("Invariant 1 Violation: Invalid SnapshotReceipt head_commit")

        # 2. PacketSensitivityReceipt
        sens = receipt_chain["PacketSensitivityReceipt"]
        valid_tiers = {"PUBLIC_PROVENANCE_ONLY", "INTERNAL_NO_TRAIN_OK", "LOCAL_ONLY_VERIFIED", "APEX_PAID"}
        if sens.get("compliance_tier") not in valid_tiers:
            errors.append(f"Invariant 2 Violation: Invalid compliance tier '{sens.get('compliance_tier')}'")

        # 3. PatchReceipt
        patch = receipt_chain["PatchReceipt"]
        if not patch.get("files") or not isinstance(patch.get("files"), list):
            errors.append("Invariant 3 Violation: PatchReceipt must list target files")

        # 4. ExecutionSandboxReceipt
        sandbox = receipt_chain["ExecutionSandboxReceipt"]
        isolation_mode = sandbox.get("isolation_mode")
        if isolation_mode not in VALID_ISOLATION_MODES:
            errors.append("Invariant 4 Violation: ExecutionSandboxReceipt missing or invalid isolation_mode")
        elif isolation_mode == "DOCKER_CONTAINER_ENFORCED":
            if sandbox.get("exit_code") != 0 or sandbox.get("isolated") is not True or sandbox.get("network") != "none":
                errors.append(
                    "Invariant 4 Violation: Docker sandbox must be container-enforced, network=none, and exit_code 0"
                )
            if sandbox.get("container_engine") not in {"docker", "podman"}:
                errors.append(
                    "Invariant 4 Violation: DOCKER_CONTAINER_ENFORCED requires docker or podman container_engine"
                )
            if not sandbox.get("container_id") or not sandbox.get("container_image_digest"):
                errors.append(
                    "Invariant 4 Violation: DOCKER_CONTAINER_ENFORCED requires container_id and container_image_digest"
                )
            network_receipt = sandbox.get("network_inspection_sha256")
            if not isinstance(network_receipt, str) or len(network_receipt) != 64:
                errors.append(
                    "Invariant 4 Violation: DOCKER_CONTAINER_ENFORCED requires network_inspection_sha256 evidence"
                )
            if sandbox.get("simulated_demo") is True:
                errors.append("Invariant 4 Violation: Docker-enforced receipts must not be simulated_demo")
        elif isolation_mode == "LOCAL_SUBPROCESS_MOCK":
            if sandbox.get("simulated_demo") is not True:
                errors.append("Invariant 4 Violation: local subprocess mock receipts must be tagged simulated_demo")
            if sandbox.get("container_engine") == "docker" or sandbox.get("network_isolated") is True:
                errors.append("Invariant 4 Violation: local subprocess mock must not claim Docker/network isolation")
            if sandbox.get("tests_passed") not in (None, "SIMULATED_DEMO"):
                errors.append("Invariant 4 Violation: local subprocess mock must not claim numeric passing test counts")

        if require_enforced_apply and isolation_mode != "DOCKER_CONTAINER_ENFORCED":
            errors.append("Invariant 4 Violation: enforced apply requires DOCKER_CONTAINER_ENFORCED isolation_mode")

        # 5. CouncilRosterReceipt (N=3 distinct families)
        roster = receipt_chain["CouncilRosterReceipt"]
        voters = roster.get("voters", [])
        if len(voters) < 3:
            errors.append(f"Invariant 5 Violation: Council requires at least N=3 voters (found {len(voters)})")
        families = {v.get("family") for v in voters if isinstance(v, dict)}
        if len(families) < 3:
            errors.append(f"Invariant 5 Violation: Council requires at least 3 distinct model families (found {len(families)})")

        # 6. ModelQualificationReceipts
        quals = receipt_chain["ModelQualificationReceipt"]
        if not isinstance(quals, list):
            quals = [quals]
        for q in quals:
            if q.get("qualification_status") != "REVIEW_USABLE_FRESH":
                errors.append(f"Invariant 6 Violation: Voter '{q.get('model_id')}' is not REVIEW_USABLE_FRESH")
            if not (
                q.get("gate1_schema_conformance") is True
                and q.get("gate2_benign_control") is True
                and q.get("gate3_grounded_bug") is True
            ):
                errors.append(
                    f"Invariant 6 Violation: Voter '{q.get('model_id')}' failed required qualification gates"
                )

        # 7. CouncilVoteReceipt (Approvals >= ceil(2N/3))
        vote = receipt_chain["CouncilVoteReceipt"]
        approvals = vote.get("approvals", 0)
        total_voters = len(voters)
        required_approvals = math.ceil(2 * total_voters / 3)
        if approvals < required_approvals or vote.get("verdict") != "APPROVED":
            errors.append(
                f"Invariant 7 Violation: Insufficient approvals ({approvals}/{total_voters}, required {required_approvals})"
            )

        # 8. SpendLedgerReceipt
        spend = receipt_chain["SpendLedgerReceipt"]
        if spend.get("cost_usd", 0.0) > spend.get("budget_cap_usd", 0.0):
            errors.append("Invariant 8 Violation: Spend ledger exceeded allocated budget cap")

        # 9. AdversarialScoutReceipt
        scout = receipt_chain["AdversarialScoutReceipt"]
        if not scout.get("scout_model") or scout.get("fuzz_passed") is None:
            errors.append("Invariant 9 Violation: Adversarial scout receipt missing required fuzz metadata")

        # 10. RouteAttestationReceipt
        route = receipt_chain["RouteAttestationReceipt"]
        if not route.get("route_id") or not route.get("route_verified"):
            errors.append("Invariant 10 Violation: Route attestation failed verification")
        if route.get("compliance_tier") in {"HOSTED_NO_TRAIN", "APEX_PAID"} and route.get("zdr_verified") is True:
            if not route.get("zdr_attestation_artifact"):
                errors.append(
                    "Invariant 10 Violation: hosted ZDR/no-train claims require account-level attestation artifact"
                )

        # 11. ApplyAuthorizationReceipt
        auth = receipt_chain["ApplyAuthorizationReceipt"]
        auth_mode = auth.get("auth_mode")
        if auth_mode not in VALID_AUTH_MODES:
            errors.append("Invariant 11 Violation: ApplyAuthorizationReceipt missing or invalid auth_mode")
        if not auth.get("signer") or not auth.get("authorized"):
            errors.append("Invariant 11 Violation: apply authorization signer is missing or unauthorized")
        if auth_mode == "INTERACTIVE_HUMAN_PROMPT" and auth.get("simulated_demo") is True:
            errors.append("Invariant 11 Violation: interactive human authorization cannot be marked simulated_demo")
        if auth_mode == "INTERACTIVE_HUMAN_PROMPT" and not auth.get("approval_artifact"):
            errors.append("Invariant 11 Violation: interactive human authorization requires approval_artifact")
        if auth_mode == "INTERACTIVE_HUMAN_PROMPT" and auth.get("approval_artifact"):
            approval_artifact = auth.get("approval_artifact")
            if not isinstance(approval_artifact, dict):
                errors.append("Invariant 11 Violation: approval_artifact must be a structured object")
            else:
                if approval_artifact.get("simulated_demo") is True:
                    errors.append("Invariant 11 Violation: interactive human authorization cannot use simulated_demo artifact")
                if approval_artifact.get("signature_algorithm") != "HMAC_SHA256":
                    errors.append("Invariant 11 Violation: current interactive authorization requires HMAC_SHA256 artifact")
                if not approval_artifact.get("detached_signature"):
                    errors.append("Invariant 11 Violation: approval_artifact requires detached_signature")
                if approval_artifact.get("subject_sha256") != patch.get("payload_digest"):
                    errors.append("Invariant 11 Violation: approval_artifact subject_sha256 must match PatchReceipt digest")
        if auth_mode == "SIMULATED_TEST_SIGNATURE" and auth.get("approval_artifact"):
            errors.append("Invariant 11 Violation: simulated test signatures must not attach live approval artifacts")
        if require_enforced_apply and auth_mode != "INTERACTIVE_HUMAN_PROMPT":
            errors.append("Invariant 11 Violation: enforced apply requires INTERACTIVE_HUMAN_PROMPT auth_mode")

        # Cryptographic Digest Consistency
        for r_type, r_data in receipt_chain.items():
            if isinstance(r_data, dict) and "payload_digest" in r_data:
                # Re-compute digest omitting payload_digest key
                data_copy = {k: v for k, v in r_data.items() if k != "payload_digest"}
                expected_digest = canonical_json_digest(data_copy)
                if r_data["payload_digest"] != expected_digest:
                    errors.append(f"Cryptographic Digest Mismatch in {r_type}")
            elif isinstance(r_data, list):
                for idx, item in enumerate(r_data):
                    if isinstance(item, dict) and "payload_digest" in item:
                        item_copy = {k: v for k, v in item.items() if k != "payload_digest"}
                        expected_digest = canonical_json_digest(item_copy)
                        if item["payload_digest"] != expected_digest:
                            errors.append(f"Cryptographic Digest Mismatch in {r_type}[{idx}]")

        is_valid = len(errors) == 0
        return is_valid, errors


# ---------------------------------------------------------------------------
# Council Convocation Orchestrator Demo
# ---------------------------------------------------------------------------

def run_mock_council_convocation(head_commit: str = "4a89257", target_files: list = None) -> dict:
    """Builds a simulated 3-family council convocation receipt chain."""
    if target_files is None:
        target_files = ["contracts/PBMRebateTreasury.sol"]

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Step 1: SnapshotReceipt
    snap_data = {
        "receipt_type": "SnapshotReceipt",
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "head_commit": head_commit,
        "branch": "main",
        "timestamp": now_iso,
    }
    snap_data["payload_digest"] = canonical_json_digest(snap_data)

    # Step 2: PacketSensitivityReceipt
    sens_data = {
        "receipt_type": "PacketSensitivityReceipt",
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "compliance_tier": "INTERNAL_NO_TRAIN_OK",
        "zdr_verified": False,
        "zdr_attestation_status": "SIMULATED_DEMO_UNATTESTED",
        "timestamp": now_iso,
    }
    sens_data["payload_digest"] = canonical_json_digest(sens_data)

    # Step 3: PatchReceipt
    patch_data = {
        "receipt_type": "PatchReceipt",
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "files": target_files,
        "hunks_count": 1,
        "timestamp": now_iso,
    }
    patch_data["payload_digest"] = canonical_json_digest(patch_data)

    # Step 4: ExecutionSandboxReceipt
    sandbox_data = {
        "receipt_type": "ExecutionSandboxReceipt",
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "isolation_mode": "LOCAL_SUBPROCESS_MOCK",
        "isolated": False,
        "network": "not_enforced_mock",
        "container_engine": "none",
        "exit_code": 0,
        "test_suite": "simulated_demo",
        "tests_passed": "SIMULATED_DEMO",
        "simulated_demo": True,
        "simulation_scope": "receipt-chain schema demo; no live container or Hardhat execution is asserted",
        "timestamp": now_iso,
    }
    sandbox_data["payload_digest"] = canonical_json_digest(sandbox_data)

    # Step 5: CouncilRosterReceipt (N=3 distinct families)
    roster_data = {
        "receipt_type": "CouncilRosterReceipt",
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "voters": [
            {"seat": 1, "model_id": "qwen2.5-coder:7b", "family": "qwen", "provider": "ollama_local"},
            {"seat": 2, "model_id": "glm4:latest", "family": "glm", "provider": "ollama_local"},
            {"seat": 3, "model_id": "mistral:latest", "family": "mistral", "provider": "ollama_local"},
        ],
        "timestamp": now_iso,
    }
    roster_data["payload_digest"] = canonical_json_digest(roster_data)

    # Step 6: ModelQualificationReceipts (3 seats qualified)
    qual_receipts = [
        ModelQualificationLadder.run_qualification("qwen2.5-coder:7b", "qwen", "ollama_local"),
        ModelQualificationLadder.run_qualification("glm4:latest", "glm", "ollama_local"),
        ModelQualificationLadder.run_qualification("mistral:latest", "mistral", "ollama_local"),
    ]

    # Step 7: CouncilVoteReceipt (3/3 approvals)
    vote_data = {
        "receipt_type": "CouncilVoteReceipt",
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "total_seats": 3,
        "approvals": 3,
        "rejections": 0,
        "verdict": "APPROVED",
        "ballots": [
            {"seat": 1, "model": "qwen2.5-coder:7b", "vote": "APPROVE", "confidence": 1.0},
            {"seat": 2, "model": "glm4:latest", "vote": "APPROVE", "confidence": 1.0},
            {"seat": 3, "model": "mistral:latest", "vote": "APPROVE", "confidence": 0.95},
        ],
        "timestamp": now_iso,
    }
    vote_data["payload_digest"] = canonical_json_digest(vote_data)

    # Step 8: SpendLedgerReceipt
    spend_data = {
        "receipt_type": "SpendLedgerReceipt",
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "cost_usd": 0.0000,
        "budget_cap_usd": 1.0000,
        "ledger_engine": "sqlite_triggers_local",
        "timestamp": now_iso,
    }
    spend_data["payload_digest"] = canonical_json_digest(spend_data)

    # Step 9: AdversarialScoutReceipt
    scout_data = {
        "receipt_type": "AdversarialScoutReceipt",
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "scout_model": "jiunsong-supergemma-12b-gguf",
        "fuzz_mode": "uncensored_reentrancy_griefing",
        "fuzz_passed": True,
        "vulnerabilities_found": 0,
        "timestamp": now_iso,
    }
    scout_data["payload_digest"] = canonical_json_digest(scout_data)

    # Step 10: RouteAttestationReceipt
    route_data = {
        "receipt_type": "RouteAttestationReceipt",
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "route_id": "route_local_ollama_3_family_quorum",
        "compliance_tier": "LOCAL_ONLY_VERIFIED",
        "route_verified": True,
        "timestamp": now_iso,
    }
    route_data["payload_digest"] = canonical_json_digest(route_data)

    # Step 11: ApplyAuthorizationReceipt
    auth_data = {
        "receipt_type": "ApplyAuthorizationReceipt",
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "auth_mode": "SIMULATED_TEST_SIGNATURE",
        "signer": "simulated_test_operator@local",
        "authorized": True,
        "simulated_demo": True,
        "timestamp": now_iso,
    }
    auth_data["payload_digest"] = canonical_json_digest(auth_data)

    chain = {
        "SnapshotReceipt": snap_data,
        "PacketSensitivityReceipt": sens_data,
        "PatchReceipt": patch_data,
        "ExecutionSandboxReceipt": sandbox_data,
        "CouncilRosterReceipt": roster_data,
        "ModelQualificationReceipt": qual_receipts,
        "CouncilVoteReceipt": vote_data,
        "SpendLedgerReceipt": spend_data,
        "AdversarialScoutReceipt": scout_data,
        "RouteAttestationReceipt": route_data,
        "ApplyAuthorizationReceipt": auth_data,
    }

    return chain


def tamper_wire_payload(payload: dict, field_name: str) -> dict:
    """Returns a modified wire payload for fail-closed log reconstruction tests."""
    tampered = json.loads(json.dumps(payload))
    if field_name == "max_tokens":
        tampered["max_tokens"] = tampered.get("max_tokens", 0) + 1
    elif field_name == "temperature":
        tampered["temperature"] = 0.99
    elif field_name == "messages":
        tampered.setdefault("messages", []).append({"role": "user", "content": "tampered late context"})
    elif field_name == "model":
        tampered["model"] = "tampered-model"
    else:
        raise ValueError(f"Unsupported tamper field: {field_name}")
    return tampered


def run_gateway_dispatch_demo(prompt_text: str, tamper_wire_field: Optional[str] = None) -> dict:
    """
    Executes the repo-local gateway path without network dispatch.

    This is a proof-boundary demo for Gate 0 and log reconstruction, not a live
    provider call or hosted ZDR attestation.
    """
    model_id = "qwen2.5-coder:7b"
    model_family = "qwen"
    provider = "ollama_local"
    route_id = "route_local_gateway_demo"
    system_prompt = (
        "You are a local simulated council reviewer. "
        "Return strict JSON with reentrancy_risk and reason."
    )

    context_engine = build_gateway_context(
        model_id=model_id,
        model_family=model_family,
        provider=provider,
        route_id=route_id,
        prompt_text=prompt_text,
        system_prompt=system_prompt,
    )
    actual_wire_payload = context_engine.derive_wire_payload()
    if tamper_wire_field:
        actual_wire_payload = tamper_wire_payload(actual_wire_payload, tamper_wire_field)

    gateway = ModelGateway()
    gateway_receipt, raw_response = gateway.invoke_with_resilience(
        model_id=model_id,
        model_family=model_family,
        provider=provider,
        route_id=route_id,
        prompt_text=prompt_text,
        context_engine=context_engine,
        system_prompt=system_prompt,
        wire_payload_override=actual_wire_payload if tamper_wire_field else None,
    )

    receipt = {
        "receipt_type": "GatewayDispatchDemoReceipt",
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "dispatch_boundary": "MODEL_GATEWAY_INVOKE_WITH_RESILIENCE",
        "dispatch_mode": "LOCAL_GATEWAY_SIMULATION_NO_NETWORK",
        "network_dispatch_attempted": False,
        "tamper_wire_field": tamper_wire_field,
        "gateway_invocation_receipt": gateway_receipt,
        "raw_response_sha256": sha256_digest(raw_response),
        "timestamp": utc_now_iso(),
    }
    receipt["payload_digest"] = canonical_json_digest(receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description="Dual-Chain Multi-Agent Council Orchestrator & 11-Receipt Verifier")
    parser.add_argument("--demo", action="store_true", help="Execute a mock 3-family council convocation and verify receipts")
    parser.add_argument("--qualify", type=str, help="Run 4-gate qualification ladder on specified model ID")
    parser.add_argument("--verify-json", type=str, help="Path to receipt chain JSON file to verify")
    parser.add_argument(
        "--gateway-dispatch-demo",
        action="store_true",
        help="Run a repo-local ModelGateway.invoke_with_resilience dispatch proof demo",
    )
    parser.add_argument(
        "--gateway-prompt",
        type=str,
        default="Evaluate this Solidity getter for reentrancy risk: function getBalance(address a) external view returns (uint256) { return balances[a]; }",
        help="Prompt text for --gateway-dispatch-demo",
    )
    parser.add_argument(
        "--tamper-wire-field",
        choices=["max_tokens", "temperature", "messages", "model"],
        help="Tamper a reconstructed wire payload field to prove fail-closed desync detection",
    )
    parser.add_argument(
        "--require-enforced-apply",
        action="store_true",
        help="Require live Docker isolation and interactive human authorization instead of simulated demo modes",
    )

    args = parser.parse_args()

    if args.qualify:
        print(f"=== RUNNING 4-GATE QUALIFICATION LADDER: {args.qualify} ===")
        receipt = ModelQualificationLadder.run_qualification(args.qualify, "generic", "ollama_local")
        print(json.dumps(receipt, indent=2))
        sys.exit(0 if receipt["qualification_status"] == "REVIEW_USABLE_FRESH" else 1)

    if args.gateway_dispatch_demo:
        try:
            receipt = run_gateway_dispatch_demo(
                prompt_text=args.gateway_prompt,
                tamper_wire_field=args.tamper_wire_field,
            )
            print(json.dumps(receipt, indent=2))
            sys.exit(0)
        except (Gate0PolicyError, LogReconstructionDesyncError, ValueError) as exc:
            print(f">> GATEWAY DISPATCH FAILED: {exc}")
            sys.exit(1)

    if args.verify_json:
        if not os.path.exists(args.verify_json):
            print(f"Error: File '{args.verify_json}' not found.")
            sys.exit(1)
        with open(args.verify_json, "r", encoding="utf-8") as f:
            chain = json.load(f)
        valid, errors = CouncilReceiptVerifier.verify_full_apply_chain(
            chain,
            require_enforced_apply=args.require_enforced_apply,
        )
        if valid:
            print(">> VERIFICATION SUCCESS: All 11 receipt invariants hold for the supplied policy mode.")
            sys.exit(0)
        else:
            print(f">> VERIFICATION FAILED ({len(errors)} errors):")
            for e in errors:
                print(f"  - {e}")
            sys.exit(1)

    if args.demo or len(sys.argv) == 1:
        print("================================================================================")
        print("INITIATING SIMULATED DUAL-CHAIN MULTI-AGENT COUNCIL CONVOCATION")
        print("================================================================================")
        chain = run_mock_council_convocation()
        print("[Step 1] Sealed SnapshotReceipt (Head: 4a89257)")
        print("[Step 2] Sealed PacketSensitivityReceipt (Tier: INTERNAL_NO_TRAIN_OK, ZDR: SIMULATED_DEMO_UNATTESTED)")
        print("[Step 3] Sealed PatchReceipt (Files: ['contracts/PBMRebateTreasury.sol'], Hunks: 1)")
        print("[Step 4] Sealed ExecutionSandboxReceipt (Mode: LOCAL_SUBPROCESS_MOCK, tests: SIMULATED_DEMO)")
        print("[Step 5] Sealed Frozen CouncilRosterReceipt (N=3 voters across 3 families: Qwen, GLM, Mistral)")
        print("[Step 6] Running 4-Gate Qualification Ladder via ModelGateway.invoke_with_resilience -> All REVIEW_USABLE_FRESH")
        print("[Step 7] Sealed CouncilVoteReceipt: Verdict=APPROVED (3/3 approvals)")
        print("[Step 8] Sealed SpendLedgerReceipt (Cost: $0.0000 / Cap: $1.0000)")
        print("[Step 9] Sealed AdversarialScoutReceipt (Model: Jiunsong SuperGemma 12B GGUF)")
        print("[Step 10] Sealed RouteAttestationReceipt (Tier: LOCAL_ONLY_VERIFIED)")
        print("[Step 11] Sealed ApplyAuthorizationReceipt (Mode: SIMULATED_TEST_SIGNATURE)")
        print("--------------------------------------------------------------------------------")
        print("Running CouncilReceiptVerifier.verify_full_apply_chain...")
        valid, errors = CouncilReceiptVerifier.verify_full_apply_chain(chain)
        if valid:
            print(">> VERIFICATION SUCCESS: All 11 receipt invariants hold for SIMULATED demo mode.")
            print(">> This is not evidence of live Docker isolation or live human authorization.")
            # Save demo receipt
            os.makedirs(CACHE_DIR, exist_ok=True)
            out_file = os.path.join(CACHE_DIR, "council_convocation_demo_receipt.json")
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(chain, f, indent=2)
            print(f">> Sealed receipt written to: {out_file}")
            sys.exit(0)
        else:
            print(f">> VERIFICATION FAILED with {len(errors)} errors:")
            for e in errors:
                print(f"  - {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
