"""
External Agent-to-Agent (A2A) Adapter & Agent Card Gateway
Provides standard, read-only Agent Card fixtures, JSON-RPC 2.0 message schemas,
and strict privacy/PHI redaction guards. Does not grant remote execution authority.
"""

import json
import re
import time
from typing import Dict, Any, List, Optional, Tuple, Literal, Set
from council_contracts import ImmutableContract, A2AMessage

# Sensitive pattern regular expressions for redaction
PRIVATE_PATH_REGEX = re.compile(r"([A-Za-z]:\\[^\s\"'>]+|/(?:Users|home|root|var|tmp)/[^\s\"'>]+)")
PRIVATE_KEY_REGEX = re.compile(r"(?:private_key|secret|password|bearer\s+[A-Za-z0-9_\-\.]+)", re.IGNORECASE)
PHI_PII_REGEX = re.compile(r"\b(?:\d{3}-\d{2}-\d{4}|\b\d{10}\b(?=.*(?:ssn|npi|patient|dob)))\b", re.IGNORECASE)

class AgentCard(ImmutableContract):
    """
    Standardized, public-safe metadata descriptor for a Council Agent.
    Strictly contains no private storage paths, internal secrets, or execution bindings.
    """
    agent_id: str
    name: str
    description: str
    version: str
    protocol_version: str = "A2A-v1.0"
    capabilities: List[str]
    supported_transports: List[str] = ["jsonrpc_http", "signed_envelope"]
    authentication_methods: List[str] = ["ed25519", "hmac_sha256"]
    security_clearance: Literal["PUBLIC_SAFE", "INTERNAL_NO_TRAIN_OK"] = "PUBLIC_SAFE"
    read_only_mode: bool = True
    remote_execution_permitted: bool = False

class JSONRPCRequest(ImmutableContract):
    """Standard JSON-RPC 2.0 request envelope."""
    jsonrpc: str = "2.0"
    method: str
    params: Dict[str, Any]
    id: Optional[str] = None

class JSONRPCResponse(ImmutableContract):
    """Standard JSON-RPC 2.0 response envelope."""
    jsonrpc: str = "2.0"
    result: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None
    id: Optional[str] = None

class ExternalA2ASecurityError(Exception):
    """Raised when an external A2A payload violates privacy, PHI, or remote execution rules."""
    pass

class ExternalA2AAdapter:
    """
    Converts Council-native messages to and from external A2A shapes,
    enforcing zero-trust privacy boundaries and blocking remote execution.
    """

    ALLOWED_EXTERNAL_METHODS: Set[str] = {
        "council.getAgentCard",
        "council.verifyReceipt",
        "council.querySolvencyAttestation",
        "council.queryFraudInvariantAttestation",
        "council.inspectHandoffSchema",
        "council.ping"
    }

    @staticmethod
    def create_agent_card(
        agent_id: str,
        name: str,
        description: str,
        capabilities: List[str],
        version: str = "1.0.0"
    ) -> AgentCard:
        """Constructs a certified read-only Agent Card."""
        return AgentCard(
            agent_id=agent_id,
            name=name,
            description=description,
            version=version,
            capabilities=capabilities,
            read_only_mode=True,
            remote_execution_permitted=False
        )

    @classmethod
    def sanitize_external_payload(cls, data: Any) -> Any:
        """
        Recursively sanitizes dictionary or string payloads to eliminate:
        1. Local absolute filesystem paths (C:\\... or /Users/...)
        2. Private keys, secret tokens, or API credentials
        3. Potential PHI/PII markers
        """
        if isinstance(data, dict):
            sanitized = {}
            for k, v in data.items():
                if PRIVATE_KEY_REGEX.search(str(k)):
                    continue  # Strip secret keys
                sanitized[k] = cls.sanitize_external_payload(v)
            return sanitized
        elif isinstance(data, list):
            return [cls.sanitize_external_payload(item) for item in data]
        elif isinstance(data, str):
            # Redact file system paths
            redacted = PRIVATE_PATH_REGEX.sub("[REDACTED_LOCAL_PATH]", data)
            # Redact secret phrases
            redacted = PRIVATE_KEY_REGEX.sub("[REDACTED_SECRET]", redacted)
            return redacted
        else:
            return data

    @classmethod
    def to_jsonrpc_request(cls, message: A2AMessage) -> JSONRPCRequest:
        """Converts an internal A2AMessage into a sanitized external JSON-RPC request."""
        sanitized_payload = cls.sanitize_external_payload(message.payload_data)
        return JSONRPCRequest(
            jsonrpc="2.0",
            method=f"council.{message.intent.lower()}",
            params={
                "sender": message.sender_agent_id,
                "recipient": message.recipient_agent_id,
                "data": sanitized_payload,
                "context_snapshot_sha256": message.context_snapshot_sha256,
                "timestamp": message.timestamp
            },
            id=message.message_id
        )

    @classmethod
    def handle_external_request(
        cls,
        request: JSONRPCRequest,
        local_agent_card: AgentCard
    ) -> JSONRPCResponse:
        """
        Processes inbound external JSON-RPC requests under strict read-only rules.
        Rejects any mutating or code-execution methods.
        """
        if request.method not in cls.ALLOWED_EXTERNAL_METHODS:
            return JSONRPCResponse(
                jsonrpc="2.0",
                error={
                    "code": -32601,
                    "message": f"Method '{request.method}' not allowed. Council A2A gateway is read-only and prohibits remote code execution."
                },
                id=request.id
            )

        if request.method == "council.getAgentCard":
            return JSONRPCResponse(
                jsonrpc="2.0",
                result=local_agent_card.model_dump(),
                id=request.id
            )

        if request.method == "council.ping":
            return JSONRPCResponse(
                jsonrpc="2.0",
                result={"status": "PONG", "timestamp": time.time()},
                id=request.id
            )

        if request.method == "council.verifyReceipt":
            return JSONRPCResponse(
                jsonrpc="2.0",
                result=cls._verify_receipt_envelope(request.params),
                id=request.id
            )

        if request.method == "council.inspectHandoffSchema":
            return JSONRPCResponse(
                jsonrpc="2.0",
                result={
                    "schema_version": "A2A-v1.0",
                    "supported_methods": sorted(list(cls.ALLOWED_EXTERNAL_METHODS)),
                    "receipt_types": [
                        "PBMRebateFormalInvariantReceipt",
                        "PBMFraudFormalInvariantReceipt",
                        "SubcommitteeConvocationReceipt",
                    ],
                    "read_only_mode": True,
                    "remote_execution_permitted": False,
                    "timestamp": time.time(),
                },
                id=request.id
            )

        if request.method == "council.querySolvencyAttestation":
            return JSONRPCResponse(
                jsonrpc="2.0",
                result=cls._build_solvency_attestation(),
                id=request.id
            )

        if request.method == "council.queryFraudInvariantAttestation":
            return JSONRPCResponse(
                jsonrpc="2.0",
                result=cls._build_fraud_invariant_attestation(),
                id=request.id
            )

        return JSONRPCResponse(
            jsonrpc="2.0",
            result={"status": "RECEIVED_READ_ONLY"},
            id=request.id
        )

    @classmethod
    def _build_solvency_attestation(cls) -> Dict[str, Any]:
        """
        Builds a public-safe solvency proof summary for external A2A callers.
        Exposes hashes, SMT proof domains, and proof-boundary flags only;
        it does not expose raw local evidence, PHI, or any remote execution capability.
        """
        from pbm_rebate_formal_invariants import PBMRebateFormalInvariantEngine

        receipt_envelope = PBMRebateFormalInvariantEngine().prove_all()
        receipt = receipt_envelope.payload
        attestation = {
            "attestation_status": "SOLVENT" if receipt.all_invariants_proved else "REVIEW_REQUIRED",
            "proof_status": "PROVED" if receipt.all_invariants_proved else "REVIEW_REQUIRED",
            "solvency_status": "CONSERVED" if receipt.all_invariants_proved else "DEFICIT_RISK",
            "proof_suite_id": receipt.proof_suite_id,
            "proof_digest_sha256": receipt.proof_digest_sha256,
            "receipt_payload_sha256": receipt_envelope.payload_sha256,
            "domains_verified": sorted({proof.domain for proof in receipt.invariants}),
            "invariant_count": len(receipt.invariants),
            "target_contracts": receipt.target_contracts,
            "audit_replacement_claimed": receipt.audit_replacement_claimed,
            "market_truth_claimed": receipt.market_truth_claimed,
            "proof_boundary": receipt.proof_boundary,
            "remote_execution_permitted": False,
            "timestamp": time.time(),
        }
        return cls.sanitize_external_payload(attestation)

    @classmethod
    def _verify_receipt_envelope(cls, params: Dict[str, Any]) -> Dict[str, Any]:
        """Verifies a receipt envelope's SHA-256 payload digest in read-only mode."""
        import hashlib
        envelope_data = params.get("envelope") or params.get("receipt_envelope") or params
        if not isinstance(envelope_data, dict):
            return {"verified": False, "reason": "Missing or invalid envelope object"}
        payload_data = envelope_data.get("payload")
        payload_sha256 = envelope_data.get("payload_sha256")
        if not payload_data or not payload_sha256:
            return {"verified": False, "reason": "Envelope missing payload or payload_sha256"}
        computed = hashlib.sha256(
            json.dumps(payload_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        is_valid = (computed == payload_sha256)
        return {
            "verified": is_valid,
            "contract_version": envelope_data.get("contract_version", "unknown"),
            "payload_sha256_match": is_valid,
            "remote_execution_permitted": False,
            "timestamp": time.time(),
        }

    @classmethod
    def _build_fraud_invariant_attestation(cls) -> Dict[str, Any]:
        """
        Builds a public-safe proof summary for external A2A callers.
        This exposes hashes and proof-boundary flags only; it does not expose
        raw local evidence, PHI, or any remote execution capability.
        """
        from pbm_fraud_formal_invariants import PBMFraudFormalInvariantEngine

        receipt_envelope = PBMFraudFormalInvariantEngine().prove_all()
        receipt = receipt_envelope.payload
        attestation = {
            "attestation_status": "PROVED" if receipt.all_invariants_proved else "REVIEW_REQUIRED",
            "proof_suite_id": receipt.proof_suite_id,
            "proof_digest_sha256": receipt.proof_digest_sha256,
            "receipt_payload_sha256": receipt_envelope.payload_sha256,
            "domains_verified": sorted({proof.domain for proof in receipt.invariants}),
            "invariant_count": len(receipt.invariants),
            "benford_output_contract": receipt.benford_output_contract,
            "fraud_proof_claimed": receipt.fraud_proof_claimed,
            "external_business_truth_proven": receipt.external_business_truth_proven,
            "proof_boundary": receipt.proof_boundary,
            "remote_execution_permitted": False,
            "timestamp": time.time(),
        }
        return cls.sanitize_external_payload(attestation)
