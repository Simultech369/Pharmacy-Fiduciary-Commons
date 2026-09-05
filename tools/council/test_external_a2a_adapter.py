import unittest
import json
import time
from council_contracts import A2AMessage
from external_a2a_adapter import (
    AgentCard,
    JSONRPCRequest,
    JSONRPCResponse,
    ExternalA2AAdapter
)

class TestExternalA2AAdapter(unittest.TestCase):

    def setUp(self):
        self.card = ExternalA2AAdapter.create_agent_card(
            agent_id="agent.antigravity.v1",
            name="Antigravity Fiduciary Verifier",
            description="Autonomous PBM rebate treasury formal verifier",
            capabilities=["solvency_audit", "smt_z3_bounds", "benford_triage"]
        )

    def test_agent_card_fixture_properties(self):
        self.assertEqual(self.card.agent_id, "agent.antigravity.v1")
        self.assertTrue(self.card.read_only_mode)
        self.assertFalse(self.card.remote_execution_permitted)
        self.assertEqual(self.card.security_clearance, "PUBLIC_SAFE")
        self.assertIn("solvency_audit", self.card.capabilities)

    def test_to_jsonrpc_request_and_redaction(self):
        msg = A2AMessage(
            message_id="msg_001",
            conversation_id="conv_123",
            sender_agent_id="agent.antigravity.v1",
            recipient_agent_id="agent.codex.v1",
            intent="TASK_PROPOSAL",
            payload_data={
                "local_file": "C:\\Users\\Josh\\Desktop\\PBMRebateTreasuryFinal\\contracts\\PBMRebateTreasury.sol",
                "secret_key": "private_key_super_secret_123",
                "normal_field": "verified_status_ok"
            },
            context_snapshot_sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            nonce="nonce_abc",
            timestamp=time.time()
        )

        rpc_req = ExternalA2AAdapter.to_jsonrpc_request(msg)
        self.assertEqual(rpc_req.jsonrpc, "2.0")
        self.assertEqual(rpc_req.method, "council.task_proposal")
        self.assertEqual(rpc_req.id, "msg_001")

        # Verify filesystem path redaction
        params_data = rpc_req.params["data"]
        self.assertEqual(params_data["local_file"], "[REDACTED_LOCAL_PATH]")
        # Verify secret key exclusion / redaction
        self.assertNotIn("secret_key", params_data)
        self.assertEqual(params_data["normal_field"], "verified_status_ok")

    def test_handle_external_request_allowed_methods(self):
        # 1. Ping
        ping_req = JSONRPCRequest(method="council.ping", params={}, id="req_ping")
        res = ExternalA2AAdapter.handle_external_request(ping_req, self.card)
        self.assertIsNone(res.error)
        self.assertIsNotNone(res.result)
        self.assertEqual(res.result.get("status"), "PONG")

        # 2. GetAgentCard
        card_req = JSONRPCRequest(method="council.getAgentCard", params={}, id="req_card")
        res = ExternalA2AAdapter.handle_external_request(card_req, self.card)
        self.assertIsNone(res.error)
        self.assertEqual(res.result.get("agent_id"), "agent.antigravity.v1")
        self.assertTrue(res.result.get("read_only_mode"))

        # 3. Query Solvency Attestation (dynamic SMT Z3 bridge)
        solv_req = JSONRPCRequest(method="council.querySolvencyAttestation", params={}, id="req_solv")
        res = ExternalA2AAdapter.handle_external_request(solv_req, self.card)
        self.assertIsNone(res.error)
        self.assertEqual(res.result.get("attestation_status"), "SOLVENT")
        self.assertEqual(res.result.get("proof_status"), "PROVED")
        self.assertEqual(res.result.get("solvency_status"), "CONSERVED")
        self.assertFalse(res.result.get("audit_replacement_claimed"))
        self.assertFalse(res.result.get("market_truth_claimed"))
        self.assertFalse(res.result.get("remote_execution_permitted"))
        self.assertEqual(
            res.result.get("domains_verified"),
            ["DISPUTE_ESCROW_CAP", "FEE_ON_TRANSFER_INTEGRITY", "GROSS_NET_NON_NEGATIVE", "MUTUAL_CREDIT_ZERO_SUM", "PATIENT_FUND_RECYCLE_SINK_BOUND", "SOLVENCY_DEBT_CONSERVATION", "TREASURY_BUCKET_CONSERVATION"]
        )
        self.assertGreater(res.result.get("invariant_count", 0), 0)
        solv_serialized = json.dumps(res.result, sort_keys=True)
        self.assertNotIn("C:\\", solv_serialized)
        self.assertNotIn("/Users/", solv_serialized)
        self.assertNotIn("private_key", solv_serialized)

        # 4. Query PBM fraud formal invariant attestation
        fraud_req = JSONRPCRequest(method="council.queryFraudInvariantAttestation", params={}, id="req_fraud")
        res = ExternalA2AAdapter.handle_external_request(fraud_req, self.card)
        self.assertIsNone(res.error)
        self.assertEqual(res.result.get("attestation_status"), "PROVED")
        self.assertEqual(res.result.get("benford_output_contract"), "ANOMALY_REVIEW_REQUIRED_ONLY")
        self.assertFalse(res.result.get("fraud_proof_claimed"))
        self.assertFalse(res.result.get("external_business_truth_proven"))
        self.assertFalse(res.result.get("remote_execution_permitted"))
        self.assertEqual(
            res.result.get("domains_verified"),
            ["BENFORD", "DUPLICATE_THERAPY", "HHI", "MME", "REFILL_TOO_SOON"]
        )
        serialized = json.dumps(res.result, sort_keys=True)
        self.assertNotIn("C:\\", serialized)
        self.assertNotIn("/Users/", serialized)
        self.assertNotIn("private_key", serialized)

        # 5. Inspect handoff schema
        schema_req = JSONRPCRequest(method="council.inspectHandoffSchema", params={}, id="req_schema")
        schema_res = ExternalA2AAdapter.handle_external_request(schema_req, self.card)
        self.assertIsNone(schema_res.error)
        self.assertEqual(schema_res.result.get("schema_version"), "A2A-v1.0")
        self.assertTrue(schema_res.result.get("read_only_mode"))
        self.assertFalse(schema_res.result.get("remote_execution_permitted"))
        self.assertIn("council.querySolvencyAttestation", schema_res.result.get("supported_methods", []))

        # 6. Verify receipt envelope
        from pbm_rebate_formal_invariants import PBMRebateFormalInvariantEngine
        valid_envelope = PBMRebateFormalInvariantEngine().prove_all()
        verify_req = JSONRPCRequest(
            method="council.verifyReceipt",
            params={"envelope": valid_envelope.model_dump()},
            id="req_verify"
        )
        verify_res = ExternalA2AAdapter.handle_external_request(verify_req, self.card)
        self.assertIsNone(verify_res.error)
        self.assertTrue(verify_res.result.get("verified"))
        self.assertTrue(verify_res.result.get("payload_sha256_match"))

        # Tampered envelope verification must fail
        tampered = valid_envelope.model_dump()
        tampered["payload"]["all_invariants_proved"] = False
        bad_verify_req = JSONRPCRequest(
            method="council.verifyReceipt",
            params={"envelope": tampered},
            id="req_bad_verify"
        )
        bad_verify_res = ExternalA2AAdapter.handle_external_request(bad_verify_req, self.card)
        self.assertIsNone(bad_verify_res.error)
        self.assertFalse(bad_verify_res.result.get("verified"))

    def test_handle_external_request_blocks_remote_execution(self):
        # Disallowed / dangerous methods must return -32601
        for dangerous_method in [
            "council.executeCode",
            "council.runBashCommand",
            "council.deployContract",
            "council.modifyGovernance",
            "system.eval"
        ]:
            req = JSONRPCRequest(method=dangerous_method, params={"code": "os.system('id')"}, id="req_attack")
            res = ExternalA2AAdapter.handle_external_request(req, self.card)
            self.assertIsNotNone(res.error)
            self.assertEqual(res.error.get("code"), -32601)
            self.assertIn("not allowed", res.error.get("message"))

if __name__ == "__main__":
    unittest.main()
