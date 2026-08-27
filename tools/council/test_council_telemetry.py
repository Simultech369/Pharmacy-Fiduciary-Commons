import os
import shutil
import tempfile
import unittest
from council_telemetry import CouncilTelemetryTracer

class TestCouncilTelemetry(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.tracer = CouncilTelemetryTracer(trace_storage_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_single_span_lifecycle(self):
        t_id, s_id = self.tracer.start_span(
            name="model.invocation",
            attributes={
                "llm.model_slug": "qwen/qwen-3.8-coder",
                "llm.provider": "alibabacloud",
                "route.compliance_tier": "HOSTED_NO_TRAIN"
            }
        )
        self.assertTrue(len(t_id) >= 16)
        self.assertTrue(len(s_id) >= 8)

        self.tracer.add_span_event(s_id, "token.first_received", {"chunk_index": 0})

        span_record = self.tracer.end_span(
            span_id=s_id,
            status_code="OK",
            additional_attributes={
                "llm.tokens.prompt": 512,
                "llm.tokens.completion": 128,
                "llm.cost_usd": 0.00015
            }
        )
        self.assertEqual(span_record.name, "model.invocation")
        self.assertEqual(span_record.status_code, "OK")
        self.assertEqual(span_record.attributes["llm.tokens.prompt"], 512)
        self.assertEqual(len(span_record.events), 1)
        self.assertGreaterEqual(span_record.duration_ms, 0.0)

    def test_multi_span_parent_child_trace(self):
        # Root span: council.convocation
        t_id, root_id = self.tracer.start_span(name="council.convocation")

        # Child span: sandbox.execution
        _, child_id = self.tracer.start_span(
            name="sandbox.execution",
            trace_id=t_id,
            parent_span_id=root_id,
            attributes={"sandbox.engine": "docker", "sandbox.network": "none"}
        )
        self.tracer.end_span(child_id, status_code="OK", additional_attributes={"test.exit_code": 0})

        # End root span
        self.tracer.end_span(root_id, status_code="OK", additional_attributes={"council.verdict": "APPROVED"})

        # Read back spans from trace CAS file
        spans = self.tracer.list_spans_for_trace(t_id)
        self.assertEqual(len(spans), 2)
        
        span_names = [s.name for s in spans]
        self.assertIn("sandbox.execution", span_names)
        self.assertIn("council.convocation", span_names)

        child_span = next(s for s in spans if s.name == "sandbox.execution")
        self.assertEqual(child_span.parent_span_id, root_id)

if __name__ == "__main__":
    unittest.main()
