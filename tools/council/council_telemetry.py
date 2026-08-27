import json
import os
import time
import uuid
from typing import Dict, Any, List, Optional, Tuple
from council_contracts import ImmutableContract

class OTelSpanRecord(ImmutableContract):
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    name: str
    kind: str  # INTERNAL, CLIENT, SERVER
    start_time_ns: int
    end_time_ns: int
    duration_ms: float
    status_code: str  # OK, ERROR, UNSET
    attributes: Dict[str, Any]
    events: List[Dict[str, Any]]

class CouncilTelemetryTracer:
    """
    Framework-agnostic OpenTelemetry (OTel) distributed tracer:
    - W3C TraceContext compliant trace/span ID generation.
    - Zero-dependency span recording for LLM invocations, sandbox runs, and council votes.
    - NDJSON/JSON span logging for observability dashboards.
    """

    def __init__(self, trace_storage_dir: Optional[str] = None):
        state_dir = os.environ.get("COUNCIL_STATE_DIR") or os.path.expanduser("~/.council_state")
        self.trace_storage_dir = trace_storage_dir or os.path.join(state_dir, "traces")
        os.makedirs(self.trace_storage_dir, exist_ok=True)
        self.active_spans: Dict[str, Dict[str, Any]] = {}

    def generate_trace_id(self) -> str:
        return uuid.uuid4().hex

    def generate_span_id(self) -> str:
        return uuid.uuid4().hex[:16]

    def start_span(
        self,
        name: str,
        trace_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
        kind: str = "INTERNAL",
        attributes: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, str]:
        """Starts a span and returns (trace_id, span_id)."""
        t_id = trace_id or self.generate_trace_id()
        s_id = self.generate_span_id()
        start_ns = time.time_ns()

        self.active_spans[s_id] = {
            "trace_id": t_id,
            "span_id": s_id,
            "parent_span_id": parent_span_id,
            "name": name,
            "kind": kind,
            "start_time_ns": start_ns,
            "attributes": attributes or {},
            "events": []
        }
        return t_id, s_id

    def add_span_event(self, span_id: str, event_name: str, attributes: Optional[Dict[str, Any]] = None):
        if span_id in self.active_spans:
            self.active_spans[span_id]["events"].append({
                "name": event_name,
                "time_ns": time.time_ns(),
                "attributes": attributes or {}
            })

    def end_span(
        self,
        span_id: str,
        status_code: str = "OK",
        error_message: Optional[str] = None,
        additional_attributes: Optional[Dict[str, Any]] = None
    ) -> OTelSpanRecord:
        """Ends a span, writes to trace CAS storage, and returns OTelSpanRecord."""
        if span_id not in self.active_spans:
            raise KeyError(f"Span ID '{span_id}' not found in active spans")

        span_data = self.active_spans.pop(span_id)
        end_ns = time.time_ns()
        duration_ms = round((end_ns - span_data["start_time_ns"]) / 1_000_000.0, 3)

        attrs = span_data["attributes"]
        if additional_attributes:
            attrs.update(additional_attributes)
        if error_message:
            attrs["error.message"] = str(error_message)

        record = OTelSpanRecord(
            trace_id=span_data["trace_id"],
            span_id=span_data["span_id"],
            parent_span_id=span_data["parent_span_id"],
            name=span_data["name"],
            kind=span_data["kind"],
            start_time_ns=span_data["start_time_ns"],
            end_time_ns=end_ns,
            duration_ms=duration_ms,
            status_code=status_code,
            attributes=attrs,
            events=span_data["events"]
        )

        trace_file = os.path.join(self.trace_storage_dir, f"trace_{record.trace_id}.ndjson")
        with open(trace_file, "a", encoding="utf-8") as f:
            f.write(record.model_dump_json() + "\n")

        return record

    def list_spans_for_trace(self, trace_id: str) -> List[OTelSpanRecord]:
        trace_file = os.path.join(self.trace_storage_dir, f"trace_{trace_id}.ndjson")
        if not os.path.exists(trace_file):
            return []

        spans = []
        with open(trace_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    spans.append(OTelSpanRecord(**json.loads(line)))
        return spans
