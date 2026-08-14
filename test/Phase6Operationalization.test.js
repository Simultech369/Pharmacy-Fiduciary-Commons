const { expect } = require("chai");
const request = require("supertest");
const { createApp } = require("../server/createApp");

describe("Phase 6: FDE-Grade Operationalization & Saga Telemetry", function () {
  let app;
  let mockSupabase;
  const sensitivePharmacy = "0x4444444444444444444444444444444444444444";
  const sensitiveVoucher = `0x${"d".repeat(64)}`;
  const sensitiveAmount = "99999912345";

  beforeEach(function () {
    const now = new Date().toISOString();
    const stale = new Date(Date.now() - 60 * 1000).toISOString();

    mockSupabase = {
      _mockDb: {
        voter_profiles: [],
        offline_vouchers: [],
        users: [],
        consumed_nonces: [],
        registration_ledger: [],
        voucher_settlement_saga: [
          {
            status: "pending",
            updated_at: now,
            pharmacy_address: sensitivePharmacy,
            voucher_id: sensitiveVoucher,
            amount: sensitiveAmount
          },
          {
            status: "retrying",
            updated_at: now,
            pharmacy_address: "0x5555555555555555555555555555555555555555",
            voucher_id: `0x${"e".repeat(64)}`,
            amount: "2500"
          },
          {
            status: "dead_letter",
            updated_at: now,
            pharmacy_address: "0x6666666666666666666666666666666666666666",
            voucher_id: `0x${"f".repeat(64)}`,
            amount: "3000",
            last_error: "invalid_signature"
          },
          {
            status: "completed",
            updated_at: stale,
            pharmacy_address: "0x7777777777777777777777777777777777777777",
            voucher_id: `0x${"a".repeat(64)}`,
            amount: "4000"
          }
        ]
      },
      auth: {
        admin: {
          createUser: async () => ({ data: { user: { id: "mock-user-id" } }, error: null })
        }
      },
      rpc: async () => ({ data: null, error: null }),
      from: () => ({
        select: () => ({ eq: () => ({ single: async () => ({ data: null, error: null }) }) }),
        insert: async () => ({ error: null }),
        update: () => ({ eq: async () => ({ error: null }) })
      })
    };

    app = createApp(mockSupabase, {
      chainId: 31337,
      roundId: "1",
      proxyAddress: "0x1111111111111111111111111111111111111111",
      contractAddress: "0x2222222222222222222222222222222222222222",
      trustedCredentialIssuer: "0x3333333333333333333333333333333333333333",
      credentialPepper: "secure-long-test-credential-blinding-pepper",
      testMode: true
    });
  });

  it("returns saga queue telemetry counters in GET /api/health/observability", async function () {
    const res = await request(app)
      .get("/api/health/observability")
      .expect(200);

    expect(res.body).to.have.property("status", "healthy");
    expect(res.body).to.have.property("saga_queue_telemetry");

    const telemetry = res.body.saga_queue_telemetry;
    expect(telemetry).to.have.property("saga_queue_status", "instrumented_in_memory");
    expect(telemetry).to.have.property("metric_source", "prototype_memory_snapshot");
    expect(telemetry).to.include({
      pending_count: 1,
      retrying_count: 1,
      dead_letter_count: 1,
      completed_count: 1,
      active_leases_count: 2,
      alert_status: "DLQ_ATTENTION_REQUIRED"
    });
    expect(res.body.rate_limit_contracts).to.deep.equal({
      voter_registration_max: 100,
      relay_intake_max: 100,
      voucher_reconciliation_max: 50,
      window_ms: 900000
    });
    expect(res.headers["x-ratelimit-contract-voucher-reconciliation"]).to.equal("50");
    expect(res.headers["x-ratelimit-contract-window-ms"]).to.equal("900000");
  });

  it("redacts pharmacy identities, voucher IDs, and financial amounts from observability response", async function () {
    const res = await request(app)
      .get("/api/health/observability")
      .set("Authorization", "Bearer secret-test-jwt")
      .expect(200);

    const rawStr = JSON.stringify(res.body);
    expect(rawStr).to.not.include(sensitivePharmacy);
    expect(rawStr).to.not.include(sensitiveVoucher);
    expect(rawStr).to.not.include(sensitiveAmount);
    expect(rawStr).to.not.include("secret-test-jwt");
    expect(res.body.sanitized_rca).to.deep.include({
      trace_scope: "aggregate_counts_only",
      raw_trace_logging: false
    });
    expect(res.body.sanitized_rca.redacted_fields).to.include("authorization");
    expect(res.body.sanitized_rca.redacted_fields).to.include("signature");
    expect(res.body.solvency.solvency_debt_total).to.be.null;
    expect(res.body.solvency.unclaimed_rebate_escrow).to.be.null;
    expect(res.body.solvency.patient_fund_balance).to.be.null;
  });

  it("reports not_live_instrumented instead of fake zeros when no saga snapshot source exists", async function () {
    const appWithoutSagaSnapshot = createApp({
      auth: { admin: {} },
      rpc: async () => ({ data: null, error: null }),
      from: () => ({})
    }, {
      chainId: 31337,
      roundId: "1",
      proxyAddress: "0x1111111111111111111111111111111111111111",
      contractAddress: "0x2222222222222222222222222222222222222222",
      trustedCredentialIssuer: "0x3333333333333333333333333333333333333333",
      credentialPepper: "secure-long-test-credential-blinding-pepper",
      testMode: true
    });

    const res = await request(appWithoutSagaSnapshot)
      .get("/api/health/observability")
      .expect(200);

    expect(res.body.saga_queue_telemetry).to.include({
      saga_queue_status: "not_live_instrumented",
      metric_source: "unavailable_without_live_reader",
      pending_count: null,
      retrying_count: null,
      dead_letter_count: null,
      completed_count: null,
      active_leases_count: null,
      alert_status: "not_instrumented"
    });
  });
});
