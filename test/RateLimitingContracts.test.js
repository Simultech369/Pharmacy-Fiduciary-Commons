const { expect } = require("chai");
const request = require("supertest");
const { createApp } = require("../server/createApp");

describe("Phase 6: FDE Rate Limiting Contracts & Independent Bucket Isolation", function () {
  let app;
  let mockSupabase;

  beforeEach(function () {
    mockSupabase = {
      _mockDb: {
        voter_profiles: [],
        offline_vouchers: [],
        users: [],
        consumed_nonces: [],
        registration_ledger: [],
        voucher_settlement_saga: []
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

  it("publishes rate limit contracts in GET /api/health/observability response and headers", async function () {
    const res = await request(app)
      .get("/api/health/observability")
      .expect(200);

    expect(res.headers["x-ratelimit-contract-voter-registration"]).to.equal("100");
    expect(res.headers["x-ratelimit-contract-relay-intake"]).to.equal("100");
    expect(res.headers["x-ratelimit-contract-voucher-reconciliation"]).to.equal("50");
    expect(res.headers["x-ratelimit-contract-window-ms"]).to.equal("900000");

    expect(res.body.rate_limit_contracts).to.deep.equal({
      voter_registration_max: 100,
      relay_intake_max: 100,
      voucher_reconciliation_max: 50,
      window_ms: 900000
    });
  });

  it("enforces voucher reconciliation rate limit of 50 requests per window", async function () {
    // Send 50 requests with invalid payload (triggering 400 Bad Request)
    for (let i = 0; i < 50; i++) {
      const res = await request(app)
        .post("/api/vouchers/reconcile")
        .set("Origin", "http://localhost:3000")
        .send({});
      expect(res.status).to.equal(400);
    }

    // The 51st request must trigger 429 Too Many Requests
    const blockedRes = await request(app)
      .post("/api/vouchers/reconcile")
      .set("Origin", "http://localhost:3000")
      .send({});

    expect(blockedRes.status).to.equal(429);
    expect(blockedRes.body).to.have.property("error", "Too many requests, please try again later");
  });

  it("isolates voter registration rate limit bucket from voucher reconciliation bucket", async function () {
    // Fill up the voucher reconciliation bucket (50 requests)
    for (let i = 0; i < 50; i++) {
      await request(app)
        .post("/api/vouchers/reconcile")
        .set("Origin", "http://localhost:3000")
        .send({});
    }

    // Voucher endpoint is now rate limited
    const voucherRes = await request(app)
      .post("/api/vouchers/reconcile")
      .set("Origin", "http://localhost:3000")
      .send({});
    expect(voucherRes.status).to.equal(429);

    // Voter registration endpoint must STILL be available (independent bucket)
    const voterRes = await request(app)
      .post("/api/voters/register")
      .set("Origin", "http://localhost:3000")
      .send({});
    expect(voterRes.status).to.not.equal(429);
  });
});
