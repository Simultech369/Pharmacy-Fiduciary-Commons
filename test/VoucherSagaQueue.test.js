const request = require("supertest");
const { expect } = require("chai");
const ethers = require("ethers");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { createApp, deriveVoucherSagaKey } = require("../server/createApp");

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}

function canonicalVoucherSagaRequest(payload) {
  return {
    pharmacyAddress: payload.pharmacyAddress.toLowerCase(),
    chainId: Number(payload.chainId),
    roundId: payload.roundId.toString(),
    voucherId: payload.voucherId.toLowerCase(),
    amount: payload.amount.toString(),
    clientNonce: payload.clientNonce,
    expiresAt: payload.expiresAt,
    signature: payload.signature
  };
}

function createMockSagaSupabase() {
  const mockDb = {
    voucher_settlement_saga: []
  };

  const client = {
    _mockDb: mockDb,
    _shouldFail: false,
    _voucherCompleteFailuresRemaining: 0,
    _testSkipVoucherLeaseCheck: false,
    rpc: async (func, args) => {
      if (client._shouldFail) {
        return { data: null, error: new Error("PostgreSQL voucher saga outage at supabase.internal") };
      }

      if (func === "voucher_saga_start") {
        let entry = mockDb.voucher_settlement_saga.find(row => row.saga_key === args.p_saga_key);
        if (entry) {
          if (entry.request_hash !== args.p_request_hash) {
            return { data: [{ status: "mismatch", result_json: null, retry_count: entry.retry_count }], error: null };
          }
          if (entry.status === "completed") {
            return {
              data: [{ status: "completed", result_json: entry.result_json, retry_count: entry.retry_count }],
              error: null
            };
          }
          if (entry.status === "dead_letter") {
            return { data: [{ status: "dead_letter", result_json: null, retry_count: entry.retry_count }], error: null };
          }
          const elapsed = Date.now() - new Date(entry.updated_at).getTime();
          if ((entry.status === "pending" || entry.status === "retrying") && elapsed < 15000 && !client._testSkipVoucherLeaseCheck) {
            return { data: [{ status: entry.status, result_json: null, retry_count: entry.retry_count }], error: null };
          }
          entry.status = "pending";
          entry.updated_at = new Date().toISOString();
          return { data: [{ status: "success", result_json: null, retry_count: entry.retry_count }], error: null };
        }

        entry = {
          saga_key: args.p_saga_key,
          request_hash: args.p_request_hash,
          voucher_id: args.p_voucher_id,
          pharmacy_address: args.p_pharmacy_address,
          amount: args.p_amount,
          client_nonce: args.p_client_nonce,
          payload_json: args.p_payload_json,
          result_json: null,
          status: "pending",
          retry_count: 0,
          last_error: null,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };
        mockDb.voucher_settlement_saga.push(entry);
        return { data: [{ status: "success", result_json: null, retry_count: 0 }], error: null };
      }

      if (func === "voucher_saga_complete") {
        if (client._voucherCompleteFailuresRemaining > 0) {
          client._voucherCompleteFailuresRemaining -= 1;
          return { error: new Error("PostgreSQL write lock timeout while completing voucher saga") };
        }
        const entry = mockDb.voucher_settlement_saga.find(row => row.saga_key === args.p_saga_key);
        if (entry) {
          entry.status = "completed";
          entry.result_json = args.p_result_json;
          entry.updated_at = new Date().toISOString();
        }
        return { error: null };
      }

      if (func === "voucher_saga_fail") {
        const entry = mockDb.voucher_settlement_saga.find(row => row.saga_key === args.p_saga_key);
        if (entry) {
          entry.retry_count += 1;
          entry.last_error = args.p_error_code;
          entry.status = args.p_transient && entry.retry_count < 3 ? "retrying" : "dead_letter";
          entry.updated_at = new Date().toISOString();
        }
        return { error: null };
      }

      if (func === "voucher_saga_dead_letter") {
        let entry = mockDb.voucher_settlement_saga.find(row => row.saga_key === args.p_saga_key);
        if (!entry) {
          entry = {
            saga_key: args.p_saga_key,
            request_hash: args.p_request_hash,
            voucher_id: args.p_voucher_id,
            pharmacy_address: args.p_pharmacy_address,
            amount: args.p_amount,
            client_nonce: args.p_client_nonce,
            payload_json: null,
            result_json: null,
            status: "dead_letter",
            retry_count: 0,
            last_error: args.p_error_code,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          };
          mockDb.voucher_settlement_saga.push(entry);
        } else {
          entry.status = "dead_letter";
          entry.last_error = args.p_error_code;
          entry.updated_at = new Date().toISOString();
        }
        return { error: null };
      }

      return { data: null, error: new Error(`Unknown RPC function ${func}`) };
    },
    from: () => {
      throw new Error("Voucher saga tests should use RPC seam only");
    }
  };

  return client;
}

describe("Phase 4: Durable Voucher Settlement Saga Queue", function () {
  let mockSupabase;
  let config;
  let app;
  const pharmacyWallet = ethers.Wallet.createRandom();

  beforeEach(function () {
    mockSupabase = createMockSagaSupabase();
    config = {
      chainId: 31337,
      roundId: "1",
      proxyAddress: "0x1111111111111111111111111111111111111111",
      contractAddress: "0x2222222222222222222222222222222222222222",
      trustedCredentialIssuer: ethers.Wallet.createRandom().address,
      credentialPepper: "secure-long-test-credential-blinding-pepper",
      sagaRetryDelaysMs: [0, 0, 0],
      testMode: true
    };
    app = createApp(mockSupabase, config);
  });

  async function getValidVoucherPayload(overrides = {}) {
    const payload = {
      pharmacyAddress: overrides.pharmacyAddress || pharmacyWallet.address,
      chainId: overrides.chainId || config.chainId,
      roundId: (overrides.roundId || config.roundId).toString(),
      voucherId: overrides.voucherId || `0x${"a".repeat(64)}`,
      amount: overrides.amount || "12500",
      clientNonce: overrides.clientNonce || crypto.randomUUID(),
      expiresAt: overrides.expiresAt || new Date(Date.now() + 5 * 60 * 1000).toISOString()
    };

    const canonicalString = [
      `Pharmacy Fiduciary Commons Database Proxy`,
      `Version: 1`,
      `Action: voucher-reconcile`,
      `Proxy Address: ${config.proxyAddress.toLowerCase()}`,
      `Chain ID: ${payload.chainId}`,
      `Round ID: ${payload.roundId.toString()}`,
      `Pharmacy: ${payload.pharmacyAddress.toLowerCase()}`,
      `Voucher ID: ${payload.voucherId.toLowerCase()}`,
      `Amount: ${payload.amount.toString()}`,
      `Client Nonce: ${payload.clientNonce}`,
      `Expires At: ${payload.expiresAt}`
    ].join("\n");

    payload.signature = await pharmacyWallet.signMessage(canonicalString);
    return payload;
  }

  it("derives unambiguous saga keys across amount and nonce boundaries", function () {
    const base = {
      voucherId: `0x${"b".repeat(64)}`,
      pharmacyAddress: pharmacyWallet.address
    };

    const first = deriveVoucherSagaKey({ ...base, amount: "12", clientNonce: "3" });
    const second = deriveVoucherSagaKey({ ...base, amount: "1", clientNonce: "23" });

    expect(first).to.not.equal(second);
  });

  it("settles a valid voucher intent idempotently on first attempt", async function () {
    const payload = await getValidVoucherPayload();
    const expectedSagaKey = deriveVoucherSagaKey({
      voucherId: payload.voucherId,
      pharmacyAddress: payload.pharmacyAddress,
      amount: payload.amount,
      clientNonce: payload.clientNonce
    });

    const res = await request(app)
      .post("/api/vouchers/reconcile")
      .set("Origin", "http://localhost:3000")
      .send(payload)
      .expect(200);

    expect(res.body).to.deep.include({
      success: true,
      sagaKey: expectedSagaKey,
      status: "completed"
    });
    expect(res.body.result).to.deep.include({
      voucher_id: payload.voucherId.toLowerCase(),
      pharmacy_address: payload.pharmacyAddress.toLowerCase(),
      amount: payload.amount,
      settlement_status: "proxy_reconciled",
      onchain_settlement: "not_claimed"
    });

    const saga = mockSupabase._mockDb.voucher_settlement_saga[0];
    expect(saga.status).to.equal("completed");
    expect(saga.saga_key).to.equal(expectedSagaKey);
  });

  it("returns cached completion and prevents double-settlement on duplicate submission", async function () {
    const payload = await getValidVoucherPayload();

    const first = await request(app)
      .post("/api/vouchers/reconcile")
      .set("Origin", "http://localhost:3000")
      .send(payload)
      .expect(200);

    const second = await request(app)
      .post("/api/vouchers/reconcile")
      .set("Origin", "http://localhost:3000")
      .send(payload)
      .expect(200);

    expect(second.body.replayed).to.equal(true);
    expect(second.body.sagaKey).to.equal(first.body.sagaKey);
    expect(mockSupabase._mockDb.voucher_settlement_saga).to.have.lengthOf(1);
    expect(mockSupabase._mockDb.voucher_settlement_saga[0].status).to.equal("completed");
  });

  it("blocks a concurrent submission while the saga lease is active", async function () {
    const payload = await getValidVoucherPayload();
    const normalized = canonicalVoucherSagaRequest(payload);
    const sagaKey = deriveVoucherSagaKey(normalized);

    mockSupabase._mockDb.voucher_settlement_saga.push({
      saga_key: sagaKey,
      request_hash: sha256(stableStringify(normalized)),
      voucher_id: normalized.voucherId,
      pharmacy_address: normalized.pharmacyAddress,
      amount: normalized.amount,
      client_nonce: normalized.clientNonce,
      payload_json: normalized,
      result_json: null,
      status: "pending",
      retry_count: 0,
      last_error: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    const res = await request(app)
      .post("/api/vouchers/reconcile")
      .set("Origin", "http://localhost:3000")
      .send(payload)
      .expect(429);

    expect(res.body).to.deep.equal({ error: "Voucher settlement lease active" });
  });

  it("retries transient commit failures up to three attempts before DLQ transition", async function () {
    const payload = await getValidVoucherPayload();
    mockSupabase._voucherCompleteFailuresRemaining = 3;

    const res = await request(app)
      .post("/api/vouchers/reconcile")
      .set("Origin", "http://localhost:3000")
      .send(payload)
      .expect(500);

    expect(res.body).to.deep.equal({ error: "Database transaction failed" });
    expect(JSON.stringify(res.body)).to.not.contain("PostgreSQL");
    const saga = mockSupabase._mockDb.voucher_settlement_saga[0];
    expect(saga.status).to.equal("dead_letter");
    expect(saga.retry_count).to.equal(3);
    expect(saga.last_error).to.equal("transient_commit_failure");
  });

  it("routes schema-valid signature failures to dead_letter without exposing internals", async function () {
    const payload = await getValidVoucherPayload();
    payload.signature = await ethers.Wallet.createRandom().signMessage("wrong domain");

    const res = await request(app)
      .post("/api/vouchers/reconcile")
      .set("Origin", "http://localhost:3000")
      .send(payload)
      .expect(401);

    expect(res.body).to.deep.equal({ error: "Invalid voucher reconciliation payload" });
    const saga = mockSupabase._mockDb.voucher_settlement_saga[0];
    expect(saga.status).to.equal("dead_letter");
    expect(saga.last_error).to.equal("invalid_signature");
    expect(JSON.stringify(res.body)).to.not.contain("wrong domain");
  });

  it("fails closed during saga RPC outage with sanitized response payload", async function () {
    const payload = await getValidVoucherPayload();
    mockSupabase._shouldFail = true;

    const res = await request(app)
      .post("/api/vouchers/reconcile")
      .set("Origin", "http://localhost:3000")
      .send(payload)
      .expect(500);

    expect(res.body).to.deep.equal({ error: "Database transaction failed" });
    expect(JSON.stringify(res.body)).to.not.contain("PostgreSQL");
    expect(JSON.stringify(res.body)).to.not.contain("supabase.internal");
  });

  it("documents voucher saga RLS as pharmacy-owner or service-role only", function () {
    const schema = fs.readFileSync(path.join(__dirname, "..", "supabase", "schema.sql"), "utf8");

    expect(schema).to.include("CREATE TABLE IF NOT EXISTS public.voucher_settlement_saga");
    expect(schema).to.include("Pharmacies can read own voucher saga entries");
    expect(schema).to.include("(auth.jwt() ->> 'wallet_address') = pharmacy_address");
    expect(schema).to.include("auth.role() = 'service_role'");
    expect(schema).to.include("ON CONFLICT (saga_key) DO NOTHING");
  });
});
