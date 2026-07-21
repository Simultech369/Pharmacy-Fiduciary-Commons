const request = require("supertest");
const { expect } = require("chai");
const ethers = require("ethers");
const crypto = require("crypto");
const { createApp } = require("../server/createApp");

// Generate random wallet for voter
const testWallet = ethers.Wallet.createRandom();

// Well-known Hardhat account 0 used as trusted issuer
const issuerPrivateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const issuerWallet = new ethers.Wallet(issuerPrivateKey);

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function createMockSupabase() {
  const mockDb = {
    voter_profiles: [],
    offline_vouchers: [],
    users: [],
    consumed_nonces: []
  };

  const client = {
    _mockDb: mockDb,
    _shouldFail: false,
    auth: {
      admin: {
        createUser: async ({ email, user_metadata }) => {
          const id = crypto.randomUUID();
          const user = { id, email, user_metadata };
          mockDb.users.push(user);
          return { data: { user }, error: null };
        }
      }
    },
    from: (table) => {
      return {
        select: () => ({
          eq: (col, val) => ({
            maybeSingle: async () => {
              if (client._shouldFail) {
                return { data: null, error: new Error("Mock Supabase query error") };
              }
              const data = mockDb[table].find(row => row[col] === val);
              return { data: data || null, error: null };
            }
          })
        }),
        insert: async (row) => {
          if (client._shouldFail) {
            return { error: new Error("Mock database connection failed") };
          }
          // Enforce unique constraint simulation on consumed_nonces table
          if (table === "consumed_nonces") {
            const exists = mockDb.consumed_nonces.some(r => r.nonce_key === row.nonce_key);
            if (exists) {
              return { error: new Error("Duplicate key violation on nonces") };
            }
          }
          mockDb[table].push(row);
          return { error: null };
        },
        update: (updates) => ({
          eq: async (col, val) => {
            if (client._shouldFail) {
              return { error: new Error("Mock database connection failed") };
            }
            const data = mockDb[table].find(row => row[col] === val);
            if (data) {
              Object.assign(data, updates);
            }
            return { error: null };
          }
        })
      };
    }
  };

  return client;
}

describe("Database API Proxy Server", () => {
  let mockSupabase;
  let app;

  beforeEach(() => {
    mockSupabase = createMockSupabase();
    mockSupabase._shouldFail = false;
    app = createApp(mockSupabase);
  });

  async function getValidRegistrationPayload() {
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    const chainId = 31337;
    const roundId = "1";
    const credentialHash = "0x" + "a".repeat(64);
    const policyVersion = "1.0.0";
    const nonce = crypto.randomUUID();

    const voterMessage = [
      `Pharmacy Fiduciary Commons Database Proxy`,
      `Version: 1`,
      `Action: register-voter`,
      `Chain ID: ${chainId}`,
      `Round ID: ${roundId}`,
      `Wallet: ${testWallet.address}`,
      `Credential Hash: ${credentialHash}`,
      `Policy Version: ${policyVersion}`,
      `Nonce: ${nonce}`,
      `Expires At: ${expiresAt}`
    ].join("\n");
    const signature = await testWallet.signMessage(voterMessage);

    const issuerMessage = [
      `Pharmacy Fiduciary Commons Credential Authorization`,
      `Wallet: ${testWallet.address.toLowerCase()}`,
      `Credential Hash: ${credentialHash}`,
      `Policy Version: ${policyVersion}`
    ].join("\n");
    const issuerSignature = await issuerWallet.signMessage(issuerMessage);

    return {
      walletAddress: testWallet.address,
      chainId,
      roundId,
      credentialHash,
      policyVersion,
      nonce,
      expiresAt,
      signature,
      issuerSignature
    };
  }

  describe("POST /api/voters/register", () => {
    it("successfully registers a new voter with valid signatures", async () => {
      const payload = await getValidRegistrationPayload();

      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(200);
      expect(res.body.success).to.be.true;
      expect(res.body.userId).to.be.a("string");

      expect(mockSupabase._mockDb.voter_profiles).to.have.lengthOf(1);
      const profile = mockSupabase._mockDb.voter_profiles[0];
      expect(profile.wallet_address).to.equal(testWallet.address.toLowerCase());
      
      const expectedBlindedHash = sha256(payload.credentialHash);
      expect(JSON.parse(profile.encrypted_metadata)).to.deep.equal({
        credentialHash: expectedBlindedHash,
        policyVersion: payload.policyVersion
      });
    });

    it("fails registration if voter signature is invalid", async () => {
      const payload = await getValidRegistrationPayload();
      payload.signature = await testWallet.signMessage("wrong payload message");

      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(401);
      expect(res.body.error).to.include("Signature recovery mismatch");
    });

    it("fails registration if issuer signature is invalid (unauthorized credential)", async () => {
      const payload = await getValidRegistrationPayload();
      const unauthorizedWallet = ethers.Wallet.createRandom();
      payload.issuerSignature = await unauthorizedWallet.signMessage("some random auth signature");

      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(401);
      expect(res.body.error.toLowerCase()).to.include("unauthorized");
    });

    it("fails registration if expiresAt timestamp is expired", async () => {
      const expiredTimestamp = new Date(Date.now() - 5 * 60 * 1000).toISOString();
      const payload = await getValidRegistrationPayload();
      payload.expiresAt = expiredTimestamp;

      // Re-sign with correct expired time
      const voterMessage = [
        `Pharmacy Fiduciary Commons Database Proxy`,
        `Version: 1`,
        `Action: register-voter`,
        `Chain ID: ${payload.chainId}`,
        `Round ID: ${payload.roundId}`,
        `Wallet: ${testWallet.address}`,
        `Credential Hash: ${payload.credentialHash}`,
        `Policy Version: ${payload.policyVersion}`,
        `Nonce: ${payload.nonce}`,
        `Expires At: ${expiredTimestamp}`
      ].join("\n");
      payload.signature = await testWallet.signMessage(voterMessage);

      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(401);
      expect(res.body.error).to.include("expiration has passed");
    });

    it("fails if nonce is replayed (durable unique check)", async () => {
      const payload = await getValidRegistrationPayload();

      // First request passes
      const res1 = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);
      expect(res1.status).to.equal(200);

      // Second request fails with same nonce
      const res2 = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);
      expect(res2.status).to.equal(401);
      expect(res2.body.error).to.include("Replay attempt detected");
    });

    it("does NOT burn the nonce if signature verification fails", async () => {
      const payload = await getValidRegistrationPayload();
      const goodSignature = payload.signature;
      
      // Submit with a bad signature first
      payload.signature = await testWallet.signMessage("bad message signature");
      const res1 = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);
      expect(res1.status).to.equal(401);

      // Submit again using the correct signature and same nonce (should succeed)
      payload.signature = goodSignature;
      const res2 = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);
      expect(res2.status).to.equal(200);
    });

    it("rejects signature lifetime extensions over the 15-minute maximum", async () => {
      const farFutureExpiry = new Date(Date.now() + 20 * 60 * 1000).toISOString();
      const payload = await getValidRegistrationPayload();
      payload.expiresAt = farFutureExpiry;

      const voterMessage = [
        `Pharmacy Fiduciary Commons Database Proxy`,
        `Version: 1`,
        `Action: register-voter`,
        `Chain ID: ${payload.chainId}`,
        `Round ID: ${payload.roundId}`,
        `Wallet: ${testWallet.address}`,
        `Credential Hash: ${payload.credentialHash}`,
        `Policy Version: ${payload.policyVersion}`,
        `Nonce: ${payload.nonce}`,
        `Expires At: ${farFutureExpiry}`
      ].join("\n");
      payload.signature = await testWallet.signMessage(voterMessage);

      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(400);
      expect(res.body.error).to.include("exceeds maximum permitted lifetime");
    });

    it("rejects malformed dates with NaN values", async () => {
      const payload = await getValidRegistrationPayload();
      payload.expiresAt = "invalid-date-format";

      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(400);
      expect(res.body.error).to.include("Invalid expiration format");
    });

    it("returns redacted 500 when Supabase write fails", async () => {
      const payload = await getValidRegistrationPayload();
      mockSupabase._shouldFail = true;

      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(500);
      expect(res.body.error).to.equal("Database transaction failed"); // Matches new redacted error format
    });
  });

  describe("POST /api/relay/intake", () => {
    async function getValidRelayPayload() {
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
      const chainId = 31337;
      const roundId = "1";
      const nonce = crypto.randomUUID();
      const body = {
        roundId: 1,
        nullifier: "0x" + "c".repeat(64),
        projectId: 5,
        proofRequired: false
      };

      const payloadString = JSON.stringify(body);
      const payloadHash = "0x" + sha256(payloadString);

      const canonicalString = [
        `Pharmacy Fiduciary Commons Database Proxy`,
        `Version: 1`,
        `Action: relay-intake`,
        `Chain ID: ${chainId}`,
        `Round ID: ${roundId}`,
        `Wallet: ${testWallet.address}`,
        `Payload Hash: ${payloadHash}`,
        `Nonce: ${nonce}`,
        `Expires At: ${expiresAt}`
      ].join("\n");
      const signature = await testWallet.signMessage(canonicalString);

      return {
        walletAddress: testWallet.address,
        chainId,
        roundId,
        nonce,
        expiresAt,
        signature,
        body
      };
    }

    it("successfully receives a sanitized relay batch", async () => {
      const payload = await getValidRelayPayload();

      const res = await request(app)
        .post("/api/relay/intake")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(200);
      expect(res.body.success).to.be.true;
    });

    it("rejects relay intake with forbidden fields using schema allowlist", async () => {
      const payload = await getValidRelayPayload();
      
      // Inject forbidden 'preimage' field (fails validation check)
      payload.body = {
        roundId: 1,
        nullifier: "0x" + "c".repeat(64),
        preimage: "0x" + "d".repeat(64)
      };

      const payloadString = JSON.stringify(payload.body);
      const payloadHash = "0x" + sha256(payloadString);

      const canonicalString = [
        `Pharmacy Fiduciary Commons Database Proxy`,
        `Version: 1`,
        `Action: relay-intake`,
        `Chain ID: ${payload.chainId}`,
        `Round ID: ${payload.roundId}`,
        `Wallet: ${testWallet.address}`,
        `Payload Hash: ${payloadHash}`,
        `Nonce: ${payload.nonce}`,
        `Expires At: ${payload.expiresAt}`
      ].join("\n");
      payload.signature = await testWallet.signMessage(canonicalString);

      const res = await request(app)
        .post("/api/relay/intake")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(400);
      expect(res.body.error).to.include("Forbidden or malformed fields detected");
    });
  });

  describe("API Proxy Security Headers and Origin Controls", () => {
    it("returns modern security and Cache-Control headers on endpoints", async () => {
      const res = await request(app).get("/health");
      expect(res.status).to.equal(200);
      expect(res.headers["cache-control"]).to.equal("no-store, no-cache, must-revalidate, proxy-revalidate");
      expect(res.headers["pragma"]).to.equal("no-cache");
      expect(res.headers["expires"]).to.equal("0");
      expect(res.headers["x-content-type-options"]).to.equal("nosniff");
      expect(res.headers["referrer-policy"]).to.equal("no-referrer");
      expect(res.headers["cross-origin-resource-policy"]).to.equal("same-origin");
      expect(res.headers["x-powered-by"]).to.be.undefined;
    });

    it("rejects unauthorized Origins with 403 on state-changing API endpoints", async () => {
      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://unauthorized-hacker-site.com")
        .send({ walletAddress: testWallet.address });

      expect(res.status).to.equal(403);
      expect(res.body.error).to.include("CORS policy violation: unauthorized origin");
    });

    it("rejects null Origin value directly with 403", async () => {
      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "null")
        .send({ walletAddress: testWallet.address });

      expect(res.status).to.equal(403);
      expect(res.body.error).to.include("CORS policy violation: null origin not permitted");
    });

    it("triggers 429 rate limiter response when threshold is exceeded", async () => {
      let limitTriggered = false;
      for (let i = 0; i < 101; i++) {
        // Send POST requests to target the correct rate-limited route
        const res = await request(app)
          .post("/api/voters/register")
          .set("Origin", "http://localhost:3000")
          .send({});
        if (res.status === 429) {
          limitTriggered = true;
          break;
        }
      }
      expect(limitTriggered).to.be.true;
    });
  });
});
