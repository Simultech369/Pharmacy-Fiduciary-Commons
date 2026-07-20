const request = require("supertest");
const { expect } = require("chai");
const ethers = require("ethers");
const crypto = require("crypto");
const { createApp } = require("../server/createApp");

// Generate a random wallet for testing signatures
const testWallet = ethers.Wallet.createRandom();

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function createMockSupabase() {
  const mockDb = {
    voter_profiles: [],
    offline_vouchers: [],
    users: []
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
              const data = mockDb[table].find(row => row[col] === val);
              return { data: data || null, error: null };
            }
          })
        }),
        insert: async (row) => {
          if (client._shouldFail) {
            return { error: new Error("Mock database connection failed") };
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

  describe("POST /api/voters/register", () => {
    it("successfully registers a new voter with valid signature", async () => {
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
      const chainId = 31337;
      const roundId = "1";
      const credentialHash = "0x" + "a".repeat(64);
      const policyVersion = "1.0.0";
      const nonce = crypto.randomUUID();

      const canonicalString = [
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

      const signature = await testWallet.signMessage(canonicalString);

      const res = await request(app)
        .post("/api/voters/register")
        .send({
          walletAddress: testWallet.address,
          chainId,
          roundId,
          credentialHash,
          policyVersion,
          nonce,
          expiresAt,
          signature
        });

      expect(res.status).to.equal(200);
      expect(res.body.success).to.be.true;
      expect(res.body.userId).to.be.a("string");

      expect(mockSupabase._mockDb.voter_profiles).to.have.lengthOf(1);
      const profile = mockSupabase._mockDb.voter_profiles[0];
      expect(profile.wallet_address).to.equal(testWallet.address.toLowerCase());
      expect(JSON.parse(profile.encrypted_metadata)).to.deep.equal({ credentialHash, policyVersion });
    });

    it("fails registration if signature is invalid", async () => {
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
      const chainId = 31337;
      const roundId = "1";
      const credentialHash = "0x" + "a".repeat(64);
      const policyVersion = "1.0.0";
      const nonce = crypto.randomUUID();
      const signature = await testWallet.signMessage("some other message");

      const res = await request(app)
        .post("/api/voters/register")
        .send({
          walletAddress: testWallet.address,
          chainId,
          roundId,
          credentialHash,
          policyVersion,
          nonce,
          expiresAt,
          signature
        });

      expect(res.status).to.equal(401);
      expect(res.body.error).to.include("Signature recovery mismatch");
    });

    it("fails registration if timestamp is expired", async () => {
      const expiredTimestamp = new Date(Date.now() - 5 * 60 * 1000).toISOString(); // 5 mins ago
      const chainId = 31337;
      const roundId = "1";
      const credentialHash = "0x" + "a".repeat(64);
      const policyVersion = "1.0.0";
      const nonce = crypto.randomUUID();

      const canonicalString = [
        `Pharmacy Fiduciary Commons Database Proxy`,
        `Version: 1`,
        `Action: register-voter`,
        `Chain ID: ${chainId}`,
        `Round ID: ${roundId}`,
        `Wallet: ${testWallet.address}`,
        `Credential Hash: ${credentialHash}`,
        `Policy Version: ${policyVersion}`,
        `Nonce: ${nonce}`,
        `Expires At: ${expiredTimestamp}`
      ].join("\n");

      const signature = await testWallet.signMessage(canonicalString);

      const res = await request(app)
        .post("/api/voters/register")
        .send({
          walletAddress: testWallet.address,
          chainId,
          roundId,
          credentialHash,
          policyVersion,
          nonce,
          expiresAt: expiredTimestamp,
          signature
        });

      expect(res.status).to.equal(401);
      expect(res.body.error).to.include("expiration has passed");
    });

    it("fails if nonce is replayed", async () => {
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
      const chainId = 31337;
      const roundId = "1";
      const credentialHash = "0x" + "a".repeat(64);
      const policyVersion = "1.0.0";
      const nonce = "shared-replayed-nonce";

      const canonicalString = [
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

      const signature = await testWallet.signMessage(canonicalString);

      const payload = {
        walletAddress: testWallet.address,
        chainId,
        roundId,
        credentialHash,
        policyVersion,
        nonce,
        expiresAt,
        signature
      };

      // First request passes
      const res1 = await request(app).post("/api/voters/register").send(payload);
      expect(res1.status).to.equal(200);

      // Second request fails with same nonce
      const res2 = await request(app).post("/api/voters/register").send(payload);
      expect(res2.status).to.equal(401);
      expect(res2.body.error).to.include("Replay attempt detected");
    });

    it("returns 500 when Supabase write fails", async () => {
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
      const chainId = 31337;
      const roundId = "1";
      const credentialHash = "0x" + "a".repeat(64);
      const policyVersion = "1.0.0";
      const nonce = crypto.randomUUID();

      const canonicalString = [
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

      const signature = await testWallet.signMessage(canonicalString);

      // Force mock write failures
      mockSupabase._shouldFail = true;

      const res = await request(app)
        .post("/api/voters/register")
        .send({
          walletAddress: testWallet.address,
          chainId,
          roundId,
          credentialHash,
          policyVersion,
          nonce,
          expiresAt,
          signature
        });

      expect(res.status).to.equal(500);
      expect(res.body.error).to.include("Supabase write error");
    });
  });

  describe("POST /api/relay/intake", () => {
    it("successfully receives a sanitized relay batch", async () => {
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
      const chainId = 31337;
      const roundId = "1";
      const nonce = crypto.randomUUID();
      const body = {
        roundId: 1,
        nullifier: "0x" + "c".repeat(64),
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

      const res = await request(app)
        .post("/api/relay/intake")
        .send({
          walletAddress: testWallet.address,
          chainId,
          roundId,
          nonce,
          expiresAt,
          signature,
          body
        });

      expect(res.status).to.equal(200);
      expect(res.body.success).to.be.true;
    });

    it("rejects relay intake with forbidden fields", async () => {
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
      const chainId = 31337;
      const roundId = "1";
      const nonce = crypto.randomUUID();
      
      // Inject forbidden 'preimage' field
      const body = {
        roundId: 1,
        nullifier: "0x" + "c".repeat(64),
        preimage: "0x" + "d".repeat(64)
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

      const res = await request(app)
        .post("/api/relay/intake")
        .send({
          walletAddress: testWallet.address,
          chainId,
          roundId,
          nonce,
          expiresAt,
          signature,
          body
        });

      expect(res.status).to.equal(400);
      expect(res.body.error).to.include("Forbidden fields detected");
    });
  });
});
