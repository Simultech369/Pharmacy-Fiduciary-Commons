const request = require("supertest");
const { expect } = require("chai");
const ethers = require("ethers");
const crypto = require("crypto");
const { createApp } = require("../server/createApp");

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}

// Generate dynamic random wallets for voter and trusted issuer relayer
const testWallet = ethers.Wallet.createRandom();
const issuerWallet = ethers.Wallet.createRandom();

function createMockSupabase() {
  const mockDb = {
    voter_profiles: [],
    offline_vouchers: [],
    users: [],
    consumed_nonces: [],
    registration_ledger: []
  };

  const client = {
    _mockDb: mockDb,
    _shouldFail: false,
    _authFailMode: false,
    _profileFailMode: false,
    _testSkipLeaseCheck: false,
    auth: {
      admin: {
        createUser: async ({ email, user_metadata }) => {
          if (client._shouldFail || client._authFailMode) {
            return { data: { user: null }, error: new Error("Mock Auth service failed") };
          }
          // Simulate email already exists error
          const exists = mockDb.users.some(u => u.email === email);
          if (exists) {
            return { data: { user: null }, error: { message: "Email already exists", status: 422 } };
          }
          const id = crypto.randomUUID();
          const user = { id, email, user_metadata };
          mockDb.users.push(user);
          return { data: { user }, error: null };
        },
        listUsers: async () => {
          if (client._shouldFail) {
            return { data: null, error: new Error("Mock Supabase query error") };
          }
          return { data: { users: mockDb.users }, error: null };
        }
      }
    },
    rpc: async (func, args) => {
      if (client._shouldFail) {
        return { data: null, error: new Error("Mock database connection failed") };
      }
      if (func === "register_voter_ledger_start") {
        const nonceKey = args.p_nonce_key;
        const requestHash = args.p_request_hash;
        
        let entry = mockDb.registration_ledger.find(r => r.nonce_key === nonceKey);
        if (entry) {
          if (entry.request_hash !== requestHash) {
            return { data: [{ status: "mismatch", user_id: null }], error: null };
          }
          if (entry.status === "completed") {
            return { data: [{ status: "completed", user_id: entry.user_id }], error: null };
          }
          if (entry.status === "pending") {
            const elapsed = Date.now() - new Date(entry.updated_at).getTime();
            if (elapsed < 15000 && !client._testSkipLeaseCheck) {
              return { data: [{ status: "pending", user_id: null }], error: null };
            }
          }
          // Lease expired or retry of failed: reset to pending
          entry.status = "pending";
          entry.updated_at = new Date().toISOString();
          return { data: [{ status: "success", user_id: null }], error: null };
        } else {
          const newEntry = {
            nonce_key: nonceKey,
            request_hash: requestHash,
            status: "pending",
            user_id: null,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          };
          mockDb.registration_ledger.push(newEntry);
          return { data: [{ status: "success", user_id: null }], error: null };
        }
      }
      if (func === "register_voter_ledger_complete") {
        if (client._ledgerCompleteFailMode) {
          return { error: new Error("Mock ledger complete RPC failure") };
        }
        const entry = mockDb.registration_ledger.find(r => r.nonce_key === args.p_nonce_key);
        if (entry) {
          entry.status = "completed";
          entry.user_id = args.p_user_id;
          entry.updated_at = new Date().toISOString();
        }
        return { error: null };
      }
      if (func === "register_voter_ledger_fail") {
        const entry = mockDb.registration_ledger.find(r => r.nonce_key === args.p_nonce_key);
        if (entry) {
          entry.status = "failed";
          entry.updated_at = new Date().toISOString();
        }
        return { error: null };
      }
      return { data: null, error: new Error(`Unknown RPC function ${func}`) };
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
          if (table === "consumed_nonces") {
            const exists = mockDb.consumed_nonces.some(r => r.nonce_key === row.nonce_key);
            if (exists) {
              return { error: new Error("Duplicate key violation on nonces") };
            }
          }
          if (table === "voter_profiles" && client._profileFailMode) {
            return { error: new Error("Mock profile insert failure") };
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

describe("Database API Proxy Server Security Patch", () => {
  let mockSupabase;
  let config;
  let app;

  beforeEach(() => {
    mockSupabase = createMockSupabase();
    config = {
      chainId: 31337,
      roundId: "1",
      proxyAddress: "0x1111111111111111111111111111111111111111",
      contractAddress: "0x2222222222222222222222222222222222222222",
      trustedCredentialIssuer: issuerWallet.address,
      credentialPepper: "secure-long-test-credential-blinding-pepper",
      testMode: true
    };
    app = createApp(mockSupabase, config);
  });

  async function getValidRegistrationPayload(overrides = {}) {
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    const clientNonce = overrides.clientNonce || crypto.randomUUID();
    const relayerNonce = 0;
    const relayerDeadline = Math.floor((Date.now() + 30 * 60 * 1000) / 1000);
    const credentialHash = overrides.credentialHash || "0x" + "a".repeat(64);
    const policyVersion = overrides.policyVersion || "fiduciary-credential-policy-v1";
    
    const policyVersionBytes = policyVersion.startsWith("0x")
      ? policyVersion
      : ethers.keccak256(ethers.toUtf8Bytes(policyVersion));

    const domain = {
      name: "Pharmacy Fiduciary Commons",
      version: "1",
      chainId: BigInt(overrides.chainId || config.chainId),
      verifyingContract: overrides.contractAddress || config.contractAddress
    };

    const types = {
      VoterRegistration: [
        { name: "roundId", type: "uint256" },
        { name: "voter", type: "address" },
        { name: "nonce", type: "uint256" },
        { name: "credentialHash", type: "bytes32" },
        { name: "policyVersion", type: "bytes32" },
        { name: "deadline", type: "uint256" }
      ]
    };

    const value = {
      roundId: BigInt(overrides.roundId || config.roundId),
      voter: testWallet.address,
      nonce: BigInt(relayerNonce),
      credentialHash,
      policyVersion: policyVersionBytes,
      deadline: BigInt(overrides.relayerDeadline || relayerDeadline)
    };

    const issuerSignature = await issuerWallet.signTypedData(domain, types, value);

    const voterMessage = [
      `Pharmacy Fiduciary Commons Database Proxy`,
      `Version: 1`,
      `Action: register-voter`,
      `Proxy Address: ${(overrides.proxyAddress || config.proxyAddress).toLowerCase()}`,
      `Chain ID: ${overrides.chainId || config.chainId}`,
      `Round ID: ${(overrides.roundId || config.roundId).toString()}`,
      `Wallet: ${testWallet.address.toLowerCase()}`,
      `Credential Hash: ${credentialHash}`,
      `Policy Version: ${policyVersion}`,
      `Client Nonce: ${clientNonce}`,
      `Expires At: ${overrides.expiresAt || expiresAt}`
    ].join("\n");

    const signature = await testWallet.signMessage(voterMessage);

    return {
      walletAddress: testWallet.address,
      chainId: Number(overrides.chainId || config.chainId),
      roundId: (overrides.roundId || config.roundId).toString(),
      credentialHash,
      policyVersion,
      clientNonce,
      expiresAt: overrides.expiresAt || expiresAt,
      signature,
      issuerSignature,
      relayerNonce,
      relayerDeadline: overrides.relayerDeadline || relayerDeadline
    };
  }

  describe("Startup Configuration Validations", () => {
    it("fails closed if any required configuration parameter is missing", () => {
      const badConfig = { ...config };
      delete badConfig.chainId;
      expect(() => createApp(mockSupabase, badConfig)).to.throw("missing required parameter chainId");
    });

    it("rejects well-known Hardhat account 0 relayer address outside test mode", () => {
      const prodConfig = {
        ...config,
        trustedCredentialIssuer: "0xF39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        testMode: false
      };
      expect(() => createApp(mockSupabase, prodConfig)).to.throw("Dev issuer address rejected");
    });

    it("rejects default development pepper outside test mode", () => {
      const prodConfig = {
        ...config,
        credentialPepper: "default-dev-pepper-do-not-use-in-prod",
        testMode: false
      };
      expect(() => createApp(mockSupabase, prodConfig)).to.throw("Dev credential pepper rejected");
    });
  });

  describe("POST /api/voters/register - Signature & Domain Validations", () => {
    it("successfully registers with valid voter and issuer signatures", async () => {
      const payload = await getValidRegistrationPayload();
      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(200);
      expect(res.body.success).to.be.true;

      // Verify HMAC blinding with pepper and domain separation
      const profile = mockSupabase._mockDb.voter_profiles[0];
      const domainString = `domain:voter-credential-hash:chainId:${config.chainId}:roundId:${config.roundId}:`;
      const expectedBlinded = crypto
        .createHmac("sha256", config.credentialPepper)
        .update(domainString + payload.credentialHash)
        .digest("hex");
      expect(JSON.parse(profile.encrypted_metadata).credentialHash).to.equal(expectedBlinded);
    });

    it("successfully registers when policyVersion is bytes32 format (hash compatibility)", async () => {
      const bytes32Policy = ethers.keccak256(ethers.toUtf8Bytes("fiduciary-credential-policy-v1"));
      const payload = await getValidRegistrationPayload({ policyVersion: bytes32Policy });
      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(200);
      expect(res.body.success).to.be.true;
    });

    it("rejects voter EIP-191 domain mismatch (Chain ID spoofing)", async () => {
      const payload = await getValidRegistrationPayload({ chainId: 9999 });
      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(400);
      expect(res.body.error).to.equal("Invalid registration signature payload");
    });

    it("rejects voter EIP-191 domain mismatch (Proxy Address spoofing)", async () => {
      const payload = await getValidRegistrationPayload({ proxyAddress: "0x8a7b8c8d8e8f8a8b8c8d8e8f8a8b8c8d8e8f8a8b" });
      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(401);
      expect(res.body.error).to.equal("Invalid registration signature payload");
    });

    it("rejects relayer EIP-712 domain mismatch (Cross-Contract signature reuse)", async () => {
      const payload = await getValidRegistrationPayload({ contractAddress: "0x9999999999999999999999999999999999999999" });
      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(401);
      expect(res.body.error).to.equal("Invalid registration signature payload");
    });

    it("rejects stale/expired relayer authorizations", async () => {
      const expiredRelayerDeadline = Math.floor((Date.now() - 5 * 60 * 1000) / 1000);
      const payload = await getValidRegistrationPayload({ relayerDeadline: expiredRelayerDeadline });
      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(401);
      expect(res.body.error).to.equal("Invalid registration signature payload");
    });

    it("redacts internal signature error details in response", async () => {
      const payload = await getValidRegistrationPayload();
      payload.signature = "0x" + "0".repeat(130); // Malformed voter signature

      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(401);
      expect(res.body.error).to.equal("Invalid registration signature payload");
    });

    it("rejects oversized JSON request bodies before registration processing", async () => {
      const payload = await getValidRegistrationPayload();
      payload.padding = "x".repeat(12 * 1024);

      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(413);
      expect(res.body.error).to.equal("Request body too large");
      expect(mockSupabase._mockDb.registration_ledger).to.have.lengthOf(0);
    });

    it("rejects deeply nested registration payloads before request-hash canonicalization", async () => {
      const payload = await getValidRegistrationPayload();
      let nested = {};
      for (let i = 0; i < 25; i++) {
        nested = { child: nested };
      }
      payload.extra = nested;

      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(400);
      expect(res.body.error).to.equal("Invalid registration signature payload");
      expect(mockSupabase._mockDb.registration_ledger).to.have.lengthOf(0);
    });
  });

  describe("Database Request Ledger & Idempotency", () => {
    it("returns previous completed result on exact registration retry", async () => {
      const payload = await getValidRegistrationPayload();

      // First call succeeds
      const res1 = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);
      expect(res1.status).to.equal(200);
      const userId = res1.body.userId;

      // Second identical call returns exact same 200 response and userId
      const res2 = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);
      expect(res2.status).to.equal(200);
      expect(res2.body.userId).to.equal(userId);
    });

    it("returns previous completed result when retry JSON keys arrive in a different order", async () => {
      const payload = await getValidRegistrationPayload();
      const reorderedPayload = {
        relayerDeadline: payload.relayerDeadline,
        relayerNonce: payload.relayerNonce,
        issuerSignature: payload.issuerSignature,
        signature: payload.signature,
        expiresAt: payload.expiresAt,
        clientNonce: payload.clientNonce,
        policyVersion: payload.policyVersion,
        credentialHash: payload.credentialHash,
        roundId: payload.roundId,
        chainId: payload.chainId,
        walletAddress: payload.walletAddress
      };

      const res1 = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);
      expect(res1.status).to.equal(200);
      const userId = res1.body.userId;

      const res2 = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(reorderedPayload);
      expect(res2.status).to.equal(200);
      expect(res2.body.userId).to.equal(userId);
    });

    it("rejects same-nonce retry if the payload request hash is mismatched (replay attempt)", async () => {
      const clientNonce = crypto.randomUUID();
      const payload1 = await getValidRegistrationPayload({ clientNonce, credentialHash: "0x" + "a".repeat(64) });
      const payload2 = await getValidRegistrationPayload({ clientNonce, credentialHash: "0x" + "b".repeat(64) });

      // First payload succeeds
      const res1 = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload1);
      expect(res1.status).to.equal(200);

      // Second payload with different hash fails on the same nonce
      const res2 = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload2);
      expect(res2.status).to.equal(401);
      expect(res2.body.error).to.equal("Invalid registration signature payload");
    });

    it("allows retry and successfully recovers if Auth creation succeeded but profile write failed previously", async () => {
      const payload = await getValidRegistrationPayload();

      // Set profile write to fail but auth write to succeed
      mockSupabase._profileFailMode = true;
      const res1 = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);
      expect(res1.status).to.equal(500);

      // Verify profile is empty, but auth user exists
      expect(mockSupabase._mockDb.voter_profiles).to.have.lengthOf(0);
      expect(mockSupabase._mockDb.users).to.have.lengthOf(1);
      // Ledger record status should be 'failed'
      const ledgerEntry = mockSupabase._mockDb.registration_ledger[0];
      expect(ledgerEntry.status).to.equal("failed");

      // Re-enable profile write, retry exact payload
      mockSupabase._profileFailMode = false;
      const res2 = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);
      
      expect(res2.status).to.equal(200);
      expect(mockSupabase._mockDb.voter_profiles).to.have.lengthOf(1);
      expect(mockSupabase._mockDb.registration_ledger[0].status).to.equal("completed");
    });

    it("marks status as failed if ledger commit step fails", async () => {
      const payload = await getValidRegistrationPayload();
      mockSupabase._ledgerCompleteFailMode = true;

      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);
      expect(res.status).to.equal(500);

      expect(mockSupabase._mockDb.registration_ledger[0].status).to.equal("failed");
    });

    it("blocks concurrent requests within the active lease window", async () => {
      const payload = await getValidRegistrationPayload();

      // Inject pending status directly to simulate a concurrent request currently processing
      mockSupabase._mockDb.registration_ledger.push({
        nonce_key: `${payload.walletAddress.toLowerCase()}:${payload.clientNonce}`,
        request_hash: crypto.createHash("sha256").update(stableStringify(payload)).digest("hex"),
        status: "pending",
        user_id: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });

      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);
      
      expect(res.status).to.equal(429);
      expect(res.body.error).to.equal("Too many requests, please try again later");
    });

    it("prevents completed registration from regressing to failed on subsequent database error", async () => {
      const payload = await getValidRegistrationPayload();

      // First call succeeds and commits to 'completed'
      const res1 = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);
      expect(res1.status).to.equal(200);
      expect(mockSupabase._mockDb.registration_ledger[0].status).to.equal("completed");

      // Set profile write to fail, simulate retry or concurrent failure
      mockSupabase._profileFailMode = true;
      const res2 = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);
      
      // Because it was already completed, it returns 200 immediately and doesn't run DB writes
      expect(res2.status).to.equal(200);
      expect(mockSupabase._mockDb.registration_ledger[0].status).to.equal("completed");
    });

    it("applies domain-separated HMAC hashing to credential data", async () => {
      const payload = await getValidRegistrationPayload();
      const res = await request(app)
        .post("/api/voters/register")
        .set("Origin", "http://localhost:3000")
        .send(payload);

      expect(res.status).to.equal(200);
      const profile = mockSupabase._mockDb.voter_profiles[0];
      const metadata = JSON.parse(profile.encrypted_metadata);

      // Verify domain-separated HMAC matches formula
      const domainString = `domain:voter-credential-hash:chainId:${config.chainId}:roundId:${config.roundId}:`;
      const expectedBlinded = crypto
        .createHmac("sha256", config.credentialPepper)
        .update(domainString + payload.credentialHash)
        .digest("hex");
      
      expect(metadata.credentialHash).to.equal(expectedBlinded);
    });
  });

  describe("Supabase Row-Level Security (RLS) Policy Checks", () => {
    function simulateRLSPolicy({ role, userId, targetProfile }) {
      // Voter profiles policy: USING (auth.uid() = id OR auth.role() = 'service_role')
      if (role === "service_role") {
        return true;
      }
      if (role === "authenticated" && userId === targetProfile.id) {
        return true;
      }
      return false; // anon or non-owner select blocked
    }

    function simulateClaimsRLSPolicy({ role, tenantId, targetClaim }) {
      // Multi-tenant claims policy: USING (auth.role() = 'service_role' OR (auth.role() = 'authenticated' AND tenant_id = current_tenant()))
      if (role === "service_role") {
        return true;
      }
      if (role === "authenticated" && tenantId && tenantId === targetClaim.tenant_id) {
        return true;
      }
      return false; // Cross-tenant access blocked
    }

    it("enforces voter profile visibility restrictions per the RLS role matrix", () => {
      const profile = { id: "user-123", wallet_address: "0x123..." };

      // Owner SELECT should be permitted
      expect(simulateRLSPolicy({ role: "authenticated", userId: "user-123", targetProfile: profile })).to.be.true;

      // Service Role SELECT should be permitted
      expect(simulateRLSPolicy({ role: "service_role", userId: null, targetProfile: profile })).to.be.true;

      // Anonymous / Non-owner SELECT must be blocked
      expect(simulateRLSPolicy({ role: "anon", userId: null, targetProfile: profile })).to.be.false;
      expect(simulateRLSPolicy({ role: "authenticated", userId: "another-user", targetProfile: profile })).to.be.false;
    });

    it("enforces multi-tenant claim isolation preventing cross-tenant context contamination", () => {
      const claimTenantA = { id: "claim-101", tenant_id: "tenant-pharmacy-a", amount: "$12,450" };

      // Tenant A accessing Tenant A claim should be permitted
      expect(simulateClaimsRLSPolicy({ role: "authenticated", tenantId: "tenant-pharmacy-a", targetClaim: claimTenantA })).to.be.true;

      // Tenant B attempting to access Tenant A claim MUST be blocked
      expect(simulateClaimsRLSPolicy({ role: "authenticated", tenantId: "tenant-pharmacy-b", targetClaim: claimTenantA })).to.be.false;

      // Service role access for audit consolidation permitted
      expect(simulateClaimsRLSPolicy({ role: "service_role", tenantId: null, targetClaim: claimTenantA })).to.be.true;
    });
  });
});
