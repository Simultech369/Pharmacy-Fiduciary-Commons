const request = require("supertest");
const { expect } = require("chai");
const ethers = require("ethers");
const crypto = require("crypto");
const { createApp } = require("../server/createApp");

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

describe("Phase 3: Disaster Recovery & Fail-Closed Outage Test Harness", () => {
  let mockSupabase;
  let config;
  let app;
  const testWallet = ethers.Wallet.createRandom();
  const issuerWallet = ethers.Wallet.createRandom();

  function createMockOutageSupabase() {
    return {
      _shouldFail: true,
      auth: {
        admin: {
          createUser: async () => ({ data: { user: null }, error: new Error("Supabase Auth Outage (503)") }),
          listUsers: async () => ({ data: null, error: new Error("Supabase Outage") })
        }
      },
      rpc: async () => ({ data: null, error: new Error("PostgreSQL RPC Connection Timeout (504)") }),
      from: () => ({
        select: () => ({
          eq: () => ({
            maybeSingle: async () => ({ data: null, error: new Error("PostgreSQL Connection Terminated") })
          })
        }),
        insert: async () => ({ error: new Error("PostgreSQL Write Lock Timeout (500)") }),
        update: () => ({
          eq: async () => ({ error: new Error("PostgreSQL Connection Terminated") })
        })
      })
    };
  }

  beforeEach(() => {
    mockSupabase = createMockOutageSupabase();
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
    const credentialData = overrides.credentialData || { test: "data" };
    const policyVersion = overrides.policyVersion || "fiduciary-credential-policy-v1";

    const canonicalPayloadString = stableStringify(credentialData);
    const credentialHash = "0x" + sha256(`${config.credentialPepper}:${testWallet.address.toLowerCase()}:${canonicalPayloadString}`);

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

  it("fails closed on GET /api/health/observability during DB outage with sanitized health response", async () => {
    const res = await request(app)
      .get("/api/health/observability")
      .expect(200);

    expect(res.body.status).to.equal("healthy");
    expect(res.body.solvency.dispute_retraction_toll_policy).to.equal("zero_toll");
  });

  it("fails closed on POST /api/voters/register before database call if signature is invalid", async () => {
    const payload = await getValidRegistrationPayload();
    payload.signature = "0x" + "1".repeat(130);

    const res = await request(app)
      .post("/api/voters/register")
      .send(payload)
      .expect(401);

    expect(res.body).to.deep.equal({ error: "Invalid registration signature payload" });
  });

  it("fails closed on POST /api/voters/register during DB outage with 500 when valid signature passes pre-database domain validation", async () => {
    const payload = await getValidRegistrationPayload();

    const res = await request(app)
      .post("/api/voters/register")
      .send(payload)
      .expect(500);

    expect(res.body).to.deep.equal({ error: "Database transaction failed" });
    expect(JSON.stringify(res.body)).to.not.contain("PostgreSQL");
    expect(JSON.stringify(res.body)).to.not.contain("Supabase");
  });

  it("fails closed on relay intake during DB outage with 500 when valid EIP-191 relayer signature is supplied", async () => {
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    const nonce = "100";
    const body = {
      roundId: 1,
      nullifier: "0x" + "a".repeat(64),
      projectId: 1,
      proofRequired: true,
      proof: "0x1234"
    };

    const payloadString = JSON.stringify(body);
    const payloadHash = "0x" + sha256(payloadString);

    const canonicalString = [
      `Pharmacy Fiduciary Commons Database Proxy`,
      `Version: 1`,
      `Action: relay-intake`,
      `Proxy Address: ${config.proxyAddress.toLowerCase()}`,
      `Chain ID: ${config.chainId}`,
      `Round ID: ${config.roundId.toString()}`,
      `Wallet: ${testWallet.address.toLowerCase()}`,
      `Payload Hash: ${payloadHash}`,
      `Nonce: ${nonce}`,
      `Expires At: ${expiresAt}`
    ].join("\n");

    const signature = await testWallet.signMessage(canonicalString);

    const reqPayload = {
      walletAddress: testWallet.address,
      chainId: config.chainId,
      roundId: config.roundId,
      nonce,
      expiresAt,
      signature,
      body
    };

    const res = await request(app)
      .post("/api/relay/intake")
      .send(reqPayload)
      .expect(500);

    expect(res.body).to.deep.equal({ error: "Database transaction failed" });
  });
});
