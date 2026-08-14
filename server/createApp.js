const express = require("express");
const cors = require("cors");
const ethers = require("ethers");
const crypto = require("crypto");

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

const JSON_BODY_LIMIT = "10kb";
const MAX_CANONICAL_DEPTH = 20;
const MAX_CANONICAL_KEYS = 1000;
const MAX_RELAY_PROOF_CHARS = 4096;
const MAX_VOUCHER_CLIENT_NONCE_CHARS = 128;
const MAX_VOUCHER_RETRY_ATTEMPTS = 3;
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const VOTER_REGISTRATION_RATE_LIMIT = 100;
const RELAY_INTAKE_RATE_LIMIT = 100;
const VOUCHER_RECONCILIATION_RATE_LIMIT = 50;
const VOUCHER_SAGA_LEASE_MS = 15 * 1000;

function stableStringify(value, depth = 0, state = { keys: 0 }) {
  if (depth > MAX_CANONICAL_DEPTH) {
    throw new Error("Canonical payload depth exceeded");
  }

  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    state.keys += value.length;
    if (state.keys > MAX_CANONICAL_KEYS) {
      throw new Error("Canonical payload key count exceeded");
    }
    return `[${value.map((item) => stableStringify(item, depth + 1, state)).join(",")}]`;
  }

  const keys = Object.keys(value);
  state.keys += keys.length;
  if (state.keys > MAX_CANONICAL_KEYS) {
    throw new Error("Canonical payload key count exceeded");
  }

  return `{${keys.sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key], depth + 1, state)}`).join(",")}}`;
}

const allowedPolicyVersions = new Set([
  "fiduciary-credential-policy-v1",
  ethers.keccak256(ethers.toUtf8Bytes("fiduciary-credential-policy-v1"))
]);

// Strict allowlist validation schema for relay intake body
const allowedIntakeKeys = new Set(["roundId", "nullifier", "projectId", "proofRequired", "proof"]);

function validateRelayIntakeBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return false;
  }
  
  for (const key of Object.keys(body)) {
    if (!allowedIntakeKeys.has(key)) {
      return false; // Reject any unknown key (denial-of-service / alternative casing protection)
    }
    
    const val = body[key];
    if (key === "roundId" || key === "projectId") {
      if (typeof val !== "number" || !Number.isInteger(val) || val < 0) return false;
    } else if (key === "proofRequired") {
      if (typeof val !== "boolean") return false;
    } else if (key === "nullifier" || key === "proof") {
      if (typeof val !== "string") return false;
      if (key === "nullifier" && val.replace(/^0x/, "").length !== 64) return false;
      if (key === "proof" && val.length > MAX_RELAY_PROOF_CHARS) return false;
      const hexRegex = /^(0x)?[0-9a-fA-F]+$/;
      if (!hexRegex.test(val)) return false;
    }
  }
  return true;
}

// EIP-191 Voter Signature Verification (bounds chainId, roundId, proxyAddress)
function verifyRegisterSignature({
  config,
  walletAddress,
  credentialHash,
  policyVersion,
  clientNonce,
  expiresAt,
  signature
}) {
  const canonicalString = [
    `Pharmacy Fiduciary Commons Database Proxy`,
    `Version: 1`,
    `Action: register-voter`,
    `Proxy Address: ${config.proxyAddress.toLowerCase()}`,
    `Chain ID: ${config.chainId}`,
    `Round ID: ${config.roundId.toString()}`,
    `Wallet: ${walletAddress.toLowerCase()}`,
    `Credential Hash: ${credentialHash}`,
    `Policy Version: ${policyVersion}`,
    `Client Nonce: ${clientNonce}`,
    `Expires At: ${expiresAt}`
  ].join("\n");

  const recoveredAddress = ethers.verifyMessage(canonicalString, signature);
  if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
    throw new Error("Invalid voter signature");
  }
}

// EIP-712 Relayer Signature Verification
function verifyRelayerSignature({
  config,
  walletAddress,
  credentialHash,
  policyVersionBytes,
  relayerNonce,
  relayerDeadline,
  issuerSignature
}) {
  const acceptedPolicyVersionHash = ethers.keccak256(ethers.toUtf8Bytes("fiduciary-credential-policy-v1"));

  if (policyVersionBytes !== acceptedPolicyVersionHash) {
    throw new Error("Unsupported policy version");
  }

  const recoveredRelayer = ethers.verifyTypedData(
    {
      name: "Pharmacy Fiduciary Commons",
      version: "1",
      chainId: config.chainId,
      verifyingContract: config.contractAddress
    },
    {
      VoterRegistration: [
        { name: "roundId", type: "uint256" },
        { name: "voter", type: "address" },
        { name: "nonce", type: "uint256" },
        { name: "credentialHash", type: "bytes32" },
        { name: "policyVersion", type: "bytes32" },
        { name: "deadline", type: "uint256" }
      ]
    },
    {
      roundId: BigInt(config.roundId),
      voter: walletAddress,
      nonce: BigInt(relayerNonce),
      credentialHash,
      policyVersion: policyVersionBytes,
      deadline: BigInt(relayerDeadline)
    },
    issuerSignature
  );

  if (recoveredRelayer.toLowerCase() !== config.trustedCredentialIssuer.toLowerCase()) {
    throw new Error("Invalid issuer credential signature");
  }
}

// EIP-191 Relay Request Verification
function verifyRelaySignature({
  config,
  walletAddress,
  payloadHash,
  nonce,
  expiresAt,
  signature
}) {
  const canonicalString = [
    `Pharmacy Fiduciary Commons Database Proxy`,
    `Version: 1`,
    `Action: relay-intake`,
    `Proxy Address: ${config.proxyAddress.toLowerCase()}`,
    `Chain ID: ${config.chainId}`,
    `Round ID: ${config.roundId.toString()}`,
    `Wallet: ${walletAddress.toLowerCase()}`,
    `Payload Hash: ${payloadHash}`,
    `Nonce: ${nonce}`,
    `Expires At: ${expiresAt}`
  ].join("\n");

  const recoveredAddress = ethers.verifyMessage(canonicalString, signature);
  if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
    throw new Error("Invalid relay signature");
  }
}

function deriveVoucherSagaKey({ voucherId, pharmacyAddress, amount, clientNonce }) {
  return sha256([
    voucherId.toLowerCase(),
    pharmacyAddress.toLowerCase(),
    amount.toString(),
    clientNonce
  ].join("|"));
}

function normalizeVoucherAmount(amount) {
  if (typeof amount === "number") {
    if (!Number.isSafeInteger(amount) || amount <= 0) {
      throw new Error("Invalid voucher amount");
    }
    return amount.toString();
  }

  if (typeof amount !== "string" || !/^[1-9][0-9]*$/.test(amount)) {
    throw new Error("Invalid voucher amount");
  }

  return BigInt(amount).toString();
}

function validateVoucherReconcilePayload(body) {
  const allowedVoucherKeys = new Set([
    "pharmacyAddress",
    "chainId",
    "roundId",
    "voucherId",
    "amount",
    "clientNonce",
    "expiresAt",
    "signature"
  ]);

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("Invalid voucher reconciliation payload");
  }

  for (const key of Object.keys(body)) {
    if (!allowedVoucherKeys.has(key)) {
      throw new Error("Invalid voucher reconciliation payload");
    }
  }

  const {
    pharmacyAddress,
    chainId,
    roundId,
    voucherId,
    amount,
    clientNonce,
    expiresAt,
    signature
  } = body;

  if (
    !ethers.isAddress(pharmacyAddress) ||
    chainId === undefined ||
    roundId === undefined ||
    typeof voucherId !== "string" ||
    typeof clientNonce !== "string" ||
    typeof expiresAt !== "string" ||
    typeof signature !== "string"
  ) {
    throw new Error("Invalid voucher reconciliation payload");
  }

  if (!/^(0x)[0-9a-fA-F]{64}$/.test(voucherId)) {
    throw new Error("Invalid voucher reconciliation payload");
  }

  if (
    clientNonce.length === 0 ||
    clientNonce.length > MAX_VOUCHER_CLIENT_NONCE_CHARS ||
    !/^[a-zA-Z0-9:_-]+$/.test(clientNonce)
  ) {
    throw new Error("Invalid voucher reconciliation payload");
  }

  if (!/^(0x)?[0-9a-fA-F]{130}$/.test(signature)) {
    throw new Error("Invalid voucher reconciliation payload");
  }

  return {
    pharmacyAddress: pharmacyAddress.toLowerCase(),
    chainId: Number(chainId),
    roundId: roundId.toString(),
    voucherId: voucherId.toLowerCase(),
    amount: normalizeVoucherAmount(amount),
    clientNonce,
    expiresAt,
    signature
  };
}

function verifyVoucherSagaSignature({
  config,
  pharmacyAddress,
  voucherId,
  amount,
  clientNonce,
  expiresAt,
  signature
}) {
  const canonicalString = [
    `Pharmacy Fiduciary Commons Database Proxy`,
    `Version: 1`,
    `Action: voucher-reconcile`,
    `Proxy Address: ${config.proxyAddress.toLowerCase()}`,
    `Chain ID: ${config.chainId}`,
    `Round ID: ${config.roundId.toString()}`,
    `Pharmacy: ${pharmacyAddress.toLowerCase()}`,
    `Voucher ID: ${voucherId.toLowerCase()}`,
    `Amount: ${amount}`,
    `Client Nonce: ${clientNonce}`,
    `Expires At: ${expiresAt}`
  ].join("\n");

  const recoveredAddress = ethers.verifyMessage(canonicalString, signature);
  if (recoveredAddress.toLowerCase() !== pharmacyAddress.toLowerCase()) {
    throw new Error("Invalid voucher reconciliation signature");
  }
}

function canonicalVoucherSagaRequest(payload) {
  return {
    pharmacyAddress: payload.pharmacyAddress,
    chainId: payload.chainId,
    roundId: payload.roundId,
    voucherId: payload.voucherId,
    amount: payload.amount,
    clientNonce: payload.clientNonce,
    expiresAt: payload.expiresAt,
    signature: payload.signature
  };
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildSagaQueueTelemetry(supabaseClient) {
  const rows = supabaseClient && supabaseClient._mockDb && supabaseClient._mockDb.voucher_settlement_saga;
  const emptyCounts = {
    pending_count: null,
    retrying_count: null,
    dead_letter_count: null,
    completed_count: null,
    active_leases_count: null
  };

  if (!Array.isArray(rows)) {
    return {
      saga_queue_status: "not_live_instrumented",
      metric_source: "unavailable_without_live_reader",
      ...emptyCounts,
      alert_status: "not_instrumented"
    };
  }

  const now = Date.now();
  const telemetry = {
    saga_queue_status: "instrumented_in_memory",
    metric_source: "prototype_memory_snapshot",
    pending_count: 0,
    retrying_count: 0,
    dead_letter_count: 0,
    completed_count: 0,
    active_leases_count: 0,
    alert_status: "healthy"
  };

  for (const row of rows) {
    if (!row || typeof row !== "object") {
      continue;
    }

    if (row.status === "pending") {
      telemetry.pending_count += 1;
    } else if (row.status === "retrying") {
      telemetry.retrying_count += 1;
    } else if (row.status === "dead_letter") {
      telemetry.dead_letter_count += 1;
    } else if (row.status === "completed") {
      telemetry.completed_count += 1;
    }

    if (row.status === "pending" || row.status === "retrying") {
      const updatedAtMs = new Date(row.updated_at || row.created_at || 0).getTime();
      if (!Number.isNaN(updatedAtMs) && now - updatedAtMs < VOUCHER_SAGA_LEASE_MS) {
        telemetry.active_leases_count += 1;
      }
    }
  }

  if (telemetry.dead_letter_count > 0) {
    telemetry.alert_status = "DLQ_ATTENTION_REQUIRED";
  }

  return telemetry;
}

// Bounded IP Rate Limiter to prevent memory exhaustion
const rateLimitMap = new Map();

// Periodic cleanup of rate limit states to keep cardinality bounded
const rateLimitInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimitMap.entries()) {
    record.timestamps = record.timestamps.filter(t => now - t < 15 * 60 * 1000);
    if (record.timestamps.length === 0) {
      rateLimitMap.delete(key);
    }
  }
}, 5 * 60 * 1000);

if (rateLimitInterval.unref) {
  rateLimitInterval.unref(); // Enable clean exit in test suites
}

function rateLimiter(maxRequests, windowMs) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress || "127.0.0.1";
    const routeKey = `${req.baseUrl || ""}${req.path}:${ip}`;
    const now = Date.now();
    
    if (!rateLimitMap.has(routeKey)) {
      rateLimitMap.set(routeKey, { timestamps: [] });
    }
    
    const record = rateLimitMap.get(routeKey);
    record.timestamps = record.timestamps.filter(t => now - t < windowMs);
    
    const remaining = Math.max(0, maxRequests - record.timestamps.length - 1);
    const resetTime = Math.ceil((now + windowMs) / 1000);

    res.setHeader("X-RateLimit-Limit", maxRequests);
    res.setHeader("X-RateLimit-Remaining", remaining);
    res.setHeader("X-RateLimit-Reset", resetTime);

    if (record.timestamps.length >= maxRequests) {
      return res.status(429).json({ error: "Too many requests, please try again later" });
    }
    
    record.timestamps.push(now);
    next();
  };
}

// Strict Origin validation check for browser clients (CSRF defense-in-depth)
const allowedOrigins = new Set([
  "http://localhost:3000",
  "http://localhost:5000",
  "http://127.0.0.1:3000",
  "http://127.0.0.1:5000"
]);

function originCheck(req, res, next) {
  const origin = req.headers.origin;
  const referer = req.headers.referer;
  
  if (origin) {
    if (origin === "null") {
      return res.status(403).json({ error: "CORS policy violation: null origin not permitted" });
    }
    try {
      const parsedOrigin = new URL(origin).origin;
      if (!allowedOrigins.has(parsedOrigin)) {
        return res.status(403).json({ error: "CORS policy violation: unauthorized origin" });
      }
    } catch (err) {
      return res.status(403).json({ error: "Invalid Origin header" });
    }
  }
  
  if (!origin && referer) {
    try {
      const parsedReferer = new URL(referer).origin;
      if (!allowedOrigins.has(parsedReferer)) {
        return res.status(403).json({ error: "CORS policy violation: unauthorized referer" });
      }
    } catch (err) {
      return res.status(403).json({ error: "Invalid Referer header" });
    }
  }
  
  next();
}

function createApp(supabaseClient, config = {}) {
  // Clear rate limit state in test mode to guarantee test isolation across test files
  if (config.testMode || config.resetRateLimits) {
    rateLimitMap.clear();
  }

  // Validate config parameters exist (fail-closed check)
  const requiredConfig = ["chainId", "roundId", "proxyAddress", "contractAddress", "trustedCredentialIssuer", "credentialPepper"];
  for (const param of requiredConfig) {
    if (config[param] === undefined || config[param] === null || config[param] === "") {
      throw new Error(`Proxy configuration breach: missing required parameter ${param}`);
    }
  }

  // Reject well-known Hardhat Account 0 as Relayer outside test mode
  const devIssuer = "0xF39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
  if (config.testMode !== true && config.trustedCredentialIssuer.toLowerCase() === devIssuer.toLowerCase()) {
    throw new Error("Proxy configuration breach: Dev issuer address rejected in production mode");
  }

  // Reject default development pepper outside test mode
  const devPepper = "default-dev-pepper-do-not-use-in-prod";
  if (config.testMode !== true && config.credentialPepper === devPepper) {
    throw new Error("Proxy configuration breach: Dev credential pepper rejected in production mode");
  }

  const app = express();
  
  app.set("trust proxy", false);
  app.disable("x-powered-by");

  const corsOptions = {
    origin: (origin, callback) => {
      if (!origin) {
        callback(null, true);
      } else if (origin === "null") {
        callback(new Error("Null Origin not permitted"));
      } else if (allowedOrigins.has(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    }
  };

  app.use(cors(corsOptions));
  app.use(express.json({ limit: JSON_BODY_LIMIT }));

  app.use((err, req, res, next) => {
    if (err && err.type === "entity.too.large") {
      return res.status(413).json({ error: "Request body too large" });
    }
    if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
      return res.status(400).json({ error: "Invalid JSON payload" });
    }
    next(err);
  });
  
  app.use((req, res, next) => {
    const requestId = req.headers["x-request-id"] || crypto.randomUUID();
    req.requestId = requestId;
    res.setHeader("X-Request-ID", requestId);
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    next();
  });

  app.get("/health", (req, res) => {
    res.status(200).json({ status: "healthy", proxyAddress: config.proxyAddress });
  });

  app.post("/api/voters/register", rateLimiter(VOTER_REGISTRATION_RATE_LIMIT, RATE_LIMIT_WINDOW_MS), originCheck, async (req, res) => {
    const {
      walletAddress,
      chainId,
      roundId,
      credentialHash,
      policyVersion,
      clientNonce,
      expiresAt,
      signature,
      issuerSignature,
      relayerNonce,
      relayerDeadline
    } = req.body;

    const nonceKey = `${walletAddress ? walletAddress.toLowerCase() : ""}:${clientNonce}`;

    try {
      if (
        !walletAddress ||
        !chainId ||
        !roundId ||
        !credentialHash ||
        !policyVersion ||
        !clientNonce ||
        !expiresAt ||
        !signature ||
        !issuerSignature ||
        relayerNonce === undefined ||
        relayerDeadline === undefined
      ) {
        return res.status(400).json({ error: "Invalid registration signature payload" });
      }

      // Chain ID & Round ID Check (domain containment)
      if (Number(chainId) !== Number(config.chainId) || roundId.toString() !== config.roundId.toString()) {
        return res.status(400).json({ error: "Invalid registration signature payload" });
      }

      // Check credential hash format
      const hexRegex = /^(0x)?[0-9a-fA-F]{64}$/;
      if (!hexRegex.test(credentialHash)) {
        return res.status(400).json({ error: "Invalid registration signature payload" });
      }

      // Validate policy version string or bytes32 hash
      if (!allowedPolicyVersions.has(policyVersion)) {
        return res.status(400).json({ error: "Invalid registration signature payload" });
      }

      // Convert policy version to bytes32 format for standard EIP-712 verification
      const policyVersionBytes = policyVersion.startsWith("0x")
        ? policyVersion
        : ethers.keccak256(ethers.toUtf8Bytes(policyVersion));

      // Expiry validation & maximum signature lifetime bounds
      const expiresTime = new Date(expiresAt).getTime();
      if (isNaN(expiresTime)) {
        return res.status(400).json({ error: "Invalid registration signature payload" });
      }

      const now = Date.now();
      const maxAllowedExpiry = now + 15 * 60 * 1000;
      if (expiresTime <= now || expiresTime > maxAllowedExpiry) {
        return res.status(401).json({ error: "Invalid registration signature payload" });
      }

      // Relayer signature deadline check
      const deadlineMs = Number(relayerDeadline) * 1000;
      if (deadlineMs <= now) {
        return res.status(401).json({ error: "Invalid registration signature payload" });
      }

      // 1. Voter EIP-191 Signature Verification
      try {
        verifyRegisterSignature({
          config,
          walletAddress,
          credentialHash,
          policyVersion,
          clientNonce,
          expiresAt,
          signature
        });
      } catch (err) {
        return res.status(401).json({ error: "Invalid registration signature payload" });
      }

      // 2. Relayer EIP-712 Signature Verification
      try {
        verifyRelayerSignature({
          config,
          walletAddress,
          credentialHash,
          policyVersionBytes,
          relayerNonce,
          relayerDeadline,
          issuerSignature
        });
      } catch (err) {
        return res.status(401).json({ error: "Invalid registration signature payload" });
      }

      // --- ATOMIC DATABASE LEDGER TRANSACTION CLAIM ---
      let requestHash;
      try {
        requestHash = sha256(stableStringify(req.body));
      } catch (err) {
        return res.status(400).json({ error: "Invalid registration signature payload" });
      }
      const { data: ledgerRes, error: rpcErr } = await supabaseClient.rpc("register_voter_ledger_start", {
        p_nonce_key: nonceKey,
        p_request_hash: requestHash
      });

      if (rpcErr) {
        console.error("Ledger start RPC failure:", rpcErr);
        return res.status(500).json({ error: "Database transaction failed" });
      }

      const ledger = ledgerRes && ledgerRes[0];
      if (!ledger) {
        return res.status(500).json({ error: "Database transaction failed" });
      }

      if (ledger.status === "mismatch") {
        return res.status(401).json({ error: "Invalid registration signature payload" });
      }

      if (ledger.status === "completed") {
        return res.status(200).json({ success: true, userId: ledger.user_id });
      }

      if (ledger.status === "pending") {
        return res.status(429).json({ error: "Too many requests, please try again later" });
      }

      // Salted HMAC Blinded Credential with deployment/use-case domain separation
      // Privacy Note: Storing wallet address alongside blinded credential HMAC exposes the operator
      // to correlation risk. An operator holding the credentialPepper secret can perform pre-image 
      // correlation to map specific pharmacy wallets to their respective raw credentials.
      const domainString = `domain:voter-credential-hash:chainId:${config.chainId}:roundId:${config.roundId}:`;
      const blindedCredential = crypto
        .createHmac("sha256", config.credentialPepper)
        .update(domainString + credentialHash)
        .digest("hex");

      // Database Sync
      const { data: existingProfile, error: profileErr } = await supabaseClient
        .from("voter_profiles")
        .select("id")
        .eq("wallet_address", walletAddress.toLowerCase())
        .maybeSingle();

      if (profileErr) {
        console.error("Supabase profile check error:", profileErr);
        await supabaseClient.rpc("register_voter_ledger_fail", { p_nonce_key: nonceKey });
        return res.status(500).json({ error: "Database transaction failed" });
      }

      let userId;

      if (!existingProfile) {
        // Idempotent synthetic user creation/lookup saga
        const syntheticEmail = `${walletAddress.toLowerCase()}@fiduciary.commons`;
        const { data: newUser, error: createErr } = await supabaseClient.auth.admin.createUser({
          email: syntheticEmail,
          email_confirm: true,
          user_metadata: { wallet_address: walletAddress.toLowerCase() }
        });

        if (createErr) {
          // If user exists due to partial failure, resolve user ID via listUsers
          if (createErr.message.includes("already exists") || createErr.status === 422) {
            const { data: users, error: listErr } = await supabaseClient.auth.admin.listUsers();
            if (listErr) {
              console.error("List users error during recovery:", listErr);
              await supabaseClient.rpc("register_voter_ledger_fail", { p_nonce_key: nonceKey });
              return res.status(500).json({ error: "Database transaction failed" });
            }
            const existingUser = users.users.find(u => u.email === syntheticEmail);
            if (!existingUser) {
              await supabaseClient.rpc("register_voter_ledger_fail", { p_nonce_key: nonceKey });
              return res.status(500).json({ error: "Database transaction failed" });
            }
            userId = existingUser.id;
          } else {
            console.error("Supabase user create error:", createErr);
            await supabaseClient.rpc("register_voter_ledger_fail", { p_nonce_key: nonceKey });
            return res.status(500).json({ error: "Database transaction failed" });
          }
        } else {
          userId = newUser.user.id;
        }

        // Insert profile
        const { error: insertErr } = await supabaseClient
          .from("voter_profiles")
          .insert({
            id: userId,
            wallet_address: walletAddress.toLowerCase(),
            encrypted_metadata: JSON.stringify({ credentialHash: blindedCredential, policyVersion })
          });

        if (insertErr) {
          console.error("Supabase voter profile insert error:", insertErr);
          await supabaseClient.rpc("register_voter_ledger_fail", { p_nonce_key: nonceKey });
          return res.status(500).json({ error: "Database transaction failed" });
        }
      } else {
        userId = existingProfile.id;

        // Update existing profile
        const { error: updateErr } = await supabaseClient
          .from("voter_profiles")
          .update({
            encrypted_metadata: JSON.stringify({ credentialHash: blindedCredential, policyVersion })
          })
          .eq("id", userId);

        if (updateErr) {
          console.error("Supabase voter profile update error:", updateErr);
          await supabaseClient.rpc("register_voter_ledger_fail", { p_nonce_key: nonceKey });
          return res.status(500).json({ error: "Database transaction failed" });
        }
      }

      // --- FINALISE REQUEST LEDGER STATUS (COMMIT) ---
      const { error: finalErr } = await supabaseClient.rpc("register_voter_ledger_complete", {
        p_nonce_key: nonceKey,
        p_user_id: userId
      });

      if (finalErr) {
        console.error("Supabase ledger commit error:", finalErr);
        await supabaseClient.rpc("register_voter_ledger_fail", { p_nonce_key: nonceKey });
        return res.status(500).json({ error: "Database transaction failed" });
      }

      res.status(200).json({ success: true, userId });
    } catch (err) {
      console.error("Register endpoint failure:", err);
      if (nonceKey) {
        await supabaseClient.rpc("register_voter_ledger_fail", { p_nonce_key: nonceKey }).catch(() => {});
      }
      res.status(500).json({ error: "Database transaction failed" });
    }
  });

  app.post("/api/relay/intake", rateLimiter(RELAY_INTAKE_RATE_LIMIT, RATE_LIMIT_WINDOW_MS), originCheck, async (req, res) => {
    try {
      const {
        walletAddress,
        chainId,
        roundId,
        nonce,
        expiresAt,
        signature,
        body
      } = req.body;

      if (
        !walletAddress ||
        !chainId ||
        !roundId ||
        !nonce ||
        !expiresAt ||
        !signature ||
        !body
      ) {
        return res.status(400).json({ error: "Invalid relay signature" });
      }

      // Domain check
      if (Number(chainId) !== Number(config.chainId) || roundId.toString() !== config.roundId.toString()) {
        return res.status(400).json({ error: "Invalid relay signature" });
      }

      const expiresTime = new Date(expiresAt).getTime();
      if (isNaN(expiresTime)) {
        return res.status(400).json({ error: "Invalid relay signature" });
      }

      const now = Date.now();
      const maxAllowedExpiry = now + 15 * 60 * 1000;
      if (expiresTime <= now || expiresTime > maxAllowedExpiry) {
        return res.status(401).json({ error: "Invalid relay signature" });
      }

      if (!validateRelayIntakeBody(body)) {
        return res.status(400).json({ error: "Invalid relay signature" });
      }

      const payloadString = JSON.stringify(body);
      const payloadHash = "0x" + sha256(payloadString);

      try {
        verifyRelaySignature({
          config,
          walletAddress,
          payloadHash,
          nonce,
          expiresAt,
          signature
        });
      } catch (err) {
        return res.status(401).json({ error: "Invalid relay signature" });
      }

      // Check nonce state
      const nonceKey = `${walletAddress.toLowerCase()}:${nonce}`;
      const { data: existingNonce, error: nonceCheckErr } = await supabaseClient
        .from("consumed_nonces")
        .select("nonce_key")
        .eq("nonce_key", nonceKey)
        .maybeSingle();

      if (nonceCheckErr) {
        return res.status(500).json({ error: "Database transaction failed" });
      }

      if (existingNonce) {
        return res.status(401).json({ error: "Invalid relay signature" });
      }

      // Nonce commit at the end
      const { error: nonceErr } = await supabaseClient
        .from("consumed_nonces")
        .insert({ nonce_key: nonceKey });

      if (nonceErr) {
        return res.status(500).json({ error: "Database transaction failed" });
      }

      res.status(200).json({ success: true });
    } catch (err) {
      console.error("Relay intake endpoint failure:", err);
      res.status(500).json({ error: "Database transaction failed" });
    }
  });

  app.post("/api/vouchers/reconcile", rateLimiter(VOUCHER_RECONCILIATION_RATE_LIMIT, RATE_LIMIT_WINDOW_MS), originCheck, async (req, res) => {
    let sagaKey;
    let parsedPayload;

    try {
      try {
        parsedPayload = validateVoucherReconcilePayload(req.body);
      } catch (err) {
        return res.status(400).json({ error: "Invalid voucher reconciliation payload" });
      }

      if (
        Number(parsedPayload.chainId) !== Number(config.chainId) ||
        parsedPayload.roundId !== config.roundId.toString()
      ) {
        return res.status(400).json({ error: "Invalid voucher reconciliation payload" });
      }

      const expiresTime = new Date(parsedPayload.expiresAt).getTime();
      if (isNaN(expiresTime)) {
        return res.status(400).json({ error: "Invalid voucher reconciliation payload" });
      }

      const now = Date.now();
      const maxAllowedExpiry = now + 15 * 60 * 1000;
      if (expiresTime <= now || expiresTime > maxAllowedExpiry) {
        return res.status(401).json({ error: "Invalid voucher reconciliation payload" });
      }

      sagaKey = deriveVoucherSagaKey(parsedPayload);

      try {
        verifyVoucherSagaSignature({ config, ...parsedPayload });
      } catch (err) {
        await supabaseClient.rpc("voucher_saga_dead_letter", {
          p_saga_key: sagaKey,
          p_request_hash: sha256(stableStringify(canonicalVoucherSagaRequest(parsedPayload))),
          p_voucher_id: parsedPayload.voucherId,
          p_pharmacy_address: parsedPayload.pharmacyAddress,
          p_amount: parsedPayload.amount,
          p_client_nonce: parsedPayload.clientNonce,
          p_error_code: "invalid_signature"
        }).catch(() => {});
        return res.status(401).json({ error: "Invalid voucher reconciliation payload" });
      }

      let requestHash;
      try {
        requestHash = sha256(stableStringify(canonicalVoucherSagaRequest(parsedPayload)));
      } catch (err) {
        return res.status(400).json({ error: "Invalid voucher reconciliation payload" });
      }

      const { data: sagaStartRes, error: sagaStartErr } = await supabaseClient.rpc("voucher_saga_start", {
        p_saga_key: sagaKey,
        p_request_hash: requestHash,
        p_voucher_id: parsedPayload.voucherId,
        p_pharmacy_address: parsedPayload.pharmacyAddress,
        p_amount: parsedPayload.amount,
        p_client_nonce: parsedPayload.clientNonce,
        p_payload_json: canonicalVoucherSagaRequest(parsedPayload)
      });

      if (sagaStartErr) {
        console.error("Voucher saga start RPC failure");
        return res.status(500).json({ error: "Database transaction failed" });
      }

      const saga = sagaStartRes && sagaStartRes[0];
      if (!saga) {
        return res.status(500).json({ error: "Database transaction failed" });
      }

      if (saga.status === "mismatch") {
        return res.status(401).json({ error: "Invalid voucher reconciliation payload" });
      }

      if (saga.status === "completed") {
        return res.status(200).json({
          success: true,
          sagaKey,
          status: "completed",
          replayed: true,
          result: saga.result_json || null
        });
      }

      if (saga.status === "pending" || saga.status === "retrying") {
        return res.status(429).json({ error: "Voucher settlement lease active" });
      }

      if (saga.status === "dead_letter") {
        return res.status(409).json({ error: "Voucher settlement requires manual review", sagaKey });
      }

      const result = {
        voucher_id: parsedPayload.voucherId,
        pharmacy_address: parsedPayload.pharmacyAddress,
        amount: parsedPayload.amount,
        settlement_status: "proxy_reconciled",
        proof_scope: "database_proxy_saga",
        onchain_settlement: "not_claimed"
      };

      const retryDelays = Array.isArray(config.sagaRetryDelaysMs)
        ? config.sagaRetryDelaysMs
        : [1000, 2000, 4000];

      for (let attempt = 1; attempt <= MAX_VOUCHER_RETRY_ATTEMPTS; attempt++) {
        const { error: completeErr } = await supabaseClient.rpc("voucher_saga_complete", {
          p_saga_key: sagaKey,
          p_result_json: result
        });

        if (!completeErr) {
          return res.status(200).json({ success: true, sagaKey, status: "completed", result });
        }

        console.error("Voucher saga complete RPC failure");
        await supabaseClient.rpc("voucher_saga_fail", {
          p_saga_key: sagaKey,
          p_error_code: "transient_commit_failure",
          p_transient: true
        }).catch(() => {});

        if (attempt < MAX_VOUCHER_RETRY_ATTEMPTS) {
          await delay(Number(retryDelays[attempt - 1] || 0));
        }
      }

      return res.status(500).json({ error: "Database transaction failed" });
    } catch (err) {
      console.error("Voucher reconcile endpoint failure");
      if (sagaKey) {
        await supabaseClient.rpc("voucher_saga_fail", {
          p_saga_key: sagaKey,
          p_error_code: "unhandled_proxy_exception",
          p_transient: false
        }).catch(() => {});
      }
      res.status(500).json({ error: "Database transaction failed" });
    }
  });

  // GET /api/health/observability - Solvency & System Observability Telemetry
  app.get("/api/health/observability", async (req, res) => {
    try {
      const fs = require("fs");
      const path = require("path");

      let matrixReceiptPresent = false;
      const matrixPath = path.join(__dirname, "..", "reviews", "provider_capability_matrix.json");
      if (fs.existsSync(matrixPath)) {
        matrixReceiptPresent = true;
      }

      res.setHeader("X-RateLimit-Contract-Voter-Registration", VOTER_REGISTRATION_RATE_LIMIT);
      res.setHeader("X-RateLimit-Contract-Relay-Intake", RELAY_INTAKE_RATE_LIMIT);
      res.setHeader("X-RateLimit-Contract-Voucher-Reconciliation", VOUCHER_RECONCILIATION_RATE_LIMIT);
      res.setHeader("X-RateLimit-Contract-Window-Ms", RATE_LIMIT_WINDOW_MS);

      const telemetry = {
        status: "healthy",
        status_scope: "endpoint_available",
        timestamp: new Date().toISOString(),
        solvency: {
          metric_source: "prototype_static_policy",
          live_contract_reads: false,
          debt_queue_status: "not_live_instrumented",
          solvency_debt_total: null,
          unclaimed_rebate_escrow: null,
          patient_fund_balance: null,
          dispute_retraction_toll_policy: "zero_toll"
        },
        zk_verifier: {
          active_version: "v1",
          circuit: "vote_nullifier.circom",
          signal_order_pinned: true,
          proof_scope: "local_schema_gate",
          production_unlinkability: "not_claimed"
        },
        model_observability: {
          matrix_receipt_present: matrixReceiptPresent,
          capability_matrix_path: "reviews/provider_capability_matrix.json",
          receipt_scope: "tracked_repo_receipt_presence"
        },
        saga_queue_telemetry: buildSagaQueueTelemetry(supabaseClient),
        rate_limit_contracts: {
          voter_registration_max: VOTER_REGISTRATION_RATE_LIMIT,
          relay_intake_max: RELAY_INTAKE_RATE_LIMIT,
          voucher_reconciliation_max: VOUCHER_RECONCILIATION_RATE_LIMIT,
          window_ms: RATE_LIMIT_WINDOW_MS
        },
        sanitized_rca: {
          trace_scope: "aggregate_counts_only",
          raw_trace_logging: false,
          redacted_fields: [
            "authorization",
            "cookie",
            "signature",
            "credentialPepper",
            "pharmacyAddress",
            "voucherId",
            "amount"
          ]
        },
        proxy_config: {
          chain_id: config.chainId,
          round_id: config.roundId,
          test_mode: config.testMode
        }
      };

      res.status(200).json(telemetry);
    } catch (err) {
      console.error("Observability health check failure:", err);
      res.status(500).json({ status: "degraded", error: "Failed to query observability metrics" });
    }
  });

  app.use((err, req, res, next) => {
    if (err && err.message === "Null Origin not permitted") {
      return res.status(403).json({ error: "CORS policy violation: null origin not permitted" });
    }
    if (err && err.message === "Not allowed by CORS") {
      return res.status(403).json({ error: "CORS policy violation: unauthorized origin" });
    }
    next(err);
  });

  return app;
}

module.exports = {
  createApp,
  verifyRegisterSignature,
  verifyRelaySignature,
  verifyVoucherSagaSignature,
  deriveVoucherSagaKey
};
