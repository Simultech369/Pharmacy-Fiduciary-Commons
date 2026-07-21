const express = require("express");
const cors = require("cors");
const ethers = require("ethers");
const crypto = require("crypto");

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
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
    const ip = req.ip || req.connection.remoteAddress; 
    const now = Date.now();
    
    if (!rateLimitMap.has(ip)) {
      rateLimitMap.set(ip, { timestamps: [] });
    }
    
    const record = rateLimitMap.get(ip);
    record.timestamps = record.timestamps.filter(t => now - t < windowMs);
    
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
  app.use(express.json());
  
  app.use((req, res, next) => {
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

  app.post("/api/voters/register", rateLimiter(100, 15 * 60 * 1000), originCheck, async (req, res) => {
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
      const requestHash = sha256(JSON.stringify(req.body));
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

  app.post("/api/relay/intake", rateLimiter(100, 15 * 60 * 1000), originCheck, async (req, res) => {
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

module.exports = { createApp, verifyRegisterSignature, verifyRelaySignature };
