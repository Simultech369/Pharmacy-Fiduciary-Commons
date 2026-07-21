const express = require("express");
const cors = require("cors");
const ethers = require("ethers");
const crypto = require("crypto");

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

const allowedPolicyVersions = new Set(["1.0.0"]);

// Hardcoded trusted credential issuer address for authority validation
const TRUSTED_ISSUER_ADDRESS = "0xF39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

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

// EIP-191 Signature Verification
function verifyRegisterSignature({
  chainId,
  roundId,
  walletAddress,
  credentialHash,
  policyVersion,
  nonce,
  expiresAt,
  signature
}) {
  const canonicalString = [
    `Pharmacy Fiduciary Commons Database Proxy`,
    `Version: 1`,
    `Action: register-voter`,
    `Chain ID: ${chainId}`,
    `Round ID: ${roundId}`,
    `Wallet: ${walletAddress}`,
    `Credential Hash: ${credentialHash}`,
    `Policy Version: ${policyVersion}`,
    `Nonce: ${nonce}`,
    `Expires At: ${expiresAt}`
  ].join("\n");

  const recoveredAddress = ethers.verifyMessage(canonicalString, signature);
  if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
    throw new Error(`Signature recovery mismatch: expected ${walletAddress}, got ${recoveredAddress}`);
  }

  return true;
}

// Verify that the credential is signed and approved by the trusted issuer
function verifyIssuerSignature({
  walletAddress,
  credentialHash,
  policyVersion,
  issuerSignature
}) {
  const canonicalString = [
    `Pharmacy Fiduciary Commons Credential Authorization`,
    `Wallet: ${walletAddress.toLowerCase()}`,
    `Credential Hash: ${credentialHash}`,
    `Policy Version: ${policyVersion}`
  ].join("\n");

  const recoveredIssuer = ethers.verifyMessage(canonicalString, issuerSignature);
  return recoveredIssuer.toLowerCase() === TRUSTED_ISSUER_ADDRESS.toLowerCase();
}

function verifyRelaySignature({
  chainId,
  roundId,
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
    `Chain ID: ${chainId}`,
    `Round ID: ${roundId}`,
    `Wallet: ${walletAddress}`,
    `Payload Hash: ${payloadHash}`,
    `Nonce: ${nonce}`,
    `Expires At: ${expiresAt}`
  ].join("\n");

  const recoveredAddress = ethers.verifyMessage(canonicalString, signature);
  if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
    throw new Error(`Signature recovery mismatch: expected ${walletAddress}, got ${recoveredAddress}`);
  }

  return true;
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

function createApp(supabaseClient) {
  const app = express();
  
  // Explicitly configure 'trust proxy' to false to prevent ip address spoofing
  app.set("trust proxy", false);
  app.disable("x-powered-by");

  // Route-specific CORS allowlist instead of global wildcard
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
  
  // Security and Cache-Control Headers Middleware
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
    res.status(200).json({ status: "healthy" });
  });

  app.post("/api/voters/register", rateLimiter(100, 15 * 60 * 1000), originCheck, async (req, res) => {
    try {
      const {
        walletAddress,
        chainId,
        roundId,
        credentialHash,
        policyVersion,
        nonce,
        expiresAt,
        signature,
        issuerSignature
      } = req.body;

      if (
        !walletAddress ||
        !chainId ||
        !roundId ||
        !credentialHash ||
        !policyVersion ||
        !nonce ||
        !expiresAt ||
        !signature ||
        !issuerSignature
      ) {
        return res.status(400).json({ error: "Missing required signature registration fields" });
      }

      // Check credential hash format
      const hexRegex = /^(0x)?[0-9a-fA-F]{64}$/;
      if (!hexRegex.test(credentialHash)) {
        return res.status(400).json({ error: "Invalid credential hash format" });
      }

      // Validate policy version strictly
      if (!allowedPolicyVersions.has(policyVersion)) {
        return res.status(400).json({ error: "Unsupported policy version" });
      }

      // Expiry validation & maximum signature lifetime bounds
      const expiresTime = new Date(expiresAt).getTime();
      if (isNaN(expiresTime)) {
        return res.status(400).json({ error: "Invalid expiration format" });
      }

      const now = Date.now();
      const maxAllowedExpiry = now + 15 * 60 * 1000; // max 15 minutes in the future
      if (expiresTime <= now) {
        return res.status(401).json({ error: "Signature expiration has passed" });
      }
      if (expiresTime > maxAllowedExpiry) {
        return res.status(400).json({ error: "Signature expiration exceeds maximum permitted lifetime" });
      }

      // EIP-191 Signature Verification (FIRST before database/nonce operations)
      try {
        verifyRegisterSignature({
          chainId,
          roundId,
          walletAddress,
          credentialHash,
          policyVersion,
          nonce,
          expiresAt,
          signature
        });
      } catch (err) {
        return res.status(401).json({ error: err.message });
      }

      // Verify that the credential is signed and approved by the trusted issuer
      try {
        const isApproved = verifyIssuerSignature({
          walletAddress,
          credentialHash,
          policyVersion,
          issuerSignature
        });
        if (!isApproved) {
          return res.status(401).json({ error: "Unauthorized: credential is not approved by a trusted issuer" });
        }
      } catch (err) {
        return res.status(401).json({ error: "Issuer signature verification failed: " + err.message });
      }

      // Replay Protection: Durable, atomic unique-key check using DB insert
      const nonceKey = `${walletAddress.toLowerCase()}:${nonce}`;
      const { error: nonceErr } = await supabaseClient
        .from("consumed_nonces")
        .insert({ nonce_key: nonceKey });

      if (nonceErr) {
        // Distinguish actual unique constraint replay conflict from other database failures
        if (nonceErr.code === "23505" || nonceErr.message.includes("Duplicate key") || nonceErr.message.includes("unique")) {
          return res.status(401).json({ error: "Replay attempt detected: nonce has already been used" });
        }
        console.error("Supabase nonce insert error:", nonceErr);
        return res.status(500).json({ error: "Database transaction failed" });
      }

      // Blind the stable credential hash to prevent correlation leakage in the database
      const blindedCredential = sha256(credentialHash);

      // Database Sync
      const { data: existingProfile, error: profileErr } = await supabaseClient
        .from("voter_profiles")
        .select("id")
        .eq("wallet_address", walletAddress.toLowerCase())
        .maybeSingle();

      if (profileErr) {
        console.error("Supabase profile check error:", profileErr);
        return res.status(500).json({ error: "Database profile verification failed" });
      }

      let userId;

      if (!existingProfile) {
        // Create synthetic user account to satisfy DB constraints
        const syntheticEmail = `${walletAddress.toLowerCase()}@fiduciary.commons`;
        const { data: newUser, error: createErr } = await supabaseClient.auth.admin.createUser({
          email: syntheticEmail,
          email_confirm: true,
          user_metadata: { wallet_address: walletAddress.toLowerCase() }
        });

        if (createErr) {
          console.error("Supabase user create error:", createErr);
          return res.status(500).json({ error: "Database user creation failed" });
        }
        userId = newUser.user.id;

        // Create the voter profile with blinded metadata
        const { error: insertErr } = await supabaseClient
          .from("voter_profiles")
          .insert({
            id: userId,
            wallet_address: walletAddress.toLowerCase(),
            encrypted_metadata: JSON.stringify({ credentialHash: blindedCredential, policyVersion })
          });

        if (insertErr) {
          console.error("Supabase voter profile insert error:", insertErr);
          return res.status(500).json({ error: "Database profile registration failed" });
        }
      } else {
        userId = existingProfile.id;

        // Update existing profile with blinded metadata
        const { error: updateErr } = await supabaseClient
          .from("voter_profiles")
          .update({
            encrypted_metadata: JSON.stringify({ credentialHash: blindedCredential, policyVersion })
          })
          .eq("id", userId);

        if (updateErr) {
          console.error("Supabase voter profile update error:", updateErr);
          return res.status(500).json({ error: "Database profile update failed" });
        }
      }

      res.status(200).json({ success: true, userId });
    } catch (err) {
      console.error("Register endpoint failure:", err);
      res.status(500).json({ error: "Internal server error" });
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
        return res.status(400).json({ error: "Missing required signature relay intake fields" });
      }

      // Expiry validation & maximum signature lifetime bounds
      const expiresTime = new Date(expiresAt).getTime();
      if (isNaN(expiresTime)) {
        return res.status(400).json({ error: "Invalid expiration format" });
      }

      const now = Date.now();
      const maxAllowedExpiry = now + 15 * 60 * 1000;
      if (expiresTime <= now) {
        return res.status(401).json({ error: "Signature expiration has passed" });
      }
      if (expiresTime > maxAllowedExpiry) {
        return res.status(400).json({ error: "Signature expiration exceeds maximum permitted lifetime" });
      }

      // Enforce strict recursive allowlist check (reject any forbidden or unknown files/fields)
      if (!validateRelayIntakeBody(body)) {
        return res.status(400).json({ error: "Forbidden or malformed fields detected in relay intake" });
      }

      // Verify EIP-191 signature over payload hash (FIRST before database/nonce operations)
      const payloadString = JSON.stringify(body);
      const payloadHash = "0x" + sha256(payloadString);

      try {
        verifyRelaySignature({
          chainId,
          roundId,
          walletAddress,
          payloadHash,
          nonce,
          expiresAt,
          signature
        });
      } catch (err) {
        return res.status(401).json({ error: err.message });
      }

      // Replay Protection: Durable, atomic unique-key check using DB insert
      const nonceKey = `${walletAddress.toLowerCase()}:${nonce}`;
      const { error: nonceErr } = await supabaseClient
        .from("consumed_nonces")
        .insert({ nonce_key: nonceKey });

      if (nonceErr) {
        if (nonceErr.code === "23505" || nonceErr.message.includes("Duplicate key") || nonceErr.message.includes("unique")) {
          return res.status(401).json({ error: "Replay attempt detected: nonce has already been used" });
        }
        console.error("Supabase nonce insert error:", nonceErr);
        return res.status(500).json({ error: "Database transaction failed" });
      }

      res.status(200).json({ success: true, message: "Relay batch accepted for review, pending settlement verification." });
    } catch (err) {
      console.error("Relay intake endpoint failure:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Global Error Handler for CORS block to return 403 on Origin/CORS errors
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
