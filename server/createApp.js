const express = require("express");
const cors = require("cors");
const ethers = require("ethers");
const crypto = require("crypto");

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

const forbiddenFields = new Set([
  "address",
  "gasPayer",
  "ipAddress",
  "mac",
  "metadata",
  "mockZKProof",
  "pharmacyAddress",
  "preimage",
  "proof",
  "rawRpcIdentifier",
  "signature",
  "timestamp",
  "userAgent",
  "voter",
  "voterAddress",
  "voucherPreimage",
  "voucherPreimageHash",
  "wallet"
]);

function hasForbiddenFields(obj) {
  if (!obj || typeof obj !== "object") return false;
  
  if (Array.isArray(obj)) {
    return obj.some(item => hasForbiddenFields(item));
  }

  for (const key of Object.keys(obj)) {
    if (forbiddenFields.has(key)) return true;
    if (typeof obj[key] === "object" && hasForbiddenFields(obj[key])) {
      return true;
    }
  }
  return false;
}

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

  const expTime = new Date(expiresAt).getTime();
  if (Date.now() > expTime) {
    throw new Error("Signature expiration has passed");
  }

  return true;
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

  const expTime = new Date(expiresAt).getTime();
  if (Date.now() > expTime) {
    throw new Error("Signature expiration has passed");
  }

  return true;
}

function createApp(supabaseClient) {
  const app = express();
  app.use(cors());
  app.use(express.json());

  // In-memory set for replay protection
  const usedNonces = new Set();

  app.get("/health", (req, res) => {
    res.status(200).json({ status: "healthy" });
  });

  app.post("/api/voters/register", async (req, res) => {
    try {
      const {
        walletAddress,
        chainId,
        roundId,
        credentialHash,
        policyVersion,
        nonce,
        expiresAt,
        signature
      } = req.body;

      if (
        !walletAddress ||
        !chainId ||
        !roundId ||
        !credentialHash ||
        !policyVersion ||
        !nonce ||
        !expiresAt ||
        !signature
      ) {
        return res.status(400).json({ error: "Missing required signature registration fields" });
      }

      // Replay Protection: Check and track nonces
      if (usedNonces.has(nonce)) {
        return res.status(401).json({ error: "Replay attempt detected: nonce has already been used" });
      }
      usedNonces.add(nonce);

      // Verify EIP-191 signature
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

      // Database Sync
      const { data: existingProfile, error: profileErr } = await supabaseClient
        .from("voter_profiles")
        .select("id")
        .eq("wallet_address", walletAddress.toLowerCase())
        .maybeSingle();

      if (profileErr) {
        return res.status(500).json({ error: "Supabase write error: " + profileErr.message });
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
          return res.status(500).json({ error: "Supabase write error: " + createErr.message });
        }
        userId = newUser.user.id;

        // Create the voter profile
        const { error: insertErr } = await supabaseClient
          .from("voter_profiles")
          .insert({
            id: userId,
            wallet_address: walletAddress.toLowerCase(),
            encrypted_metadata: JSON.stringify({ credentialHash, policyVersion })
          });

        if (insertErr) {
          return res.status(500).json({ error: "Supabase write error: " + insertErr.message });
        }
      } else {
        userId = existingProfile.id;

        // Update existing profile metadata
        const { error: updateErr } = await supabaseClient
          .from("voter_profiles")
          .update({
            encrypted_metadata: JSON.stringify({ credentialHash, policyVersion })
          })
          .eq("id", userId);

        if (updateErr) {
          return res.status(500).json({ error: "Supabase write error: " + updateErr.message });
        }
      }

      res.status(200).json({ success: true, userId });
    } catch (err) {
      console.error("Register endpoint failure:", err);
      res.status(500).json({ error: "Internal server error: " + err.message });
    }
  });

  app.post("/api/relay/intake", async (req, res) => {
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

      // Replay Protection: Check and track nonces
      if (usedNonces.has(nonce)) {
        return res.status(401).json({ error: "Replay attempt detected: nonce has already been used" });
      }
      usedNonces.add(nonce);

      // Verify EIP-191 signature over payload hash
      const payloadString = typeof body === "string" ? body : JSON.stringify(body);
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

      // Enforce strict containment check: reject any forbidden files/fields
      if (hasForbiddenFields(body)) {
        return res.status(400).json({ error: "Forbidden fields detected: preimage, mac, or other sensitive details are not permitted in sanitized relay intake" });
      }

      // Stub response (no database upload until separate design checkpoint approves fields)
      res.status(200).json({ success: true, message: "Relay batch accepted for review, pending settlement verification." });
    } catch (err) {
      console.error("Relay intake endpoint failure:", err);
      res.status(500).json({ error: "Internal server error: " + err.message });
    }
  });

  return app;
}

module.exports = { createApp, verifyRegisterSignature, verifyRelaySignature };
