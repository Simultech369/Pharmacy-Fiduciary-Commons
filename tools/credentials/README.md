# Verifiable Credential Layer (P-07)

This folder contains prototype tooling to issue and verify credentials for independent pharmacies and patient advocates.

## Cryptography

The credentials utilize **Ed25519 signatures** via Node's native `crypto` module. This provides:
- High performance signing and verification.
- Tamper-proof JSON payloads.
- Small key sizes and public key formats (SPKI/PKCS8 PEM).

## How to Use

### 1. Generate Key Pair

Generate the issuer's public and private key files:

```bash
node tools/credentials/credentials.mjs key-gen
```

This creates:
- `tools/credentials/issuer_private.key` (Keep secure!)
- `tools/credentials/issuer_public.key` (Share publicly to allow anyone to verify your issued credentials.)

### 2. Issue a Verifiable Credential

Issue a signed credential by taking subject claims and signing them with the issuer's private key.
Credentials expire after 90 days by default. Use `--valid-days` to select a period from 1 to 365 days.

To sign the **Pharmacy License** (index `0` in `mock_subject.json`):

```bash
node tools/credentials/credentials.mjs issue \
  --subject tools/credentials/mock_subject.json \
  --index 0 \
  --key tools/credentials/issuer_private.key \
  --out tools/credentials/signed_pharmacy.json \
  --valid-days 90
```

To sign the **Patient Advocate** credential (index `1` in `mock_subject.json`):

```bash
node tools/credentials/credentials.mjs issue \
  --subject tools/credentials/mock_subject.json \
  --index 1 \
  --key tools/credentials/issuer_private.key \
  --out tools/credentials/signed_advocate.json
```

### 3. Verify a Credential

Verification enforces the pinned issuer key, eligible credential type, active status, issuance and expiration dates, and the revocation registry. Supplying `--voter` additionally binds the credential subject to that wallet.

```bash
node tools/credentials/credentials.mjs verify \
  --credential tools/credentials/signed_pharmacy.json \
  --key tools/credentials/issuer_public.key \
  --voter 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
  --revocations tools/credentials/revoked_credentials.json
```

### 4. Test Tamper Detection

If anyone attempts to modify any part of the claims (e.g. changing `"active": true` to `"active": false` or altering the subject name) or the proof metadata inside the signed JSON, verification will fail.

Try editing `signed_pharmacy.json` manually and then run the verification command to observe the security rejection:

```bash
node tools/credentials/credentials.mjs verify \
  --credential tools/credentials/signed_pharmacy.json \
  --key tools/credentials/issuer_public.key
```

### Revocation And Trust Rotation

Add revoked credential IDs to `revoked_credentials.json`. The voter relayer reads the same registry before issuing an on-chain registration signature.

`credential-policy.mjs` pins the accepted issuer-key fingerprint. Generating a replacement key does not automatically make it trusted: rotate the fingerprint deliberately, regenerate public examples, and retain the old credential IDs in the revocation registry.

### Voter Relayer

The voter relayer applies this same policy before signing. Supply the current on-chain `registrationNonces(roundId, voter)` value and target chain ID:

```bash
RELAYER_PRIVATE_KEY=0x... node scripts/register-voter-relayer.mjs \
  --credential tools/credentials/signed_pharmacy.json \
  --voter 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
  --round 1 \
  --contract 0x... \
  --chain-id 31337 \
  --nonce 0 \
  --issuer-key tools/credentials/issuer_public.key \
  --revocations tools/credentials/revoked_credentials.json
```

The contract consumes the nonce after successful registration. Any council registration or revocation also advances it, invalidating previously issued signatures. Each EIP-712 authorization additionally binds the verified credential hash, credential-policy version, and a deadline no later than the credential expiry; the default authorization lifetime is one hour. Wallets can display the typed registration fields instead of an opaque raw hash.
