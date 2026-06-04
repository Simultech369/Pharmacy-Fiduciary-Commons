# Verifiable Credential Layer (P-07)

This folder contains a zero-dependency cryptographic tool to issue and verify decentralized credentials for independent pharmacies and patient advocates.

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

To sign the **Pharmacy License** (index `0` in `mock_subject.json`):

```bash
node tools/credentials/credentials.mjs issue \
  --subject tools/credentials/mock_subject.json \
  --index 0 \
  --key tools/credentials/issuer_private.key \
  --out tools/credentials/signed_pharmacy.json
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

Verify the cryptographic integrity and authenticity of the credential using the issuer's public key:

```bash
node tools/credentials/credentials.mjs verify \
  --credential tools/credentials/signed_pharmacy.json \
  --key tools/credentials/issuer_public.key
```

### 4. Test Tamper Detection

If anyone attempts to modify any part of the claims (e.g. changing `"active": true` to `"active": false` or altering the subject name) or the proof metadata inside the signed JSON, verification will fail.

Try editing `signed_pharmacy.json` manually and then run the verification command to observe the security rejection:

```bash
node tools/credentials/credentials.mjs verify \
  --credential tools/credentials/signed_pharmacy.json \
  --key tools/credentials/issuer_public.key
```
