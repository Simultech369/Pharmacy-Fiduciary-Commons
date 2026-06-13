import crypto from "node:crypto";
import { ethers } from "ethers";

export const TRUSTED_ISSUER_KEYS = new Map([
  [
    "did:web:fiduciarycommons.org#key-1",
    "cf38d1f0834f43d87f69ff75e874c9bf5487db6c60470dc851b41760f0a1b6ec"
  ]
]);

export const ELIGIBLE_VOTER_TYPES = new Set([
  "PharmacyLicenseCredential",
  "PatientAdvocateCredential"
]);

export function canonicalize(obj) {
  function sortKeys(value) {
    if (value === null || typeof value !== "object") return value;
    if (Array.isArray(value)) return value.map(sortKeys);

    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      sorted[key] = sortKeys(value[key]);
    }
    return sorted;
  }

  return JSON.stringify(sortKeys(obj));
}

export function subjectAddress(subjectId) {
  if (typeof subjectId !== "string") {
    throw new Error("Credential subject id is missing.");
  }

  const candidate = subjectId.startsWith("did:ethr:")
    ? subjectId.slice("did:ethr:".length)
    : subjectId;
  return ethers.getAddress(candidate);
}

export function publicKeyFingerprint(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("hex");
}

export function verifyCredential({
  credential,
  publicKeyPem,
  expectedVoter,
  revokedCredentialIds = new Set(),
  trustedIssuerKeys = TRUSTED_ISSUER_KEYS,
  eligibleTypes = ELIGIBLE_VOTER_TYPES,
  now = new Date()
}) {
  const proof = credential?.proof;
  if (!proof?.proofValue || !proof?.verificationMethod) {
    throw new Error("Credential is missing its cryptographic proof.");
  }

  const trustedFingerprint = trustedIssuerKeys.get(proof.verificationMethod);
  if (!trustedFingerprint) {
    throw new Error(`Untrusted verification method '${proof.verificationMethod}'.`);
  }

  const suppliedFingerprint = publicKeyFingerprint(publicKeyPem);
  if (suppliedFingerprint !== trustedFingerprint) {
    throw new Error("Supplied public key does not match the pinned issuer key.");
  }

  if (credential.issuer !== "did:web:fiduciarycommons.org") {
    throw new Error("Credential issuer is not trusted.");
  }

  if (!Array.isArray(credential.type) || !credential.type.some(type => eligibleTypes.has(type))) {
    throw new Error("Credential type is not eligible for voter registration.");
  }

  if (credential.credentialSubject?.active !== true) {
    throw new Error("Credential subject is not active.");
  }

  const issuanceTime = Date.parse(credential.issuanceDate);
  const expirationTime = Date.parse(credential.expirationDate);
  const nowTime = now.getTime();
  if (!Number.isFinite(issuanceTime) || issuanceTime > nowTime) {
    throw new Error("Credential issuance date is invalid or in the future.");
  }
  if (!Number.isFinite(expirationTime) || expirationTime <= nowTime) {
    throw new Error("Credential is expired or missing a valid expiration date.");
  }

  if (typeof credential.id !== "string" || revokedCredentialIds.has(credential.id)) {
    throw new Error("Credential is revoked or has no stable credential id.");
  }

  const credentialAddress = subjectAddress(credential.credentialSubject?.id);
  if (expectedVoter && credentialAddress !== ethers.getAddress(expectedVoter)) {
    throw new Error("Credential subject does not match the requested voter address.");
  }

  const unsignedCredential = { ...credential };
  delete unsignedCredential.proof;
  const signature = Buffer.from(proof.proofValue, "hex");
  const valid = crypto.verify(
    null,
    Buffer.from(canonicalize(unsignedCredential)),
    publicKeyPem,
    signature
  );
  if (!valid) {
    throw new Error("Credential signature is invalid or the payload was modified.");
  }

  return { credentialAddress, credentialType: credential.type.find(type => eligibleTypes.has(type)) };
}
