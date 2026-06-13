const { expect } = require("chai");
const crypto = require("node:crypto");
const { ethers } = require("hardhat");

describe("Credential voter authorization policy", function () {
  let canonicalize;
  let publicKeyFingerprint;
  let createRegistrationAuthorization;
  let credentialPolicyVersion;
  let registrationDomainName;
  let registrationDomainVersion;
  let registrationTypes;
  let privateKey;
  let publicKey;
  let trustedIssuerKeys;
  let voter;
  let relayer;
  let contractAddress;
  const now = new Date("2026-06-13T12:00:00.000Z");

  before(async function () {
    ({ canonicalize, publicKeyFingerprint } = await import("../tools/credentials/credential-policy.mjs"));
    ({
      createRegistrationAuthorization,
      CREDENTIAL_POLICY_VERSION: credentialPolicyVersion,
      REGISTRATION_DOMAIN_NAME: registrationDomainName,
      REGISTRATION_DOMAIN_VERSION: registrationDomainVersion,
      REGISTRATION_TYPES: registrationTypes
    } = await import("../scripts/register-voter-relayer.mjs"));

    ({ publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" }
    }));
    const fingerprint = publicKeyFingerprint(publicKey);
    trustedIssuerKeys = new Map([["did:web:fiduciarycommons.org#test-key", fingerprint]]);

    const signers = await ethers.getSigners();
    voter = signers[6];
    relayer = ethers.Wallet.createRandom();
    contractAddress = signers[8].address;
  });

  function signedCredential(overrides = {}) {
    const credential = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      id: "urn:uuid:test-credential",
      type: ["VerifiableCredential", "PharmacyLicenseCredential"],
      issuer: "did:web:fiduciarycommons.org",
      issuanceDate: "2026-06-01T00:00:00.000Z",
      expirationDate: "2026-07-01T00:00:00.000Z",
      credentialSubject: {
        id: `did:ethr:${voter.address}`,
        active: true
      },
      ...overrides
    };
    const signature = crypto.sign(null, Buffer.from(canonicalize(credential)), privateKey);
    credential.proof = {
      type: "Ed25519Signature2020",
      verificationMethod: "did:web:fiduciarycommons.org#test-key",
      proofPurpose: "assertionMethod",
      proofValue: signature.toString("hex")
    };
    return credential;
  }

  async function authorize(credential, options = {}) {
    return createRegistrationAuthorization({
      credential,
      publicKeyPem: publicKey,
      voter: options.voter ?? voter.address,
      roundId: 1n,
      contractAddress,
      chainId: 31337n,
      nonce: 0n,
      relayerPrivateKey: relayer.privateKey,
      revokedCredentialIds: options.revokedCredentialIds ?? new Set(),
      trustedIssuerKeys,
      now
    });
  }

  it("authorizes an active, unexpired credential bound to the voter", async function () {
    const credential = signedCredential();
    const result = await authorize(credential);
    expect(result.voter).to.equal(voter.address);
    expect(result.credentialHash).to.equal(
      ethers.keccak256(ethers.toUtf8Bytes(canonicalize(credential)))
    );
    expect(result.policyVersion).to.equal(credentialPolicyVersion);
    expect(result.deadline).to.equal(Math.floor(now.getTime() / 1000) + 3600);

    const recovered = ethers.verifyTypedData(
      {
        name: registrationDomainName,
        version: registrationDomainVersion,
        chainId: 31337n,
        verifyingContract: contractAddress
      },
      registrationTypes,
      {
        roundId: 1n,
        voter: voter.address,
        nonce: 0n,
        credentialHash: result.credentialHash,
        policyVersion: result.policyVersion,
        deadline: result.deadline
      },
      result.signature
    );
    expect(recovered).to.equal(relayer.address);
  });

  it("uses a line-ending-independent issuer key fingerprint", function () {
    expect(publicKeyFingerprint(publicKey.replaceAll("\n", "\r\n"))).to.equal(
      publicKeyFingerprint(publicKey)
    );
  });

  it("rejects a credential bound to a different voter", async function () {
    let error;
    try {
      await authorize(signedCredential(), { voter: relayer.address });
    } catch (caught) {
      error = caught;
    }
    expect(error.message).to.contain("does not match");
  });

  it("rejects inactive, expired, and revoked credentials", async function () {
    const inactive = signedCredential({ credentialSubject: { id: `did:ethr:${voter.address}`, active: false } });
    const expired = signedCredential({ expirationDate: "2026-06-12T00:00:00.000Z" });

    for (const [credential, expected, revokedCredentialIds] of [
      [inactive, "not active", new Set()],
      [expired, "expired", new Set()],
      [signedCredential(), "revoked", new Set(["urn:uuid:test-credential"])]
    ]) {
      let error;
      try {
        await authorize(credential, { revokedCredentialIds });
      } catch (caught) {
        error = caught;
      }
      expect(error.message).to.contain(expected);
    }
  });

  it("rejects self-issued or untrusted issuer keys", async function () {
    const credential = signedCredential();
    credential.proof.verificationMethod = "did:web:attacker.example#key-1";

    let error;
    try {
      await authorize(credential);
    } catch (caught) {
      error = caught;
    }
    expect(error.message).to.contain("Untrusted verification method");
  });

  it("rejects credential types outside the voter eligibility policy", async function () {
    const credential = signedCredential({ type: ["VerifiableCredential", "NewsletterSubscriber"] });
    let error;
    try {
      await authorize(credential);
    } catch (caught) {
      error = caught;
    }
    expect(error.message).to.contain("not eligible");
  });
});
