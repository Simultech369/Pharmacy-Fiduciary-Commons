const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

const FORBIDDEN_UNLINKABLE_FIELDS = [
  "walletAddress",
  "npi",
  "ncpdp",
  "stableCredentialHash",
  "rawCredential",
  "credentialSecret",
  "witnessMaterial",
  "issuerSideRealWorldIdentifier",
  "voterNullifierCoExposure",
  "exactTimestamp",
  "gasPayer",
  "rawRpcIdentifier",
  "supportTicketId"
];

describe("ZK/Nullifier Design Fixture and Test Gate", function () {
  let futureSchema;
  let mockPayload;
  let unlinkablePayload;
  let governanceFixture;
  let leakageTable;

  before(function () {
    futureSchema = JSON.parse(
      fs.readFileSync(path.join(__dirname, "fixtures", "futurePayloadSchema.json"), "utf8")
    );
    mockPayload = JSON.parse(
      fs.readFileSync(path.join(__dirname, "fixtures", "mockPathPayload.json"), "utf8")
    );
    unlinkablePayload = JSON.parse(
      fs.readFileSync(path.join(__dirname, "fixtures", "unlinkablePayload.json"), "utf8")
    );
    governanceFixture = JSON.parse(
      fs.readFileSync(path.join(__dirname, "fixtures", "governanceFixture.json"), "utf8")
    );
    leakageTable = JSON.parse(
      fs.readFileSync(path.join(__dirname, "fixtures", "metadataLeakageTable.json"), "utf8")
    );
  });

  // Helper validation function for the payload schema
  function validateBasicSchema(payload, schema) {
    // 1. Check required fields
    schema.required.forEach((field) => {
      expect(payload, `Payload missing required field: ${field}`).to.have.property(field);
    });

    // 2. Validate format of nullifier and membershipRoot
    const hexPattern = /^0x[0-9a-fA-F]{64}$/;
    expect(payload.nullifier).to.match(hexPattern, "nullifier must be a 32-byte hex string");
    expect(payload.membershipRoot).to.match(hexPattern, "membershipRoot must be a 32-byte hex string");

    // 3. Validate types
    expect(payload.publicSignals).to.be.an("array");
    expect(payload.metadataLeakageBudget).to.be.an("object");

    schema.properties.metadataLeakageBudget.required.forEach((field) => {
      expect(payload.metadataLeakageBudget, `metadataLeakageBudget missing required field: ${field}`).to.have.property(field);
    });
  }

  describe("1. Fixture Schema Validation", function () {
    it("validates mock-path payload against future schema structure", function () {
      validateBasicSchema(mockPayload, futureSchema);
    });

    it("validates unlinkable-path payload against future schema structure", function () {
      validateBasicSchema(unlinkablePayload, futureSchema);
    });
  });

  describe("2. Current Mock-Path Fixture Gate", function () {
    it("ensures mock-path is explicitly labeled semantic-wallet-linkable", function () {
      expect(mockPayload.privacyTarget).to.equal("semantic-wallet-linkable");
    });

    it("allows wallet and stable hash exposure on semantic-wallet-linkable payloads", function () {
      expect(mockPayload).to.have.property("walletAddress");
      expect(mockPayload).to.have.property("stableCredentialHash");
      expect(mockPayload.metadataLeakageBudget.allowsWalletAddress).to.be.true;
      expect(mockPayload.metadataLeakageBudget.allowsStableHash).to.be.true;
    });

    it("asserts semantic-wallet-linkable payloads are never labeled unlinkable", function () {
      expect(mockPayload.privacyTarget).to.not.equal("unlinkable");
    });
  });

  describe("3. Future Unlinkable-Path Fixture Gate", function () {
    it("ensures unlinkable-path is explicitly labeled unlinkable", function () {
      expect(unlinkablePayload.privacyTarget).to.equal("unlinkable");
    });

    it("asserts forbidden fields are strictly absent in unlinkable payload", function () {
      FORBIDDEN_UNLINKABLE_FIELDS.forEach((field) => {
        expect(unlinkablePayload, `Forbidden field '${field}' must not be present in unlinkable payload`).to.not.have.property(field);
      });
    });

    it("asserts metadata leakage budget does not permit sensitive exposure", function () {
      const budget = unlinkablePayload.metadataLeakageBudget;
      expect(budget.allowsWalletAddress).to.be.false;
      expect(budget.allowsStableHash).to.be.false;
      expect(budget.allowsExactTimestamp).to.be.false;
      expect(budget.allowsNpiOrNcpdp).to.be.false;
    });

    it("asserts nullifier domains are separated and unique across workflows", function () {
      const requiredDomains = [
        "round_voting",
        "epoch_claim",
        "dispute",
        "portability_export",
        "migration",
        "emergency_burn_revocation"
      ];

      const domainsData = unlinkablePayload.domainSeparation;
      expect(domainsData).to.be.an("object");

      const nullifiers = new Set();

      requiredDomains.forEach((domainKey) => {
        expect(domainsData, `Domain separation configuration missing for: ${domainKey}`).to.have.property(domainKey);
        const domainItem = domainsData[domainKey];
        expect(domainItem.domain).to.equal(domainKey);
        expect(domainItem.nullifier).to.match(/^0x[0-9a-fA-F]{64}$/);

        // Add to nullifiers set to verify uniqueness
        nullifiers.add(domainItem.nullifier);
      });

      // Assert each domain has a unique nullifier (no cross-domain linkage)
      expect(nullifiers.size).to.equal(requiredDomains.length, "Each workflow domain must have a unique, non-overlapping nullifier");
    });
  });

  describe("4. Governance Fixture Gate", function () {
    it("defines the expected verifier/root lifecycle states", function () {
      const expectedStates = ["proposed", "active", "deprecated", "emergency-paused", "sunset"];
      expect(governanceFixture.states).to.deep.equal(expectedStates);
    });

    it("validates active verifier metadata", function () {
      const active = governanceFixture.activeVerifier;
      expect(active.state).to.equal("active");
      expect(active.version).to.be.a("string").that.is.not.empty;
      expect(active.activationWindow).to.have.property("startTime").that.is.a("number");
      expect(active.activationWindow).to.have.property("endTime").that.is.a("number");
      expect(active.activationWindow.startTime).to.be.lessThan(active.activationWindow.endTime);
      expect(active.governanceSigner).to.match(/^0x[0-9a-fA-F]{40}$/);
      expect(active.quorumThreshold).to.be.greaterThan(0);
      expect(active.deprecationReason).to.be.null;
      expect(active.replacementPointer).to.be.null;
    });

    it("validates deprecated verifier metadata and upgrade redirection", function () {
      const deprecated = governanceFixture.deprecatedVerifier;
      expect(deprecated.state).to.equal("deprecated");
      expect(deprecated.version).to.be.a("string").that.is.not.empty;
      expect(deprecated.deprecationReason).to.be.a("string").that.is.not.empty;
      expect(deprecated.replacementPointer).to.be.a("string").that.is.not.empty;
    });
  });

  describe("5. Metadata Leakage Table Fixture Gate", function () {
    it("encodes correct public and forbidden fields in leakage table", function () {
      expect(leakageTable.allowedPublicFields).to.include("nullifier");
      expect(leakageTable.allowedPublicFields).to.include("membershipRoot");
      expect(leakageTable.allowedPublicFields).to.not.include("exactTimestamp");
      expect(leakageTable.allowedPublicFields).to.not.include("walletAddress");

      const requiredMetadataForbidden = [
        "exactTimestamp",
        "gasPayerAddress",
        "rawRpcIpAddress",
        "rawRpcApiKey",
        "supportTicketId",
        "walletAddress"
      ];
      expect(leakageTable.forbiddenPrivacyClaimedFields).to.include.members(requiredMetadataForbidden);
      expect(leakageTable.forbiddenPrivacyClaimedFields).to.include.members(FORBIDDEN_UNLINKABLE_FIELDS);
    });

    it("asserts exact timestamps, gas payer identity, raw RPC identifiers, and wallet addresses are not in unlinkable payload", function () {
      FORBIDDEN_UNLINKABLE_FIELDS.forEach((field) => {
        expect(unlinkablePayload, `Unlinkable payload must not contain metadata/forbidden field: ${field}`).to.not.have.property(field);
      });
    });
  });
});
