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
  let mockSchema;
  let mockPayload;
  let unlinkablePayload;
  let governanceFixture;
  let leakageTable;
  let projectScopedCircuit;

  before(function () {
    futureSchema = JSON.parse(
      fs.readFileSync(path.join(__dirname, "fixtures", "futurePayloadSchema.json"), "utf8")
    );
    mockSchema = JSON.parse(
      fs.readFileSync(path.join(__dirname, "fixtures", "mockPathPayloadSchema.json"), "utf8")
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
    projectScopedCircuit = JSON.parse(
      fs.readFileSync(path.join(__dirname, "fixtures", "projectScopedZKCircuitInterface.json"), "utf8")
    );
  });

  // Helper validation function enforcing strict JSON schema bounds including additionalProperties
  function validateStrictSchema(payload, schema) {
    if (!payload || typeof payload !== "object") {
      throw new Error("Schema validation failed: payload must be an object");
    }

    // 1. Check required fields
    schema.required.forEach((field) => {
      expect(payload, `Payload missing required field: ${field}`).to.have.property(field);
    });

    // 2. Enforce additionalProperties: false at top level
    if (schema.additionalProperties === false) {
      const allowedKeys = Object.keys(schema.properties);
      const extraKeys = Object.keys(payload).filter((k) => !allowedKeys.includes(k));
      if (extraKeys.length > 0) {
        throw new Error(`Schema validation failed: unexpected top-level property '${extraKeys[0]}'`);
      }
    }

    // 3. Enforce additionalProperties: false on metadataLeakageBudget
    if (schema.properties && schema.properties.metadataLeakageBudget) {
      const leakageSchema = schema.properties.metadataLeakageBudget;
      leakageSchema.required.forEach((field) => {
        expect(payload.metadataLeakageBudget, `metadataLeakageBudget missing required field: ${field}`).to.have.property(field);
      });

      if (leakageSchema.additionalProperties === false) {
        const allowedLeakageKeys = Object.keys(leakageSchema.properties);
        const extraLeakageKeys = Object.keys(payload.metadataLeakageBudget || {}).filter(
          (k) => !allowedLeakageKeys.includes(k)
        );
        if (extraLeakageKeys.length > 0) {
          throw new Error(`Schema validation failed: unexpected metadataLeakageBudget property '${extraLeakageKeys[0]}'`);
        }
      }
    }

    // 4. Validate format of nullifier and membershipRoot
    const hexPattern = /^0x[0-9a-fA-F]{64}$/;
    expect(payload.nullifier).to.match(hexPattern, "nullifier must be a 32-byte hex string");
    expect(payload.membershipRoot).to.match(hexPattern, "membershipRoot must be a 32-byte hex string");

    // 5. Validate types
    expect(payload.publicSignals).to.be.an("array");
    expect(payload.metadataLeakageBudget).to.be.an("object");
  }

  describe("1. Fixture Schema Validation", function () {
    it("validates mock-path payload against mock schema structure", function () {
      validateStrictSchema(mockPayload, mockSchema);
    });

    it("validates unlinkable-path payload against future unlinkable schema structure", function () {
      validateStrictSchema(unlinkablePayload, futureSchema);
    });

    it("rejects forbidden real-world identity fields in future unlinkable schema validator", function () {
      const invalidPayload = { ...unlinkablePayload, npi: "1982736450" };
      expect(() => validateStrictSchema(invalidPayload, futureSchema)).to.throw(
        /unexpected top-level property 'npi'/
      );
    });

    it("rejects payloads containing unapproved extra top-level properties via strict schema validator", function () {
      const invalidPayload = { ...unlinkablePayload, unexpectedExtraField: "leaked_data" };
      expect(() => validateStrictSchema(invalidPayload, futureSchema)).to.throw(
        /unexpected top-level property 'unexpectedExtraField'/
      );
    });

    it("rejects metadataLeakageBudget objects containing unapproved extra properties via strict schema validator", function () {
      const invalidPayload = {
        ...unlinkablePayload,
        metadataLeakageBudget: { ...unlinkablePayload.metadataLeakageBudget, unexpectedLeakageKey: true }
      };
      expect(() => validateStrictSchema(invalidPayload, futureSchema)).to.throw(
        /unexpected metadataLeakageBudget property 'unexpectedLeakageKey'/
      );
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

  describe("6. Project-Scoped Circuit and Verifier Interface Gate", function () {
    it("labels the project-scoped circuit as unlinkable spec-only work", function () {
      expect(projectScopedCircuit.status).to.equal("spec-only");
      expect(projectScopedCircuit.privacyTarget).to.equal("unlinkable");
      expect(projectScopedCircuit.scopeKind).to.equal("project-scoped-round-vote");
      expect(projectScopedCircuit.proofSystem).to.equal("backend-undecided");
    });

    it("pins canonical public signal order for verifier version v1", function () {
      expect(projectScopedCircuit.publicSignalOrder).to.deep.equal([
        "domainSeparator",
        "chainId",
        "verifyingContract",
        "roundId",
        "projectId",
        "projectRegistryRoot",
        "membershipRoot",
        "nullifier",
        "policyVersion",
        "relayerPolicyHash",
        "timestampBucket"
      ]);

      projectScopedCircuit.publicSignalOrder.forEach((field) => {
        expect(projectScopedCircuit.publicInputs, `public input metadata missing: ${field}`).to.have.property(field);
        expect(projectScopedCircuit.publicInputs[field].visibility).to.equal("public");
      });
    });

    it("keeps forbidden identity, support, RPC, and witness fields out of public signals", function () {
      const publicSignals = new Set(projectScopedCircuit.publicSignalOrder);

      projectScopedCircuit.forbiddenPublicInputs.forEach((field) => {
        expect(publicSignals, `forbidden public input present: ${field}`).to.not.include(field);
      });

      projectScopedCircuit.privateWitness.forEach((field) => {
        expect(publicSignals, `private witness leaked as public input: ${field}`).to.not.include(field);
      });
    });

    it("derives nullifiers from round and project scope plus policy domain", function () {
      expect(projectScopedCircuit.nullifierDerivation).to.deep.equal({
        hash: "Poseidon",
        inputs: [
          "credentialSecret",
          "roundId",
          "projectId",
          "domainSeparator"
        ],
        output: "nullifier"
      });
    });

    it("pins the exact Circom public/private signal boundary", function () {
      expect(projectScopedCircuit.minimalCircomInterface).to.include({
        language: "Circom 2.1.0 spec packet",
        template: "ProjectScopedVoteNullifier",
        treeDepthParameter: "MEMBERSHIP_TREE_DEPTH"
      });
      expect(projectScopedCircuit.minimalCircomInterface.publicSignalOrder).to.deep.equal([
        "roundId",
        "projectId",
        "domainSeparator",
        "membershipRoot",
        "nullifier"
      ]);
      expect(projectScopedCircuit.minimalCircomInterface.privateInputs).to.deep.equal([
        "credentialSecret",
        "membershipPathElements",
        "membershipPathIndices"
      ]);
      expect(projectScopedCircuit.minimalCircomInterface.publicInputs).to.deep.equal([
        "roundId",
        "projectId",
        "domainSeparator",
        "membershipRoot",
        "nullifier"
      ]);
      expect(projectScopedCircuit.minimalCircomInterface.publicOutputs).to.deep.equal([]);
      expect(projectScopedCircuit.minimalCircomInterface.constraints).to.include(
        "nullifier === Poseidon(credentialSecret, roundId, projectId, domainSeparator)"
      );
    });

    it("requires a stateless verifier ABI with fixed-width public signals", function () {
      expect(projectScopedCircuit.verifierInterface).to.include({
        name: "IProjectScopedZKVerifier",
        statefulness: "stateless",
        returnValue: "proof-validity-only"
      });
      expect(projectScopedCircuit.verifierInterface.solidity).to.equal(
        "function verifyProof(bytes calldata proof, uint256[11] calldata publicSignals) external view returns (bool)"
      );
    });

    it("pins the host-facing verifyVoteProof adapter parameters", function () {
      expect(projectScopedCircuit.hostVerifierFacade).to.include({
        name: "verifyVoteProof",
        callerMaySupplyDomainSeparator: false
      });
      expect(projectScopedCircuit.hostVerifierFacade.solidity).to.equal(
        "function verifyVoteProof(bytes calldata proof, uint256 root, uint256 nullifier, uint256 roundId, uint256 projectId) external view returns (bool)"
      );
      expect(projectScopedCircuit.hostVerifierFacade.parameterMapping).to.deep.equal({
        proof: "opaque proof bytes",
        root: "membershipRoot",
        nullifier: "nullifier",
        roundId: "roundId",
        projectId: "projectId"
      });
    });

    it("requires project-scoped host replay guards and frozen project registries", function () {
      expect(projectScopedCircuit.hostContractGuard).to.include({
        replayMapping: "used[roundId][projectId][nullifier]",
        nullifierZeroRejected: true,
        projectRegistryFrozenBeforeActivation: true,
        verifierMayMutateState: false,
        eventOmitsSender: true
      });
    });
  });
});
