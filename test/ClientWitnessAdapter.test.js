const { expect } = require("chai");
const fs = require("fs");
const path = require("path");
const { ClientWitnessAdapter, FORBIDDEN_FIELDS, REQUIRED_WITNESS_INPUTS } = require("../tools/zk/ClientWitnessAdapter");

describe("ClientWitnessAdapter", function () {
    const validPayload = {
        credentialSecret: "123",
        membershipPathElements: ["1", "2"],
        membershipPathIndices: [0, 1],
        roundId: "1",
        projectId: "5",
        domainSeparator: "999",
        membershipRoot: "777",
        nullifier: "888"
    };

    it("successfully prepares a clean witness", function () {
        const witness = ClientWitnessAdapter.prepareWitness(validPayload);
        expect(witness.credentialSecret).to.equal("123");
        expect(witness.membershipPathElements).to.deep.equal(["1", "2"]);
        expect(witness.membershipPathIndices).to.deep.equal([0, 1]);
        expect(witness.nullifier).to.equal("888");
        expect(REQUIRED_WITNESS_INPUTS).to.include("nullifier");
    });

    it("tracks forbidden side-channel fields from the metadata leakage fixture", function () {
        const leakageTable = JSON.parse(
            fs.readFileSync(path.join(__dirname, "fixtures", "metadataLeakageTable.json"), "utf8")
        );
        const adapterForbidden = new Set(FORBIDDEN_FIELDS);
        const fieldsAllowedOnlyAsRootPrivateWitness = new Set(["credentialSecret"]);

        for (const field of leakageTable.forbiddenPrivacyClaimedFields) {
            if (fieldsAllowedOnlyAsRootPrivateWitness.has(field)) continue;
            expect(adapterForbidden, `missing adapter forbidden field: ${field}`).to.include(field);
        }
    });

    it("throws if forbidden metadata is present at the top level", function () {
        const maliciousPayload = { ...validPayload, walletAddress: "0xABC" };
        expect(() => ClientWitnessAdapter.prepareWitness(maliciousPayload)).to.throw("Forbidden metadata detected in payload: walletAddress");
    });

    it("throws if forbidden metadata is nested inside ignored fields", function () {
        const maliciousPayload = {
            ...validPayload,
            diagnostics: {
                request: {
                    rawRpcIpAddress: "203.0.113.10"
                }
            }
        };
        expect(() => ClientWitnessAdapter.prepareWitness(maliciousPayload)).to.throw(
            "Forbidden metadata detected in payload: diagnostics.request.rawRpcIpAddress"
        );
    });

    it("throws if a required field is missing", function () {
        const incomplete = { ...validPayload };
        delete incomplete.nullifier;
        expect(() => ClientWitnessAdapter.prepareWitness(incomplete)).to.throw("Missing required witness input: nullifier");
    });

    it("throws if Merkle path indices are not bits", function () {
        const invalid = { ...validPayload, membershipPathIndices: [0, 2] };
        expect(() => ClientWitnessAdapter.prepareWitness(invalid)).to.throw("membershipPathIndices[1] must be 0 or 1");
    });

    it("throws if field elements are malformed or zero where disallowed", function () {
        expect(() => ClientWitnessAdapter.prepareWitness({ ...validPayload, membershipRoot: "not-a-field" })).to.throw(
            "membershipRoot must be a field element"
        );
        expect(() => ClientWitnessAdapter.prepareWitness({ ...validPayload, nullifier: "0" })).to.throw(
            "nullifier must be non-zero"
        );
    });

    it("strips non-forbidden extras and returns only circuit inputs", function () {
        const witness = ClientWitnessAdapter.prepareWitness({
            ...validPayload,
            harmlessLocalNote: "not copied",
            extra: { localOnly: true }
        });
        expect(Object.keys(witness).sort()).to.deep.equal([
            "credentialSecret",
            "domainSeparator",
            "membershipPathElements",
            "membershipPathIndices",
            "membershipRoot",
            "nullifier",
            "projectId",
            "roundId"
        ].sort());
    });
});
