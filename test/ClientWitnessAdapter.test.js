const { expect } = require("chai");
const { ClientWitnessAdapter } = require("../tools/zk/ClientWitnessAdapter");

describe("ClientWitnessAdapter", function () {
    const validPayload = {
        credentialSecret: "123",
        membershipPathElements: ["1", "2"],
        membershipPathIndices: [0, 1],
        roundId: "1",
        projectId: "5",
        domainSeparator: "999",
        membershipRoot: "abc"
    };

    it("successfully prepares a clean witness", function () {
        const witness = ClientWitnessAdapter.prepareWitness(validPayload);
        expect(witness.credentialSecret).to.equal("123");
        expect(witness.membershipPathElements).to.deep.equal(["1", "2"]);
    });

    it("throws if forbidden metadata is present", function () {
        const maliciousPayload = { ...validPayload, walletAddress: "0xABC" };
        expect(() => ClientWitnessAdapter.prepareWitness(maliciousPayload)).to.throw("Forbidden metadata detected in payload: walletAddress");
    });

    it("throws if a required field is missing", function () {
        const incomplete = { ...validPayload };
        delete incomplete.membershipRoot;
        expect(() => ClientWitnessAdapter.prepareWitness(incomplete)).to.throw("Missing required witness input: membershipRoot");
    });
});
