/**
 * ClientWitnessAdapter.js
 * 
 * Prepares the local Circom input (witness) for the VoteNullifier circuit.
 * Enforces strict isolation: it only returns exactly the public and private 
 * inputs required by the circuit. It aggressively strips forbidden metadata 
 * like walletAddress, IP, or timestamps to prevent privacy leakage.
 */

const FORBIDDEN_FIELDS = [
    "walletAddress",
    "npi",
    "ncpdp",
    "stableCredentialHash",
    "rawCredential",
    "issuerSideRealWorldIdentifier",
    "voterNullifierCoExposure",
    "exactTimestamp",
    "gasPayer",
    "rawRpcIdentifier",
    "supportTicketId"
];

class ClientWitnessAdapter {
    static prepareWitness(rawPayload) {
        if (!rawPayload) {
            throw new Error("Missing raw payload");
        }

        for (const field of FORBIDDEN_FIELDS) {
            if (field in rawPayload) {
                throw new Error(`Forbidden metadata detected in payload: ${field}`);
            }
        }

        const requiredInputs = [
            "credentialSecret",
            "membershipPathElements",
            "membershipPathIndices",
            "roundId",
            "projectId",
            "domainSeparator",
            "membershipRoot"
        ];

        const witness = {};
        for (const req of requiredInputs) {
            if (rawPayload[req] === undefined || rawPayload[req] === null) {
                throw new Error(`Missing required witness input: ${req}`);
            }
            witness[req] = rawPayload[req];
        }

        if (!Array.isArray(witness.membershipPathElements) || !Array.isArray(witness.membershipPathIndices)) {
            throw new Error("Merkle path arrays invalid");
        }
        if (witness.membershipPathElements.length !== witness.membershipPathIndices.length) {
            throw new Error("Merkle path length mismatch");
        }
        return witness;
    }
}

module.exports = { ClientWitnessAdapter, FORBIDDEN_FIELDS };
