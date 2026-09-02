/**
 * ClientWitnessAdapter.js
 * 
 * Prepares the local Circom input (witness) for the VoteNullifier circuit.
 * Enforces strict isolation: it returns exactly the public and private inputs
 * required by the current minimal circuit interface and rejects side-channel
 * metadata before the payload reaches proof generation.
 */

const BN254_SCALAR_FIELD =
    BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

const REQUIRED_WITNESS_INPUTS = [
    "credentialSecret",
    "membershipPathElements",
    "membershipPathIndices",
    "roundId",
    "projectId",
    "domainSeparator",
    "membershipRoot",
    "nullifier"
];

const FORBIDDEN_FIELDS = [
    "walletAddress",
    "wallet_address",
    "npi",
    "ncpdp",
    "stableCredentialHash",
    "rawCredential",
    "witnessMaterial",
    "issuerSideRealWorldIdentifier",
    "voterNullifierCoExposure",
    "exactTimestamp",
    "gasPayer",
    "gasPayerAddress",
    "rawRpcIdentifier",
    "rawRpcIpAddress",
    "rawRpcApiKey",
    "rawRpcUrl",
    "rpcUrl",
    "rpcEndpoint",
    "ipAddress",
    "userAgent",
    "browserFingerprint",
    "sessionId",
    "authorization",
    "bearer",
    "supportTicketId"
];

const FORBIDDEN_FIELD_SET = new Set(FORBIDDEN_FIELDS.map((field) => field.toLowerCase()));
const ALLOWED_ROOT_FIELDS = new Set(REQUIRED_WITNESS_INPUTS);
const MAX_MERKLE_DEPTH = 64;

class ClientWitnessAdapter {
    static prepareWitness(rawPayload) {
        if (!rawPayload || typeof rawPayload !== "object" || Array.isArray(rawPayload)) {
            throw new Error("Missing raw payload");
        }

        const forbiddenPath = findForbiddenFieldPath(rawPayload);
        if (forbiddenPath) {
            throw new Error(`Forbidden metadata detected in payload: ${forbiddenPath}`);
        }

        const witness = {};
        for (const req of REQUIRED_WITNESS_INPUTS) {
            if (rawPayload[req] === undefined || rawPayload[req] === null) {
                throw new Error(`Missing required witness input: ${req}`);
            }
        }

        if (!Array.isArray(rawPayload.membershipPathElements) || !Array.isArray(rawPayload.membershipPathIndices)) {
            throw new Error("Merkle path arrays invalid");
        }
        if (rawPayload.membershipPathElements.length !== rawPayload.membershipPathIndices.length) {
            throw new Error("Merkle path length mismatch");
        }
        if (rawPayload.membershipPathElements.length === 0 || rawPayload.membershipPathElements.length > MAX_MERKLE_DEPTH) {
            throw new Error("Merkle path depth out of bounds");
        }

        witness.credentialSecret = normalizeFieldElement(rawPayload.credentialSecret, "credentialSecret");
        witness.membershipPathElements = rawPayload.membershipPathElements.map((element, index) =>
            normalizeFieldElement(element, `membershipPathElements[${index}]`)
        );
        witness.membershipPathIndices = rawPayload.membershipPathIndices.map((bit, index) =>
            normalizeMerklePathBit(bit, `membershipPathIndices[${index}]`)
        );
        witness.roundId = normalizeFieldElement(rawPayload.roundId, "roundId");
        witness.projectId = normalizeFieldElement(rawPayload.projectId, "projectId");
        witness.domainSeparator = normalizeFieldElement(rawPayload.domainSeparator, "domainSeparator");
        witness.membershipRoot = normalizeFieldElement(rawPayload.membershipRoot, "membershipRoot");
        witness.nullifier = normalizeFieldElement(rawPayload.nullifier, "nullifier");

        if (witness.credentialSecret === "0") {
            throw new Error("credentialSecret must be non-zero");
        }
        if (witness.nullifier === "0") {
            throw new Error("nullifier must be non-zero");
        }

        return witness;
    }
}

function findForbiddenFieldPath(value, path = "$", seen = new Set()) {
    if (!value || typeof value !== "object") {
        return null;
    }
    if (seen.has(value)) {
        return null;
    }
    seen.add(value);

    if (Array.isArray(value)) {
        for (let index = 0; index < value.length; index++) {
            const nestedPath = findForbiddenFieldPath(value[index], `${path}[${index}]`, seen);
            if (nestedPath) return nestedPath;
        }
        return null;
    }

    for (const [key, nested] of Object.entries(value)) {
        const isAllowedRootWitnessKey = path === "$" && ALLOWED_ROOT_FIELDS.has(key);
        if (!isAllowedRootWitnessKey && FORBIDDEN_FIELD_SET.has(key.toLowerCase())) {
            return path === "$" ? key : `${path}.${key}`;
        }
        const nestedPath = findForbiddenFieldPath(nested, path === "$" ? key : `${path}.${key}`, seen);
        if (nestedPath) return nestedPath;
    }
    return null;
}

function normalizeFieldElement(value, fieldName) {
    let parsed;
    if (typeof value === "bigint") {
        parsed = value;
    } else if (typeof value === "number") {
        if (!Number.isSafeInteger(value)) {
            throw new Error(`${fieldName} must be a safe integer field element`);
        }
        parsed = BigInt(value);
    } else if (typeof value === "string") {
        const trimmed = value.trim();
        if (!/^(0x[0-9a-fA-F]+|[0-9]+)$/.test(trimmed)) {
            throw new Error(`${fieldName} must be a field element`);
        }
        parsed = BigInt(trimmed);
    } else {
        throw new Error(`${fieldName} must be a field element`);
    }

    if (parsed < 0n || parsed >= BN254_SCALAR_FIELD) {
        throw new Error(`${fieldName} out of BN254 scalar field range`);
    }
    return parsed.toString();
}

function normalizeMerklePathBit(value, fieldName) {
    const normalized = normalizeFieldElement(value, fieldName);
    if (normalized !== "0" && normalized !== "1") {
        throw new Error(`${fieldName} must be 0 or 1`);
    }
    return Number(normalized);
}

module.exports = {
    ClientWitnessAdapter,
    FORBIDDEN_FIELDS,
    REQUIRED_WITNESS_INPUTS
};
