const { expect } = require("chai");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const CIRCUIT_PATH = path.join(__dirname, "..", "circuits", "vote_nullifier.circom");
const INTERFACE_FIXTURE_PATH = path.join(__dirname, "fixtures", "projectScopedZKCircuitInterface.json");
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const EXPECTED_PUBLIC_SIGNAL_ORDER = [
  "roundId",
  "projectId",
  "domainSeparator",
  "membershipRoot",
  "nullifier"
];

const EXPECTED_PRIVATE_INPUTS = [
  "credentialSecret",
  "membershipPathElements",
  "membershipPathIndices"
];

function normalize(source) {
  return source.replace(/\s+/g, " ");
}

function parseMainPublicSignals(source) {
  const match = source.match(/component\s+main\s*\{\s*public\s*\[([^\]]+)\]\s*\}\s*=/m);
  expect(match, "main component must declare explicit public signals").to.not.equal(null);
  return match[1].split(",").map((signal) => signal.trim()).filter(Boolean);
}

function toField(value) {
  const valueString = value.toString();
  if (valueString.startsWith("0x")) {
    return BigInt(valueString) % FIELD_PRIME;
  }
  return BigInt(valueString) % FIELD_PRIME;
}

function poseidonConstraintModel(inputs) {
  const hash = crypto.createHash("sha256");
  hash.update("poseidon-constraint-model:v1");
  hash.update(Buffer.from([inputs.length]));
  inputs.forEach((input) => {
    const normalized = toField(input).toString(16).padStart(64, "0");
    hash.update(Buffer.from(normalized, "hex"));
  });

  return BigInt(`0x${hash.digest("hex")}`) % FIELD_PRIME;
}

function buildMerkleRoot(leaf, pathElements, pathIndices) {
  return pathElements.reduce((computedRoot, sibling, index) => {
    const direction = Number(pathIndices[index]);
    if (direction !== 0 && direction !== 1) {
      throw new Error(`membershipPathIndices[${index}] must be 0 or 1`);
    }

    const pair = direction === 0
      ? [computedRoot, sibling]
      : [sibling, computedRoot];

    return poseidonConstraintModel(pair);
  }, leaf);
}

function buildValidWitness() {
  const credentialSecret = 123456789n;
  const roundId = 20260722n;
  const projectId = 17n;
  const domainSeparator = 8675309n;
  const membershipPathElements = [111n, 222n, 333n, 444n];
  const membershipPathIndices = [0, 1, 0, 1];
  const leaf = poseidonConstraintModel([credentialSecret]);

  return {
    credentialSecret,
    membershipPathElements,
    membershipPathIndices,
    roundId,
    projectId,
    domainSeparator,
    membershipRoot: buildMerkleRoot(leaf, membershipPathElements, membershipPathIndices),
    nullifier: poseidonConstraintModel([credentialSecret, roundId, projectId, domainSeparator])
  };
}

function evaluateVoteNullifierWitness(witness) {
  const leaf = poseidonConstraintModel([witness.credentialSecret]);
  const computedRoot = buildMerkleRoot(
    leaf,
    witness.membershipPathElements,
    witness.membershipPathIndices
  );
  const computedNullifier = poseidonConstraintModel([
    witness.credentialSecret,
    witness.roundId,
    witness.projectId,
    witness.domainSeparator
  ]);

  return {
    computedRoot,
    computedNullifier,
    rootMatches: computedRoot === witness.membershipRoot,
    nullifierMatches: computedNullifier === witness.nullifier,
    satisfiesCircuit: computedRoot === witness.membershipRoot && computedNullifier === witness.nullifier
  };
}

describe("VoteNullifier Circom circuit", function () {
  let circuitSource;
  let normalizedSource;
  let interfaceFixture;

  before(function () {
    circuitSource = fs.readFileSync(CIRCUIT_PATH, "utf8");
    normalizedSource = normalize(circuitSource);
    interfaceFixture = JSON.parse(fs.readFileSync(INTERFACE_FIXTURE_PATH, "utf8"));
  });

  describe("structural circuit gate", function () {
    it("declares the expected Circom version, Poseidon include, and template facade", function () {
      expect(circuitSource).to.include("pragma circom 2.1.0;");
      expect(circuitSource).to.include('include "circomlib/circuits/poseidon.circom";');
      expect(circuitSource.toLowerCase()).to.not.include("sha256");
      expect(circuitSource).to.include("template VoteNullifier(nLevels)");
      expect(circuitSource).to.include("template ProjectScopedVoteNullifier(MEMBERSHIP_TREE_DEPTH)");
    });

    it("pins the minimal public signal order from Spec Gate A", function () {
      expect(parseMainPublicSignals(circuitSource)).to.deep.equal(EXPECTED_PUBLIC_SIGNAL_ORDER);
      expect(interfaceFixture.minimalCircomInterface.publicSignalOrder).to.deep.equal(EXPECTED_PUBLIC_SIGNAL_ORDER);
    });

    it("keeps credential secret and Merkle path material out of the public boundary", function () {
      const publicSignals = new Set(parseMainPublicSignals(circuitSource));
      EXPECTED_PRIVATE_INPUTS.forEach((input) => {
        expect(publicSignals, `${input} must remain private`).to.not.include(input);
      });
      expect(interfaceFixture.minimalCircomInterface.privateInputs).to.deep.equal(EXPECTED_PRIVATE_INPUTS);
    });

    it("wires the leaf, Merkle path, and nullifier Poseidon constraints", function () {
      expect(normalizedSource).to.include("component leafHash = Poseidon(1);");
      expect(normalizedSource).to.include("pathHash[i] = Poseidon(2);");
      expect(normalizedSource).to.include("component nullifierHash = Poseidon(4);");
      expect(normalizedSource).to.include("nullifierHash.inputs[0] <== credentialSecret;");
      expect(normalizedSource).to.include("nullifierHash.inputs[1] <== roundId;");
      expect(normalizedSource).to.include("nullifierHash.inputs[2] <== projectId;");
      expect(normalizedSource).to.include("nullifierHash.inputs[3] <== domainSeparator;");
      expect(normalizedSource).to.include("nullifier === nullifierHash.out;");
      expect(interfaceFixture.minimalCircomInterface.constraints).to.include(
        "nullifier === Poseidon(credentialSecret, roundId, projectId, domainSeparator)"
      );
    });

    it("constrains Merkle path direction bits and root equality", function () {
      expect(normalizedSource).to.include("membershipPathIndices[i] * (membershipPathIndices[i] - 1) === 0;");
      expect(normalizedSource).to.include("left[i] <== computedRoot[i] + membershipPathIndices[i] * (membershipPathElements[i] - computedRoot[i]);");
      expect(normalizedSource).to.include("right[i] <== membershipPathElements[i] + membershipPathIndices[i] * (computedRoot[i] - membershipPathElements[i]);");
      expect(normalizedSource).to.include("membershipRoot === computedRoot[nLevels];");
      expect(interfaceFixture.minimalCircomInterface.constraints).to.include(
        "membershipRoot === recomputeRoot(Poseidon(credentialSecret), membershipPathElements, membershipPathIndices)"
      );
    });

    it("does not expose the credential secret or direct leaf as the public membership root", function () {
      expect(normalizedSource).to.include("computedRoot[0] <== leafHash.out;");
      expect(normalizedSource).to.include("membershipRoot === computedRoot[nLevels];");

      [
        "membershipRoot === credentialSecret;",
        "membershipRoot <== credentialSecret;",
        "membershipRoot === leafHash.out;",
        "membershipRoot <== leafHash.out;"
      ].forEach((forbiddenConstraint) => {
        expect(normalizedSource).to.not.include(forbiddenConstraint);
      });
    });
  });

  describe("constraint model witness gate", function () {
    it("accepts a matching secret, project-scoped nullifier, and Merkle membership root", function () {
      const witness = buildValidWitness();
      const result = evaluateVoteNullifierWitness(witness);

      expect(result.satisfiesCircuit).to.equal(true);
      expect(result.computedRoot).to.equal(witness.membershipRoot);
      expect(result.computedNullifier).to.equal(witness.nullifier);
    });

    it("rejects a nullifier produced for a different project or round", function () {
      const witness = buildValidWitness();

      const tamperedProject = {
        ...witness,
        projectId: witness.projectId + 1n
      };
      const tamperedRound = {
        ...witness,
        roundId: witness.roundId + 1n
      };

      expect(evaluateVoteNullifierWitness(tamperedProject).satisfiesCircuit).to.equal(false);
      expect(evaluateVoteNullifierWitness(tamperedProject).rootMatches).to.equal(true);
      expect(evaluateVoteNullifierWitness(tamperedProject).nullifierMatches).to.equal(false);

      expect(evaluateVoteNullifierWitness(tamperedRound).satisfiesCircuit).to.equal(false);
      expect(evaluateVoteNullifierWitness(tamperedRound).rootMatches).to.equal(true);
      expect(evaluateVoteNullifierWitness(tamperedRound).nullifierMatches).to.equal(false);
    });

    it("rejects an invalid Merkle path or unregistered secret", function () {
      const witness = buildValidWitness();
      const wrongPath = {
        ...witness,
        membershipPathElements: [
          witness.membershipPathElements[0] + 99n,
          ...witness.membershipPathElements.slice(1)
        ]
      };
      const wrongSecret = {
        ...witness,
        credentialSecret: witness.credentialSecret + 1n,
        nullifier: poseidonConstraintModel([
          witness.credentialSecret + 1n,
          witness.roundId,
          witness.projectId,
          witness.domainSeparator
        ])
      };

      expect(evaluateVoteNullifierWitness(wrongPath).satisfiesCircuit).to.equal(false);
      expect(evaluateVoteNullifierWitness(wrongPath).rootMatches).to.equal(false);
      expect(evaluateVoteNullifierWitness(wrongPath).nullifierMatches).to.equal(true);

      expect(evaluateVoteNullifierWitness(wrongSecret).satisfiesCircuit).to.equal(false);
      expect(evaluateVoteNullifierWitness(wrongSecret).rootMatches).to.equal(false);
      expect(evaluateVoteNullifierWitness(wrongSecret).nullifierMatches).to.equal(true);
    });

    it("rejects non-bit Merkle path indices", function () {
      const witness = buildValidWitness();
      const invalidDirection = {
        ...witness,
        membershipPathIndices: [0, 1, 2, 1]
      };

      expect(() => evaluateVoteNullifierWitness(invalidDirection)).to.throw(
        "membershipPathIndices[2] must be 0 or 1"
      );
    });
  });
});
