pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";

template VoteNullifier(nLevels) {
    // Private witness.
    signal input credentialSecret;
    signal input membershipPathElements[nLevels];
    signal input membershipPathIndices[nLevels];

    // Public signals.
    signal input roundId;
    signal input projectId;
    signal input domainSeparator;
    signal input membershipRoot;
    signal input nullifier;

    component leafHash = Poseidon(1);
    leafHash.inputs[0] <== credentialSecret;

    signal computedRoot[nLevels + 1];
    computedRoot[0] <== leafHash.out;

    component pathHash[nLevels];
    signal left[nLevels];
    signal right[nLevels];

    for (var i = 0; i < nLevels; i++) {
        membershipPathIndices[i] * (membershipPathIndices[i] - 1) === 0;

        left[i] <== computedRoot[i] + membershipPathIndices[i] * (membershipPathElements[i] - computedRoot[i]);
        right[i] <== membershipPathElements[i] + membershipPathIndices[i] * (computedRoot[i] - membershipPathElements[i]);

        pathHash[i] = Poseidon(2);
        pathHash[i].inputs[0] <== left[i];
        pathHash[i].inputs[1] <== right[i];
        computedRoot[i + 1] <== pathHash[i].out;
    }

    membershipRoot === computedRoot[nLevels];

    component nullifierHash = Poseidon(4);
    nullifierHash.inputs[0] <== credentialSecret;
    nullifierHash.inputs[1] <== roundId;
    nullifierHash.inputs[2] <== projectId;
    nullifierHash.inputs[3] <== domainSeparator;
    nullifier === nullifierHash.out;
}

template ProjectScopedVoteNullifier(MEMBERSHIP_TREE_DEPTH) {
    signal input credentialSecret;
    signal input membershipPathElements[MEMBERSHIP_TREE_DEPTH];
    signal input membershipPathIndices[MEMBERSHIP_TREE_DEPTH];

    signal input roundId;
    signal input projectId;
    signal input domainSeparator;
    signal input membershipRoot;
    signal input nullifier;

    component voteNullifier = VoteNullifier(MEMBERSHIP_TREE_DEPTH);
    voteNullifier.credentialSecret <== credentialSecret;

    for (var i = 0; i < MEMBERSHIP_TREE_DEPTH; i++) {
        voteNullifier.membershipPathElements[i] <== membershipPathElements[i];
        voteNullifier.membershipPathIndices[i] <== membershipPathIndices[i];
    }

    voteNullifier.roundId <== roundId;
    voteNullifier.projectId <== projectId;
    voteNullifier.domainSeparator <== domainSeparator;
    voteNullifier.membershipRoot <== membershipRoot;
    voteNullifier.nullifier <== nullifier;
}

component main { public [roundId, projectId, domainSeparator, membershipRoot, nullifier] } =
    ProjectScopedVoteNullifier(20);
