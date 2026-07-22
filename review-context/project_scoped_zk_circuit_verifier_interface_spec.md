# Project-Scoped ZK Circuit and Verifier Interface Specification

Snapshot discipline for this packet:

- Branch: `feature/db-proxy`
- HEAD Commit at refinement start: `252395cb6720c84de04a547b3a2742fcfa522da8`
- Tracked Changes at refinement start: dirty outside this packet (`AGENT_REVIEW_ORCHESTRATION.md`, `ONBOARDING.md`, `review-context/reflection_local_backend_router_receipts.md`, and `test/ZKNullifierFixtureGate.test.js` already modified).
- Ambient Untracked Artifacts: review and handoff dossiers are present in `review-context/` and repository root; this packet only defines the project-scoped ZK interface spec and fixture gate.
- Status: specification and fixture gate only. This is not a production circuit, verifier deployment, or on-chain settlement change.

## 1. Purpose

The current mock ZK path proves a semantic registration milestone, but it is still wallet-linkable. The future unlinkable path needs a concrete circuit statement and a verifier ABI that downstream contract work can implement without reintroducing stable wallet, credential, or metadata linkage.

This specification defines the first production-target shape for project-scoped participatory-budgeting votes:

- one nullifier per `(roundId, projectId, credentialSecret, domainSeparator)`;
- no wallet address, NPI/NCPDP, stable credential hash, raw credential, or witness material in public inputs, logs, support payloads, or verifier calldata;
- contract replay protection keyed by `used[roundId][projectId][nullifier]`;
- immutable project registry commitment for the active round;
- stateless verifier calls whose truth claim is limited to proof validity for the supplied public inputs.

## 2. Circuit Statement

For a voter with private credential secret `s`, the circuit proves:

1. `participantCommitment` is a leaf in the active `membershipRoot`.
2. `participantCommitment` is derived from `s` and issuer-bound private credential material.
3. `nullifier == Poseidon(s, roundId, projectId, domainSeparator)`.
4. `projectId` is included in the frozen `projectRegistryRoot` for `roundId`.
5. `domainSeparator`, `chainId`, `verifyingContract`, `policyVersion`, and `relayerPolicyHash` match the public policy selected by governance for the round.
6. No forbidden identity or witness fields are exposed as public inputs.

The circuit does not prove that the relayer hid network metadata, that a user used a fresh client session, or that timing cannot correlate multiple votes. Those are operational privacy requirements outside the arithmetic statement.

## 3. Public Signals

The canonical public signal order for verifier version `fiduciary-zk-verifier-v1` is:

| Index | Name | Purpose |
| --- | --- | --- |
| 0 | `domainSeparator` | Deployment and workflow domain separation. |
| 1 | `chainId` | Prevents proof replay across chains. |
| 2 | `verifyingContract` | Prevents proof replay across verifier/host contracts. |
| 3 | `roundId` | Participatory-budgeting round scope. |
| 4 | `projectId` | Project-level nullifier scope. |
| 5 | `projectRegistryRoot` | Frozen commitment to the active project set and ordering. |
| 6 | `membershipRoot` | Active eligible-participant membership root. |
| 7 | `nullifier` | Public double-vote guard for this `(roundId, projectId)`. |
| 8 | `policyVersion` | Governance-selected privacy and eligibility policy version. |
| 9 | `relayerPolicyHash` | Public commitment to the relayer/batching policy. |
| 10 | `timestampBucket` | Coarse time bucket only; exact timestamps remain forbidden. |

Forbidden public inputs include `walletAddress`, `gasPayer`, `gasPayerAddress`, `rawRpcIdentifier`, `rawRpcIpAddress`, `rawRpcApiKey`, `supportTicketId`, `npi`, `ncpdp`, `stableCredentialHash`, `rawCredential`, `credentialSecret`, `witnessMaterial`, `issuerSideRealWorldIdentifier`, and `voterNullifierCoExposure`.

## 4. Private Witness

The private witness contains:

- `credentialSecret`;
- issuer credential opening material;
- membership Merkle path and index bits;
- project registry path and index bits, if the project registry root is circuit-checked rather than contract-checked;
- any random blinding required by the credential commitment scheme.

The witness must never be persisted by the proxy, printed in browser diagnostics, sent to support logs, included in JSON relay batches, or emitted by contracts.

## 5. Exact Circom Signal Interface

This packet pins the minimal Circom-facing signal contract for verifier version `fiduciary-zk-verifier-v1`. The notation maps the user-facing formula:

```text
eta = Poseidon(s, R, P, Delta)
```

to the following signal names:

| Formula Term | Circom Signal | Visibility |
| --- | --- | --- |
| `s` | `credentialSecret` | private |
| `R` | `roundId` | public |
| `P` | `projectId` | public |
| `Delta` | `domainSeparator` | public |
| `M` | `membershipRoot` | public |
| `eta` | `nullifier` | public constrained input |

Canonical Circom main declaration:

```circom
pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";

template ProjectScopedVoteNullifier(MEMBERSHIP_TREE_DEPTH) {
    // Private witness.
    signal input credentialSecret;
    signal input membershipPathElements[MEMBERSHIP_TREE_DEPTH];
    signal input membershipPathIndices[MEMBERSHIP_TREE_DEPTH];

    // Public signals.
    signal input roundId;
    signal input projectId;
    signal input domainSeparator;
    signal input membershipRoot;
    signal input nullifier;

    component nullifierHash = Poseidon(4);
    nullifierHash.inputs[0] <== credentialSecret;
    nullifierHash.inputs[1] <== roundId;
    nullifierHash.inputs[2] <== projectId;
    nullifierHash.inputs[3] <== domainSeparator;
    nullifier === nullifierHash.out;

    // Membership path constraint:
    // recomputeRoot(Poseidon(credentialSecret), membershipPathElements, membershipPathIndices)
    // must equal membershipRoot. The exact leaf commitment formula remains a
    // backend selection item and must be frozen before production proving keys.
}

component main { public [roundId, projectId, domainSeparator, membershipRoot, nullifier] } =
    ProjectScopedVoteNullifier(20);
```

The public signal order for the minimal circuit facade is:

```text
[roundId, projectId, domainSeparator, membershipRoot, nullifier]
```

The expanded host-verifier signal vector in Section 3 preserves replay and policy fields required by this repository. A production circuit may either expose those fields directly as public signals or bind them through the host adapter, but it must not silently reinterpret the five-signal facade above.

## 6. Verifier ABI

The canonical verifier interface for this packet is intentionally stateless:

```solidity
interface IProjectScopedZKVerifier {
    function verifyProof(
        bytes calldata proof,
        uint256[11] calldata publicSignals
    ) external view returns (bool);
}
```

The host contract constructs `publicSignals` in the order defined above and calls the verifier with `staticcall` or an equivalent `view` interface. The verifier must not read host contract storage, consume nullifiers, mutate round state, or decide governance policy. It only returns whether the proof verifies for the exact public signal vector.

The host-facing adapter requested for the project-scoped vote path is:

```solidity
function verifyVoteProof(
    bytes calldata proof,
    uint256 root,
    uint256 nullifier,
    uint256 roundId,
    uint256 projectId
) external view returns (bool);
```

Adapter parameter mapping:

| Adapter Parameter | Circuit Signal |
| --- | --- |
| `proof` | opaque proof bytes |
| `root` | `membershipRoot` |
| `nullifier` | `nullifier` |
| `roundId` | `roundId` |
| `projectId` | `projectId` |

`domainSeparator` is bound from contract state or immutable deployment metadata for the active verifier version. It must not be supplied by an untrusted caller without comparison against the governance-selected domain.

## 7. Host Contract Integration Contract

The future `castVoteWithZK` path must perform these checks before accepting a vote:

1. Round exists and is active.
2. Project registry is frozen for the round; projects cannot be added, deleted, or reordered after activation.
3. `projectId` is in range and corresponds to the frozen `projectRegistryRoot`.
4. `membershipRoot`, `policyVersion`, `verifierVersion`, and `relayerPolicyHash` are active for the round.
5. `nullifier != bytes32(0)`.
6. `used[roundId][projectId][nullifier] == false`.
7. Verifier returns true for the canonical public signal vector.
8. Host contract writes `used[roundId][projectId][nullifier] = true`.
9. Host contract increments the project vote tally and emits a private vote event that omits `msg.sender`.

Recommended event:

```solidity
event PrivateVoteCast(
    uint256 indexed roundId,
    uint256 indexed projectId,
    bytes32 indexed nullifier,
    bytes32 verifierVersion,
    uint256 timestampBucket
);
```

`msg.sender` may still exist at the transaction layer. The event and app payload must not claim complete voter anonymity unless gas is relayed under the active relayer policy.

## 8. Governance and Upgrade Rules

Verifier metadata must remain explicit and inspectable:

- states: `proposed`, `active`, `deprecated`, `emergency-paused`, `sunset`;
- `circuitId`;
- `verifierVersion`;
- activation window;
- governance signer or timelock authority;
- quorum threshold;
- deprecation reason;
- replacement pointer.

Verifier upgrades must not silently reinterpret public signal order. A changed public signal order requires a new `circuitId` or major verifier version and a migration note explaining replay and nullifier compatibility.

## 9. Non-Claims

This packet does not claim:

- production ZK proving keys exist;
- Groth16, Plonk, Halo2, or another backend has been selected;
- a Solidity verifier has been generated or audited;
- the Circom code block above is already compiled or trusted as a production circuit;
- user network metadata is hidden by the current proxy;
- wallet gas-payer linkage is solved without relayer enforcement;
- historical wallet-linkable registrations become private.

## 10. Acceptance Gate

The design gate is green when tests assert:

- the exact Circom facade exposes only `[roundId, projectId, domainSeparator, membershipRoot, nullifier]` as public signals;
- the private witness contains `credentialSecret`, `membershipPathElements`, and `membershipPathIndices`;
- the public `nullifier` input is constrained to `Poseidon(credentialSecret, roundId, projectId, domainSeparator)`;
- the host-facing `verifyVoteProof(bytes calldata proof, uint256 root, uint256 nullifier, uint256 roundId, uint256 projectId)` adapter is pinned;
- the public signal order is canonical and includes `roundId`, `projectId`, `projectRegistryRoot`, `membershipRoot`, `nullifier`, and policy commitments;
- all forbidden identity, support, RPC, and witness fields are excluded from public signals;
- the verifier interface is stateless and returns only a proof-validity boolean;
- replay protection is project scoped as `used[roundId][projectId][nullifier]`;
- the fixture is explicitly labeled `spec-only` until production circuit artifacts exist.
