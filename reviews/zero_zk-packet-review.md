**Summary**  
The packet documents a prototype ZK‑nullifier design (Circom circuit `circuits/vote_nullifier.circom`) intended to replace stable credential hashes with scoped nullifiers. The design documents (e.g., `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md`, `zk_nullifier_claims_and_lineage_spec.md`) state that unlinkability is limited to static field elements and that the current repository remains a test‑net prototype. Empirical evidence shows the circuit passes signal‑order and Poseidon‑constraint tests (`test/ZKNullifierFixtureGate.test.js`), but the forensic evidence reveals a concrete privacy leakage: the private `credentialSecret` is used to compute a public `membershipRoot` (lines 18‑40, `circuits/vote_nullifier.circom`), which can be observed on‑chain and enables correlation with real‑world identifiers, directly contravening the forbidden unlinkable field list (`FORBIDDEN_UNLINKABLE_FIELDS` in `test/ZKNullifierFixtureGate.test.js`). Moreover, the unlinkability claim is qualified as “static field elements only,” indicating that on‑chain metadata (e.g., transaction timing, relayer batching) may still deanonymize participants, turning the cryptographic guarantee into “theater” rather than a proven security property.

---

**Positive Findings**  

1. **Signal‑order and schema enforcement** – `test/ZKNullifierFixtureGate.test.js` (lines 55‑64) validates that the public signal order (`roundId`, `projectId`, `domainSeparator`, `membershipRoot`, `nullifier`) and the Poseidon hash constraints are correctly declared, confirming that the circuit’s structural gate is sound (entry 6, `claim-spec-gate-a-zk-nullifier-circuit-signals`).  

2. **Host‑adapter verification** – The same test gate confirms that the `verifyVoteProof` host‑adapter signature verification works as specified in `review-context/project_scoped_zk_circuit_verifier_interface_spec.md` (entry 6).  

3. **Comprehensive test coverage** – `test/ZKNullifierCircuit.test.js` (lines 1‑9) passes 9/9 assertions, indicating that the core circuit semantics (Merkle path evaluation, Poseidon leaf/nullifier constraints) are implemented correctly (entry 7, `claim-phase1-vote-nullifier-circom-implementation`).  

4. **Schema‑strictness** – The strict JSON schema validation in `test/ZKNullifierFixtureGate.test.js` (lines 55‑64) ensures that no extraneous properties are permitted, preserving integrity of the input payload (entry 20, `claim-codex-56-reconciliation-diff-hygiene-global-cache-cli-and-strict-zk-schema`).  

5. **Consistent CI pipeline** – All relevant tests (`test/ZKNullifierFixtureGate.test.js`, `test/ZKNullifierCircuit.test.js`, `test/ContinuityAndAdversarialTools.test.js`) pass, showing that the current codebase meets the defined quality gates (entries 6, 7, 18).  

---

**Critical Issues (ranked)**  

1. **CredentialSecret leakage via public `membershipRoot`** – Lines 18‑40 in `circuits/vote_nullifier.circom` compute `membershipRoot` from `leafHash.out`, which equals `credentialSecret`. Because `membershipRoot` is a public signal, the secret can be reconstructed on‑chain, violating the forbidden unlinkable field `credentialSecret` listed in `test/ZKNullifierFixtureGate.test.js` (lines 5‑18). This creates a concrete privacy breach, turning the “static‑field‑only” unlinkability claim into a practical deanonymisation vector.  

2. **Incomplete unlinkability guarantee** – Entry 3 (`claim-zk-nullifier-unlinkability-bounds`) explicitly states that “Poseidon PRF nullifier unlinkability applies to static field elements only and does not defeat on‑chain metadata correlation.” The design documents (`ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md`, lines 10‑15) confirm the current repo is a prototype with “public‑wallet and stable‑hash privacy limits,” meaning the cryptographic guarantees are unverified and likely insufficient for real‑world privacy.  

3. **Custom Poseidon hash implementation** – The circuit uses a manual SHA‑256 based Poseidon emulation (lines 43‑53, `buildMerkleRoot` function) rather than the formally verified Poseidon constraints from `circomlib`. This deviates from the intended cryptographic guarantee and may weaken collision resistance, constituting a design‑level risk.  

4. **Nullifier reuse / replay risk** – The nullifier is derived solely from `credentialSecret`, `roundId`, `projectId`, and `domainSeparator` (lines 42‑47). If any of these values repeat across rounds (e.g., same credentialSecret reused), the Poseidon(4) output may collide, enabling nullifier reuse attacks. No explicit uniqueness enforcement (e.g., a per‑nullifier nonce) is evident.  

---

**Suggestions**  

- **Isolate credential secret from public state**: Modify the circuit so that `membershipRoot` is computed from a commitment to `credentialSecret` (e.g., a Pedersen commitment) rather than directly from the secret itself. This would prevent on‑chain derivation of the secret while preserving the required equality check.  

- **Enforce true secrecy of `membershipPathElements`**: Ensure that the Merkle path elements are generated from a secret source (e.g., a random per‑claim nonce) and not derivable from publicly observable data. If they must be derived from a public Merkle tree, add a cryptographic commitment (e.g., a zero‑knowledge proof) that proves knowledge of the secret path without revealing it.  

- **Adopt the official Poseidon library**: Replace the custom SHA‑256 Poseidon implementation with the verified Poseidon constraints from `circomlib/circuits/poseidon.circom` to guarantee the intended cryptographic security properties.  

- **Add nullifier uniqueness enforcement**: Introduce a per‑nullifier random nonce (e.g., a 32‑byte secret) into the Poseidon(4) input, or enforce a on‑chain nullifier cache that rejects duplicates, thereby mitigating replay and double‑spend attempts.  

- **Document the prototype status**: Clearly annotate the current implementation as a design prototype in `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md` and `IDENTITY_NULLIFIER_DESIGN.md`, specifying that actual ZK proof generation, verification, and deployment are pending and must not be used for production claims until the above privacy and unlinkability gaps are resolved.  

- **Add explicit audit tests for indirect leakage**: Extend `test/ZKNullifierFixtureGate.test.js` to verify that no public signal can be algebraically inverted to recover `credentialSecret` or any other forbidden unlinkable field, ensuring the circuit truly respects the forbidden‑field list.  

---

**Open Questions**  

1. **Secret‑path derivation** – How will the system ensure that `membershipPathElements` remain secret when they are conceptually derived from a public Merkle tree of credential hashes?  

2. **Scope of nullifier uniqueness** – Is the intended nullifier scope per‑round, per‑epoch, or global, and what on‑chain mechanism will prevent reuse across different scopes?  

3. **Integration with revocation** – What on‑chain revocation process will invalidate a nullifier once its associated credential is compromised, and how will this interact with the static‑field unlinkability model?  

4. **Poseidon parameterization** – Are the Poseidon constants (e.g., arity, domain) tuned for the target field prime (2¹⁸⁸) defined in `test/ZKNullifierCircuit.test.js` (line 9), or do they need adjustment for the actual circuit depth?  

5. **Transition timeline** – When will the prototype be replaced by a fully verified ZK‑proof system, and what are the required milestones (e.g., formal verification, audit, production deployment) to ensure that the unlinkability guarantees move from “theater” to proven security?  

---  

*All observations respect the packet’s disclosure and advisory boundaries; no deployment‑authorizing actions or secret‑material usage is implied.*