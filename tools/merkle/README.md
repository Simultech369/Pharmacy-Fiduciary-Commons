# Merkle tooling (internal)

This folder contains **internal** (non-library) scripts used to generate Merkle roots + proofs for `PBMRebateTreasury`.

## Pharmacy allocation tree

`allocations.js` builds a Merkle tree where each leaf matches the on-chain encoding:

- inner: `keccak256(abi.encodePacked(pharmacy, grossAmount, eligibleCap))`
- leaf:  `keccak256(bytes.concat(inner))` (double-hash)

Tree rules:
- Leaf ordering: input order (append index).
- Pair hashing: OpenZeppelin `MerkleProof` compatible (sorted pair hash).
- Odd leaf: duplicate last leaf.

### Input format

Provide a JSON file containing either an array or `{ "entries": [...] }`:

```json
[
  { "pharmacy": "0x...", "grossAmount": "1000000", "eligibleCap": "1000000" }
]
```

Amounts must be integers (use strings to avoid JSON number issues).

### Run

```bash
node tools/merkle/allocations.js --in allocations.json --out merkle.json
```

The output includes `root`, `totalAmount`, and per-entry `proof` arrays you can feed into `claim()` / `flagClaim()`.

