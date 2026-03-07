# Pharmacy Fiduciary Commons

**On-chain rebate transparency for independent pharmacies and patients.**

> ⚠️ **This contract has not yet been audited. Do not deploy with real funds until a formal audit is complete.**

---

## What This Is

Pharmacy Benefit Managers (PBMs) negotiate billions in drug rebates annually from manufacturers. Most of it never reaches the independent pharmacies or patients it was negotiated for. There is currently no mechanism — legal, regulatory, or technical — that makes the flow of that money permanently visible.

This is that mechanism.

`PBMRebateTreasury` is an Ethereum smart contract that:

- Records every rebate deposit **permanently on-chain** with depositor identity, amount, quarter, drug class, and source — in a format that cannot be altered retroactively
- Routes captured funds directly to independent pharmacies via **Merkle-proof claims**
- Allocates **10% of every gross claim** to a dedicated patient fund, automatically, at claim time
- Makes every **missing deposit equally visible** — a Ledger of Omissions in which every quarter a PBM does not deposit is a timestamped, permanent, documented record

The silence is the number.

---

## Background

California SB 41 (signed October 2025, effective January 2026) mandates 100% rebate pass-through — but explicitly exempts Taft-Hartley self-insured union plans, which cover tens of millions of American workers. The FTC's January 2025 report documented $7.3 billion in excess PBM revenue. Federal law currently requires nothing comparable to SB 41 for these plans.

The gap is not in the law. It is in the infrastructure. This contract is that infrastructure.

DOL CAR 2025-01 (May 2025) formally removed the prior "extreme care" standard for cryptocurrency in ERISA plans. Stablecoins (DAI, USDC) are now evaluated under the standard prudent process applicable to any asset class.

---

## Contract Architecture

### Treasury Buckets (split at deposit)
| Bucket | Allocation | Purpose |
|--------|-----------|---------|
| Distribution Pool | 99% | Pharmacy Merkle claims |
| Governance Reserve | 1% | Council operations (EXECUTOR_ROLE access only) |

### Patient Fund (allocated at claim time)
| Source | Amount |
|--------|--------|
| Every gross claim | 10% routed to `patientFund` |
| Unclaimed epoch funds after 30-day recall delay | 100% to `patientFund` |
| Non-payout token sweeps | 100% to `patientFund` |

### Roles
| Role | Holder | Permissions |
|------|--------|-------------|
| `COUNCIL_ROLE` | 3/5 Gnosis Safe | Epoch management, root co-sign, recall, sanctions, unpause |
| `EXECUTOR_ROLE` | TimelockController | Cap changes, governance reserve withdrawal, env fund update |
| `GUARDIAN_ROLE` | Separate fast-response address | Emergency pause only — cannot unpause, cannot access funds |

### Core Lifecycle
1. PBM (or any party) calls `depositRebate()` — funds enter escrow, source logged permanently
2. Council member calls `proposeRoot()` — Merkle root proposed for current epoch
3. Second distinct council member calls `confirmRoot()` — root goes live (co-sign gate)
4. Pharmacies (or delegated claims agent) call `claim()` or `claimBatch()` (array compatibility wrapper — enforces exactly one entry)
5. Council calls `finalizeEpoch()` to close epoch and open the next
6. After 30-day `RECALL_DELAY`, unclaimed funds recalled to `patientFund`

### Security Properties
- Hard cap enforced at root proposal and claim (monotonic decrease only — ratchet)
- Daily cap enforced at root proposal and claim
- Root total enforced at claim
- Per-pharmacy cap enforced via Merkle leaf encoding
- Double-hash leaf construction (second-preimage protection)
- Root publication requires co-sign from two **distinct** `COUNCIL_ROLE` members
- Daily cap bounded by hard cap at all times
- Recall only after `RECALL_DELAY`, only unclaimed amount, sent to `patientFund`
- Payout token cannot be swept
- Non-payout tokens swept to `patientFund` (not general fund)
- `GUARDIAN_ROLE` is a separate address from `COUNCIL_ROLE`
- `flagClaim` requires a valid Merkle proof — pool-locking griefing prevented
- `flagClaim` increments `epochClaimedTotal`, `epochVolume`, and sets `hasClaimed` — caps and recall math fully consistent on disputed epochs
- Sanctioned addresses cannot flag claims — pool-locking via dispute prevented
- Open dispute flag blocks `claim()` — no parallel claim and dispute on same epoch
- ETH rejected via `receive()` and `fallback()`
- No upgradeability

---

## Merkle Leaf Encoding

```solidity
// Double-hash — second-preimage protection
// abi.encodePacked is safe here: all fields are fixed-size (address + uint256 + uint256)
bytes32 leaf = keccak256(
    bytes.concat(keccak256(abi.encodePacked(pharmacy, grossAmount, eligibleCap)))
);
```

Each leaf encodes:
- `pharmacy` — claimant address
- `grossAmount` — gross allocation this epoch (patient share drawn from this)
- `eligibleCap` — per-pharmacy maximum enforced on-chain

> **Off-chain tooling note:** Merkle tree generators and proof scripts **must** use `encodePacked` (not `encode`) when hashing leaves, or proofs will be invalid on-chain.

---

## Dependencies

```
@openzeppelin/contracts ^4.x
  - token/ERC20/utils/SafeERC20
  - token/ERC20/IERC20
  - security/ReentrancyGuard
  - security/Pausable
  - access/AccessControlEnumerable
  - utils/cryptography/MerkleProof
```

---

## Deployment Parameters

```solidity
constructor(
    address _token,             // DAI or USDC contract address
    address _patientFund,       // Immutable — receives patient allocations
    address _environmentalFund, // Receives accidentally sent ETH
    uint256 _initialDailyCap,   // Starting daily volume cap (hardCap = dailyCap * 10)
    address _council,           // 3/5 Gnosis Safe — COUNCIL_ROLE + DEFAULT_ADMIN_ROLE
    address _executor,          // TimelockController — EXECUTOR_ROLE
    address _guardian           // Separate address — GUARDIAN_ROLE only, must != _council
)
```

> **Before deploying to mainnet:**
> - Complete a formal security audit
> - Configure a 3/5 Gnosis Safe for `_council`
> - Deploy and configure a `TimelockController` for `_executor`
> - Confirm `_guardian` is a separate, dedicated address
> - Verify all addresses on the target network

---

## Audit Status

| Status | Detail |
|--------|--------|
| ✅ Internal review complete | Architecture and security properties reviewed by contract author |
| ⏳ External audit | Pending — budgeted for pre-mainnet deployment |
| ❌ Mainnet deployment | Not yet deployed — do not use with real funds |

Audit inquiries: open an issue or see contact below.

---

## Project Status

| Component | Status |
|-----------|--------|
| Smart contract | ✅ Complete |
| Public dashboard (epochStats / Ledger of Omissions) | 🔨 In development |
| Merkle tree generator + proof tooling | 🔨 In development |
| ERISA counsel review of model procurement clause | ⏳ Pending funding |
| Mainnet deployment | ⏳ Pending audit |

---

## Contributing

This is an open-source public goods project. Contributions welcome — particularly:

- Merkle tree generation tooling (JavaScript / Python)
- Dashboard frontend
- Test suite expansion
- Documentation improvements

Open an issue to discuss before submitting a large PR.

---

## License

MIT — see [LICENSE](./LICENSE)

---

## Mission

Independent pharmacies serve the communities that large chains abandon. They dispense prescriptions on thin margins, absorb retroactive clawbacks they cannot audit, and have no ledger to point to when the numbers don't add up.

This contract is that ledger.

Every deposit is permanent. Every omission is equally permanent. PBM silence is the evidence.

---

*This repository does not constitute legal, financial, or investment advice. All procurement clause language referenced in project documentation requires review by qualified ERISA counsel before use in any plan document or RFP.*
