# Privacy Posture

Pharmacy Fiduciary Commons is a local/testnet prototype. This repository is designed to demonstrate proof boundaries for pharmacy rebate accounting, patient-fund allocation, and portability checks without collecting real patient, pharmacy, or claims data.

## Data Boundary

- Public dashboard PBM names, displayed amounts, onboarding examples, and sample receipts are synthetic fixtures.
- The repository does not require protected health information, real patient identifiers, live pharmacy claims, or production rebate files.
- Any future work with real participant data must happen outside this prototype boundary and requires a separate privacy, legal, security, and governance review.

## Tracking Boundary

- The static dashboard is intended to run locally and does not embed Google Analytics, Mixpanel, ad pixels, or third-party visitor tracking.
- No cookie banner is included because the intended public dashboard posture is zero non-essential cookies and zero analytics.
- Do not add visitor tracking, telemetry beacons, or third-party scripts without updating this file, the threat model, and the public disclaimer language first.

## Cryptographic Proof Boundary

- Local receipts, static checks, and contract tests are engineering evidence, not a production privacy guarantee.
- Mock ZK/nullifier flows are semantic fixtures unless a production circuit, relayer model, metadata analysis, and independent review are explicitly documented.
- On-chain addresses, transaction timing, gas payment, RPC metadata, support workflows, and public events can remain linkable even when a prototype fixture passes.

## Operator Guidance

Use synthetic data only. Do not paste real patient information, real pharmacy claim files, private keys, live RPC secrets, or production service credentials into the dashboard, repository files, issues, screenshots, prompts, or generated receipts.

For deeper threat modeling, see:

- [RETALIATION_AND_PRIVACY_THREAT_MODEL.md](docs/design/RETALIATION_AND_PRIVACY_THREAT_MODEL.md)
- [IDENTITY_NULLIFIER_DESIGN.md](docs/design/IDENTITY_NULLIFIER_DESIGN.md)
- [SECURITY.md](SECURITY.md)
