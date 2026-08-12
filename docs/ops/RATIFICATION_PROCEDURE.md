# Ratification Procedure (Proposed)

This document outlines the proposed formal ratification procedure for the Pharmacy Fiduciary Commons Constitution. 

> [!IMPORTANT]
> **PROPOSED PROCEDURE**: This procedure is not currently implemented in smart contract code or active governance. It represents the planned roadmap for moving the Commons from a testnet prototype to a fully ratified community-governed public utility.

---

## 1. Frozen Draft Phase

Before any vote occurs, the constitution and voter eligibility list must be frozen:
* **Constitutional Freeze**: The draft of the Constitution must be frozen, assigning a specific version identifier, a git commit hash of the repository, and a cryptographic hash (SHA-256) of the constitutional text.
* **Diff Transparency**: Any changes from previous drafts must be published as a clear markdown diff.
* **Public Comment & Challenge Period**: A mandatory 30-day challenge window must be observed, allowing participants to submit comments or dispute exclusions before voting begins.

---

## 2. Plural Admission & Bounded Veto (Voter Eligibility)

To prevent circularity where the Council holds absolute control over who gets to vote, voter eligibility is governed by a **Plural Admission, Bounded Veto** model:
* **Council Admission**: The Council can admit participants based on verified operational history.
* **Trusted Issuer Admission**: Pre-authorized credential issuers can cryptographically attest to voter eligibility (e.g., verifying a pharmacy's active state license).
* **Cooperative Nomination**: Local pharmacy cooperatives or patient advocacy groups can nominate voters.
* **Appeal Path**: Any participant excluded from the eligibility list has a defined, documented path to appeal to the governance forum.
* **Bounded Veto**: The Council or a specialized Guardian may veto a voter admission only by publishing an emergency veto containing a reason and an `evidenceHash` (which expires and must be reviewed within 14 days).

### Credential Revocation Appeals

Credential revocation is not currently appeal-enforced by contract. Before ratification, the Commons must define a revocation appeal procedure that covers:

* **Issuer capture or coercion**: a participant may challenge revocation if the credential issuer is suspected of PBM, payer, or council pressure.
* **Evidence packet**: every contested revocation must publish a reason code, `evidenceHash`, issuer identity, and expiration or review deadline.
* **Temporary continuity**: pharmacies or patient advocates under active appeal should have a documented temporary-status path so issuer capture cannot silently remove claim, vote, or dispute standing.
* **Independent review**: appeal review must involve a role or constituency not controlled solely by the revoking issuer.

This procedure is proposed only; current credential policy tooling checks revocation state but does not adjudicate revocation legitimacy.

---

## 3. Multi-Class Constituency Thresholds

Ratification cannot be achieved by a simple flat majority of total voters. Instead, voting is divided into distinct constituency classes, each requiring a separate threshold to pass:
1. **Independent Pharmacy Class**: Requires a $> 60\%$ approval rate from registered pharmacy addresses.
2. **Patient & Community Advocate Class**: Requires a $> 50\%$ approval rate from community representatives.
3. **Technical Stewards & Operators Class**: Requires a $> 50\%$ approval rate from developers and protocol maintainers.

---

## 4. Post-Vote Objection & Publication

* **Objection Window**: A 14-day post-vote objection window is established before final ratification is declared.
* **Mandatory Disclosure**: The following data must be publicly published:
  * Electorate eligibility-list hash.
  * Count of excluded or challenged voters.
  * Count of unresolved appeals.
  * Vote totals broken down by constituency class.

---

## 5. Ratification & Exit Package

Once ratified, a permanent **Ratification Artifact** is compiled, binding together:
* The constitution text hash.
* The electorate eligibility criteria hash.
* The detailed vote results.
* A summary of any unresolved objections.

### Fork & Exit Procedure
If a constituency group decides to fork the project due to governance capture or unresolved disputes, they can export a clean **Fork/Exit Package** containing:
1. The frozen constitution hash.
2. The current code repository commit hash.
3. The cryptographic credential policy.
4. The portability export bundle (generated via `scripts/export-portability.js`).
5. The complete cryptographic vote records.
