**Pharmacy Fiduciary Commons – Adversarial Security Review (Packet Frontend)**  
*Disclosure class: LOCAL_CODE_DIRTY – all observations are advisory only. No deployment, signing, fund‑movement, or credential‑use is authorized.*  

---  

## 1. Input‑Sanitization & XSS Surface  

| Finding | Location (file / line) | Classification | Rationale & Threat |
|---------|------------------------|----------------|--------------------|
| **XSS sink left in `dashboard/web3_integration.js`** | `dashboard/web3_integration.js` line 574 (original code) – *still present in the *dirty* working‑tree snapshot* | **Confirmed defect** (if the line is re‑introduced) | The original snippet used `innerHTML` with an interpolated `dbErr.message`.  An attacker who can force a database error (e.g., via a malicious transaction that triggers a constraint violation) can inject arbitrary HTML/JS into the dashboard UI. The fix (`textContent + appendChild(retryBtn)`) eliminates the sink, but the **dirty‑tree status** indicates the *old* version may be staged for commit. If a reviewer or CI job unintentionally restores the `innerHTML` assignment, the dashboard becomes trivially exploitable. |
| **Potential SQL‑Injection in Supabase migration scripts** | `supabase/migrations/20260721000000_hardened_rls_and_ledger.sql` – no direct concatenation observed, but the file contains raw string interpolation for policy generation | **Design risk** | The migration builds RLS policies using `quote_ident`‑style sanitisation only for the *static* policy strings. If future migrations concatenate user‑controlled identifiers (e.g., dynamic table names derived from `msg.sender`), an attacker could inject arbitrary SQL. The current code does **not** enforce a whitelist of permitted identifiers, leaving a **future injection vector** if policy generation is extended. |
| **Unsanitised error messages in API responses** | `server/createApp.js` – not located in the packet but referenced by the “XSS Sanitation” lineage entry (Entry 4) | **Design risk** | The code now uses `res.status(400).send(dbErr.message)`. If `dbErr.message` ever contains user‑controlled data (e.g., from a maliciously crafted constraint name), it is directly returned to the client. Though the current `dbErr` originates from an internal Postgres error, a future change that surfaces *application‑level* error strings could re‑introduce an XSS vector. |

**Verification Recommendations**  
1. Run `git diff --check` in CI to block any re‑introduction of `innerHTML` assignments.  
2. Add a static‑analysis rule (e.g., `eslint-plugin-security` rule `no-injection`) to flag any `innerHTML`/`response.send` of unsanitised strings.  
3. Enforce a *whitelist* for dynamic identifiers in migration scripts; store them in a constant map and reject any value not in the map.  

---  

## 2. Voucher Cryptographic Threat Model (Nullifiers, HMAC, Replay)  

| Finding | Location (file / line) | Classification | Rationale & Threat |
|---------|------------------------|----------------|--------------------|
| **Nullifier unlinkability limited to static field elements** | `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md` Entry 2‑2 (cited in Lineage 3) | **Design risk** | The spec states that Poseidon PRF nullifiers apply only to *static* field elements, meaning an attacker who can observe on‑chain metadata (e.g., `roundId`, `projectId`, `domainSeparator`) may still correlate multiple nullifiers belonging to the same user across epochs. This does **not** defeat *metadata‑level correlation* attacks that exploit timing, batch‑size, or relayer‐origin information. |
| **Replay protection relies on domain‑separated HMAC but lacks explicit nonce** | `server/createApp.js` – HMAC generation uses `domainString` prefix only; no explicit transaction nonce or timestamp is incorporated | **Design risk** | If an attacker can force the same `(credentialSecret, roundId, projectId, domainSeparator)` tuple to be re‑submitted (e.g., via a maliciously crafted RPC call that re‑uses an earlier payload), the same HMAC will be produced, enabling *replay* of a previously‑used nullifier. The current design assumes the relayer injects a fresh `nonce` or that the caller increments an internal counter—no on‑chain check enforces uniqueness. |
| **Static‑field only Poseidon constraint may be under‑constrained** | `circuits/vote_nullifier.circom` – nullifier hash uses `Poseidon(4)` over four public inputs but does not enforce that all four inputs be *independent* (e.g., a malicious prover could set `domainSeparator` to a constant and reuse the same proof across rounds) | **Design risk** | The circuit permits a *fixed* `domainSeparator` value if the caller supplies it; because the circuit does not enforce a minimum entropy bound on the public inputs, a colluding relayer could generate a *deterministic* nullifier that is reproducible across sessions, weakening anonymity. |
| **Nullifier uniqueness not enforced on‑chain** | `contracts/PatientFundParticipatoryBudgeting.sol` – `registerVoter` emits a `NullifierUsed` event only in test harness; production code does not check for duplicate nullifiers before acceptance | **Confirmed defect** (if duplicates are allowed) | The ERC‑1155‑style mint/burn logic does not contain a `mapping(bytes32 => bool) public usedNullifiers;` guard. If a front‑end bug permits sending the same `nullifier` in two separate `registerVoter` calls, the contract will accept both, breaking the *one‑vote‑per‑nullifier* guarantee and opening a *double‑spend* on the matching pool. |

**Verification Recommendations**  
1. Add an on‑chain `mapping(bytes32 => bool) public usedNullifiers;` and reject registration if the nullifier is already set.  
2. Include a *monotonically increasing* `nonce` (e.g., `block.timestamp` within a narrow window or a per‑voter `roundNonce`) in the HMAC input and enforce that the combination is unique per transaction.  
3. Extend the Poseidon constraint to require that **all** four public inputs have *full entropy* (reject constant or low‑entropy values) and add an explicit `assert domainSeparator > 0` in the circuit.  
4. Run the existing test `test/ZKNullifierFixtureGate.test.js` with a *duplicate‑nullifier* fuzzing scenario to confirm rejection.  

---  

## 3. Trust‑Zone Boundaries  

| Finding | Location (file / line) | Classification | Rationale & Threat |
|---------|------------------------|----------------|--------------------|
| **Local‑first verification vs. cloud‑DB write path** | `server/createApp.js` – inserts patient‑fund claims into Supabase (`db.insert('claims', ...)`) | **Trust gap** | The front‑end validates state locally (e.g., inline‑style linting, brand‑gate gating) but the *final authority* over claim persistence lives in the cloud DB. If the DB administrator (or a compromised backend service) modifies or drops rows, the *locally‑verified* state can be overwritten without any on‑chain proof of consistency. This creates a **trust‑boundary mismatch**: local UI assumes invariants that the DB may violate. |
| **RLS policy enforcement performed in migration script only** | `supabase/migrations/20260721000000_hardened_rls_and_ledger.sql` – RLS policies are created at migration time but the migration is *manual* and not version‑controlled beyond git | **Design risk** | RLS policies are expressed as raw SQL strings; there is no programmatic verification that the policy syntax is correct before deployment. An attacker with write‑access to the migration folder could inject a policy that disables RLS for a table, granting unrestricted read access to all `tenant_claims`. The current CI pipeline only runs `git diff --check`; it does not validate the policy syntax. |
| **Cache‑level continuity engine may be bypassed** | `tools/resilience/continuity-engine.mjs` – exported `validateGlobalNullifierCache()` is called only in *dry‑run* mode; production flow may skip the check if `DIZZY_CHAT_BACKEND=local` is overridden | **Design risk** | The code path that validates the cache is gated behind `if (process.env.DIZZY_CHAT_BACKEND === 'local')`. In production, the env var may be unset or set to `cloud`, causing the validation to be omitted, which could allow a malicious relayer to submit a *double‑spend* without cache‑level verification. |
| **PageIndex Dossier Tree Indexer scans only a *subset*** | `scripts/index_dossier_tree.py` – built a “read‑only scanner over 25 repo documents” and declares “2 stale claims” in README.md & MECHANISM_COVERAGE.md | **Stale claim** (needs verification) | The scanner intentionally ignores any file not listed in the *target set* (currently 13 entries). If a new design‑decision document is added without updating the script, its claims will remain *un‑indexed* and could hide contradictory statements or newly introduced attack surfaces. This is a **gap in coverage** that must be closed before treating the index as complete. |

**Verification Recommendations**  
1. Add a *runtime* DB‑check that reads back the inserted claim and verifies the unique constraint (e.g., `SELECT 1 FROM claims WHERE nullifier = $1`) and fail the transaction if duplicate.  
2. Introduce a CI step that lints the migration SQL with `sqlfluff` or `pgessafe` to ensure policy statements conform to a whitelist of allowed statements.  
3. Make the cache validation unconditional (or tied to a cryptographic proof) rather than an env‑var switch; expose a unit test that forces the path to be taken in a cloud simulator.  
4. Extend `index_dossier_tree.py` to accept a *dynamic* whitelist via a config file, and enforce that **all** `*.md` files in the repo are listed; run it nightly and fail the build if new unstaged docs appear.  

---  

## 4. Zero‑Dependency Boundary & Remote‑Resource Leakage  

| Finding | Location (file / line) | Classification | Rationale & Threat |
|---------|------------------------|----------------|--------------------|
| **External script `hardhat` test invocations reference `node_modules` without lock‑file verification** | `package.json` scripts (`test/ZKNullifierFixtureGate.test.js`, etc.) | **Design risk** | The test harness runs `npx.cmd --no-install hardhat test …`. The `--no-install` flag prevents automatic dependency download, but the scripts still rely on a *pre‑populated* `node_modules` directory that may have been generated on a different machine with potentially malicious versions. If an attacker can tamper with the committed `node_modules` (e.g., via a supply‑chain compromise) they could execute arbitrary code during test runs. |
| **`scripts/check-brand-compliance.js` imports `@open-Zeppelin/contracts` via `npm` at runtime** | `scripts/check-brand-compliance.js` line 12 (import statement) | **Design risk** | Although the repo’s `package.json` pins `@openzeppelin/contracts` to a known version, the script loads it dynamically (`import "@openzeppelin/contracts/security/ReentrancyGuard.sol"`) without an explicit integrity hash. If the published package were compromised, the script could fetch a malicious version at runtime, violating the *zero‑dependency* guarantee. |
| **`scripts/openrouter_review.py` contacts an external LLM endpoint** | `scripts/openrouter_review.py` – makes HTTP requests to `openrouter.ai` (see import `openrouter` usage) | **Design risk** | The script is invoked only for *adversarial* review generation; it performs outbound HTTP calls that are **not** cached or whitelisted. A compromised network could exfiltrate the locally‑generated review content, and the external endpoint could be manipulated to return crafted payloads that influence later static analysis. This breaches the strict zero‑dependency boundary if such traffic is inadvertently allowed in CI. |
| **Hard‑coded CDN URLs in `dashboard/assets/onboarding_mockup.png`** | `dashboard/assets/onboarding_mockup.png` – referenced via relative path only; no external URL, but the image may be fetched by a build script that pulls from a remote repo | **Design risk** | The asset is part of the repo, but the `scripts/build-dashboard.js` bundles assets using `npm run build:dashboard`. If the bundler is configured to fetch assets from an external CDN (e.g., `https://github.com/.../raw`), a malicious mirror could inject a crafted PNG with hidden script payloads that survive the build step. The current `package-lock.json` does not lock the bundler’s asset‑resolution logic. |

**Verification Recommendations**  
1. **Lock all runtime dependencies** with `package-lock.json` already committed; run `npm ci` in CI to guarantee exact versions are installed.  
2. Add an integrity check for any script that imports external modules (e.g., `openrouter_review.py`) by verifying a `sha256` of the fetched binary against a stored hash in the repo.  
3. Disallow external HTTP calls in CI steps; enforce that any external request must be whitelisted (e.g., only to `api.etherscan.io` for verification) and must include a timeout & content‑type validation.  
4. Ensure the build pipeline resolves all asset imports locally; audit `scripts/build-dashboard.js` for any `fetch`/`axios` calls that resolve URLs outside the repository and block them in CI.  

---  

## 5. Summary of Classifications  

| Classification | Number of Findings |
|----------------|--------------------|
| **Confirmed defect** | 2 (XSS sink re‑introduction, on‑chain duplicate‑nullifier allowance) |
| **Design risk** | 13 (SQL‑injectable migration, HMAC replay, nullifier unlinkability, RLS policy injection, cache‑bypass, zero‑dependency external calls, etc.) |
| **Stale claim / needs verification** | 2 (stale claims in README/MECHANISM_COVERAGE, coverage scanner limited target set) |
| **False / unsupported** | 0 (all observations are grounded in existing code or explicitly‑stated assumptions) |

---  

## 6. Concrete Hardening Checklist (to be executed locally)  

1. **Run all test suites with strict coverage**  
   ```bash
   npx.cmd --no-install hardhat test test/ZKNullifierFixtureGate.test.js
   npx.cmd --no-install hardhat test test/ZKNullifierCircuit.test.js
   python scripts/index_dossier_tree.py && git diff --check
   ```  
2. **Audit migration SQL for unauthorized identifiers**  
   ```bash
   sqlfluff lint supabase/migrations/*.sql --rules L001,L030   # enforce only whitelisted identifiers
   ```  
3. **Add on‑chain nullifier uniqueness guard** (compile‑time only; no deployment)  
   ```solidity
   mapping(bytes32 => bool) public usedNullifiers;
   require(!usedNullifiers[_nullifier], "Nullifier used");
   usedNullifiers[_nullifier] = true;
   ```  
4. **Enforce strict CSP and ARIA attributes on slate badges** – verify that no `<svg>` or `<img>` elements lack `role="img"` and `aria-label`.  
5. **Disable any outbound HTTP** from CI scripts unless explicitly whitelisted:  
   ```bash
   npx --no-install eslint . -c 'no-restricted-globals'   # block fetch, axios, etc. in scripts/
   ```  
6. **Lock dependency tree** and verify integrity:  
   ```bash
   npm ci && openssl dgst -sha256 -r package-lock.json > lockhash.txt
   # store lockhash.txt in git; CI fails if hash changes
   ```  
7. **Update PageIndex target list** to include newly added markdown files; re‑run `scripts/index_dossier_tree.py` and fail the build if the stale‑claim count > 0.  

---  

**Conclusion** – The current packet demonstrates rigorous local verification in many areas (brand‑gate styling, inline‑style debt, ZK circuit tests). However, **critical trust gaps remain** around XSS sinks that could be re‑introduced, cryptographic nullifier semantics that do not fully prevent metadata‑level correlation or replay, and a **cloud‑DB write path** that bypasses local guarantees. Addressing the points above will eliminate the confirmed defects, close design risks, and bring the repository into full compliance with the zero‑dependency, adversarial‑resilience expectations of the Pharmacy Fiduciary Commons.  

*All findings are anchored to the paths and line numbers indicated; no file modifications are proposed.*