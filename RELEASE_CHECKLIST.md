# Public Release Verification Checklist

This runbook defines the required gate checks before tagging a public commit or releasing contract/dashboard code to staging or production networks. 

---

## 1. Automated Tests & Compiler Pass

No release tag may be created while compile warnings or failing tests exist.

- [ ] **Clean Compilation Check**:
  Run compiler validation to ensure no unexpected Solc or eslint warnings exist:
  ```bash
  npm run compile
  ```
- [ ] **Full Test Suite Execution**:
  Run all contract and threat-model tests, confirming 145+ passing tests:
  ```bash
  npm test
  ```
- [ ] **Readiness Script Pass**:
  Confirm that the mechanical readiness script passes under the targeted environment:
  ```bash
  node scripts/check-readiness.js --env local
  ```

---

## 2. Front End & Build Hygiene

- [ ] **Local Asset Integrity**:
  Verify the size and checksum of `dashboard/ethers.umd.min.js` to ensure it was copied cleanly from `node_modules` without tampering:
  ```bash
  # In PowerShell, confirm file size is approximately 522 KB (522,095 bytes)
  (Get-Item dashboard/ethers.umd.min.js).Length
  ```
- [ ] **No Public Source Maps**:
  Ensure no `.map` files are present in the `dashboard/` directory.
- [ ] **Strict CDN & HTML Inspection**:
  Verify that `dashboard/index.html` has no un-hashed third-party script CDNs (all external script calls must contain `integrity` attributes).

---

## 3. Disclaimers & Naming Compliance

- [ ] **"What This Cannot Do" Notice**:
  Confirm that the brutally explicit warnings in the top section of `README.md` are intact.
- [ ] **Non-Dismissible UI Warnings**:
  Verify that the red/yellow warning box disclaimers are present on every dashboard tab.
- [ ] **Neutral Omissions Terminology**:
  Verify that no dashboard element or documentation file uses speculative, accusatory terms (e.g., "theft", "fraud") in reference to missing PBM deposits.

---

## 4. Release Tagging

Once all checks pass, tag the exact commit with a semantic version (prefixed with `v`) and push:
```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```
