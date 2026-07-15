# Public Release Verification Checklist

This runbook defines the required gate checks before tagging a public source checkpoint or releasing contract/dashboard code to staging or production networks. A local/source checkpoint is not a production release. Production release requires the dedicated production gate in section 5.

---

## 1. Automated Tests & Compiler Pass

No release tag may be created while compile warnings or failing tests exist.

- [ ] **Clean Compilation Check**:
  Run compiler validation to ensure no unexpected Solc or eslint warnings exist:
  ```bash
  npm run compile
  ```
- [ ] **Full Test Suite Execution**:
  Run all contract and threat-model tests, confirming the full suite passes:
  ```bash
  npm test
  ```
- [ ] **Prototype Readiness Script Pass**:
  For local/source checkpoints only, confirm that mechanical checks pass while open production items remain visible:
  ```bash
  node scripts/check-readiness.js --env local
  ```
- [ ] **Deployment Template Validation**:
  Confirm that parameter and governance templates still pass shape/range checks. This is not a deployment-ready config check:
  ```bash
  npm.cmd run check:deployment-template
  ```

---

## 2. Front End & Build Hygiene

- [ ] **Local Asset Integrity**:
  Verify the size and checksum of `dashboard/ethers.umd.min.js` to ensure it was copied cleanly from `node_modules` without tampering:
  ```bash
  # In PowerShell, confirm file size is approximately 522 KB (522,095 bytes)
  (Get-Item dashboard/ethers.umd.min.js).Length
  ```
- [ ] **Production Dashboard Build**:
  Generate static production assets with local script files and an asset manifest:
  ```bash
  npm.cmd run build:dashboard
  npm.cmd run check:frontend
  ```
- [ ] **No Public Source Maps**:
  Ensure no `.map` files are present in `dashboard/` or `dist/dashboard/`.
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

## 4. Source Checkpoint Tagging

Once local/source-checkpoint checks pass, tag the exact commit only as a prototype/source checkpoint unless section 5 also passes:
```bash
git tag -a prototype-v1.0.0 -m "Prototype source checkpoint v1.0.0"
git push origin prototype-v1.0.0
```

Do not use a production-looking tag for a commit that only passed local readiness or template validation.

---

## 5. Production Release Gate

No staging/production-network release tag may be created unless this gate passes against the exact release commit. It requires production readiness, non-template deployment config without `--allow-placeholders`, exact-commit scanner evidence, published independent-audit evidence, frontend build hygiene, and an on-chain deployment audit log.

```bash
npm.cmd run build:dashboard
npm.cmd run check:release:production -- `
  --parameters deployment/parameters.production.json `
  --governance deployment/governance-roles.production.json `
  --audit-report audits/independent-audit-<commit>.md `
  --scanner-report audits/scanner-evidence-<commit>.md `
  --deployment-audit artifacts/deployment-audit-<commit>.log
```
