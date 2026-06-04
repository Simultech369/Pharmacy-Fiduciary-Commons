# Independent Pharmacy Cooperative Procurement Layer (P-02)

This folder contains the prototype tools for the federated cooperative purchasing and pricing intelligence system.

## Purpose

Negotiating drug pricing with massive wholesalers and PBMs presents severe asymmetries for single, independent pharmacies. This procurement layer:
1. **Audits Price Dispersion**: Tracks base drug pricing variances across different distributors (McKesson, Cardinal Health, AmerisourceBergen).
2. **Flags PBM Formulary Exclusions**: Identifies and warns when specific National Drug Codes (NDCs) are excluded on PBM formularies, avoiding retroactive claim clawbacks.
3. **Aggregates Volume for Discounts**: Groups purchasing orders across local pharmacies to cross volume-based bulk discount thresholds, allocating savings back to participants proportionally.

## Files

- `mock_catalogs.json`: Base drug catalogs, wholesale pricing levels, bulk discount rules, and PBM exclusion list.
- `mock_purchase_orders.json`: Simulated drug orders from three distinct community pharmacies.
- `pricing_analysis.mjs`: Core analytics script executing price checks, exclusion tracking, and group-savings calculations.

## How to Run

Execute the pricing analysis and generate the optimization report:

```bash
node tools/procurement/pricing_analysis.mjs
```

Upon execution, the script:
- Prints a terminal report displaying Price Dispersion, Formulary Warnings, Pharmacy Allocations, and Net Cooperative Savings.
- Writes a detailed JSON audit summary to `tools/procurement/procurement_audit_report.json`.
