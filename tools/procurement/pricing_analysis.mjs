import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function formatCurrency(val) {
  return `$${val.toFixed(2)}`;
}

function printTable(title, headers, rows) {
  console.log(`\n=== ${title} ===`);
  const colWidths = headers.map((h, i) => {
    let max = h.length;
    for (const r of rows) {
      const len = String(r[i] ?? "").length;
      if (len > max) max = len;
    }
    return max + 2;
  });

  const separator = colWidths.map(w => "-".repeat(w)).join("+");
  
  // Print Header
  const headerStr = headers.map((h, i) => String(h).padEnd(colWidths[i])).join("|");
  console.log(headerStr);
  console.log(separator);

  // Print Rows
  for (const r of rows) {
    const rowStr = r.map((cell, i) => String(cell ?? "").padEnd(colWidths[i])).join("|");
    console.log(rowStr);
  }
}

function getBestIndividualPrice(ndc, wholesalers) {
  let bestWholesaler = null;
  let bestPrice = Infinity;

  for (const [wsName, wsData] of Object.entries(wholesalers)) {
    const item = wsData[ndc];
    if (item && item.unitCost < bestPrice) {
      bestPrice = item.unitCost;
      bestWholesaler = wsName;
    }
  }

  return { wholesaler: bestWholesaler, unitCost: bestPrice };
}

function calculateCost(ndc, qty, wholesalerName, wholesalers) {
  const wsData = wholesalers[wholesalerName];
  const item = wsData[ndc];
  if (!item) return Infinity;

  let price = item.unitCost;
  
  // Check bulk discounts
  if (item.bulkDiscounts) {
    for (const discount of item.bulkDiscounts) {
      if (qty >= discount.minQty) {
        const discountFraction = discount.discountBP / 10000;
        price = item.unitCost * (1 - discountFraction);
      }
    }
  }

  return price * qty;
}

function getBestCooperativePrice(ndc, qty, wholesalers) {
  let bestWholesaler = null;
  let bestTotalCost = Infinity;
  let baseUnitCost = Infinity;

  for (const [wsName, wsData] of Object.entries(wholesalers)) {
    const item = wsData[ndc];
    if (!item) continue;

    const total = calculateCost(ndc, qty, wsName, wholesalers);
    if (total < bestTotalCost) {
      bestTotalCost = total;
      bestWholesaler = wsName;
      baseUnitCost = item.unitCost;
    }
  }

  const effectiveUnitCost = bestTotalCost / qty;
  return {
    wholesaler: bestWholesaler,
    totalCost: bestTotalCost,
    effectiveUnitCost,
    baseUnitCost,
    discountApplied: effectiveUnitCost < baseUnitCost
  };
}

async function main() {
  const catalogsPath = path.join(__dirname, "mock_catalogs.json");
  const ordersPath = path.join(__dirname, "mock_purchase_orders.json");

  const catalogs = JSON.parse(fs.readFileSync(catalogsPath, "utf8"));
  const orders = JSON.parse(fs.readFileSync(ordersPath, "utf8"));

  // 1. Wholesaler Price Dispersion Audit
  const dispersionHeaders = ["NDC", "Drug Name", "McKesson", "Cardinal", "Amerisource", "Spread", "Best Base Option"];
  const dispersionRows = [];

  for (const [ndc, info] of Object.entries(catalogs.drugs)) {
    const mck = catalogs.wholesalers.McKesson[ndc]?.unitCost;
    const card = catalogs.wholesalers.CardinalHealth[ndc]?.unitCost;
    const ab = catalogs.wholesalers.AmerisourceBergen[ndc]?.unitCost;

    const prices = [mck, card, ab].filter(p => p !== undefined);
    const min = Math.min(...prices);
    const max = Math.max(...prices);
    const spread = max - min;

    const bestOpt = getBestIndividualPrice(ndc, catalogs.wholesalers);

    dispersionRows.push([
      ndc,
      info.name,
      mck ? formatCurrency(mck) : "N/A",
      card ? formatCurrency(card) : "N/A",
      ab ? formatCurrency(ab) : "N/A",
      formatCurrency(spread),
      `${bestOpt.wholesaler} (${formatCurrency(bestOpt.unitCost)})`
    ]);
  }

  printTable("Wholesaler Base Price Dispersion Audit", dispersionHeaders, dispersionRows);

  // 2. PBM Exclusion Audit
  const exclusionHeaders = ["PBM / Insurer", "Excluded NDC", "Excluded Drug Name"];
  const exclusionRows = [];

  for (const [pbm, ndcs] of Object.entries(catalogs.pbmExclusions)) {
    for (const ndc of ndcs) {
      exclusionRows.push([
        pbm,
        ndc,
        catalogs.drugs[ndc]?.name || "Unknown"
      ]);
    }
  }

  printTable("PBM Formulary Exclusion Warning Registry", exclusionHeaders, exclusionRows);

  // 3. Aggregate Orders & Compare Scenarios
  const aggregatedQty = {};
  const pharmacyOrders = [];

  for (const [pharmaName, items] of Object.entries(orders)) {
    for (const item of items) {
      aggregatedQty[item.ndc] = (aggregatedQty[item.ndc] || 0) + item.qty;
      pharmacyOrders.push({
        pharmacy: pharmaName,
        ndc: item.ndc,
        qty: item.qty
      });
    }
  }

  // Scenario A: Decoupled Purchasing
  let totalDecoupledCost = 0;
  const decoupledDetails = [];

  for (const orderItem of pharmacyOrders) {
    const best = getBestIndividualPrice(orderItem.ndc, catalogs.wholesalers);
    const cost = best.unitCost * orderItem.qty;
    totalDecoupledCost += cost;

    decoupledDetails.push({
      ...orderItem,
      wholesaler: best.wholesaler,
      unitCost: best.unitCost,
      totalCost: cost
    });
  }

  // Scenario B: Cooperative Aggregated Purchasing
  let totalCoopCost = 0;
  const aggregatedSummary = {};

  for (const [ndc, qty] of Object.entries(aggregatedQty)) {
    const coopBest = getBestCooperativePrice(ndc, qty, catalogs.wholesalers);
    totalCoopCost += coopBest.totalCost;

    aggregatedSummary[ndc] = {
      qty,
      wholesaler: coopBest.wholesaler,
      effectiveUnitCost: coopBest.effectiveUnitCost,
      baseUnitCost: coopBest.baseUnitCost,
      totalCost: coopBest.totalCost,
      discountApplied: coopBest.discountApplied
    };
  }

  // Allocate coop cost back to pharmacies proportionally
  const coopDetails = [];
  for (const orderItem of pharmacyOrders) {
    const summary = aggregatedSummary[orderItem.ndc];
    const proportionalCost = summary.effectiveUnitCost * orderItem.qty;
    
    coopDetails.push({
      ...orderItem,
      wholesaler: summary.wholesaler,
      effectiveUnitCost: summary.effectiveUnitCost,
      proportionalCost
    });
  }

  // Summary tables
  const summaryHeaders = ["Pharmacy", "Drug Name", "NDC", "Qty", "Decoupled Cost", "Coop Allocated Cost", "Net Savings"];
  const summaryRows = [];

  let pharmacySavings = {};

  for (let i = 0; i < pharmacyOrders.length; i++) {
    const dec = decoupledDetails[i];
    const coop = coopDetails[i];
    const savings = dec.totalCost - coop.proportionalCost;

    pharmacySavings[dec.pharmacy] = (pharmacySavings[dec.pharmacy] || 0) + savings;

    summaryRows.push([
      dec.pharmacy,
      catalogs.drugs[dec.ndc].name,
      dec.ndc,
      dec.qty,
      formatCurrency(dec.totalCost),
      formatCurrency(coop.proportionalCost),
      formatCurrency(savings)
    ]);
  }

  printTable("Detailed Purchasing Optimization Audit", summaryHeaders, summaryRows);

  // Totals table
  const totalsHeaders = ["Pharmacy Participant", "Total Decoupled Cost", "Total Coop Cost", "Total Net Savings", "Savings %"];
  const totalsRows = [];

  for (const pharmaName of Object.keys(orders)) {
    let decTotal = decoupledDetails.filter(d => d.pharmacy === pharmaName).reduce((sum, d) => sum + d.totalCost, 0);
    let coopTotal = coopDetails.filter(c => c.pharmacy === pharmaName).reduce((sum, c) => sum + c.proportionalCost, 0);
    const savings = decTotal - coopTotal;
    const pct = (savings / decTotal) * 100;

    totalsRows.push([
      pharmaName,
      formatCurrency(decTotal),
      formatCurrency(coopTotal),
      formatCurrency(savings),
      `${pct.toFixed(2)}%`
    ]);
  }

  const overallSavings = totalDecoupledCost - totalCoopCost;
  const overallPct = (overallSavings / totalDecoupledCost) * 100;

  totalsRows.push([
    "TOTAL COOPERATIVE",
    formatCurrency(totalDecoupledCost),
    formatCurrency(totalCoopCost),
    formatCurrency(overallSavings),
    `${overallPct.toFixed(2)}%`
  ]);

  printTable("Cooperative Aggregation Savings Summary", totalsHeaders, totalsRows);

  // Save report to disk
  const reportOut = {
    generatedAt: new Date().toISOString(),
    dispersion: dispersionRows,
    exclusions: exclusionRows,
    totals: {
      decoupledTotal: totalDecoupledCost,
      coopTotal: totalCoopCost,
      savingsTotal: overallSavings,
      savingsPercent: overallPct
    },
    pharmacySummary: totalsRows
  };

  const reportPath = path.join(__dirname, "procurement_audit_report.json");
  fs.writeFileSync(reportPath, JSON.stringify(reportOut, null, 2) + "\n");
  console.log(`\nProcurement Audit Report written successfully to: ${reportPath}`);
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
