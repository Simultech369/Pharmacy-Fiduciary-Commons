#!/usr/bin/env node
/* eslint-disable no-console */

const fs = require("node:fs");
const path = require("node:path");

const rootDir = path.resolve(__dirname, "..");
const coveragePath = path.join(rootDir, "coverage.json");

function pct(covered, total) {
  if (total === 0) return "100.00%";
  return `${((covered / total) * 100).toFixed(2)}%`;
}

function summarizeFile(entry) {
  const sVals = Object.values(entry.s || {});
  const fVals = Object.values(entry.f || {});
  const bVals = Object.values(entry.b || {});
  const lVals = Object.values(entry.l || {});

  const sCovered = sVals.filter((v) => v > 0).length;
  const fCovered = fVals.filter((v) => v > 0).length;
  let bTotal = 0;
  let bCovered = 0;
  for (const arr of bVals) {
    for (const count of arr) {
      bTotal += 1;
      if (count > 0) bCovered += 1;
    }
  }
  const lCovered = lVals.filter((v) => v > 0).length;

  return {
    sCovered,
    sTotal: sVals.length,
    bCovered,
    bTotal,
    fCovered,
    fTotal: fVals.length,
    lCovered,
    lTotal: lVals.length
  };
}

function main() {
  if (!fs.existsSync(coveragePath)) {
    console.error(`Missing ${coveragePath}. Run npx hardhat coverage first.`);
    process.exit(1);
  }

  const raw = JSON.parse(fs.readFileSync(coveragePath, "utf8"));
  const rows = [];
  const totals = { sCovered: 0, sTotal: 0, bCovered: 0, bTotal: 0, fCovered: 0, fTotal: 0, lCovered: 0, lTotal: 0 };

  for (const [fileKey, entry] of Object.entries(raw)) {
    const rel = path.relative(rootDir, path.resolve(rootDir, fileKey)).replace(/\\/g, "/");
    if (rel.startsWith("contracts/mocks/") || rel === "contracts/OZTimelockControllerImport.sol") {
      continue;
    }
    const stats = summarizeFile(entry);
    for (const k of Object.keys(totals)) {
      totals[k] += stats[k];
    }
    rows.push({ rel, stats });
  }

  rows.sort((a, b) => a.rel.localeCompare(b.rel));

  const lines = [
    "### Solidity Test Coverage Summary",
    "",
    "| Contract | Statements | Branches | Functions | Lines |",
    "| :--- | ---: | ---: | ---: | ---: |"
  ];

  for (const { rel, stats } of rows) {
    lines.push(
      `| \`${rel}\` | ${pct(stats.sCovered, stats.sTotal)} (${stats.sCovered}/${stats.sTotal}) | ${pct(stats.bCovered, stats.bTotal)} (${stats.bCovered}/${stats.bTotal}) | ${pct(stats.fCovered, stats.fTotal)} (${stats.fCovered}/${stats.fTotal}) | ${pct(stats.lCovered, stats.lTotal)} (${stats.lCovered}/${stats.lTotal}) |`
    );
  }

  lines.push(
    `| **Total (Core Protocol)** | **${pct(totals.sCovered, totals.sTotal)}** | **${pct(totals.bCovered, totals.bTotal)}** | **${pct(totals.fCovered, totals.fTotal)}** | **${pct(totals.lCovered, totals.lTotal)}** |`
  );

  const md = lines.join("\n").concat("\n");
  console.log(`\n${md}`);

  const outMdPath = path.join(rootDir, "coverage", "COVERAGE_SUMMARY.md");
  fs.mkdirSync(path.dirname(outMdPath), { recursive: true });
  fs.writeFileSync(outMdPath, md, "utf8");

  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${md}\n`, "utf8");
  }
}

if (require.main === module) {
  main();
}
