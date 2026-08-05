/* eslint-disable no-console */

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const rootDir = path.resolve(__dirname, "..");
const demoDir = path.join(rootDir, "cache", "local-demo");
const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";
const npxCmd = process.platform === "win32" ? "npx.cmd" : "npx";

function run(label, command, args) {
  console.log(`\n==> ${label}`);
  const result = spawnSync(command, args, {
    cwd: rootDir,
    stdio: "inherit",
    shell: process.platform === "win32"
  });

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function writeSyntheticAllocations() {
  fs.mkdirSync(demoDir, { recursive: true });

  const allocationsPath = path.join(demoDir, "allocations.json");
  const merklePath = path.join(demoDir, "merkle.json");
  const allocations = [
    {
      pharmacy: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      grossAmount: "12450000000000000000000",
      eligibleCap: "12450000000000000000000"
    },
    {
      pharmacy: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
      grossAmount: "8900000000000000000000",
      eligibleCap: "8900000000000000000000"
    }
  ];

  fs.writeFileSync(
    allocationsPath,
    JSON.stringify({ entries: allocations }, null, 2).concat("\n"),
    "utf8"
  );

  return { allocationsPath, merklePath };
}

function main() {
  const { allocationsPath, merklePath } = writeSyntheticAllocations();

  run("Compile contracts", npmCmd, ["run", "compile"]);
  run("Generate synthetic Merkle root and proofs", process.execPath, [
    "tools/merkle/allocations.js",
    "--in",
    allocationsPath,
    "--out",
    merklePath
  ]);
  run("Run portability claim/export verification slice", npxCmd, [
    "hardhat",
    "test",
    "test/PortabilityExport.test.js"
  ]);
  run("Run patient fund matching slice", npxCmd, [
    "hardhat",
    "test",
    "test/PatientFundParticipatoryBudgeting.test.js"
  ]);
  run("Build static dashboard assets", npmCmd, ["run", "build:dashboard"]);
  run("Check dashboard production bundle", npmCmd, ["run", "check:frontend"]);

  console.log("\nLocal demo completed.");
  console.log(`Synthetic allocations: ${path.relative(rootDir, allocationsPath)}`);
  console.log(`Merkle output: ${path.relative(rootDir, merklePath)}`);
  console.log("Dashboard build: dist/dashboard/index.html");
  console.log("Open dist/dashboard/index.html and start with the First Run Receipt Flow panel.");
}

if (require.main === module) {
  main();
}
