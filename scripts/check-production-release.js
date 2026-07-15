/* eslint-disable no-console */

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

function usage() {
  console.log(`
Usage:
  node scripts/check-production-release.js \\
    --parameters deployment/parameters.production.json \\
    --governance deployment/governance-roles.production.json \\
    --audit-report audits/independent-audit-<commit>.md \\
    --scanner-report audits/scanner-evidence-<commit>.md \\
    --deployment-audit artifacts/deployment-audit-<commit>.log

This is the production release gate. It intentionally rejects placeholder
configuration, local-only readiness, unpinned scanner/audit evidence, missing
dashboard build checks, and missing on-chain deployment audit evidence.
`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    args[arg.slice(2)] = argv[i + 1];
    i++;
  }
  return args;
}

function run(label, command, args) {
  console.log(`\n[release gate] ${label}`);
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    encoding: "utf8",
    stdio: "inherit",
  });
  if (result.status !== 0) {
    throw new Error(`${label} failed`);
  }
}

function output(command, args) {
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(`Command failed: ${command} ${args.join(" ")}`);
  }
  return result.stdout.trim();
}

function readEvidence(filePath, label) {
  if (!filePath) throw new Error(`Missing required argument: --${label}`);
  const absolute = path.resolve(filePath);
  if (!fs.existsSync(absolute)) {
    throw new Error(`${label} does not exist: ${filePath}`);
  }
  const stat = fs.statSync(absolute);
  if (!stat.isFile() || stat.size === 0) {
    throw new Error(`${label} must be a non-empty file: ${filePath}`);
  }
  return fs.readFileSync(absolute, "utf8");
}

function requirePinnedEvidence(filePath, label, head) {
  const content = readEvidence(filePath, label);
  if (!content.includes(head)) {
    throw new Error(`${label} must cite current HEAD ${head}: ${filePath}`);
  }
  return content;
}

function rejectTemplatePath(filePath, label) {
  if (!filePath) throw new Error(`Missing required argument: --${label}`);
  const normalized = filePath.toLowerCase();
  if (normalized.includes("template") || normalized.includes("placeholder")) {
    throw new Error(`${label} must point to real deployment config, not a template: ${filePath}`);
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (
    !args.parameters ||
    !args.governance ||
    !args["audit-report"] ||
    !args["scanner-report"] ||
    !args["deployment-audit"]
  ) {
    usage();
    process.exitCode = 1;
    return;
  }

  rejectTemplatePath(args.parameters, "parameters");
  rejectTemplatePath(args.governance, "governance");

  const head = output("git", ["rev-parse", "HEAD"]);
  console.log(`[release gate] HEAD ${head}`);

  requirePinnedEvidence(args["audit-report"], "audit-report", head);
  requirePinnedEvidence(args["scanner-report"], "scanner-report", head);
  const deploymentAudit = requirePinnedEvidence(args["deployment-audit"], "deployment-audit", head);
  if (!deploymentAudit.includes("AUDIT PASSED")) {
    throw new Error("deployment-audit must include AUDIT PASSED evidence");
  }
  if (!deploymentAudit.includes("Strict deployment: true")) {
    throw new Error("deployment-audit must prove strict non-demo deployment auditing");
  }
  if (/Deployment environment:\s*demo/i.test(deploymentAudit)) {
    throw new Error("deployment-audit must not be generated in demo mode");
  }

  run("production readiness", process.execPath, ["scripts/check-readiness.js", "--env", "production"]);
  run("real deployment config", process.execPath, [
    "scripts/validate-deployment-config.js",
    "--parameters",
    args.parameters,
    "--governance",
    args.governance,
  ]);
  run("dashboard frontend build hygiene", process.execPath, ["scripts/check-frontend-build.js"]);

  console.log("\nProduction release gate passed.");
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(`Production release gate failed: ${error.message}`);
    process.exitCode = 1;
  }
}
