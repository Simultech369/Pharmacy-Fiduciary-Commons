/* eslint-disable no-console */

const fs = require("node:fs");
const path = require("node:path");

function usage() {
  console.log(`
Usage:
  node scripts/check-readiness.js --env <local|public|production>

For public or production exposure, this script fails while any unchecked item
remains in PRODUCTION_READINESS_CHECKLIST.md.
`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      args[arg.slice(2)] = argv[i + 1];
    }
  }
  return args;
}

function uncheckedItems(markdown) {
  return markdown
    .split(/\r?\n/)
    .map((line, index) => ({ line, number: index + 1 }))
    .filter(item => /^\s*-\s+\[\s\]\s+/.test(item.line));
}

function walkFiles(dir) {
  const files = [];
  if (!fs.existsSync(dir)) return files;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkFiles(fullPath));
    } else {
      files.push(fullPath);
    }
  }
  return files;
}

function checkMechanicalSafety() {
  let failed = false;

  // 1. Check for .env file
  const envPath = path.resolve(process.cwd(), ".env");
  if (fs.existsSync(envPath)) {
    console.error("Safety violation: .env file exists in the project root.");
    failed = true;
  }

  // 2. Check for .map files in dashboard source and production build output.
  for (const scanDir of ["dashboard", path.join("dist", "dashboard")]) {
    const dashboardDir = path.resolve(process.cwd(), scanDir);
    for (const filePath of walkFiles(dashboardDir)) {
      if (filePath.endsWith(".map")) {
        console.error(`Safety violation: source map file found: ${path.relative(process.cwd(), filePath)}`);
        failed = true;
      }
    }
  }

  // 3. Scan dashboard/index.html for innerHTML and CDN integrity
  const sourceDashboardDir = path.resolve(process.cwd(), "dashboard");
  const indexPath = path.resolve(sourceDashboardDir, "index.html");
  if (fs.existsSync(indexPath)) {
    const htmlContent = fs.readFileSync(indexPath, "utf8");

    // Check innerHTML assignments that are not empty string
    const innerHtmlRegex = /\.innerHTML\s*=\s*(?!\s*(["'`])\1\s*;?)/g;
    let match;
    while ((match = innerHtmlRegex.exec(htmlContent)) !== null) {
      const lines = htmlContent.substring(0, match.index).split("\n");
      const lineNum = lines.length;
      console.error(`Safety violation: Unsafe innerHTML assignment in dashboard/index.html at line ${lineNum}: ${lines[lineNum - 1].trim()}`);
      failed = true;
    }

    // Check script tags from CDN (src starts with http) and make sure they have integrity
    const scriptRegex = /<script\s+[^>]*src=["'](http[^"']+)["'][^>]*>/gi;
    while ((match = scriptRegex.exec(htmlContent)) !== null) {
      const tag = match[0];
      if (!tag.includes("integrity=")) {
        const lines = htmlContent.substring(0, match.index).split("\n");
        console.error(`Safety violation: CDN script tag in dashboard/index.html lacks integrity attribute at line ${lines.length}: ${tag.trim()}`);
        failed = true;
      }
    }

    const linkRegex = /<link\s+[^>]*href=["'](https?:\/\/[^"']+)["'][^>]*>/gi;
    while ((match = linkRegex.exec(htmlContent)) !== null) {
      const lines = htmlContent.substring(0, match.index).split("\n");
      console.error(`Safety violation: remote link resource in dashboard/index.html at line ${lines.length}: ${match[0].trim()}`);
      failed = true;
    }
  }

  return !failed;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const env = args.env;

  if (!env || !["local", "public", "production"].includes(env)) {
    usage();
    process.exitCode = 1;
    return;
  }

  console.log("Running mechanical safety checks...");
  const safetyPassed = checkMechanicalSafety();
  if (!safetyPassed) {
    console.error("Mechanical safety checks failed!");
    process.exitCode = 1;
    return;
  }
  console.log("✅ Mechanical safety checks passed.");

  const checklistPath = path.resolve(process.cwd(), "PRODUCTION_READINESS_CHECKLIST.md");
  const markdown = fs.readFileSync(checklistPath, "utf8");
  const openItems = uncheckedItems(markdown);

  if (env === "local") {
    console.log(`Local readiness check: ${openItems.length} open checklist items are allowed for prototype work.`);
    return;
  }

  if (openItems.length > 0) {
    console.error(`${env} readiness blocked: ${openItems.length} unchecked item(s) remain.`);
    for (const item of openItems.slice(0, 20)) {
      console.error(`- ${checklistPath}:${item.number} ${item.line.trim()}`);
    }
    if (openItems.length > 20) {
      console.error(`- ...and ${openItems.length - 20} more.`);
    }
    process.exitCode = 1;
    return;
  }

  console.log(`${env} readiness check passed: no unchecked production-readiness items remain.`);
}

if (require.main === module) {
  main();
}

module.exports = { uncheckedItems, checkMechanicalSafety };
