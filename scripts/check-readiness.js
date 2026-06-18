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

function main() {
  const args = parseArgs(process.argv.slice(2));
  const env = args.env;

  if (!env || !["local", "public", "production"].includes(env)) {
    usage();
    process.exitCode = 1;
    return;
  }

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

module.exports = { uncheckedItems };
