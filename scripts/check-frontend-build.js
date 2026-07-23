/* eslint-disable no-console */

const fs = require("node:fs");
const path = require("node:path");

const rootDir = path.resolve(__dirname, "..");
const buildDir = path.join(rootDir, "dist", "dashboard");
const headersPath = path.join(rootDir, "deployment", "hosting.headers.example.json");

const secretPatterns = [
  { name: "OpenAI-style secret key", regex: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { name: "AWS access key", regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "private key PEM", regex: /-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----/ },
  { name: "explicit private key assignment", regex: /\b(?:PRIVATE_KEY|RELAYER_PRIVATE_KEY|DEPLOYER_PRIVATE_KEY)\s*[:=]\s*["']?0x[a-fA-F0-9]{64}/ },
  { name: "service role key assignment", regex: /\b(?:SUPABASE_SERVICE_ROLE_KEY|CLERK_SECRET_KEY|FIREBASE_PRIVATE_KEY|WEBHOOK_SECRET)\s*[:=]/ }
];

function walk(dir) {
  const output = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      output.push(...walk(fullPath));
    } else {
      output.push(fullPath);
    }
  }
  return output;
}

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

function checkScriptTags(html) {
  if (/<script\b(?![^>]*\bsrc=)[^>]*>/i.test(html)) {
    fail("Frontend build contains inline script; production CSP expects local script assets only.");
  }

  const scriptRegex = /<script\s+[^>]*src=["']([^"']+)["'][^>]*>/gi;
  let match;
  while ((match = scriptRegex.exec(html)) !== null) {
    const src = match[1];
    if (/^https?:\/\//i.test(src)) {
      fail(`Frontend build uses remote script source: ${src}`);
    }
  }
}

function checkRemoteLinkTags(html) {
  const linkRegex = /<link\s+[^>]*href=["'](https?:\/\/[^"']+)["'][^>]*>/gi;
  let match;
  while ((match = linkRegex.exec(html)) !== null) {
    fail(`Frontend build uses remote link resource: ${match[1]}`);
  }
}

function checkHeadersConfig() {
  if (!fs.existsSync(headersPath)) {
    fail("Missing deployment/hosting.headers.example.json.");
    return;
  }

  const headers = JSON.parse(fs.readFileSync(headersPath, "utf8"));
  for (const key of [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "X-Frame-Options"
  ]) {
    if (!headers.headers || !headers.headers[key]) {
      fail(`Hosting headers example is missing ${key}.`);
    }
  }

  const csp = headers.headers["Content-Security-Policy"];
  if (/fonts\.googleapis|fonts\.gstatic/i.test(csp)) {
    fail("Hosting headers example allows remote Google font providers.");
  }
  if (!/font-src 'self'/.test(csp)) {
    fail("Hosting headers example must restrict font-src to self.");
  }
}

function checkDistFreshness() {
  const distIndex = path.join(buildDir, "index.html");
  if (!fs.existsSync(distIndex)) {
    fail("Missing dist/dashboard/index.html. Run npm.cmd run build:dashboard first.");
    return;
  }

  const distMtime = fs.statSync(distIndex).mtimeMs;
  const sourceFiles = [
    path.join(rootDir, "dashboard", "index.html"),
    path.join(rootDir, "dashboard", "design-system.css"),
    path.join(rootDir, "scripts", "build-dashboard.js")
  ];

  for (const srcFile of sourceFiles) {
    if (fs.existsSync(srcFile)) {
      const srcMtime = fs.statSync(srcFile).mtimeMs;
      if (srcMtime > distMtime + 1000) {
        fail(`Stale build detected: ${path.relative(rootDir, distIndex)} is older than ${path.relative(rootDir, srcFile)}. Run npm.cmd run build:dashboard.`);
        return;
      }
    }
  }
}

function main() {
  if (!fs.existsSync(buildDir)) {
    fail("Missing dist/dashboard. Run npm.cmd run build:dashboard first.");
    return;
  }

  checkDistFreshness();

  const files = walk(buildDir);
  if (files.length === 0) {
    fail("dist/dashboard is empty.");
    return;
  }

  for (const file of files) {
    const relative = path.relative(rootDir, file);
    if (file.endsWith(".map")) {
      fail(`Public source map found: ${relative}`);
    }

    const content = fs.readFileSync(file, "utf8");
    if (/sourceMappingURL/i.test(content)) {
      fail(`Source map reference found in ${relative}.`);
    }

    for (const pattern of secretPatterns) {
      if (pattern.regex.test(content)) {
        fail(`Potential ${pattern.name} found in ${relative}.`);
      }
    }

    if (path.basename(file) === "index.html") {
      checkScriptTags(content);
      checkRemoteLinkTags(content);
    }
  }

  const manifestPath = path.join(buildDir, "asset-manifest.json");
  if (!fs.existsSync(manifestPath)) {
    fail("Missing dist/dashboard/asset-manifest.json.");
  }

  checkHeadersConfig();

  // Run Brand Compliance Linter (Slice B1 + B4 Staged Guardrail)
  try {
    const { execSync } = require("node:child_process");
    const linterOutput = execSync("python scripts/check-brand-compliance.js", { cwd: rootDir, encoding: "utf8" });
    console.log(linterOutput.trim());
  } catch (err) {
    fail(`Brand compliance linter failed: ${err.stdout || err.message}`);
  }

  if (!process.exitCode) {
    console.log("Frontend production build checks passed.");
  }
}

if (require.main === module) {
  main();
}
