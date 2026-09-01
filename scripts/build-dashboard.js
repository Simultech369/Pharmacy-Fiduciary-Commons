/* eslint-disable no-console */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const rootDir = path.resolve(__dirname, "..");
const sourceDir = path.join(rootDir, "dashboard");
const outputDir = path.join(rootDir, "dist", "dashboard");

function assertInsideRoot(targetPath) {
  const relative = path.relative(rootDir, targetPath);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`Refusing to write outside repository root: ${targetPath}`);
  }
}

function ensureCleanDir(dir) {
  assertInsideRoot(dir);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
}

function sha256(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function minifyCss(css) {
  return css
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\s+/g, " ")
    .replace(/\s*([{}:;,>])\s*/g, "$1")
    .replace(/;}/g, "}")
    .trim();
}

function minifyJsConservatively(js) {
  return js
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("//"))
    .join("\n")
    .concat("\n");
}

function buildHtml() {
  const sourcePath = path.join(sourceDir, "index.html");
  let html = fs.readFileSync(sourcePath, "utf8");
  const inlineScripts = [];

  html = html.replace(/<style>([\s\S]*?)<\/style>/i, (_match, css) => {
    return `<style>${minifyCss(css)}</style>`;
  });

  let inlineScriptInserted = false;
  html = html.replace(/<script>([\s\S]*?)<\/script>/gi, (_match, js) => {
    inlineScripts.push(js);
    if (inlineScriptInserted) return "";
    inlineScriptInserted = true;
    return '<script src="./dashboard-inline.min.js"></script>';
  });

  html = html
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/href="\.\.\/ONBOARDING\.md"/g, 'href="ONBOARDING.md"')
    .replace(/href="\.\.\/docs\//g, 'href="docs/')
    .replace(/<script src="\.\/web3_integration\.js"><\/script>/g, '<script src="./web3_integration.min.js"></script>')
    .replace(/>\s+</g, "><")
    .trim()
    .concat("\n");

  fs.writeFileSync(path.join(outputDir, "index.html"), html);
  fs.writeFileSync(path.join(outputDir, "dashboard-inline.min.js"), minifyJsConservatively(inlineScripts.join("\n")));
}

function writeManifest(files) {
  const manifest = {
    generatedAt: new Date().toISOString(),
    source: "dashboard",
    warning: "Static dashboard build only. Do not publish without running check:frontend.",
    files: files.map((file) => {
      const filePath = path.join(outputDir, file);
      return {
        path: file,
        bytes: fs.statSync(filePath).size,
        sha256: sha256(filePath)
      };
    })
  };

  fs.writeFileSync(
    path.join(outputDir, "asset-manifest.json"),
    JSON.stringify(manifest, null, 2).concat("\n")
  );
}

function main() {
  ensureCleanDir(outputDir);

  buildHtml();

  const web3Source = fs.readFileSync(path.join(sourceDir, "web3_integration.js"), "utf8");
  fs.writeFileSync(path.join(outputDir, "web3_integration.min.js"), minifyJsConservatively(web3Source));

  const cssSource = fs.readFileSync(path.join(sourceDir, "design-system.css"), "utf8");
  fs.writeFileSync(path.join(outputDir, "design-system.css"), minifyCss(cssSource));

  fs.copyFileSync(
    path.join(sourceDir, "ethers.umd.min.js"),
    path.join(outputDir, "ethers.umd.min.js")
  );

  fs.copyFileSync(
    path.join(sourceDir, "supabase.js"),
    path.join(outputDir, "supabase.js")
  );

  const assetsSourceDir = path.join(sourceDir, "assets");
  const assetsOutputDir = path.join(outputDir, "assets");
  if (fs.existsSync(assetsSourceDir)) {
    fs.mkdirSync(assetsOutputDir, { recursive: true });
    for (const file of fs.readdirSync(assetsSourceDir)) {
      fs.copyFileSync(path.join(assetsSourceDir, file), path.join(assetsOutputDir, file));
    }
  }

  const docsToCopy = [
    "ONBOARDING.md",
    "NEXT.md",
    "README.md",
    "PORTABILITY.md",
    "GOVERNANCE.md",
    "docs/ops/MECHANISM_COVERAGE.md",
    "docs/ops/OPEN_DESIGN_DECISIONS.md",
    "docs/ops/PRODUCTION_READINESS_CHECKLIST.md",
    "docs/design/CARE_CONTINUITY.md",
    "docs/design/IDENTITY_NULLIFIER_DESIGN.md",
    "docs/design/RETALIATION_AND_PRIVACY_THREAT_MODEL.md",
    "docs/design/SCARCITY_GOVERNANCE.md"
  ];
  for (const docFile of docsToCopy) {
    const srcDoc = path.join(rootDir, docFile);
    if (fs.existsSync(srcDoc)) {
      const destDoc = path.join(outputDir, docFile);
      fs.mkdirSync(path.dirname(destDoc), { recursive: true });
      fs.copyFileSync(srcDoc, destDoc);
    }
  }

  writeManifest(["index.html", "dashboard-inline.min.js", "design-system.css", "web3_integration.min.js", "ethers.umd.min.js", "supabase.js", ...docsToCopy.filter(f => fs.existsSync(path.join(rootDir, f)))]);

  console.log(`Dashboard production assets written to ${path.relative(rootDir, outputDir)}`);
}

if (require.main === module) {
  main();
}
