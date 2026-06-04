import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function usage() {
  console.log(`
Usage:
  node tools/credentials/credentials.mjs key-gen [--out-dir <dir>]
  node tools/credentials/credentials.mjs issue --subject <file> --index <num> --key <private_key_file> --out <file>
  node tools/credentials/credentials.mjs verify --credential <file> --key <public_key_file>
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

// Canonicalize the object for reliable signing (sort keys recursively)
function canonicalize(obj) {
  function sortKeys(value) {
    if (value === null || typeof value !== "object") {
      return value;
    }
    if (Array.isArray(value)) {
      return value.map(sortKeys);
    }
    const sorted = {};
    const keys = Object.keys(value).sort();
    for (const key of keys) {
      sorted[key] = sortKeys(value[key]);
    }
    return sorted;
  }
  return JSON.stringify(sortKeys(obj));
}

async function main() {
  const command = process.argv[2];
  const args = parseArgs(process.argv.slice(3));

  if (command === "key-gen") {
    const outDir = args["out-dir"] ? path.resolve(process.cwd(), args["out-dir"]) : __dirname;
    
    console.log("Generating Ed25519 Key Pair...");
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" }
    });

    const privPath = path.join(outDir, "issuer_private.key");
    const pubPath = path.join(outDir, "issuer_public.key");

    fs.writeFileSync(privPath, privateKey);
    fs.writeFileSync(pubPath, publicKey);

    console.log("Keys generated successfully:");
    console.log(`  Private Key: ${privPath}`);
    console.log(`  Public Key:  ${pubPath}`);

  } else if (command === "issue") {
    const subjectFile = args["subject"];
    const index = parseInt(args["index"] ?? "0", 10);
    const keyFile = args["key"];
    const outFile = args["out"];

    if (!subjectFile || !keyFile || !outFile) {
      usage();
      process.exitCode = 1;
      return;
    }

    const subjects = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), subjectFile), "utf8"));
    const entry = subjects[index];
    if (!entry) {
      throw new Error(`Subject index ${index} out of range`);
    }

    const privateKeyPem = fs.readFileSync(path.resolve(process.cwd(), keyFile), "utf8");

    const vc = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
      ],
      "id": `urn:uuid:${crypto.randomUUID()}`,
      "type": ["VerifiableCredential", entry.type],
      "issuer": "did:web:fiduciarycommons.org",
      "issuanceDate": new Date().toISOString(),
      "credentialSubject": entry.subject
    };

    // Sign the canonicalized representation of the inner VC
    const payload = canonicalize(vc);
    const signature = crypto.sign(null, Buffer.from(payload), privateKeyPem);
    const signatureHex = signature.toString("hex");

    vc.proof = {
      "type": "Ed25519Signature2020",
      "created": new Date().toISOString(),
      "verificationMethod": "did:web:fiduciarycommons.org#key-1",
      "proofPurpose": "assertionMethod",
      "proofValue": signatureHex
    };

    const outPath = path.resolve(process.cwd(), outFile);
    fs.writeFileSync(outPath, JSON.stringify(vc, null, 2) + "\n");
    console.log(`Verifiable Credential issued and signed to: ${outPath}`);

  } else if (command === "verify") {
    const credFile = args["credential"];
    const keyFile = args["key"];

    if (!credFile || !keyFile) {
      usage();
      process.exitCode = 1;
      return;
    }

    const vc = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), credFile), "utf8"));
    const publicKeyPem = fs.readFileSync(path.resolve(process.cwd(), keyFile), "utf8");

    if (!vc.proof || !vc.proof.proofValue) {
      console.error("Verification Failed: Missing cryptographic proof signature!");
      process.exitCode = 1;
      return;
    }

    const signatureHex = vc.proof.proofValue;
    
    // To verify, we strip the signature and check the payload
    const vcToVerify = { ...vc };
    delete vcToVerify.proof;

    const payload = canonicalize(vcToVerify);
    const signatureBuffer = Buffer.from(signatureHex, "hex");

    const isValid = crypto.verify(null, Buffer.from(payload), publicKeyPem, signatureBuffer);

    if (isValid) {
      console.log("\n==================================================");
      console.log("✅ VERIFICATION SUCCESSFUL: Cryptographic proof is VALID.");
      console.log("==================================================");
      console.log(`Type:       ${vc.type.join(", ")}`);
      console.log(`Issuer:     ${vc.issuer}`);
      console.log(`Subject ID: ${vc.credentialSubject.id}`);
      console.log(`Claims:`);
      for (const [k, v] of Object.entries(vc.credentialSubject)) {
        if (k !== "id") console.log(`  ${k}: ${v}`);
      }
      console.log("==================================================\n");
    } else {
      console.error("\n==================================================");
      console.error("❌ VERIFICATION FAILED: Invalid signature or modified payload!");
      console.error("==================================================\n");
      process.exitCode = 1;
    }
  } else {
    usage();
    process.exitCode = 1;
  }
}

main().catch(err => {
  console.error("Error:", err.message);
  process.exitCode = 1;
});
