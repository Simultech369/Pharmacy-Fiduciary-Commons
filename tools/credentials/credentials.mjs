import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { canonicalize, verifyCredential } from "./credential-policy.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function usage() {
  console.log(`
Usage:
  node tools/credentials/credentials.mjs key-gen [--out-dir <dir>]
  node tools/credentials/credentials.mjs issue --subject <file> --index <num> --key <private_key_file> --out <file> [--valid-days <days>]
  node tools/credentials/credentials.mjs verify --credential <file> --key <public_key_file> [--voter <address>] [--revocations <file>]
`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) args[argv[i].slice(2)] = argv[i + 1];
  }
  return args;
}

async function main() {
  const command = process.argv[2];
  const args = parseArgs(process.argv.slice(3));

  if (command === "key-gen") {
    const outDir = args["out-dir"] ? path.resolve(args["out-dir"]) : __dirname;
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" }
    });
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(path.join(outDir, "issuer_private.key"), privateKey, { mode: 0o600 });
    fs.writeFileSync(path.join(outDir, "issuer_public.key"), publicKey, { mode: 0o644 });
    console.log(`Keys generated in ${outDir}`);
    return;
  }

  if (command === "issue") {
    const { subject, index = "0", key, out } = args;
    const validDays = Number.parseInt(args["valid-days"] ?? "90", 10);
    if (!subject || !key || !out) {
      usage();
      process.exitCode = 1;
      return;
    }
    if (!Number.isInteger(validDays) || validDays < 1 || validDays > 365) {
      throw new Error("valid-days must be an integer between 1 and 365");
    }

    const subjects = JSON.parse(fs.readFileSync(path.resolve(subject), "utf8"));
    const entry = subjects[Number.parseInt(index, 10)];
    if (!entry) throw new Error(`Subject index ${index} out of range`);

    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + validDays * 24 * 60 * 60 * 1000);
    const credential = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
      ],
      "id": `urn:uuid:${crypto.randomUUID()}`,
      "type": ["VerifiableCredential", entry.type],
      "issuer": "did:web:fiduciarycommons.org",
      "issuanceDate": issuedAt.toISOString(),
      "expirationDate": expiresAt.toISOString(),
      "credentialSubject": entry.subject
    };

    const privateKeyPem = fs.readFileSync(path.resolve(key), "utf8");
    const signature = crypto.sign(null, Buffer.from(canonicalize(credential)), privateKeyPem);
    credential.proof = {
      "type": "Ed25519Signature2020",
      "created": issuedAt.toISOString(),
      "verificationMethod": "did:web:fiduciarycommons.org#key-1",
      "proofPurpose": "assertionMethod",
      "proofValue": signature.toString("hex")
    };

    fs.writeFileSync(path.resolve(out), JSON.stringify(credential, null, 2) + "\n");
    console.log(`Verifiable Credential issued and signed to: ${path.resolve(out)}`);
    return;
  }

  if (command === "verify") {
    const credentialFile = args.credential;
    const keyFile = args.key;
    if (!credentialFile || !keyFile) {
      usage();
      process.exitCode = 1;
      return;
    }

    const credential = JSON.parse(fs.readFileSync(path.resolve(credentialFile), "utf8"));
    const publicKeyPem = fs.readFileSync(path.resolve(keyFile), "utf8");
    const revocationsPath = path.resolve(args.revocations ?? path.join(__dirname, "revoked_credentials.json"));
    const revocations = JSON.parse(fs.readFileSync(revocationsPath, "utf8"));

    try {
      verifyCredential({
        credential,
        publicKeyPem,
        expectedVoter: args.voter,
        revokedCredentialIds: new Set(revocations.revokedCredentialIds ?? [])
      });
      console.log("Credential verification passed.");
    } catch (error) {
      console.error(`Credential verification failed: ${error.message}`);
      process.exitCode = 1;
    }
    return;
  }

  usage();
  process.exitCode = 1;
}

main().catch(error => {
  console.error("Error:", error.message);
  process.exitCode = 1;
});
