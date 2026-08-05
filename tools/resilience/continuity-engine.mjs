#!/usr/bin/env node
/**
 * tools/resilience/continuity-engine.mjs
 *
 * Draft offline continuity artifacts for paper vouchers and proxy-relay intake.
 *
 * Boundary: this tool does not create a valid on-chain mock ZK proof. The
 * current Solidity mock expects a verifier-signed attestation over voter,
 * nullifier, verifier version, and round root before registerVoterWithMockZK.
 *
/**
 * Usage:
 *   node tools/resilience/continuity-engine.mjs generate-voucher <roundId>
 *   node tools/resilience/continuity-engine.mjs verify-offline <voucherPath>
 *   node tools/resilience/continuity-engine.mjs package-relay <vouchersDir> <outputPath> [globalCachePath]
 *
 * Boundary Notice:
 *   The local nullifier cache provides single-operator sequential replay protection on disk.
 *   Cross-process file locking, atomic writes, fsync guarantees, and multi-operator shared authority
 *   remain unresolved gaps for production.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

function getLocalMacSecret() {
  return process.env.LOCAL_MAC_SECRET;
}

const command = process.argv[2];
const MIN_MAC_SECRET_LENGTH = 16;
const REQUIRED_VOUCHER_FIELDS = [
  'roundId',
  'preimage',
  'nullifier',
  'generatedAt',
  'status',
  'proofFormat',
  'warning'
];

function showHelp() {
  console.log(`
Offline Continuity Engine (Draft, Offline Artifacts Only)
=========================================================
Usage:
  node tools/resilience/continuity-engine.mjs generate-voucher <roundId>
  node tools/resilience/continuity-engine.mjs verify-offline <voucherPath>
  node tools/resilience/continuity-engine.mjs package-relay <vouchersDir> <outputPath> [globalCachePath]
`);
  process.exit(1);
}

function requireLocalMacSecret() {
  const secret = getLocalMacSecret();
  if (!secret) {
    console.error('Error: LOCAL_MAC_SECRET is required for voucher generation and verification.');
    console.error('Set it in the local operator environment; do not commit it to the repo.');
    process.exit(1);
  }
  if (secret.length < MIN_MAC_SECRET_LENGTH) {
    console.error(`Error: LOCAL_MAC_SECRET must be at least ${MIN_MAC_SECRET_LENGTH} characters.`);
    console.error('Use a high-entropy local secret managed outside the repository.');
    process.exit(1);
  }
}

function computeVoucherMac(voucher) {
  requireLocalMacSecret();
  const sortedKeys = Object.keys(voucher).filter((key) => key !== 'mac').sort();
  const signedFields = {};
  for (const key of sortedKeys) {
    signedFields[key] = voucher[key] ?? null;
  }

  const message = JSON.stringify(signedFields);
  const hmac = crypto.createHmac('sha256', getLocalMacSecret());
  hmac.update(message);
  return `0x${hmac.digest('hex').slice(0, 16)}`;
}

function assertVoucherShape(voucher) {
  const requiredFields = [...REQUIRED_VOUCHER_FIELDS, 'mac'];
  for (const field of requiredFields) {
    if (!(field in voucher)) {
      console.error(`Schema validation failed: missing field '${field}'`);
      process.exit(1);
    }
  }

  if (typeof voucher.roundId !== 'number' || !Number.isInteger(voucher.roundId) || voucher.roundId <= 0) {
    console.error(`Schema validation failed: 'roundId' must be a positive integer`);
    process.exit(1);
  }

  const hex64Pattern = /^0x[0-9a-fA-F]{64}$/;
  if (typeof voucher.preimage !== 'string' || !hex64Pattern.test(voucher.preimage)) {
    console.error(`Schema validation failed: 'preimage' must be a 32-byte hex string starting with 0x`);
    process.exit(1);
  }

  if (typeof voucher.nullifier !== 'string' || !hex64Pattern.test(voucher.nullifier)) {
    console.error(`Schema validation failed: 'nullifier' must be a 32-byte hex string starting with 0x`);
    process.exit(1);
  }

  if (typeof voucher.mac !== 'string' || !/^0x[0-9a-fA-F]{16}$/.test(voucher.mac)) {
    console.error(`Schema validation failed: 'mac' must be a 16-character hex string starting with 0x`);
    process.exit(1);
  }

  if (typeof voucher.status !== 'string' || voucher.status.trim() === '') {
    console.error(`Schema validation failed: 'status' must be a non-empty string`);
    process.exit(1);
  }

  if (typeof voucher.generatedAt !== 'string' || isNaN(Date.parse(voucher.generatedAt))) {
    console.error(`Schema validation failed: 'generatedAt' must be a valid date string`);
    process.exit(1);
  }

  if (typeof voucher.proofFormat !== 'string' || voucher.proofFormat.trim() === '') {
    console.error(`Schema validation failed: 'proofFormat' must be a non-empty string`);
    process.exit(1);
  }

  if (typeof voucher.warning !== 'string' || voucher.warning.trim() === '') {
    console.error(`Schema validation failed: 'warning' must be a non-empty string`);
    process.exit(1);
  }
}

function assertVoucherMac(voucher) {
  const computedMac = computeVoucherMac(voucher);
  if (computedMac.toLowerCase() !== String(voucher.mac).toLowerCase()) {
    console.error('OFFLINE VERIFICATION FAILED: MAC verification failed against local secret.');
    console.error('Do not treat this voucher as verified. Check the local secret, voucher source, and evidence trail.');
    process.exit(1);
  }
}

export function validateGlobalNullifierCache(vouchers, globalCacheSet = new Set()) {
  const localSeen = new Set(globalCacheSet);
  for (const voucher of vouchers) {
    assertVoucherShape(voucher);
    assertVoucherMac(voucher);
    const nullifier = String(voucher.nullifier).toLowerCase();
    if (localSeen.has(nullifier)) {
      throw new Error(`DUPLICATE_NULLIFIER: Nullifier ${nullifier} already exists in global cache or batch.`);
    }
    localSeen.add(nullifier);
  }
  for (const n of localSeen) {
    globalCacheSet.add(n);
  }
  return true;
}

if (!command) {
  // Module imported without CLI arguments
} else {
  switch (command) {
    case 'test':
      break;

    case 'generate-voucher': {
      requireLocalMacSecret();

      const roundIdArg = process.argv[3];
      if (!roundIdArg) {
        console.error('Error: Missing roundId argument.');
        showHelp();
      }

      const roundId = parseInt(roundIdArg, 10);
      if (isNaN(roundId) || roundId <= 0) {
        console.error('Error: roundId must be a positive integer.');
        process.exit(1);
      }

      const preimage = `0x${crypto.randomBytes(32).toString('hex')}`;
      const nullifier = `0x${crypto.createHash('sha256').update(preimage).digest('hex')}`;

      const voucher = {
        roundId,
        preimage,
        nullifier,
        generatedAt: new Date().toISOString(),
        status: 'pending_sync',
        proofFormat: 'offline-voucher-v1-not-zk-proof',
        warning: 'preimage is bearer recovery material; it is not an on-chain mock ZK proof; voter identity is intentionally not stored'
      };

      voucher.mac = computeVoucherMac(voucher);

      const timestamp = Date.now();
      const filename = `voucher-${roundId}-${timestamp}.json`;
      const filepath = path.join(process.cwd(), 'exports', filename);

      if (!fs.existsSync(path.dirname(filepath))) {
        fs.mkdirSync(path.dirname(filepath), { recursive: true });
      }

      fs.writeFileSync(filepath, JSON.stringify(voucher, null, 2));

      console.log(`
==================================================
OFFLINE PAPER VOUCHER GENERATED
==================================================
Round ID:   ${roundId}
Voter:      not stored in voucher artifact
Nullifier:  0x${nullifier.slice(0, 10)}...
MAC:        ${voucher.mac}
File:       ${filepath}
==================================================
PRINTING GUIDELINES:
- Print the QR code representing the JSON payload.
- Ensure the MAC is clearly legible for manual verification.
- Treat the preimage as bearer recovery material.
- A verifier-signed mock ZK proof is still required before on-chain submission.
==================================================
`);
      break;
    }

    case 'verify-offline': {
      requireLocalMacSecret();

      const voucherPath = process.argv[3];
      if (!voucherPath || !fs.existsSync(voucherPath)) {
        console.error('Error: Voucher file not found.');
        process.exit(1);
      }

      const voucher = JSON.parse(fs.readFileSync(voucherPath, 'utf8'));

      console.log('Starting Local Failsafe / Rising Floor Schema Verification...');
      console.log('Analyzing offline voucher syntax using local rules...');

      assertVoucherShape(voucher);
      assertVoucherMac(voucher);

      console.log('Local MAC Verification: SUCCESS');
      console.log(`
==================================================
OFFLINE SCHEMA VERIFICATION RESULT: PASSED
==================================================
Voter Address:      not stored in voucher artifact
Round ID:           ${voucher.roundId}
Nullifier:          ${voucher.nullifier}
Verified Status:    LOCAL INTEGRITY ONLY (Failsafe baseline satisfied - NOT A ZK PROOF)
==================================================
`);
      break;
    }

    case 'package-relay': {
      requireLocalMacSecret();

      const vouchersDir = process.argv[3];
      const outputPath = process.argv[4];
      const globalCachePath = process.argv[5] || process.env.GLOBAL_NULLIFIER_CACHE;

      if (!vouchersDir || !outputPath) {
        console.error('Error: Missing vouchers directory or output path.');
        showHelp();
      }

      if (!fs.existsSync(vouchersDir)) {
        console.error('Error: Vouchers directory does not exist.');
        process.exit(1);
      }

      const files = fs.readdirSync(vouchersDir).filter((file) => file.endsWith('.json') && file.startsWith('voucher-'));
      const relayBatch = [];
      const batchVouchers = [];
      const globalSeen = new Set();

      if (globalCachePath && fs.existsSync(globalCachePath)) {
        try {
          const cacheData = JSON.parse(fs.readFileSync(globalCachePath, 'utf8'));
          if (!Array.isArray(cacheData)) {
            console.error(`Error: Global nullifier cache at ${globalCachePath} is not a valid JSON array.`);
            process.exit(1);
          }
          for (const n of cacheData) globalSeen.add(String(n).toLowerCase());
        } catch (err) {
          console.error(`Error: Failed to parse global nullifier cache at ${globalCachePath}: ${err.message}`);
          process.exit(1);
        }
      }

      for (const file of files) {
        const filepath = path.join(vouchersDir, file);
        const voucher = JSON.parse(fs.readFileSync(filepath, 'utf8'));
        assertVoucherShape(voucher);
        assertVoucherMac(voucher);

        if (voucher.status === 'pending_sync') {
          batchVouchers.push(voucher);
          relayBatch.push({
            roundId: voucher.roundId,
            nullifier: voucher.nullifier,
            proofRequired: 'verifier-signed mock ZK attestation required before registerVoterWithMockZK'
          });
        }
      }

      try {
        validateGlobalNullifierCache(batchVouchers, globalSeen);
      } catch (err) {
        console.error(`Duplicate nullifier detected while packaging relay batch: ${err.message}`);
        console.error(`Global nullifier cache validation failed: ${err.message}`);
        process.exit(1);
      }

      if (globalCachePath) {
        const updatedCache = Array.from(globalSeen);
        fs.mkdirSync(path.dirname(globalCachePath), { recursive: true });
        fs.writeFileSync(globalCachePath, JSON.stringify(updatedCache, null, 2), 'utf8');
      }

      fs.writeFileSync(outputPath, JSON.stringify(relayBatch, null, 2));

      console.log(`
==================================================
RELAY BATCH PACKAGED FOR REVIEW
==================================================
Total Vouchers:    ${relayBatch.length}
Output File:       ${outputPath}
==================================================
NOT READY FOR ON-CHAIN SUBMISSION:
Each entry still needs a verifier-signed mock ZK attestation.
==================================================
`);
      break;
    }

    default:
      if (['test', 'mocha'].some(t => process.argv[1] && process.argv[1].includes(t))) {
        // Being executed under test runner
      } else {
        console.error(`Unknown command: ${command}`);
        showHelp();
      }
  }
}
