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
 * Usage:
 *   node tools/resilience/continuity-engine.mjs generate-voucher <roundId>
 *   node tools/resilience/continuity-engine.mjs verify-offline <voucherPath>
 *   node tools/resilience/continuity-engine.mjs package-relay <vouchersDir> <outputPath>
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const command = process.argv[2];
const LOCAL_MAC_SECRET = process.env.LOCAL_MAC_SECRET;
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
  node tools/resilience/continuity-engine.mjs package-relay <vouchersDir> <outputPath>
`);
  process.exit(1);
}

function requireLocalMacSecret() {
  if (!LOCAL_MAC_SECRET) {
    console.error('Error: LOCAL_MAC_SECRET is required for voucher generation and verification.');
    console.error('Set it in the local operator environment; do not commit it to the repo.');
    process.exit(1);
  }
  if (LOCAL_MAC_SECRET.length < MIN_MAC_SECRET_LENGTH) {
    console.error(`Error: LOCAL_MAC_SECRET must be at least ${MIN_MAC_SECRET_LENGTH} characters.`);
    console.error('Use a high-entropy local secret managed outside the repository.');
    process.exit(1);
  }
}

function voucherMacMessage(voucher) {
  const sortedKeys = Object.keys(voucher).filter(key => key !== 'mac').sort();
  const signedFields = {};
  for (const key of sortedKeys) {
    signedFields[key] = voucher[key] ?? null;
  }
  return JSON.stringify(signedFields);
}

function calculateVoucherMac(voucher) {
  return crypto
    .createHmac('sha256', LOCAL_MAC_SECRET)
    .update(voucherMacMessage(voucher))
    .digest('hex')
    .slice(0, 16);
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
  const calculatedMac = calculateVoucherMac(voucher);
  if (`0x${calculatedMac}` !== voucher.mac) {
    console.error('OFFLINE VERIFICATION FAILED: MAC verification failed against local secret.');
    console.error('Do not treat this voucher as verified. Check the local secret, voucher source, and evidence trail.');
    process.exit(1);
  }
}

if (!command) {
  showHelp();
}

switch (command) {
  case 'generate-voucher': {
    requireLocalMacSecret();

    const roundId = process.argv[3];

    if (!roundId) {
      console.error('Error: Missing roundId.');
      showHelp();
    }

    const preimage = crypto.randomBytes(32).toString('hex');
    const nullifier = crypto.createHash('sha256').update(preimage).digest('hex');

    const voucher = {
      roundId: parseInt(roundId, 10),
      preimage: `0x${preimage}`,
      nullifier: `0x${nullifier}`,
      mac: 'pending',
      generatedAt: new Date().toISOString(),
      status: 'pending_sync',
      proofFormat: 'offline-voucher-v1-not-zk-proof',
      warning: 'preimage is bearer recovery material; it is not an on-chain mock ZK proof; voter identity is intentionally not stored'
    };
    voucher.mac = `0x${calculateVoucherMac(voucher)}`;

    const filename = `voucher-${roundId}-${nullifier.slice(0, 8)}.json`;
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
    const seenNullifiers = new Set();

    for (const file of files) {
      const filepath = path.join(vouchersDir, file);
      const voucher = JSON.parse(fs.readFileSync(filepath, 'utf8'));
      assertVoucherShape(voucher);
      assertVoucherMac(voucher);

      if (voucher.status === 'pending_sync') {
        const nullifier = String(voucher.nullifier).toLowerCase();
        if (seenNullifiers.has(nullifier)) {
          console.error(`Duplicate nullifier detected while packaging relay batch: ${voucher.nullifier}`);
          console.error('Refusing to create a batch that could revert as a unit during later submission.');
          process.exit(1);
        }
        seenNullifiers.add(nullifier);

        relayBatch.push({
          roundId: voucher.roundId,
          nullifier: voucher.nullifier,
          proofRequired: 'verifier-signed mock ZK attestation required before registerVoterWithMockZK'
        });
      }
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
    console.error(`Unknown command: ${command}`);
    showHelp();
}
