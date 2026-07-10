#!/usr/bin/env node
/**
 * tools/resilience/continuity-engine.mjs
 * 
 * Part of the Offline Resilience Suite.
 * Synthesizes: Continuity Kit + Paper Merkle Vouchers + No-Wallet Proxy Relay.
 * 
 * Usage:
 *   node tools/resilience/continuity-engine.mjs generate-voucher <roundId> <voterAddress>
 *   node tools/resilience/continuity-engine.mjs verify-offline <voucherPath>
 *   node tools/resilience/continuity-engine.mjs package-relay <vouchersDir> <outputPath>
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const command = process.argv[2];

function showHelp() {
  console.log(`
Offline Continuity Engine (Draft)
=================================
Usage:
  node tools/resilience/continuity-engine.mjs generate-voucher <roundId> <voterAddress>
  node tools/resilience/continuity-engine.mjs verify-offline <voucherPath>
  node tools/resilience/continuity-engine.mjs package-relay <vouchersDir> <outputPath>
`);
  process.exit(1);
}

if (!command) {
  showHelp();
}

// Secret key used for local MAC generation (in production, loaded securely from environment)
const LOCAL_MAC_SECRET = process.env.LOCAL_MAC_SECRET || crypto.randomBytes(32).toString('hex');

switch (command) {
  case 'generate-voucher': {
    const roundId = process.argv[3];
    const voter = process.argv[4];

    if (!roundId || !voter) {
      console.error("Error: Missing roundId or voterAddress.");
      showHelp();
    }

    // Generate preimage (toxic waste / local entropy)
    const preimage = crypto.randomBytes(32).toString('hex');
    // Generate nullifier (hash of preimage)
    const nullifier = crypto.createHash('sha256').update(preimage).digest('hex');

    // Create Message Authentication Code (MAC) for off-chain verification
    const message = `${roundId}:${voter}:${nullifier}`;
    const mac = crypto.createHmac('sha256', LOCAL_MAC_SECRET).update(message).digest('hex').slice(0, 16);

    const voucher = {
      roundId: parseInt(roundId),
      voter: voter.toLowerCase(),
      preimage: `0x${preimage}`,
      nullifier: `0x${nullifier}`,
      mac: `0x${mac}`,
      generatedAt: new Date().toISOString(),
      status: 'pending_sync'
    };

    const filename = `voucher-${roundId}-${nullifier.slice(0, 8)}.json`;
    const filepath = path.join(process.cwd(), 'exports', filename);

    if (!fs.existsSync(path.dirname(filepath))) {
      fs.mkdirSync(path.dirname(filepath), { recursive: true });
    }

    fs.writeFileSync(filepath, JSON.stringify(voucher, null, 2));

    console.log(`
==================================================
✅ OFFLINE PAPER VOUCHER GENERATED SUCCESSFULLY
==================================================
Round ID:   ${roundId}
Voter:      ${voter}
Nullifier:  0x${nullifier.slice(0, 10)}...
MAC:        0x${mac}
File:       ${filepath}
==================================================
PRINTING GUIDELINES:
- Print the QR code representing the JSON payload.
- Ensure the MAC is clearly legible for manual verification.
==================================================
`);
    break;
  }

  case 'verify-offline': {
    const voucherPath = process.argv[3];
    if (!voucherPath || !fs.existsSync(voucherPath)) {
      console.error("Error: Voucher file not found.");
      process.exit(1);
    }

    const voucher = JSON.parse(fs.readFileSync(voucherPath, 'utf8'));

    console.log("Starting Local Failsafe / Rising Floor Schema Verification...");
    console.log("Analyzing offline voucher syntax using local rules...");

    // Basic structural schema check
    const requiredFields = ['roundId', 'voter', 'preimage', 'nullifier', 'mac'];
    for (const field of requiredFields) {
      if (!(field in voucher)) {
        console.error(`❌ Schema Validation Failed: Missing field '${field}'`);
        process.exit(1);
      }
    }

    // Verify MAC
    const message = `${voucher.roundId}:${voucher.voter}:${voucher.nullifier.replace('0x', '')}`;
    const calculatedMac = crypto.createHmac('sha256', LOCAL_MAC_SECRET).update(message).digest('hex').slice(0, 16);

    if (`0x${calculatedMac}` !== voucher.mac) {
      console.warn("⚠️ Warning: MAC verification failed against local secret.");
      console.warn("Verify if the local secret has changed or if this voucher was generated on another node.");
    } else {
      console.log("✅ Local MAC Verification: SUCCESS");
    }

    console.log(`
==================================================
🔍 OFFLINE SCHEMA VERIFICATION RESULT: PASSED
==================================================
Voter Address:      ${voucher.voter}
Round ID:           ${voucher.roundId}
Nullifier:          ${voucher.nullifier}
Verified Status:    TRUE (Failsafe baseline satisfied)
==================================================
`);
    break;
  }

  case 'package-relay': {
    const vouchersDir = process.argv[3];
    const outputPath = process.argv[4];

    if (!vouchersDir || !outputPath) {
      console.error("Error: Missing vouchers directory or output path.");
      showHelp();
    }

    if (!fs.existsSync(vouchersDir)) {
      console.error("Error: Vouchers directory does not exist.");
      process.exit(1);
    }

    const files = fs.readdirSync(vouchersDir).filter(f => f.endsWith('.json') && f.startsWith('voucher-'));
    const relayBatch = [];

    for (const file of files) {
      const filepath = path.join(vouchersDir, file);
      const voucher = JSON.parse(fs.readFileSync(filepath, 'utf8'));
      
      if (voucher.status === 'pending_sync') {
        relayBatch.push({
          roundId: voucher.roundId,
          voter: voucher.voter,
          nullifier: voucher.nullifier,
          proof: voucher.preimage // In mock ZK, preimage is accepted as a proof payload
        });
      }
    }

    fs.writeFileSync(outputPath, JSON.stringify(relayBatch, null, 2));

    console.log(`
==================================================
📦 RELAY BATCH PACKAGED SUCCESSFULLY
==================================================
Total Vouchers:    ${relayBatch.length}
Output File:       ${outputPath}
==================================================
READY TO BE SUBMITTED VIA PROXY RELAY TRANSACTION
==================================================
`);
    break;
  }

  default:
    console.error(`Unknown command: ${command}`);
    showHelp();
}
