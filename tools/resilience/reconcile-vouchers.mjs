#!/usr/bin/env node
/**
 * tools/resilience/reconcile-vouchers.mjs
 *
 * Deterministic offline-receipt reconciliation tool.
 * Classifies locally verified vouchers against on-chain/mock events.
 */

import fs from 'fs';
import path from 'path';

function entriesFromJson(content) {
  if (Array.isArray(content)) return content;
  if (content && Array.isArray(content.entries)) return content.entries;
  return [content];
}

/**
 * Deterministically classifies vouchers based on on-chain events and duplicate detection.
 *
 * @param {Array} vouchers Array of local vouchers or batch entries with roundId and nullifier.
 * @param {Array} onChainEvents Array of on-chain events/records with roundId and nullifier.
 * @returns {Array} List of classified records.
 */
export function reconcileVouchers(vouchers, onChainEvents) {
  if (!Array.isArray(vouchers)) {
    throw new Error('Vouchers must be an array');
  }
  if (!Array.isArray(onChainEvents)) {
    throw new Error('On-chain events must be an array');
  }

  const onChainSet = new Set();
  for (const event of onChainEvents) {
    if (event && event.roundId !== undefined && event.nullifier !== undefined) {
      const key = `${event.roundId}-${String(event.nullifier).toLowerCase()}`;
      onChainSet.add(key);
    }
  }

  const localCounts = new Map();
  for (const v of vouchers) {
    if (v && v.roundId !== undefined && v.nullifier !== undefined) {
      const key = `${v.roundId}-${String(v.nullifier).toLowerCase()}`;
      localCounts.set(key, (localCounts.get(key) || 0) + 1);
    }
  }

  return vouchers.map((v) => {
    if (!v || v.roundId === undefined || v.nullifier === undefined) {
      return {
        voucher: v,
        classification: 'unresolved',
        detail: 'Invalid voucher schema or missing roundId/nullifier.'
      };
    }

    const nullifierLower = String(v.nullifier).toLowerCase();
    const key = `${v.roundId}-${nullifierLower}`;
    const localCount = localCounts.get(key) || 0;

    let classification = 'unresolved';
    let detail = 'Voucher is local-only and has not been reconciled on-chain.';

    if (localCount > 1) {
      classification = 'duplicate_conflict';
      detail = 'Duplicate nullifier detected within the local voucher batch.';
    } else if (onChainSet.has(key)) {
      classification = 'reconciled';
      detail = 'Successfully matched to an expected on-chain/mock event.';
    }

    return {
      roundId: v.roundId,
      nullifier: v.nullifier,
      classification,
      detail
    };
  });
}

function showHelp() {
  console.log(`
Offline Voucher Reconciliation Tool (Phase 0)
==============================================
Usage:
  node tools/resilience/reconcile-vouchers.mjs <vouchersPathOrDir> <onChainEventsJsonPath>

Classifies locally verified vouchers into one of:
  - reconciled
  - duplicate_conflict
  - unresolved
`);
  process.exit(1);
}

// CLI Runner
async function runCli() {
  const args = process.argv.slice(2);
  if (args.length < 2) {
    showHelp();
  }

  const vouchersPath = args[0];
  const eventsPath = args[1];

  try {
    let vouchers = [];
    if (fs.existsSync(vouchersPath)) {
      const stat = fs.statSync(vouchersPath);
      if (stat.isDirectory()) {
        const files = fs.readdirSync(vouchersPath).filter(f => f.endsWith('.json')).sort();
        for (const file of files) {
          const content = JSON.parse(fs.readFileSync(path.join(vouchersPath, file), 'utf8'));
          vouchers.push(...entriesFromJson(content));
        }
      } else {
        const content = JSON.parse(fs.readFileSync(vouchersPath, 'utf8'));
        vouchers = entriesFromJson(content);
      }
    } else {
      console.error(`Error: Vouchers path not found: ${vouchersPath}`);
      process.exit(1);
    }

    let onChainEvents = [];
    if (fs.existsSync(eventsPath)) {
      const content = JSON.parse(fs.readFileSync(eventsPath, 'utf8'));
      onChainEvents = entriesFromJson(content);
    } else {
      console.error(`Error: On-chain events path not found: ${eventsPath}`);
      process.exit(1);
    }

    const results = reconcileVouchers(vouchers, onChainEvents);
    console.log(JSON.stringify(results, null, 2));
  } catch (err) {
    console.error(`Error running reconciliation: ${err.message}`);
    process.exit(1);
  }
}

// Check if run directly
const isDirectRun = process.argv[1] && (
  process.argv[1].endsWith('reconcile-vouchers.mjs') ||
  process.argv[1].endsWith('reconcile-vouchers')
);

if (isDirectRun) {
  runCli();
}
