/**
 * Care Continuity & Human Capabilities Metric Calculator
 * 
 * Computes human-centered health adherence metrics for Pharmacy Fiduciary Commons:
 * - Continuous Refill Ratio (CRR): % of chronic refills within <= 3-day clinical schedule variance.
 * - Emergency Fill Access (EFA): % of pharmacies meeting 30-day mutual credit capacity targets.
 * - Non-Digital Workflow Adoption (NDWA): % of offline paper/voucher/proxy claims vs web wallet claims.
 * 
 * Privacy & Security Boundary:
 * All patient identity inputs must be pre-hashed or synthetic. Direct PHI / NPI linkages are strictly forbidden.
 */

export function calculateCRR(refillRecords) {
  if (!Array.isArray(refillRecords) || refillRecords.length === 0) {
    return { crr: 0, total: 0, compliantCount: 0, advisoryAlert: false };
  }

  let compliantCount = 0;
  for (const record of refillRecords) {
    if (!record || typeof record.varianceDays !== 'number') {
      continue;
    }
    if (Math.abs(record.varianceDays) <= 3) {
      compliantCount++;
    }
  }

  const crr = (compliantCount / refillRecords.length) * 100;
  const advisoryAlert = crr < 90.0;

  return {
    crr: Number(crr.toFixed(2)),
    total: refillRecords.length,
    compliantCount,
    advisoryAlert,
    targetMet: crr >= 95.0
  };
}

export function calculateEFA(pharmacyCreditRecords) {
  if (!Array.isArray(pharmacyCreditRecords) || pharmacyCreditRecords.length === 0) {
    return { efaRatio: 0, total: 0, compliantCount: 0 };
  }

  let compliantCount = 0;
  for (const p of pharmacyCreditRecords) {
    if (!p || typeof p.currentCreditLimit !== 'number' || typeof p.thirtyDayDemand !== 'number') {
      continue;
    }
    if (p.currentCreditLimit >= p.thirtyDayDemand) {
      compliantCount++;
    }
  }

  const efaRatio = (compliantCount / pharmacyCreditRecords.length) * 100;

  return {
    efaRatio: Number(efaRatio.toFixed(2)),
    total: pharmacyCreditRecords.length,
    compliantCount,
    targetMet: efaRatio >= 100.0
  };
}

export function calculateNDWA(transactionRecords) {
  if (!Array.isArray(transactionRecords) || transactionRecords.length === 0) {
    return { ndwaRatio: 0, total: 0, offlineCount: 0 };
  }

  let offlineCount = 0;
  for (const tx of transactionRecords) {
    if (tx && (tx.channel === 'offline_voucher' || tx.channel === 'sms' || tx.channel === 'paper_proxy')) {
      offlineCount++;
    }
  }

  const ndwaRatio = (offlineCount / transactionRecords.length) * 100;

  return {
    ndwaRatio: Number(ndwaRatio.toFixed(2)),
    total: transactionRecords.length,
    offlineCount,
    targetMet: ndwaRatio >= 20.0
  };
}

export function generateCareContinuityReport(refillRecords, creditRecords, txRecords) {
  const crrResult = calculateCRR(refillRecords);
  const efaResult = calculateEFA(creditRecords);
  const ndwaResult = calculateNDWA(txRecords);

  return {
    timestamp: new Date().toISOString(),
    metrics: {
      continuousRefillRatio: crrResult,
      emergencyFillAccess: efaResult,
      nonDigitalWorkflowAdoption: ndwaResult
    },
    advisoryActionRequired: crrResult.advisoryAlert,
    provenance: "Synthetic / Hashed Local Care Continuity Calculator"
  };
}
