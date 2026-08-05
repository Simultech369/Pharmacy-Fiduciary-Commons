/**
 * Pharmacy Fiduciary Commons — Native State Machine Verifier
 * Enforces explicit, fail-closed state transition bounds for:
 * 1. Treasury Debt Queues (UNFUNDED -> ALLOCATED -> DISBURSED -> RECALLED)
 * 2. Participatory Budgeting Rounds (INACTIVE -> PROPOSAL_SUBMISSION -> VOTING_ACTIVE -> TALLYING -> FINALIZED)
 * 3. Offline Continuity Vouchers (ISSUED -> CACHE_VERIFIED -> ONLINE_SYNCED -> SETTLED)
 */

export const DEBT_QUEUE_STATES = Object.freeze({
  UNFUNDED: 'UNFUNDED',
  ALLOCATED: 'ALLOCATED',
  DISBURSED: 'DISBURSED',
  RECALLED: 'RECALLED',
});

export const VALID_DEBT_TRANSITIONS = Object.freeze({
  UNFUNDED: [DEBT_QUEUE_STATES.ALLOCATED],
  ALLOCATED: [DEBT_QUEUE_STATES.DISBURSED, DEBT_QUEUE_STATES.UNFUNDED],
  DISBURSED: [DEBT_QUEUE_STATES.RECALLED],
  RECALLED: [],
});

export const BUDGETING_ROUND_STATES = Object.freeze({
  INACTIVE: 'INACTIVE',
  PROPOSAL_SUBMISSION: 'PROPOSAL_SUBMISSION',
  VOTING_ACTIVE: 'VOTING_ACTIVE',
  TALLYING: 'TALLYING',
  FINALIZED: 'FINALIZED',
});

export const VALID_BUDGETING_TRANSITIONS = Object.freeze({
  INACTIVE: [BUDGETING_ROUND_STATES.PROPOSAL_SUBMISSION],
  PROPOSAL_SUBMISSION: [BUDGETING_ROUND_STATES.VOTING_ACTIVE],
  VOTING_ACTIVE: [BUDGETING_ROUND_STATES.TALLYING],
  TALLYING: [BUDGETING_ROUND_STATES.FINALIZED],
  FINALIZED: [BUDGETING_ROUND_STATES.INACTIVE],
});

export const OFFLINE_VOUCHER_STATES = Object.freeze({
  ISSUED: 'ISSUED',
  CACHE_VERIFIED: 'CACHE_VERIFIED',
  ONLINE_SYNCED: 'ONLINE_SYNCED',
  SETTLED: 'SETTLED',
});

export const VALID_VOUCHER_TRANSITIONS = Object.freeze({
  ISSUED: [OFFLINE_VOUCHER_STATES.CACHE_VERIFIED],
  CACHE_VERIFIED: [OFFLINE_VOUCHER_STATES.ONLINE_SYNCED],
  ONLINE_SYNCED: [OFFLINE_VOUCHER_STATES.SETTLED],
  SETTLED: [],
});

/**
 * Validates a state transition against allowed target states.
 * Throws a detailed error if the transition is invalid.
 */
export function validateStateTransition(current, next, allowedTransitionsMap, domainName) {
  if (!current || !next) {
    throw new Error(`[${domainName}] Invalid state parameters: current=${current}, next=${next}`);
  }
  const allowed = allowedTransitionsMap[current];
  if (!allowed) {
    throw new Error(`[${domainName}] Unknown current state: '${current}'`);
  }
  if (!allowed.includes(next)) {
    throw new Error(
      `[${domainName}] Forbidden state transition: '${current}' -> '${next}'. Allowed target states: [${allowed.join(', ')}]`
    );
  }
  return true;
}

export function transitionDebtState(current, next) {
  validateStateTransition(current, next, VALID_DEBT_TRANSITIONS, 'DebtQueue');
  return next;
}

export function transitionBudgetingRound(current, next) {
  validateStateTransition(current, next, VALID_BUDGETING_TRANSITIONS, 'ParticipatoryBudgeting');
  return next;
}

export function transitionOfflineVoucher(current, next) {
  validateStateTransition(current, next, VALID_VOUCHER_TRANSITIONS, 'OfflineVoucher');
  return next;
}
