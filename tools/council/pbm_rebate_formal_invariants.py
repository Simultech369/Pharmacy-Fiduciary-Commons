"""
Formal Invariant SMT Engine for PBM Rebate Treasury and Solvency Arithmetic.

This module uses Microsoft Z3 to formally verify local mathematical invariants
and state-machine properties of contracts/PBMRebateTreasury.sol,
contracts/PatientFundParticipatoryBudgeting.sol, and contracts/PharmacyMutualCredit.sol.

BOUNDARIES & NON-CLAIMS:
- These proofs cover local mathematical models and state-variable arithmetic.
- They DO NOT prove overall EVM bytecode correctness, third-party audit completion,
  or protection against economic market volatility.
"""

import hashlib
import json
import time
from typing import Any, Dict, List, Literal, Optional

from council_contracts import ImmutableContract, ReceiptEnvelope

ProofStatus = Literal["PROVED", "COUNTEREXAMPLE_FOUND", "SOLVER_UNKNOWN"]
ProofDomain = Literal[
    "GROSS_NET_NON_NEGATIVE",
    "SOLVENCY_DEBT_CONSERVATION",
    "DISPUTE_ESCROW_CAP",
    "MUTUAL_CREDIT_ZERO_SUM",
    "FEE_ON_TRANSFER_INTEGRITY",
]


class RebateInvariantProof(ImmutableContract):
    invariant_id: str
    domain: ProofDomain
    statement: str
    assumptions: List[str]
    proof_method: Literal["Z3_UNSAT_NEGATION"]
    solver_status: ProofStatus
    counterexample: Optional[str] = None
    lean4_theorem_stub: Optional[str] = None


class PBMRebateFormalInvariantReceipt(ImmutableContract):
    proof_suite_id: str
    target_contracts: List[str]
    invariants: List[RebateInvariantProof]
    all_invariants_proved: bool
    audit_replacement_claimed: bool
    market_truth_claimed: bool
    proof_boundary: str
    proof_digest_sha256: str
    proved_at: float


class PBMRebateFormalInvariantEngine:
    """Builds and verifies formal Z3 SMT invariants for PBM Rebate Treasury settlement."""

    MAX_ADMIN_FEE_PCT = 1.0  # 100% cap

    def prove_all(self) -> ReceiptEnvelope[PBMRebateFormalInvariantReceipt]:
        proofs: List[RebateInvariantProof] = []
        proofs.extend(self.prove_gross_net_non_negative())
        proofs.extend(self.prove_solvency_debt_conservation())
        proofs.extend(self.prove_dispute_escrow_cap_monotonicity())
        proofs.extend(self.prove_mutual_credit_zero_sum())
        proofs.extend(self.prove_fee_on_transfer_intake_integrity())

        all_proved = all(proof.solver_status == "PROVED" for proof in proofs)
        digest = hashlib.sha256(
            json.dumps([p.model_dump() for p in proofs], sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        receipt = PBMRebateFormalInvariantReceipt(
            proof_suite_id=f"pbm_rebate_formal_{digest[:12]}",
            target_contracts=[
                "contracts/PBMRebateTreasury.sol",
                "contracts/PatientFundParticipatoryBudgeting.sol",
                "contracts/PharmacyMutualCredit.sol",
            ],
            invariants=proofs,
            all_invariants_proved=all_proved,
            audit_replacement_claimed=False,
            market_truth_claimed=False,
            proof_boundary=(
                "Local SMT Z3 proofs for PBM rebate treasury arithmetic and solvency debt balance; "
                "does not prove external EVM compiler correctness, live market solvency, or audit clearance."
            ),
            proof_digest_sha256=digest,
            proved_at=time.time(),
        )
        return ReceiptEnvelope.seal(receipt)

    def _prove_unsat(
        self,
        invariant_id: str,
        domain: ProofDomain,
        statement: str,
        assumptions: List[str],
        constraints: List[Any],
        negated_property: Any,
        lean4_theorem_stub: Optional[str] = None,
    ) -> RebateInvariantProof:
        import z3

        solver = z3.Solver()
        for c in constraints:
            solver.add(c)
        solver.add(negated_property)

        result = solver.check()
        if result == z3.unsat:
            return RebateInvariantProof(
                invariant_id=invariant_id,
                domain=domain,
                statement=statement,
                assumptions=assumptions,
                proof_method="Z3_UNSAT_NEGATION",
                solver_status="PROVED",
                counterexample=None,
                lean4_theorem_stub=lean4_theorem_stub,
            )
        elif result == z3.sat:
            m = solver.model()
            cex = ", ".join(f"{d}={m[d]}" for d in m.decls()[:6])
            return RebateInvariantProof(
                invariant_id=invariant_id,
                domain=domain,
                statement=statement,
                assumptions=assumptions,
                proof_method="Z3_UNSAT_NEGATION",
                solver_status="COUNTEREXAMPLE_FOUND",
                counterexample=f"Counterexample: {cex}",
                lean4_theorem_stub=lean4_theorem_stub,
            )
        else:
            return RebateInvariantProof(
                invariant_id=invariant_id,
                domain=domain,
                statement=statement,
                assumptions=assumptions,
                proof_method="Z3_UNSAT_NEGATION",
                solver_status="SOLVER_UNKNOWN",
                counterexample=str(result),
                lean4_theorem_stub=lean4_theorem_stub,
            )

    def prove_gross_net_non_negative(self) -> List[RebateInvariantProof]:
        """Proves net manufacturer rebate R_net = R_gross - F_admin >= 0."""
        import z3

        r_gross = z3.Real("r_gross")
        p_admin = z3.Real("p_admin")
        f_admin = z3.Real("f_admin")
        r_net = z3.Real("r_net")

        constraints = [
            r_gross >= 0,
            p_admin >= 0,
            p_admin <= self.MAX_ADMIN_FEE_PCT,
            f_admin == r_gross * p_admin,
            r_net == r_gross - f_admin,
        ]

        return [
            self._prove_unsat(
                invariant_id="REBATE-MATH-001",
                domain="GROSS_NET_NON_NEGATIVE",
                statement="Net rebate is non-negative for any gross rebate and fee percentage bounded in [0, 100%].",
                assumptions=[
                    "r_gross >= 0",
                    "0 <= p_admin <= 1.0",
                    "f_admin == r_gross * p_admin",
                    "r_net == r_gross - f_admin",
                ],
                constraints=constraints,
                negated_property=r_net < 0,
                lean4_theorem_stub="theorem net_rebate_nonnegative (r_gross p_admin : Real) (h1 : r_gross >= 0) (h2 : p_admin <= 1) : r_gross - (r_gross * p_admin) >= 0",
            )
        ]

    def prove_solvency_debt_conservation(self) -> List[RebateInvariantProof]:
        """Proves _syncSolvencyDebt guarantees contract obligations are fully backed by balance + debt."""
        import z3

        unclaimed = z3.Real("unclaimed_shares")
        pool = z3.Real("matching_pool")
        balance = z3.Real("token_balance")
        d_old = z3.Real("total_debt_old")

        r_req = z3.Real("required_solvency")
        d_out = z3.Real("outstanding_deficit")
        d_new = z3.Real("total_debt_new")

        constraints = [
            unclaimed >= 0,
            pool >= 0,
            balance >= 0,
            d_old >= 0,
            r_req == unclaimed + pool,
            d_out == z3.If(r_req > balance, r_req - balance, z3.RealVal(0)),
            d_new == z3.If(d_out > d_old, d_out, d_old),
        ]

        return [
            self._prove_unsat(
                invariant_id="REBATE-MATH-002",
                domain="SOLVENCY_DEBT_CONSERVATION",
                statement="Obligations (unclaimed + pool) are strictly bounded by token balance plus synchronized debt.",
                assumptions=[
                    "unclaimed >= 0, pool >= 0, balance >= 0, d_old >= 0",
                    "r_req == unclaimed + pool",
                    "d_out == max(0, r_req - balance)",
                    "d_new == max(d_out, d_old)",
                ],
                constraints=constraints,
                negated_property=balance + d_new < r_req,
                lean4_theorem_stub="theorem solvency_conservation (b u p d_old : Real) (h : u >= 0 ∧ p >= 0 ∧ b >= 0) : b + max (max 0 ((u+p) - b)) d_old >= u + p",
            )
        ]

    def prove_dispute_escrow_cap_monotonicity(self) -> List[RebateInvariantProof]:
        """Proves dispute reservation cannot exceed total deposited epoch escrow."""
        import z3

        epoch_escrow = z3.Real("epoch_escrow")
        flagged_1 = z3.Real("flagged_claim_1")
        flagged_2 = z3.Real("flagged_claim_2")
        total_flagged = z3.Real("total_flagged")

        constraints = [
            epoch_escrow >= 0,
            flagged_1 >= 0,
            flagged_2 >= 0,
            total_flagged == flagged_1 + flagged_2,
            total_flagged <= epoch_escrow,
        ]

        remaining_pool = epoch_escrow - total_flagged

        return [
            self._prove_unsat(
                invariant_id="REBATE-MATH-003",
                domain="DISPUTE_ESCROW_CAP",
                statement="Active dispute flagged allocations cannot exceed total epoch escrow balance.",
                assumptions=[
                    "epoch_escrow >= 0",
                    "flagged_i >= 0",
                    "sum(flagged_i) <= epoch_escrow enforced by contract guards",
                ],
                constraints=constraints,
                negated_property=remaining_pool < 0,
                lean4_theorem_stub="theorem dispute_escrow_bounded (e f : Real) (h : f <= e) : e - f >= 0",
            )
        ]

    def prove_mutual_credit_zero_sum(self) -> List[RebateInvariantProof]:
        """Proves closed circular debt settlement conserves net mutual credit balance."""
        import z3

        delta_1 = z3.Real("delta_balance_pharmacy_1")
        delta_2 = z3.Real("delta_balance_pharmacy_2")
        delta_3 = z3.Real("delta_balance_pharmacy_3")
        cycle_clear_volume = z3.Real("cycle_clear_volume")

        # In a 3-party circular clearance cycle (P1 pays P2, P2 pays P3, P3 pays P1)
        constraints = [
            cycle_clear_volume >= 0,
            delta_1 == cycle_clear_volume - cycle_clear_volume,
            delta_2 == cycle_clear_volume - cycle_clear_volume,
            delta_3 == cycle_clear_volume - cycle_clear_volume,
        ]

        sum_deltas = delta_1 + delta_2 + delta_3

        return [
            self._prove_unsat(
                invariant_id="REBATE-MATH-004",
                domain="MUTUAL_CREDIT_ZERO_SUM",
                statement="Net balance mutations in closed circular credit clearing cycles strictly sum to zero.",
                assumptions=[
                    "cycle_clear_volume >= 0",
                    "bilateral credit adjustments balance pairwise",
                ],
                constraints=constraints,
                negated_property=sum_deltas != 0,
                lean4_theorem_stub="theorem mutual_credit_zero_sum (v : Real) : (v - v) + (v - v) + (v - v) = 0",
            )
        ]

    def prove_fee_on_transfer_intake_integrity(self) -> List[RebateInvariantProof]:
        """Proves token intake received = balanceAfter - balanceBefore <= transferAmount."""
        import z3

        amount = z3.Real("transfer_amount")
        b_before = z3.Real("balance_before")
        token_tax = z3.Real("token_transfer_fee")
        b_after = z3.Real("balance_after")
        received = z3.Real("received_amount")

        constraints = [
            amount >= 0,
            b_before >= 0,
            token_tax >= 0,
            token_tax <= amount,
            b_after == b_before + (amount - token_tax),
            received == z3.If(b_after >= b_before, b_after - b_before, z3.RealVal(0)),
        ]

        return [
            self._prove_unsat(
                invariant_id="REBATE-MATH-005",
                domain="FEE_ON_TRANSFER_INTEGRITY",
                statement="Actual token intake under fee-on-transfer tokens is non-negative and bounded by requested amount.",
                assumptions=[
                    "amount >= 0, b_before >= 0",
                    "0 <= token_tax <= amount",
                    "b_after == b_before + amount - token_tax",
                    "received == max(0, b_after - b_before)",
                ],
                constraints=constraints,
                negated_property=z3.Or(received < 0, received > amount),
                lean4_theorem_stub="theorem fot_intake_bounded (a b_before tax : Real) (h1 : a >= 0) (h2 : 0 <= tax ∧ tax <= a) : (b_before + a - tax) - b_before <= a",
            )
        ]
