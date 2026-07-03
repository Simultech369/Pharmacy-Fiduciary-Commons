// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

interface ITreasuryReentryTarget {
    function currentEpoch() external view returns (uint256);
    function distributionPool() external view returns (uint256);
    function governanceReserve() external view returns (uint256);
    function exclusionRemediationReserve() external view returns (uint256);
    function totalRebateDeposited() external view returns (uint256);
    function rebateDepositCount() external view returns (uint256);
    function epochEscrow(uint256 epoch) external view returns (uint256);
    function totalEscrowed() external view returns (uint256);
    function epochClaimedTotal(uint256 epoch) external view returns (uint256);
    function epochRootClaimedTotal(uint256 epoch) external view returns (uint256);
    function hasClaimed(uint256 epoch, address pharmacy) external view returns (bool);
    function pharmacyClaimedThisEpoch(uint256 epoch, address pharmacy) external view returns (uint256);

    function depositRebate(uint256 amount, string calldata source) external;
    function fundExclusionRemediation(uint256 amount) external;
    function claim(uint256 amount, uint256 eligibleCap, bytes32[] calldata proof) external;
    function resolveClaim(uint256 epoch, address pharmacy, uint8 resolution, bytes32 evidenceHash) external;
    function recallUnclaimed(uint256 epoch) external;
    function withdrawGovernanceReserve(address recipient, uint256 amount) external;
    function recoverStaleDistributionPool(address recipient, uint256 amount) external;
    function sweepETH() external;
    function sweep(address token, uint256 amount) external;
}

contract TreasuryReentrantToken is ERC20 {
    error InvalidAddress();

    enum AttackPhase {
        None,
        Deposit,
        Remediation,
        Claim
    }

    ITreasuryReentryTarget public target;
    AttackPhase public attackPhase;
    bool public attackEnabled;
    bool private entered;

    address public watchedPharmacy;
    uint256 public callbackCount;
    uint256 public unexpectedSuccessCount;

    uint256 public observedCurrentEpoch;
    uint256 public observedDistributionPool;
    uint256 public observedGovernanceReserve;
    uint256 public observedExclusionRemediationReserve;
    uint256 public observedTotalRebateDeposited;
    uint256 public observedRebateDepositCount;
    uint256 public observedEpochEscrow;
    uint256 public observedTotalEscrowed;
    uint256 public observedEpochClaimedTotal;
    uint256 public observedEpochRootClaimedTotal;
    uint256 public observedPharmacyClaimed;
    bool public observedHasClaimed;

    bool public depositRebateBlocked;
    bool public fundExclusionRemediationBlocked;
    bool public claimBlocked;
    bool public resolveClaimBlocked;
    bool public recallUnclaimedBlocked;
    bool public withdrawGovernanceReserveBlocked;
    bool public recoverStaleDistributionPoolBlocked;
    bool public sweepETHBlocked;
    bool public sweepBlocked;

    event TargetUpdated(address indexed target);
    event AttackConfigured(AttackPhase indexed phase, address indexed watchedPharmacy, bool enabled);

    constructor() ERC20("Treasury Reentrant Token", "TRT") {}

    function setTarget(address target_) external {
        if (target_ == address(0)) revert InvalidAddress();
        target = ITreasuryReentryTarget(target_);
        emit TargetUpdated(target_);
    }

    function configureAttack(AttackPhase phase, address watchedPharmacy_, bool enabled) external {
        attackPhase = phase;
        watchedPharmacy = watchedPharmacy_;
        attackEnabled = enabled;
        emit AttackConfigured(phase, watchedPharmacy_, enabled);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        if (_shouldAttack(AttackPhase.Claim)) {
            _probeTreasuryCallback();
        }
        return super.transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        if (_shouldAttack(AttackPhase.Deposit) || _shouldAttack(AttackPhase.Remediation)) {
            _probeTreasuryCallback();
        }
        return super.transferFrom(from, to, amount);
    }

    function _shouldAttack(AttackPhase phase) private view returns (bool) {
        return (
            attackEnabled &&
            !entered &&
            callbackCount == 0 &&
            attackPhase == phase &&
            msg.sender == address(target)
        );
    }

    function _probeTreasuryCallback() private {
        entered = true;
        callbackCount += 1;

        observedCurrentEpoch = target.currentEpoch();
        observedDistributionPool = target.distributionPool();
        observedGovernanceReserve = target.governanceReserve();
        observedExclusionRemediationReserve = target.exclusionRemediationReserve();
        observedTotalRebateDeposited = target.totalRebateDeposited();
        observedRebateDepositCount = target.rebateDepositCount();
        observedEpochEscrow = target.epochEscrow(observedCurrentEpoch);
        observedTotalEscrowed = target.totalEscrowed();
        observedEpochClaimedTotal = target.epochClaimedTotal(observedCurrentEpoch);
        observedEpochRootClaimedTotal = target.epochRootClaimedTotal(observedCurrentEpoch);

        if (watchedPharmacy != address(0)) {
            observedHasClaimed = target.hasClaimed(observedCurrentEpoch, watchedPharmacy);
            observedPharmacyClaimed = target.pharmacyClaimedThisEpoch(observedCurrentEpoch, watchedPharmacy);
        }

        _attemptGuardedMutators();
        entered = false;
    }

    function _attemptGuardedMutators() private {
        bytes32 evidenceHash = keccak256("treasury-reentrant-token-callback");
        bytes32[] memory proof = new bytes32[](0);

        try target.depositRebate(1, "reentrant deposit") {
            unexpectedSuccessCount += 1;
        } catch {
            depositRebateBlocked = true;
        }

        try target.fundExclusionRemediation(1) {
            unexpectedSuccessCount += 1;
        } catch {
            fundExclusionRemediationBlocked = true;
        }

        try target.claim(1, 1, proof) {
            unexpectedSuccessCount += 1;
        } catch {
            claimBlocked = true;
        }

        try target.resolveClaim(observedCurrentEpoch, address(this), 0, evidenceHash) {
            unexpectedSuccessCount += 1;
        } catch {
            resolveClaimBlocked = true;
        }

        try target.recallUnclaimed(0) {
            unexpectedSuccessCount += 1;
        } catch {
            recallUnclaimedBlocked = true;
        }

        try target.withdrawGovernanceReserve(address(this), 1) {
            unexpectedSuccessCount += 1;
        } catch {
            withdrawGovernanceReserveBlocked = true;
        }

        try target.recoverStaleDistributionPool(address(this), 1) {
            unexpectedSuccessCount += 1;
        } catch {
            recoverStaleDistributionPoolBlocked = true;
        }

        try target.sweepETH() {
            unexpectedSuccessCount += 1;
        } catch {
            sweepETHBlocked = true;
        }

        try target.sweep(address(this), 1) {
            unexpectedSuccessCount += 1;
        } catch {
            sweepBlocked = true;
        }
    }
}
