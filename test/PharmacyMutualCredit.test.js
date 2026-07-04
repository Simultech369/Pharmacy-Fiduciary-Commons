const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("PharmacyMutualCredit", function () {
  let credit;
  let council;
  let pharmacyA;
  let pharmacyB;
  let advocate;
  let attacker;
  let guardian;

  function errorText(err) {
    return [
      err?.message,
      err?.shortMessage,
      err?.errorName,
      err?.error?.message,
      err?.data?.message,
    ]
      .filter(Boolean)
      .join(" | ");
  }

  async function expectRevert(promise, expectedSnippet) {
    let reverted = false;
    try {
      await promise;
    } catch (err) {
      reverted = true;
      const text = errorText(err);
      expect(text).to.contain(expectedSnippet);
    }

    if (!reverted) {
      expect.fail(`Expected revert containing '${expectedSnippet}'`);
    }
  }

  beforeEach(async function () {
    [council, pharmacyA, pharmacyB, advocate, attacker, guardian] = await ethers.getSigners();

    const PharmacyMutualCredit = await ethers.getContractFactory("PharmacyMutualCredit");
    credit = await PharmacyMutualCredit.deploy(council.address, guardian.address);
    await credit.waitForDeployment();
  });

  describe("Governance", function () {
    it("allows council to register participants", async function () {
      await credit.connect(council).registerParticipant(pharmacyA.address, 1000n);
      expect(await credit.registered(pharmacyA.address)).to.be.true;
      expect(await credit.creditLimits(pharmacyA.address)).to.equal(1000n);
    });

    it("prevents double registration", async function () {
      await credit.connect(council).registerParticipant(pharmacyA.address, 1000n);
      await expectRevert(
        credit.connect(council).registerParticipant(pharmacyA.address, 500n),
        "AlreadyRegistered"
      );
    });

    it("restricts registration to council", async function () {
      await expectRevert(
        credit.connect(attacker).registerParticipant(pharmacyA.address, 1000n),
        "AccessControl"
      );
    });

    it("allows council to update credit limits", async function () {
      await credit.connect(council).registerParticipant(pharmacyA.address, 1000n);
      await credit.connect(council).updateCreditLimit(pharmacyA.address, 2000n);
      expect(await credit.creditLimits(pharmacyA.address)).to.equal(2000n);
    });

    it("reverts limit updates for unregistered addresses", async function () {
      await expectRevert(
        credit.connect(council).updateCreditLimit(attacker.address, 2000n),
        "NotRegistered"
      );
    });

    it("allows council to authorize voucher issuers", async function () {
      await credit.connect(council).registerParticipant(advocate.address, 500n);
      await credit.connect(council).updateIssuerStatus(advocate.address, true);
      expect(await credit.authorizedIssuers(advocate.address)).to.be.true;
    });

    it("requires voucher issuers to be registered before authorization", async function () {
      await expectRevert(
        credit.connect(council).updateIssuerStatus(advocate.address, true),
        "NotRegistered"
      );
    });
  });

  describe("Mutual Credit Clearing", function () {
    beforeEach(async function () {
      await credit.connect(council).registerParticipant(pharmacyA.address, 500n);
      await credit.connect(council).registerParticipant(pharmacyB.address, 1000n);
    });

    it("allows valid credit transfers and maintains zero-sum", async function () {
      // Transfer 300 credit from A to B (A goes to -300, B goes to +300)
      await credit.connect(pharmacyA).transferCredit(pharmacyB.address, 300n);
      expect(await credit.balances(pharmacyA.address)).to.equal(-300n);
      expect(await credit.balances(pharmacyB.address)).to.equal(300n);

      // Verify A + B balances = 0
      const balA = await credit.balances(pharmacyA.address);
      const balB = await credit.balances(pharmacyB.address);
      expect(balA + balB).to.equal(0n);
    });

    it("reverts transfers exceeding sender's credit limit", async function () {
      // Pharmacy A limit is 500. Transfer 600 should revert.
      await expectRevert(
        credit.connect(pharmacyA).transferCredit(pharmacyB.address, 600n),
        "CreditLimitExceeded"
      );
    });

    it("reverts transfers involving unregistered participants", async function () {
      await expectRevert(
        credit.connect(pharmacyA).transferCredit(attacker.address, 100n),
        "NotRegistered"
      );

      await expectRevert(
        credit.connect(attacker).transferCredit(pharmacyB.address, 100n),
        "NotRegistered"
      );
    });

    it("prevents integer underflow and cleanly reverts with CreditLimitExceeded when balance is near type(int256).min", async function () {
      const maxInt256 = 2n ** 255n - 1n;
      
      // Update credit limits to maxInt256
      await credit.connect(council).updateCreditLimit(pharmacyA.address, maxInt256);
      await credit.connect(council).updateCreditLimit(pharmacyB.address, maxInt256);

      // Transfer maxInt256 to push pharmacyA's balance to -maxInt256
      await credit.connect(pharmacyA).transferCredit(pharmacyB.address, maxInt256);
      expect(await credit.balances(pharmacyA.address)).to.equal(-maxInt256);

      // Attempting to transfer 2 more should exceed limit and revert with CreditLimitExceeded
      await expectRevert(
        credit.connect(pharmacyA).transferCredit(pharmacyB.address, 2n),
        "CreditLimitExceeded"
      );

      // Authorize pharmacyA to issue vouchers, and verify voucher capacity underflow check
      await credit.connect(council).updateIssuerStatus(pharmacyA.address, true);
      const voucherId = ethers.keccak256(ethers.toUtf8Bytes("underflow-voucher"));
      const latestBlock = await ethers.provider.getBlock("latest");
      const expiry = BigInt(latestBlock.timestamp) + 3600n;

      await expectRevert(
        credit.connect(pharmacyA).createVoucher(voucherId, pharmacyB.address, 2n, expiry),
        "CreditLimitExceeded"
      );
    });
  });

  describe("Voucher System", function () {
    let voucherId;
    let amount;
    let expiry;

    beforeEach(async function () {
      await credit.connect(council).registerParticipant(pharmacyA.address, 500n);
      await credit.connect(council).registerParticipant(advocate.address, 200n);
      await credit.connect(council).updateIssuerStatus(advocate.address, true);

      voucherId = ethers.keccak256(ethers.toUtf8Bytes("voucher-001"));
      amount = 150n;
      const latestBlock = await ethers.provider.getBlock("latest");
      expiry = BigInt(latestBlock.timestamp) + 3600n; // 1 hour expiry
    });

    it("allows authorized issuer to create and pharmacy to redeem voucher", async function () {
      await credit.connect(advocate).createVoucher(voucherId, pharmacyA.address, amount, expiry);

      // Verify voucher stats
      const v = await credit.vouchers(voucherId);
      expect(v.issuer).to.equal(advocate.address);
      expect(v.recipient).to.equal(pharmacyA.address);
      expect(v.amount).to.equal(amount);
      expect(v.redeemed).to.be.false;
      expect(v.createdAt).to.be.gt(0n);
      expect(await credit.reservedVoucherCredit(advocate.address)).to.equal(amount);

      // Pharmacy A redeems voucher
      await credit.connect(pharmacyA).redeemVoucher(voucherId);

      // Check balance updates (Advocate goes to -150, Pharmacy A goes to +150)
      expect(await credit.balances(advocate.address)).to.equal(-150n);
      expect(await credit.balances(pharmacyA.address)).to.equal(150n);
      expect(await credit.reservedVoucherCredit(advocate.address)).to.equal(0n);

      const redeemedV = await credit.vouchers(voucherId);
      expect(redeemedV.redeemed).to.be.true;
    });

    it("allows vouchers created before issuer deauthorization to redeem inside the grace window", async function () {
      const latestBlock = await ethers.provider.getBlock("latest");
      const longExpiry = BigInt(latestBlock.timestamp) + 60n * 24n * 60n * 60n;
      await credit.connect(advocate).createVoucher(voucherId, pharmacyA.address, amount, longExpiry);
      const createdVoucher = await credit.vouchers(voucherId);

      await credit.connect(council).updateIssuerStatus(advocate.address, false);
      const deregTime = await credit.issuerDeregistrationTimestamp(advocate.address);
      expect(deregTime).to.be.gt(createdVoucher.createdAt);
      expect(await credit.authorizedIssuers(advocate.address)).to.be.false;

      await ethers.provider.send("evm_increaseTime", [15 * 24 * 60 * 60]);
      await ethers.provider.send("evm_mine", []);

      await credit.connect(pharmacyA).redeemVoucher(voucherId);
      expect(await credit.balances(advocate.address)).to.equal(-amount);
      expect(await credit.balances(pharmacyA.address)).to.equal(amount);
    });

    it("rejects pre-deauthorization vouchers after the issuer grace window", async function () {
      const latestBlock = await ethers.provider.getBlock("latest");
      const longExpiry = BigInt(latestBlock.timestamp) + 60n * 24n * 60n * 60n;
      await credit.connect(advocate).createVoucher(voucherId, pharmacyA.address, amount, longExpiry);
      await credit.connect(council).updateIssuerStatus(advocate.address, false);

      await ethers.provider.send("evm_increaseTime", [31 * 24 * 60 * 60]);
      await ethers.provider.send("evm_mine", []);

      await expectRevert(
        credit.connect(pharmacyA).redeemVoucher(voucherId),
        "Unauthorized"
      );
    });

    it("keeps voucher expiry authoritative even inside the issuer grace window", async function () {
      await credit.connect(advocate).createVoucher(voucherId, pharmacyA.address, amount, expiry);
      await credit.connect(council).updateIssuerStatus(advocate.address, false);

      await ethers.provider.send("evm_increaseTime", [2 * 60 * 60]);
      await ethers.provider.send("evm_mine", []);

      await expectRevert(
        credit.connect(pharmacyA).redeemVoucher(voucherId),
        "VoucherExpired"
      );
    });

    it("resets issuer deauthorization timestamps across reauthorization cycles", async function () {
      const latestBlock = await ethers.provider.getBlock("latest");
      const longExpiry = BigInt(latestBlock.timestamp) + 60n * 24n * 60n * 60n;
      const oldVoucher = ethers.keccak256(ethers.toUtf8Bytes("old-cycle-voucher"));
      const newVoucher = ethers.keccak256(ethers.toUtf8Bytes("new-cycle-voucher"));

      await credit.connect(advocate).createVoucher(oldVoucher, pharmacyA.address, 50n, longExpiry);
      await credit.connect(council).updateIssuerStatus(advocate.address, false);
      const firstDeregTime = await credit.issuerDeregistrationTimestamp(advocate.address);
      expect(firstDeregTime).to.be.gt(0n);

      await credit.connect(council).updateIssuerStatus(advocate.address, true);
      expect(await credit.issuerDeregistrationTimestamp(advocate.address)).to.equal(0n);

      await ethers.provider.send("evm_increaseTime", [2 * 24 * 60 * 60]);
      await ethers.provider.send("evm_mine", []);
      await credit.connect(advocate).createVoucher(newVoucher, pharmacyA.address, 50n, longExpiry);

      await credit.connect(council).updateIssuerStatus(advocate.address, false);
      const secondDeregTime = await credit.issuerDeregistrationTimestamp(advocate.address);
      expect(secondDeregTime).to.be.gt(firstDeregTime);

      await credit.connect(pharmacyA).redeemVoucher(newVoucher);
      expect(await credit.balances(pharmacyA.address)).to.equal(50n);
    });

    it("rejects voucher issuance that would exceed issuer credit capacity", async function () {
      const largeVoucherId = ethers.keccak256(ethers.toUtf8Bytes("voucher-large"));
      await expectRevert(
        credit.connect(advocate).createVoucher(largeVoucherId, pharmacyA.address, 250n, expiry),
        "CreditLimitExceeded"
      );
    });

    it("protects reserved vouchers from later transfers and limit reductions", async function () {
      await credit.connect(advocate).createVoucher(voucherId, pharmacyA.address, 150n, expiry);

      await expectRevert(
        credit.connect(advocate).transferCredit(pharmacyA.address, 51n),
        "CreditLimitExceeded"
      );
      await credit.connect(advocate).transferCredit(pharmacyA.address, 50n);

      await expectRevert(
        credit.connect(council).updateCreditLimit(advocate.address, 199n),
        "CreditLimitExceeded"
      );

      await credit.connect(pharmacyA).redeemVoucher(voucherId);
      expect(await credit.balances(advocate.address)).to.equal(-200n);
      expect(await credit.balances(pharmacyA.address)).to.equal(200n);
    });

    it("releases expired voucher reservations exactly once", async function () {
      await credit.connect(advocate).createVoucher(voucherId, pharmacyA.address, amount, expiry);
      await ethers.provider.send("evm_setNextBlockTimestamp", [Number(expiry + 1n)]);
      await ethers.provider.send("evm_mine", []);

      await credit.connect(attacker).releaseExpiredVoucher(voucherId);
      expect(await credit.reservedVoucherCredit(advocate.address)).to.equal(0n);

      await expectRevert(
        credit.connect(attacker).releaseExpiredVoucher(voucherId),
        "VoucherExpired"
      );
    });

    it("releases batch of expired voucher reservations", async function () {
      const voucherId1 = ethers.keccak256(ethers.toUtf8Bytes("voucher-001"));
      const voucherId2 = ethers.keccak256(ethers.toUtf8Bytes("voucher-002"));

      await credit.connect(advocate).createVoucher(voucherId1, pharmacyA.address, 80n, expiry);
      await credit.connect(advocate).createVoucher(voucherId2, pharmacyA.address, 100n, expiry);

      expect(await credit.reservedVoucherCredit(advocate.address)).to.equal(180n);

      await ethers.provider.send("evm_setNextBlockTimestamp", [Number(expiry + 1n)]);
      await ethers.provider.send("evm_mine", []);

      await credit.connect(attacker).releaseExpiredVouchersBatch([voucherId1, voucherId2]);
      expect(await credit.reservedVoucherCredit(advocate.address)).to.equal(0n);

      await expectRevert(
        credit.connect(attacker).releaseExpiredVouchersBatch([voucherId1]),
        "VoucherExpired"
      );
    });

    it("caps batch voucher reservation release size", async function () {
      const maxBatch = Number(await credit.MAX_VOUCHER_RELEASE_BATCH());
      const oversizedBatch = Array.from(
        { length: maxBatch + 1 },
        (_, i) => ethers.keccak256(ethers.toUtf8Bytes(`voucher-release-${i}`))
      );

      await expectRevert(
        credit.connect(attacker).releaseExpiredVouchersBatch(oversizedBatch),
        "BatchTooLarge"
      );
    });

    it("reverts batch release if any voucher is not expired, redeemed, or non-existent", async function () {
      const voucherId1 = ethers.keccak256(ethers.toUtf8Bytes("voucher-001"));
      const voucherId2 = ethers.keccak256(ethers.toUtf8Bytes("voucher-002"));
      const nonExistentVoucher = ethers.keccak256(ethers.toUtf8Bytes("voucher-nonexistent"));

      await credit.connect(advocate).createVoucher(voucherId1, pharmacyA.address, 80n, expiry);

      // Revert if any in batch doesn't exist
      await expectRevert(
        credit.connect(attacker).releaseExpiredVouchersBatch([nonExistentVoucher]),
        "VoucherDoesNotExist"
      );

      // Revert if any in batch is not expired yet
      await expectRevert(
        credit.connect(attacker).releaseExpiredVouchersBatch([voucherId1]),
        "VoucherNotExpired"
      );

      await ethers.provider.send("evm_setNextBlockTimestamp", [Number(expiry + 1n)]);
      await ethers.provider.send("evm_mine", []);

      const newExpiry = expiry + 3600n;
      await credit.connect(advocate).createVoucher(voucherId2, pharmacyA.address, 50n, newExpiry);

      await expectRevert(
        credit.connect(attacker).releaseExpiredVouchersBatch([voucherId1, voucherId2]),
        "VoucherNotExpired"
      );

      const voucherId3 = ethers.keccak256(ethers.toUtf8Bytes("voucher-003"));
      const currentBlock = await ethers.provider.getBlock("latest");
      const tempExpiry = BigInt(currentBlock.timestamp) + 1000n;
      await credit.connect(advocate).createVoucher(voucherId3, pharmacyA.address, 20n, tempExpiry);

      await credit.connect(pharmacyA).redeemVoucher(voucherId3);

      await ethers.provider.send("evm_setNextBlockTimestamp", [Number(tempExpiry + 1n)]);
      await ethers.provider.send("evm_mine", []);

      await expectRevert(
        credit.connect(attacker).releaseExpiredVouchersBatch([voucherId3]),
        "VoucherAlreadyRedeemed"
      );
    });

    it("requires voucher creators to be authorized registered participants", async function () {
      const attackerVoucherId = ethers.keccak256(ethers.toUtf8Bytes("voucher-attacker"));

      await credit.connect(council).registerParticipant(attacker.address, 200n);
      await expectRevert(
        credit.connect(attacker).createVoucher(attackerVoucherId, pharmacyA.address, amount, expiry),
        "Unauthorized"
      );
    });

    it("reverts redemption of expired vouchers", async function () {
      const expiredTime = BigInt(Math.floor(Date.now() / 1000)) - 10n;
      const expiredId = ethers.keccak256(ethers.toUtf8Bytes("voucher-expired"));

      await credit.connect(advocate).createVoucher(expiredId, pharmacyA.address, amount, expiry);
      
      // Fast forward EVM time to expire voucher
      await ethers.provider.send("evm_increaseTime", [3610]);
      await ethers.provider.send("evm_mine", []);

      await expectRevert(
        credit.connect(pharmacyA).redeemVoucher(expiredId),
        "VoucherExpired"
      );
    });

    it("reverts double spend of a voucher", async function () {
      await credit.connect(advocate).createVoucher(voucherId, pharmacyA.address, amount, expiry);
      await credit.connect(pharmacyA).redeemVoucher(voucherId);

      await expectRevert(
        credit.connect(pharmacyA).redeemVoucher(voucherId),
        "VoucherAlreadyRedeemed"
      );
    });

    it("binds voucher redemption to the intended registered recipient", async function () {
      await credit.connect(council).registerParticipant(pharmacyB.address, 500n);
      await credit.connect(advocate).createVoucher(voucherId, pharmacyA.address, amount, expiry);

      await expectRevert(
        credit.connect(pharmacyB).redeemVoucher(voucherId),
        "Unauthorized"
      );

      await credit.connect(pharmacyA).redeemVoucher(voucherId);
      expect(await credit.balances(pharmacyA.address)).to.equal(amount);
      expect(await credit.balances(pharmacyB.address)).to.equal(0n);
    });

    it("reverts if attempting to create a voucher exceeding MAX_VOUCHER_LIFETIME", async function () {
      const longExpiryId = ethers.keccak256(ethers.toUtf8Bytes("voucher-too-long"));
      const tooLongExpiry = expiry + 91n * 24n * 60n * 60n; // 91 days
      await expectRevert(
        credit.connect(advocate).createVoucher(longExpiryId, pharmacyA.address, amount, tooLongExpiry),
        "VoucherExpiryTooLong"
      );
    });
  });

  describe("Pausable & Sweep Enhancements", function () {
    it("enforces constructor guardian and council separation", async function () {
      const PharmacyMutualCredit = await ethers.getContractFactory("PharmacyMutualCredit");
      await expectRevert(
        PharmacyMutualCredit.deploy(council.address, council.address),
        "GuardianMustDifferFromCouncil"
      );
    });

    it("preserves council/guardian/admin separation during role rotation", async function () {
      const councilRole = await credit.COUNCIL_ROLE();
      const guardianRole = await credit.GUARDIAN_ROLE();
      const defaultAdminRole = ethers.ZeroHash;

      await expectRevert(
        credit.connect(council).grantRole(guardianRole, council.address),
        "GovernanceRoleSeparationViolation"
      );
      await expectRevert(
        credit.connect(council).grantRole(councilRole, guardian.address),
        "GovernanceRoleSeparationViolation"
      );
      await expectRevert(
        credit.connect(council).grantRole(defaultAdminRole, guardian.address),
        "GovernanceRoleSeparationViolation"
      );
    });

    it("allows guardian to pause and blocks all credit and voucher actions, then council can unpause", async function () {
      await credit.connect(council).registerParticipant(pharmacyA.address, 1000n);
      await credit.connect(council).registerParticipant(pharmacyB.address, 1000n);

      // Guardian pauses
      await credit.connect(guardian).pause();

      // Check actions revert when paused
      await expectRevert(
        credit.connect(council).registerParticipant(advocate.address, 1000n),
        "Pausable: paused"
      );
      await expectRevert(
        credit.connect(pharmacyA).transferCredit(pharmacyB.address, 100n),
        "Pausable: paused"
      );

      // Attacker cannot unpause
      await expectRevert(
        credit.connect(attacker).unpause(),
        "AccessControl"
      );

      // Council unpauses
      await credit.connect(council).unpause();

      // Actions now succeed
      await credit.connect(pharmacyA).transferCredit(pharmacyB.address, 100n);
      expect(await credit.balances(pharmacyA.address)).to.equal(-100n);
      expect(await credit.balances(pharmacyB.address)).to.equal(100n);
    });

    it("allows council to sweep accidental ERC-20 tokens", async function () {
      const MockERC20 = await ethers.getContractFactory("MockERC20");
      const randomToken = await MockERC20.deploy("Random Token", "RDM", 18);
      await randomToken.waitForDeployment();

      await randomToken.mint(await credit.getAddress(), 1000n);
      expect(await randomToken.balanceOf(await credit.getAddress())).to.equal(1000n);

      // Attacker cannot sweep
      await expectRevert(
        credit.connect(attacker).sweep(await randomToken.getAddress(), 1000n),
        "AccessControl"
      );

      // Council sweeps
      const councilBefore = await randomToken.balanceOf(council.address);
      await credit.connect(council).sweep(await randomToken.getAddress(), 1000n);
      const councilAfter = await randomToken.balanceOf(council.address);
      expect(councilAfter - councilBefore).to.equal(1000n);
    });
  });
});
