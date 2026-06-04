const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("PharmacyMutualCredit", function () {
  let credit;
  let council;
  let pharmacyA;
  let pharmacyB;
  let advocate;
  let attacker;

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
    [council, pharmacyA, pharmacyB, advocate, attacker] = await ethers.getSigners();

    const PharmacyMutualCredit = await ethers.getContractFactory("PharmacyMutualCredit");
    credit = await PharmacyMutualCredit.deploy(council.address);
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
      await credit.connect(council).updateIssuerStatus(advocate.address, true);
      expect(await credit.authorizedIssuers(advocate.address)).to.be.true;
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
  });

  describe("Voucher System", function () {
    let voucherId;
    let amount;
    let expiry;

    beforeEach(async function () {
      await credit.connect(council).registerParticipant(pharmacyA.address, 500n);
      await credit.connect(council).updateIssuerStatus(advocate.address, true);

      voucherId = ethers.keccak256(ethers.toUtf8Bytes("voucher-001"));
      amount = 150n;
      const latestBlock = await ethers.provider.getBlock("latest");
      expiry = BigInt(latestBlock.timestamp) + 3600n; // 1 hour expiry
    });

    it("allows authorized issuer to create and pharmacy to redeem voucher", async function () {
      await credit.connect(advocate).createVoucher(voucherId, amount, expiry);

      // Verify voucher stats
      const v = await credit.vouchers(voucherId);
      expect(v.issuer).to.equal(advocate.address);
      expect(v.amount).to.equal(amount);
      expect(v.redeemed).to.be.false;

      // Pharmacy A redeems voucher
      await credit.connect(pharmacyA).redeemVoucher(voucherId);

      // Check balance updates (Advocate goes to -150, Pharmacy A goes to +150)
      expect(await credit.balances(advocate.address)).to.equal(-150n);
      expect(await credit.balances(pharmacyA.address)).to.equal(150n);

      const redeemedV = await credit.vouchers(voucherId);
      expect(redeemedV.redeemed).to.be.true;
    });

    it("reverts redemption of expired vouchers", async function () {
      const expiredTime = BigInt(Math.floor(Date.now() / 1000)) - 10n;
      const expiredId = ethers.keccak256(ethers.toUtf8Bytes("voucher-expired"));

      await credit.connect(advocate).createVoucher(expiredId, amount, expiry);
      
      // Fast forward EVM time to expire voucher
      await ethers.provider.send("evm_increaseTime", [3610]);
      await ethers.provider.send("evm_mine", []);

      await expectRevert(
        credit.connect(pharmacyA).redeemVoucher(expiredId),
        "VoucherExpired"
      );
    });

    it("reverts double spend of a voucher", async function () {
      await credit.connect(advocate).createVoucher(voucherId, amount, expiry);
      await credit.connect(pharmacyA).redeemVoucher(voucherId);

      await expectRevert(
        credit.connect(pharmacyA).redeemVoucher(voucherId),
        "VoucherAlreadyRedeemed"
      );
    });
  });
});
