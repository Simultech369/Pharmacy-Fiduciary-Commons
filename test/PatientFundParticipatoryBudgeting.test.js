const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("PatientFundParticipatoryBudgeting", function () {
  const toWei = (val) => ethers.parseEther(val);

  let token;
  let pb;
  let council;
  let recipientA;
  let recipientB;
  let voters;
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
    const signers = await ethers.getSigners();
    council = signers[0];
    recipientA = signers[1];
    recipientB = signers[2];
    attacker = signers[3];
    voters = signers.slice(4, 11); // 7 voters available

    const MockERC20 = await ethers.getContractFactory("MockERC20");
    token = await MockERC20.deploy("Mock DAI", "mDAI");
    await token.waitForDeployment();

    const PB = await ethers.getContractFactory("PatientFundParticipatoryBudgeting");
    pb = await PB.deploy(await token.getAddress(), council.address);
    await pb.waitForDeployment();

    // Mint tokens to council and approve PB contract
    await token.mint(council.address, toWei("50000"));
    await token.connect(council).approve(await pb.getAddress(), toWei("50000"));
  });

  describe("Round Administration", function () {
    it("allows council to start a round and locks tokens", async function () {
      await pb.connect(council).startRound(toWei("10000"));
      expect(await pb.currentRound()).to.equal(1n);

      const r = await pb.rounds(1n);
      expect(r.matchingPool).to.equal(toWei("10000"));
      expect(r.state).to.equal(1n); // RoundState.Active is enum value 1

      expect(await token.balanceOf(await pb.getAddress())).to.equal(toWei("10000"));
    });

    it("restricts startRound to council", async function () {
      await expectRevert(
        pb.connect(attacker).startRound(toWei("10000")),
        "AccessControl"
      );
    });

    it("allows council to register projects", async function () {
      await pb.connect(council).startRound(toWei("10000"));
      await pb.connect(council).registerProject(1n, "Solar Grid", recipientA.address);

      const p = await pb.roundProjects(1n, 0n);
      expect(p.title).to.equal("Solar Grid");
      expect(p.recipient).to.equal(recipientA.address);
      expect(p.voteCount).to.equal(0n);
      expect(p.active).to.be.true;
    });

    it("allows council to register voters in batch", async function () {
      await pb.connect(council).startRound(toWei("10000"));
      const voterAddrs = voters.map(v => v.address);
      await pb.connect(council).registerVotersBatch(1n, voterAddrs);

      for (const voter of voters) {
        expect(await pb.registeredVoters(1n, voter.address)).to.be.true;
      }
    });
  });

  describe("Quadratic Voting & Payout Distribution", function () {
    beforeEach(async function () {
      await pb.connect(council).startRound(toWei("10000"));
      await pb.connect(council).registerProject(1n, "Project Solar", recipientA.address); // Project 0
      await pb.connect(council).registerProject(1n, "Project Insulin", recipientB.address); // Project 1

      const voterAddrs = voters.map(v => v.address);
      await pb.connect(council).registerVotersBatch(1n, voterAddrs);
    });

    it("enforces voting boundaries (registration, unique votes)", async function () {
      // 1. Unregistered voter cannot vote
      await expectRevert(
        pb.connect(attacker).castVote(1n, 0n),
        "Unauthorized"
      );

      // 2. Registered voter casts vote successfully
      await pb.connect(voters[0]).castVote(1n, 0n);
      expect(await pb.hasVoted(1n, voters[0].address, 0n)).to.be.true;

      const p = await pb.roundProjects(1n, 0n);
      expect(p.voteCount).to.equal(1n);

      // 3. Double voting reverts
      await expectRevert(
        pb.connect(voters[0]).castVote(1n, 0n),
        "AlreadyVoted"
      );
    });

    it("calculates matching distribution proportionally (Quadratic Funding)", async function () {
      // Project 0 (Solar) gets 4 unique votes: voter 0, 1, 2, 3
      await pb.connect(voters[0]).castVote(1n, 0n);
      await pb.connect(voters[1]).castVote(1n, 0n);
      await pb.connect(voters[2]).castVote(1n, 0n);
      await pb.connect(voters[3]).castVote(1n, 0n);

      // Project 1 (Insulin) gets 2 unique votes: voter 4, 5
      await pb.connect(voters[4]).castVote(1n, 1n);
      await pb.connect(voters[5]).castVote(1n, 1n);

      // Total Matching Pool = $10,000
      // Proportions:
      // Project 0: 4 votes -> weight = 4^2 = 16
      // Project 1: 2 votes -> weight = 2^2 = 4
      // Total weight = 20
      // Project 0 receives 16/20 = 80% ($8,000)
      // Project 1 receives 4/20 = 20% ($2,000)

      const balBeforeA = await token.balanceOf(recipientA.address);
      const balBeforeB = await token.balanceOf(recipientB.address);

      await pb.connect(council).finalizeRound(1n);

      const balAfterA = await token.balanceOf(recipientA.address);
      const balAfterB = await token.balanceOf(recipientB.address);

      expect(balAfterA - balBeforeA).to.equal(toWei("8000"));
      expect(balAfterB - balBeforeB).to.equal(toWei("2000"));

      const r = await pb.rounds(1n);
      expect(r.state).to.equal(2n); // RoundState.Finalized is enum value 2
    });

    it("returns matching pool to council if no votes are cast", async function () {
      const balanceBefore = await token.balanceOf(council.address);
      
      await pb.connect(council).finalizeRound(1n);
      
      const balanceAfter = await token.balanceOf(council.address);
      // The 10,000 DAI matching pool should be refunded back to the council
      expect(balanceAfter - balanceBefore).to.equal(toWei("10000"));
    });
  });

  describe("Voter Self-Registration via Relayer Signature", function () {
    let relayer;
    let voter;

    beforeEach(async function () {
      const signers = await ethers.getSigners();
      relayer = signers[8]; // Assign a specific signer as the relayer
      voter = signers[4];
      
      await pb.connect(council).startRound(toWei("10000"));
      await pb.connect(council).setRelayerVerifier(relayer.address);
    });

    it("allows a voter to self-register with a valid relayer signature", async function () {
      const messageHash = ethers.solidityPackedKeccak256(
        ["uint256", "address", "address"],
        [1n, voter.address, await pb.getAddress()]
      );
      const messageHashBytes = ethers.toBeArray(messageHash);
      const signature = await relayer.signMessage(messageHashBytes);

      await pb.connect(voter).registerVoterWithSignature(1n, voter.address, signature);
      expect(await pb.registeredVoters(1n, voter.address)).to.be.true;
    });

    it("reverts if the signature is invalid or signed by an unauthorized key", async function () {
      const messageHash = ethers.solidityPackedKeccak256(
        ["uint256", "address", "address"],
        [1n, voter.address, await pb.getAddress()]
      );
      const messageHashBytes = ethers.toBeArray(messageHash);
      
      // Signed by attacker instead of relayer
      const invalidSignature = await attacker.signMessage(messageHashBytes);

      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(1n, voter.address, invalidSignature),
        "Unauthorized"
      );
    });

    it("prevents signature replay across different voters or rounds", async function () {
      const messageHash = ethers.solidityPackedKeccak256(
        ["uint256", "address", "address"],
        [1n, voter.address, await pb.getAddress()]
      );
      const messageHashBytes = ethers.toBeArray(messageHash);
      const signature = await relayer.signMessage(messageHashBytes);

      // Attempt to register another voter address using the same signature
      const otherVoter = voters[1];
      await expectRevert(
        pb.connect(otherVoter).registerVoterWithSignature(1n, otherVoter.address, signature),
        "Unauthorized"
      );

      // Attempt to register on a different round using the same signature
      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(2n, voter.address, signature),
        "WrongRoundState"
      );
    });
  });
});
