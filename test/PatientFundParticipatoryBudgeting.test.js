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
    const signers = await ethers.getSigners();
    council = signers[0];
    recipientA = signers[1];
    recipientB = signers[2];
    attacker = signers[3];
    voters = signers.slice(4, 11); // 7 voters available
    guardian = signers[11];

    const MockERC20 = await ethers.getContractFactory("MockERC20");
    token = await MockERC20.deploy("Mock DAI", "mDAI", 18);
    await token.waitForDeployment();

    const PB = await ethers.getContractFactory("PatientFundParticipatoryBudgeting");
    pb = await PB.deploy(await token.getAddress(), council.address, guardian.address);
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

    it("rejects fee-on-transfer matching tokens before opening a round", async function () {
      const FeeToken = await ethers.getContractFactory("MockFeeOnTransferERC20");
      const feeToken = await FeeToken.deploy();
      await feeToken.waitForDeployment();

      const PB = await ethers.getContractFactory("PatientFundParticipatoryBudgeting");
      const feePb = await PB.deploy(await feeToken.getAddress(), council.address, guardian.address);
      await feePb.waitForDeployment();

      await feeToken.mint(council.address, toWei("50000"));
      await feeToken.connect(council).approve(await feePb.getAddress(), toWei("50000"));

      await expectRevert(
        feePb.connect(council).startRound(toWei("1000")),
        "TokenTransferAmountMismatch"
      );

      expect(await feePb.currentRound()).to.equal(0n);
      expect((await feePb.rounds(1n)).state).to.equal(0n); // RoundState.Inactive
      expect(await feeToken.balanceOf(await feePb.getAddress())).to.equal(0n);
    });

    it("restricts startRound to council", async function () {
      await expectRevert(
        pb.connect(attacker).startRound(toWei("10000")),
        "AccessControl"
      );
    });

    it("does not expose a pending round to malicious token callbacks during startRound", async function () {
      const ReentrantToken = await ethers.getContractFactory("StartRoundReentrantToken");
      const reentrantToken = await ReentrantToken.deploy();
      await reentrantToken.waitForDeployment();

      const PB = await ethers.getContractFactory("PatientFundParticipatoryBudgeting");
      const reentrantPb = await PB.deploy(await reentrantToken.getAddress(), council.address, guardian.address);
      await reentrantPb.waitForDeployment();

      await reentrantToken.setTarget(await reentrantPb.getAddress());
      await reentrantToken.mint(council.address, toWei("50000"));
      await reentrantToken.connect(council).approve(await reentrantPb.getAddress(), toWei("50000"));

      const councilRole = await reentrantPb.COUNCIL_ROLE();
      await reentrantPb.connect(council).grantRole(councilRole, await reentrantToken.getAddress());

      await reentrantPb.connect(council).startRound(toWei("1000"));
      await reentrantPb.connect(council).finalizeRound(1n);
      expect((await reentrantPb.rounds(1n)).state).to.equal(2n); // RoundState.Finalized

      await reentrantToken.setAttackEnabled(true);
      await reentrantPb.connect(council).startRound(toWei("2000"));

      expect(await reentrantToken.callbackCount()).to.equal(1n);
      expect(await reentrantToken.observedCurrentRound()).to.equal(1n);
      expect(await reentrantToken.observedNextRoundState()).to.equal(0n); // RoundState.Inactive during callback
      expect(await reentrantToken.observedNextRoundProjectCount()).to.equal(0n);
      expect(await reentrantToken.unexpectedSuccessCount()).to.equal(0n);
      expect(await reentrantToken.recursiveStartRoundBlocked()).to.be.true;
      expect(await reentrantToken.registerVoterBlocked()).to.be.true;
      expect(await reentrantToken.registerVotersBatchBlocked()).to.be.true;
      expect(await reentrantToken.registerProjectBlocked()).to.be.true;
      expect(await reentrantToken.proposeProjectBlocked()).to.be.true;
      expect(await reentrantToken.supportProposalBlocked()).to.be.true;
      expect(await reentrantToken.castVoteBlocked()).to.be.true;

      expect(await reentrantPb.currentRound()).to.equal(2n);
      const r = await reentrantPb.rounds(2n);
      expect(r.matchingPool).to.equal(toWei("2000"));
      expect(r.state).to.equal(1n); // RoundState.Active after transfer succeeds
      expect(r.projectCount).to.equal(0n);
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

    it("caps projects so round finalization remains executable", async function () {
      await pb.connect(council).startRound(toWei("10000"));
      const maxProjects = await pb.MAX_PROJECTS_PER_ROUND();
      for (let i = 0n; i < maxProjects; i++) {
        await pb.connect(council).registerProject(1n, `Project ${i}`, recipientA.address);
      }

      await expectRevert(
        pb.connect(council).registerProject(1n, "Project over limit", recipientB.address),
        "ProjectLimitReached"
      );
      expect((await pb.rounds(1n)).projectCount).to.equal(maxProjects);
    });

    it("allows council to register voters in batch", async function () {
      await pb.connect(council).startRound(toWei("10000"));
      const voterAddrs = voters.map(v => v.address);
      await pb.connect(council).registerVotersBatch(1n, voterAddrs);

      for (const voter of voters) {
        expect(await pb.registeredVoters(1n, voter.address)).to.be.true;
      }
    });

    it("caps voter registration batch size", async function () {
      await pb.connect(council).startRound(toWei("10000"));
      const maxBatch = Number(await pb.MAX_VOTERS_PER_BATCH());
      const oversizedBatch = Array.from({ length: maxBatch + 1 }, () => voters[0].address);

      await expectRevert(
        pb.connect(council).registerVotersBatch(1n, oversizedBatch),
        "BatchTooLarge"
      );
    });
  });

  describe("Squared Vote Weight & Payout Distribution", function () {
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

    it("calculates matching distribution using squared vote weights", async function () {
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

      // 1. Finalize round - should not distribute directly
      await pb.connect(council).finalizeRound(1n);

      // Verify no balance changes yet
      expect(await token.balanceOf(recipientA.address)).to.equal(balBeforeA);
      expect(await token.balanceOf(recipientB.address)).to.equal(balBeforeB);

      // 2. Claim match share for project 0 (A) and project 1 (B)
      await pb.claimMatchShare(1n, 0n);
      await pb.claimMatchShare(1n, 1n);

      const balAfterA = await token.balanceOf(recipientA.address);
      const balAfterB = await token.balanceOf(recipientB.address);

      expect(balAfterA - balBeforeA).to.equal(toWei("8000"));
      expect(balAfterB - balBeforeB).to.equal(toWei("2000"));

      const r = await pb.rounds(1n);
      expect(r.state).to.equal(2n); // RoundState.Finalized is enum value 2
    });

    it("reverts claims made before round is finalized", async function () {
      // Voter casts vote
      await pb.connect(voters[0]).castVote(1n, 0n);
      
      // Attempting to claim before finalization should revert
      await expectRevert(
        pb.claimMatchShare(1n, 0n),
        "WrongRoundState"
      );
    });

    it("documents underfunded finalized rounds: smaller shares can claim, larger shares revert", async function () {
      // Project 0 receives 80% of the pool; project 1 receives 20%.
      await pb.connect(voters[0]).castVote(1n, 0n);
      await pb.connect(voters[1]).castVote(1n, 0n);
      await pb.connect(voters[2]).castVote(1n, 0n);
      await pb.connect(voters[3]).castVote(1n, 0n);
      await pb.connect(voters[4]).castVote(1n, 1n);
      await pb.connect(voters[5]).castVote(1n, 1n);

      await pb.connect(council).finalizeRound(1n);
      expect(await pb.roundProjectShares(1n, 0n)).to.equal(toWei("8000"));
      expect(await pb.roundProjectShares(1n, 1n)).to.equal(toWei("2000"));

      // Simulate unexpected matching-token liquidity loss after shares are committed.
      await token.burn(await pb.getAddress(), toWei("5000"));
      expect(await token.balanceOf(await pb.getAddress())).to.equal(toWei("5000"));

      const recipientBBefore = await token.balanceOf(recipientB.address);
      await pb.claimMatchShare(1n, 1n);
      expect(await token.balanceOf(recipientB.address) - recipientBBefore).to.equal(toWei("2000"));
      expect(await token.balanceOf(await pb.getAddress())).to.equal(toWei("3000"));

      await expectRevert(
        pb.claimMatchShare(1n, 0n),
        "InsufficientContractBalance"
      );
      expect(await pb.roundProjectShares(1n, 0n)).to.equal(toWei("8000"));
    });

    it("reverts double claims and claims for zero shares", async function () {
      // Voter casts vote for project 0
      await pb.connect(voters[0]).castVote(1n, 0n);
      await pb.connect(council).finalizeRound(1n);

      // Claim first time succeeds
      await pb.claimMatchShare(1n, 0n);

      // Claim second time reverts
      await expectRevert(
        pb.claimMatchShare(1n, 0n),
        "ZeroAmount"
      );

      // Claim for project 1 (0 votes, so 0 share) reverts
      await expectRevert(
        pb.claimMatchShare(1n, 1n),
        "ZeroAmount"
      );
    });

    it("allows council to reclaim unclaimed project shares only after the grace period", async function () {
      await pb.connect(voters[0]).castVote(1n, 0n);

      await expectRevert(
        pb.connect(council).reclaimUnclaimedMatchShare(1n, 0n),
        "WrongRoundState"
      );

      await pb.connect(council).finalizeRound(1n);

      await expectRevert(
        pb.connect(council).reclaimUnclaimedMatchShare(1n, 0n),
        "ReclaimGracePeriodNotElapsed"
      );

      await ethers.provider.send("evm_increaseTime", [90 * 24 * 60 * 60 + 1]);
      await ethers.provider.send("evm_mine", []);

      await expectRevert(
        pb.connect(council).reclaimUnclaimedMatchShare(1n, 999n),
        "ProjectInactive"
      );

      const councilBefore = await token.balanceOf(council.address);
      const tx = await pb.connect(council).reclaimUnclaimedMatchShare(1n, 0n);
      const receipt = await tx.wait();
      const event = receipt.logs.find(x => x.fragment && x.fragment.name === "MatchShareReclaimed");
      expect(event).to.not.be.undefined;
      expect(event.args[0]).to.equal(1n);
      expect(event.args[1]).to.equal(0n);
      expect(event.args[2]).to.equal(recipientA.address);
      expect(event.args[3]).to.equal(toWei("10000"));
      const councilAfter = await token.balanceOf(council.address);

      expect(councilAfter).to.equal(councilBefore);
      expect(await pb.recycledMatchingPool()).to.equal(toWei("10000"));
      expect(await pb.roundProjectShares(1n, 0n)).to.equal(0n);

      await expectRevert(
        pb.claimMatchShare(1n, 0n),
        "ZeroAmount"
      );
      await expectRevert(
        pb.connect(council).reclaimUnclaimedMatchShare(1n, 0n),
        "ZeroAmount"
      );

      await pb.connect(council).startRound(0n);
      const nextRound = await pb.rounds(2n);
      expect(nextRound.matchingPool).to.equal(toWei("10000"));
      expect(await pb.recycledMatchingPool()).to.equal(0n);
    });

    it("documents reclaim and recycling after matching-token liquidity is depleted", async function () {
      await pb.connect(voters[0]).castVote(1n, 0n);
      await pb.connect(council).finalizeRound(1n);
      expect(await pb.roundProjectShares(1n, 0n)).to.equal(toWei("10000"));

      await token.burn(await pb.getAddress(), toWei("10000"));
      expect(await token.balanceOf(await pb.getAddress())).to.equal(0n);

      await ethers.provider.send("evm_increaseTime", [90 * 24 * 60 * 60 + 1]);
      await ethers.provider.send("evm_mine", []);

      await pb.connect(council).reclaimUnclaimedMatchShare(1n, 0n);
      expect(await pb.recycledMatchingPool()).to.equal(toWei("10000"));
      expect(await pb.roundProjectShares(1n, 0n)).to.equal(0n);

      await pb.connect(council).startRound(0n);
      const nextRound = await pb.rounds(2n);
      expect(nextRound.matchingPool).to.equal(toWei("10000"));
      expect(await pb.recycledMatchingPool()).to.equal(0n);
      expect(await token.balanceOf(await pb.getAddress())).to.equal(0n);

      await pb.connect(council).registerProject(2n, "Recycled Empty Pool", recipientA.address);
      await pb.connect(council).registerVotersBatch(2n, [voters[0].address]);
      await pb.connect(voters[0]).castVote(2n, 0n);
      await expectRevert(
        pb.connect(council).finalizeRound(2n),
        "InsufficientSolvencyBalance"
      );

      // Top up the contract to satisfy the hard solvency check
      await token.mint(await pb.getAddress(), toWei("10000"));
      await pb.connect(council).finalizeRound(2n);
      expect(await pb.roundProjectShares(2n, 0n)).to.equal(toWei("10000"));

      // Claiming Project share succeeds after top-up
      await pb.claimMatchShare(2n, 0n);
      expect(await pb.roundProjectShares(2n, 0n)).to.equal(0n);
    });

    it("lets the project recipient claim before the reclaim grace period expires", async function () {
      await pb.connect(voters[0]).castVote(1n, 0n);
      await pb.connect(council).finalizeRound(1n);

      await ethers.provider.send("evm_increaseTime", [89 * 24 * 60 * 60]);
      await ethers.provider.send("evm_mine", []);

      const recipientBefore = await token.balanceOf(recipientA.address);
      await pb.claimMatchShare(1n, 0n);
      const recipientAfter = await token.balanceOf(recipientA.address);

      expect(recipientAfter - recipientBefore).to.equal(toWei("10000"));

      await ethers.provider.send("evm_increaseTime", [2 * 24 * 60 * 60]);
      await ethers.provider.send("evm_mine", []);

      await expectRevert(
        pb.connect(council).reclaimUnclaimedMatchShare(1n, 0n),
        "ZeroAmount"
      );
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
    const credentialHash = ethers.keccak256(ethers.toUtf8Bytes("test-credential"));
    const policyVersion = ethers.keccak256(ethers.toUtf8Bytes("fiduciary-credential-policy-v1"));

    beforeEach(async function () {
      const signers = await ethers.getSigners();
      relayer = signers[8]; // Assign a specific signer as the relayer
      voter = signers[4];
      
      await pb.connect(council).startRound(toWei("10000"));
      await pb.connect(council).setRelayerVerifier(relayer.address);
    });

    async function registrationTypedData(targetVoter = voter, roundId = 1n, deadline) {
      const nonce = await pb.registrationNonces(roundId, targetVoter.address);
      const { chainId } = await ethers.provider.getNetwork();
      return {
        domain: {
          name: "Pharmacy Fiduciary Commons",
          version: "1",
          chainId,
          verifyingContract: await pb.getAddress()
        },
        types: {
          VoterRegistration: [
            { name: "roundId", type: "uint256" },
            { name: "voter", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "credentialHash", type: "bytes32" },
            { name: "policyVersion", type: "bytes32" },
            { name: "deadline", type: "uint256" }
          ]
        },
        value: { roundId, voter: targetVoter.address, nonce, credentialHash, policyVersion, deadline }
      };
    }

    async function authorizationDeadline(offset = 3600n) {
      const block = await ethers.provider.getBlock("latest");
      return BigInt(block.timestamp) + offset;
    }

    async function signRegistration(targetVoter = voter, roundId = 1n, deadline) {
      const expiresAt = deadline ?? await authorizationDeadline();
      const typedData = await registrationTypedData(targetVoter, roundId, expiresAt);
      const signature = await relayer.signTypedData(typedData.domain, typedData.types, typedData.value);
      return { signature, deadline: expiresAt };
    }

    it("allows a voter to self-register with a valid relayer signature", async function () {
      const { signature, deadline } = await signRegistration();

      await pb.connect(voter).registerVoterWithSignature(
        1n, voter.address, credentialHash, policyVersion, deadline, signature
      );
      expect(await pb.registeredVoters(1n, voter.address)).to.be.true;
      expect(await pb.registrationNonces(1n, voter.address)).to.equal(1n);
    });

    it("allows an ERC-1271 verifier contract to authorize voter self-registration", async function () {
      const MockERC1271Verifier = await ethers.getContractFactory("MockERC1271Verifier");
      const verifier = await MockERC1271Verifier.deploy(relayer.address);
      await pb.connect(council).setRelayerVerifier(await verifier.getAddress());

      const { signature, deadline } = await signRegistration();

      await pb.connect(voter).registerVoterWithSignature(
        1n, voter.address, credentialHash, policyVersion, deadline, signature
      );
      expect(await pb.registeredVoters(1n, voter.address)).to.be.true;
      expect(await pb.registrationNonces(1n, voter.address)).to.equal(1n);
    });

    it("rejects signatures when the ERC-1271 verifier does not approve them", async function () {
      const MockERC1271Verifier = await ethers.getContractFactory("MockERC1271Verifier");
      const verifier = await MockERC1271Verifier.deploy(attacker.address);
      await pb.connect(council).setRelayerVerifier(await verifier.getAddress());

      const { signature, deadline } = await signRegistration();

      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(
          1n, voter.address, credentialHash, policyVersion, deadline, signature
        ),
        "Unauthorized"
      );
    });

    it("consumes relayer signatures and invalidates outstanding signatures on council revocation", async function () {
      const consumed = await signRegistration();
      await pb.connect(voter).registerVoterWithSignature(
        1n, voter.address, credentialHash, policyVersion, consumed.deadline, consumed.signature
      );

      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(
          1n, voter.address, credentialHash, policyVersion, consumed.deadline, consumed.signature
        ),
        "Unauthorized"
      );

      const outstanding = await signRegistration();
      await pb.connect(council).registerVoter(1n, voter.address, false);
      expect(await pb.registeredVoters(1n, voter.address)).to.be.false;

      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(
          1n, voter.address, credentialHash, policyVersion, outstanding.deadline, outstanding.signature
        ),
        "Unauthorized"
      );
    });

    it("reverts if the signature is invalid or signed by an unauthorized key", async function () {
      const deadline = await authorizationDeadline();
      const typedData = await registrationTypedData(voter, 1n, deadline);
      const invalidSignature = await attacker.signTypedData(
        typedData.domain, typedData.types, typedData.value
      );

      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(
          1n, voter.address, credentialHash, policyVersion, deadline, invalidSignature
        ),
        "Unauthorized"
      );
    });

    it("prevents signature replay across different voters or rounds", async function () {
      const { signature, deadline } = await signRegistration();

      // Attempt to register another voter address using the same signature
      const otherVoter = voters[1];
      await expectRevert(
        pb.connect(otherVoter).registerVoterWithSignature(
          1n, otherVoter.address, credentialHash, policyVersion, deadline, signature
        ),
        "Unauthorized"
      );

      // Attempt to register on a different round using the same signature
      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(
          2n, voter.address, credentialHash, policyVersion, deadline, signature
        ),
        "WrongRoundState"
      );
    });

    it("requires the signed voter to submit the self-registration transaction", async function () {
      const { signature, deadline } = await signRegistration();

      await expectRevert(
        pb.connect(attacker).registerVoterWithSignature(
          1n, voter.address, credentialHash, policyVersion, deadline, signature
        ),
        "Unauthorized"
      );
    });

    it("rejects invalid-v and high-s relayer signatures", async function () {
      const { signature, deadline } = await signRegistration();
      const parsed = ethers.Signature.from(signature);

      const invalidVSignature = ethers.hexlify(ethers.concat([
        ethers.getBytes(parsed.r),
        ethers.getBytes(parsed.s),
        Uint8Array.from([1])
      ]));

      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(
          1n, voter.address, credentialHash, policyVersion, deadline, invalidVSignature
        ),
        "Unauthorized"
      );

      const curveOrder = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
      const highS = ethers.toBeHex(curveOrder - BigInt(parsed.s), 32);
      const flippedV = parsed.v === 27 ? 28 : 27;
      const highSSignature = ethers.hexlify(ethers.concat([
        ethers.getBytes(parsed.r),
        ethers.getBytes(highS),
        Uint8Array.from([flippedV])
      ]));

      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(
          1n, voter.address, credentialHash, policyVersion, deadline, highSSignature
        ),
        "Unauthorized"
      );
    });

    it("rejects expired or metadata-tampered registration authorizations", async function () {
      const deadline = await authorizationDeadline(10n);
      const { signature } = await signRegistration(voter, 1n, deadline);

      await ethers.provider.send("evm_setNextBlockTimestamp", [Number(deadline + 1n)]);
      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(
          1n, voter.address, credentialHash, policyVersion, deadline, signature
        ),
        "AuthorizationExpired"
      );

      const fresh = await signRegistration();
      const differentCredential = ethers.keccak256(ethers.toUtf8Bytes("different-credential"));
      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(
          1n, voter.address, differentCredential, policyVersion, fresh.deadline, fresh.signature
        ),
        "Unauthorized"
      );
    });

    it("rejects verifier-signed authorizations from an unsupported policy version", async function () {
      const deadline = await authorizationDeadline();
      const unsupportedPolicy = ethers.keccak256(ethers.toUtf8Bytes("fiduciary-credential-policy-v2"));
      const nonce = await pb.registrationNonces(1n, voter.address);
      const { chainId } = await ethers.provider.getNetwork();
      const domain = {
        name: "Pharmacy Fiduciary Commons",
        version: "1",
        chainId,
        verifyingContract: await pb.getAddress()
      };
      const types = {
        VoterRegistration: [
          { name: "roundId", type: "uint256" },
          { name: "voter", type: "address" },
          { name: "nonce", type: "uint256" },
          { name: "credentialHash", type: "bytes32" },
          { name: "policyVersion", type: "bytes32" },
          { name: "deadline", type: "uint256" }
        ]
      };
      const signature = await relayer.signTypedData(domain, types, {
        roundId: 1n,
        voter: voter.address,
        nonce,
        credentialHash,
        policyVersion: unsupportedPolicy,
        deadline
      });

      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(
          1n, voter.address, credentialHash, unsupportedPolicy, deadline, signature
        ),
        "UnsupportedCredentialPolicy"
      );
    });
  });

  describe("Active Round, Pausable & Sweep Enhancements", function () {
    it("prevents starting a new round if the current round is still active", async function () {
      await pb.connect(council).startRound(toWei("1000"));
      // Try starting another round while it's active
      await expectRevert(
        pb.connect(council).startRound(toWei("1000")),
        "RoundAlreadyActive"
      );
    });

    it("enforces constructor guardian and council separation", async function () {
      const PB = await ethers.getContractFactory("PatientFundParticipatoryBudgeting");
      await expectRevert(
        PB.deploy(await token.getAddress(), council.address, council.address),
        "GuardianMustDifferFromCouncil"
      );
    });

    it("allows guardian to pause and blocks all state changes, then council can unpause", async function () {
      await pb.connect(council).startRound(toWei("1000"));
      await pb.connect(council).registerVoter(1n, voters[0].address, true);

      // Guardian pauses
      await pb.connect(guardian).pause();

      // Check actions revert when paused
      await expectRevert(
        pb.connect(council).registerProject(1n, "Solar Grid", recipientA.address),
        "Pausable: paused"
      );
      await expectRevert(
        pb.connect(voters[0]).castVote(1n, 0n),
        "Pausable: paused"
      );

      // Attacker cannot unpause
      await expectRevert(
        pb.connect(attacker).unpause(),
        "AccessControl"
      );

      // Council unpauses
      await pb.connect(council).unpause();

      // Actions now succeed
      await pb.connect(council).registerProject(1n, "Solar Grid", recipientA.address);
      await pb.connect(voters[0]).castVote(1n, 0n);
    });

    it("allows council to sweep accidental non-matching ERC-20 tokens, but not matching pool token", async function () {
      const MockERC20 = await ethers.getContractFactory("MockERC20");
      const badToken = await MockERC20.deploy("Bad Token", "BAD", 18);
      await badToken.waitForDeployment();

      await badToken.mint(await pb.getAddress(), toWei("500"));
      expect(await badToken.balanceOf(await pb.getAddress())).to.equal(toWei("500"));

      // Attacker cannot sweep
      await expectRevert(
        pb.connect(attacker).sweep(await badToken.getAddress(), toWei("500")),
        "AccessControl"
      );

      // Council sweeps non-matching token
      const councilBefore = await badToken.balanceOf(council.address);
      await pb.connect(council).sweep(await badToken.getAddress(), toWei("500"));
      const councilAfter = await badToken.balanceOf(council.address);
      expect(councilAfter - councilBefore).to.equal(toWei("500"));

      // Cannot sweep the matching token
      await expectRevert(
        pb.connect(council).sweep(await token.getAddress(), toWei("500")),
        "CannotSweepMatchingToken"
      );
    });

    it("refunds dust and zero-vote pools to council address, not msg.sender", async function () {
      // Grant COUNCIL_ROLE to another signer (recipientA)
      const councilRole = await pb.COUNCIL_ROLE();
      await pb.connect(council).grantRole(councilRole, recipientA.address);

      // Start a round using council
      await pb.connect(council).startRound(toWei("1000"));

      // 1. Test zero-vote refund: finalize round (0 votes cast) using recipientA
      const councilBalBefore = await token.balanceOf(council.address);
      const recipientABalBefore = await token.balanceOf(recipientA.address);

      // RecipientA finalizes the round
      await pb.connect(recipientA).finalizeRound(1n);

      const councilBalAfter = await token.balanceOf(council.address);
      const recipientABalAfter = await token.balanceOf(recipientA.address);

      // The refund should go to council, not recipientA
      expect(councilBalAfter - councilBalBefore).to.equal(toWei("1000"));
      expect(recipientABalAfter).to.equal(recipientABalBefore);

      // 2. Test dust refund: Start a second round
      await pb.connect(council).startRound(toWei("1000")); // Round 2
      await pb.connect(council).registerProject(2n, "Project A", recipientB.address);
      await pb.connect(council).registerProject(2n, "Project B", recipientB.address);
      await pb.connect(council).registerProject(2n, "Project C", recipientB.address);
      await pb.connect(council).registerVotersBatch(2n, [voters[0].address, voters[1].address, voters[2].address]);

      // Project 0 gets 1 vote. Weight = 1.
      // Project 1 gets 1 vote. Weight = 1.
      // Project 2 gets 1 vote. Weight = 1.
      // Total weight = 3.
      // 1000 * 1 / 3 = 333.333333333333333333
      // Total distributed = 999.999999999999999999
      // Dust = 1 wei
      await pb.connect(voters[0]).castVote(2n, 0n);
      await pb.connect(voters[1]).castVote(2n, 1n);
      await pb.connect(voters[2]).castVote(2n, 2n);

      const councilBalBeforeDust = await token.balanceOf(council.address);
      const recipientABalBeforeDust = await token.balanceOf(recipientA.address);

      // Finalize round 2 using recipientA
      await pb.connect(recipientA).finalizeRound(2n);

      const councilBalAfterDust = await token.balanceOf(council.address);
      const recipientABalAfterDust = await token.balanceOf(recipientA.address);

      // The dust (1 wei) should go to council, not recipientA
      expect(councilBalAfterDust - councilBalBeforeDust).to.equal(1n); // 1 wei
      expect(recipientABalAfterDust).to.equal(recipientABalBeforeDust);
    });
  });

  describe("On-Chain Credential Voter Registration", function () {
    let issuer;
    const credentialHash = ethers.keccak256(ethers.toUtf8Bytes("voter-credential-123"));
    const policyVersion = ethers.keccak256(ethers.toUtf8Bytes("fiduciary-credential-policy-v1"));

    async function signIssuerCredential(voter, roundId, hash = credentialHash, policy = policyVersion, deadline = null) {
      const nonce = await pb.registrationNonces(roundId, voter.address);
      const expiresAt = deadline ?? BigInt((await ethers.provider.getBlock("latest")).timestamp + 3600);
      const { chainId } = await ethers.provider.getNetwork();
      const domain = {
        name: "Pharmacy Fiduciary Commons",
        version: "1",
        chainId,
        verifyingContract: await pb.getAddress()
      };
      const types = {
        VoterCredential: [
          { name: "roundId", type: "uint256" },
          { name: "voter", type: "address" },
          { name: "nonce", type: "uint256" },
          { name: "credentialHash", type: "bytes32" },
          { name: "policyVersion", type: "bytes32" },
          { name: "deadline", type: "uint256" }
        ]
      };
      const value = {
        roundId,
        voter: voter.address,
        nonce,
        credentialHash: hash,
        policyVersion: policy,
        deadline: expiresAt
      };
      const signature = await issuer.signTypedData(domain, types, value);
      return { deadline: expiresAt, signature };
    }

    beforeEach(async function () {
      issuer = ethers.Wallet.createRandom().connect(ethers.provider);
      // Start round 1
      await pb.connect(council).startRound(toWei("1000"));
    });

    it("allows council to configure trusted issuers, but restricts to council", async function () {
      await pb.connect(council).setTrustedCredentialIssuer(issuer.address, true);
      expect(await pb.trustedCredentialIssuers(issuer.address)).to.be.true;

      await expectRevert(
        pb.connect(attacker).setTrustedCredentialIssuer(issuer.address, false),
        "AccessControl"
      );
    });

    it("allows a voter to self-register with a valid trusted issuer signature", async function () {
      await pb.connect(council).setTrustedCredentialIssuer(issuer.address, true);

      const { deadline, signature } = await signIssuerCredential(voters[0], 1n);

      // Voter self-registers
      await pb.connect(voters[0]).registerVoterWithCredential(
        1n,
        credentialHash,
        policyVersion,
        deadline,
        signature
      );

      expect(await pb.registeredVoters(1n, voters[0].address)).to.be.true;
      expect(await pb.registrationNonces(1n, voters[0].address)).to.equal(1n);
    });

    it("reverts if the issuer is not trusted", async function () {
      // Issuer is NOT configured as trusted
      const { deadline, signature } = await signIssuerCredential(voters[0], 1n);

      await expectRevert(
        pb.connect(voters[0]).registerVoterWithCredential(
          1n,
          credentialHash,
          policyVersion,
          deadline,
          signature
        ),
        "Unauthorized"
      );
    });

    it("reverts if the signature is invalid or tampered", async function () {
      await pb.connect(council).setTrustedCredentialIssuer(issuer.address, true);

      const { deadline, signature } = await signIssuerCredential(voters[1], 1n);

      // Voter 0 tries to use Voter 1's signature
      await expectRevert(
        pb.connect(voters[0]).registerVoterWithCredential(
          1n,
          credentialHash,
          policyVersion,
          deadline,
          signature
        ),
        "Unauthorized"
      );
    });

    it("rejects expired or nonce-stale trusted issuer signatures", async function () {
      await pb.connect(council).setTrustedCredentialIssuer(issuer.address, true);

      const expiredDeadline = BigInt((await ethers.provider.getBlock("latest")).timestamp - 1);
      const expired = await signIssuerCredential(voters[0], 1n, credentialHash, policyVersion, expiredDeadline);

      await expectRevert(
        pb.connect(voters[0]).registerVoterWithCredential(
          1n,
          credentialHash,
          policyVersion,
          expired.deadline,
          expired.signature
        ),
        "AuthorizationExpired"
      );

      const current = await signIssuerCredential(voters[0], 1n);
      await pb.connect(council).registerVoter(1n, voters[0].address, false);

      await expectRevert(
        pb.connect(voters[0]).registerVoterWithCredential(
          1n,
          credentialHash,
          policyVersion,
          current.deadline,
          current.signature
        ),
        "Unauthorized"
      );
    });

    it("rejects trusted issuer signatures replayed across deployments", async function () {
      await pb.connect(council).setTrustedCredentialIssuer(issuer.address, true);
      const { deadline, signature } = await signIssuerCredential(voters[0], 1n);

      const PB = await ethers.getContractFactory("PatientFundParticipatoryBudgeting");
      const otherPb = await PB.deploy(await token.getAddress(), council.address, guardian.address);
      await otherPb.waitForDeployment();
      await token.connect(council).approve(await otherPb.getAddress(), toWei("1000"));
      await otherPb.connect(council).startRound(toWei("1000"));
      await otherPb.connect(council).setTrustedCredentialIssuer(issuer.address, true);

      await expectRevert(
        otherPb.connect(voters[0]).registerVoterWithCredential(
          1n,
          credentialHash,
          policyVersion,
          deadline,
          signature
        ),
        "Unauthorized"
      );
    });

    it("reverts if the policy version is unsupported", async function () {
      await pb.connect(council).setTrustedCredentialIssuer(issuer.address, true);
      const badPolicy = ethers.keccak256(ethers.toUtf8Bytes("bad-policy-v2"));

      const { deadline, signature } = await signIssuerCredential(voters[0], 1n, credentialHash, badPolicy);

      await expectRevert(
        pb.connect(voters[0]).registerVoterWithCredential(
          1n,
          credentialHash,
          badPolicy,
          deadline,
          signature
        ),
        "UnsupportedCredentialPolicy"
      );
    });
  });

  describe("Decentralized Project Proposals", function () {
    const title = "Clean Water Initiative";

    beforeEach(async function () {
      await pb.connect(council).startRound(toWei("1000"));
      // Register voters[0], voters[1], voters[2]
      await pb.connect(council).registerVotersBatch(1n, [
        voters[0].address,
        voters[1].address,
        voters[2].address
      ]);
    });

    it("allows registered voters to propose a project", async function () {
      await pb.connect(voters[0]).proposeProject(1n, title, recipientA.address);
      const prop = await pb.roundProposals(1n, 0n);
      expect(prop.title).to.equal(title);
      expect(prop.recipient).to.equal(recipientA.address);
      expect(prop.supportCount).to.equal(0n);
      expect(prop.registered).to.be.false;

      expect(await pb.roundProposalCount(1n)).to.equal(1n);
    });

    it("reverts if non-registered voter attempts to propose", async function () {
      await expectRevert(
        pb.connect(attacker).proposeProject(1n, title, recipientA.address),
        "Unauthorized"
      );
    });

    it("allows registered voters to support proposals and auto-registers at threshold", async function () {
      await pb.connect(council).setProjectSupportThreshold(2n);
      await pb.connect(voters[0]).proposeProject(1n, title, recipientA.address);

      // Support 1
      await pb.connect(voters[0]).supportProposal(1n, 0n);
      let prop = await pb.roundProposals(1n, 0n);
      expect(prop.supportCount).to.equal(1n);
      expect(prop.registered).to.be.false;

      // Support 2 (reaches threshold of 2)
      await pb.connect(voters[1]).supportProposal(1n, 0n);
      prop = await pb.roundProposals(1n, 0n);
      expect(prop.supportCount).to.equal(2n);
      expect(prop.registered).to.be.true; // Marked as registered!

      // Verify project is now in roundProjects and count has updated
      const proj = await pb.roundProjects(1n, 0n);
      expect(proj.title).to.equal(title);
      expect(proj.recipient).to.equal(recipientA.address);
      expect(proj.active).to.be.true;
      expect((await pb.rounds(1n)).projectCount).to.equal(1n);
    });

    it("reverts if a voter double supports a proposal", async function () {
      await pb.connect(voters[0]).proposeProject(1n, title, recipientA.address);
      await pb.connect(voters[0]).supportProposal(1n, 0n);

      await expectRevert(
        pb.connect(voters[0]).supportProposal(1n, 0n),
        "AlreadySupported"
      );
    });

    it("reverts if supporting an already registered proposal", async function () {
      await pb.connect(council).setProjectSupportThreshold(1n);
      await pb.connect(voters[0]).proposeProject(1n, title, recipientA.address);

      // Support 1 (auto-registers because threshold = 1)
      await pb.connect(voters[0]).supportProposal(1n, 0n);

      // Attempt to support again by another voter
      await expectRevert(
        pb.connect(voters[1]).supportProposal(1n, 0n),
        "ProposalAlreadyRegistered"
      );
    });

    it("reverts if supporting a non-existent proposal", async function () {
      await expectRevert(
        pb.connect(voters[0]).supportProposal(1n, 999n),
        "ProposalDoesNotExist"
      );
    });
    it("allows council to set support threshold, but restricts to council", async function () {
      await pb.connect(council).setProjectSupportThreshold(5n);
      expect(await pb.projectSupportThreshold()).to.equal(5n);

      await expectRevert(
        pb.connect(attacker).setProjectSupportThreshold(2n),
        "AccessControl"
      );
    });
  });

  describe("Patient Fund Balance Verification & Dry-Run Preview", function () {
    beforeEach(async function () {
      // Start a round with 1000 tokens
      await pb.connect(council).startRound(toWei("1000"));

      // Register voters
      await pb.connect(council).registerVotersBatch(1n, [
        voters[0].address,
        voters[1].address
      ]);

      // Register projects
      await pb.connect(council).registerProject(1n, "Project Alpha", recipientA.address);
      await pb.connect(council).registerProject(1n, "Project Beta", recipientB.address);

      // Vote
      await pb.connect(voters[0]).castVote(1n, 0n); // Project Alpha gets 1 vote
      await pb.connect(voters[1]).castVote(1n, 0n); // Project Alpha gets 2 votes total
      await pb.connect(voters[0]).castVote(1n, 1n); // Project Beta gets 1 vote total
    });

    it("tracks totalUnclaimedShares correctly on finalize, claim, and reclaim", async function () {
      // Initial unclaimed shares should be 0
      expect(await pb.totalUnclaimedShares()).to.equal(0n);

      // Finalize Round
      // Project Alpha weight: 4. Project Beta weight: 1. Total weight: 5.
      // Project Alpha share: 4/5 * 1000 = 800.
      // Project Beta share: 1/5 * 1000 = 200.
      await pb.connect(council).finalizeRound(1n);

      // totalUnclaimedShares should now be 1000
      expect(await pb.totalUnclaimedShares()).to.equal(toWei("1000"));

      // User claims Project Beta share (200)
      await pb.claimMatchShare(1n, 1n);
      expect(await pb.totalUnclaimedShares()).to.equal(toWei("800"));

      // Fast forward MATCH_RECLAIM_GRACE_PERIOD (90 days)
      await ethers.provider.send("evm_increaseTime", [90 * 24 * 60 * 60 + 1]);
      await ethers.provider.send("evm_mine");

      // Council reclaims Project Alpha share (800)
      await pb.connect(council).reclaimUnclaimedMatchShare(1n, 0n);

      // totalUnclaimedShares should now be 0 (since it moved to recycledMatchingPool)
      expect(await pb.totalUnclaimedShares()).to.equal(0n);
      expect(await pb.recycledMatchingPool()).to.equal(toWei("800"));
    });

    it("verifies previewFinalize works correctly", async function () {
      const preview = await pb.previewFinalize(1n);

      expect(preview.projects[0]).to.equal(recipientA.address);
      expect(preview.projects[1]).to.equal(recipientB.address);
      expect(preview.expectedShares[0]).to.equal(toWei("800"));
      expect(preview.expectedShares[1]).to.equal(toWei("200"));
      expect(preview.actualBalance).to.equal(toWei("1000"));
      expect(preview.totalRequiredAfterFinalize).to.equal(toWei("1000"));
      expect(preview.isSufficient).to.be.true;
    });

    it("verifies dryRunFinalize matches previewFinalize", async function () {
      const preview = await pb.previewFinalize(1n);
      const dryRun = await pb.dryRunFinalize(1n);

      expect(dryRun.projects).to.deep.equal(preview.projects);
      expect(dryRun.expectedShares).to.deep.equal(preview.expectedShares);
      expect(dryRun.actualBalance).to.equal(preview.actualBalance);
      expect(dryRun.totalRequiredAfterFinalize).to.equal(preview.totalRequiredAfterFinalize);
      expect(dryRun.isSufficient).to.equal(preview.isSufficient);
    });

    it("reverts claimMatchShare and emits event if contract is depleted", async function () {
      // Finalize Round (allocates 800 and 200)
      await pb.connect(council).finalizeRound(1n);

      // Burn tokens from the contract to simulate depletion/theft/accident
      // Total contract balance is 1000. Burn 900 tokens so balance is 100.
      await token.burn(await pb.getAddress(), toWei("900"));

      // Now actual balance is 100. Attempt to claim Project Beta (requires 200).
      // Should revert with InsufficientContractBalance.
      await expectRevert(
        pb.claimMatchShare(1n, 1n),
        "InsufficientContractBalance"
      );

      // Attempt to claim Project Alpha (requires 800). Should also revert.
      await expectRevert(
        pb.claimMatchShare(1n, 0n),
        "InsufficientContractBalance"
      );
    });

    it("does not revert reclaimUnclaimedMatchShare on depletion but emits LowBalanceDetected event", async function () {
      // Finalize Round
      await pb.connect(council).finalizeRound(1n);

      // Burn tokens from contract to simulate depletion. Balance becomes 100.
      await token.burn(await pb.getAddress(), toWei("900"));

      // Fast forward MATCH_RECLAIM_GRACE_PERIOD (90 days)
      await ethers.provider.send("evm_increaseTime", [90 * 24 * 60 * 60 + 1]);
      await ethers.provider.send("evm_mine");

      // Council reclaims Project Alpha (requires 800, balance is 100).
      // This should succeed (not revert), set share to 0, and emit LowBalanceDetected and MatchShareReclaimed events.
      const tx = await pb.connect(council).reclaimUnclaimedMatchShare(1n, 0n);

      // Verify events in receipt
      const receipt = await tx.wait();
      // Find LowBalanceDetected event
      const lowBalanceLog = receipt.logs.find(
        (log) => pb.interface.parseLog(log)?.name === "LowBalanceDetected"
      );
      expect(lowBalanceLog).to.not.be.undefined;

      const parsedLog = pb.interface.parseLog(lowBalanceLog);
      expect(parsedLog.args.requested).to.equal(toWei("800"));
      expect(parsedLog.args.actual).to.equal(toWei("100"));

      // Verify state changes still succeeded
      expect(await pb.roundProjectShares(1n, 0n)).to.equal(0n);
      expect(await pb.recycledMatchingPool()).to.equal(toWei("800"));
    });

    it("blocks underfunded finalization before council refund", async function () {
      // Finalize Round 1 first to allow starting Round 2
      await pb.connect(council).finalizeRound(1n);

      // Start a new round (Round 2) with 1000 matching pool (council deposits 1000 tokens)
      await pb.connect(council).startRound(toWei("1000"));
      expect(await pb.currentRound()).to.equal(2n);

      // Simulate a depletion event: burn 900 tokens from the contract.
      // Contract balance after Round 1 finalization was 1000 (unclaimed shares for Project Alpha and Beta).
      // Council deposits 1000 for Round 2, making balance = 2000.
      // We burn 900 tokens, leaving exactly 1100 tokens.
      await token.burn(await pb.getAddress(), toWei("900"));
      expect(await token.balanceOf(await pb.getAddress())).to.equal(toWei("1100"));

      // No votes are cast for Round 2, so totalWeight is 0.
      // Preview finalization says isSufficient = false because totalUnclaimed + pool = 2000,
      // and actualBalance = 1100.
      const preview = await pb.previewFinalize(2n);
      expect(preview.isSufficient).to.be.false;

      // Finalize Round 2 reverts because the contract does not satisfy the hard solvency invariant.
      await expectRevert(
        pb.connect(council).finalizeRound(2n),
        "InsufficientSolvencyBalance"
      );

      // Verify that after topping up the contract with 900 tokens, finalization succeeds.
      await token.mint(await pb.getAddress(), toWei("900"));
      await pb.connect(council).finalizeRound(2n);

      // Contract balance after Round 2 finalization (reclaiming 1000 matching pool) is 1000.
      expect(await token.balanceOf(await pb.getAddress())).to.equal(toWei("1000"));

      // Claiming Project Alpha's share (requires 800 tokens) succeeds.
      await pb.claimMatchShare(1n, 0n);
    });

    it("registers multiple projects and asserts gas consumption bounds to prevent sybil/DoS locks", async function () {
      // Finalize Round 1 first to allow starting Round 2
      await pb.connect(council).finalizeRound(1n);

      // Start Round 2
      await pb.connect(council).startRound(toWei("1000"));
      const roundId = 2n;

      // Register voters
      const voter = voters[0];
      await pb.connect(council).registerVoter(roundId, voter.address, true);

      // Propose 20 projects to verify gas loops scale safely
      for (let i = 0; i < 20; i++) {
        await pb.connect(voter).proposeProject(roundId, `Project Sybil ${i}`, recipientA.address);
      }

      // Check gas used to finalize 20 projects
      const tx = await pb.connect(council).finalizeRound(roundId);
      const receipt = await tx.wait();
      expect(receipt.gasUsed).to.be.lessThan(3000000n); // well below block gas limit (30M)
    });

    it("prevents double-reclaiming of matched project shares", async function () {
      // Finalize Round 1 so that matching shares are recorded
      await pb.connect(council).finalizeRound(1n);

      // Let's fast forward 90 days
      // and reclaim Project Beta (index 1) which has 200 mDAI share.
      await ethers.provider.send("evm_increaseTime", [90 * 24 * 60 * 60 + 1]);
      await ethers.provider.send("evm_mine");

      // Verify original share is 200 mDAI
      expect(await pb.roundProjectShares(1n, 1n)).to.equal(toWei("200"));

      // First reclaim succeeds
      await pb.connect(council).reclaimUnclaimedMatchShare(1n, 1n);

      // Second reclaim fails with ZeroAmount because share has been set to 0
      await expectRevert(
        pb.connect(council).reclaimUnclaimedMatchShare(1n, 1n),
        "ZeroAmount"
      );
    });
  });
});
