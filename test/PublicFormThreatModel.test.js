const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Public Form & Cryptographic Threat Model", function () {
  let pb;
  let token;
  let council;
  let relayer;
  let voter;
  let attacker;
  let guardian;

  const credentialHash = ethers.keccak256(ethers.toUtf8Bytes("test-credential"));
  const policyVersion = ethers.keccak256(ethers.toUtf8Bytes("fiduciary-credential-policy-v1"));

  // EIP-712 registration types matching the contract
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

  function toWei(amount) {
    return ethers.parseEther(amount);
  }

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
    relayer = signers[1];
    voter = signers[2];
    attacker = signers[3];
    guardian = signers[4];

    // Deploy Mock ERC20
    const MockERC20 = await ethers.getContractFactory("MockERC20");
    token = await MockERC20.deploy("Mock DAI", "mDAI", 18);
    await token.waitForDeployment();

    // Deploy Budgeting Contract
    const PB = await ethers.getContractFactory("PatientFundParticipatoryBudgeting");
    pb = await PB.deploy(await token.getAddress(), council.address, guardian.address);
    await pb.waitForDeployment();

    // Configure Relayer
    await pb.connect(council).setRelayerVerifier(relayer.address);

    // Start a round
    await token.mint(council.address, toWei("50000"));
    await token.connect(council).approve(await pb.getAddress(), toWei("50000"));
    await pb.connect(council).startRound(toWei("10000"));
  });

  async function getDomain(contractAddress, chainId) {
    return {
      name: "Pharmacy Fiduciary Commons",
      version: "1",
      chainId: chainId,
      verifyingContract: contractAddress
    };
  }

  async function createSignature(targetVoter, roundId, nonce, deadline, relayerSigner, domainOverride) {
    const { chainId } = await ethers.provider.getNetwork();
    const domain = domainOverride || await getDomain(await pb.getAddress(), chainId);
    const value = {
      roundId,
      voter: targetVoter.address,
      nonce,
      credentialHash,
      policyVersion,
      deadline
    };
    return relayerSigner.signTypedData(domain, types, value);
  }

  describe("Cryptographic Signature Safety", function () {
    it("rejects duplicate registration attempts (Nonce Replay Protection)", async function () {
      const block = await ethers.provider.getBlock("latest");
      const deadline = BigInt(block.timestamp) + 3600n;
      const nonce = await pb.registrationNonces(1n, voter.address);
      
      const sig = await createSignature(voter, 1n, nonce, deadline, relayer);

      // First registration succeeds
      await pb.connect(voter).registerVoterWithSignature(
        1n, voter.address, credentialHash, policyVersion, deadline, sig
      );
      expect(await pb.registeredVoters(1n, voter.address)).to.be.true;

      // Second registration fails because the nonce has advanced to 1, causing recovered signer to be different
      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(
          1n, voter.address, credentialHash, policyVersion, deadline, sig
        ),
        "Unauthorized"
      );
    });

    it("rejects domain mismatch (Chain ID & Contract Address Protection)", async function () {
      const block = await ethers.provider.getBlock("latest");
      const deadline = BigInt(block.timestamp) + 3600n;
      const nonce = await pb.registrationNonces(1n, voter.address);

      // Sign with a different Chain ID (e.g. 1 for Mainnet instead of local network)
      const wrongChainDomain = await getDomain(await pb.getAddress(), 1n);
      const wrongChainSig = await createSignature(voter, 1n, nonce, deadline, relayer, wrongChainDomain);

      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(
          1n, voter.address, credentialHash, policyVersion, deadline, wrongChainSig
        ),
        "Unauthorized"
      );

      // Sign with a different contract address
      const wrongContractDomain = await getDomain(attacker.address, 31337n);
      const wrongContractSig = await createSignature(voter, 1n, nonce, deadline, relayer, wrongContractDomain);

      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(
          1n, voter.address, credentialHash, policyVersion, deadline, wrongContractSig
        ),
        "Unauthorized"
      );
    });

    it("rejects expired authorization signatures (Deadline Protection)", async function () {
      const block = await ethers.provider.getBlock("latest");
      const pastDeadline = BigInt(block.timestamp) - 100n; // 100 seconds in the past
      const nonce = await pb.registrationNonces(1n, voter.address);
      const expiredSig = await createSignature(voter, 1n, nonce, pastDeadline, relayer);

      await expectRevert(
        pb.connect(voter).registerVoterWithSignature(
          1n, voter.address, credentialHash, policyVersion, pastDeadline, expiredSig
        ),
        "AuthorizationExpired"
      );
    });
  });

  describe("Client-Side Form Input Threat Model Simulation", function () {
    // NOTE: This section performs threat-model checks simulating input validation rules.
    // These tests demonstrate conceptual input defenses and do not substitute for a production-level backend API audit.
    // Simulated client-side submission handler
    function processFormSubmission(fields, session = {}) {
      // 1. CSRF validation
      if (session.csrfToken && (!fields.csrfToken || fields.csrfToken !== session.csrfToken)) {
        throw new Error("CSRF token verification failed.");
      }

      // 2. Honeypot check
      if (fields.fax_number && fields.fax_number.trim().length > 0) {
        throw new Error("Spam detected: Honeypot field filled.");
      }

      // 3. Prevent hidden administrative parameter injection
      if (fields.isAdmin !== undefined || fields.userRole === "admin") {
        throw new Error("Security violation: Attempt to inject administrative parameter.");
      }

      // 4. Size limit checks
      const MAX_LENGTH = 1024;
      for (const [key, value] of Object.entries(fields)) {
        if (typeof value === "string" && value.length > MAX_LENGTH) {
          throw new Error(`Input size limit exceeded for field: ${key}`);
        }
      }

      // 5. XSS sanitization check (reject if tags or script patterns present)
      const xssPattern = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>|javascript:|on\w+=/gi;
      for (const [key, value] of Object.entries(fields)) {
        if (typeof value === "string" && xssPattern.test(value)) {
          throw new Error(`Potential XSS payload detected in field: ${key}`);
        }
      }

      return { success: true, sanitized: true };
    }

    it("detects and blocks automated spam bots using honeypot fields", function () {
      const goodSubmission = {
        name: "Co-op Pharmacy",
        email: "contact@coop.org",
        fax_number: "" // Normal user leaves honeypot empty
      };

      const badSubmission = {
        name: "Co-op Pharmacy",
        email: "contact@coop.org",
        fax_number: "555-0199" // Bot fills in honeypot
      };

      expect(processFormSubmission(goodSubmission).success).to.be.true;
      expect(() => processFormSubmission(badSubmission)).to.throw("Spam detected: Honeypot field filled.");
    });

    it("rejects oversized input payloads to prevent memory exhaustion / DoS", function () {
      const oversizedPayload = {
        name: "A".repeat(1025) // Exceeds 1024 limit
      };

      expect(() => processFormSubmission(oversizedPayload)).to.throw("Input size limit exceeded for field: name");
    });

    it("identifies and blocks potential XSS script payloads in form fields", function () {
      const xssSubmissions = [
        { name: "John <script>alert('XSS')</script>" },
        { name: "John", desc: "onclick=javascript:alert('XSS')" },
        { name: "John", email: "javascript:void(0)" }
      ];

      xssSubmissions.forEach(sub => {
        expect(() => processFormSubmission(sub)).to.throw(/Potential XSS payload/);
      });
    });

    it("rejects submissions with missing or mismatched CSRF tokens", function () {
      const session = { csrfToken: "secure-token-123" };
      const goodSubmission = {
        name: "Co-op Pharmacy",
        email: "contact@coop.org",
        csrfToken: "secure-token-123"
      };

      const missingTokenSubmission = {
        name: "Co-op Pharmacy",
        email: "contact@coop.org"
      };

      const badTokenSubmission = {
        name: "Co-op Pharmacy",
        email: "contact@coop.org",
        csrfToken: "attacker-token"
      };

      expect(processFormSubmission(goodSubmission, session).success).to.be.true;
      expect(() => processFormSubmission(missingTokenSubmission, session)).to.throw("CSRF token verification failed.");
      expect(() => processFormSubmission(badTokenSubmission, session)).to.throw("CSRF token verification failed.");
    });

    it("rejects submissions attempting to inject administrative roles or parameters", function () {
      const session = { csrfToken: "secure-token-123" };
      
      const adminFieldSubmission = {
        name: "Co-op Pharmacy",
        email: "contact@coop.org",
        csrfToken: "secure-token-123",
        isAdmin: true
      };

      const adminRoleSubmission = {
        name: "Co-op Pharmacy",
        email: "contact@coop.org",
        csrfToken: "secure-token-123",
        userRole: "admin"
      };

      expect(() => processFormSubmission(adminFieldSubmission, session)).to.throw("Security violation: Attempt to inject administrative parameter.");
      expect(() => processFormSubmission(adminRoleSubmission, session)).to.throw("Security violation: Attempt to inject administrative parameter.");
    });
  });
});
