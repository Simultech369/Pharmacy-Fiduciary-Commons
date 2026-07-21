const DEPLOYMENT_CONFIG = {
  31337: {
    name: "Hardhat Local Network",
    pbAddress: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    mutualCreditAddress: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
    treasuryAddress: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
  },
  1337: {
    name: "Hardhat Local Network (Alternate)",
    pbAddress: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    mutualCreditAddress: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
    treasuryAddress: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
  }
  /*
  // Template placeholders for public networks.
  // Note: No active deployments currently exist on public networks.
  , 11155111: {
    name: "Sepolia Testnet",
    pbAddress: "0x0000000000000000000000000000000000000000",
    mutualCreditAddress: "0x0000000000000000000000000000000000000000",
    treasuryAddress: "0x0000000000000000000000000000000000000000"
  },
  1: {
    name: "Ethereum Mainnet",
    pbAddress: "0x0000000000000000000000000000000000000000",
    mutualCreditAddress: "0x0000000000000000000000000000000000000000",
    treasuryAddress: "0x0000000000000000000000000000000000000000"
  }
  */
};

let pbAddress = DEPLOYMENT_CONFIG[31337].pbAddress;
let mutualCreditAddress = DEPLOYMENT_CONFIG[31337].mutualCreditAddress;
let treasuryAddress = DEPLOYMENT_CONFIG[31337].treasuryAddress;

const PB_ABI = [
  "function currentRound() view returns (uint256)",
  "function rounds(uint256) view returns (uint256 matchingPool, uint8 state, uint256 projectCount, uint256 finalizedAt, uint256 freshMatchingPool)",
  "function roundProjects(uint256, uint256) view returns (string title, address recipient, uint256 voteCount, bool active)",
  "function registeredVoters(uint256, address) view returns (bool)",
  "function castVote(uint256 roundId, uint256 projectId) external",
  "function registerVoterWithSignature(uint256 roundId, address voter, bytes32 credentialHash, bytes32 policyVersion, uint256 deadline, bytes calldata signature) external",
  "function token() view returns (address)",
  "function totalUnclaimedShares() view returns (uint256)",
  "function recycledMatchingPool() view returns (uint256)",
  "function council() view returns (address)",
  "function previewFinalize(uint256 roundId) view returns (address[] projects, uint256[] expectedShares, uint256 actualBalance, uint256 totalRequiredAfterFinalize, bool isSufficient)",
  "function dryRunFinalize(uint256 roundId) view returns (address[] projects, uint256[] expectedShares, uint256 actualBalance, uint256 totalRequiredAfterFinalize, bool isSufficient)",
  "function finalizeRound(uint256 roundId) external"
];

const CREDIT_ABI = [
  "function registered(address) view returns (bool)",
  "function creditLimits(address) view returns (uint256)",
  "function balances(address) view returns (int256)"
];

const EXPECTED_CHAIN_IDS = new Set([
  31337, // Hardhat local
  1337
]);

let provider = null;
let signer = null;
let userAddress = "";
let isWeb3Connected = false;

let pbContract = null;
let creditContract = null;

// Initial state and project details loaded dynamically if Web3 is active
let activeRoundId = 1n;
let activeProjects = [];

document.addEventListener("DOMContentLoaded", () => {
  const btnConnect = document.getElementById("btn-connect");
  if (btnConnect) {
    btnConnect.addEventListener("click", connectWallet);
  }

  const btnRegister = document.getElementById("btn-register");
  if (btnRegister) {
    btnRegister.addEventListener("click", registerWithSignature);
  }

  const btnPreview = document.getElementById("btn-preview-finalize");
  if (btnPreview) {
    btnPreview.addEventListener("click", previewFinalization);
  }

  const btnFinalize = document.getElementById("btn-finalize-round");
  if (btnFinalize) {
    btnFinalize.addEventListener("click", finalizeCurrentRound);
  }

  const btnLoadMore = document.getElementById("btn-load-more-events");
  if (btnLoadMore) {
    btnLoadMore.addEventListener("click", () => loadOnChainEvents(false));
  }

  // Check if wallet is already connected
  checkWeb3Provider();
});

async function checkWeb3Provider() {
  if (window.ethereum) {
    provider = new ethers.BrowserProvider(window.ethereum);
    // Listen for chain and account changes to reload page
    if (typeof window.ethereum.on === "function") {
      window.ethereum.on("chainChanged", () => window.location.reload());
      window.ethereum.on("accountsChanged", () => window.location.reload());
    }
  }
}

async function connectWallet() {
  if (!window.ethereum) {
    alert("No Ethereum browser extension detected. Please install MetaMask to use Web3 features.");
    return;
  }

  try {
    provider = new ethers.BrowserProvider(window.ethereum);
    const accounts = await provider.send("eth_requestAccounts", []);
    if (accounts.length > 0) {
      await setupWeb3Connection(accounts[0]);
    }
  } catch (e) {
    console.error("Wallet connection failed:", e);
    alert("Connection failed: " + e.message);
  }
}

async function setupWeb3Connection(account) {
  const requestedAddress = typeof account === "string" ? account : account?.address;
  signer = requestedAddress ? await provider.getSigner(requestedAddress) : await provider.getSigner();
  userAddress = await signer.getAddress();

  const network = await provider.getNetwork();
  const chainId = Number(network.chainId);
  const config = DEPLOYMENT_CONFIG[chainId];
  if (!config) {
    showConnectionWarning(`Wallet connected to unsupported chain ${chainId}. Use the local/test Hardhat network.`);
    return;
  }

  pbAddress = config.pbAddress;
  mutualCreditAddress = config.mutualCreditAddress;
  treasuryAddress = config.treasuryAddress;

  const [pbCode, creditCode] = await Promise.all([
    provider.getCode(pbAddress),
    provider.getCode(mutualCreditAddress)
  ]);

  if (pbCode === "0x" || creditCode === "0x") {
    showConnectionWarning("Wallet connected, but expected local/test contracts are not deployed on this chain.");
    return;
  }

  // Initialize contracts
  pbContract = new ethers.Contract(pbAddress, PB_ABI, signer);
  creditContract = new ethers.Contract(mutualCreditAddress, CREDIT_ABI, signer);
  isWeb3Connected = true;

  // Update UI Elements
  const btnConnect = document.getElementById("btn-connect");
  if (btnConnect) {
    btnConnect.innerText = `\uD83D\uDD0C Connected: ${userAddress.slice(0, 6)}...${userAddress.slice(-4)}`;
    btnConnect.style.background = "linear-gradient(135deg, var(--accent-green), #047857)";
    btnConnect.style.boxShadow = "0 4px 12px rgba(16, 185, 129, 0.3)";
  }

  const mockBadge = document.getElementById("mock-badge");
  if (mockBadge) {
    mockBadge.innerText = "LOCAL CONTRACTS CONNECTED - STATIC PANELS REMAIN DEMO DATA";
    mockBadge.className = "status-badge recorded";
    mockBadge.style.animation = "none";
  }

  setDashboardLocked(false);

  console.log("Connected to Web3.");

  // Fetch live state from contracts
  await fetchLiveState();

  // Show events panel and load events
  const eventsPanel = document.getElementById("onchain-events-panel");
  if (eventsPanel) eventsPanel.style.display = "block";
  await loadOnChainEvents(true);
}

function showConnectionWarning(message) {
  isWeb3Connected = false;
  const btnConnect = document.getElementById("btn-connect");
  if (btnConnect) {
    btnConnect.innerText = `Connected: ${userAddress.slice(0, 6)}...${userAddress.slice(-4)}`;
  }

  const mockBadge = document.getElementById("mock-badge");
  if (mockBadge) {
    mockBadge.innerText = "NOT AUDITED - VERIFY TEST NETWORK";
    mockBadge.className = "badge-unverified";
    mockBadge.style.animation = "";
  }

  const voterStatus = document.getElementById("voter-status");
  if (voterStatus) {
    voterStatus.innerText = message;
    voterStatus.style.color = "var(--accent-red)";
  }

  setDashboardLocked(true, message);

  console.warn(message);
}

function setDashboardLocked(locked, warningMessage) {
  const warningBanner = document.getElementById("network-warning-banner");
  if (warningBanner) {
    if (locked) {
      warningBanner.style.display = "block";
      if (warningMessage) {
        warningBanner.querySelector("span").innerText = `\u26A0\uFE0F NETWORK WARNING: ${warningMessage}`;
      }
    } else {
      warningBanner.style.display = "none";
    }
  }

  // Disable or enable interactive elements
  const elementsToLock = [
    "btn-preview-finalize",
    "btn-finalize-round",
    "btn-register"
  ];
  elementsToLock.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.disabled = locked;
      el.style.opacity = locked ? "0.5" : "1.0";
      el.style.cursor = locked ? "not-allowed" : "pointer";
    }
  });

  // Also lock all project vote buttons
  const voteButtons = document.querySelectorAll(".projects-grid button");
  voteButtons.forEach(btn => {
    btn.disabled = locked;
    btn.style.opacity = locked ? "0.5" : "1.0";
    btn.style.cursor = locked ? "not-allowed" : "pointer";
  });
}

async function fetchLiveState() {
  try {
    // 1. Get active round ID
    activeRoundId = await pbContract.currentRound();
    console.log(`Active QF Round ID: ${activeRoundId}`);

    // 2. Query voter registration status
    const isReg = await pbContract.registeredVoters(activeRoundId, userAddress);
    updateVoterUI(isReg);

    // 3. Query Mutual Credit limits & balance
    try {
      const balance = await creditContract.balances(userAddress);
      const registered = await creditContract.registered(userAddress);
      const creditLimit = await creditContract.creditLimits(userAddress);
      
      const formatBal = (Number(balance) / 1e18).toFixed(2);
      const formatLimit = (Number(creditLimit) / 1e18).toFixed(2);
      
      console.log(`Mutual Credit registered: ${registered}, balance: ${formatBal}, limit: ${formatLimit}`);
      // If we had display boxes for specific user balances in dashboard, we could update them here.
    } catch (err) {
      console.log("Could not query mutual credit limits for user address:", err.message);
    }

    // 4. Load QF projects
    await loadProjectsFromContract();

    // 5. Query Patient Fund Liquidity and Council check
    try {
      const tokenAddress = await pbContract.token();
      const tokenContract = new ethers.Contract(tokenAddress, [
        "function balanceOf(address) view returns (uint256)",
        "function decimals() view returns (uint8)"
      ], signer);

      const tokenDecimals = await tokenContract.decimals();
      const divisor = 10n ** BigInt(tokenDecimals);

      const actualBalRaw = await tokenContract.balanceOf(pbAddress);
      const totalUnclaimedRaw = await pbContract.totalUnclaimedShares();
      const recycledPoolRaw = await pbContract.recycledMatchingPool();

      const round = await pbContract.rounds(activeRoundId);
      const matchingPoolRaw = round.matchingPool;
      const roundState = Number(round.state);

      const actualBalance = Number(actualBalRaw) / Number(divisor);
      const totalUnclaimed = Number(totalUnclaimedRaw) / Number(divisor);
      const recycledPool = Number(recycledPoolRaw) / Number(divisor);
      const matchingPool = Number(matchingPoolRaw) / Number(divisor);

      let requiredBalance = totalUnclaimed + recycledPool;
      if (roundState === 1) { // Active
        requiredBalance += matchingPool;
      }

      // Update index.html TOTAL_MATCHING_POOL global variable so math renders correctly
      window.TOTAL_MATCHING_POOL = matchingPool;
      window.recalculateMatching();

      // Show liquidity board and populate values
      const board = document.getElementById("liquidity-board");
      if (board) board.style.display = "block";

      const actualBalEl = document.getElementById("actual-token-balance");
      if (actualBalEl) actualBalEl.innerText = actualBalance.toFixed(2);

      const reqBalEl = document.getElementById("required-accounting-balance");
      if (reqBalEl) reqBalEl.innerText = requiredBalance.toFixed(2);

      const recycledEl = document.getElementById("recycled-matching-pool-display");
      if (recycledEl) recycledEl.innerText = recycledPool.toFixed(2);

      const unclaimedEl = document.getElementById("unclaimed-shares-display");
      if (unclaimedEl) unclaimedEl.innerText = totalUnclaimed.toFixed(2);

      const warningBanner = document.getElementById("liquidity-warning-message");
      if (warningBanner) {
        if (actualBalance < requiredBalance) {
          warningBanner.style.display = "block";
          warningBanner.style.background = "rgba(239, 68, 68, 0.1)";
          warningBanner.style.borderColor = "var(--accent-red)";
          warningBanner.style.color = "var(--accent-red-text)";
          let msg = `\u26A0\uFE0F LIQUIDITY DEFICIT: The actual contract balance (${actualBalance.toFixed(2)}) is lower than the required accounting balance (${requiredBalance.toFixed(2)}).`;
          if (roundState === 1) {
            msg += ` Finalizing the active round will execute a council refund of up to ${matchingPool.toFixed(2)} tokens, which will leave the contract insolvent and lock out previous claimants! Please deposit at least ${(requiredBalance - actualBalance).toFixed(2)} tokens immediately.`;
          } else {
            msg += ` Claims/finalization will fail due to depletion. Please top up the contract with ${tokenAddress}.`;
          }
          warningBanner.innerText = msg;
        } else if (roundState === 1 && actualBalance < (totalUnclaimed + matchingPool)) {
          warningBanner.style.display = "block";
          warningBanner.style.background = "rgba(239, 68, 68, 0.1)";
          warningBanner.style.borderColor = "var(--accent-red)";
          warningBanner.style.color = "var(--accent-red-text)";
          const deficit = (totalUnclaimed + matchingPool) - actualBalance;
          warningBanner.innerText = `\u26A0\uFE0F SOLVENCY LOCK DETECTED: The contract balance (${actualBalance.toFixed(2)}) is less than totalUnclaimed + matchingPool (${(totalUnclaimed + matchingPool).toFixed(2)}). Finalizing this round will revert on-chain due to the solvency invariant check! Please top up the contract by depositing at least ${deficit.toFixed(2)} tokens to allow finalization.`;
        } else if (roundState === 1 && matchingPool === 0) {
          warningBanner.style.display = "block";
          warningBanner.style.background = "rgba(245, 158, 11, 0.1)";
          warningBanner.style.borderColor = "var(--accent-orange)";
          warningBanner.style.color = "var(--accent-orange)";
          warningBanner.innerText = `\u26A0\uFE0F WARNING: Active round has zero liquidity in matching pool.`;
        } else if (recycledPool === 0 && roundState === 0) {
          warningBanner.style.display = "block";
          warningBanner.style.background = "rgba(245, 158, 11, 0.1)";
          warningBanner.style.borderColor = "var(--accent-orange)";
          warningBanner.style.color = "var(--accent-orange)";
          warningBanner.innerText = `\u26A0\uFE0F WARNING: Zero liquidity in recycled pool.`;
        } else {
          warningBanner.style.display = "none";
        }
      }

      // Check if connected wallet is Council
      const councilAddress = await pbContract.council();
      const councilPortal = document.getElementById("council-controls");
      if (councilPortal) {
        if (userAddress.toLowerCase() === councilAddress.toLowerCase()) {
          councilPortal.style.display = "block";
        } else {
          councilPortal.style.display = "none";
        }
      }
    } catch (err) {
      console.log("Could not query token address or balance updates:", err.message);
    }

  } catch (e) {
    console.error("Error fetching live contract state:", e);
  }
}

function updateVoterUI(isRegistered) {
  const voterStatus = document.getElementById("voter-status");
  const btnRegister = document.getElementById("btn-register");
  const inputSig = document.getElementById("input-signature");

  if (!voterStatus) return;

  if (isRegistered) {
    voterStatus.innerText = "\u2705 REGISTERED ADVOCATE VOTER (Eligible to cast QF votes)";
    voterStatus.style.color = "var(--accent-green)";
    if (btnRegister) btnRegister.style.display = "none";
    if (inputSig) inputSig.style.display = "none";
  } else {
    voterStatus.innerText = "\u274C UNREGISTERED (Submit a valid relayer signature to self-register)";
    voterStatus.style.color = "var(--accent-red)";
    if (btnRegister) btnRegister.style.display = "inline-block";
    if (inputSig) inputSig.style.display = "inline-block";
  }
}

async function loadProjectsFromContract() {
  try {
    const round = await pbContract.rounds(activeRoundId);
    const projCount = Number(round.projectCount);
    
    activeProjects = [];
    for (let i = 0; i < projCount; i++) {
      const proj = await pbContract.roundProjects(activeRoundId, i);
      activeProjects.push({
        id: i,
        title: proj.title,
        voteCount: Number(proj.voteCount),
        recipient: proj.recipient
      });
    }

    // Override the mock projects array and recalculate matching
    if (activeProjects.length > 0) {
      window.projects = activeProjects.map(p => ({
        id: p.id,
        title: p.title,
        votes: p.voteCount
      }));
      window.recalculateMatching();
    }
  } catch (err) {
    console.error("Error loading projects from contract:", err);
  }
}

async function registerWithSignature() {
  const inputSig = document.getElementById("input-signature");
  if (!inputSig || !inputSig.value.trim()) {
    alert("Please paste a valid registration authorization first.");
    return;
  }

  try {
    const authorization = JSON.parse(inputSig.value.trim());
    const { credentialHash, policyVersion, deadline, signature, nonce } = authorization;
    if (!credentialHash || !policyVersion || !deadline || !signature) {
      throw new Error("Authorization must include credentialHash, policyVersion, deadline, and signature.");
    }
    console.log(`Submitting voter self-registration transaction for round ${activeRoundId}...`);
    const tx = await pbContract.registerVoterWithSignature(
      activeRoundId,
      userAddress,
      credentialHash,
      policyVersion,
      deadline,
      signature
    );
    alert("Self-registration transaction sent. Waiting for confirmation...");
    await tx.wait();
    alert("Voter registered successfully!");
    
    // Refresh state
    const isReg = await pbContract.registeredVoters(activeRoundId, userAddress);
    updateVoterUI(isReg);

    // Sync voter profile to the server database proxy
    window.savedRegistrationParams = {
      credentialHash,
      policyVersion,
      deadline,
      signature,
      nonce
    };

    await window.syncProxyProfile();
  } catch (e) {
    console.error("Self-registration transaction failed:", e);
    alert("Registration failed: " + (e.reason || e.message));
  }
}

window.syncProxyProfile = async function() {
  const statusEl = document.getElementById("db-sync-status");
  if (!statusEl) return;

  statusEl.style.display = "block";
  statusEl.style.color = "var(--text-muted)";
  statusEl.innerHTML = "Syncing voter profile to proxy database...";

  try {
    const { credentialHash, policyVersion, deadline, signature, nonce } = window.savedRegistrationParams;
    const clientNonce = (typeof crypto.randomUUID === "function") 
      ? crypto.randomUUID() 
      : Math.random().toString(36).substring(2, 15);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    const network = await provider.getNetwork();
    const chainId = network.chainId.toString();

    // Retrieve proxy config dynamically to obtain the configured proxyAddress
    let proxyAddress = "0x1111111111111111111111111111111111111111"; // Default dev address fallback
    try {
      const healthResponse = await fetch("http://localhost:3000/health");
      if (healthResponse.ok) {
        const healthData = await healthResponse.json();
        if (healthData.proxyAddress) {
          proxyAddress = healthData.proxyAddress;
        }
      }
    } catch (err) {
      console.warn("Could not query proxyAddress from health check, falling back:", err.message);
    }

    // Ensure policyVersion is passed as literal policy string or bytes32 representation
    // If the relayer output includes policyVersion as bytes32, we pass it directly.
    // If it's the raw string "fiduciary-credential-policy-v1", we can also pass it.
    // The contract expects bytes32. The relayer script output is already a bytes32 hex string.
    const policyVersionStr = "fiduciary-credential-policy-v1";

    const canonicalString = [
      `Pharmacy Fiduciary Commons Database Proxy`,
      `Version: 1`,
      `Action: register-voter`,
      `Proxy Address: ${proxyAddress.toLowerCase()}`,
      `Chain ID: ${chainId}`,
      `Round ID: ${activeRoundId.toString()}`,
      `Wallet: ${userAddress.toLowerCase()}`,
      `Credential Hash: ${credentialHash}`,
      `Policy Version: ${policyVersionStr}`,
      `Client Nonce: ${clientNonce}`,
      `Expires At: ${expiresAt}`
    ].join("\n");

    const signer = await provider.getSigner();
    const clientSignature = await signer.signMessage(canonicalString);

    const relayerNonce = nonce !== undefined ? Number(nonce) : 0;

    const response = await fetch("http://localhost:3000/api/voters/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        walletAddress: userAddress,
        chainId: Number(chainId),
        roundId: activeRoundId.toString(),
        credentialHash,
        policyVersion: policyVersionStr,
        clientNonce,
        expiresAt,
        signature: clientSignature,
        issuerSignature: signature,
        relayerNonce,
        relayerDeadline: Number(deadline)
      })
    });

    if (!response.ok) {
      const errData = await response.json();
      throw new Error(errData.error || "Proxy sync failed");
    }

    statusEl.style.color = "#4ade80"; // Light green
    statusEl.innerHTML = "✅ Database profile successfully synced.";
    setTimeout(() => {
      statusEl.style.display = "none";
    }, 5000);
    console.log("Voter profile successfully synced to database via proxy.");
  } catch (dbErr) {
    console.error("Database sync failure:", dbErr.message);
    statusEl.style.color = "#f87171"; // Light red
    statusEl.innerHTML = `⚠️ Profile sync failed: ${dbErr.message}. <button class="btn-vote" style="padding: 0.2rem 0.5rem; font-size: 0.75rem; background: var(--accent-purple);" onclick="window.syncProxyProfile()">Retry Sync</button>`;
  }
}

// Override the global castVote function to send live transactions when Web3 is connected
const originalCastVote = window.castVote;
window.castVote = async function(projectId) {
  if (!isWeb3Connected) {
    // Fallback to original mock behavior if not connected to wallet
    if (originalCastVote) {
      originalCastVote(projectId);
    } else {
      // Inline mock fallback
      const proj = window.projects.find(p => p.id === projectId);
      if (proj) {
        proj.votes += 1;
        window.recalculateMatching();
      }
    }
    return;
  }

  try {
    console.log(`Casting vote on-chain for project ${projectId} in round ${activeRoundId}...`);
    const tx = await pbContract.castVote(activeRoundId, projectId);
    alert("Vote transaction submitted. Waiting for confirmation...");
    await tx.wait();
    alert("Vote cast successfully!");
    await loadProjectsFromContract();
  } catch (e) {
    console.error("On-chain voting failed:", e);
    alert("Voting failed: " + (e.reason || e.message));
  }
};

async function previewFinalization() {
  try {
    const tokenAddress = await pbContract.token();
    const tokenContract = new ethers.Contract(tokenAddress, [
      "function decimals() view returns (uint8)"
    ], signer);
    const tokenDecimals = await tokenContract.decimals();
    const divisor = 10n ** BigInt(tokenDecimals);

    console.log("Simulating round finalization (dry-run)...");
    const results = await pbContract.dryRunFinalize(activeRoundId);
    const projectsList = results.projects;
    const sharesList = results.expectedShares;
    const actualBal = results.actualBalance;
    const reqBal = results.totalRequiredAfterFinalize;
    const isSufficient = results.isSufficient;

    let previewText = `Active Round ID: ${activeRoundId}\n`;
    previewText += `Actual Contract Balance: ${(Number(actualBal) / Number(divisor)).toFixed(2)}\n`;
    previewText += `Total Required Balance after Finalize: ${(Number(reqBal) / Number(divisor)).toFixed(2)}\n\n`;
    previewText += `Expected Project Matching Payouts:\n`;

    for (let i = 0; i < projectsList.length; i++) {
      const shareFormatted = (Number(sharesList[i]) / Number(divisor)).toFixed(2);
      previewText += `- Project ${i} (${projectsList[i]}): ${shareFormatted} tokens\n`;
    }

    const previewDiv = document.getElementById("finalize-preview-results");
    const previewTextDiv = document.getElementById("finalize-preview-text");
    const previewWarning = document.getElementById("finalize-preview-warning");

    previewDiv.style.display = "block";
    previewTextDiv.innerText = previewText;

    const distributed = sharesList.reduce((a, b) => a + b, 0n);
    const roundDetails = await pbContract.rounds(activeRoundId);
    const pool = roundDetails.matchingPool;
    const totalUnclaimedShares = reqBal - distributed;
    const isSolvencyTrap = !isSufficient && (actualBal >= totalUnclaimedShares + distributed);

    if (isSolvencyTrap) {
      const deficit = (totalUnclaimedShares + pool) - actualBal;
      const deficitFormatted = (Number(deficit) / Number(divisor)).toFixed(2);
      const refundFormatted = (Number(pool - distributed) / Number(divisor)).toFixed(2);
      const remainingFormatted = (Number(actualBal - (pool - distributed)) / Number(divisor)).toFixed(2);
      const unclaimedFormatted = (Number(totalUnclaimedShares) / Number(divisor)).toFixed(2);

      previewWarning.className = "alert-panel-red";
      previewWarning.style.display = "block";
      previewWarning.innerText = `\u26A0\uFE0F SOLVENCY TRAP DETECTED! Although current recorded shares fit the balance, finalizing this round will trigger a council refund of ${refundFormatted} tokens. This refund will drain the contract balance to ${remainingFormatted} tokens, which is less than the outstanding unclaimed shares of ${unclaimedFormatted} tokens from prior rounds. This will leave the contract insolvent and lock out previous claimants! Please deposit at least ${deficitFormatted} tokens before finalization.`;
    } else if (isSufficient) {
      previewWarning.className = "alert-panel-green";
      previewWarning.style.display = "block";
      previewWarning.innerText = `\u2705 LIQUIDITY VERIFIED: Contract has sufficient balance to finalize and distribute.`;
    } else {
      previewWarning.className = "alert-panel-red";
      previewWarning.style.display = "block";
      previewWarning.innerText = `\u274C INSUFFICIENT LIQUIDITY: Finalization will cause a deficit! Please top up the contract.`;
    }
  } catch (err) {
    console.error("Preview finalization failed:", err);
    alert("Preview finalization failed: " + (err.reason || err.message));
  }
}

async function finalizeCurrentRound() {
  if (!confirm("Are you sure you want to finalize the current round? This will allocate matching shares to all projects based on the squared vote weights and freeze the round.")) {
    return;
  }

  try {
    console.log(`Finalizing round ${activeRoundId} on-chain...`);
    const tx = await pbContract.finalizeRound(activeRoundId);
    alert("Finalization transaction submitted. Waiting for confirmation...");
    await tx.wait();
    alert("Round finalized successfully!");
    await fetchLiveState();
  } catch (err) {
    console.error("Finalization failed:", err);
    alert("Finalization failed: " + (err.reason || err.message));
  }
}

// Variables for paginated on-chain event history
let currentEventBlock = 0n;
const EVENT_CHUNK_SIZE = 10000n;
const EVENTS_PAGE_SIZE = 5;

async function loadOnChainEvents(reset = false) {
  if (!pbContract) return;

  const eventListEl = document.getElementById("onchain-events-list");
  const loadMoreBtn = document.getElementById("btn-load-more-events");
  const statusEl = document.getElementById("onchain-events-status");

  if (!eventListEl || !loadMoreBtn || !statusEl) return;

  if (reset) {
    eventListEl.innerHTML = "";
    currentEventBlock = BigInt(await provider.getBlockNumber());
    loadMoreBtn.style.display = "none";
  }

  statusEl.innerText = "Querying events...";
  loadMoreBtn.disabled = true;

  try {
    const filter = pbContract.filters.VoterRegistered();
    const collectedEvents = [];
    
    // Scan block range backwards to find events
    let toBlock = currentEventBlock;
    let fromBlock = toBlock - EVENT_CHUNK_SIZE + 1n;
    if (fromBlock < 0n) fromBlock = 0n;

    while (toBlock >= 0n && collectedEvents.length < EVENTS_PAGE_SIZE) {
      const batch = await pbContract.queryFilter(filter, fromBlock, toBlock);
      
      // Sort in reverse order (latest first)
      batch.sort((a, b) => {
        if (b.blockNumber !== a.blockNumber) {
          return b.blockNumber - a.blockNumber;
        }
        return b.transactionIndex - a.transactionIndex;
      });

      collectedEvents.push(...batch);

      if (fromBlock === 0n) {
        currentEventBlock = -1n;
        break;
      }

      toBlock = fromBlock - 1n;
      fromBlock = toBlock - EVENT_CHUNK_SIZE + 1n;
      if (fromBlock < 0n) fromBlock = 0n;
    }

    if (currentEventBlock !== -1n) {
      currentEventBlock = toBlock;
    }

    // Render events page
    const displayEvents = collectedEvents.slice(0, EVENTS_PAGE_SIZE);
    
    if (displayEvents.length === 0 && eventListEl.children.length === 0) {
      const emptyLi = document.createElement("li");
      emptyLi.className = "receipt-item";
      const emptyMeta = document.createElement("span");
      emptyMeta.className = "receipt-meta";
      emptyMeta.textContent = "No recent on-chain registrations found.";
      emptyLi.appendChild(emptyMeta);
      eventListEl.appendChild(emptyLi);
    } else {
      for (const ev of displayEvents) {
        const roundId = ev.args[0];
        const voter = ev.args[1];
        const isZK = ev.args[2];
        const blockNum = ev.blockNumber;
        
        const li = document.createElement("li");
        li.className = "receipt-item";

        const leftDiv = document.createElement("div");
        
        const nameSpan = document.createElement("span");
        nameSpan.className = "receipt-name";
        nameSpan.style.color = "var(--accent-cyan)";
        nameSpan.textContent = "Voter Registered";
        leftDiv.appendChild(nameSpan);

        const metaSpan = document.createElement("span");
        metaSpan.className = "receipt-meta";
        metaSpan.textContent = ` • Round ${roundId} • ${isZK ? "ZK Mode" : "Sig Mode"}`;
        leftDiv.appendChild(metaSpan);

        li.appendChild(leftDiv);

        const rightSpan = document.createElement("span");
        rightSpan.className = "receipt-meta";
        rightSpan.style.fontFamily = "monospace";
        const voterStr = typeof voter === "string" ? voter : String(voter);
        rightSpan.textContent = `Block #${blockNum} (${voterStr.slice(0, 6)}...${voterStr.slice(-4)})`;
        li.appendChild(rightSpan);

        eventListEl.appendChild(li);
      }
    }

    if (currentEventBlock >= 0n) {
      loadMoreBtn.style.display = "inline-block";
      loadMoreBtn.disabled = false;
      statusEl.innerText = `Idle (scanned down to block #${currentEventBlock})`;
    } else {
      loadMoreBtn.style.display = "none";
      statusEl.innerText = "All historical events loaded.";
    }
  } catch (err) {
    console.error("Failed to query on-chain events:", err);
    statusEl.innerText = `Error: ${err.message}`;
    loadMoreBtn.disabled = false;
  }
}
