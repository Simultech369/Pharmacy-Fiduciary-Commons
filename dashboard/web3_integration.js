// Web3 and ethers.js Integration for Wellbeing Dashboard
// Integrates MetaMask, PBMRebateTreasury, PharmacyMutualCredit, and PatientFundParticipatoryBudgeting contracts

const PB_CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const MUTUAL_CREDIT_ADDRESS = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
const TREASURY_ADDRESS = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0";

const PB_ABI = [
  "function currentRound() view returns (uint256)",
  "function rounds(uint256) view returns (uint256 matchingPool, uint8 state, uint256 projectCount)",
  "function roundProjects(uint256, uint256) view returns (string title, address recipient, uint256 voteCount, bool active)",
  "function registeredVoters(uint256, address) view returns (bool)",
  "function castVote(uint256 roundId, uint256 projectId) external",
  "function registerVoterWithSignature(uint256 roundId, address voter, bytes32 credentialHash, bytes32 policyVersion, uint256 deadline, bytes calldata signature) external"
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

  // Check if wallet is already connected
  checkWeb3Provider();
});

async function checkWeb3Provider() {
  if (window.ethereum) {
    provider = new ethers.BrowserProvider(window.ethereum);
    try {
      const accounts = await provider.listAccounts();
      if (accounts.length > 0) {
        await setupWeb3Connection(accounts[0]);
      }
    } catch (e) {
      console.log("Check Web3 account failed:", e);
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
  signer = await provider.getSigner();
  userAddress = account.address;

  const network = await provider.getNetwork();
  const chainId = Number(network.chainId);
  if (!EXPECTED_CHAIN_IDS.has(chainId)) {
    showConnectionWarning(`Wallet connected to unsupported chain ${chainId}. Use the local/test Hardhat network.`);
    return;
  }

  const [pbCode, creditCode] = await Promise.all([
    provider.getCode(PB_CONTRACT_ADDRESS),
    provider.getCode(MUTUAL_CREDIT_ADDRESS)
  ]);

  if (pbCode === "0x" || creditCode === "0x") {
    showConnectionWarning("Wallet connected, but expected local/test contracts are not deployed on this chain.");
    return;
  }

  // Initialize contracts
  pbContract = new ethers.Contract(PB_CONTRACT_ADDRESS, PB_ABI, signer);
  creditContract = new ethers.Contract(MUTUAL_CREDIT_ADDRESS, CREDIT_ABI, signer);
  isWeb3Connected = true;

  // Update UI Elements
  const btnConnect = document.getElementById("btn-connect");
  if (btnConnect) {
    btnConnect.innerText = `🔌 Connected: ${userAddress.slice(0, 6)}...${userAddress.slice(-4)}`;
    btnConnect.style.background = "linear-gradient(135deg, var(--accent-green), #047857)";
    btnConnect.style.boxShadow = "0 4px 12px rgba(16, 185, 129, 0.3)";
  }

  const mockBadge = document.getElementById("mock-badge");
  if (mockBadge) {
    mockBadge.innerText = "LOCAL CONTRACTS CONNECTED - STATIC PANELS REMAIN DEMO DATA";
    mockBadge.className = "status-badge recorded";
    mockBadge.style.animation = "none";
  }

  console.log(`Connected to Web3. Address: ${userAddress}`);

  // Fetch live state from contracts
  await fetchLiveState();
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

  console.warn(message);
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
    voterStatus.innerText = "✅ REGISTERED ADVOCATE VOTER (Eligible to cast QF votes)";
    voterStatus.style.color = "var(--accent-green)";
    if (btnRegister) btnRegister.style.display = "none";
    if (inputSig) inputSig.style.display = "none";
  } else {
    voterStatus.innerText = "❌ UNREGISTERED (Submit a valid relayer signature to self-register)";
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
    const { credentialHash, policyVersion, deadline, signature } = authorization;
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
  } catch (e) {
    console.error("Self-registration transaction failed:", e);
    alert("Registration failed: " + (e.reason || e.message));
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
