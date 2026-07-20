# Secure Database API Proxy Architecture Plan

Design and implementation plan to establish a secure Node.js server-side API proxy for the Pharmacy Fiduciary Commons repository. This proxy will handle Web3 signature authentication and database writes, removing direct client-to-database connections.

---

## User Review Required

> [!IMPORTANT]
> The proxy server will require a Supabase **Service Role Key** (highly privileged database access) to write to table records. This key MUST be kept strictly in server-side environment variables (`.env`) and never committed to version control.

> [!WARNING]
> Since direct database inputs are removed from the frontend UI, local developers must run the proxy server alongside the dashboard to enable database features. A mock option will remain fallback default.

---

## Security Addendum: EIP-191 Replay Protection & Boundary Containment

### 1. Canonical Message Format
To prevent signature replay attacks across different rounds, chains, or deployments, all signature verification requests must sign a canonical formatted string rather than raw data. 

The payload format signed by the wallet's `personal_sign` is:
```text
Domain: Pharmacy Fiduciary Commons
Version: 1.0.0
ChainID: <chainId>
RoundID: <roundId>
Action: <actionName>
Wallet: <walletAddress>
Timestamp: <isoTimestamp>
BodyHash: <sha256HexOfPayloadBody>
```

The server-side proxy will:
1. Reconstruct this identical string using the input parameters.
2. Verify the signature matches the input `walletAddress` via `ethers.verifyMessage`.
3. Assert that `Timestamp` is within a reasonable grace window (e.g., 5-10 minutes) to prevent delayed replays.
4. Verify the `BodyHash` matches the SHA-256 hash of the JSON payload.

### 2. Containment Boundaries
*   **Offline Kit Syncing:** Direct cloud uploads in `tools/offline/continuity-kit.html` were removed. We will implement proxy uploads by having the local operator sign a proxy upload message when synchronization is restored, sending the signed EIP-191 structure to the API proxy.
*   **Unlinkable ZK Proof Batches vs Linkable API Requests:** The `tools/resilience/proxy-validator.js` checker enforces that unlinkable relay payloads contain no signatures, addresses, or wallets to prevent metadata leakage. The proxy database endpoints (`POST /api/voters/register` and `POST /api/vouchers/upload`) are **explicitly linkable** operations that sync wallet profiles to Supabase. Replay-protection signatures are strictly kept at the API transport layer and must not be saved into any ZK verification data fields.

---

## Proposed Changes

### Backend Proxy Server

#### [NEW] [server.js](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/server/server.js)
A lightweight Node.js Express server handling request verification and Supabase syncing:
*   Initializes Supabase Client using backend environment variables (`SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`).
*   **Endpoint `POST /api/voters/register`:**
    *   Receives `walletAddress`, `credentialHash`, `policyVersion`, `roundId`, `signature`, `timestamp`, `chainId`.
    *   Reconstructs the registration message and recovers the signer's address via `ethers.verifyMessage`.
    *   Asserts recovered signer matches the requested `walletAddress`.
    *   Performs database write (upserting voter profile record).
*   **Endpoint `POST /api/vouchers/upload`:**
    *   Receives `walletAddress`, `voucherData` (preimage, nullifier, mac, etc.), `signature`, `timestamp`, `chainId`, `roundId`.
    *   Verifies signature matches `walletAddress` and that the voter profile exists.
    *   Inserts record into `offline_vouchers` queue.

#### [NEW] [.env.template](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/server/.env.template)
Template file for configuring local backend variables:
```ini
PORT=3000
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=ey...
```

---

### Package and Dependencies

#### [MODIFY] [package.json](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/package.json)
*   Add dependencies: `express`, `cors`, `dotenv`, and `@supabase/supabase-js`.
*   Add script `npm run dev:server` to run the proxy server locally.

---

### Dashboard and Offline Integration

#### [MODIFY] [dashboard/web3_integration.js](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/dashboard/web3_integration.js)
*   Point sync tasks to `/api/voters/register` on the local proxy.
*   Prompt the connected wallet to sign registration messages before submitting them.

#### [MODIFY] [tools/offline/continuity-kit.html](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/tools/offline/continuity-kit.html)
*   Point upload tasks to `/api/vouchers/upload` on the local proxy.
*   Prompt the local operator to sign the verified voucher sync payloads before upload.

---

## Verification Plan

### Automated Tests
*   **New Backend Tests:** Create [test/server.test.js](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/test/server.test.js) to assert signature validation, reject invalid signatures, and assert correct Supabase writes via mock client.

### Manual Verification
1.  Launch proxy server: `npm run dev:server`.
2.  Open dashboard in browser.
3.  Connect wallet, register voter, and verify that the request is successfully verified by the proxy and logged in Supabase.
