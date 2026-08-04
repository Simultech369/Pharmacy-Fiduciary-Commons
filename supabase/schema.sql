-- Supabase Initial Schema and RLS Policies for Pharmacy Fiduciary Commons
-- Enable the pgcrypto extension for cryptographic signature checks
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. DATABASE TABLES (DDL)

-- A. Voter Profiles (Linked to Supabase Auth Users)
CREATE TABLE IF NOT EXISTS public.voter_profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    wallet_address VARCHAR(42) NOT NULL UNIQUE,
    encrypted_metadata TEXT, -- Encrypted JSON string for credential claims
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    CONSTRAINT chk_wallet_address_format CHECK (wallet_address ~* '^0x[a-f0-9]{40}$')
);

-- B. Proposal Drafts (Participatory Budgeting drafts before going on-chain)
CREATE TABLE IF NOT EXISTS public.proposals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    creator_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    amount NUMERIC(78, 0) NOT NULL, -- Supports uint256 token amounts
    round_id NUMERIC(78, 0) NOT NULL,
    status VARCHAR(50) DEFAULT 'draft'::character varying NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    CONSTRAINT chk_proposal_status CHECK (status IN ('draft', 'approved', 'rejected', 'onchain')),
    CONSTRAINT chk_positive_amount CHECK (amount >= 0)
);

-- C. Offline Vouchers Queue (Vouchers collected offline during outages)
CREATE TABLE IF NOT EXISTS public.offline_vouchers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    round_id INTEGER NOT NULL,
    preimage VARCHAR(66) NOT NULL, -- Bearer secret key (hex starting with 0x)
    nullifier VARCHAR(66) NOT NULL, -- Public nullifier hash (hex starting with 0x)
    generated_at VARCHAR(50) NOT NULL, -- JS ISO Date string
    status VARCHAR(50) NOT NULL, -- Sync status, e.g. pending_sync
    proof_format VARCHAR(100) NOT NULL, -- e.g. offline-voucher-v1-not-zk-proof
    warning TEXT NOT NULL,
    mac VARCHAR(18) NOT NULL, -- HMAC truncated to 16 hex chars starting with 0x
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    CONSTRAINT chk_preimage_format CHECK (preimage ~* '^0x[a-f0-9]{64}$'),
    CONSTRAINT chk_nullifier_format CHECK (nullifier ~* '^0x[a-f0-9]{64}$'),
    CONSTRAINT chk_mac_format CHECK (mac ~* '^0x[a-f0-9]{16}$')
);

-- D. Reconciliation Runs (Audit log of local-to-chain reconciliation jobs)
CREATE TABLE IF NOT EXISTS public.reconciliation_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_by UUID NOT NULL REFERENCES auth.users(id) ON DELETE SET NULL,
    total_vouchers_processed INTEGER DEFAULT 0 NOT NULL,
    reconciled_count INTEGER DEFAULT 0 NOT NULL,
    duplicate_conflict_count INTEGER DEFAULT 0 NOT NULL,
    unresolved_count INTEGER DEFAULT 0 NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- E. Consumed Nonces (Durable atomic replay protection)
CREATE TABLE IF NOT EXISTS public.consumed_nonces (
    nonce_key VARCHAR(255) PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- F. Registration Ledger (Idempotent request state machine)
CREATE TABLE IF NOT EXISTS public.registration_ledger (
    nonce_key VARCHAR(255) PRIMARY KEY,
    request_hash VARCHAR(64) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending' NOT NULL,
    user_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    CONSTRAINT chk_ledger_status CHECK (status IN ('pending', 'completed', 'failed'))
);

-- Indices for performance and unique constraint enforcement
CREATE INDEX IF NOT EXISTS idx_voter_profiles_wallet ON public.voter_profiles(wallet_address);
CREATE INDEX IF NOT EXISTS idx_proposals_creator ON public.proposals(creator_id);
CREATE INDEX IF NOT EXISTS idx_offline_vouchers_user ON public.offline_vouchers(user_id);
CREATE INDEX IF NOT EXISTS idx_offline_vouchers_status ON public.offline_vouchers(status);


-- 2. ROW-LEVEL SECURITY (RLS) POLICIES

-- Enable RLS on all tables
ALTER TABLE public.voter_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.offline_vouchers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reconciliation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.consumed_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.registration_ledger ENABLE ROW LEVEL SECURITY;

-- A. Voter Profiles Policies
DROP POLICY IF EXISTS "Voter profiles are viewable by everyone" ON public.voter_profiles;

CREATE POLICY "Voter profiles are viewable only by the owner or service role" ON public.voter_profiles
    FOR SELECT USING (auth.uid() = id OR auth.role() = 'service_role');

CREATE POLICY "Users can insert their own profile" ON public.voter_profiles
    FOR INSERT WITH CHECK (auth.uid() = id);

CREATE POLICY "Users can update their own profile" ON public.voter_profiles
    FOR UPDATE USING (auth.uid() = id);

-- B. Proposal Policies
CREATE POLICY "Proposals are viewable by everyone" ON public.proposals
    FOR SELECT USING (true);

CREATE POLICY "Authenticated users can create proposals" ON public.proposals
    FOR INSERT WITH CHECK (auth.uid() = creator_id);

CREATE POLICY "Creators can update their own draft proposals" ON public.proposals
    FOR UPDATE USING (auth.uid() = creator_id AND status = 'draft');

CREATE POLICY "Creators can delete their own draft proposals" ON public.proposals
    FOR DELETE USING (auth.uid() = creator_id AND status = 'draft');

-- C. Tenant Claims Policies
CREATE TABLE IF NOT EXISTS public.tenant_claims (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(64) NOT NULL,
    claim_hash VARCHAR(64) NOT NULL,
    amount NUMERIC(18,2) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

ALTER TABLE public.tenant_claims ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Tenant claims viewable by tenant members or service role" ON public.tenant_claims
    FOR SELECT USING (
        (auth.jwt() -> 'app_metadata'::text ->> 'tenant_id') = tenant_id OR
        auth.role() = 'service_role'
    );

CREATE POLICY "Tenant claims insertable by tenant members or service role" ON public.tenant_claims
    FOR INSERT WITH CHECK (
        (auth.jwt() -> 'app_metadata'::text ->> 'tenant_id') = tenant_id OR
        auth.role() = 'service_role'
    );

-- D. Offline Vouchers Policies
CREATE POLICY "Users can view their own vouchers" ON public.offline_vouchers
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can queue their own vouchers" ON public.offline_vouchers
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Admins and Service Roles have full clearance on vouchers for processing
CREATE POLICY "Admins and service roles can view all vouchers" ON public.offline_vouchers
    FOR SELECT USING (
        (auth.jwt() -> 'app_metadata'::text ->> 'role') = 'admin' OR 
        auth.role() = 'service_role'
    );

CREATE POLICY "Admins and service roles can update all vouchers" ON public.offline_vouchers
    FOR UPDATE USING (
        (auth.jwt() -> 'app_metadata'::text ->> 'role') = 'admin' OR 
        auth.role() = 'service_role'
    );

-- D. Reconciliation Runs Policies
CREATE POLICY "Only admins and service roles can view or run reconciliation logs" ON public.reconciliation_runs
    FOR ALL USING (
        (auth.jwt() -> 'app_metadata'::text ->> 'role') = 'admin' OR 
        auth.role() = 'service_role'
    );

-- E. Consumed Nonces Policies
CREATE POLICY "Only service roles can access consumed nonces" ON public.consumed_nonces
    FOR ALL USING (auth.role() = 'service_role');

-- F. Registration Ledger Policies
CREATE POLICY "Only service roles can access registration_ledger" ON public.registration_ledger
    FOR ALL USING (auth.role() = 'service_role');


-- 3. CRYPTOGRAPHIC VERIFICATION (PL/pgSQL Trigger)

-- Trigger function to check the 64-bit HMAC signature on incoming vouchers
CREATE OR REPLACE FUNCTION public.verify_voucher_hmac()
RETURNS TRIGGER AS $$
DECLARE
  v_secret text;
  v_computed_hmac text;
  v_raw_data text;
  v_warning text;
BEGIN
  -- Retrieve secret key from database custom configuration parameter
  v_secret := current_setting('app.settings.voucher_secret', true);
  IF v_secret IS NULL OR v_secret = '' THEN
    RAISE EXCEPTION 'Configuration security breach: app.settings.voucher_secret is not configured. Database transactions must fail-closed.';
  END IF;

  -- Escape backslashes and double quotes in warning to ensure exact JSON formatting if needed,
  -- but since it is a hardcoded warning string in code, we can append it directly.
  v_warning := NEW.warning;

  -- Construct the deterministic JSON payload matching alphabetical keys:
  -- {"generatedAt":"...","nullifier":"...","preimage":"...","proofFormat":"...","roundId":...,"status":"...","warning":"..."}
  v_raw_data := '{"generatedAt":"' || NEW.generated_at || '",'
             || '"nullifier":"' || NEW.nullifier || '",'
             || '"preimage":"' || NEW.preimage || '",'
             || '"proofFormat":"' || NEW.proof_format || '",'
             || '"roundId":' || NEW.round_id::text || ','
             || '"status":"' || NEW.status || '",'
             || '"warning":"' || v_warning || '"}';

  -- Compute HMAC-SHA256 and truncate to 16 hex chars (64 bits) prefixed with 0x
  v_computed_hmac := '0x' || substring(
    encode(hmac(v_raw_data::bytea, v_secret::bytea, 'sha256'), 'hex')
    from 1 for 16
  );

  -- Assert signature validity
  IF NEW.mac <> v_computed_hmac THEN
    RAISE EXCEPTION 'Cryptographic verification failed: invalid offline voucher signature.';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Bind trigger to offline_vouchers insert
CREATE OR REPLACE TRIGGER trg_verify_voucher_hmac
    BEFORE INSERT ON public.offline_vouchers
    FOR EACH ROW
    EXECUTE FUNCTION public.verify_voucher_hmac();


-- -- 4. REGISTRATION LEDGER PL/PGSQL STATE MACHINE FUNCTIONS

-- Atomically reserve or retrieve the state of a voter registration request
CREATE OR REPLACE FUNCTION public.register_voter_ledger_start(
    p_nonce_key VARCHAR(255),
    p_request_hash VARCHAR(64)
) RETURNS TABLE (
    status VARCHAR(20),
    user_id UUID
) SET search_path = public AS $$
DECLARE
    v_status VARCHAR(20);
    v_user_id UUID;
    v_hash VARCHAR(64);
    v_created TIMESTAMP WITH TIME ZONE;
    v_updated TIMESTAMP WITH TIME ZONE;
BEGIN
    IF auth.role() <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: register_voter_ledger_start can only be executed by the database proxy service role.';
    END IF;

    -- Perform an atomic row-level lock on the specific nonce key
    SELECT r.status, r.user_id, r.request_hash, r.created_at, r.updated_at
    INTO v_status, v_user_id, v_hash, v_created, v_updated
    FROM public.registration_ledger r
    WHERE r.nonce_key = p_nonce_key
    FOR UPDATE;

    IF FOUND THEN
        IF v_hash <> p_request_hash THEN
            RETURN QUERY SELECT 'mismatch'::varchar, NULL::uuid;
        ELSIF v_status = 'completed' THEN
            RETURN QUERY SELECT 'completed'::varchar, v_user_id;
        ELSIF v_status = 'pending' AND v_updated > timezone('utc'::text, now()) - INTERVAL '15 seconds' THEN
            RETURN QUERY SELECT 'pending'::varchar, NULL::uuid;
        ELSE
            -- Lease expired or retry of failed attempt: set back to pending, refresh timestamp
            UPDATE public.registration_ledger
            SET status = 'pending',
                updated_at = timezone('utc'::text, now())
            WHERE nonce_key = p_nonce_key;
            RETURN QUERY SELECT 'success'::varchar, NULL::uuid;
        END IF;
    ELSE
        -- Insert initial ledger record
        INSERT INTO public.registration_ledger (nonce_key, request_hash, status)
        VALUES (p_nonce_key, p_request_hash, 'pending');
        RETURN QUERY SELECT 'success'::varchar, NULL::uuid;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;


-- Mark the ledger record as completed with the associated user ID
CREATE OR REPLACE FUNCTION public.register_voter_ledger_complete(
    p_nonce_key VARCHAR(255),
    p_user_id UUID
) RETURNS VOID SET search_path = public AS $$
BEGIN
    IF auth.role() <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: register_voter_ledger_complete can only be executed by the database proxy service role.';
    END IF;

    UPDATE public.registration_ledger
    SET status = 'completed',
        user_id = p_user_id,
        updated_at = timezone('utc'::text, now())
    WHERE nonce_key = p_nonce_key;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;


-- Mark the ledger record as failed
CREATE OR REPLACE FUNCTION public.register_voter_ledger_fail(
    p_nonce_key VARCHAR(255)
) RETURNS VOID SET search_path = public AS $$
BEGIN
    IF auth.role() <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: register_voter_ledger_fail can only be executed by the database proxy service role.';
    END IF;

    UPDATE public.registration_ledger
    SET status = 'failed',
        updated_at = timezone('utc'::text, now())
    WHERE nonce_key = p_nonce_key;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- REVOKE PUBLIC EXECUTE PRIVILEGES & GRANT ONLY TO SERVICE ROLE
REVOKE EXECUTE ON FUNCTION public.register_voter_ledger_start(VARCHAR, VARCHAR) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.register_voter_ledger_complete(VARCHAR, UUID) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.register_voter_ledger_fail(VARCHAR) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.register_voter_ledger_start(VARCHAR, VARCHAR) TO service_role;
GRANT EXECUTE ON FUNCTION public.register_voter_ledger_complete(VARCHAR, UUID) TO service_role;
GRANT EXECUTE ON FUNCTION public.register_voter_ledger_fail(VARCHAR) TO service_role;
