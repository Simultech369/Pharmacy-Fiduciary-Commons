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

-- A. Voter Profiles Policies
CREATE POLICY "Voter profiles are viewable by everyone" ON public.voter_profiles
    FOR SELECT USING (true);

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

-- C. Offline Vouchers Policies
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
  -- Retrieve secret key from custom app setting or use the default system key
  v_secret := coalesce(
    current_setting('app.settings.voucher_secret', true),
    'fiduciary-commons-secret-key-12345'
  );

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
