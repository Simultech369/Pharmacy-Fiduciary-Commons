-- Migration: Hardened RLS and Idempotent Registration Ledger
-- Path: supabase/migrations/20260721000000_hardened_rls_and_ledger.sql

-- 1. DROP LEGACY PERMISSIVE POLICY
DROP POLICY IF EXISTS "Voter profiles are viewable by everyone" ON public.voter_profiles;

-- 2. CREATE REGISTRATION LEDGER TABLE
CREATE TABLE IF NOT EXISTS public.registration_ledger (
    nonce_key VARCHAR(255) PRIMARY KEY,
    request_hash VARCHAR(64) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending' NOT NULL,
    user_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    CONSTRAINT chk_ledger_status CHECK (status IN ('pending', 'completed', 'failed'))
);

-- 3. ENABLE RLS AND CONSTRAIN PRIVILEGES
ALTER TABLE public.voter_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.registration_ledger ENABLE ROW LEVEL SECURITY;

-- Voter profiles: visible only by the owner or database service roles
CREATE POLICY "Voter profiles are viewable only by the owner or service role" ON public.voter_profiles
    FOR SELECT USING (auth.uid() = id OR auth.role() = 'service_role');

CREATE POLICY "Users can insert their own profile" ON public.voter_profiles
    FOR INSERT WITH CHECK (auth.uid() = id);

CREATE POLICY "Users can update their own profile" ON public.voter_profiles
    FOR UPDATE USING (auth.uid() = id);

-- Registration ledger: accessible only by database service roles (proxy server backend)
CREATE POLICY "Only service roles can access registration_ledger" ON public.registration_ledger
    FOR ALL USING (auth.role() = 'service_role');


-- 4. REGISTRATION LEDGER PL/PGSQL STATE MACHINE FUNCTIONS

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
    -- Strict Service Role Guard
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

-- 5. REVOKE PUBLIC EXECUTE PRIVILEGES & GRANT ONLY TO SERVICE ROLE
REVOKE EXECUTE ON FUNCTION public.register_voter_ledger_start(VARCHAR, VARCHAR) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.register_voter_ledger_complete(VARCHAR, UUID) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.register_voter_ledger_fail(VARCHAR) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.register_voter_ledger_start(VARCHAR, VARCHAR) TO service_role;
GRANT EXECUTE ON FUNCTION public.register_voter_ledger_complete(VARCHAR, UUID) TO service_role;
GRANT EXECUTE ON FUNCTION public.register_voter_ledger_fail(VARCHAR) TO service_role;

-- Privacy Warning Documentation:
-- Storing wallet address alongside blinded credential HMAC exposes the proxy operator to correlation risk.
-- If the operator accesses both the public blockchain ledger (to resolve on-chain credential events) 
-- and holds the credentialPepper secret, they can perform pre-image correlation to match specific 
-- pharmacy wallets to their respective raw credentials. Implement physical and credential access separation 
-- for the database pepper configuration in production environments.
