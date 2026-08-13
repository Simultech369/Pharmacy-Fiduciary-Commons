-- Phase 4: Durable Voucher Settlement Saga Queue

CREATE TABLE IF NOT EXISTS public.voucher_settlement_saga (
    saga_key VARCHAR(64) PRIMARY KEY,
    request_hash VARCHAR(64) NOT NULL,
    voucher_id VARCHAR(66) NOT NULL,
    pharmacy_address VARCHAR(42) NOT NULL,
    amount NUMERIC(78, 0) NOT NULL,
    client_nonce VARCHAR(128) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending' NOT NULL,
    retry_count INTEGER DEFAULT 0 NOT NULL,
    last_error VARCHAR(128),
    payload_json JSONB NOT NULL,
    result_json JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    CONSTRAINT chk_voucher_saga_key_format CHECK (saga_key ~* '^[a-f0-9]{64}$'),
    CONSTRAINT chk_voucher_saga_hash_format CHECK (request_hash ~* '^[a-f0-9]{64}$'),
    CONSTRAINT chk_voucher_saga_voucher_id_format CHECK (voucher_id ~* '^0x[a-f0-9]{64}$'),
    CONSTRAINT chk_voucher_saga_pharmacy_format CHECK (pharmacy_address ~* '^0x[a-f0-9]{40}$'),
    CONSTRAINT chk_voucher_saga_amount_positive CHECK (amount > 0),
    CONSTRAINT chk_voucher_saga_status CHECK (status IN ('pending', 'retrying', 'completed', 'dead_letter'))
);

CREATE INDEX IF NOT EXISTS idx_voucher_saga_pharmacy ON public.voucher_settlement_saga(pharmacy_address);
CREATE INDEX IF NOT EXISTS idx_voucher_saga_status ON public.voucher_settlement_saga(status);

ALTER TABLE public.voucher_settlement_saga ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Pharmacies can read own voucher saga entries" ON public.voucher_settlement_saga
    FOR SELECT USING (
        (auth.jwt() ->> 'wallet_address') = pharmacy_address OR
        auth.role() = 'service_role'
    );

CREATE POLICY "Only service roles can mutate voucher saga entries" ON public.voucher_settlement_saga
    FOR ALL USING (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');

CREATE OR REPLACE FUNCTION public.voucher_saga_start(
    p_saga_key VARCHAR(64),
    p_request_hash VARCHAR(64),
    p_voucher_id VARCHAR(66),
    p_pharmacy_address VARCHAR(42),
    p_amount TEXT,
    p_client_nonce VARCHAR(128),
    p_payload_json JSONB
) RETURNS TABLE (
    status VARCHAR(20),
    result_json JSONB,
    retry_count INTEGER
) SET search_path = public AS $$
DECLARE
    v_status VARCHAR(20);
    v_hash VARCHAR(64);
    v_result JSONB;
    v_retry_count INTEGER;
    v_updated TIMESTAMP WITH TIME ZONE;
    v_inserted BOOLEAN;
BEGIN
    IF auth.role() <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: voucher_saga_start can only be executed by the database proxy service role.';
    END IF;

    WITH inserted AS (
        INSERT INTO public.voucher_settlement_saga (
            saga_key,
            request_hash,
            voucher_id,
            pharmacy_address,
            amount,
            client_nonce,
            payload_json,
            status
        ) VALUES (
            p_saga_key,
            p_request_hash,
            lower(p_voucher_id),
            lower(p_pharmacy_address),
            p_amount::numeric,
            p_client_nonce,
            p_payload_json,
            'pending'
        )
        ON CONFLICT (saga_key) DO NOTHING
        RETURNING true
    )
    SELECT COALESCE((SELECT true FROM inserted LIMIT 1), false)
    INTO v_inserted;

    IF v_inserted THEN
        RETURN QUERY SELECT 'success'::varchar, NULL::jsonb, 0;
        RETURN;
    END IF;

    SELECT s.status, s.request_hash, s.result_json, s.retry_count, s.updated_at
    INTO v_status, v_hash, v_result, v_retry_count, v_updated
    FROM public.voucher_settlement_saga s
    WHERE s.saga_key = p_saga_key
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Voucher saga lease state unavailable after insert conflict.';
    END IF;

    IF v_hash <> p_request_hash THEN
        RETURN QUERY SELECT 'mismatch'::varchar, NULL::jsonb, v_retry_count;
    ELSIF v_status = 'completed' THEN
        RETURN QUERY SELECT 'completed'::varchar, v_result, v_retry_count;
    ELSIF v_status = 'dead_letter' THEN
        RETURN QUERY SELECT 'dead_letter'::varchar, NULL::jsonb, v_retry_count;
    ELSIF v_updated > timezone('utc'::text, now()) - INTERVAL '15 seconds' THEN
        RETURN QUERY SELECT v_status, NULL::jsonb, v_retry_count;
    ELSE
        UPDATE public.voucher_settlement_saga
        SET status = 'pending',
            updated_at = timezone('utc'::text, now())
        WHERE saga_key = p_saga_key;
        RETURN QUERY SELECT 'success'::varchar, NULL::jsonb, v_retry_count;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.voucher_saga_complete(
    p_saga_key VARCHAR(64),
    p_result_json JSONB
) RETURNS VOID SET search_path = public AS $$
BEGIN
    IF auth.role() <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: voucher_saga_complete can only be executed by the database proxy service role.';
    END IF;

    UPDATE public.voucher_settlement_saga
    SET status = 'completed',
        result_json = p_result_json,
        updated_at = timezone('utc'::text, now())
    WHERE saga_key = p_saga_key
      AND status <> 'completed';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.voucher_saga_fail(
    p_saga_key VARCHAR(64),
    p_error_code VARCHAR(128),
    p_transient BOOLEAN
) RETURNS VOID SET search_path = public AS $$
DECLARE
    v_next_retry INTEGER;
BEGIN
    IF auth.role() <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: voucher_saga_fail can only be executed by the database proxy service role.';
    END IF;

    SELECT retry_count + 1
    INTO v_next_retry
    FROM public.voucher_settlement_saga
    WHERE saga_key = p_saga_key
    FOR UPDATE;

    UPDATE public.voucher_settlement_saga
    SET retry_count = COALESCE(v_next_retry, retry_count + 1),
        last_error = p_error_code,
        status = CASE
            WHEN p_transient AND COALESCE(v_next_retry, retry_count + 1) < 3 THEN 'retrying'
            ELSE 'dead_letter'
        END,
        updated_at = timezone('utc'::text, now())
    WHERE saga_key = p_saga_key
      AND status <> 'completed';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.voucher_saga_dead_letter(
    p_saga_key VARCHAR(64),
    p_request_hash VARCHAR(64),
    p_voucher_id VARCHAR(66),
    p_pharmacy_address VARCHAR(42),
    p_amount TEXT,
    p_client_nonce VARCHAR(128),
    p_error_code VARCHAR(128)
) RETURNS VOID SET search_path = public AS $$
BEGIN
    IF auth.role() <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: voucher_saga_dead_letter can only be executed by the database proxy service role.';
    END IF;

    INSERT INTO public.voucher_settlement_saga (
        saga_key,
        request_hash,
        voucher_id,
        pharmacy_address,
        amount,
        client_nonce,
        status,
        retry_count,
        last_error,
        payload_json
    ) VALUES (
        p_saga_key,
        p_request_hash,
        lower(p_voucher_id),
        lower(p_pharmacy_address),
        p_amount::numeric,
        p_client_nonce,
        'dead_letter',
        0,
        p_error_code,
        '{}'::jsonb
    )
    ON CONFLICT (saga_key) DO UPDATE
    SET status = 'dead_letter',
        last_error = EXCLUDED.last_error,
        updated_at = timezone('utc'::text, now())
    WHERE public.voucher_settlement_saga.status <> 'completed';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

REVOKE EXECUTE ON FUNCTION public.voucher_saga_start(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TEXT, VARCHAR, JSONB) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.voucher_saga_complete(VARCHAR, JSONB) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.voucher_saga_fail(VARCHAR, VARCHAR, BOOLEAN) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.voucher_saga_dead_letter(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TEXT, VARCHAR, VARCHAR) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.voucher_saga_start(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TEXT, VARCHAR, JSONB) TO service_role;
GRANT EXECUTE ON FUNCTION public.voucher_saga_complete(VARCHAR, JSONB) TO service_role;
GRANT EXECUTE ON FUNCTION public.voucher_saga_fail(VARCHAR, VARCHAR, BOOLEAN) TO service_role;
GRANT EXECUTE ON FUNCTION public.voucher_saga_dead_letter(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TEXT, VARCHAR, VARCHAR) TO service_role;
