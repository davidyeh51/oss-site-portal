-- =============================================================================
-- ACMEPOINT Energy Services (6692) — OSS Executive Portal Security Schema
-- Project: cowljafosekwvxithwjd (Supabase)
-- Applied via migration: oss_portal_rbac_and_access_keys
-- =============================================================================

-- 1. Granular RBAC columns on public.oss_admins
ALTER TABLE public.oss_admins
  ADD COLUMN IF NOT EXISTS enabled boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS can_export boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS can_view_commercial boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS display_name text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE public.oss_admins DROP CONSTRAINT IF EXISTS oss_admins_role_check;
ALTER TABLE public.oss_admins
  ADD CONSTRAINT oss_admins_role_check
  CHECK (role = ANY (ARRAY['owner'::text, 'admin'::text, 'member'::text, 'viewer'::text]));

-- 2. Hashed Portal Access Keys (service_role only via Edge Function)
CREATE TABLE IF NOT EXISTS public.oss_access_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  label text NOT NULL,
  key_hint text NOT NULL,
  key_salt text NOT NULL,
  key_hash text NOT NULL,
  scope text NOT NULL DEFAULT 'portal',
  enabled boolean NOT NULL DEFAULT true,
  expires_at timestamptz,
  usage_count integer NOT NULL DEFAULT 0,
  last_used_at timestamptz,
  created_by text NOT NULL DEFAULT 'system',
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.oss_access_keys ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.oss_access_keys FROM PUBLIC, anon, authenticated;

-- 3. Protected Portal Configuration (Drive link, Gate toggle, Gate HMAC secret)
CREATE TABLE IF NOT EXISTS public.oss_portal_config (
  key text PRIMARY KEY,
  value jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_by text NOT NULL DEFAULT 'system',
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.oss_portal_config ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.oss_portal_config FROM PUBLIC, anon, authenticated;

-- 4. Security & Admin Audit Logs
CREATE TABLE IF NOT EXISTS public.oss_audit_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  actor_email text,
  action text NOT NULL,
  target text,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS oss_audit_logs_created_at_idx ON public.oss_audit_logs (created_at DESC);
ALTER TABLE public.oss_audit_logs ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.oss_audit_logs FROM PUBLIC, anon, authenticated;

-- 5. Hardened RLS Helper Functions
CREATE OR REPLACE FUNCTION public.oss_is_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path TO ''
AS $$
  SELECT auth.uid() IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM public.oss_admins a
      WHERE lower(a.email) = lower(COALESCE(auth.jwt()->>'email', ''))
        AND a.enabled = true
    );
$$;

CREATE OR REPLACE FUNCTION public.oss_is_owner()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path TO ''
AS $$
  SELECT auth.uid() IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM public.oss_admins a
      WHERE lower(a.email) = lower(COALESCE(auth.jwt()->>'email', ''))
        AND a.role = 'owner'
        AND a.enabled = true
    );
$$;

CREATE OR REPLACE FUNCTION public.oss_is_manager()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path TO ''
AS $$
  SELECT auth.uid() IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM public.oss_admins a
      WHERE lower(a.email) = lower(COALESCE(auth.jwt()->>'email', ''))
        AND a.role IN ('owner', 'admin')
        AND a.enabled = true
    );
$$;

REVOKE ALL ON FUNCTION public.oss_is_admin() FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.oss_is_owner() FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.oss_is_manager() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.oss_is_admin() TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.oss_is_owner() TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.oss_is_manager() TO authenticated, service_role;

-- 6. Strict Least-Privilege Table Grants
REVOKE ALL ON public.oss_admins FROM PUBLIC, anon, authenticated;
REVOKE ALL ON public.oss_sites, public.oss_contracts, public.oss_contract_sites, public.oss_customers, public.oss_files FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.oss_sites, public.oss_contracts, public.oss_contract_sites, public.oss_customers, public.oss_files TO authenticated;
