import { createClient } from 'npm:@supabase/supabase-js@2.57.4';

// =============================================================================
// ACMEPOINT Energy Services (6692) — OSS Executive Portal Backend
// Edge Function: oss-account-admin (v4 — Role-Scoped Access Keys + Admin Console)
// Features:
//   1. Single-Step Access Key Unlock (salted SHA-256 verification + RLS session minting)
//   2. Role-Scoped Permissions (owner / admin / member / viewer + export/commercial guards)
//   3. 60-Day Key Rotation Tracking, Reminder Metadata & Self-Service Rotation
//   4. Admin Console APIs (key issuance/toggle/delete, portal config, roster, audit logs)
// =============================================================================

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const service = createClient(SUPABASE_URL, SERVICE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const DEFAULT_ORIGIN = 'https://davidyeh51.github.io';
const ALLOWED_ORIGINS = new Set([
  DEFAULT_ORIGIN,
  'http://127.0.0.1:4180',
  'http://localhost:4180',
  'http://127.0.0.1:8080',
  'http://localhost:8080',
  'http://127.0.0.1:8765',
  'http://localhost:8765',
]);

const VALID_SCOPES = new Set(['owner', 'admin', 'member', 'viewer']);
const ROTATION_CYCLE_DAYS = 60;
const ROTATION_WARN_DAYS = 7;
const GATE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours per browser unlock session
const INTERNAL_KEY_USER_EMAIL = 'portal-key-session@acme-oss.example';
const enc = new TextEncoder();

function toHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function randomHex(nBytes: number): string {
  const bytes = new Uint8Array(nBytes);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

function generateAccessKeyString(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = (n: number) => {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return Array.from(b, (x) => chars[x % chars.length]).join('');
  };
  return `ACME-${seg(4)}-${seg(4)}`;
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(input));
  return toHex(digest);
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function base64UrlEncode(input: string | Uint8Array): string {
  const bytes = typeof input === 'string' ? enc.encode(input) : input;
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str: string): string {
  const pad = '='.repeat((4 - (str.length % 4)) % 4);
  const b64 = (str + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

async function hmacSign(data: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return base64UrlEncode(new Uint8Array(sig));
}

async function createGateToken(
  payload: { key_id: string; label: string; scope: string; exp: number },
  secret: string,
): Promise<string> {
  const body = base64UrlEncode(JSON.stringify(payload));
  const sig = await hmacSign(body, secret);
  return `${body}.${sig}`;
}

async function verifyGateToken(
  token: string,
  secret: string,
): Promise<{ key_id: string; label: string; scope?: string; exp: number } | null> {
  if (!token || !token.includes('.')) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = await hmacSign(body, secret);
  if (!timingSafeEqual(sig, expected)) return null;
  try {
    const parsed = JSON.parse(base64UrlDecode(body));
    if (!parsed?.key_id || typeof parsed.exp !== 'number' || parsed.exp < Date.now()) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function maskKey(raw: string): string {
  const s = raw.trim();
  if (s.length <= 6) return '••••••';
  return `${s.slice(0, 4)}-••••-${s.slice(-4)}`;
}

function normalizeScope(scope: unknown): 'owner' | 'admin' | 'member' | 'viewer' {
  const s = String(scope || '').toLowerCase();
  if (s === 'owner' || s === 'portal') return 'owner';
  if (s === 'admin') return 'admin';
  if (s === 'viewer') return 'viewer';
  return 'member';
}

function buildPermissions(keyRow: any) {
  const role = normalizeScope(keyRow?.scope);
  const isOwner = role === 'owner';
  const isAdmin = role === 'owner' || role === 'admin';
  const canExport = role === 'owner' || (role !== 'viewer' && keyRow?.can_export !== false);
  const canViewCommercial = role === 'owner' || (role !== 'viewer' && keyRow?.can_view_commercial !== false);
  return {
    role,
    is_owner: isOwner,
    is_admin: isAdmin,
    can_manage_keys: isAdmin,
    can_rotate: isAdmin,
    can_export: canExport,
    can_view_commercial: canViewCommercial,
  };
}

function isKeyHardExpired(keyRow: any): boolean {
  if (!keyRow?.enforce_expiry || !keyRow?.expires_at) return false;
  const expMs = Date.parse(keyRow.expires_at);
  return Number.isFinite(expMs) && expMs <= Date.now();
}

async function getConfigMap(): Promise<Record<string, unknown>> {
  const { data, error } = await service.from('oss_portal_config').select('key,value');
  if (error) throw error;
  const out: Record<string, unknown> = {};
  for (const row of data || []) out[row.key] = row.value;
  return out;
}

async function writeAudit(
  actor: string,
  action: string,
  target: string | null,
  detail: Record<string, unknown> = {},
) {
  try {
    await service.from('oss_audit_logs').insert({
      actor_email: actor,
      action,
      target,
      detail,
    });
  } catch (e) {
    console.warn('Audit log write skipped:', e);
  }
}

function buildRotationInfo(keyRow: any) {
  const now = Date.now();
  const rotatedAtMs = keyRow?.created_at ? new Date(keyRow.created_at).getTime() : now;
  const cycleMs = ROTATION_CYCLE_DAYS * 86400000;
  const dueAtMs = keyRow?.expires_at ? new Date(keyRow.expires_at).getTime() : rotatedAtMs + cycleMs;
  const daysElapsed = Math.max(0, Math.floor((now - rotatedAtMs) / 86400000));
  const daysRemaining = Math.ceil((dueAtMs - now) / 86400000);
  const isOverdue = daysRemaining <= 0;
  const shouldRemind = daysRemaining <= ROTATION_WARN_DAYS;
  return {
    key_id: keyRow.id,
    label: keyRow.label || '系統存取金鑰',
    key_hint: keyRow.key_hint || '••••',
    scope: normalizeScope(keyRow.scope),
    rotated_at: new Date(rotatedAtMs).toISOString(),
    due_at: new Date(dueAtMs).toISOString(),
    cycle_days: ROTATION_CYCLE_DAYS,
    days_elapsed: daysElapsed,
    days_remaining: daysRemaining,
    is_overdue: isOverdue,
    should_remind: shouldRemind,
    enforce_expiry: Boolean(keyRow.enforce_expiry),
  };
}

// Mint a real Supabase Auth session bound to an internal RLS-authorized account
// so the frontend only needs the Access Key while all database tables stay RLS-protected.
async function mintPortalRlsSession() {
  const derivedPassword = 'AcmeKey#' + (await hmacSign(INTERNAL_KEY_USER_EMAIL, SERVICE_KEY)).slice(0, 28);

  await service.from('oss_admins').upsert(
    {
      email: INTERNAL_KEY_USER_EMAIL,
      role: 'owner',
      enabled: true,
      can_export: true,
      can_view_commercial: true,
      display_name: '金鑰解鎖通行憑證',
      updated_at: new Date().toISOString(),
    },
    { onConflict: 'email' },
  );

  const tempClient = createClient(SUPABASE_URL, SERVICE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  let signInRes = await tempClient.auth.signInWithPassword({
    email: INTERNAL_KEY_USER_EMAIL,
    password: derivedPassword,
  });

  if (signInRes.error || !signInRes.data?.session) {
    const { data: listData } = await service.auth.admin.listUsers({ page: 1, perPage: 1000 });
    const existing = (listData?.users || []).find(
      (u: any) => String(u.email || '').toLowerCase() === INTERNAL_KEY_USER_EMAIL,
    );
    if (!existing) {
      await service.auth.admin.createUser({
        email: INTERNAL_KEY_USER_EMAIL,
        password: derivedPassword,
        email_confirm: true,
      });
    } else {
      await service.auth.admin.updateUserById(existing.id, {
        password: derivedPassword,
        email_confirm: true,
      });
    }
    signInRes = await tempClient.auth.signInWithPassword({
      email: INTERNAL_KEY_USER_EMAIL,
      password: derivedPassword,
    });
    if (signInRes.error || !signInRes.data?.session) {
      throw new Error('簽發資料庫讀取憑證失敗：' + (signInRes.error?.message || 'unknown'));
    }
  }

  return {
    access_token: signInRes.data.session.access_token,
    refresh_token: signInRes.data.session.refresh_token,
  };
}

async function findMatchingActiveKey(rawKey: string) {
  const { data: keys, error } = await service
    .from('oss_access_keys')
    .select('id,label,key_hint,key_salt,key_hash,scope,can_export,can_view_commercial,enabled,enforce_expiry,expires_at,usage_count,created_at')
    .eq('enabled', true)
    .order('created_at', { ascending: false });
  if (error) throw error;

  for (const k of keys || []) {
    const candidateHash = await sha256Hex(`${k.key_salt}:${rawKey}`);
    if (timingSafeEqual(candidateHash, k.key_hash)) {
      return k;
    }
  }
  return null;
}

async function resolveGateSession(gateToken: string) {
  const cfg = await getConfigMap();
  const secret = String(cfg.gate_secret || '');
  const payload = secret && gateToken ? await verifyGateToken(gateToken, secret) : null;
  if (!payload) return { valid: false as const, cfg };

  const { data: keyRow } = await service
    .from('oss_access_keys')
    .select('id,label,key_hint,scope,can_export,can_view_commercial,enabled,enforce_expiry,expires_at,created_at')
    .eq('id', payload.key_id)
    .maybeSingle();

  if (!keyRow || !keyRow.enabled || isKeyHardExpired(keyRow)) {
    return { valid: false as const, cfg };
  }

  return {
    valid: true as const,
    cfg,
    keyRow,
    permissions: buildPermissions(keyRow),
  };
}

async function countActiveOwners(excludeKeyId?: string): Promise<number> {
  const { data, error } = await service
    .from('oss_access_keys')
    .select('id,scope')
    .eq('enabled', true);
  if (error) throw error;
  return (data || []).filter(
    (k: any) => normalizeScope(k.scope) === 'owner' && k.id !== excludeKeyId,
  ).length;
}

Deno.serve(async (req) => {
  const requestOrigin = req.headers.get('origin') || '';
  const allowOrigin = ALLOWED_ORIGINS.has(requestOrigin) ? requestOrigin : DEFAULT_ORIGIN;
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-client-info, x-oss-gate',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Vary': 'Origin',
  };
  const reply = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers });

  if (req.method === 'OPTIONS') return new Response('ok', { headers });
  if (req.method !== 'POST') return reply({ error: 'Method not allowed' }, 405);

  try {
    const body = await req.json().catch(() => ({}));
    const action = String(body.action || '');
    const gateToken = String(body.gate_token || req.headers.get('x-oss-gate') || '');

    // ── 1. Check Existing Gate Token & Return Session + Permissions + Rotation Info ──
    if (action === 'gate_status' || action === 'validate_gate') {
      const gate = await resolveGateSession(gateToken);
      if (!gate.valid) {
        return reply({ require_access_key: true, gate_valid: false, valid: false });
      }
      const rotation = buildRotationInfo(gate.keyRow);
      const session = await mintPortalRlsSession();
      return reply({
        require_access_key: true,
        gate_valid: true,
        valid: true,
        key_label: gate.keyRow.label,
        permissions: gate.permissions,
        rotation,
        session,
        config: {
          portal_notice: String(gate.cfg.portal_notice || ''),
          drive_folder_url: String(gate.cfg.drive_folder_url || ''),
        },
      });
    }

    // ── 2. Single-Step Unlock with Access Key ──
    if (action === 'verify_key' || action === 'unlock') {
      const rawKey = String(body.access_key || '').trim();
      if (!rawKey || rawKey.length < 4) {
        await new Promise((r) => setTimeout(r, 300));
        return reply({ error: '請輸入有效的系統存取金鑰（Access Key）。' }, 400);
      }

      const matched = await findMatchingActiveKey(rawKey);
      if (!matched) {
        await new Promise((r) => setTimeout(r, 400));
        await writeAudit('anonymous', 'gate_failed', maskKey(rawKey), { reason: 'invalid_key' });
        return reply({ error: '存取金鑰不正確或已停用，請重新確認。' }, 401);
      }
      if (isKeyHardExpired(matched)) {
        await writeAudit(matched.label, 'gate_failed', matched.key_hint, { reason: 'expired_key', key_id: matched.id });
        return reply({ error: '此存取金鑰已逾有效期限，請聯繫系統管理員重新發行。' }, 401);
      }

      const cfg = await getConfigMap();
      const secret = String(cfg.gate_secret || '');
      const permissions = buildPermissions(matched);
      const exp = Date.now() + GATE_TTL_MS;
      const token = await createGateToken(
        { key_id: matched.id, label: matched.label, scope: permissions.role, exp },
        secret,
      );

      await service
        .from('oss_access_keys')
        .update({
          usage_count: (matched.usage_count || 0) + 1,
          last_used_at: new Date().toISOString(),
        })
        .eq('id', matched.id);

      const rotation = buildRotationInfo(matched);
      const session = await mintPortalRlsSession();
      await writeAudit(matched.label, 'gate_verified', matched.key_hint, {
        key_id: matched.id,
        role: permissions.role,
      });

      return reply({
        ok: true,
        required: true,
        gate_token: token,
        key_label: matched.label,
        expires_at: new Date(exp).toISOString(),
        permissions,
        rotation,
        session,
        config: {
          portal_notice: String(cfg.portal_notice || ''),
          drive_folder_url: String(cfg.drive_folder_url || ''),
        },
      });
    }

    // ── All actions below require a valid active Gate Token ──
    const gate = await resolveGateSession(gateToken);
    if (!gate.valid) {
      return reply({ error: '通行憑證已失效或尚未解鎖，請重新輸入存取金鑰。' }, 401);
    }

    const actor = `${gate.keyRow.label} (${gate.permissions.role})`;

    // ── 3. Log CSV Export (Authenticated + Export Permission Guarded) ──
    if (action === 'log_export') {
      if (!gate.permissions.can_export) {
        return reply({ error: '目前金鑰權限不允許匯出報表。' }, 403);
      }
      await writeAudit(actor, 'data_exported', String(body.target || 'csv').slice(0, 120), {
        rows: Number(body.rows || 0),
        key_id: gate.keyRow.id,
      });
      return reply({ success: true });
    }

    // ── 4. Self-Service Access Key Rotation (Admin/Owner Only) ──
    if (action === 'rotate_key') {
      if (!gate.permissions.can_rotate) {
        return reply({ error: '僅管理員或擁有者金鑰可執行金鑰輪替變更。' }, 403);
      }
      const currentKey = String(body.current_key || '').trim();
      const newKey = String(body.new_key || '').trim();
      const label = String(body.label || gate.keyRow.label || '進能服維運決策平台管理金鑰').trim().slice(0, 80);

      if (!currentKey) {
        return reply({ error: '請輸入目前使用中的存取金鑰以驗證身分。' }, 400);
      }
      if (newKey.length < 8) {
        return reply({ error: '新存取金鑰長度至少需 8 個字元。' }, 400);
      }
      if (currentKey === newKey) {
        return reply({ error: '新存取金鑰不可與目前金鑰相同，請設定新的組合以符合 60 天輪替規範。' }, 400);
      }

      const matched = await findMatchingActiveKey(currentKey);
      if (!matched || matched.id !== gate.keyRow.id) {
        await new Promise((r) => setTimeout(r, 400));
        await writeAudit(actor, 'key_rotate_failed', maskKey(currentKey), { reason: 'wrong_current_key' });
        return reply({ error: '目前存取金鑰驗證不正確，無法變更金鑰。' }, 401);
      }

      const nowIso = new Date().toISOString();
      const dueIso = new Date(Date.now() + ROTATION_CYCLE_DAYS * 86400000).toISOString();
      const newSalt = randomHex(16);
      const newHash = await sha256Hex(`${newSalt}:${newKey}`);
      const newHint = maskKey(newKey);
      const role = normalizeScope(matched.scope);

      // Only disable the rotated key so other team/viewer keys remain intact
      await service.from('oss_access_keys').update({ enabled: false }).eq('id', matched.id);

      const { data: inserted, error: insErr } = await service
        .from('oss_access_keys')
        .insert({
          label,
          key_hint: newHint,
          key_salt: newSalt,
          key_hash: newHash,
          scope: role,
          can_export: matched.can_export !== false,
          can_view_commercial: matched.can_view_commercial !== false,
          enabled: true,
          enforce_expiry: Boolean(matched.enforce_expiry),
          created_at: nowIso,
          expires_at: dueIso,
          usage_count: 1,
          last_used_at: nowIso,
          created_by: actor,
        })
        .select('id,label,key_hint,scope,can_export,can_view_commercial,enabled,enforce_expiry,expires_at,created_at')
        .single();
      if (insErr) throw insErr;

      const secret = String(gate.cfg.gate_secret || '');
      const exp = Date.now() + GATE_TTL_MS;
      const newGateToken = await createGateToken(
        { key_id: inserted.id, label: inserted.label, scope: role, exp },
        secret,
      );
      const rotation = buildRotationInfo(inserted);
      const permissions = buildPermissions(inserted);

      await writeAudit(actor, 'access_key_rotated', inserted.label, {
        old_key_id: matched.id,
        new_key_id: inserted.id,
        next_due_at: dueIso,
      });

      return reply({
        ok: true,
        gate_token: newGateToken,
        permissions,
        rotation,
      });
    }

    // ── Admin Console Endpoints (owner / admin only) ──
    if (!gate.permissions.is_admin) {
      return reply({ error: '此操作僅限「管理員 / 擁有者」金鑰使用。' }, 403);
    }

    // ── 5. Admin Overview (Keys, Config, Admins Roster, Audit Logs) ──
    if (action === 'admin_overview') {
      const [keysRes, adminsRes, logsRes] = await Promise.all([
        service
          .from('oss_access_keys')
          .select('id,label,key_hint,scope,can_export,can_view_commercial,enabled,enforce_expiry,expires_at,usage_count,last_used_at,created_by,created_at')
          .order('created_at', { ascending: false }),
        service
          .from('oss_admins')
          .select('email,display_name,role,enabled,can_export,can_view_commercial,created_at,updated_at')
          .neq('email', INTERNAL_KEY_USER_EMAIL)
          .order('role', { ascending: true })
          .order('email', { ascending: true }),
        service
          .from('oss_audit_logs')
          .select('id,actor_email,action,target,detail,created_at')
          .order('created_at', { ascending: false })
          .limit(80),
      ]);

      if (keysRes.error) throw keysRes.error;
      if (adminsRes.error) throw adminsRes.error;
      if (logsRes.error) throw logsRes.error;

      return reply({
        ok: true,
        current_key_id: gate.keyRow.id,
        permissions: gate.permissions,
        keys: (keysRes.data || []).map((k: any) => ({
          ...k,
          scope: normalizeScope(k.scope),
          is_current: k.id === gate.keyRow.id,
        })),
        admins: adminsRes.data || [],
        config: {
          portal_notice: String(gate.cfg.portal_notice || ''),
          drive_folder_url: String(gate.cfg.drive_folder_url || ''),
          require_access_key: gate.cfg.require_access_key !== false,
        },
        audit_logs: logsRes.data || [],
      });
    }

    // ── 6. Create New Scoped Access Key ──
    if (action === 'create_access_key') {
      const label = String(body.label || '').trim().slice(0, 80);
      const scope = String(body.scope || 'member').toLowerCase();
      const rawKeyInput = String(body.raw_key || '').trim();
      const expiresDays = Math.min(365, Math.max(1, Number(body.expires_days || 60)));
      const enforceExpiry = Boolean(body.enforce_expiry);

      if (!label) return reply({ error: '請填寫金鑰用途標籤（例如：財務部稽核唯讀金鑰）。' }, 400);
      if (!VALID_SCOPES.has(scope)) return reply({ error: '不支援的權限等級。' }, 400);
      if (scope === 'owner' && !gate.permissions.is_owner) {
        return reply({ error: '僅最高擁有者金鑰可發行 owner 等級金鑰。' }, 403);
      }

      const plaintextKey = rawKeyInput || generateAccessKeyString();
      if (plaintextKey.length < 8) {
        return reply({ error: '自訂金鑰長度至少需 8 個字元。' }, 400);
      }

      const canExport = scope === 'owner' ? true : scope === 'viewer' ? false : body.can_export !== false;
      const canViewCommercial = scope === 'owner' ? true : scope === 'viewer' ? false : body.can_view_commercial !== false;
      const nowIso = new Date().toISOString();
      const expiresAt = new Date(Date.now() + expiresDays * 86400000).toISOString();
      const salt = randomHex(16);
      const hash = await sha256Hex(`${salt}:${plaintextKey}`);
      const hint = maskKey(plaintextKey);

      const { data: created, error } = await service
        .from('oss_access_keys')
        .insert({
          label,
          key_hint: hint,
          key_salt: salt,
          key_hash: hash,
          scope,
          can_export: canExport,
          can_view_commercial: canViewCommercial,
          enabled: true,
          enforce_expiry: enforceExpiry,
          expires_at: expiresAt,
          created_at: nowIso,
          created_by: actor,
        })
        .select('id,label,key_hint,scope,can_export,can_view_commercial,enabled,enforce_expiry,expires_at,usage_count,last_used_at,created_by,created_at')
        .single();
      if (error) throw error;

      await writeAudit(actor, 'access_key_created', `${label} (${hint})`, {
        key_id: created.id,
        scope,
        can_export: canExport,
        can_view_commercial: canViewCommercial,
        enforce_expiry: enforceExpiry,
        expires_days: expiresDays,
      });

      return reply({
        ok: true,
        plaintext_key: plaintextKey,
        key: created,
      });
    }

    // ── 7. Toggle / Update Access Key ──
    if (action === 'update_access_key') {
      const id = String(body.id || '').trim();
      if (!id) return reply({ error: '缺少金鑰 ID。' }, 400);

      const { data: target, error: findErr } = await service
        .from('oss_access_keys')
        .select('id,label,key_hint,scope,enabled,can_export,can_view_commercial')
        .eq('id', id)
        .maybeSingle();
      if (findErr) throw findErr;
      if (!target) return reply({ error: '找不到指定的金鑰。' }, 404);

      const targetScope = normalizeScope(target.scope);
      if (targetScope === 'owner' && !gate.permissions.is_owner) {
        return reply({ error: '僅最高擁有者可修改 owner 等級金鑰。' }, 403);
      }

      const nextEnabled = typeof body.enabled === 'boolean' ? body.enabled : target.enabled;
      const nextScope = body.scope && VALID_SCOPES.has(String(body.scope)) ? String(body.scope) : targetScope;
      if (nextScope === 'owner' && !gate.permissions.is_owner) {
        return reply({ error: '僅最高擁有者可指派 owner 等級。' }, 403);
      }

      if (target.id === gate.keyRow.id && nextEnabled === false) {
        return reply({ error: '不可停用目前正在登入操作中的金鑰。' }, 400);
      }
      if (targetScope === 'owner' && (nextEnabled === false || nextScope !== 'owner')) {
        const otherOwners = await countActiveOwners(target.id);
        if (otherOwners < 1) {
          return reply({ error: '系統必須至少保留一組啟用中的 owner 金鑰，避免無法管理後台。' }, 400);
        }
      }

      const patch: Record<string, unknown> = {
        enabled: nextEnabled,
        scope: nextScope,
      };
      if (typeof body.can_export === 'boolean') patch.can_export = nextScope === 'owner' ? true : body.can_export;
      if (typeof body.can_view_commercial === 'boolean') {
        patch.can_view_commercial = nextScope === 'owner' ? true : body.can_view_commercial;
      }
      if (typeof body.label === 'string' && body.label.trim()) patch.label = body.label.trim().slice(0, 80);

      const { data: updated, error: updErr } = await service
        .from('oss_access_keys')
        .update(patch)
        .eq('id', id)
        .select('id,label,key_hint,scope,can_export,can_view_commercial,enabled,enforce_expiry,expires_at,usage_count,last_used_at,created_by,created_at')
        .single();
      if (updErr) throw updErr;

      await writeAudit(actor, 'access_key_updated', `${updated.label} (${updated.key_hint})`, patch);
      return reply({ ok: true, key: updated });
    }

    // ── 8. Delete Disabled / Old Access Key ──
    if (action === 'delete_access_key') {
      const id = String(body.id || '').trim();
      if (!id) return reply({ error: '缺少金鑰 ID。' }, 400);
      if (id === gate.keyRow.id) {
        return reply({ error: '不可刪除目前正在使用中的金鑰。' }, 400);
      }

      const { data: target } = await service
        .from('oss_access_keys')
        .select('id,label,key_hint,scope,enabled')
        .eq('id', id)
        .maybeSingle();
      if (!target) return reply({ error: '找不到指定的金鑰。' }, 404);

      if (normalizeScope(target.scope) === 'owner') {
        if (!gate.permissions.is_owner) return reply({ error: '僅最高擁有者可刪除 owner 金鑰。' }, 403);
        const otherOwners = await countActiveOwners(target.id);
        if (target.enabled && otherOwners < 1) {
          return reply({ error: '系統必須至少保留一組啟用中的 owner 金鑰。' }, 400);
        }
      }

      const { error: delErr } = await service.from('oss_access_keys').delete().eq('id', id);
      if (delErr) throw delErr;

      await writeAudit(actor, 'access_key_deleted', `${target.label} (${target.key_hint})`, { key_id: id });
      return reply({ ok: true });
    }

    // ── 9. Update Portal Configuration (Drive URL & Notice) ──
    if (action === 'update_portal_config') {
      const driveUrl = String(body.drive_folder_url || '').trim();
      const notice = String(body.portal_notice || '').trim().slice(0, 300);

      if (driveUrl && !/^https:\/\/[a-zA-Z0-9.-]+/.test(driveUrl)) {
        return reply({ error: '雲端資料庫網址必須為 https:// 開頭之安全網址。' }, 400);
      }

      const nowIso = new Date().toISOString();
      const rows = [
        { key: 'drive_folder_url', value: driveUrl, updated_by: actor, updated_at: nowIso },
        { key: 'portal_notice', value: notice, updated_by: actor, updated_at: nowIso },
      ];
      const { error } = await service.from('oss_portal_config').upsert(rows, { onConflict: 'key' });
      if (error) throw error;

      await writeAudit(actor, 'portal_config_updated', 'oss_portal_config', {
        has_drive_url: Boolean(driveUrl),
        notice_length: notice.length,
      });

      return reply({
        ok: true,
        config: { drive_folder_url: driveUrl, portal_notice: notice },
      });
    }

    // ── 10. Manage Authorized Roster (oss_admins) ──
    if (action === 'upsert_admin_member') {
      const email = String(body.email || '').trim().toLowerCase();
      const displayName = String(body.display_name || '').trim().slice(0, 60);
      const role = String(body.role || 'member').toLowerCase();
      const enabled = body.enabled !== false;
      const canExport = role === 'viewer' ? false : body.can_export !== false;
      const canViewCommercial = role === 'viewer' ? false : body.can_view_commercial !== false;

      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return reply({ error: '請輸入有效的公司 Email 地址。' }, 400);
      }
      if (email === INTERNAL_KEY_USER_EMAIL) {
        return reply({ error: '系統內部憑證帳號不可修改。' }, 400);
      }
      if (!VALID_SCOPES.has(role)) {
        return reply({ error: '不支援的角色等級。' }, 400);
      }
      if (role === 'owner' && !gate.permissions.is_owner) {
        return reply({ error: '僅最高擁有者可新增或修改 owner 帳號。' }, 403);
      }

      const { data: saved, error } = await service
        .from('oss_admins')
        .upsert(
          {
            email,
            display_name: displayName,
            role,
            enabled,
            can_export: canExport,
            can_view_commercial: canViewCommercial,
            updated_at: new Date().toISOString(),
          },
          { onConflict: 'email' },
        )
        .select('email,display_name,role,enabled,can_export,can_view_commercial,created_at,updated_at')
        .single();
      if (error) throw error;

      await writeAudit(actor, 'admin_member_saved', email, { role, enabled, can_export: canExport });
      return reply({ ok: true, member: saved });
    }

    if (action === 'delete_admin_member') {
      const email = String(body.email || '').trim().toLowerCase();
      if (!email || email === INTERNAL_KEY_USER_EMAIL) {
        return reply({ error: '無效的帳號識別。' }, 400);
      }
      const { data: existing } = await service.from('oss_admins').select('role').eq('email', email).maybeSingle();
      if (existing?.role === 'owner' && !gate.permissions.is_owner) {
        return reply({ error: '僅最高擁有者可移除 owner 名單。' }, 403);
      }
      const { error } = await service.from('oss_admins').delete().eq('email', email);
      if (error) throw error;

      await writeAudit(actor, 'admin_member_deleted', email, {});
      return reply({ ok: true });
    }

    return reply({ error: '不支援的操作指令。' }, 400);
  } catch (error) {
    console.error('OSS Gate Error:', error);
    return reply({ error: '系統驗證服務異常，請稍後再試。' }, 500);
  }
});
