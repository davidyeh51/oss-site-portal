import { createClient } from 'npm:@supabase/supabase-js@2.57.4';

// =============================================================================
// ACMEPOINT Energy Services (6692) — OSS Executive Portal Backend
// Edge Function: oss-account-admin
// Features:
//   1. Access Key Gate (salted SHA-256 + HMAC-SHA256 stateless gate tokens)
//   2. Granular RBAC (owner / admin / member / viewer + export/commercial flags)
//   3. Protected Portal Config (Drive URL, Gate toggle, Notice)
//   4. Audit Logging & Self-Service Password Update
//   5. Synchronized access with taiwan-weather-ops (wx_portfolio_members)
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

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const VALID_ROLES = new Set(['owner', 'admin', 'member', 'viewer']);
const GATE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
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
  payload: { key_id: string; label: string; exp: number },
  secret: string,
): Promise<string> {
  const body = base64UrlEncode(JSON.stringify(payload));
  const sig = await hmacSign(body, secret);
  return `${body}.${sig}`;
}

async function verifyGateToken(
  token: string,
  secret: string,
): Promise<{ key_id: string; label: string; exp: number } | null> {
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

function generateAccessKey(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const pick = (len: number) => {
    const bytes = new Uint8Array(len);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('');
  };
  return `ACME-${pick(4)}-${pick(4)}-${pick(4)}`;
}

function maskKey(raw: string): string {
  const s = raw.trim();
  if (s.length <= 6) return '••••••';
  return `${s.slice(0, 4)}-••••-${s.slice(-4)}`;
}

async function getConfigMap(): Promise<Record<string, unknown>> {
  const { data, error } = await service.from('oss_portal_config').select('key,value');
  if (error) throw error;
  const out: Record<string, unknown> = {};
  for (const row of data || []) out[row.key] = row.value;
  return out;
}

async function writeAudit(actor: string | null, action: string, target: string | null, detail: Record<string, unknown> = {}) {
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

async function authUsers() {
  const out: any[] = [];
  for (let page = 1; ; page++) {
    const { data, error } = await service.auth.admin.listUsers({ page, perPage: 1000 });
    if (error) throw error;
    out.push(...data.users);
    if (data.users.length < 1000) return out;
  }
}

async function validateLiveGate(token: string, cfg: Record<string, unknown>): Promise<{ valid: boolean; required: boolean; key_label?: string }> {
  const required = cfg.require_access_key !== false;
  if (!required) return { valid: true, required: false };
  const secret = String(cfg.gate_secret || '');
  if (!secret || !token) return { valid: false, required: true };
  const payload = await verifyGateToken(token, secret);
  if (!payload) return { valid: false, required: true };

  const { data: keyRow } = await service
    .from('oss_access_keys')
    .select('id,label,enabled,expires_at')
    .eq('id', payload.key_id)
    .maybeSingle();

  if (!keyRow || !keyRow.enabled) return { valid: false, required: true };
  if (keyRow.expires_at && new Date(keyRow.expires_at).getTime() < Date.now()) {
    return { valid: false, required: true };
  }
  return { valid: true, required: true, key_label: keyRow.label };
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

    // ── 1. Public Gate Actions (Zero business data exposed) ──
    if (action === 'gate_status') {
      const cfg = await getConfigMap();
      const gate = await validateLiveGate(gateToken, cfg);
      return reply({
        require_access_key: gate.required,
        gate_valid: gate.valid,
        key_label: gate.key_label || null,
      });
    }

    if (action === 'verify_key') {
      const cfg = await getConfigMap();
      const required = cfg.require_access_key !== false;
      if (!required) {
        return reply({ ok: true, required: false });
      }
      const rawKey = String(body.access_key || '').trim();
      if (!rawKey || rawKey.length < 4) {
        await new Promise((r) => setTimeout(r, 300));
        return reply({ error: '請輸入有效的系統存取金鑰（Access Key）。' }, 400);
      }

      const { data: keys, error: keyErr } = await service
        .from('oss_access_keys')
        .select('id,label,key_salt,key_hash,enabled,expires_at,usage_count')
        .eq('enabled', true);
      if (keyErr) throw keyErr;

      const now = Date.now();
      let matched: any = null;
      for (const k of keys || []) {
        if (k.expires_at && new Date(k.expires_at).getTime() < now) continue;
        const candidateHash = await sha256Hex(`${k.key_salt}:${rawKey}`);
        if (timingSafeEqual(candidateHash, k.key_hash)) {
          matched = k;
          break;
        }
      }

      if (!matched) {
        await new Promise((r) => setTimeout(r, 400));
        await writeAudit(null, 'gate_failed', maskKey(rawKey), { reason: 'invalid_key' });
        return reply({ error: '存取金鑰無效、已過期或已撤銷，請聯繫進金生能源系統管理員。' }, 401);
      }

      const secret = String(cfg.gate_secret || '');
      const exp = now + GATE_TTL_MS;
      const token = await createGateToken({ key_id: matched.id, label: matched.label, exp }, secret);

      await service
        .from('oss_access_keys')
        .update({ usage_count: (matched.usage_count || 0) + 1, last_used_at: new Date().toISOString() })
        .eq('id', matched.id);

      await writeAudit(null, 'gate_verified', matched.label, { key_id: matched.id });
      return reply({
        ok: true,
        required: true,
        gate_token: token,
        key_label: matched.label,
        expires_at: new Date(exp).toISOString(),
      });
    }

    if (action === 'validate_gate') {
      const cfg = await getConfigMap();
      const gate = await validateLiveGate(gateToken, cfg);
      return reply(gate);
    }

    // ── 2. Authenticated User Check ──
    const authToken = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
    const { data: { user }, error: authError } = await service.auth.getUser(authToken);
    if (authError || !user?.email) {
      return reply({ error: '請先完成授權帳號登入。' }, 401);
    }
    const me = user.email.toLowerCase();
    const { data: caller, error: callerErr } = await service
      .from('oss_admins')
      .select('email,role,enabled,can_export,can_view_commercial,display_name,created_at')
      .ilike('email', me)
      .maybeSingle();

    if (callerErr) throw callerErr;
    if (!caller || !caller.enabled) {
      return reply({ error: '此帳號尚未授權或已停用，請聯繫進金生能源系統擁有者。' }, 403);
    }

    const isOwner = caller.role === 'owner';
    const isManager = caller.role === 'owner' || caller.role === 'admin';

    // Current user profile & protected config
    if (action === 'me') {
      const cfg = await getConfigMap();
      const gate = await validateLiveGate(gateToken, cfg);
      return reply({
        me: {
          email: caller.email,
          role: caller.role,
          enabled: caller.enabled,
          can_export: caller.role === 'viewer' ? false : !!caller.can_export,
          can_view_commercial: caller.role === 'viewer' ? false : !!caller.can_view_commercial,
          display_name: caller.display_name || '',
        },
        gate_valid: gate.valid,
        require_access_key: gate.required,
        key_label: gate.key_label || null,
        config: {
          portal_notice: String(cfg.portal_notice || ''),
          drive_folder_url:
            caller.role !== 'viewer' && caller.can_export ? String(cfg.drive_folder_url || '') : null,
        },
      });
    }

    if (action === 'change_own_password') {
      const newPassword = typeof body.new_password === 'string' ? body.new_password : '';
      if (newPassword.length < 8) {
        return reply({ error: '新密碼長度至少需要 8 個字元。' }, 400);
      }
      const { error } = await service.auth.admin.updateUserById(user.id, { password: newPassword });
      if (error) return reply({ error: '密碼變更失敗：' + error.message }, 400);
      await writeAudit(me, 'self_password_changed', me, {});
      return reply({ success: true });
    }

    if (action === 'log_export') {
      await writeAudit(me, 'data_exported', String(body.target || 'csv'), {
        rows: Number(body.rows || 0),
      });
      return reply({ success: true });
    }

    // ── 3. Manager Actions (Owner & Admin) ──
    if (!isManager) {
      return reply({ error: '此功能僅限系統擁有者或管理員使用。' }, 403);
    }

    if (action === 'list') {
      const [{ data: rows, error }, users, { data: wx }] = await Promise.all([
        service
          .from('oss_admins')
          .select('email,role,enabled,can_export,can_view_commercial,display_name,created_at,updated_at')
          .order('created_at'),
        authUsers(),
        service.from('wx_portfolio_members').select('email,role,enabled'),
      ]);
      if (error) throw error;
      const byEmail = new Map(users.map((u) => [String(u.email || '').toLowerCase(), u]));
      const wxBy = new Map((wx || []).map((w: any) => [String(w.email || '').toLowerCase(), w]));
      return reply({
        me,
        my_role: caller.role,
        members: (rows || []).map((r: any) => {
          const em = String(r.email || '').toLowerCase();
          const u = byEmail.get(em);
          const w = wxBy.get(em);
          return {
            ...r,
            account: !!u,
            confirmed: !!u?.email_confirmed_at,
            last_sign_in_at: u?.last_sign_in_at || null,
            wx_role: w && w.enabled ? w.role : null,
          };
        }),
      });
    }

    if (action === 'list_audit_logs') {
      const { data: logs, error } = await service
        .from('oss_audit_logs')
        .select('id,actor_email,action,target,detail,created_at')
        .order('created_at', { ascending: false })
        .limit(80);
      if (error) throw error;
      return reply({ logs: logs || [] });
    }

    if (action === 'add') {
      const email = String(body.email || '').trim().toLowerCase();
      if (!EMAIL_RE.test(email)) return reply({ error: '請輸入有效的電子郵件。' }, 400);
      const password = typeof body.password === 'string' ? body.password : '';
      if (password && password.length < 8) return reply({ error: '密碼至少需要 8 個字元。' }, 400);

      let role = String(body.role || 'member').toLowerCase();
      if (!VALID_ROLES.has(role)) role = 'member';
      if (!isOwner && (role === 'owner' || role === 'admin')) {
        return reply({ error: '管理員僅可新增一般成員或唯讀訪客。' }, 403);
      }

      const displayName = String(body.display_name || '').trim().slice(0, 60);
      const canExport = role === 'viewer' ? false : body.can_export !== false;
      const canViewCommercial = role === 'viewer' ? false : body.can_view_commercial !== false;

      const existing = (await authUsers()).find((u) => String(u.email || '').toLowerCase() === email);
      let created = false;
      if (!existing) {
        if (!password) return reply({ error: '此信箱尚未有登入帳號，請設定初始密碼（至少 8 碼）。' }, 400);
        const { error } = await service.auth.admin.createUser({ email, password, email_confirm: true });
        if (error) return reply({ error: '建立登入帳號失敗：' + error.message }, 400);
        created = true;
      }

      const { error } = await service.from('oss_admins').upsert(
        {
          email,
          role,
          enabled: true,
          can_export: canExport,
          can_view_commercial: canViewCommercial,
          display_name: displayName,
          updated_at: new Date().toISOString(),
        },
        { onConflict: 'email' },
      );
      if (error) throw error;

      if (body.wx_viewer) {
        const { data: w } = await service.from('wx_portfolio_members').select('role').eq('email', email).maybeSingle();
        if (!w) {
          const { error: e } = await service
            .from('wx_portfolio_members')
            .insert({ email, role: 'viewer', enabled: true });
          if (e) throw e;
        } else {
          const { error: e } = await service
            .from('wx_portfolio_members')
            .update({ enabled: true })
            .eq('email', email);
          if (e) throw e;
        }
      }

      await writeAudit(me, 'member_added', email, { role, created, canExport, canViewCommercial });
      return reply({ success: true, created, password_ignored: !!existing && !!password });
    }

    if (action === 'update_member') {
      const email = String(body.email || '').trim().toLowerCase();
      if (!EMAIL_RE.test(email)) return reply({ error: '無效的電子郵件。' }, 400);
      const { data: target } = await service
        .from('oss_admins')
        .select('email,role,enabled,can_export,can_view_commercial,display_name')
        .ilike('email', email)
        .maybeSingle();
      if (!target) return reply({ error: '此信箱不在授權名單內。' }, 404);

      if (target.role === 'owner' && !isOwner) {
        return reply({ error: '管理員無法修改系統擁有者的權限。' }, 403);
      }
      if (email === me && body.enabled === false) {
        return reply({ error: '無法停用自己目前的登入帳號。' }, 400);
      }
      if (email === me && body.role && body.role !== target.role) {
        return reply({ error: '無法變更自己目前的角色層級。' }, 400);
      }

      const nextRole = body.role && VALID_ROLES.has(body.role) ? body.role : target.role;
      if (!isOwner && (nextRole === 'owner' || nextRole === 'admin')) {
        return reply({ error: '僅系統擁有者可指派擁有者或管理員角色。' }, 403);
      }

      const patch = {
        role: nextRole,
        enabled: typeof body.enabled === 'boolean' ? body.enabled : target.enabled,
        can_export:
          nextRole === 'viewer'
            ? false
            : typeof body.can_export === 'boolean'
            ? body.can_export
            : target.can_export,
        can_view_commercial:
          nextRole === 'viewer'
            ? false
            : typeof body.can_view_commercial === 'boolean'
            ? body.can_view_commercial
            : target.can_view_commercial,
        display_name:
          typeof body.display_name === 'string'
            ? body.display_name.trim().slice(0, 60)
            : target.display_name,
        updated_at: new Date().toISOString(),
      };

      const { error } = await service.from('oss_admins').update(patch).eq('email', target.email);
      if (error) throw error;
      await writeAudit(me, 'member_updated', target.email, patch);
      return reply({ success: true });
    }

    if (action === 'password') {
      const email = String(body.email || '').trim().toLowerCase();
      if (!EMAIL_RE.test(email)) return reply({ error: '無效的電子郵件。' }, 400);
      const password = typeof body.password === 'string' ? body.password : '';
      if (password.length < 8) return reply({ error: '新密碼至少需要 8 個字元。' }, 400);

      const { data: target } = await service.from('oss_admins').select('role').ilike('email', email).maybeSingle();
      if (!target) return reply({ error: '此信箱不在授權名單內。' }, 404);
      if (target.role === 'owner' && !isOwner) {
        return reply({ error: '管理員無法重設系統擁有者密碼。' }, 403);
      }

      const existing = (await authUsers()).find((u) => String(u.email || '').toLowerCase() === email);
      if (!existing) return reply({ error: '此信箱尚未建立登入帳號。' }, 404);
      const { error } = await service.auth.admin.updateUserById(existing.id, { password });
      if (error) return reply({ error: '密碼更新失敗：' + error.message }, 400);
      await writeAudit(me, 'password_reset', email, {});
      return reply({ success: true });
    }

    if (action === 'remove') {
      const email = String(body.email || '').trim().toLowerCase();
      if (!EMAIL_RE.test(email)) return reply({ error: '無效的電子郵件。' }, 400);
      const { data: target } = await service.from('oss_admins').select('email,role').ilike('email', email).maybeSingle();
      if (!target) return reply({ error: '此信箱不在授權名單內。' }, 404);
      if (email === me || target.role === 'owner') return reply({ error: '無法移除系統擁有者。' }, 400);
      if (!isOwner && target.role === 'admin') return reply({ error: '僅擁有者可移除管理員。' }, 403);

      const { error } = await service.from('oss_admins').delete().eq('email', target.email);
      if (error) throw error;
      if (body.wx_also) {
        const { error: e } = await service
          .from('wx_portfolio_members')
          .update({ enabled: false })
          .eq('email', target.email)
          .neq('role', 'admin');
        if (e) throw e;
      }
      await writeAudit(me, 'member_removed', target.email, { wx_also: !!body.wx_also });
      return reply({ success: true });
    }

    // ── 4. Owner-Only Actions (Access Keys & Protected System Config) ──
    if (!isOwner) {
      return reply({ error: '存取金鑰與系統設定僅限系統擁有者（Owner）操作。' }, 403);
    }

    if (action === 'list_keys') {
      const [{ data: keys, error }, cfg] = await Promise.all([
        service
          .from('oss_access_keys')
          .select('id,label,key_hint,scope,enabled,expires_at,usage_count,last_used_at,created_by,created_at')
          .order('created_at', { ascending: false }),
        getConfigMap(),
      ]);
      if (error) throw error;
      return reply({
        keys: keys || [],
        config: {
          require_access_key: cfg.require_access_key !== false,
          drive_folder_url: String(cfg.drive_folder_url || ''),
          portal_notice: String(cfg.portal_notice || ''),
        },
      });
    }

    if (action === 'create_key') {
      const label = String(body.label || '').trim().slice(0, 80);
      if (!label) return reply({ error: '請輸入金鑰用途名稱（例如：2026 Q4 團隊通行碼）。' }, 400);
      const customKey = typeof body.custom_key === 'string' ? body.custom_key.trim() : '';
      if (customKey && customKey.length < 8) {
        return reply({ error: '自訂存取金鑰至少需要 8 個字元。' }, 400);
      }
      const rawKey = customKey || generateAccessKey();
      const salt = randomHex(16);
      const hash = await sha256Hex(`${salt}:${rawKey}`);
      const expiresAt = body.expires_at ? new Date(String(body.expires_at)).toISOString() : null;

      const { data: inserted, error } = await service
        .from('oss_access_keys')
        .insert({
          label,
          key_hint: maskKey(rawKey),
          key_salt: salt,
          key_hash: hash,
          scope: 'portal',
          enabled: true,
          expires_at: expiresAt,
          created_by: me,
        })
        .select('id,label,key_hint,scope,enabled,expires_at,usage_count,last_used_at,created_by,created_at')
        .single();
      if (error) throw error;

      await writeAudit(me, 'access_key_created', label, { key_id: inserted.id, expires_at: expiresAt });
      return reply({ success: true, key: inserted, plain_key: rawKey });
    }

    if (action === 'toggle_key') {
      const id = String(body.id || '');
      const enabled = Boolean(body.enabled);
      if (!id) return reply({ error: '缺少金鑰識別碼。' }, 400);

      if (!enabled) {
        const cfg = await getConfigMap();
        if (cfg.require_access_key !== false) {
          const { data: activeKeys } = await service
            .from('oss_access_keys')
            .select('id,expires_at')
            .eq('enabled', true);
          const others = (activeKeys || []).filter(
            (k: any) => k.id !== id && (!k.expires_at || new Date(k.expires_at).getTime() > Date.now()),
          );
          if (others.length === 0) {
            return reply(
              { error: '安全防鎖機制：門禁開啟中，無法停用最後一組有效金鑰。請先新增替代金鑰或關閉門禁。' },
              400,
            );
          }
        }
      }

      const { data: updated, error } = await service
        .from('oss_access_keys')
        .update({ enabled })
        .eq('id', id)
        .select('id,label,enabled')
        .maybeSingle();
      if (error) throw error;
      if (!updated) return reply({ error: '找不到指定的存取金鑰。' }, 404);
      await writeAudit(me, enabled ? 'access_key_enabled' : 'access_key_disabled', updated.label, { key_id: id });
      return reply({ success: true });
    }

    if (action === 'delete_key') {
      const id = String(body.id || '');
      if (!id) return reply({ error: '缺少金鑰識別碼。' }, 400);
      const { data: target } = await service
        .from('oss_access_keys')
        .select('id,label,enabled')
        .eq('id', id)
        .maybeSingle();
      if (!target) return reply({ error: '找不到指定的存取金鑰。' }, 404);
      if (target.enabled) {
        return reply({ error: '請先停用此金鑰，再執行刪除。' }, 400);
      }
      const { error } = await service.from('oss_access_keys').delete().eq('id', id);
      if (error) throw error;
      await writeAudit(me, 'access_key_deleted', target.label, { key_id: id });
      return reply({ success: true });
    }

    if (action === 'update_config') {
      const updates: Array<{ key: string; value: unknown }> = [];
      if (typeof body.require_access_key === 'boolean') {
        if (body.require_access_key) {
          const { data: activeKeys } = await service
            .from('oss_access_keys')
            .select('id,expires_at')
            .eq('enabled', true);
          const validCount = (activeKeys || []).filter(
            (k: any) => !k.expires_at || new Date(k.expires_at).getTime() > Date.now(),
          ).length;
          if (validCount === 0) {
            return reply({ error: '啟用門禁前，請至少建立一組有效中的存取金鑰。' }, 400);
          }
        }
        updates.push({ key: 'require_access_key', value: body.require_access_key });
      }
      if (typeof body.drive_folder_url === 'string') {
        updates.push({ key: 'drive_folder_url', value: body.drive_folder_url.trim() });
      }
      if (typeof body.portal_notice === 'string') {
        updates.push({ key: 'portal_notice', value: body.portal_notice.trim().slice(0, 300) });
      }
      if (body.rotate_gate_secret === true) {
        updates.push({ key: 'gate_secret', value: randomHex(32) });
      }

      for (const u of updates) {
        const { error } = await service.from('oss_portal_config').upsert(
          { key: u.key, value: u.value, updated_by: me, updated_at: new Date().toISOString() },
          { onConflict: 'key' },
        );
        if (error) throw error;
      }

      await writeAudit(me, 'config_updated', 'portal_config', {
        keys: updates.map((u) => u.key),
      });
      return reply({ success: true });
    }

    return reply({ error: '不支援的操作指令。' }, 400);
  } catch (error) {
    console.error('OSS Admin Error:', error);
    return reply({ error: '系統操作失敗，請稍後再試。' }, 500);
  }
});
