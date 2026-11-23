import { createClient } from 'npm:@supabase/supabase-js@2.57.4';

// =============================================================================
// ACMEPOINT Energy Services (6692) — OSS Executive Portal Backend
// Edge Function: oss-account-admin (v3 — Unified Access Key Unlock + 60-Day Rotation)
// Features:
//   1. Single-Step Access Key Unlock (salted SHA-256 verification + RLS session minting)
//   2. 60-Day Key Rotation Tracking & Reminder Metadata
//   3. Self-Service Access Key Change (verifies current key, resets 60-day cycle)
//   4. Protected Portal Config (Drive URL & Notice returned only after key unlock)
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

async function writeAudit(action: string, target: string | null, detail: Record<string, unknown> = {}) {
  try {
    await service.from('oss_audit_logs').insert({
      actor_email: 'access_key_gate',
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
  const dueAtMs = rotatedAtMs + cycleMs;
  const daysElapsed = Math.max(0, Math.floor((now - rotatedAtMs) / 86400000));
  const daysRemaining = Math.ceil((dueAtMs - now) / 86400000);
  const isOverdue = daysRemaining <= 0;
  const shouldRemind = daysRemaining <= ROTATION_WARN_DAYS;
  return {
    key_id: keyRow.id,
    label: keyRow.label || '系統存取金鑰',
    key_hint: keyRow.key_hint || '••••',
    rotated_at: new Date(rotatedAtMs).toISOString(),
    due_at: new Date(dueAtMs).toISOString(),
    cycle_days: ROTATION_CYCLE_DAYS,
    days_elapsed: daysElapsed,
    days_remaining: daysRemaining,
    is_overdue: isOverdue,
    should_remind: shouldRemind,
  };
}

// Mint a real Supabase Auth session bound to an internal RLS-authorized account
// so the frontend only needs the Access Key while all database tables stay RLS-protected.
async function mintPortalRlsSession() {
  const derivedPassword = 'AcmeKey#' + (await hmacSign(INTERNAL_KEY_USER_EMAIL, SERVICE_KEY)).slice(0, 28);

  // Ensure row in oss_admins is active
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

  // Try signing in directly first (fast path)
  const tempClient = createClient(SUPABASE_URL, SERVICE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  let signInRes = await tempClient.auth.signInWithPassword({
    email: INTERNAL_KEY_USER_EMAIL,
    password: derivedPassword,
  });

  if (signInRes.error || !signInRes.data?.session) {
    // Create or update internal auth user
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
    .select('id,label,key_hint,key_salt,key_hash,enabled,expires_at,usage_count,created_at')
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

    // ── 1. Check Existing Gate Token & Return Session + 60-Day Rotation Info ──
    if (action === 'gate_status' || action === 'validate_gate') {
      const cfg = await getConfigMap();
      const secret = String(cfg.gate_secret || '');
      const payload = secret && gateToken ? await verifyGateToken(gateToken, secret) : null;
      if (!payload) {
        return reply({ require_access_key: true, gate_valid: false, valid: false });
      }
      const { data: keyRow } = await service
        .from('oss_access_keys')
        .select('id,label,key_hint,enabled,expires_at,created_at')
        .eq('id', payload.key_id)
        .maybeSingle();

      if (!keyRow || !keyRow.enabled) {
        return reply({ require_access_key: true, gate_valid: false, valid: false });
      }

      const rotation = buildRotationInfo(keyRow);
      const session = await mintPortalRlsSession();
      return reply({
        require_access_key: true,
        gate_valid: true,
        valid: true,
        key_label: keyRow.label,
        rotation,
        session,
        config: {
          portal_notice: String(cfg.portal_notice || ''),
          drive_folder_url: String(cfg.drive_folder_url || ''),
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
        await writeAudit('gate_failed', maskKey(rawKey), { reason: 'invalid_key' });
        return reply({ error: '存取金鑰不正確或已失效，請重新確認。' }, 401);
      }

      const cfg = await getConfigMap();
      const secret = String(cfg.gate_secret || '');
      const exp = Date.now() + GATE_TTL_MS;
      const token = await createGateToken({ key_id: matched.id, label: matched.label, exp }, secret);

      await service
        .from('oss_access_keys')
        .update({
          usage_count: (matched.usage_count || 0) + 1,
          last_used_at: new Date().toISOString(),
        })
        .eq('id', matched.id);

      const rotation = buildRotationInfo(matched);
      const session = await mintPortalRlsSession();
      await writeAudit('gate_verified', matched.label, { key_id: matched.id });

      return reply({
        ok: true,
        required: true,
        gate_token: token,
        key_label: matched.label,
        expires_at: new Date(exp).toISOString(),
        rotation,
        session,
        config: {
          portal_notice: String(cfg.portal_notice || ''),
          drive_folder_url: String(cfg.drive_folder_url || ''),
        },
      });
    }

    // ── 3. Change / Rotate Access Key (Resets 60-Day Rotation Timer) ──
    if (action === 'rotate_key') {
      const currentKey = String(body.current_key || '').trim();
      const newKey = String(body.new_key || '').trim();
      const label = String(body.label || '進能服維運決策平台存取金鑰').trim().slice(0, 80);

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
      if (!matched) {
        await new Promise((r) => setTimeout(r, 400));
        await writeAudit('key_rotate_failed', maskKey(currentKey), { reason: 'wrong_current_key' });
        return reply({ error: '目前存取金鑰驗證不正確，無法變更金鑰。' }, 401);
      }

      const nowIso = new Date().toISOString();
      const dueIso = new Date(Date.now() + ROTATION_CYCLE_DAYS * 86400000).toISOString();
      const newSalt = randomHex(16);
      const newHash = await sha256Hex(`${newSalt}:${newKey}`);
      const newHint = maskKey(newKey);

      // Disable all previous active keys and insert the freshly rotated key
      await service.from('oss_access_keys').update({ enabled: false }).eq('enabled', true);

      const { data: inserted, error: insErr } = await service
        .from('oss_access_keys')
        .insert({
          label,
          key_hint: newHint,
          key_salt: newSalt,
          key_hash: newHash,
          scope: 'portal',
          enabled: true,
          created_at: nowIso,
          expires_at: dueIso,
          usage_count: 1,
          last_used_at: nowIso,
          created_by: 'key_rotation',
        })
        .select('id,label,key_hint,enabled,expires_at,created_at')
        .single();
      if (insErr) throw insErr;

      // Rotate gate_secret so all devices using the old key must re-unlock with the new key
      const newSecret = randomHex(32);
      await service.from('oss_portal_config').upsert(
        { key: 'gate_secret', value: newSecret, updated_by: 'key_rotation', updated_at: nowIso },
        { onConflict: 'key' },
      );

      const exp = Date.now() + GATE_TTL_MS;
      const newGateToken = await createGateToken({ key_id: inserted.id, label: inserted.label, exp }, newSecret);
      const rotation = buildRotationInfo(inserted);

      await writeAudit('access_key_rotated', inserted.label, {
        old_key_id: matched.id,
        new_key_id: inserted.id,
        next_due_at: dueIso,
      });

      return reply({
        ok: true,
        gate_token: newGateToken,
        rotation,
      });
    }

    if (action === 'log_export') {
      await writeAudit('data_exported', String(body.target || 'csv'), {
        rows: Number(body.rows || 0),
      });
      return reply({ success: true });
    }

    return reply({ error: '不支援的操作指令。' }, 400);
  } catch (error) {
    console.error('OSS Gate Error:', error);
    return reply({ error: '系統驗證服務異常，請稍後再試。' }, 500);
  }
});
