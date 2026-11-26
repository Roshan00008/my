// User-account (MTProto) login flow:
//   POST /api/accounts/user/start   { phone, label? }  -> sends login code, returns phone_code_hash
//   POST /api/accounts/user/submit  { account_id, phone, phone_code_hash, code, password? } -> signs in
//   POST /api/accounts/user/session { session_string, label? } -> imports a Telethon StringSession directly
import { MtprotoClient } from "../../mtproto/api";
import { TelegramApiError } from "../../telegram/errors";
import { hex } from "../../mtproto/bytes";
import { sha1 } from "../../mtproto/hash";
import {
  findUserAccountByPhone,
  getBotWithSecrets,
  insertUserAccount,
  updateMtprotoSession,
  updateUserAccountIdentity,
} from "../../db/queries";
import type {
  BotSummary,
  UserLoginStartRequest,
  UserLoginStartResponse,
  UserLoginSubmitRequest,
  UserLoginSubmitResponse,
  UserSessionImportRequest,
} from "../../shared/rpcTypes";

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

function apiCreds(env: Env): { apiId: number; apiHash: string } {
  if (!env.TG_API_ID || !env.TG_API_HASH) {
    throw new Error("TG_API_ID / TG_API_HASH secrets are not set on this Worker (wrangler secret put TG_API_ID)");
  }
  return { apiId: Number(env.TG_API_ID), apiHash: env.TG_API_HASH };
}

function randomSecret(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function handleUserLoginStart(request: Request, env: Env): Promise<Response> {
  try {
    const body = (await request.json()) as UserLoginStartRequest;
    const phone = (body.phone ?? "").trim();
    if (!/^\+?[0-9]{8,15}$/.test(phone)) {
      return json({ ok: false, errorCode: 400, description: "invalid phone number (use international format, e.g. +15551234567)", reason: "invalid_request" }, 400);
    }
    apiCreds(env);

    const existing = await findUserAccountByPhone(env.DB, phone);
    if (existing) {
      return json({ ok: false, errorCode: 409, description: "a user account with this phone already exists", reason: "invalid_request" }, 409);
    }

    // Create the row up-front so the MTProto auth key created by the
    // handshake can be persisted immediately and reused by the submit call
    // (possibly on a different isolate).
    const id = crypto.randomUUID();
    const label = (body.label ?? "").trim() || phone;
    await insertUserAccount(env.DB, {
      id,
      user_id: 0,
      username: "",
      label,
      phone,
      webhook_secret: randomSecret(),
      mtproto_session: null,
    });

    const { apiId, apiHash } = apiCreds(env);
    const client = new MtprotoClient({
      apiId,
      apiHash,
      sessionJson: null,
      onSessionPersist: (s) => updateMtprotoSession(env.DB, id, s),
    });
    try {
      const sent = await client.sendCode(phone);
      const res: UserLoginStartResponse = { account_id: id, phone_code_hash: sent.phoneCodeHash, phone_code_type: sent.type };
      return json({ ok: true, data: res });
    } catch (e) {
      const desc = e instanceof Error ? e.message : String(e);
      return json({ ok: false, errorCode: 400, description: `could not send login code: ${desc}`, reason: "invalid_request" }, 400);
    } finally {
      client.close();
    }
  } catch (e) {
    const desc = e instanceof Error ? e.message : String(e);
    return json({ ok: false, errorCode: 500, description: desc, reason: "unknown" }, 500);
  }
}

export async function handleUserLoginSubmit(request: Request, env: Env): Promise<Response> {
  try {
    const body = (await request.json()) as UserLoginSubmitRequest;
    const row = await getBotWithSecrets(env.DB, body.account_id);
    if (!row || row.account_type !== "user") {
      return json({ ok: false, errorCode: 404, description: "user account not found", reason: "invalid_request" }, 404);
    }
    const { apiId, apiHash } = apiCreds(env);
    const client = new MtprotoClient({
      apiId,
      apiHash,
      sessionJson: row.mtproto_session,
      onSessionPersist: (s) => updateMtprotoSession(env.DB, row.id, s),
    });

    const fail = (description: string, needsPassword = false, status = 400): Response =>
      json({ ok: false, errorCode: status, description, reason: "invalid_request", needs_password: needsPassword } satisfies UserLoginSubmitResponse, status);

    try {
      let auth: Record<string, unknown>;
      try {
        auth = await client.signIn(body.phone, body.phone_code_hash, body.code);
      } catch (e) {
        if (e instanceof TelegramApiError && /SESSION_PASSWORD_NEEDED/i.test(e.message)) {
          if (!body.password) return fail("two-factor authentication is enabled on this account — provide password", true);
          try {
            auth = await client.checkPassword(body.password);
          } catch (e2) {
            const msg = e2 instanceof Error ? e2.message : String(e2);
            return fail(/PASSWORD_HASH_INVALID/i.test(msg) ? "wrong 2FA password" : `2FA check failed: ${msg}`);
          }
        } else {
          const msg = e instanceof Error ? e.message : String(e);
          return fail(/PHONE_CODE_INVALID/i.test(msg) ? "invalid login code" : /PHONE_CODE_EXPIRED/i.test(msg) ? "login code expired — start again" : `sign-in failed: ${msg}`);
        }
      }

      const user = auth.user as Record<string, unknown> | undefined;
      if (!user || user._name !== "user") {
        return fail("sign-in succeeded but returned an unexpected authorization object");
      }
      const userId = Number(user.id as bigint);
      const username = (user.username as string) ?? "";
      await updateUserAccountIdentity(env.DB, row.id, userId, username);

      const summary: BotSummary = {
        id: row.id,
        bot_id: userId,
        bot_username: username,
        label: row.label,
        account_type: "user",
        phone: row.phone,
        created_at: row.created_at,
      };
      const res: UserLoginSubmitResponse = { ok: true, data: summary };
      return json(res, 200);
    } finally {
      client.close();
    }
  } catch (e) {
    const desc = e instanceof Error ? e.message : String(e);
    return json({ ok: false, errorCode: 500, description: desc, reason: "unknown" }, 500);
  }
}

function b64UrlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Parses a Telethon StringSession: '1' + base64url( dc_id:1 | ip:4|16 | port:2 | auth_key:256 ).
 * Returns the DC id and the raw 256-byte auth key.
 */
export function parseSessionString(sessionString: string): { dcId: number; authKey: Uint8Array } {
  const s = sessionString.trim();
  if (!s.startsWith("1")) throw new Error("not a Telethon-style session string (must start with '1')");
  const raw = b64UrlDecode(s.slice(1));
  const ipLen = raw.length === 263 ? 4 : raw.length === 275 ? 16 : 0;
  if (!ipLen) throw new Error(`unexpected session payload length ${raw.length} (expected 263 for IPv4 or 275 for IPv6)`);
  let dcId = raw[0];
  if (dcId > 127) dcId -= 256; // media-only DCs are encoded as negative bytes
  const authKey = raw.subarray(raw.length - 256);
  if (authKey.every((b) => b === 0)) throw new Error("session string contains an empty auth key");
  return { dcId, authKey };
}

export async function handleUserSessionImport(request: Request, env: Env): Promise<Response> {
  try {
    const body = (await request.json()) as UserSessionImportRequest;
    let parsed: { dcId: number; authKey: Uint8Array };
    try {
      parsed = parseSessionString(body.session_string ?? "");
    } catch (e) {
      const desc = e instanceof Error ? e.message : String(e);
      return json({ ok: false, errorCode: 400, description: desc, reason: "invalid_request" }, 400);
    }
    const dcId = Math.abs(parsed.dcId);
    const authKeyId = (await sha1(parsed.authKey)).slice(-8);
    const store = {
      primaryDc: dcId,
      dcs: {
        [String(dcId)]: {
          dcId,
          authKey: hex(parsed.authKey),
          authKeyId: hex(authKeyId),
          serverSalt: "0000000000000000", // updated by the server on first RPC response
        },
      },
    };
    const id = crypto.randomUUID();
    const label = (body.label ?? "").trim() || `user@dc${dcId}`;
    await insertUserAccount(env.DB, {
      id,
      user_id: 0,
      username: "",
      label,
      phone: "",
      webhook_secret: randomSecret(),
      mtproto_session: JSON.stringify(store),
    });

    // Best-effort identity resolution over MTProto; the account is usable even
    // if this fails (transport issues) — identity fills in on first successful sync.
    let userId = 0;
    let username = "";
    try {
      const { apiId, apiHash } = apiCreds(env);
      const client = new MtprotoClient({
        apiId,
        apiHash,
        sessionJson: JSON.stringify(store),
        onSessionPersist: (s) => updateMtprotoSession(env.DB, id, s),
      });
      try {
        const me = await client.getMe();
        userId = me.id;
        username = me.username ?? "";
        await updateUserAccountIdentity(env.DB, id, userId, username);
      } finally {
        client.close();
      }
    } catch {
      // ignore — session is stored, identity resolves later
    }

    const row = await getBotWithSecrets(env.DB, id);
    const summary: BotSummary = {
      id,
      bot_id: userId,
      bot_username: username,
      label,
      account_type: "user",
      phone: null,
      created_at: row?.created_at ?? 0,
    };
    return json({ ok: true, data: summary }, 200);
  } catch (e) {
    const desc = e instanceof Error ? e.message : String(e);
    return json({ ok: false, errorCode: 500, description: desc, reason: "unknown" }, 500);
  }
}
