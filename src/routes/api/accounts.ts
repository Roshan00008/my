// User-account (MTProto) login flow:
//   POST /api/accounts/user/start   { phone, label? }  -> sends login code, returns phone_code_hash
//   POST /api/accounts/user/submit  { account_id, phone, phone_code_hash, code, password? } -> signs in
import { MtprotoClient } from "../../mtproto/api";
import { TelegramApiError } from "../../telegram/errors";
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
