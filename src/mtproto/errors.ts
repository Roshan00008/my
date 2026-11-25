import { TelegramApiError } from "../telegram/errors";

/** MTProto RPC error, surfaced as a TelegramApiError so all existing
 * rate-limit / unauthorized / permissions handling in tick.ts and the API
 * routes works unchanged for user accounts. */
export class MtprotoRpcError extends Error {
  constructor(
    public code: number,
    message: string,
  ) {
    super(message);
    this.name = "MtprotoRpcError";
  }

  toTelegramApiError(): TelegramApiError {
    const msg = this.message;
    let retryAfter: number | undefined;
    let reason: TelegramApiError["reason"];
    const lower = msg.toLowerCase();

    const flood = /FLOOD_WAIT_(\d+)/i.exec(msg) || /SLOWMODE_WAIT_(\d+)/i.exec(msg) || /FLOOD_PREMIUM_WAIT_(\d+)/i.exec(msg);
    if (flood) {
      retryAfter = parseInt(flood[1], 10);
      reason = "rate_limited";
    } else if (lower.includes("peer_flood") || lower.includes("msg flood")) {
      reason = "rate_limited";
    } else if (
      this.code === 401 ||
      lower.includes("auth_key_unregistered") ||
      lower.includes("auth_key_invalid") ||
      lower.includes("session_revoked") ||
      lower.includes("user_deactivated") ||
      lower.includes("auth_key_duplicated")
    ) {
      reason = "unauthorized";
    } else if (
      lower.includes("chat_admin_required") ||
      lower.includes("not enough rights") ||
      lower.includes("right_forbidden") ||
      lower.includes("forwards_restricted") ||
      lower.includes("user_not_participant") ||
      lower.includes("channel_private") ||
      lower.includes("chat_write_forbidden") ||
      lower.includes("user_banned_in_channel") ||
      lower.includes("chat_send_media_forbidden") ||
      lower.includes("chat_send_plain_forbidden")
    ) {
      reason = "insufficient_permissions";
    } else if (lower.includes("bot was kicked") || lower.includes("not a member") || lower.includes("peer_id_invalid") || lower.includes("channel_invalid") || lower.includes("chat_invalid")) {
      reason = "bot_not_in_chat";
    } else if (this.code === 400) {
      reason = "invalid_request";
    } else {
      reason = "unknown";
    }

    return new TelegramApiError({
      ok: false,
      error_code: this.code,
      description: msg,
      parameters: retryAfter !== undefined ? { retry_after: retryAfter } : undefined,
    }) as TelegramApiError & { reason: typeof reason };
  }
}

/** Classify and re-tag the reason (TelegramApiError.classify is Bot API oriented). */
export function rpcErrorToApiError(code: number, message: string): TelegramApiError {
  const e = new MtprotoRpcError(code, message).toTelegramApiError();
  const lower = message.toLowerCase();
  const flood = /FLOOD_WAIT_(\d+)/i.exec(message) || /SLOWMODE_WAIT_(\d+)/i.exec(message) || /FLOOD_PREMIUM_WAIT_(\d+)/i.exec(message);
  if (flood) {
    e.reason = "rate_limited";
    e.retryAfter = parseInt(flood[1], 10);
  } else if (lower.includes("peer_flood")) {
    e.reason = "rate_limited";
  } else if (
    code === 401 ||
    lower.includes("auth_key_unregistered") ||
    lower.includes("auth_key_invalid") ||
    lower.includes("session_revoked") ||
    lower.includes("user_deactivated")
  ) {
    e.reason = "unauthorized";
  } else if (
    lower.includes("chat_admin_required") ||
    lower.includes("not enough rights") ||
    lower.includes("right_forbidden") ||
    lower.includes("forwards_restricted") ||
    lower.includes("user_not_participant") ||
    lower.includes("channel_private") ||
    lower.includes("chat_write_forbidden") ||
    lower.includes("user_banned_in_channel") ||
    lower.includes("chat_send_media_forbidden") ||
    lower.includes("chat_send_plain_forbidden") ||
    lower.includes("messages_too_much") ||
    lower.includes("media_invalid")
  ) {
    e.reason = "insufficient_permissions";
  } else if (lower.includes("peer_id_invalid") || lower.includes("channel_invalid") || lower.includes("chat_invalid") || lower.includes("message_id_invalid") || lower.includes("msg_id_invalid")) {
    e.reason = "bot_not_in_chat";
  }
  return e;
}
