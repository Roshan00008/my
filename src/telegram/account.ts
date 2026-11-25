// Account abstraction: every row in `bots` is either a Bot-API bot or a
// Telegram user account (MTProto). Both are exposed through AccountClient so
// routes/jobs stay account-type agnostic; per-type limits live in pacing.ts.

import { TelegramClient, type CopyResult, type PromoteRights } from "./client";
import { TelegramApiError } from "./errors";
import type {
  TelegramChat,
  TelegramChatInviteLink,
  TelegramChatMember,
  TelegramMessage,
  TelegramUpdate,
  TelegramUser,
} from "./types";
import { MtprotoClient, type ResolvedPeer } from "../mtproto/api";
import { updateMtprotoSession, type BotRow } from "../db/queries";
import type { AccountType } from "../shared/rpcTypes";

export type { AccountType };

export interface WebhookInfo {
  url: string;
  has_custom_certificate?: boolean;
  pending_update_count: number;
  ip_address?: string;
  last_error_date?: number;
  last_error_message?: string;
  last_synchronization_error_date?: number;
  max_connections?: number;
  allowed_updates?: string[];
}

export interface AccountClient {
  readonly kind: AccountType;
  getMe(): Promise<TelegramUser>;
  /** Webhooks only exist for Bot API tokens; user accounts always return false. */
  supportsWebhooks(): boolean;
  setWebhook(url: string, secretToken: string): Promise<true>;
  deleteWebhook(dropPendingUpdates?: boolean): Promise<true>;
  getWebhookInfo(): Promise<WebhookInfo | null>;
  /** Bot API long-polling. User accounts never get here — tick.ts polls via pollNewMessages. */
  getUpdates(params: { offset?: number; limit?: number; allowed_updates?: string[] }): Promise<TelegramUpdate[]>;
  getChat(chatId: string | number): Promise<TelegramChat>;
  getChatMemberCount(chatId: string | number): Promise<number>;
  getChatMember(chatId: string | number, userId: number): Promise<TelegramChatMember>;
  getChatAdministrators(chatId: string | number): Promise<TelegramChatMember[]>;
  createChatInviteLink(chatId: string | number, name?: string): Promise<TelegramChatInviteLink>;
  revokeChatInviteLink(chatId: string | number, inviteLink: string): Promise<TelegramChatInviteLink>;
  promoteChatMember(chatId: string | number, userId: number, rights: PromoteRights): Promise<true>;
  banChatMember(chatId: string | number, userId: number): Promise<true>;
  unbanChatMember(chatId: string | number, userId: number): Promise<true>;
  sendMessage(chatId: string | number, text: string): Promise<TelegramMessage>;
  deleteMessage(chatId: string | number, messageId: number): Promise<true>;
  copyMessage(destChatId: string | number, sourceChatId: string | number, messageId: number): Promise<CopyResult>;
  copyMessages(destChatId: string | number, sourceChatId: string | number, messageIds: number[]): Promise<CopyResult[]>;
  /** User-account live polling: newest message id in a chat (no probe post). */
  getLatestMessageId?(chatId: string | number): Promise<number>;
  /** User-account live polling: messages with id > minId, ascending. */
  pollNewMessages?(chatId: string | number, minId: number, limit: number): Promise<TelegramMessage[]>;
  close?(): void;
}

function unsupported(desc: string): TelegramApiError {
  return new TelegramApiError({ ok: false, error_code: 400, description: desc });
}

export class BotAccountClient implements AccountClient {
  readonly kind = "bot" as const;
  constructor(private client: TelegramClient) {}
  getMe() { return this.client.getMe(); }
  supportsWebhooks() { return true; }
  setWebhook(url: string, secretToken: string) { return this.client.setWebhook(url, secretToken); }
  deleteWebhook(dropPendingUpdates = false) { return this.client.deleteWebhook(dropPendingUpdates); }
  getWebhookInfo() { return this.client.getWebhookInfo(); }
  getUpdates(params: { offset?: number; limit?: number; allowed_updates?: string[] }) { return this.client.getUpdates(params); }
  getChat(chatId: string | number) { return this.client.getChat(chatId); }
  getChatMemberCount(chatId: string | number) { return this.client.getChatMemberCount(chatId); }
  getChatMember(chatId: string | number, userId: number) { return this.client.getChatMember(chatId, userId); }
  getChatAdministrators(chatId: string | number) { return this.client.getChatAdministrators(chatId); }
  createChatInviteLink(chatId: string | number, name?: string) { return this.client.createChatInviteLink(chatId, name); }
  revokeChatInviteLink(chatId: string | number, inviteLink: string) { return this.client.revokeChatInviteLink(chatId, inviteLink); }
  promoteChatMember(chatId: string | number, userId: number, rights: PromoteRights) { return this.client.promoteChatMember(chatId, userId, rights); }
  banChatMember(chatId: string | number, userId: number) { return this.client.banChatMember(chatId, userId); }
  unbanChatMember(chatId: string | number, userId: number) { return this.client.unbanChatMember(chatId, userId); }
  sendMessage(chatId: string | number, text: string) { return this.client.sendMessage(chatId, text); }
  deleteMessage(chatId: string | number, messageId: number) { return this.client.deleteMessage(chatId, messageId); }
  copyMessage(destChatId: string | number, sourceChatId: string | number, messageId: number) {
    return this.client.copyMessage(destChatId, sourceChatId, messageId);
  }
  copyMessages(destChatId: string | number, sourceChatId: string | number, messageIds: number[]) {
    return this.client.copyMessages(destChatId, sourceChatId, messageIds);
  }
}

const ADMIN_RIGHT_BITS: Record<string, number> = {
  can_change_info: 0,
  can_post_messages: 1,
  can_edit_messages: 2,
  can_delete_messages: 3,
  can_restrict_members: 4,
  can_invite_users: 5,
  can_pin_messages: 7,
  can_promote_members: 9,
  can_manage_chat: 11,
  can_manage_video_chats: 14,
};

function adminRightsToMemberRights(rights: Record<string, unknown> | undefined): Partial<TelegramChatMember> {
  const flags = (rights?.flags as number) ?? 0;
  const out: Record<string, boolean> = {};
  for (const [name, bit] of Object.entries(ADMIN_RIGHT_BITS)) {
    if (((flags >>> bit) & 1) === 1) out[name] = true;
  }
  return out;
}

export class UserAccountClient implements AccountClient {
  readonly kind = "user" as const;
  private peers = new Map<string, ResolvedPeer>();

  constructor(private mt: MtprotoClient) {}

  private async peer(chatId: string | number): Promise<ResolvedPeer> {
    const key = String(chatId);
    const cached = this.peers.get(key);
    if (cached) return cached;
    const p = await this.mt.resolvePeer(key);
    this.peers.set(key, p);
    return p;
  }

  async getMe(): Promise<TelegramUser> {
    return this.mt.getMe();
  }

  supportsWebhooks() { return false; }
  setWebhook(): Promise<true> { throw unsupported("webhooks are only available for bot accounts"); }
  deleteWebhook(): Promise<true> { throw unsupported("webhooks are only available for bot accounts"); }
  async getWebhookInfo(): Promise<WebhookInfo | null> { return null; }
  getUpdates(): Promise<TelegramUpdate[]> { throw unsupported("user accounts poll via getHistory, not getUpdates"); }

  async getChat(chatId: string | number): Promise<TelegramChat> {
    const info = await this.mt.getChatInfo(await this.peer(chatId));
    return info.chat;
  }

  async getChatMemberCount(chatId: string | number): Promise<number> {
    const info = await this.mt.getChatInfo(await this.peer(chatId));
    return info.memberCount ?? 0;
  }

  async getChatMember(chatId: string | number, userId: number): Promise<TelegramChatMember> {
    const me = await this.getMe();
    if (userId !== me.id) throw unsupported("user accounts can only look up their own membership");
    const info = await this.mt.getChatInfo(await this.peer(chatId));
    return {
      ...adminRightsToMemberRights(info.selfAdminRights),
      status: info.selfStatus as TelegramChatMember["status"],
      user: me,
    };
  }

  async getChatAdministrators(chatId: string | number): Promise<TelegramChatMember[]> {
    const me = await this.getMe();
    const admins = await this.mt.getAdmins(await this.peer(chatId));
    return admins.map((a) => ({
      status: a.status as TelegramChatMember["status"],
      user: { id: a.id, is_bot: a.is_bot, first_name: a.name, username: undefined },
      can_delete_messages: true,
      can_restrict_members: true,
      can_invite_users: true,
      can_promote_members: a.status === "creator",
    }));
  }

  createChatInviteLink(): Promise<TelegramChatInviteLink> {
    throw unsupported("invite-link creation is not supported for user accounts in this build");
  }
  revokeChatInviteLink(): Promise<TelegramChatInviteLink> {
    throw unsupported("invite-link revocation is not supported for user accounts in this build");
  }

  async promoteChatMember(chatId: string | number, userId: number, rights: PromoteRights): Promise<true> {
    await this.mt.editAdmin(await this.peer(chatId), userId, rights as Record<string, boolean>);
    return true;
  }
  async banChatMember(chatId: string | number, userId: number): Promise<true> {
    await this.mt.editBanned(await this.peer(chatId), userId, true);
    return true;
  }
  async unbanChatMember(chatId: string | number, userId: number): Promise<true> {
    await this.mt.editBanned(await this.peer(chatId), userId, false);
    return true;
  }

  async sendMessage(chatId: string | number, text: string): Promise<TelegramMessage> {
    const p = await this.peer(chatId);
    await this.mt.sendMessage(p, text);
    const latest = await this.mt.getHistory(p, 0, 1);
    const msg = latest[0];
    if (!msg) throw new Error("sendMessage returned no message");
    return msg;
  }

  async deleteMessage(chatId: string | number, messageId: number): Promise<true> {
    await this.mt.deleteMessages(await this.peer(chatId), [messageId]);
    return true;
  }

  async copyMessage(destChatId: string | number, sourceChatId: string | number, messageId: number): Promise<CopyResult> {
    const ids = await this.copyMessages(destChatId, sourceChatId, [messageId]);
    if (ids.length === 0) throw unsupported("message could not be forwarded (protected content or deleted)");
    return ids[0];
  }

  async copyMessages(destChatId: string | number, sourceChatId: string | number, messageIds: number[]): Promise<CopyResult[]> {
    const from = await this.peer(sourceChatId);
    const to = await this.peer(destChatId);
    try {
      // copyBatchRobust falls back to download+re-upload for protected content
      // (FORWARDS_RESTRICTED), which bots cannot copy at all.
      const newIds = await this.mt.copyBatchRobust(from, to, messageIds);
      return newIds.map((id) => ({ message_id: id }));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (/MESSAGE_ID_INVALID|MSG_ID_INVALID/i.test(msg)) {
        // forwardMessages on a gap/deleted range — same signal the bot path
        // gets as "no messages to forward", which tick.ts drops the batch on.
        throw new TelegramApiError({ ok: false, error_code: 400, description: "no messages to forward" });
      }
      throw e;
    }
  }

  async getLatestMessageId(chatId: string | number): Promise<number> {
    const latest = await this.mt.getHistory(await this.peer(chatId), 0, 1);
    return latest[0]?.message_id ?? 0;
  }

  async pollNewMessages(chatId: string | number, minId: number, limit: number): Promise<TelegramMessage[]> {
    const msgs = await this.mt.getHistory(await this.peer(chatId), minId, limit);
    return msgs.filter((m) => m.message_id > minId).sort((a, b) => a.message_id - b.message_id);
  }

  close(): void {
    this.mt.close();
  }
}

/** Build the right client for a saved account row. */
export function createAccountClient(env: Env, row: BotRow): AccountClient {
  if (row.account_type === "user") {
    if (!env.TG_API_ID || !env.TG_API_HASH) {
      throw new Error("TG_API_ID / TG_API_HASH secrets are not set — required for user accounts (wrangler secret put TG_API_ID)");
    }
    const mt = new MtprotoClient({
      apiId: Number(env.TG_API_ID),
      apiHash: env.TG_API_HASH,
      sessionJson: row.mtproto_session,
      onSessionPersist: (json) => updateMtprotoSession(env.DB, row.id, json),
    });
    return new UserAccountClient(mt);
  }
  return new BotAccountClient(new TelegramClient(row.token));
}

/** Ephemeral client for the login flow (no saved row yet); the caller
 * persists the session JSON once sign-in succeeds. */
export function createLoginClient(env: Env, onSessionPersist: (json: string) => void): MtprotoClient {
  if (!env.TG_API_ID || !env.TG_API_HASH) {
    throw new Error("TG_API_ID / TG_API_HASH secrets are not set — required for user accounts (wrangler secret put TG_API_ID)");
  }
  return new MtprotoClient({
    apiId: Number(env.TG_API_ID),
    apiHash: env.TG_API_HASH,
    sessionJson: null,
    onSessionPersist: async (json) => onSessionPersist(json),
  });
}
