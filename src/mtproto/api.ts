// High-level MTProto client used by the "user" account flavor: login flow,
// peer resolution, chat info, history, forward (copy), send, file up/download.
// All methods map MTProto RPC errors to TelegramApiError via rpcErrorToApiError.

import { MtprotoConnection } from "./client";
import { rpcErrorToApiError, MtprotoRpcError } from "./errors";
import { serializeNamed } from "./tlengine";
import { computeSrp } from "./srp";
import { dcSessionFromAuthKey, parseSession, serializeSession, type MtprotoSessionStore, type DcSession } from "./session";
import type { TelegramChat, TelegramMessage, TelegramUser } from "../telegram/types";
import { bigIntToBytesLE, bytesToBigIntLE, randomBytes } from "./bytes";

export interface MtprotoClientOptions {
  apiId: number;
  apiHash: string;
  sessionJson: string | null; // persisted store JSON
  onSessionPersist: (json: string) => Promise<void>;
}

export interface ResolvedPeer {
  peerId: string; // Bot-API-style chat id string
  inputPeer: Record<string, unknown>;
  inputChannel?: Record<string, unknown>;
  inputUser?: Record<string, unknown>;
  accessHash: bigint;
  kind: "user" | "chat" | "channel";
  title?: string;
  username?: string;
}

const CHANNEL_PREFIX = 10n ** 12n;

export function peerToChatId(peer: Record<string, unknown>): string {
  switch (peer._name) {
    case "peerChannel":
      return String(-(CHANNEL_PREFIX + (peer.channel_id as bigint)));
    case "peerChat":
      return String(-(peer.chat_id as bigint));
    case "peerUser":
      return String(peer.user_id as bigint);
    default:
      throw new Error(`unknown peer ${peer._name}`);
  }
}

export function chatIdToInputPeer(chatId: string, accessHash = 0n): { inputPeer: Record<string, unknown>; kind: "user" | "chat" | "channel" } {
  if (chatId.startsWith("@")) throw new Error("resolve username first");
  const id = BigInt(chatId);
  if (id < -CHANNEL_PREFIX) {
    const channelId = -id - CHANNEL_PREFIX;
    return { inputPeer: { _name: "inputPeerChannel", channel_id: channelId, access_hash: accessHash }, kind: "channel" };
  }
  if (id < 0n) {
    return { inputPeer: { _name: "inputPeerChat", chat_id: -id }, kind: "chat" };
  }
  return { inputPeer: { _name: "inputPeerUser", user_id: id, access_hash: accessHash }, kind: "user" };
}

export class MtprotoClient {
  private store: MtprotoSessionStore | null;
  private conns = new Map<number, MtprotoConnection>();

  constructor(private opts: MtprotoClientOptions) {
    this.store = parseSession(opts.sessionJson);
  }

  private async conn(dcId?: number): Promise<MtprotoConnection> {
    const dc = dcId ?? this.store?.primaryDc ?? 2;
    const existing = this.conns.get(dc);
    if (existing) return existing;
    const dcSession = this.store?.dcs[String(dc)] ?? null;
    const c = new MtprotoConnection(dc, this.opts.apiId, this.opts.apiHash, dcSession, (s) => {
      if (!this.store) this.store = { primaryDc: dc, dcs: {} };
      this.store.dcs[String(s.dcId)] = s;
      void this.opts.onSessionPersist(serializeSession(this.store));
    });
    await c.connect();
    this.conns.set(dc, c);
    return c;
  }

  private async call<T = Record<string, unknown>>(method: string, params: Record<string, unknown>, dcId?: number): Promise<T> {
    const c = await this.conn(dcId);
    try {
      return (await c.invoke(method, params)) as T;
    } catch (e) {
      if (e instanceof MtprotoRpcError) throw rpcErrorToApiError(e.code, e.message);
      throw e;
    }
  }

  async ensureSession(): Promise<void> {
    await this.conn();
  }

  // ---------- auth / login ----------

  async sendCode(phone: string): Promise<{ phoneCodeHash: string; type: string }> {
    const res = await this.call("auth.sendCode", {
      phone_number: phone,
      api_id: this.opts.apiId,
      api_hash: this.opts.apiHash,
      settings: { _name: "codeSettings", flags: 0 },
    });
    if (res._name !== "auth.sentCode") throw new Error(`unexpected auth.sendCode result ${res._name}`);
    return { phoneCodeHash: res.phone_code_hash as string, type: String((res.type as Record<string, unknown>)?._name ?? "unknown") };
  }

  async signIn(phone: string, phoneCodeHash: string, code: string): Promise<Record<string, unknown>> {
    return this.call("auth.signIn", { flags: 1, phone_number: phone, phone_code_hash: phoneCodeHash, phone_code: code });
  }

  async checkPassword(password: string): Promise<Record<string, unknown>> {
    const pwd = await this.call("account.getPassword", {});
    const algo = pwd.current_algo as Record<string, unknown> | undefined;
    if (!algo || algo._name !== "passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow") {
      throw new Error("unsupported 2FA KDF algorithm");
    }
    const { A, M1 } = await computeSrp(
      {
        srpId: pwd.srp_id as bigint,
        srpB: pwd.srp_B as Uint8Array,
        algo: { salt1: algo.salt1 as Uint8Array, salt2: algo.salt2 as Uint8Array, g: algo.g as number, p: algo.p as Uint8Array },
      },
      password,
    );
    return this.call("auth.checkPassword", {
      password: { _name: "inputCheckPasswordSRP", srp_id: pwd.srp_id, A, M1 },
    });
  }

  async getState(): Promise<Record<string, unknown>> {
    return this.call("updates.getState", {});
  }

  // ---------- peers / chats ----------

  async resolveUsername(username: string): Promise<ResolvedPeer> {
    const res = await this.call("contacts.resolveUsername", { flags: 0, username: username.replace(/^@/, "") });
    const peer = res.peer as Record<string, unknown>;
    const chats = (res.chats ?? []) as Record<string, unknown>[];
    const users = (res.users ?? []) as Record<string, unknown>[];
    const chatId = peerToChatId(peer);
    const chatObj = chats.find((c) => c._name === "channel" && String(c.id) === String((peer as Record<string, unknown>).channel_id ?? "")) ?? chats[0];
    const userObj = users[0];
    const kind = peer._name === "peerChannel" ? "channel" : peer._name === "peerChat" ? "chat" : "user";
    const accessHash = (chatObj?.access_hash ?? userObj?.access_hash ?? 0n) as bigint;
    const inputPeer: Record<string, unknown> =
      kind === "channel"
        ? { _name: "inputPeerChannel", channel_id: peer.channel_id, access_hash: accessHash }
        : kind === "chat"
          ? { _name: "inputPeerChat", chat_id: peer.chat_id }
          : { _name: "inputPeerUser", user_id: peer.user_id, access_hash: accessHash };
    return {
      peerId: chatId,
      inputPeer,
      inputChannel: kind === "channel" ? { _name: "inputChannel", channel_id: peer.channel_id, access_hash: accessHash } : undefined,
      inputUser: kind === "user" ? { _name: "inputUser", user_id: peer.user_id, access_hash: accessHash } : undefined,
      accessHash,
      kind,
      title: (chatObj?.title ?? userObj?.first_name) as string | undefined,
      username: (chatObj?.username ?? userObj?.username) as string | undefined,
    };
  }

  async resolvePeer(chatId: string): Promise<ResolvedPeer> {
    if (chatId.startsWith("@")) return this.resolveUsername(chatId);
    const { inputPeer, kind } = chatIdToInputPeer(chatId);
    if (kind === "channel") {
      const id = BigInt(chatId);
      const channelId = -id - CHANNEL_PREFIX;
      const res = await this.call("channels.getChannels", { id: [{ _name: "inputChannel", channel_id: channelId, access_hash: 0n }] });
      const chats = (res.chats ?? []) as Record<string, unknown>[];
      const ch = chats.find((c) => c._name === "channel" || c._name === "channelForbidden") as Record<string, unknown> | undefined;
      const accessHash = (ch?.access_hash ?? 0n) as bigint;
      return {
        peerId: chatId,
        inputPeer: { _name: "inputPeerChannel", channel_id: channelId, access_hash: accessHash },
        inputChannel: { _name: "inputChannel", channel_id: channelId, access_hash: accessHash },
        accessHash,
        kind: "channel",
        title: ch?.title as string | undefined,
        username: ch?.username as string | undefined,
      };
    }
    if (kind === "chat") {
      const res = await this.call("messages.getChats", { id: [-BigInt(chatId)] });
      const chats = (res.chats ?? []) as Record<string, unknown>[];
      const ch = chats[0];
      return { peerId: chatId, inputPeer, accessHash: 0n, kind: "chat", title: ch?.title as string | undefined };
    }
    // user by numeric id: access_hash 0 works only for self/contacts; prefer @username
    return { peerId: chatId, inputPeer, accessHash: 0n, kind: "user" };
  }

  /** Chat info + self membership/admin rights for a resolved peer. */
  async getChatInfo(peer: ResolvedPeer): Promise<{
    chat: TelegramChat;
    memberCount?: number;
    selfStatus: string;
    selfAdminRights?: Record<string, unknown>;
    noforwards: boolean;
  }> {
    if (peer.kind === "channel") {
      const res = await this.call("channels.getChannels", { id: [peer.inputChannel] });
      const chats = (res.chats ?? []) as Record<string, unknown>[];
      const ch = chats[0];
      if (!ch) throw new Error("channel not found");
      const flags = ch.flags as number;
      const selfAdminRights = ch.admin_rights as Record<string, unknown> | undefined;
      const creator = ((flags >> 0) & 1) === 1;
      const left = ((flags >> 2) & 1) === 1;
      const noforwards = ((flags >> 27) & 1) === 1;
      const broadcast = ((flags >> 5) & 1) === 1;
      const megagroup = ((flags >> 8) & 1) === 1;
      return {
        chat: {
          id: Number(-(CHANNEL_PREFIX + (ch.id as bigint))),
          type: megagroup ? "supergroup" : "channel",
          title: ch.title as string | undefined,
          username: ch.username as string | undefined,
        },
        memberCount: ch.participants_count as number | undefined,
        selfStatus: creator ? "creator" : selfAdminRights ? "administrator" : left ? "left" : "member",
        selfAdminRights,
        noforwards,
        ...(broadcast ? {} : {}),
      };
    }
    if (peer.kind === "chat") {
      const res = await this.call("messages.getChats", { id: [-BigInt(peer.peerId)] });
      const chats = (res.chats ?? []) as Record<string, unknown>[];
      const ch = chats[0];
      if (!ch) throw new Error("chat not found");
      const flags = ch.flags as number;
      const selfAdminRights = ch.admin_rights as Record<string, unknown> | undefined;
      const creator = ((flags >> 0) & 1) === 1;
      const left = ((flags >> 2) & 1) === 1;
      const noforwards = ((flags >> 25) & 1) === 1;
      return {
        chat: { id: Number(ch.id as bigint) * -1, type: "group", title: ch.title as string | undefined },
        memberCount: ch.participants_count as number | undefined,
        selfStatus: creator ? "creator" : selfAdminRights ? "administrator" : left ? "left" : "member",
        selfAdminRights,
        noforwards,
      };
    }
    // user: private chat — membership is implicit
    const me = await this.getMe();
    if (peer.peerId === String(me.id)) {
      return { chat: { id: Number(me.id), type: "private", first_name: me.first_name }, selfStatus: "member", noforwards: false };
    }
    return { chat: { id: Number(BigInt(peer.peerId)), type: "private" }, selfStatus: "member", noforwards: false };
  }

  async getMe(): Promise<TelegramUser> {
    // auth.authorization at login carries the user; for verify we stored it in the row.
    // Use updates.getState to validate the session, and users.getFullUser(self) for identity.
    const res = await this.call("users.getFullUser", { id: { _name: "inputUserSelf" } });
    const users = (res.users ?? []) as Record<string, unknown>[];
    const u = users[0];
    if (!u) throw new Error("getMe failed");
    return userToTelegram(u);
  }

  async getAdmins(peer: ResolvedPeer, limit = 200): Promise<Array<{ id: number; name: string; status: string; is_bot: boolean }>> {
    if (peer.kind !== "channel" || !peer.inputChannel) return [];
    const res = await this.call("channels.getParticipants", {
      channel: peer.inputChannel,
      filter: { _name: "channelParticipantsAdmins" },
      offset: 0,
      limit,
      hash: 0n,
    });
    const participants = (res.participants ?? []) as Record<string, unknown>[];
    const users = (res.users ?? []) as Record<string, unknown>[];
    const userById = new Map(users.map((u) => [String(u.id), u]));
    return participants.map((p) => {
      const u = userById.get(String(p.user_id ?? (p.peer as Record<string, unknown>)?.user_id)) ?? {};
      const name = [String(u.first_name ?? ""), String(u.last_name ?? "")].filter(Boolean).join(" ") || String(u.username ?? "") || String(p.user_id);
      const isBot = (((u.flags as number) ?? 0) >> 14) & 1;
      return {
        id: Number(p.user_id ?? (p.peer as Record<string, unknown>)?.user_id ?? 0n),
        name: u.username ? `${name} (@${u.username})` : name,
        status: p._name === "channelParticipantCreator" ? "creator" : "administrator",
        is_bot: isBot === 1,
      };
    });
  }

  // ---------- messages ----------

  async getHistory(peer: ResolvedPeer, minId: number, limit: number): Promise<TelegramMessage[]> {
    const res = await this.call("messages.getHistory", {
      peer: peer.inputPeer,
      offset_id: 0,
      offset_date: 0,
      add_offset: 0,
      limit,
      max_id: 0,
      min_id: minId,
      hash: 0n,
    });
    const msgs = (res.messages ?? []) as Record<string, unknown>[];
    const chats = (res.chats ?? []) as Record<string, unknown>[];
    const users = (res.users ?? []) as Record<string, unknown>[];
    return msgs.map((m) => mtMessageToTelegram(m, chats, users));
  }

  async getMessages(peer: ResolvedPeer, ids: number[]): Promise<TelegramMessage[]> {
    const res = await this.call("messages.getMessages", {
      id: ids.map((id) => ({ _name: "inputMessageID", id })),
    });
    const msgs = (res.messages ?? []) as Record<string, unknown>[];
    const chats = (res.chats ?? []) as Record<string, unknown>[];
    const users = (res.users ?? []) as Record<string, unknown>[];
    return msgs.map((m) => mtMessageToTelegram(m, chats, users));
  }

  /** Copy equivalent: forwardMessages with drop_author (hides "forwarded from").
   * Returns the ids of the newly created messages in the destination. */
  async forwardMessages(from: ResolvedPeer, to: ResolvedPeer, ids: number[]): Promise<number[]> {
    const res = await this.call("messages.forwardMessages", {
      silent: true,
      drop_author: true,
      from_peer: from.inputPeer,
      id: ids,
      random_id: ids.map(() => bytesToBigIntLE(randomBytes(8))),
      to_peer: to.inputPeer,
    });
    const updates = (res.updates ?? []) as Record<string, unknown>[];
    const newIds: number[] = [];
    for (const u of updates) {
      if (u._name === "updateNewMessage" || u._name === "updateNewChannelMessage") {
        const msg = u.message as Record<string, unknown> | undefined;
        if (msg && typeof msg.id === "number") newIds.push(msg.id);
      }
    }
    return newIds;
  }

  async getRawMessages(peer: ResolvedPeer, ids: number[]): Promise<Record<string, unknown>[]> {
    const res = await this.call("messages.getMessages", {
      id: ids.map((id) => ({ _name: "inputMessageID", id })),
    });
    return (res.messages ?? []) as Record<string, unknown>[];
  }

  /** Protected-content fallback: bots can't copy restricted messages, and user
   * accounts can't forward them (FORWARDS_RESTRICTED) — but a user CAN
   * download and re-upload. Copies one message by re-upload; returns the new
   * message id, or null when the media kind is unsupported (poll, story…). */
  async copyOneRobust(from: ResolvedPeer, to: ResolvedPeer, id: number): Promise<number | null> {
    try {
      const ids = await this.forwardMessages(from, to, [id]);
      return ids[0] ?? null;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (!/FORWARDS_RESTRICTED|CHAT_FORWARDS_RESTRICTED/i.test(msg)) throw e;
    }
    return this.reuploadMessage(from, to, id);
  }

  /** Batch variant: forward all ids in one call; if the whole batch is
   * rejected due to protected content, copy one by one so only the protected
   * ones take the slow re-upload path. Returns the new destination ids. */
  async copyBatchRobust(from: ResolvedPeer, to: ResolvedPeer, ids: number[]): Promise<number[]> {
    if (ids.length === 0) return [];
    try {
      return await this.forwardMessages(from, to, ids);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (!/FORWARDS_RESTRICTED|CHAT_FORWARDS_RESTRICTED/i.test(msg)) throw e;
      const out: number[] = [];
      for (const id of ids) {
        try {
          const newId = await this.copyOneRobust(from, to, id);
          if (newId !== null) out.push(newId);
        } catch {
          // individual failure — skipped, same as bot copyMessages skips ids
        }
      }
      return out;
    }
  }

  private async reuploadMessage(from: ResolvedPeer, to: ResolvedPeer, id: number): Promise<number | null> {
    const MAX_REUPLOAD_BYTES = 1024 * 1024 * 1024; // 1 GiB cap
    const raw = await this.getRawMessages(from, [id]);
    const m = raw[0];
    if (!m || m._name !== "message") return null;
    const text = ((m.message as string) ?? "").trim();
    const media = m.media as Record<string, unknown> | undefined;

    if (!media) {
      if (!text) return null;
      const res = await this.sendMessage(to, text);
      return extractNewMessageId(res);
    }

    if (media._name === "messageMediaPhoto") {
      const photo = media.photo as Record<string, unknown> | undefined;
      if (!photo || photo._name !== "photo") return null;
      const sizes = (photo.sizes ?? []) as Record<string, unknown>[];
      let thumbSize = "x";
      let best = -1;
      for (const s of sizes) {
        if (s._name !== "photoSize" && s._name !== "photoSizeProgressive") continue;
        const sz = (s.size as number) ?? ((s.sizes as number[] | undefined)?.reduce((a, b) => a + b, 0)) ?? 0;
        if (sz > best) {
          best = sz;
          thumbSize = s.type as string;
        }
      }
      const location = {
        _name: "inputPhotoFileLocation",
        id: photo.id,
        access_hash: photo.access_hash,
        file_reference: photo.file_reference,
        thumb_size: thumbSize,
      };
      const dcId = photo.dc_id as number;
      const newId = await this.uploadToPeer(to, location, dcId, best > 0 ? best : 0, (fid, parts, name) => ({
        _name: "inputMediaUploadedPhoto",
        flags: 0,
        file: { _name: parts > 1024 ? "inputFileBig" : "inputFile", id: fid, parts, name, md5_checksum: parts > 1024 ? undefined : "" },
      }), text);
      return newId;
    }

    if (media._name === "messageMediaDocument") {
      const doc = media.document as Record<string, unknown> | undefined;
      if (!doc || doc._name !== "document") return null;
      const size = Number(doc.size as bigint);
      if (size <= 0 || size > MAX_REUPLOAD_BYTES) return null;
      const attrs = (doc.attributes ?? []) as Record<string, unknown>[];
      const fileName = (attrs.find((a) => a._name === "documentAttributeFilename")?.file_name as string) ?? "file";
      const location = {
        _name: "inputDocumentFileLocation",
        id: doc.id,
        access_hash: doc.access_hash,
        file_reference: doc.file_reference,
        thumb_size: "",
      };
      const dcId = doc.dc_id as number;
      const newId = await this.uploadToPeer(to, location, dcId, size, (fid, parts, name) => ({
        _name: "inputMediaUploadedDocument",
        flags: 0,
        file: { _name: parts > 1024 ? "inputFileBig" : "inputFile", id: fid, parts, name, md5_checksum: parts > 1024 ? undefined : "" },
        mime_type: (doc.mime_type as string) ?? "application/octet-stream",
        attributes: attrs.filter((a) => a._name !== "documentAttributeFilename").map((a) => ({ ...a, file_name: fileName })),
      }), text);
      return newId;
    }

    return null;
  }

  /** Download a file location chunk-by-chunk and immediately re-upload each
   * chunk as a file part (constant memory), then send it as media. */
  private async uploadToPeer(
    to: ResolvedPeer,
    location: Record<string, unknown>,
    dcId: number,
    size: number,
    mediaBuilder: (fileId: bigint, parts: number, name: string) => Record<string, unknown>,
    caption: string,
  ): Promise<number | null> {
    const CHUNK = 1024 * 1024;
    const totalParts = Math.max(1, Math.ceil(size / CHUNK));
    const fileId = bytesToBigIntLE(randomBytes(8));
    let part = 0;
    await this.downloadFile(location, dcId, async (chunk) => {
      await this.uploadFilePart(fileId, part, totalParts, chunk, dcId);
      part++;
    }, size);
    if (part === 0) return null;
    const res = await this.call("messages.sendMedia", {
      silent: true,
      peer: to.inputPeer,
      media: mediaBuilder(fileId, part, "upload.bin"),
      message: caption,
      random_id: bytesToBigIntLE(randomBytes(8)),
    });
    return extractNewMessageId(res);
  }

  async sendMessage(peer: ResolvedPeer, text: string): Promise<Record<string, unknown>> {
    return this.call("messages.sendMessage", {
      flags: 0,
      peer: peer.inputPeer,
      message: text,
      random_id: bytesToBigIntLE(randomBytes(8)),
    });
  }

  async sendMediaDocument(peer: ResolvedPeer, fileId: bigint, fileParts: number, name: string, mimeType: string, caption: string, attributes: Record<string, unknown>[]): Promise<Record<string, unknown>> {
    return this.call("messages.sendMedia", {
      flags: 0,
      peer: peer.inputPeer,
      media: {
        _name: "inputMediaUploadedDocument",
        flags: 0,
        file: { _name: fileParts > 1024 ? "inputFileBig" : "inputFile", id: fileId, parts: fileParts, name, md5_checksum: fileParts > 1024 ? undefined : "" },
        mime_type: mimeType,
        attributes,
      },
      message: caption,
      random_id: bytesToBigIntLE(randomBytes(8)),
    });
  }

  async uploadFilePart(fileId: bigint, part: number, totalParts: number, data: Uint8Array, dcId?: number): Promise<void> {
    if (totalParts > 1024 || data.length > 1024 * 1024) {
      await this.call("upload.saveBigFilePart", { file_id: fileId, file_part: part, file_total_parts: totalParts, bytes: data }, dcId);
    } else {
      await this.call("upload.saveFilePart", { file_id: fileId, file_part: part, bytes: data }, dcId);
    }
  }

  async downloadFile(location: Record<string, unknown>, dcId: number, onChunk: (chunk: Uint8Array, offset: number) => Promise<void>, maxBytes: number): Promise<number> {
    const CHUNK = 1024 * 1024;
    let offset = 0;
    while (offset < maxBytes) {
      const limit = Math.min(CHUNK, maxBytes - offset);
      const res = await this.call("upload.getFile", { flags: 0, location, offset: BigInt(offset), limit }, dcId);
      const bytes = res.bytes as Uint8Array;
      if (!bytes || bytes.length === 0) break;
      await onChunk(bytes, offset);
      offset += bytes.length;
      if (bytes.length < limit) break;
    }
    return offset;
  }

  async editBanned(peer: ResolvedPeer, userId: number, ban: boolean): Promise<void> {
    if (!peer.inputChannel) throw new Error("not a channel");
    await this.call("channels.editBanned", {
      channel: peer.inputChannel,
      participant: { _name: "inputPeerUser", user_id: BigInt(userId), access_hash: 0n },
      banned_rights: ban
        ? { _name: "chatBannedRights", flags: 0b1111111111111111111111111, until_date: 0 }
        : { _name: "chatBannedRights", flags: 0, until_date: 0 },
    });
  }

  async editAdmin(peer: ResolvedPeer, userId: number, rights: Record<string, boolean>): Promise<void> {
    if (!peer.inputChannel) throw new Error("not a channel");
    const flags = Object.entries(rights).reduce((acc, [k, v]) => (v ? acc | rightBit(k) : acc), 0);
    await this.call("channels.editAdmin", {
      flags: 0,
      channel: peer.inputChannel,
      user_id: { _name: "inputUser", user_id: BigInt(userId), access_hash: 0n },
      admin_rights: { _name: "chatAdminRights", flags },
    });
  }

  async deleteMessages(peer: ResolvedPeer, ids: number[]): Promise<void> {
    await this.call("messages.deleteMessages", {
      flags: 0,
      revoke: true,
      id: ids,
    });
  }

  close(): void {
    for (const c of this.conns.values()) c.close();
    this.conns.clear();
  }
}

function extractNewMessageId(res: Record<string, unknown>): number | null {
  const updates = (res.updates ?? []) as Record<string, unknown>[];
  for (const u of updates) {
    if (u._name === "updateNewMessage" || u._name === "updateNewChannelMessage") {
      const msg = u.message as Record<string, unknown> | undefined;
      if (msg && typeof msg.id === "number") return msg.id;
    }
  }
  return null;
}

function rightBit(name: string): number {
  const map: Record<string, number> = {
    can_change_info: 0,
    can_post_messages: 1,
    can_edit_messages: 2,
    can_delete_messages: 3,
    can_restrict_members: 4,
    can_invite_users: 5,
    can_pin_messages: 7,
    can_promote_members: 9,
    can_manage_chat: 11,
  };
  const b = map[name];
  return b === undefined ? 0 : 1 << b;
}

function userToTelegram(u: Record<string, unknown>): TelegramUser {
  const flags = (u.flags as number) ?? 0;
  return {
    id: Number(u.id as bigint),
    is_bot: (((flags >> 14) & 1) === 1),
    first_name: (u.first_name as string) ?? "",
    username: u.username as string | undefined,
  };
}

function mtMessageToTelegram(m: Record<string, unknown>, chats: Record<string, unknown>[], users: Record<string, unknown>[]): TelegramMessage {
  const peer = m.peer_id as Record<string, unknown>;
  const chatId = peerToChatId(peer);
  const chatObj = chats.find((c) => peer._name === "peerChannel" && String(c.id) === String(peer.channel_id));
  const chat: TelegramChat = {
    id: Number(BigInt(chatId)),
    type: peer._name === "peerChannel" ? (chatObj && ((chatObj.flags as number) >> 8) & 1 ? "supergroup" : "channel") : peer._name === "peerChat" ? "group" : "private",
    title: chatObj?.title as string | undefined,
    username: chatObj?.username as string | undefined,
  };
  const fromPeer = m.from_id as Record<string, unknown> | undefined;
  const fromUser = fromPeer?._name === "peerUser" ? users.find((u) => String(u.id) === String(fromPeer.user_id)) : undefined;
  const msg: TelegramMessage = {
    message_id: m.id as number,
    date: m.date as number,
    chat,
    text: (m.message as string) || undefined,
  };
  if (fromUser) msg.from = userToTelegram(fromUser);
  const media = m.media as Record<string, unknown> | undefined;
  if (media) applyMedia(msg, media);
  return msg;
}

function applyMedia(msg: TelegramMessage, media: Record<string, unknown>): void {
  if (media._name === "messageMediaPhoto") {
    const photo = media.photo as Record<string, unknown> | undefined;
    if (photo?._name === "photo") {
      const sizes = (photo.sizes ?? []) as Record<string, unknown>[];
      let best: Record<string, unknown> | undefined;
      let bestSize = -1;
      for (const s of sizes) {
        const sz = (s.size as number) ?? ((s.sizes as number[] | undefined)?.reduce((a, b) => a + b, 0)) ?? 0;
        if (sz > bestSize) {
          bestSize = sz;
          best = s;
        }
      }
      if (best) {
        msg.photo = [
          {
            file_id: String(photo.id),
            file_unique_id: String(photo.id),
            file_size: bestSize,
            width: (best.w as number) ?? 0,
            height: (best.h as number) ?? 0,
          },
        ];
      }
    }
    msg.caption = msg.text;
    return;
  }
  if (media._name === "messageMediaDocument") {
    const doc = media.document as Record<string, unknown> | undefined;
    if (!doc || doc._name !== "document") return;
    const attrs = (doc.attributes ?? []) as Record<string, unknown>[];
    const fileName = (attrs.find((a) => a._name === "documentAttributeFilename")?.file_name as string) ?? undefined;
    const mime = doc.mime_type as string | undefined;
    const size = Number(doc.size as bigint);
    const videoAttr = attrs.find((a) => a._name === "documentAttributeVideo");
    const audioAttr = attrs.find((a) => a._name === "documentAttributeAudio");
    const animAttr = attrs.find((a) => a._name === "documentAttributeAnimated");
    const common = { file_id: String(doc.id), file_unique_id: String(doc.id), file_name: fileName, mime_type: mime, file_size: size };
    if (videoAttr) {
      msg.video = { ...common, duration: Math.round((videoAttr.duration as number) ?? 0) };
    } else if (audioAttr) {
      if (((audioAttr.flags as number) >> 10) & 1) {
        msg.voice = { ...common };
      } else {
        msg.audio = { ...common, duration: audioAttr.duration as number };
      }
    } else if (animAttr) {
      msg.animation = { ...common };
    } else {
      msg.document = { ...common };
    }
    msg.caption = msg.text;
  }
}

export { serializeNamed };
