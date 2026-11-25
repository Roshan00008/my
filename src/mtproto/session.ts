// Persisted MTProto session: per-DC auth keys, stored as JSON in bots.mtproto_session.

import { fromHex, hex } from "./bytes";

export interface DcSession {
  dcId: number;
  authKey: string; // hex, 256 bytes
  authKeyId: string; // hex, 8 bytes
  serverSalt: string; // hex, 8 bytes
}

export interface MtprotoSessionStore {
  primaryDc: number;
  dcs: Record<string, DcSession>; // keyed by dcId string
}

export function parseSession(json: string | null | undefined): MtprotoSessionStore | null {
  if (!json) return null;
  try {
    const o = JSON.parse(json) as MtprotoSessionStore;
    if (!o || typeof o.primaryDc !== "number" || !o.dcs) return null;
    return o;
  } catch {
    return null;
  }
}

export function serializeSession(store: MtprotoSessionStore): string {
  return JSON.stringify(store);
}

export function dcSessionFromAuthKey(result: { authKey: Uint8Array; authKeyId: Uint8Array; serverSalt: Uint8Array; dcId: number }): DcSession {
  return {
    dcId: result.dcId,
    authKey: hex(result.authKey),
    authKeyId: hex(result.authKeyId),
    serverSalt: hex(result.serverSalt),
  };
}

export function dcSessionToAuthKey(s: DcSession): { authKey: Uint8Array; authKeyId: Uint8Array; serverSalt: Uint8Array; dcId: number } {
  return {
    authKey: fromHex(s.authKey),
    authKeyId: fromHex(s.authKeyId),
    serverSalt: fromHex(s.serverSalt),
    dcId: s.dcId,
  };
}

/** Per-account live-sync watermark: max source message id seen per chat. */
export interface UpdateStateStore {
  chats: Record<string, number>;
}

export function parseUpdateState(json: string | null | undefined): UpdateStateStore {
  if (!json) return { chats: {} };
  try {
    const o = JSON.parse(json) as UpdateStateStore;
    return o && typeof o === "object" && o.chats ? o : { chats: {} };
  } catch {
    return { chats: {} };
  }
}

export function serializeUpdateState(s: UpdateStateStore): string {
  return JSON.stringify(s);
}
