// MTProto 2.0 connection over the obfuscated WSS transport: auth-key handshake
// (once per DC, then persisted), encrypted invoke/response loop, containers,
// gzip, salt updates. One connection per DC per invocation — the Worker opens
// it, does its work, and closes it.

import { aesIgeDecrypt, aesIgeEncrypt } from "./aes";
import { bigIntToBytesLE, bytesToBigIntLE, concat, randomBytes, readUint64LE, writeUint64LE } from "./bytes";
import { sha256 } from "./hash";
import { MtprotoRpcError } from "./errors";
import { ObfuscatedWsTransport } from "./transport";
import { TLReader } from "./tl";
import { ANY, parseObj, serializeNamed, UnknownCtorError } from "./tlengine";
import { hex } from "./bytes";
import "./schema";
import { createAuthKey, type AuthKeyResult } from "./authkey";
import type { DcSession } from "./session";
import { dcSessionToAuthKey } from "./session";

export const TL_LAYER = 225;

/** MTProto 2.0 msg_key: middle 128 bits of SHA256(auth_key[88+x .. +32] + plaintext). */
export async function mtprotoMsgKey(authKey: Uint8Array, plaintext: Uint8Array, x: number): Promise<Uint8Array> {
  return (await sha256(concat(authKey.subarray(88 + x, 88 + x + 32), plaintext))).subarray(8, 24);
}

/** MTProto 2.0 AES-256 key/IV derivation from auth_key + msg_key (x = 0 client→server, 8 server→client). */
export async function mtprotoAesKeyIv(
  authKey: Uint8Array,
  msgKey: Uint8Array,
  x: number,
): Promise<{ aesKey: Uint8Array; aesIv: Uint8Array }> {
  const shaA = await sha256(concat(msgKey, authKey.subarray(x, x + 36)));
  const shaB = await sha256(concat(authKey.subarray(40 + x, 40 + x + 36), msgKey));
  const aesKey = concat(shaA.subarray(0, 8), shaB.subarray(8, 24), shaA.subarray(24, 32));
  const aesIv = concat(shaB.subarray(0, 8), shaA.subarray(8, 24), shaB.subarray(24, 32));
  return { aesKey, aesIv };
}

interface PendingCall {
  resolve: (v: Record<string, unknown>) => void;
  reject: (e: unknown) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class MtprotoConnection {
  private transport = new ObfuscatedWsTransport();
  private authKey!: Uint8Array;
  private authKeyId!: Uint8Array;
  private serverSalt!: Uint8Array;
  private sessionId = bytesToBigIntLE(randomBytes(8));
  private seq = 0;
  private lastMsgId = 0n;
  private pending = new Map<bigint, PendingCall>();
  private initialized = false;
  private chain: Promise<unknown> = Promise.resolve();
  private closed = false;

  constructor(
    private dcId: number,
    private apiId: number,
    private apiHash: string,
    private session: DcSession | null,
    private onSessionCreated: ((s: DcSession) => void) | null,
  ) {}

  async connect(): Promise<void> {
    await this.transport.connect(this.dcId);
    if (this.session) {
      const s = dcSessionToAuthKey(this.session);
      this.authKey = s.authKey;
      this.authKeyId = s.authKeyId;
      this.serverSalt = s.serverSalt;
    } else {
      const result = await this.handshake();
      this.authKey = result.authKey;
      this.authKeyId = result.authKeyId;
      this.serverSalt = result.serverSalt;
      const dc: DcSession = { dcId: this.dcId, authKey: hex(result.authKey), authKeyId: hex(result.authKeyId), serverSalt: hex(result.serverSalt) };
      this.onSessionCreated?.(dc);
    }
    this.lastMsgId = this.newMsgId();
  }

  private async handshake(): Promise<AuthKeyResult> {
    return createAuthKey(this.dcId, async (body) => {
      const msgId = this.newMsgId();
      const packet = concat(new Uint8Array(8), writeUint64LE(msgId), new Uint8Array(new Uint8Array(4).buffer), body);
      // unencrypted: auth_key_id(8)=0 + msg_id(8) + len(4) + body
      const len = new Uint8Array(4);
      new DataView(len.buffer).setUint32(0, body.length, true);
      const full = concat(new Uint8Array(8), writeUint64LE(msgId), len, body);
      void packet;
      this.transport.send(full);
      const resp = await this.transport.recv(30000);
      const r = new TLReader(resp);
      const keyId = readUint64LE(resp, 0);
      if (keyId !== 0n) throw new Error("expected unencrypted response");
      r.skip(8);
      const msgId2 = r.long();
      const len2 = r.int();
      void msgId2;
      const bodyBytes = resp.subarray(20, 20 + len2);
      return parseObj("Object", new TLReader(bodyBytes));
    });
  }

  private newMsgId(): bigint {
    const now = BigInt(Math.floor(Date.now() / 1000));
    let id = (now << 32n) | BigInt(Math.floor(Math.random() * 0xffffffff));
    id &= ~3n; // client msg ids divisible by 4
    if (id <= this.lastMsgId) id = this.lastMsgId + 4n;
    this.lastMsgId = id;
    return id;
  }

  private nextSeq(contentRelated: boolean): number {
    const s = this.seq * 2 + (contentRelated ? 1 : 0);
    if (contentRelated) this.seq++;
    return s;
  }

  private async decryptMessage(payload: Uint8Array): Promise<{ body: Uint8Array; msgId: bigint }> {
    const authKeyId = payload.subarray(0, 8);
    const msgKey = payload.subarray(8, 24);
    const cipher = payload.subarray(24);
    const x = 8;
    const { aesKey, aesIv } = await mtprotoAesKeyIv(this.authKey, msgKey, x);
    const plain = aesIgeDecrypt(cipher, aesKey, aesIv);
    const check = await mtprotoMsgKey(this.authKey, plain, x);
    for (let i = 0; i < 16; i++) {
      if (check[i] !== msgKey[i]) throw new Error("msg_key mismatch");
    }
    const r = new TLReader(plain);
    this.serverSalt = plain.subarray(0, 8);
    r.skip(8);
    r.skip(8); // session
    const msgId = r.long();
    r.skip(4); // seq
    const len = r.int();
    const body = plain.subarray(24 + 4, 24 + 4 + len);
    void authKeyId;
    return { body, msgId };
  }

  private async handleBody(body: Uint8Array): Promise<void> {
    const r = new TLReader(body);
    const id = r.ctor();
    const name = ANY[id]?.name;
    switch (name) {
      case "rpc_result": {
        const reqMsgId = r.long();
        let resultBytes = r.rest();
        // result may be gzip_packed
        const rr = new TLReader(resultBytes);
        const rid = rr.ctor();
        let result: Record<string, unknown>;
        if (rid === 0x3072cfa1) {
          const packed = rr.bytes();
          const ds = new DecompressionStream("gzip");
          const stream = new Response(packed).body!.pipeThrough(ds);
          const buf = new Uint8Array(await new Response(stream).arrayBuffer());
          result = parseObj("Object", new TLReader(buf));
        } else {
          result = parseObj("Object", new TLReader(resultBytes));
        }
        void resultBytes;
        const p = this.pending.get(reqMsgId);
        if (p) {
          clearTimeout(p.timer);
          this.pending.delete(reqMsgId);
          if (result._name === "rpc_error") {
            p.reject(new MtprotoRpcError(result.error_code as number, result.error_message as string));
          } else {
            p.resolve(result);
          }
        }
        break;
      }
      case "msg_container": {
        const n = (() => {
          const c = r.ctor();
          if (c !== 0x1cb5c415) throw new UnknownCtorError(c, "container.vector");
          return r.int();
        })();
        for (let i = 0; i < n; i++) {
          r.long(); // inner msg_id
          r.int(); // seqno
          const bytes = r.int();
          const inner = r.rest().subarray(0, bytes);
          r.skip(bytes);
          await this.handleBody(inner);
        }
        break;
      }
      case "msgs_ack":
      case "pong":
        break;
      case "new_session_created": {
        r.long();
        r.long();
        const salt = r.long();
        this.serverSalt = bigIntToBytesLE(salt, 8);
        break;
      }
      case "bad_server_salt": {
        r.long();
        r.int();
        r.int();
        const salt = r.long();
        this.serverSalt = bigIntToBytesLE(salt, 8);
        break;
      }
      default:
        // unknown top-level service message — ignore
        break;
    }
  }

  private async readLoop(): Promise<void> {
    while (!this.closed) {
      try {
        const payload = await this.transport.recv(60000);
        const keyId = readUint64LE(payload, 0);
        if (keyId === 0n) {
          // unencrypted (handshake phase)
          const r = new TLReader(payload);
          r.skip(8);
          r.long();
          const len = r.int();
          await this.handleBody(payload.subarray(20, 20 + len));
        } else {
          const { body } = await this.decryptMessage(payload);
          await this.handleBody(body);
        }
      } catch (e) {
        if (!this.closed) {
          for (const p of this.pending.values()) {
            clearTimeout(p.timer);
            p.reject(e);
          }
          this.pending.clear();
        }
        return;
      }
    }
  }

  /** Serialized invoke — one RPC at a time per connection. */
  invoke(method: string, params: Record<string, unknown>, timeoutMs = 30000): Promise<Record<string, unknown>> {
    const run = this.chain.then(() => this.invokeNow(method, params, timeoutMs));
    this.chain = run.catch(() => undefined);
    return run;
  }

  private invokeNow(method: string, params: Record<string, unknown>, timeoutMs: number): Promise<Record<string, unknown>> {
    return new Promise(async (resolve, reject) => {
      try {
        let query = serializeNamed(method, params);
        if (!this.initialized) {
          const init = serializeNamed("initConnection", {
            flags: 0,
            api_id: this.apiId,
            device_model: "Telegram Clone Worker",
            system_version: "Cloudflare Workers",
            app_version: "1.0.0",
            system_lang_code: "en",
            lang_pack: "web",
            lang_code: "en",
            query,
          });
          query = serializeNamed("invokeWithLayer", { layer: TL_LAYER, query: init });
          this.initialized = true;
        }
        const msgId = this.newMsgId();
        const payload = await this.encryptMessageWithId(query, msgId, true);
        const timer = setTimeout(() => {
          this.pending.delete(msgId);
          reject(new Error(`mtproto invoke timeout: ${method}`));
        }, timeoutMs);
        this.pending.set(msgId, { resolve, reject, timer });
        if (!this.readLoopStarted) {
          this.readLoopStarted = true;
          void this.readLoop();
        }
        this.transport.send(payload);
      } catch (e) {
        reject(e);
      }
    });
  }

  private readLoopStarted = false;

  private async encryptMessageWithId(body: Uint8Array, msgId: bigint, contentRelated: boolean): Promise<Uint8Array> {
    const seq = this.nextSeq(contentRelated);
    const seqB = new Uint8Array(4);
    new DataView(seqB.buffer).setInt32(0, seq, true);
    const lenB = new Uint8Array(4);
    new DataView(lenB.buffer).setUint32(0, body.length, true);
    const plainHeader = concat(this.serverSalt, writeUint64LE(this.sessionId), writeUint64LE(msgId), seqB, lenB);
    const base = plainHeader.length + body.length;
    let padLen = 12 + Math.floor(Math.random() * 200);
    const total = base + padLen;
    padLen += (16 - (total % 16)) % 16;
    const padding = randomBytes(padLen);
    const plaintext = concat(plainHeader, body, padding);
    const msgKey = await mtprotoMsgKey(this.authKey, plaintext, 0);
    const { aesKey, aesIv } = await mtprotoAesKeyIv(this.authKey, msgKey, 0);
    const cipher = aesIgeEncrypt(plaintext, aesKey, aesIv);
    return concat(this.authKeyId, msgKey, cipher);
  }

  close(): void {
    this.closed = true;
    this.transport.close();
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(new Error("connection closed"));
    }
    this.pending.clear();
  }
}
