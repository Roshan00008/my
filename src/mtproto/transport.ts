import { connect } from "cloudflare:sockets";
import { AesCtr, aesIgeDecrypt, aesIgeEncrypt } from "./aes";
import { concat, randomBytes, reverse, xor } from "./bytes";

// DC front-end IPs, port 443 serves raw MTProto (same table Telethon uses).
export const DC_IPS: Record<number, string> = {
  1: "149.154.175.50",
  2: "149.154.167.51",
  3: "149.154.175.100",
  4: "149.154.167.91",
  5: "149.154.171.5",
};

type SocketsSocket = Awaited<ReturnType<typeof connect>>;

export function dcHost(dcId: number): string {
  const ip = DC_IPS[Math.abs(dcId)];
  if (!ip) throw new Error(`unknown DC ${dcId}`);
  return ip;
}

/**
 * Obfuscated abridged MTProto over a raw TCP socket (cloudflare:sockets).
 *
 * Standard obfuscated2 exactly as Telethon's ConnectionTcpObfuscated:
 *   init:  64 random bytes, first 56 plaintext (with forbidden prefixes),
 *          bytes 56..59 = 0xefefefef (abridged tag), bytes 56..64 AES-CTR
 *          encrypted tail.
 *   keys:  encrypt = init[8..40] / init[40..56], decrypt = first 32/16 bytes
 *          of reversed init[8..56]. RAW bytes — no hashing, no secret.
 * The encryptor keystream continues past the init; the decryptor starts at
 * keystream offset 0. Abridged framing carries the MTProto payloads.
 */
export class ObfuscatedWsTransport {
  private socket: SocketsSocket | null = null;
  private encCtr: AesCtr | null = null;
  private decCtr: AesCtr | null = null;
  private recvBuf = new Uint8Array(0);
  private closed = false;
  private reader: ReadableStreamDefaultReader<Uint8Array> | null = null;

  async connect(dcId: number): Promise<void> {
    const ip = dcHost(dcId);
    const socket = connect({ hostname: ip, port: 443 });
    await socket.opened;
    if (this.closed) {
      socket.close();
      return;
    }
    this.socket = socket;

    // Build the 64-byte obfuscated init (abridged protocol 0xef).
    let init: Uint8Array;
    for (;;) {
      init = randomBytes(64);
      const firstInt = (init[0] | (init[1] << 8) | (init[2] << 16) | (init[3] << 24)) >>> 0;
      if (
        init[0] === 0xef ||
        firstInt === 0xdddddddd ||
        firstInt === 0xeeeeeeee ||
        firstInt === 0x44414548 || // HEAD
        firstInt === 0x54534f50 || // POST
        firstInt === 0x20544547 || // GET
        firstInt === 0x4954504f || // OPTI
        firstInt === 0x47525650 || // PVrG
        firstInt === 0x02010316 || // TLS
        (init[4] | (init[5] << 8) | (init[6] << 16) | (init[7] << 24)) === 0
      ) {
        continue;
      }
      break;
    }

    // Standard obfuscated2 key derivation — raw bytes, no hashing, no secret:
    //   encrypt: key = init[8..40], iv = init[40..56]
    //   decrypt: key/iv = first 32/16 bytes of reversed(init[8..56])
    const initRev = reverse(init.subarray(8, 56));
    this.encCtr = new AesCtr(init.subarray(8, 40), init.subarray(40, 56));
    this.decCtr = new AesCtr(initRev.subarray(0, 32), initRev.subarray(32, 48));

    // Encrypt the init tail (keystream bytes 56..64); the CTR stream then
    // continues past offset 64 for all later payloads.
    const encryptedInit = this.encCtr.crypt(init);
    const finalInit = concat(init.subarray(0, 56), encryptedInit.subarray(56, 64));

    const writer = this.socket.writable.getWriter();
    await writer.write(finalInit);
    writer.releaseLock();
    this.reader = this.socket.readable.getReader();
  }

  private sendRaw(data: Uint8Array): void {
    if (!this.socket) throw new Error("transport not connected");
    const writer = this.socket.writable.getWriter();
    void writer.write(data);
    writer.releaseLock();
  }

  /** Sends one abridged-framed MTProto payload, CTR-obfuscated. */
  send(payload: Uint8Array): void {
    if (!this.encCtr) throw new Error("transport not initialized");
    const words = payload.length / 4;
    let header: Uint8Array;
    if (words < 0x7f) {
      header = new Uint8Array([words]);
    } else {
      header = new Uint8Array([0x7f, words & 0xff, (words >>> 8) & 0xff, (words >>> 16) & 0xff]);
    }
    this.sendRaw(this.encCtr.crypt(concat(header, payload)));
  }

  /** Reads exactly one abridged-framed MTProto payload (deobfuscated). */
  async recv(timeoutMs = 30000): Promise<Uint8Array> {
    if (!this.decCtr || !this.socket) throw new Error("transport not initialized");
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const frame = this.tryParseFrame();
      if (frame) return frame;
      if (this.closed) throw new Error("transport closed");
      if (Date.now() > deadline) throw new Error(`transport read timeout (recvBuf=${this.recvBuf.length} closed=${this.closed})`);
      await this.waitMessage(deadline - Date.now());
    }
  }

  private waitMessage(ms: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const reader = this.reader;
      if (!reader) {
        reject(new Error("transport not initialized"));
        return;
      }
      let timer: ReturnType<typeof setTimeout>;
      const cleanup = () => {
        clearTimeout(timer);
      };
      timer = setTimeout(() => {
        cleanup();
        reject(new Error(`transport read timeout (recvBuf=${this.recvBuf.length} closed=${this.closed})`))
      }, Math.max(ms, 1));
      reader
        .read()
        .then((res) => {
          cleanup();
          if (res.done) {
            this.closed = true;
            reject(new Error("transport closed by peer"));
            return;
          }
          this.recvBuf = concat(this.recvBuf, this.decCtr!.crypt(res.value));
          resolve();
        })
        .catch(() => {
          cleanup();
          this.closed = true;
          reject(new Error("transport closed by peer"));
        });
    });
  }

  private tryParseFrame(): Uint8Array | null {
    const b = this.recvBuf;
    if (b.length < 1) return null;
    let headerLen: number;
    let words: number;
    if ((b[0] & 0x80) !== 0) {
      // quick-ack 4-byte packet (msb set) — skip
      if (b.length < 4) return null;
      this.recvBuf = b.subarray(4);
      return this.tryParseFrame();
    }
    if (b[0] === 0x7f) {
      if (b.length < 4) return null;
      headerLen = 4;
      words = b[1] | (b[2] << 8) | (b[3] << 16);
    } else {
      headerLen = 1;
      words = b[0];
    }
    const total = headerLen + words * 4;
    if (b.length < total) return null;
    const payload = b.subarray(headerLen, total);
    this.recvBuf = b.subarray(total);
    // transport error: signed LE int32 negative
    if (words === 1 && payload.length === 4) {
      const v = (payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)) | 0;
      if (v < 0) throw new Error(`transport error ${v}`);
    }
    return payload;
  }

  close(): void {
    this.closed = true;
    try {
      this.reader?.cancel().catch(() => undefined);
      this.socket?.close();
    } catch {
      // ignore
    }
    this.socket = null;
  }
}

export { aesIgeEncrypt, aesIgeDecrypt, xor };
