import { AesCtr, aesIgeDecrypt, aesIgeEncrypt } from "./aes";
import { concat, randomBytes, reverse, xor } from "./bytes";
import { sha256 } from "./hash";

// WebSocket (WSS) endpoint names per DC. Media/CDN DCs use the same hosts.
const DC_HOSTS: Record<number, string> = {
  1: "pluto",
  2: "venus",
  3: "aurora",
  4: "vesta",
  5: "flora",
};

export function dcHost(dcId: number): string {
  const name = DC_HOSTS[Math.abs(dcId)];
  if (!name) throw new Error(`unknown DC ${dcId}`);
  return name;
}

// Fixed obfuscation "secret" used by Telegram web clients (obfuscated2 over WSS).
const OBF_SECRET = new Uint8Array(16).fill(0x99);

/**
 * Obfuscated abridged MTProto transport over a Workers outbound WebSocket.
 * The WS connection is opened via fetch with an Upgrade header (workerd
 * supports custom headers + Sec-WebSocket-Protocol this way).
 */
export class ObfuscatedWsTransport {
  private ws: WebSocket | null = null;
  private encCtr: AesCtr | null = null;
  private decCtr: AesCtr | null = null;
  private recvBuf = new Uint8Array(0);
  private closed = false;

  async connect(dcId: number): Promise<void> {
    const host = dcHost(dcId);
    const url = `https://${host}.web.telegram.org/apiws`;
    const res = await fetch(url, {
      headers: {
        Upgrade: "websocket",
        Connection: "Upgrade",
        Origin: "https://web.telegram.org",
        "Sec-WebSocket-Protocol": "binary",
      },
    });
    if (res.status !== 101 || !res.webSocket) {
      throw new Error(`WS handshake to ${url} failed: HTTP ${res.status}`);
    }
    const ws = res.webSocket;
    ws.accept();
    ws.binaryType = "arraybuffer";
    this.ws = ws;

    // Build the 64-byte obfuscated init payload (abridged protocol 0xef).
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
        firstInt === 0x20544547 || // "GET "
        firstInt === 0x4954504f || // OPTI
        firstInt === 0x02010316 ||
        (init[4] | (init[5] << 8) | (init[6] << 16) | (init[7] << 24)) === 0
      ) {
        continue;
      }
      break;
    }
    // protocol id at offset 56, padded with itself to 4 bytes: 0xef -> 0xefefefef
    init[56] = 0xef;
    init[57] = 0xef;
    init[58] = 0xef;
    init[59] = 0xef;

    const initRev = reverse(init);
    const encKey = await sha256(concat(init.subarray(8, 40), OBF_SECRET));
    const decKey = await sha256(concat(initRev.subarray(8, 40), OBF_SECRET));
    const encIv = init.subarray(40, 56);
    const decIv = initRev.subarray(40, 56);

    this.encCtr = new AesCtr(encKey, encIv);
    this.decCtr = new AesCtr(decKey, decIv);

    const encryptedInit = this.encCtr.crypt(init);
    const finalInit = concat(init.subarray(0, 56), encryptedInit.subarray(56, 64));
    this.sendRaw(finalInit);
  }

  private sendRaw(data: Uint8Array): void {
    if (!this.ws) throw new Error("transport not connected");
    this.ws.send(data);
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
    if (!this.decCtr || !this.ws) throw new Error("transport not initialized");
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const frame = this.tryParseFrame();
      if (frame) return frame;
      if (this.closed) throw new Error("transport closed");
      if (Date.now() > deadline) throw new Error("transport read timeout");
      await this.waitMessage(deadline - Date.now());
    }
  }

  private waitMessage(ms: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const ws = this.ws!;
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error("transport read timeout"));
      }, Math.max(ms, 1));
      const onMsg = (ev: MessageEvent) => {
        cleanup();
        const data = ev.data;
        const bytes = typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data as ArrayBuffer);
        this.recvBuf = concat(this.recvBuf, this.decCtr!.crypt(bytes));
        resolve();
      };
      const onClose = () => {
        cleanup();
        this.closed = true;
        reject(new Error("transport closed by peer"));
      };
      const onErr = () => {
        cleanup();
        reject(new Error("transport error"));
      };
      const cleanup = () => {
        clearTimeout(timer);
        ws.removeEventListener("message", onMsg);
        ws.removeEventListener("close", onClose);
        ws.removeEventListener("error", onErr);
      };
      ws.addEventListener("message", onMsg);
      ws.addEventListener("close", onClose);
      ws.addEventListener("error", onErr);
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
      this.ws?.close();
    } catch {
      // ignore
    }
    this.ws = null;
  }
}

export { aesIgeEncrypt, aesIgeDecrypt, xor };
