// Minimal pure-JS AES-256 (FIPS-197) with ECB block primitive, plus the
// IGE and CTR modes MTProto needs. WebCrypto has no ECB/IGE, so the block
// cipher is implemented here; SHA/PBKDF2 use WebCrypto (see hash.ts).

const SBOX = new Uint8Array(256);
const INV_SBOX = new Uint8Array(256);
{
  const rotl = (x: number, n: number): number => ((x << n) | (x >>> (8 - n))) & 0xff;
  let p = 1;
  let q = 1;
  do {
    p = (p ^ (p << 1) ^ (p & 0x80 ? 0x1b : 0)) & 0xff;
    q = (q ^ (q << 1)) & 0xff;
    q = (q ^ (q << 2)) & 0xff;
    q = (q ^ (q << 4)) & 0xff;
    if (q & 0x80) q = (q ^ 0x09) & 0xff;
    const x = (q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4)) & 0xff;
    SBOX[p] = (x ^ 0x63) & 0xff;
  } while (p !== 1);
  SBOX[0] = 0x63;
  for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;
}

const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d];

function xtime(a: number): number {
  return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;
}

function mul(a: number, b: number): number {
  let r = 0;
  let x = a;
  let y = b;
  for (let i = 0; i < 8; i++) {
    if (y & 1) r ^= x;
    x = xtime(x);
    y >>= 1;
  }
  return r & 0xff;
}

export class Aes256 {
  private roundKeys: Uint8Array; // 60 words * 4 bytes

  constructor(key: Uint8Array) {
    if (key.length !== 32) throw new Error("AES-256 key must be 32 bytes");
    const w = new Uint8Array(240);
    w.set(key, 0);
    let i = 32;
    let rconIdx = 0;
    while (i < 240) {
      let t0 = w[i - 4];
      let t1 = w[i - 3];
      let t2 = w[i - 2];
      let t3 = w[i - 1];
      if (i % 32 === 0) {
        const tmp = t0;
        t0 = SBOX[t1] ^ RCON[rconIdx++];
        t1 = SBOX[t2];
        t2 = SBOX[t3];
        t3 = SBOX[tmp];
      } else if (i % 32 === 16) {
        t0 = SBOX[t0];
        t1 = SBOX[t1];
        t2 = SBOX[t2];
        t3 = SBOX[t3];
      }
      w[i] = w[i - 32] ^ t0;
      w[i + 1] = w[i - 31] ^ t1;
      w[i + 2] = w[i - 30] ^ t2;
      w[i + 3] = w[i - 29] ^ t3;
      i += 4;
    }
    this.roundKeys = w;
  }

  private addRoundKey(s: Uint8Array, round: number): void {
    for (let i = 0; i < 16; i++) s[i] ^= this.roundKeys[round * 16 + i];
  }

  private subBytes(s: Uint8Array): void {
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
  }

  private invSubBytes(s: Uint8Array): void {
    for (let i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
  }

  private shiftRows(s: Uint8Array): void {
    // state is column-major: s[row + 4*col]
    const t = new Uint8Array(16);
    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < 4; c++) t[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
    }
    s.set(t);
  }

  private invShiftRows(s: Uint8Array): void {
    const t = new Uint8Array(16);
    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < 4; c++) t[r + 4 * c] = s[r + 4 * ((c - r + 4) % 4)];
    }
    s.set(t);
  }

  private mixColumns(s: Uint8Array): void {
    for (let c = 0; c < 4; c++) {
      const i = 4 * c;
      const a0 = s[i];
      const a1 = s[i + 1];
      const a2 = s[i + 2];
      const a3 = s[i + 3];
      s[i] = mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3;
      s[i + 1] = a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3;
      s[i + 2] = a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3);
      s[i + 3] = mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2);
    }
  }

  private invMixColumns(s: Uint8Array): void {
    for (let c = 0; c < 4; c++) {
      const i = 4 * c;
      const a0 = s[i];
      const a1 = s[i + 1];
      const a2 = s[i + 2];
      const a3 = s[i + 3];
      s[i] = mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9);
      s[i + 1] = mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13);
      s[i + 2] = mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11);
      s[i + 3] = mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14);
    }
  }

  encryptBlock(input: Uint8Array, inOff: number, output: Uint8Array, outOff: number): void {
    const s = new Uint8Array(16);
    s.set(input.subarray(inOff, inOff + 16));
    this.addRoundKey(s, 0);
    for (let round = 1; round < 14; round++) {
      this.subBytes(s);
      this.shiftRows(s);
      this.mixColumns(s);
      this.addRoundKey(s, round);
    }
    this.subBytes(s);
    this.shiftRows(s);
    this.addRoundKey(s, 14);
    output.set(s, outOff);
  }

  decryptBlock(input: Uint8Array, inOff: number, output: Uint8Array, outOff: number): void {
    const s = new Uint8Array(16);
    s.set(input.subarray(inOff, inOff + 16));
    this.addRoundKey(s, 14);
    for (let round = 13; round >= 1; round--) {
      this.invShiftRows(s);
      this.invSubBytes(s);
      this.addRoundKey(s, round);
      this.invMixColumns(s);
    }
    this.invShiftRows(s);
    this.invSubBytes(s);
    this.addRoundKey(s, 0);
    output.set(s, outOff);
  }

  encrypt(data: Uint8Array): Uint8Array {
    if (data.length % 16 !== 0) throw new Error("AES data must be multiple of 16 bytes");
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 16) this.encryptBlock(data, i, out, i);
    return out;
  }

  decrypt(data: Uint8Array): Uint8Array {
    if (data.length % 16 !== 0) throw new Error("AES data must be multiple of 16 bytes");
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 16) this.decryptBlock(data, i, out, i);
    return out;
  }
}

/** AES-256 in Infinite Garble Extension (IGE) mode, as used by MTProto. */
export function aesIgeEncrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  if (data.length % 16 !== 0) throw new Error("IGE data must be multiple of 16 bytes");
  const aes = new Aes256(key);
  const out = new Uint8Array(data.length);
  let xPrev = iv.subarray(0, 16); // x_{i-1} (plaintext of previous block for enc)
  let yPrev = iv.subarray(16, 32); // y_{i-1} (ciphertext of previous block)
  const xCur = new Uint8Array(16);
  const yCur = new Uint8Array(16);
  for (let off = 0; off < data.length; off += 16) {
    for (let i = 0; i < 16; i++) xCur[i] = data[off + i] ^ yPrev[i];
    aes.encryptBlock(xCur, 0, yCur, 0);
    for (let i = 0; i < 16; i++) out[off + i] = yCur[i] ^ xPrev[i];
    xPrev = data.subarray(off, off + 16);
    yPrev = out.subarray(off, off + 16);
  }
  return out;
}

export function aesIgeDecrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  if (data.length % 16 !== 0) throw new Error("IGE data must be multiple of 16 bytes");
  const aes = new Aes256(key);
  const out = new Uint8Array(data.length);
  // decrypt: x_i = D(y_i ^ x_{i-1}) ^ y_{i-1}, with x_{i-1} = prev plaintext, y_{i-1} = prev ciphertext
  let xPrev = iv.subarray(0, 16);
  let yPrev = iv.subarray(16, 32);
  const xCur = new Uint8Array(16);
  const yCur = new Uint8Array(16);
  for (let off = 0; off < data.length; off += 16) {
    for (let i = 0; i < 16; i++) xCur[i] = data[off + i] ^ xPrev[i];
    aes.decryptBlock(xCur, 0, yCur, 0);
    for (let i = 0; i < 16; i++) out[off + i] = yCur[i] ^ yPrev[i];
    xPrev = out.subarray(off, off + 16);
    yPrev = data.subarray(off, off + 16);
  }
  return out;
}

/** AES-256-CTR with a persistent counter state (for transport obfuscation). */
export class AesCtr {
  private aes: Aes256;
  private counter: Uint8Array; // 16 bytes, big-endian increment
  private stream: Uint8Array;
  private streamOff: number;

  constructor(key: Uint8Array, iv: Uint8Array) {
    this.aes = new Aes256(key);
    this.counter = new Uint8Array(iv);
    this.stream = new Uint8Array(0);
    this.streamOff = 0;
  }

  private nextStream(): void {
    this.stream = new Uint8Array(16);
    this.aes.encryptBlock(this.counter, 0, this.stream, 0);
    this.streamOff = 0;
    for (let i = 15; i >= 0; i--) {
      this.counter[i] = (this.counter[i] + 1) & 0xff;
      if (this.counter[i] !== 0) break;
    }
  }

  crypt(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      if (this.streamOff >= this.stream.length) this.nextStream();
      out[i] = data[i] ^ this.stream[this.streamOff++];
    }
    return out;
  }
}
