import { concat, utf8, fromUtf8 } from "./bytes";

export interface TLObject {
  _id: number;
  _name?: string;
  [k: string]: unknown;
}

type Parser = (r: TLReader) => TLObject;

export class TLWriter {
  private chunks: Uint8Array[] = [];

  private push(b: Uint8Array): void {
    this.chunks.push(b);
  }

  ctor(id: number): this {
    this.push(new Uint8Array([id & 0xff, (id >>> 8) & 0xff, (id >>> 16) & 0xff, (id >>> 24) & 0xff]));
    return this;
  }

  int(v: number): this {
    this.push(new Uint8Array([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]));
    return this;
  }

  long(v: bigint): this {
    for (let i = 0; i < 8; i++) {
      this.push(new Uint8Array([Number(v & 0xffn)]));
      v >>= 8n;
    }
    return this;
  }

  double(v: number): this {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setFloat64(0, v, true);
    this.push(b);
    return this;
  }

  int128(b: Uint8Array): this {
    if (b.length !== 16) throw new Error("int128 must be 16 bytes");
    this.push(b);
    return this;
  }

  int256(b: Uint8Array): this {
    if (b.length !== 32) throw new Error("int256 must be 32 bytes");
    this.push(b);
    return this;
  }

  bool(v: boolean): this {
    return this.ctor(v ? 0x997275b5 : 0xbc799737);
  }

  string(s: string): this {
    return this.bytes(utf8(s));
  }

  bytes(b: Uint8Array): this {
    const pad = (4 - ((b.length + 1) % 4)) % 4;
    if (b.length < 254) {
      this.push(new Uint8Array([b.length]));
    } else {
      this.push(new Uint8Array([254, b.length & 0xff, (b.length >>> 8) & 0xff, (b.length >>> 16) & 0xff]));
    }
    this.push(b);
    if (pad > 0) this.push(new Uint8Array(pad));
    return this;
  }

  vector(items: Uint8Array[]): this {
    this.ctor(0x1cb5c415);
    this.int(items.length);
    for (const it of items) this.push(it);
    return this;
  }

  object(body: Uint8Array): this {
    this.push(body);
    return this;
  }

  build(): Uint8Array {
    return concat(...this.chunks);
  }
}

export class TLReader {
  private b: Uint8Array;
  private off: number;

  constructor(b: Uint8Array, off = 0) {
    this.b = b;
    this.off = off;
  }

  get offset(): number {
    return this.off;
  }

  get remaining(): number {
    return this.b.length - this.off;
  }

  ctor(): number {
    const v = (this.b[this.off] | (this.b[this.off + 1] << 8) | (this.b[this.off + 2] << 16) | (this.b[this.off + 3] << 24)) >>> 0;
    this.off += 4;
    return v;
  }

  int(): number {
    const v = (this.b[this.off] | (this.b[this.off + 1] << 8) | (this.b[this.off + 2] << 16) | (this.b[this.off + 3] << 24)) | 0;
    this.off += 4;
    return v;
  }

  long(): bigint {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(this.b[this.off + i]);
    this.off += 8;
    return v;
  }

  double(): number {
    const v = new DataView(this.b.buffer, this.b.byteOffset + this.off, 8).getFloat64(0, true);
    this.off += 8;
    return v;
  }

  int128(): Uint8Array {
    const v = this.b.slice(this.off, this.off + 16);
    this.off += 16;
    return v;
  }

  int256(): Uint8Array {
    const v = this.b.slice(this.off, this.off + 32);
    this.off += 32;
    return v;
  }

  bytes(): Uint8Array {
    let len: number;
    const first = this.b[this.off++];
    if (first === 254) {
      len = this.b[this.off] | (this.b[this.off + 1] << 8) | (this.b[this.off + 2] << 16);
      this.off += 3;
    } else {
      len = first;
    }
    const v = this.b.slice(this.off, this.off + len);
    const pad = (4 - ((len + (first === 254 ? 4 : 1)) % 4)) % 4;
    this.off += len + pad;
    return v;
  }

  string(): string {
    return fromUtf8(this.bytes());
  }

  bool(): boolean {
    const id = this.ctor();
    if (id === 0x997275b5) return true;
    if (id === 0xbc799737) return false;
    throw new Error(`invalid bool ctor 0x${id.toString(16)}`);
  }

  vector<T>(fn: (r: TLReader) => T): T[] {
    const id = this.ctor();
    if (id !== 0x1cb5c415) throw new Error(`invalid vector ctor 0x${id.toString(16)}`);
    const n = this.int();
    const out: T[] = [];
    for (let i = 0; i < n; i++) out.push(fn(this));
    return out;
  }

  object(handlers: Record<number, Parser>): TLObject {
    const id = this.ctor();
    const h = handlers[id];
    if (!h) throw new Error(`unknown ctor 0x${id.toString(16)} at offset ${this.off - 4}`);
    return h(this);
  }

  skip(n: number): void {
    this.off += n;
  }

  rest(): Uint8Array {
    return this.b.slice(this.off);
  }
}
