import { concat } from "./bytes";

export async function sha1(data: Uint8Array): Promise<Uint8Array> {
  const h = await crypto.subtle.digest("SHA-1", data as BufferSource);
  return new Uint8Array(h);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const h = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return new Uint8Array(h);
}

export async function pbkdf2Sha512(password: Uint8Array, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  // 2048-bit output, matching tdlib/gotd SRP implementations.
  const key = await crypto.subtle.importKey("raw", password as BufferSource, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-512", salt: salt as BufferSource, iterations },
    key,
    2048,
  );
  return new Uint8Array(bits);
}

export function sha256SyncSeed(parts: Uint8Array[]): Promise<Uint8Array> {
  return sha256(concat(...parts));
}
