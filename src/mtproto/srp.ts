// SRP-6a 2FA (passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow)
// per https://core.telegram.org/api/srp. All bignum values are big-endian
// padded to 2048 bits when hashed/concatenated.

import { bigIntToBytes, bytesToBigInt, concat, utf8, xor } from "./bytes";
import { pbkdf2Sha512, sha256 } from "./hash";

const PAD = 256; // 2048 bits

function pad(v: bigint): Uint8Array {
  return bigIntToBytes(v, PAD);
}

function H(data: Uint8Array): Promise<Uint8Array> {
  return sha256(data);
}

function SH(data: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(salt, data, salt));
}

export interface SrpParams {
  srpId: bigint;
  srpB: Uint8Array; // g_b
  algo: { salt1: Uint8Array; salt2: Uint8Array; g: number; p: Uint8Array };
}

export async function computeSrp(params: SrpParams, password: string): Promise<{ A: Uint8Array; M1: Uint8Array }> {
  const { srpId, srpB, algo } = params;
  const p = bytesToBigInt(algo.p);
  const g = BigInt(algo.g);
  const salt1 = algo.salt1;
  const salt2 = algo.salt2;
  const gB = bytesToBigInt(srpB);

  if (gB % p === 0n) throw new Error("invalid srp_B");

  const pwd = utf8(password);
  const ph1 = await SH(await SH(pwd, salt1), salt2);
  // PH2 := SH(pbkdf2(sha512, PH1, salt1, 100000), salt2); x := int(PH2)
  const ph2 = await SH(await pbkdf2Sha512(ph1, salt1, 100000), salt2);
  const x = bytesToBigInt(ph2);
  const v = modPow(g, x, p);

  const k = bytesToBigInt(await H(concat(pad(p), pad(g))));
  const kV = (k * v) % p;

  const a = bytesToBigInt(crypto.getRandomValues(new Uint8Array(256)));
  const gA = modPow(g, a, p);
  const u = bytesToBigInt(await H(concat(pad(gA), pad(gB))));

  const t = ((gB - kV) % p + p) % p;
  const sA = modPow(t, a + u * x, p);
  const kA = await H(pad(sA));

  const hp = await H(pad(p));
  const hg = await H(pad(g));
  const M1 = await H(concat(xor(hp, hg), await H(salt1), await H(salt2), pad(gA), pad(gB), kA));

  return { A: bigIntToBytes(gA, PAD), M1 };
  void srpId;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}
