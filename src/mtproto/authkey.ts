// MTProto authorization-key (DH) handshake: req_pq_multi -> req_DH_params ->
// set_client_DH_params, with RSA_PAD proof-of-work. BigInt modexp for RSA,
// Pollard-rho for pq factorization.

import { Aes256, aesIgeEncrypt } from "./aes";
import { bigIntToBytes, bytesToBigInt, concat, fromHex, randomBytes, reverse, xor, hex } from "./bytes";
import { sha1, sha256 } from "./hash";
import { TLReader, TLWriter } from "./tl";
import { parseObj, serializeNamed } from "./tlengine";
import "./schema";

// Telegram server RSA public keys (modulus, exponent) — from tweb/tdlib.
// Fingerprint = low 64 bits of SHA1(TL-serialized rsa_public_key).
export const RSA_KEYS: { n: bigint; e: bigint; fingerprint: bigint }[] = [
  "e8bb3305c0b52c6cf2afdf7637313489e63e05268e5badb601af417786472e5f93b85438968e20e6729a301c0afc121bf7151f834436f7fda680847a66bf64accec78ee21c0b316f0edafe2f41908da7bd1f4a5107638eeb67040ace472a14f90d9f7c2b7def99688ba3073adb5750bb02964902a359fe745d8170e36876d4fd8a5d41b2a76cbff9a13267eb9580b2d06d10357448d20d9da2191cb5d8c93982961cdfdeda629e37f1fb09a0722027696032fe61ed663db7a37f6f263d370f69db53a0dc0a1748bdaaff6209d5645485e6e001d1953255757e4b8e42813347b11da6ab500fd0ace7e6dfa3736199ccaf9397ed0745a427dcfa6cd67bcb1acff3",
  "c150023e2f70db7985ded064759cfecf0af328e69a41daf4d6f01b538135a6f91f8f8b2a0ec9ba9720ce352efcf6c5680ffc424bd634864902de0b4bd6d49f4e580230e3ae97d95c8b19442b3c0a10d8f5633fecedd6926a7f6dab0ddb7d457f9ea81b8465fcd6fffeed114011df91c059caedaf97625f6c96ecc74725556934ef781d866b34f011fce4d835a090196e9a5f0e4449af7eb697ddb9076494ca5f81104a305b6dd27665722c46b60e5df680fb16b210607ef217652e60236c255f6a28315f4083a96791d7214bf64c1df4fd0db1944fb26a2a57031b32eee64ad15a8ba68885cde74a5bfc920f6abf59ba5c75506373e7130f9042da922179251f",
  "aeec36c8ffc109cb099624685b97815415657bd76d8c9c3e398103d7ad16c9bba6f525ed0412d7ae2c2de2b44e77d72cbf4b7438709a4e646a05c43427c7f184debf72947519680e651500890c6832796dd11f772c25ff8f576755afe055b0a3752c696eb7d8da0d8be1faf38c9bdd97ce0a77d3916230c4032167100edd0f9e7a3a9b602d04367b689536af0d64b613ccba7962939d3b57682beb6dae5b608130b2e52aca78ba023cf6ce806b1dc49c72cf928a7199d22e3d7ac84e47bc9427d0236945d10dbd15177bab413fbf0edfda09f014c7a7da088dde9759702ca760af2b8e4e97cc055c617bd74c3d97008635b98dc4d621b4891da9fb0473047927",
  "bdf2c77d81f6afd47bd30f29ac76e55adfe70e487e5e48297e5a9055c9c07d2b93b4ed3994d3eca5098bf18d978d54f8b7c713eb10247607e69af9ef44f38e28f8b439f257a11572945cc0406fe3f37bb92b79112db69eedf2dc71584a661638ea5becb9e23585074b80d57d9f5710dd30d2da940e0ada2f1b878397dc1a72b5ce2531b6f7dd158e09c828d03450ca0ff8a174deacebcaa22dde84ef66ad370f259d18af806638012da0ca4a70baa83d9c158f3552bc9158e69bf332a45809e1c36905a5caa12348dd57941a482131be7b2355a5f4635374f3bd3ddf5ff925bf4809ee27c1e67d9120c5fe08a9de458b1b4a3c5d0a428437f2beca81f4e2d5ff",
  "b3f762b739be98f343eb1921cf0148cfa27ff7af02b6471213fed9daa0098976e667750324f1abcea4c31e43b7d11f1579133f2b3d9fe27474e462058884e5e1b123be9cbbc6a443b2925c08520e7325e6f1a6d50e117eb61ea49d2534c8bb4d2ae4153fabe832b9edf4c5755fdd8b19940b81d1d96cf433d19e6a22968a85dc80f0312f596bd2530c1cfb28b5fe019ac9bc25cd9c2a5d8f0f3a1c0c79bcca524d315b5e21b5c26b46babe3d75d06d1cd33329ec782a0f22891ed1db42a1ff0ebf7f2b21afb6b1ff5c9e5e8a8c9d",
  "be6a71558ee577ff03023cfa17aab4e6c86383cff8a7ad38edb9fafe6f323f2d5106cbc8cafb83b869cffd1ccf121cd743d509e589e68765c96601e813dc5b9dfc4be415c7a6526132d0035ca33d6d6075d4f535122a1cdfe017041f1088d1419f65c8e5490ee613e16dbf662698c0f54870f0475fa893fc41eb55b08ff1ac211bc045ded31be27d12c96d8d3cfc6a7ae8aa50bf2ee0f30ed507cc2581e3dec56de94f5dc0a7abee0be990b893f2887bd2c6310a1e0a9e3e38bd34fded2541508dc102a9c9b4c95effd9dd2dfe96c29be647d6c69d66ca500843cfaed6e440196f1dbe0e2e22163c61ca48c79116fa77216726749a976a1c4b0944b5121e8c01",
].map((m) => {
  const n = bytesToBigInt(fromHex(m));
  const e = 65537n;
  return { n, e, fingerprint: 0n };
});

// compute fingerprints lazily (async sha1)
export async function rsaKeyFingerprints(): Promise<Map<string, { n: bigint; e: bigint }>> {
  const map = new Map<string, { n: bigint; e: bigint }>();
  for (const k of RSA_KEYS) {
    const w = new TLWriter();
    w.bytes(bigIntToBytes(k.n));
    w.bytes(bigIntToBytes(k.e));
    const h = await sha1(w.build());
    // low 64 bits, as LE-stored long
    const fpBytes = h.slice(-8);
    let fp = 0n;
    for (let i = 7; i >= 0; i--) fp = (fp << 8n) | BigInt(fpBytes[i]);
    map.set(fp.toString(16).padStart(16, "0"), { n: k.n, e: k.e });
    k.fingerprint = fp;
  }
  return map;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  if (b < 0n) b += mod;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

/** RSA_PAD as specified in MTProto auth_key docs. */
export async function rsaPad(data: Uint8Array, key: { n: bigint; e: bigint }): Promise<Uint8Array> {
  if (data.length > 144) throw new Error("RSA_PAD data too long");
  const nBytes = 256;
  for (;;) {
    const dataWithPadding = concat(data, randomBytes(192 - data.length));
    const dataPadReversed = reverse(dataWithPadding);
    const tempKey = randomBytes(32);
    const dataWithHash = concat(dataPadReversed, await sha256(concat(tempKey, dataWithPadding)));
    const aesEncrypted = aesIgeEncrypt(dataWithHash, tempKey, new Uint8Array(32));
    const tempKeyXor = xor(tempKey, await sha256(aesEncrypted));
    const keyAesEncrypted = concat(tempKeyXor, aesEncrypted);
    const m = bytesToBigInt(keyAesEncrypted);
    if (m >= key.n) continue;
    const c = modPow(m, key.e, key.n);
    return bigIntToBytes(c, nBytes);
  }
}

/** Factor pq (two primes, p < q) with Pollard-rho. */
export function factorPq(pq: bigint): [bigint, bigint] {
  if (pq % 2n === 0n) return [2n, pq / 2n];
  let x = 2n + (pq % 1000n);
  let y = x;
  let c = 1n + (pq % 997n);
  let d = 1n;
  const f = (v: bigint) => (v * v + c) % pq;
  while (d === 1n) {
    x = f(x);
    y = f(f(y));
    d = gcd(x > y ? x - y : y - x, pq);
  }
  if (d === pq) throw new Error("pq factorization failed");
  const p = d;
  const q = pq / d;
  return p < q ? [p, q] : [q, p];
}

function gcd(a: bigint, b: bigint): bigint {
  while (b !== 0n) {
    const t = a % b;
    a = b;
    b = t;
  }
  return a;
}

export interface AuthKeyResult {
  authKey: Uint8Array; // 256 bytes
  authKeyId: Uint8Array; // 8 bytes (low 64 of SHA1)
  serverSalt: Uint8Array; // 8 bytes
  dcId: number;
  serverTime: number;
}

/** Performs the full auth-key handshake over a transport that can send/receive
 *  unencrypted MTProto messages (auth_key_id = 0). sendUnencrypted(body) must
 *  return the parsed response object. */
export async function createAuthKey(
  dcId: number,
  sendUnencrypted: (body: Uint8Array) => Promise<Record<string, unknown>>,
): Promise<AuthKeyResult> {
  const nonce = randomBytes(16);
  const resPQ = await sendUnencrypted(serializeNamed("req_pq_multi", { nonce }));
  if (resPQ._name !== "resPQ") throw new Error(`expected resPQ, got ${resPQ._name}`);
  const pq = bytesToBigInt(resPQ.pq as Uint8Array);
  const serverNonce = resPQ.server_nonce as Uint8Array;
  const fingerprints = resPQ.fingerprints as bigint[];
  const keys = await rsaKeyFingerprints();
  let key: { n: bigint; e: bigint } | undefined;
  let fingerprint = 0n;
  for (const fp of fingerprints) {
    const hexStr = (fp < 0n ? fp + (1n << 64n) : fp).toString(16).padStart(16, "0");
    const k = keys.get(hexStr);
    if (k) {
      key = k;
      fingerprint = fp;
      break;
    }
  }
  if (!key) throw new Error("no matching RSA key for fingerprints " + fingerprints.map((f) => f.toString(16)).join(","));

  const [p, q] = factorPq(pq);
  const newNonce = randomBytes(32);
  const pqInner = serializeNamed("p_q_inner_data_dc", {
    pq: resPQ.pq,
    p: bigIntToBytes(p),
    q: bigIntToBytes(q),
    nonce,
    server_nonce: serverNonce,
    new_nonce: newNonce,
    dc: dcId,
  });
  const encryptedData = await rsaPad(pqInner, key);
  const reqDH = await sendUnencrypted(
    serializeNamed("req_DH_params", {
      nonce,
      server_nonce: serverNonce,
      p: bigIntToBytes(p),
      q: bigIntToBytes(q),
      public_key_fingerprint: fingerprint,
      encrypted_data: encryptedData,
    }),
  );
  if (reqDH._name !== "server_DH_params_ok") throw new Error(`expected server_DH_params_ok, got ${reqDH._name}`);

  // decrypt answer
  const newNonceBig = bytesToBigInt(newNonce);
  const serverNonceBig = bytesToBigInt(serverNonce);
  const h1 = await sha1(concat(newNonce, serverNonce));
  const h2 = await sha1(concat(serverNonce, newNonce));
  const h3 = await sha1(concat(newNonce, newNonce));
  const tmpAesKey = concat(h1, h2.subarray(0, 12));
  const tmpAesIv = concat(h2.subarray(12, 20), h3, newNonce.subarray(0, 4));
  const { aesIgeDecrypt } = await import("./aes");
  const answerWithHash = aesIgeDecrypt(reqDH.encrypted_answer as Uint8Array, tmpAesKey, tmpAesIv);
  const hash = answerWithHash.subarray(0, 20);
  const answerBytes = answerWithHash.subarray(20);
  // strip padding to multiple of 16
  const r = new TLReader(answerBytes);
  const inner = parseObj("Handshake", r);
  if (inner._name !== "server_DH_inner_data") throw new Error(`expected server_DH_inner_data, got ${inner._name}`);
  const g = inner.g as number;
  const dhPrime = bytesToBigInt(inner.dh_prime as Uint8Array);
  const gA = bytesToBigInt(inner.g_a as Uint8Array);
  const serverTime = inner.server_time as number;
  void hash;

  // sanity checks (light): 1 < g < p-1, 1 < g_a < p-1
  if (!(g > 1 && g < Number.MAX_SAFE_INTEGER)) throw new Error("bad g");
  if (!(gA > 1n && gA < dhPrime - 1n)) throw new Error("bad g_a");

  const b = bytesToBigInt(randomBytes(256));
  const gB = modPow(BigInt(g), b, dhPrime);
  const clientDH = serializeNamed("client_DH_inner_data", {
    nonce,
    server_nonce: serverNonce,
    retry_id: 0n,
    g_b: bigIntToBytes(gB),
  });
  const dataWithHash = concat(await sha1(clientDH), clientDH);
  const padLen = (16 - (dataWithHash.length % 16)) % 16;
  const padded = concat(dataWithHash, randomBytes(padLen));
  const encClient = aesIgeEncrypt(padded, tmpAesKey, tmpAesIv);
  const setClient = await sendUnencrypted(
    serializeNamed("set_client_DH_params", { nonce, server_nonce: serverNonce, encrypted_data: encClient }),
  );
  if (setClient._name !== "dh_gen_ok") throw new Error(`dh_gen failed: ${setClient._name}`);

  const authKeyBig = modPow(gA, b, dhPrime);
  const authKey = bigIntToBytes(authKeyBig, 256);
  const authKeyHash = await sha1(authKey);
  const authKeyId = authKeyHash.slice(-8);
  // server_salt = substr(new_nonce,0,8) XOR substr(server_nonce,0,8)
  const serverSalt = xor(newNonce.subarray(0, 8), serverNonce.subarray(0, 8));
  void newNonceBig;
  void serverNonceBig;
  return { authKey, authKeyId, serverSalt, dcId, serverTime };
}

export function authKeyIdHex(authKey: Uint8Array): string {
  return hex(authKey);
}

export { modPow, Aes256 };
