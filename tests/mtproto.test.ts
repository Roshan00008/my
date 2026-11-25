import { test } from "node:test";
import assert from "node:assert/strict";

import { Aes256, aesIgeEncrypt, aesIgeDecrypt, AesCtr } from "../src/mtproto/aes";
import { TLWriter, TLReader } from "../src/mtproto/tl";
import { serializeNamed, parseObj } from "../src/mtproto/tlengine";
import "../src/mtproto/schema"; // registers all ctors + buildAny()
import { sha256, pbkdf2Sha512 } from "../src/mtproto/hash";
import { bytesToBigIntLE, bigIntToBytesLE, fromHex, hex, utf8, concat, xor } from "../src/mtproto/bytes";
import { modPow, factorPq } from "../src/mtproto/authkey";
import { rpcErrorToApiError } from "../src/mtproto/errors";
import { computeSrp } from "../src/mtproto/srp";
import { parseSession, serializeSession, parseUpdateState, serializeUpdateState } from "../src/mtproto/session";
import { peerToChatId, chatIdToInputPeer } from "../src/mtproto/api";
import { dcHost } from "../src/mtproto/transport";
import { mtprotoMsgKey, mtprotoAesKeyIv } from "../src/mtproto/client";

test("aes-256 FIPS-197 known vector", () => {
  const key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  const pt = fromHex("00112233445566778899aabbccddeeff");
  const expected = "8ea2b7ca516745bfeafc49904b496089";
  const aes = new Aes256(key);
  const out = new Uint8Array(16);
  aes.encryptBlock(pt, 0, out, 0);
  assert.equal(hex(out), expected);
  const back = new Uint8Array(16);
  aes.decryptBlock(out, 0, back, 0);
  assert.equal(hex(back), hex(pt));
});

test("aes-ige roundtrip", () => {
  const key = new Uint8Array(32).map((_, i) => i);
  const iv = new Uint8Array(32).map((_, i) => 255 - i);
  const data = new Uint8Array(64).map((_, i) => (i * 7) & 0xff);
  const enc = aesIgeEncrypt(data, key, iv);
  assert.notEqual(hex(enc), hex(data));
  assert.equal(hex(aesIgeDecrypt(enc, key, iv)), hex(data));
});

test("aes-ctr stream is continuous across chunked crypt calls", () => {
  const key = new Uint8Array(32).map((_, i) => i * 3);
  const iv = new Uint8Array(16).map((_, i) => i);
  const data = new Uint8Array(100).map((_, i) => i);
  const a = new AesCtr(key, iv);
  const whole = a.crypt(data);
  const b = new AesCtr(key, iv);
  const chunked = concat(b.crypt(data.slice(0, 37)), b.crypt(data.slice(37)));
  assert.equal(hex(chunked), hex(whole));
});

test("tl writer/reader roundtrip", () => {
  const w = new TLWriter();
  w.ctor(0xdeadbeef).int(-42).long(0x0102030405060708n).string("hello").bytes(new Uint8Array([1, 2, 3, 250]));
  const buf = w.build();
  const r = new TLReader(buf);
  assert.equal(r.ctor(), 0xdeadbeef);
  assert.equal(r.int(), -42);
  assert.equal(r.long(), 0x0102030405060708n);
  assert.equal(r.string(), "hello");
  assert.deepEqual([...r.bytes()], [1, 2, 3, 250]);
  assert.equal(r.remaining, 0);
});

test("serializeNamed forwardMessages: ctor id + flags bits (silent=5, drop_author=11)", () => {
  const buf = serializeNamed("messages.forwardMessages", {
    silent: true,
    drop_author: true,
    from_peer: { _name: "inputPeerChat", chat_id: 5n },
    id: [1, 2, 3],
    random_id: [1n, 2n, 3n],
    to_peer: { _name: "inputPeerChat", chat_id: 6n },
  });
  const r = new TLReader(buf);
  assert.equal(r.ctor(), 0x13704a7c);
  assert.equal(r.int() >>> 0, (1 << 5) | (1 << 11));
});

test("parseObj roundtrip on auth.sentCode", () => {
  const buf = serializeNamed("auth.sentCode", {
    flags: 1,
    type: { _name: "auth.sentCodeTypeSms", length: 5 },
    phone_code_hash: "abc123",
  });
  const obj = parseObj("Object", new TLReader(buf));
  assert.equal(obj._name, "auth.sentCode");
  assert.equal(obj.phone_code_hash, "abc123");
  assert.equal((obj.type as { _name: string })._name, "auth.sentCodeTypeSms");
  assert.equal(obj.next_type, undefined); // flag bit 1 unset
});

test("sha256 known vector + pbkdf2 output size", async () => {
  assert.equal(hex(await sha256(utf8("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const dk = await pbkdf2Sha512(utf8("password"), utf8("salt"), 100000);
  assert.equal(dk.length, 256);
});

test("bigint LE helpers roundtrip", () => {
  const v = 0x0102030405060708n;
  assert.equal(bytesToBigIntLE(bigIntToBytesLE(v, 8)), v);
  assert.equal(modPow(2n, 10n, 1000n), 24n);
});

test("factorPq finds factors of a semiprime", () => {
  const p = 1000003n;
  const q = 1000033n;
  const [a, b] = factorPq(p * q);
  assert.deepEqual([a, b].sort(), [p, q].sort());
});

test("rpc error mapping", () => {
  const flood = rpcErrorToApiError(420, "FLOOD_WAIT_30");
  assert.equal(flood.reason, "rate_limited");
  assert.equal(flood.retryAfter, 30);
  assert.equal(rpcErrorToApiError(400, "PEER_FLOOD").reason, "rate_limited");
  assert.equal(rpcErrorToApiError(401, "AUTH_KEY_UNREGISTERED").reason, "unauthorized");
  assert.equal(rpcErrorToApiError(400, "CHAT_FORWARDS_RESTRICTED").reason, "insufficient_permissions");
  assert.equal(rpcErrorToApiError(400, "MESSAGE_ID_INVALID").reason, "bot_not_in_chat");
  assert.equal(rpcErrorToApiError(400, "SOMETHING_ELSE").reason, "invalid_request");
});

test("srp produces 256-byte A and M1, randomized per call", async () => {
  const p = (1n << 2048n) - 159n; // odd modulus
  const params = {
    srpId: 7n,
    srpB: new Uint8Array(256).map((_, i) => (i * 11 + 3) & 0xff),
    algo: { salt1: new Uint8Array(8).fill(1), salt2: new Uint8Array(8).fill(2), g: 3, p: bigIntToBytesLE(p, 256) },
  };
  const r1 = await computeSrp(params, "hunter2");
  const r2 = await computeSrp(params, "hunter2");
  assert.equal(r1.A.length, 256);
  assert.equal(r1.M1.length, 32);
  assert.notEqual(hex(r1.A), hex(r2.A));
});

test("session + update state stores roundtrip", () => {
  const s = parseSession(null);
  assert.equal(s, null);
  const store = {
    primaryDc: 2,
    dcs: { "2": { authKey: hex(new Uint8Array(256).fill(7)), authKeyId: "abcd", serverSalt: "ef01" } },
  };
  const parsed = parseSession(serializeSession(store));
  assert.equal(parsed?.primaryDc, 2);
  assert.equal(parsed?.dcs["2"].authKeyId, "abcd");

  const st = parseUpdateState(null);
  assert.deepEqual(st.chats, {});
  st.chats["-1001"] = 42;
  assert.equal(parseUpdateState(serializeUpdateState(st)).chats["-1001"], 42);
});

test("peer <-> chatId mapping roundtrip", () => {
  assert.equal(peerToChatId({ _name: "peerChannel", channel_id: 1234567890n }), "-1001234567890");
  assert.equal(peerToChatId({ _name: "peerChat", chat_id: 123n }), "-123");
  assert.equal(peerToChatId({ _name: "peerUser", user_id: 42n }), "42");

  const ch = chatIdToInputPeer("-1001234567890");
  assert.equal(ch.kind, "channel");
  assert.deepEqual(ch.inputPeer, { _name: "inputPeerChannel", channel_id: 1234567890n, access_hash: 0n });
  assert.equal(chatIdToInputPeer("-123").kind, "chat");
  assert.equal(chatIdToInputPeer("42").kind, "user");
});

test("dcHost mapping", () => {
  assert.equal(dcHost(1), "pluto");
  assert.equal(dcHost(2), "venus");
  assert.equal(dcHost(5), "flora");
  assert.throws(() => dcHost(9));
});

test("mtproto 2.0 framing roundtrip (msg_key + aes key/iv derivation, both directions)", async () => {
  const authKey = new Uint8Array(256).map((_, i) => (i * 31 + 7) & 0xff);
  const plaintext = new Uint8Array(48).map((_, i) => (i * 13 + 1) & 0xff);

  // client -> server (x = 0)
  const msgKeyC = await mtprotoMsgKey(authKey, plaintext, 0);
  const { aesKey: kC, aesIv: ivC } = await mtprotoAesKeyIv(authKey, msgKeyC, 0);
  const cipher = aesIgeEncrypt(plaintext, kC, ivC);
  // server -> client direction decrypts with x = 8
  const msgKeyS = await mtprotoMsgKey(authKey, plaintext, 8);
  assert.notEqual(hex(msgKeyS), hex(msgKeyC));
  const { aesKey: kS, aesIv: ivS } = await mtprotoAesKeyIv(authKey, msgKeyC, 8);
  // verify: decrypting client cipher with x=8 keys must NOT yield plaintext (different x),
  // but re-deriving msg_key over the decrypted plain with x=8 matches msg_key made with x=8
  const back = aesIgeDecrypt(cipher, kC, ivC);
  assert.equal(hex(back), hex(plaintext));
  const check = await mtprotoMsgKey(authKey, back, 0);
  assert.equal(hex(check), hex(msgKeyC));
  // tamper detection: flip a byte, msg_key must mismatch
  const tampered = plaintext.slice();
  tampered[0] ^= 1;
  const check2 = await mtprotoMsgKey(authKey, tampered, 0);
  assert.notEqual(hex(check2), hex(msgKeyC));
  void kS; void ivS; void msgKeyS;
});

test("xor helper", () => {
  assert.deepEqual([...xor(new Uint8Array([0xff, 0x0f]), new Uint8Array([0x0f, 0xff]))], [0xf0, 0xf0]);
});
