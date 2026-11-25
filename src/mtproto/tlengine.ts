// Spec-driven TL codec engine. Constructor tables live in schema.ts.

import { TLReader, TLWriter } from "./tl";

export class UnknownCtorError extends Error {
  constructor(
    public id: number,
    public typeKey: string,
  ) {
    super(`unknown ctor 0x${id.toString(16)} for ${typeKey}`);
    this.name = "UnknownCtorError";
  }
}

export type Kind =
  | "int"
  | "long"
  | "double"
  | "string"
  | "bytes"
  | "bool"
  | "int128"
  | "int256"
  | "true"
  | { vec: Kind }
  | { obj: string };

export interface Field {
  n: string;
  k: Kind;
  bit?: number;
  f2?: boolean; // bit belongs to flags2 word
}

export interface CtorDef {
  id: number;
  name: string;
  type: string;
  fields: Field[];
}

export const TYPES: Record<string, Record<number, CtorDef>> = {};
export const BY_NAME: Record<string, CtorDef> = {};

export function def(typeKey: string, name: string, id: number, fields: Field[]): CtorDef {
  const d: CtorDef = { id, name, type: typeKey, fields };
  (TYPES[typeKey] ??= {})[id] = d;
  BY_NAME[name] = d;
  return d;
}

export const F = (n: string, k: Kind, bit?: number, f2?: boolean): Field => ({ n, k, bit, f2 });
export const vec = (k: Kind): Kind => ({ vec: k });
export const obj = (t: string): Kind => ({ obj: t });

export function parseKind(k: Kind, r: TLReader, flags: number, flags2: number): unknown {
  if (typeof k === "string") {
    switch (k) {
      case "int": return r.int();
      case "long": return r.long();
      case "double": return r.double();
      case "string": return r.string();
      case "bytes": return r.bytes();
      case "bool": return r.bool();
      case "int128": return r.int128();
      case "int256": return r.int256();
      case "true": return true;
    }
  }
  if ("vec" in k) {
    const id = r.ctor();
    if (id !== 0x1cb5c415) throw new Error(`invalid vector ctor 0x${id.toString(16)}`);
    const n = r.int();
    const items: unknown[] = [];
    for (let i = 0; i < n; i++) items.push(parseKind(k.vec, r, flags, flags2));
    return items;
  }
  return parseObj(k.obj, r);
}

export function parseObj(typeKey: string, r: TLReader): Record<string, unknown> {
  const id = r.ctor();
  const table = typeKey === "Object" ? ANY : TYPES[typeKey];
  const d = table?.[id];
  if (!d) throw new UnknownCtorError(id, typeKey);
  const out: Record<string, unknown> = { _id: id, _name: d.name };
  let flags = 0;
  let flags2 = 0;
  for (const f of d.fields) {
    if (f.n === "flags") {
      flags = r.int();
      out.flags = flags;
      continue;
    }
    if (f.n === "flags2") {
      flags2 = r.int();
      out.flags2 = flags2;
      continue;
    }
    if (f.bit !== undefined) {
      const src = f.f2 ? flags2 : flags;
      if (((src >>> f.bit) & 1) === 0) continue;
    }
    out[f.n] = parseKind(f.k, r, flags, flags2);
  }
  return out;
}

export function writeKind(k: Kind, w: TLWriter, v: unknown): void {
  if (typeof k === "string") {
    switch (k) {
      case "int": w.int(v as number); return;
      case "long": w.long(v as bigint); return;
      case "double": w.double(v as number); return;
      case "string": w.string(v as string); return;
      case "bytes": w.bytes(v as Uint8Array); return;
      case "bool": w.bool(v as boolean); return;
      case "int128": w.int128(v as Uint8Array); return;
      case "int256": w.int256(v as Uint8Array); return;
      case "true": w.ctor(0x997275b5); return;
    }
  }
  if ("vec" in k) {
    const items = v as unknown[];
    w.ctor(0x1cb5c415);
    w.int(items.length);
    for (const it of items) writeKind(k.vec, w, it);
    return;
  }
  w.object(serializeNamedByDef(k.obj, v as Record<string, unknown>));
}

function serializeNamedByDef(typeKey: string, v: Record<string, unknown>): Uint8Array {
  const name = v._name as string | undefined;
  if (!name || !BY_NAME[name]) throw new Error(`cannot serialize ${typeKey}: missing _name`);
  return serializeDef(BY_NAME[name], v);
}

export function serializeNamed(name: string, v: Record<string, unknown>): Uint8Array {
  const d = BY_NAME[name];
  if (!d) throw new Error(`unknown ctor/method ${name}`);
  return serializeDef(d, { _name: name, ...v });
}

function serializeDef(d: CtorDef, v: Record<string, unknown>): Uint8Array {
  const w = new TLWriter();
  w.ctor(d.id);
  let flags = 0;
  let flags2 = 0;
  for (const f of d.fields) {
    if (f.n === "flags" || f.n === "flags2" || f.bit === undefined) continue;
    const val = v[f.n];
    if (val === undefined || val === false || val === null) continue;
    if (f.f2) flags2 |= 1 << f.bit;
    else flags |= 1 << f.bit;
  }
  let wroteFlags = false;
  let wroteFlags2 = false;
  for (const f of d.fields) {
    if (f.n === "flags") {
      w.int(flags);
      wroteFlags = true;
      continue;
    }
    if (f.n === "flags2") {
      w.int(flags2);
      wroteFlags2 = true;
      continue;
    }
    if (f.bit !== undefined) {
      const val = v[f.n];
      if (val === undefined || val === false || val === null) continue;
    }
    writeKind(f.k, w, v[f.n]);
  }
  void wroteFlags;
  void wroteFlags2;
  return w.build();
}

export const ANY: Record<number, CtorDef> = {};

export function buildAny(): void {
  for (const table of Object.values(TYPES)) Object.assign(ANY, table);
}
