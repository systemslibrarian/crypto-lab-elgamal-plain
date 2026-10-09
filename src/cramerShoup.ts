import { assertGroupElement, type ElGamalGroup } from './groups';
import { modInverse, modPow, randomBigInt } from './modular';

export interface CsPublicKey {
  group: ElGamalGroup;
  g1: bigint;
  g2: bigint;
  c: bigint;
  d: bigint;
  h: bigint;
}

export interface CsSecretKey {
  x1: bigint;
  x2: bigint;
  y1: bigint;
  y2: bigint;
  z: bigint;
}

export interface CsKeyPair {
  publicKey: CsPublicKey;
  secretKey: CsSecretKey;
  /** Displayed only in the toy proof-viewpoint card; not part of a real public key. */
  proofW: bigint | null;
}

export interface CsCiphertext {
  u1: bigint;
  u2: bigint;
  e: bigint;
  v: bigint;
}

export interface CsDecryptResult {
  valid: boolean;
  message: bigint | null;
  reason: string;
  alpha: bigint | null;
  expected: bigint | null;
}

function bytes(n: bigint): Uint8Array {
  let hex = n.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return Uint8Array.from(hex.match(/../g)!.map((part) => Number.parseInt(part, 16)));
}

/** Unambiguous three-value encoding: two-byte length, then unsigned big-endian value. */
export function csHashInput(u1: bigint, u2: bigint, e: bigint): Uint8Array<ArrayBuffer> {
  const parts = [u1, u2, e].map(bytes);
  const out = new Uint8Array(new ArrayBuffer(parts.reduce((n, part) => n + part.length + 2, 0)));
  let offset = 0;
  for (const part of parts) {
    if (part.length > 65535) throw new Error('Hash input component is too long.');
    out[offset++] = part.length >> 8;
    out[offset++] = part.length & 255;
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export async function csAlpha(ct: Pick<CsCiphertext, 'u1' | 'u2' | 'e'>, group: ElGamalGroup): Promise<bigint> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', csHashInput(ct.u1, ct.u2, ct.e)));
  let value = 0n;
  for (const byte of digest) value = (value << 8n) | BigInt(byte);
  return value % group.q;
}

export function csKeygen(group: ElGamalGroup): CsKeyPair {
  if (group.q <= 2n || modPow(group.g, group.q, group.p) !== 1n) {
    throw new Error('Cramer–Shoup requires a valid prime-order subgroup.');
  }
  const w = randomBigInt(group.q);
  const g1 = group.g;
  const g2 = modPow(g1, w, group.p);
  // Uniform in Z_q, including zero. Conditional on (c,d), every one of the
  // q² compatible tuples must have equal keygen weight for the histogram.
  const scalar = () => randomBigInt(group.q + 1n) - 1n;
  const secretKey: CsSecretKey = {
    x1: scalar(), x2: scalar(),
    y1: scalar(), y2: scalar(), z: randomBigInt(group.q),
  };
  const { x1, x2, y1, y2, z } = secretKey;
  const publicKey: CsPublicKey = {
    group, g1, g2,
    c: (modPow(g1, x1, group.p) * modPow(g2, x2, group.p)) % group.p,
    d: (modPow(g1, y1, group.p) * modPow(g2, y2, group.p)) % group.p,
    h: modPow(g1, z, group.p),
  };
  return { publicKey, secretKey, proofW: group.isToy ? w : null };
}

/** Encodes an integer in [1,q] as one of {m,p-m}, whichever belongs to G. */
export function csEncodeMessage(message: bigint, group: ElGamalGroup): bigint {
  if (message < 1n || message > group.q) throw new Error(`CS message must be in [1, ${group.q}].`);
  return modPow(message, group.q, group.p) === 1n ? message : group.p - message;
}

export function csDecodeMessage(element: bigint, group: ElGamalGroup): bigint {
  if (element < 1n || element >= group.p || modPow(element, group.q, group.p) !== 1n) {
    throw new Error('Decoded CS message is not in the subgroup.');
  }
  return element < group.p - element ? element : group.p - element;
}

export async function csEncrypt(message: bigint, publicKey: CsPublicKey, r = randomBigInt(publicKey.group.q)):
  Promise<{ ciphertext: CsCiphertext; alpha: bigint; r: bigint }> {
  const { group, g1, g2, c, d, h } = publicKey;
  if (r < 1n || r >= group.q) throw new Error('CS ephemeral exponent must be in [1, q).');
  for (const [label, value] of Object.entries({ g1, g2, h })) assertGroupElement(value, group, label);
  for (const [label, value] of Object.entries({ c, d })) {
    if (value <= 0n || value >= group.p || modPow(value, group.q, group.p) !== 1n) {
      throw new Error(`Invalid ${label}: not in the order-q group.`);
    }
  }
  const encoded = csEncodeMessage(message, group);
  const u1 = modPow(g1, r, group.p);
  const u2 = modPow(g2, r, group.p);
  const e = (modPow(h, r, group.p) * encoded) % group.p;
  const alpha = await csAlpha({ u1, u2, e }, group);
  // [extension] point: the hash-free CCA1 variant uses a different check.
  const v = (modPow(c, r, group.p) * modPow(d, (r * alpha) % group.q, group.p)) % group.p;
  return { ciphertext: { u1, u2, e, v }, alpha, r };
}

/** The sole CS verdict function. Every component is checked before secret exponentiation. */
export async function csDecrypt(ct: CsCiphertext, secretKey: CsSecretKey, group: ElGamalGroup): Promise<CsDecryptResult> {
  for (const [label, value] of Object.entries(ct)) {
    if (value <= 0n || value >= group.p || modPow(value, group.q, group.p) !== 1n) {
      return { valid: false, message: null, reason: `Invalid ${label}: not an element of the order-q group.`, alpha: null, expected: null };
    }
  }
  const alpha = await csAlpha(ct, group);
  const { x1, x2, y1, y2, z } = secretKey;
  const expected = (
    modPow(ct.u1, (x1 + y1 * alpha) % group.q, group.p) *
    modPow(ct.u2, (x2 + y2 * alpha) % group.q, group.p)
  ) % group.p;
  if (expected !== ct.v) {
    return { valid: false, message: null, reason: 'Check equation failed.', alpha, expected };
  }
  const encoded = (ct.e * modInverse(modPow(ct.u1, z, group.p), group.p)) % group.p;
  return { valid: true, message: csDecodeMessage(encoded, group), reason: 'Check equation passed.', alpha, expected };
}
