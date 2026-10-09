import type { CsCiphertext, CsPublicKey } from './cramerShoup';
import { csAlpha, csEncodeMessage } from './cramerShoup';
import { modPow } from './modular';
import { discreteLog } from './attacks';

/** Public-data-only malformed query: the two exponents disagree. */
export function makeInvalidQuery(publicKey: CsPublicKey, r1: bigint, r2: bigint, v = 1n): CsCiphertext {
  const { group, g1, g2, h } = publicKey;
  if (r1 < 1n || r1 >= group.q || r2 < 1n || r2 >= group.q || r1 === r2) {
    throw new Error('Choose distinct r1 and r2 in [1, q).');
  }
  return {
    u1: modPow(g1, r1, group.p),
    u2: modPow(g2, r2, group.p),
    e: (csEncodeMessage(42n, group) * modPow(h, r1, group.p)) % group.p,
    v,
  };
}

export function maulCs(ct: CsCiphertext, factor: bigint, publicKey: CsPublicKey): CsCiphertext {
  const { group } = publicKey;
  if (factor < 1n || factor >= group.p || modPow(factor, group.q, group.p) !== 1n) {
    throw new Error('CS mauling factor must belong to G.');
  }
  return { ...ct, e: (ct.e * factor) % group.p };
}

export function multiplyCs(a: CsCiphertext, b: CsCiphertext, publicKey: CsPublicKey): CsCiphertext {
  const p = publicKey.group.p;
  return { u1: a.u1 * b.u1 % p, u2: a.u2 * b.u2 % p, e: a.e * b.e % p, v: a.v * b.v % p };
}

/** Deliberate toy-size second-preimage search; no secret-key input or access. */
export async function findToyAlphaCollision(ct: CsCiphertext, publicKey: CsPublicKey):
  Promise<{ forged: CsCiphertext; factor: bigint; alpha: bigint; attempts: number } | null> {
  const { group, g1 } = publicKey;
  if (!group.isToy) {
    try { discreteLog(group, publicKey.g2); }
    catch (error) { throw new Error(`Toy-size α only: ${(error as Error).message}`); }
    throw new Error('Toy-size α only: collision search refuses non-toy groups.');
  }
  const target = await csAlpha(ct, group);
  let factor = 1n;
  for (let i = 1n; i < group.q; i++) {
    factor = factor * g1 % group.p;
    const forged = maulCs(ct, factor, publicKey);
    if (await csAlpha(forged, group) === target) {
      return { forged, factor, alpha: target, attempts: Number(i) };
    }
  }
  return null;
}
