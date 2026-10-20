/** Deliberately broken teaching mode. Never used by the original exhibits. */
import { TOY_SIGN_GROUP } from './signatures';
import { GROUP14, type ElGamalGroup } from './groups';
import { modPow, randomBigInt, modInverse } from './modular';
export const FULL_GROUP14_G = GROUP14.p - 2n;
if (modPow(FULL_GROUP14_G, GROUP14.q, GROUP14.p) !== GROUP14.p - 1n || modPow(FULL_GROUP14_G, 2n, GROUP14.p) === 1n) {
  throw new Error('Group 14 full-group generator failed its order assertions.');
}
export function fullGroupKeygen(group: ElGamalGroup) {
  const g = group.isToy ? TOY_SIGN_GROUP.g : FULL_GROUP14_G;
  const x = randomBigInt(group.p - 1n);
  return { x, y: modPow(g, x, group.p), g };
}
export function fullGroupEncrypt(message: bigint, y: bigint, g: bigint, p: bigint) {
  if (message < 1n || message >= p) throw new Error('Message must be in [1, p-1].');
  const k = randomBigInt(p - 1n);
  return { c1: modPow(g, k, p), c2: message * modPow(y, k, p) % p };
}
export function fullGroupDecrypt(c1: bigint, c2: bigint, x: bigint, p: bigint) {
  return c2 * modInverse(modPow(c1, x, p), p) % p;
}
