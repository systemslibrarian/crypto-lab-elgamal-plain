import { modPow } from './modular';
export function legendre(a: bigint, p: bigint): -1 | 0 | 1 {
  const x = ((a % p) + p) % p;
  if (x === 0n) return 0;
  return modPow(x, (p - 1n) / 2n, p) === 1n ? 1 : -1;
}
export function encodeToSubgroup(m: bigint, p: bigint): bigint {
  const q = (p - 1n) / 2n;
  if (p % 4n !== 3n) throw new Error('Encoding requires p = 3 mod 4.');
  if (m < 1n || m > q) throw new Error('Message outside the encodable range [1, q].');
  return legendre(m, p) === 1 ? m : p - m;
}
export function decodeFromSubgroup(x: bigint, p: bigint): bigint {
  if (x < 1n || x >= p || legendre(x, p) !== 1) throw new Error('Expected a nonzero quadratic residue.');
  return x <= (p - 1n) / 2n ? x : p - x;
}
