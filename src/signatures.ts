import { modInverse, modPow, randomBigInt } from './modular';

/**
 * Classic ElGamal signatures (the second half of ElGamal's 1985 paper, and the
 * direct ancestor of DSA). Signatures live over the FULL group Z_p*, so the
 * generator must be a primitive root of order p-1 — distinct from the prime-order
 * subgroup used for encryption.
 */
export interface SignatureGroup {
  p: bigint;
  g: bigint; // primitive root mod p (order n)
  n: bigint; // p - 1
  label: string;
}

// p = 2039 is prime; 7 is a primitive root (verified at module load below).
export const TOY_SIGN_GROUP: SignatureGroup = {
  p: 2039n,
  g: 7n,
  n: 2038n,
  label: 'Toy signature group — p = 2039, g = 7 (primitive root), n = p-1 = 2038',
};

export interface SignKeyPair {
  x: bigint; // private
  y: bigint; // public, y = g^x mod p
}

export interface Signature {
  r: bigint;
  s: bigint;
}

export interface KeyRecovery {
  k: bigint | null;
  x: bigint | null;
}

function gcd(a: bigint, b: bigint): bigint {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b) {
    const t = a % b;
    a = b;
    b = t;
  }
  return a;
}

function mod(a: bigint, n: bigint): bigint {
  return ((a % n) + n) % n;
}

/**
 * Solve a·t ≡ b (mod n) for all t in [0, n). Because n = p-1 is composite, the
 * coefficient may not be invertible, so we handle the gcd case generally rather
 * than assuming a unique solution (the luxury DSA gets from a prime modulus).
 */
export function solveCongruence(a: bigint, b: bigint, n: bigint): bigint[] {
  a = mod(a, n);
  b = mod(b, n);
  const d = gcd(a, n);
  if (mod(b, d) !== 0n) return [];

  const aR = a / d;
  const bR = b / d;
  const nR = n / d;
  const t0 = mod(bR * modInverse(mod(aR, nR), nR), nR);

  const solutions: bigint[] = [];
  for (let i = 0n; i < d; i += 1n) {
    solutions.push(mod(t0 + i * nR, n));
  }
  return solutions;
}

export function generateSignKeyPair(group: SignatureGroup = TOY_SIGN_GROUP): SignKeyPair {
  const x = randomBigInt(group.n); // in [1, n)
  return { x, y: modPow(group.g, x, group.p) };
}

/** Sign hash value h with a caller-supplied k (exposed to demonstrate reuse). */
export function signWithK(h: bigint, x: bigint, k: bigint, group: SignatureGroup = TOY_SIGN_GROUP): Signature {
  const { p, g, n } = group;
  if (gcd(k, n) !== 1n) {
    throw new Error('k must be coprime to p-1.');
  }
  const r = modPow(g, k, p);
  const s = mod(mod(h - x * r, n) * modInverse(k, n), n);
  return { r, s };
}

export function sign(h: bigint, x: bigint, group: SignatureGroup = TOY_SIGN_GROUP): { sig: Signature; k: bigint } {
  for (;;) {
    const k = randomBigInt(group.n);
    if (gcd(k, group.n) !== 1n) continue;
    const sig = signWithK(h, x, k, group);
    if (sig.s !== 0n) return { sig, k };
  }
}

export function verify(h: bigint, sig: Signature, y: bigint, group: SignatureGroup = TOY_SIGN_GROUP): boolean {
  const { p, g, n } = group;
  if (sig.r <= 0n || sig.r >= p) return false;
  if (sig.s <= 0n || sig.s >= n) return false;

  const left = modPow(g, h, p);
  const right = (modPow(y, sig.r, p) * modPow(sig.r, sig.s, p)) % p;
  return left === right;
}

/**
 * Recover the signer's private key from two signatures that reused the same k
 * (and therefore share r). This is the catastrophic, real-world nonce-reuse
 * attack — the same flaw that exposed Sony's PS3 ECDSA signing key.
 */
export function recoverKeyFromReusedNonce(
  h1: bigint,
  s1: bigint,
  h2: bigint,
  s2: bigint,
  r: bigint,
  y: bigint,
  group: SignatureGroup = TOY_SIGN_GROUP
): KeyRecovery {
  const { p, g, n } = group;

  // (s1 - s2)·k ≡ (h1 - h2) (mod n); disambiguate candidates by g^k = r.
  const k = solveCongruence(s1 - s2, h1 - h2, n).find((cand) => modPow(g, cand, p) === r) ?? null;
  if (k === null) return { k: null, x: null };

  // r·x ≡ (h1 - s1·k) (mod n); disambiguate candidates by g^x = y.
  const x = solveCongruence(r, h1 - mod(s1 * k, n), n).find((cand) => modPow(g, cand, p) === y) ?? null;
  return { k, x };
}

// Fail loudly if the hard-coded generator is ever wrong.
if (modPow(TOY_SIGN_GROUP.g, TOY_SIGN_GROUP.n / 2n, TOY_SIGN_GROUP.p) === 1n ||
    modPow(TOY_SIGN_GROUP.g, TOY_SIGN_GROUP.n / 1019n, TOY_SIGN_GROUP.p) === 1n) {
  throw new Error('TOY_SIGN_GROUP.g is not a primitive root mod p.');
}
