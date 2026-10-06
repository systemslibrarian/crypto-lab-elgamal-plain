import { modInverse, modPow, randomBigInt } from './modular';

/**
 * Classic ElGamal signatures (the second half of ElGamal's 1985 paper, and the
 * direct ancestor of DSA). Signatures live over the FULL group Z_p*, so the
 * generator must be a primitive root of order p-1 — distinct from the prime-order
 * subgroup used for encryption.
 *
 * WHAT THIS GROUP IS, because the input checks in `verify` depend on it and the
 * answer is different from the encryption side's:
 *
 *   p   the prime modulus. Group Z_p* has p-1 elements.
 *   n   the EXPONENT modulus, and n = p - 1 exactly. It is NOT a prime subgroup
 *       order: 2038 = 2 x 1019 is composite, which is why solveCongruence below
 *       has to handle a non-invertible coefficient at all.
 *   g   a PRIMITIVE ROOT, of order p-1, generating ALL of Z_p*. Asserted at
 *       module load against both prime factors of n.
 *
 * So there is no proper prime-order subgroup here, and no subgroup-membership
 * test to apply to a public key — only a range. The encryption side is the
 * mirror image: ElGamalGroup is a safe prime p = 2q+1 whose g generates the
 * order-q subgroup, and there `assertGroupElement` must test x^q mod p = 1.
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
  for (;;) {
    const x = randomBigInt(group.n); // in [1, n)
    const y = modPow(group.g, x, group.p);
    /* Skip the two degenerate public keys, so keygen agrees with the range
     * `verify` enforces. g is a primitive root, so y = 1 needs x = 0 (which
     * randomBigInt already excludes) and y = p-1 needs exactly x = n/2 -- one
     * value out of n-1, reachable about once every 2,037 draws in the toy
     * group. Without this, `verify`'s y check would intermittently reject a key
     * this function had just produced: a 500-iteration round-trip test goes red
     * roughly 22% of runs. Measured, not estimated. */
    if (y <= 1n || y >= group.p - 1n) continue;
    return { x, y };
  }
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
  const { p, g } = group;

  /* The group has to be usable before any verdict is possible. n = 0 or a
   * missing n is not a bad signature -- it is a question that cannot be asked,
   * and answering `false` would report "invalid signature" about an input
   * nothing examined. There is no uninitialised SignatureGroup constant in this
   * module (TOY_SIGN_GROUP is a complete literal and its generator is asserted
   * at module load), so this guards a caller-built group rather than a trap of
   * our own. Note what the old code did with n = 0: `s <= 0 || s >= 0` is true
   * for every s, so EVERY signature was silently rejected -- fail-closed by
   * accident, and indistinguishable from a verdict. */
  const n = (group as { n?: bigint }).n;
  if (typeof n !== 'bigint' || n <= 0n) {
    throw new Error(
      'Cannot verify: this signature group carries no exponent modulus n, so the ' +
        's range test would reject every signature without examining it.'
    );
  }

  /* 0 < r < p, and this one is the whole ballgame.
   *
   * r is used TWICE in the verification equation g^h = y^r * r^s (mod p): once
   * as an exponent, where it reduces mod n, and once as a base, where it
   * reduces mod p. An attacker who is allowed r >= p can choose those two
   * residues INDEPENDENTLY by CRT (gcd(p, n) = gcd(p, p-1) = 1) and satisfy the
   * equation without the private key -- Bleichenbacher, Eurocrypt 1996,
   * "Generating ElGamal signatures without knowing the secret key".
   *
   * The cheapest instance, which src/signatures.test.ts constructs and this
   * line refuses: take s = 1 and solve
   *     r = 0      (mod n)  so y^r = y^0 = 1 for ANY y, by Fermat
   *     r = g^h    (mod p)  so r^s = r = g^h
   * giving y^r * r^s = g^h exactly. It forges a signature on an arbitrary
   * message under an arbitrary public key, and s = 1 sails through the s range
   * test, so NOTHING ELSE HERE STOPS IT. */
  if (sig.r <= 0n || sig.r >= p) return false;

  /* 0 < s < n -- the exponent modulus, which for this group is p-1 (see the
   * note on SignatureGroup above), not p and not a prime subgroup order. */
  if (sig.s <= 0n || sig.s >= n) return false;

  /* y in [2, p-2]. y is raised to r on the next line and arrives from outside.
   * y = 0 is not in Z_p* at all; y = 1 and y = p-1 are the two elements of
   * order 1 and 2, the only small-order elements this group has.
   *
   * NO SUBGROUP CHECK, deliberately. g = 7 is a PRIMITIVE ROOT mod p: the
   * module-load assertion below rules out g^(n/2) = 1 and g^(n/1019) = 1, and
   * {2, 1019} are the complete prime factorisation of n = 2038, so g has order
   * exactly p-1 and generates all of Z_p*. There is therefore no proper
   * subgroup to be outside of -- every y in [2, p-2] is g^x for some x. This is
   * the opposite of the encryption side, where ElGamalGroup is a safe prime and
   * assertGroupElement must test x^q mod p = 1. Copying that test over here
   * would reject three quarters of all legitimate public keys. */
  if (y <= 1n || y >= p - 1n) return false;

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
