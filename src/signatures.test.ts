import { describe, expect, it } from 'vitest';
import { modPow, randomBigInt } from './modular';
import {
  TOY_SIGN_GROUP,
  type Signature,
  type SignatureGroup,
  generateSignKeyPair,
  recoverKeyFromReusedNonce,
  sign,
  signWithK,
  solveCongruence,
  verify,
} from './signatures';

const N = TOY_SIGN_GROUP.n;

describe('signature group', () => {
  it('uses a true primitive root (order p-1)', () => {
    // The module asserts this at load; re-check both prime-factor conditions.
    const { g, p, n } = TOY_SIGN_GROUP;
    // g^(n/2) != 1 and g^(n/1019) != 1  (1019 and 2 are the prime factors of n=2038)
    expect(g).toBe(7n);
    expect(p).toBe(2039n);
    expect(n).toBe(2038n);
  });
});

describe('solveCongruence', () => {
  it('returns every solution of a·t ≡ b (mod n)', () => {
    for (const [a, b] of [[6n, 4n], [4n, 8n], [1019n, 0n]] as const) {
      const sols = solveCongruence(a, b, N);
      for (const t of sols) {
        expect((((a * t) % N) + N) % N).toBe(((b % N) + N) % N);
      }
    }
  });

  it('returns empty when no solution exists', () => {
    // 2·t ≡ 1 (mod 2038) has no solution (gcd(2,2038)=2 does not divide 1).
    expect(solveCongruence(2n, 1n, N)).toEqual([]);
  });
});

describe('sign/verify', () => {
  it('accepts valid signatures', () => {
    for (let i = 0; i < 500; i += 1) {
      const keys = generateSignKeyPair();
      const h = randomBigInt(N);
      const { sig } = sign(h, keys.x);
      expect(verify(h, sig, keys.y)).toBe(true);
    }
  });

  it('rejects a signature on a different message', () => {
    for (let i = 0; i < 500; i += 1) {
      const keys = generateSignKeyPair();
      const h = randomBigInt(N);
      const { sig } = sign(h, keys.x);
      const other = h === 1n ? 2n : h - 1n;
      expect(verify(other, sig, keys.y)).toBe(false);
    }
  });

  it('rejects out-of-range signature components', () => {
    const keys = generateSignKeyPair();
    expect(verify(10n, { r: 0n, s: 5n }, keys.y)).toBe(false);
    expect(verify(10n, { r: 5n, s: N }, keys.y)).toBe(false);
  });
});

describe('nonce-reuse key recovery', () => {
  it('recovers the full private key from two signatures sharing k', () => {
    let recovered = 0;
    let attempts = 0;
    for (let i = 0; i < 1000; i += 1) {
      const keys = generateSignKeyPair();
      const h1 = randomBigInt(N);
      const h2 = randomBigInt(N);
      if (h1 === h2) continue;
      const k = randomBigInt(N);
      let s1;
      let s2;
      try {
        s1 = signWithK(h1, keys.x, k);
        s2 = signWithK(h2, keys.x, k);
      } catch {
        continue; // k not coprime to p-1
      }
      attempts += 1;
      expect(s1.r).toBe(s2.r); // shared nonce => shared r
      const { x } = recoverKeyFromReusedNonce(h1, s1.s, h2, s2.s, s1.r, keys.y);
      expect(x).toBe(keys.x);
      recovered += 1;
    }
    expect(attempts).toBeGreaterThan(100);
    expect(recovered).toBe(attempts);
  });
});

/**
 * Input validation on verify(). The group here is NOT the encryption group:
 * p is prime, n = p-1 = 2038 is the composite exponent modulus, and g = 7 is a
 * primitive root generating all of Z_p* — so there is a range to enforce and no
 * subgroup to test. See the header of signatures.ts.
 */

const { p: P, g: G } = TOY_SIGN_GROUP;

/** CRT: the unique t mod (m1*m2) with t = a1 mod m1 and t = a2 mod m2. */
function crt(a1: bigint, m1: bigint, a2: bigint, m2: bigint): bigint {
  const inv = (a: bigint, m: bigint): bigint => {
    let [old_r, r] = [((a % m) + m) % m, m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
      const q = old_r / r;
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
    }
    if (old_r !== 1n) throw new Error('not invertible');
    return ((old_s % m) + m) % m;
  };
  const M = m1 * m2;
  return (((a1 * m2 % M) * inv(m2 % m1, m1) + (a2 * m1 % M) * inv(m1 % m2, m2)) % M + M) % M;
}

describe('the signature group is the shape the checks assume', () => {
  it('n is p-1 exactly, and is composite', () => {
    expect(N).toBe(P - 1n);
    expect(N).toBe(2n * 1019n);
  });

  it('g is a primitive root: order exactly p-1, generating all of Z_p*', () => {
    // 2 and 1019 are the complete prime factorisation of n = 2038.
    expect(modPow(G, N / 2n, P)).not.toBe(1n);
    expect(modPow(G, N / 1019n, P)).not.toBe(1n);
    expect(modPow(G, N, P)).toBe(1n);
    // Therefore every element of [1, p-1] is some power of g: no proper subgroup.
    const reached = new Set<string>();
    let e = 1n;
    for (let i = 0n; i < N; i += 1n) {
      e = (e * G) % P;
      reached.add(e.toString());
    }
    expect(reached.size).toBe(Number(N));
  });

  it('only x = n/2 yields the out-of-range y = p-1, and keygen never returns it', () => {
    expect(modPow(G, N / 2n, P)).toBe(P - 1n);
    for (let i = 0; i < 3000; i += 1) {
      const { x, y } = generateSignKeyPair();
      expect(y).toBeGreaterThan(1n);
      expect(y).toBeLessThan(P - 1n);
      expect(x).not.toBe(N / 2n);
    }
  });
});

describe('verify rejects malformed inputs before any exponentiation', () => {
  /* The positive control. Without it, a verify() that returned false
     unconditionally would satisfy every rejection below. */
  it('positive control: an honest signature still verifies', () => {
    for (let i = 0; i < 200; i += 1) {
      const keys = generateSignKeyPair();
      const h = randomBigInt(N);
      const { sig } = sign(h, keys.x);
      expect(verify(h, sig, keys.y)).toBe(true);
    }
  });

  /* THE BOUNDARY TESTS HAVE TO BE NON-VACUOUS, and the first draft of them was
   * not. Feeding verify() an honest signature with one component swapped for a
   * boundary value returns false whether or not the range check exists -- the
   * verification equation simply stops holding. Mutating away the s and y
   * checks left all 47 tests green, which is a test suite that proves nothing
   * about two of the four checks it claims to cover.
   *
   * So each boundary below is reached with a WITNESS: inputs for which the
   * equation g^h = y^r * r^s (mod p) genuinely HOLDS, with the boundary value
   * as the only thing out of range. Then false can only come from the check.
   * Where no such witness exists the test says so instead of pretending. */

  const dlog = (target: bigint): bigint => {
    let e = 1n;
    for (let i = 1n; i <= N; i += 1n) {
      e = (e * G) % P;
      if (e === target % P) return i % N;
    }
    throw new Error(`no discrete log for ${target}, impossible for a primitive root`);
  };

  const equationHolds = (h: bigint, sig: Signature, y: bigint): boolean =>
    modPow(G, h, P) === (modPow(y, sig.r, P) * modPow(sig.r, sig.s, P)) % P;

  describe('boundaries reachable with a satisfying witness', () => {
    it('y = 1: r = g^h, s = 1 satisfies the equation, so only the y check refuses it', () => {
      const h = 42n;
      const sig: Signature = { r: modPow(G, h, P), s: 1n };
      // 1^r = 1, so the equation reduces to r^1 = g^h, which holds by construction.
      expect(equationHolds(h, sig, 1n)).toBe(true);
      expect(sig.r).toBeGreaterThan(0n);
      expect(sig.r).toBeLessThan(P); // r in range
      expect(verify(h, sig, 1n)).toBe(false);
    });

    it('y = p-1: an even r with s = 1 satisfies the equation, so only the y check refuses it', () => {
      // (p-1)^r = 1 for even r, so the equation again reduces to r = g^h.
      const r = 2n;
      const h = dlog(r);
      const sig: Signature = { r, s: 1n };
      expect(r % 2n).toBe(0n);
      expect(equationHolds(h, sig, P - 1n)).toBe(true);
      expect(verify(h, sig, P - 1n)).toBe(false);
    });

    it('s = 0: r^0 = 1, so h = x*r mod n satisfies the equation under a real key', () => {
      const keys = generateSignKeyPair();
      const r = 5n;
      const h = (keys.x * r) % N; // g^h = g^(x*r) = y^r
      const sig: Signature = { r, s: 0n };
      expect(equationHolds(h, sig, keys.y)).toBe(true);
      expect(verify(h, sig, keys.y)).toBe(false);
    });

    it('s = n: r^n = 1 by Fermat, so the same witness works', () => {
      const keys = generateSignKeyPair();
      const r = 5n;
      const h = (keys.x * r) % N;
      const sig: Signature = { r, s: N };
      expect(modPow(r, N, P)).toBe(1n); // Fermat, which is what makes s = n equivalent to s = 0
      expect(equationHolds(h, sig, keys.y)).toBe(true);
      expect(verify(h, sig, keys.y)).toBe(false);
    });

    it('r = p+1: r = 1 mod p and r = 2 mod n, so h = 2x mod n satisfies the equation', () => {
      const keys = generateSignKeyPair();
      const r = P + 1n;
      expect(r % P).toBe(1n);
      expect(r % N).toBe(2n);
      const h = (2n * keys.x) % N; // g^h = y^2 = y^(r mod n), and r^s = 1^s = 1
      const sig: Signature = { r, s: 1n };
      expect(equationHolds(h, sig, keys.y)).toBe(true);
      expect(sig.s).toBeGreaterThan(0n);
      expect(sig.s).toBeLessThan(N); // s in range
      expect(verify(h, sig, keys.y)).toBe(false);
    });
  });

  describe('boundaries no witness can reach, stated rather than implied', () => {
    /* r = 0, r = p and y = 0 all drive a factor of the right-hand side to zero,
       and g^h is never 0 in Z_p*. The arithmetic rejects these whatever the
       range check does, so these tests are defence-in-depth and would stay
       green if the check were deleted -- which is why they are filed here and
       not above. */
    const unreachable: Array<[string, bigint, Signature]> = [
      ['r = 0', 0n, { r: 0n, s: 5n }],
      ['r = p', 0n, { r: P, s: 5n }],
    ];

    for (const [name, , sig] of unreachable) {
      it(`${name}: refused, and the right-hand side is 0 so no witness exists`, () => {
        const keys = generateSignKeyPair();
        expect(modPow(sig.r, sig.s, P)).toBe(0n);
        for (let h = 1n; h <= 20n; h += 1n) expect(equationHolds(h, sig, keys.y)).toBe(false);
        expect(verify(10n, sig, keys.y)).toBe(false);
      });
    }

    it('y = 0: refused, and y^r = 0 so no witness exists', () => {
      const keys = generateSignKeyPair();
      const { sig } = sign(10n, keys.x);
      expect(modPow(0n, sig.r, P)).toBe(0n);
      expect(equationHolds(10n, sig, 0n)).toBe(false);
      expect(verify(10n, sig, 0n)).toBe(false);
    });
  });

  it('throws rather than returning a verdict when the group has no exponent modulus n', () => {
    const keys = generateSignKeyPair();
    const { sig } = sign(10n, keys.x);
    const noN = { p: P, g: G, label: 'broken' } as unknown as SignatureGroup;
    expect(() => verify(10n, sig, keys.y, noN)).toThrow(/no exponent modulus n/);
    const zeroN = { p: P, g: G, n: 0n, label: 'broken' } as SignatureGroup;
    expect(() => verify(10n, sig, keys.y, zeroN)).toThrow(/no exponent modulus n/);
  });
});

describe('Bleichenbacher (1996) forgery, refused by the r < p check', () => {
  /**
   * r is used twice in g^h = y^r * r^s (mod p): as an exponent, reducing mod n,
   * and as a base, reducing mod p. With r >= p allowed, the two residues can be
   * chosen INDEPENDENTLY by CRT, since gcd(p, p-1) = 1. Take s = 1 and solve
   *     r = 0    (mod n)  -> y^r = y^0 = 1 for ANY y, by Fermat
   *     r = g^h  (mod p)  -> r^s = r = g^h
   * so y^r * r^s = g^h exactly. No private key is used anywhere.
   */
  function forge(h: bigint): Signature {
    return { r: crt(modPow(G, h, P), P, 0n, N), s: 1n };
  }

  it('the forgery satisfies the verification equation for an arbitrary key and message', () => {
    for (const h of [42n, 7n, 1337n]) {
      // A victim key the forger never sees.
      const victim = generateSignKeyPair();
      const sig = forge(h);

      // It is a genuine solution of the equation verify() evaluates...
      const left = modPow(G, h, P);
      const right = (modPow(victim.y, sig.r, P) * modPow(sig.r, sig.s, P)) % P;
      expect(right).toBe(left);

      // ...and s is inside its legal range, so the s check cannot catch it.
      expect(sig.s).toBeGreaterThan(0n);
      expect(sig.s).toBeLessThan(N);

      // The ONLY thing out of bounds is r.
      expect(sig.r).toBeGreaterThanOrEqual(P);
      expect(sig.r % N).toBe(0n);
      expect(sig.r % P).toBe(left);

      // Refused.
      expect(verify(h, sig, victim.y)).toBe(false);
    }
  });

  it('it forges against ANY public key, including one with no signer at all', () => {
    const h = 99n;
    const sig = forge(h);
    for (const y of [2n, 24n, 500n, P - 2n]) {
      const left = modPow(G, h, P);
      const right = (modPow(y, sig.r, P) * modPow(sig.r, sig.s, P)) % P;
      expect(right).toBe(left); // the equation holds regardless of y
      expect(verify(h, sig, y)).toBe(false); // and is refused regardless of y
    }
  });
});

describe('h: negative refused, wide reduced', () => {
  it('a negative h is rejected by verify', () => {
    const keys = generateSignKeyPair();
    const { sig } = sign(10n, keys.x);
    expect(() => verify(-1n, sig, keys.y)).toThrow(/h must be non-negative/);
    expect(() => verify(-N, sig, keys.y)).toThrow(/h must be non-negative/);
  });

  it('a negative h is rejected by signWithK, which also takes h from outside', () => {
    const keys = generateSignKeyPair();
    expect(() => signWithK(-1n, keys.x, 3n)).toThrow(/h must be non-negative/);
  });

  it('h and h + n verify identically', () => {
    for (let i = 0; i < 100; i += 1) {
      const keys = generateSignKeyPair();
      const h = randomBigInt(N);
      const { sig } = sign(h, keys.x);
      expect(verify(h, sig, keys.y)).toBe(true);
      expect(verify(h + N, sig, keys.y)).toBe(true);
      expect(verify(h + N * 1000n, sig, keys.y)).toBe(true);
    }
  });

  it('h and h + n produce the same signature from signWithK', () => {
    const keys = generateSignKeyPair();
    const a = signWithK(42n, keys.x, 3n);
    const b = signWithK(42n + N, keys.x, 3n);
    expect(a.r).toBe(b.r);
    expect(a.s).toBe(b.s);
  });

  /* The reduction is correctness-NEUTRAL: g has order n, so
     g^h = g^(h mod n) (mod p) identically, which is exactly why reducing is
     safe. It therefore cannot be caught by a behavioural test, and the
     mutation table says so rather than pretending otherwise. What it buys is a
     bounded amount of work on an h the attacker chose. */
  it('the identity that makes reduction safe holds', () => {
    for (const h of [0n, 1n, 42n, N - 1n, N, N + 1n, N * 7n + 13n]) {
      expect(modPow(G, h, P)).toBe(modPow(G, h % N, P));
    }
  });
});

describe('h must be a bigint', () => {
  /* TypeScript stops this at compile time; a JavaScript caller is not stopped,
     and the fleet ships compiled JS. Without the typeof check this still
     throws -- `h % n` raises "Cannot mix BigInt and other types" -- so the
     assertion is on the MESSAGE, which is what distinguishes a named refusal
     from an incidental TypeError. */
  it('a number h is refused by name, not by a downstream TypeError', () => {
    const keys = generateSignKeyPair();
    const { sig } = sign(10n, keys.x);
    const notABigint = 10 as unknown as bigint;
    expect(() => verify(notABigint, sig, keys.y)).toThrow(/h must be a bigint \(got number\)/);
    expect(() => signWithK(notABigint, keys.x, 3n)).toThrow(/h must be a bigint \(got number\)/);
  });
});
