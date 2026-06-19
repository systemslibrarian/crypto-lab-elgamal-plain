import { describe, expect, it } from 'vitest';
import { randomBigInt } from './modular';
import {
  TOY_SIGN_GROUP,
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
