import { describe, expect, it } from 'vitest';
import { extendedGcd, isProbablePrime, modInverse, modPow, randomBigInt } from './modular';

describe('modPow', () => {
  it('matches small known values', () => {
    expect(modPow(2n, 10n, 1000n)).toBe(24n); // 1024 mod 1000
    expect(modPow(7n, 0n, 13n)).toBe(1n);
    expect(modPow(0n, 5n, 13n)).toBe(0n);
  });

  it('normalizes negative bases', () => {
    expect(modPow(-1n, 2n, 5n)).toBe(1n);
    expect(modPow(-3n, 3n, 7n)).toBe(modPow(4n, 3n, 7n));
  });

  it('satisfies Fermat: a^(p-1) ≡ 1 for prime p', () => {
    const p = 2039n;
    for (let a = 2n; a < 40n; a += 1n) {
      expect(modPow(a, p - 1n, p)).toBe(1n);
    }
  });

  it('throws on non-positive modulus', () => {
    expect(() => modPow(2n, 2n, 0n)).toThrow();
  });
});

describe('extendedGcd', () => {
  it('returns coefficients satisfying Bezout identity', () => {
    for (const [a, b] of [[240n, 46n], [17n, 5n], [2039n, 7n]] as const) {
      const { gcd, x, y } = extendedGcd(a, b);
      expect(a * x + b * y).toBe(gcd);
    }
  });
});

describe('modInverse', () => {
  it('produces a true inverse', () => {
    const m = 2039n;
    for (let a = 1n; a < 50n; a += 1n) {
      const inv = modInverse(a, m);
      expect((a * inv) % m).toBe(1n);
    }
  });

  it('throws when the inverse does not exist', () => {
    expect(() => modInverse(2n, 4n)).toThrow();
  });
});

describe('randomBigInt', () => {
  it('stays strictly within (0, max)', () => {
    const max = 1019n;
    for (let i = 0; i < 5000; i += 1) {
      const r = randomBigInt(max);
      expect(r > 0n && r < max).toBe(true);
    }
  });

  it('rejects max <= 1', () => {
    expect(() => randomBigInt(1n)).toThrow();
  });
});

describe('isProbablePrime', () => {
  it('classifies known primes and composites', () => {
    for (const prime of [2n, 3n, 13n, 1019n, 2039n]) {
      expect(isProbablePrime(prime)).toBe(true);
    }
    for (const composite of [1n, 4n, 9n, 2038n, 2040n]) {
      expect(isProbablePrime(composite)).toBe(false);
    }
  });
});
