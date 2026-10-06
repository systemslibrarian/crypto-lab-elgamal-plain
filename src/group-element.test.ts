import { describe, expect, it } from 'vitest';
import { authDecrypt, authEncrypt } from './authenticated';
import { decrypt, encrypt, encryptWithEphemeral, generateKeyPair, rerandomize } from './elgamal';
import { assertGroupElement, GROUP14, RFC3526_GROUP14, TOY_GROUP, type ElGamalGroup } from './groups';
import { modPow } from './modular';

/**
 * Every value an attacker can put in c1 or in a public key, and the proof that
 * each is refused before the private key touches it.
 *
 * The two that matter are not edge cases:
 *
 *   c1 = 1      the shared secret is 1^x = 1 for every x, so an attacker who
 *               never saw the key can derive the HMAC key and forge a tag.
 *   c1 = p - 1  the shared secret is (-1)^x, so whether the recipient accepts
 *               depends on x mod 2 and the accept/reject outcome alone leaks a
 *               bit of the private key.
 */

/** The smallest element outside the prime-order subgroup, by search. */
function firstNonSubgroupElement(group: ElGamalGroup): bigint {
  for (let x = 2n; x < group.p - 1n; x += 1n) {
    if (modPow(x, group.q, group.p) !== 1n) return x;
  }
  throw new Error('no non-subgroup element found, which cannot happen in a safe-prime group');
}

const TOY_NON_SUBGROUP = firstNonSubgroupElement(TOY_GROUP);
const G14_NON_SUBGROUP = firstNonSubgroupElement(GROUP14);

function badElements(group: ElGamalGroup, nonSubgroup: bigint): Array<[string, bigint]> {
  return [
    ['0', 0n],
    ['1', 1n],
    ['p-1', group.p - 1n],
    ['p', group.p],
    ['p+1', group.p + 1n],
    ['a non-subgroup element', nonSubgroup],
  ];
}

const GROUPS: Array<[string, ElGamalGroup, bigint]> = [
  ['TOY_GROUP', TOY_GROUP, TOY_NON_SUBGROUP],
  ['GROUP14', GROUP14, G14_NON_SUBGROUP],
];

describe('the groups themselves are the shape the check assumes', () => {
  /* If g were outside the order-q subgroup, this check would refuse every
     honest ciphertext, so the premise is asserted rather than assumed. */
  it.each(GROUPS)('%s: p = 2q+1 and g generates the order-q subgroup', (_label, group) => {
    expect(group.p).toBe(2n * group.q + 1n);
    expect(modPow(group.g, group.q, group.p)).toBe(1n);
  });

  it('TOY_GROUP: the first non-subgroup element found by search is 7', () => {
    expect(TOY_NON_SUBGROUP).toBe(7n);
    expect(modPow(7n, TOY_GROUP.q, TOY_GROUP.p)).not.toBe(1n);
  });

  /* The positive control. A validator that threw on everything would pass every
     rejection test below and be worthless. */
  it.each(GROUPS)('%s: g and an honest c1 both PASS the check', (_label, group) => {
    expect(() => assertGroupElement(group.g, group, 'g')).not.toThrow();
    const keys = generateKeyPair(group);
    const { ciphertext } = encrypt(42n, keys.publicKey, group);
    expect(() => assertGroupElement(ciphertext.c1, group, 'c1')).not.toThrow();
    expect(() => assertGroupElement(keys.publicKey, group, 'publicKey')).not.toThrow();
  });
});

describe('decrypt refuses an invalid c1 before using the private key', () => {
  for (const [groupLabel, group, nonSub] of GROUPS) {
    for (const [name, value] of badElements(group, nonSub)) {
      it(`${groupLabel}: c1 = ${name}`, () => {
        const keys = generateKeyPair(group);
        const { ciphertext } = encrypt(42n, keys.publicKey, group);
        const forged = { ...ciphertext, c1: value };
        expect(() => decrypt(forged, keys.privateKey, group)).toThrow(/Invalid c1/);
      });
    }
  }
});

describe('authDecrypt refuses an invalid c1 before deriving the MAC key', () => {
  for (const [groupLabel, group, nonSub] of GROUPS) {
    for (const [name, value] of badElements(group, nonSub)) {
      it(`${groupLabel}: c1 = ${name}`, async () => {
        const keys = generateKeyPair(group);
        const ct = await authEncrypt(42n, keys.publicKey, group);
        const forged = { ...ct, c1: value };
        await expect(authDecrypt(forged, keys.privateKey, group)).rejects.toThrow(/Invalid c1/);
      });
    }
  }
});

describe('the c1 = 1 forgery, and the c1 = p-1 parity leak', () => {
  it('c1 = 1 with a tag the attacker computed themselves is refused', async () => {
    /* The attacker knows the shared secret is 1 without knowing x, so they can
       build a tag that WOULD verify. The point of the test is that the request
       never reaches the MAC comparison at all. */
    const keys = generateKeyPair(TOY_GROUP);
    const honest = await authEncrypt(42n, keys.publicKey, TOY_GROUP);
    const forgedWithKnownSecret = await authEncrypt(42n, TOY_GROUP.g, TOY_GROUP);
    const attack = { ...honest, c1: 1n, c2: forgedWithKnownSecret.c2, tag: forgedWithKnownSecret.tag };
    await expect(authDecrypt(attack, keys.privateKey, TOY_GROUP)).rejects.toThrow(/Invalid c1/);
  });

  it('c1 = p-1 is refused for BOTH parities of x, so the outcome leaks no bit', async () => {
    /* Before the fix the accept/reject outcome depended on x mod 2. Here the
       two parities are driven explicitly and the outcome is identical, which is
       what "leaks nothing" has to mean. */
    const even = 2n;
    const odd = 3n;
    expect(even % 2n).toBe(0n);
    expect(odd % 2n).toBe(1n);

    const outcomes = await Promise.all([even, odd].map(async (x) => {
      const ct = await authEncrypt(42n, modPow(TOY_GROUP.g, x, TOY_GROUP.p), TOY_GROUP);
      const attack = { ...ct, c1: TOY_GROUP.p - 1n };
      return authDecrypt(attack, x, TOY_GROUP).then(() => 'accepted', (e: Error) => e.message);
    }));

    expect(outcomes[0]).toMatch(/Invalid c1/);
    expect(outcomes[1]).toMatch(/Invalid c1/);
    expect(outcomes[0]).toBe(outcomes[1]);

    /* And the same for plain decrypt, which has no MAC to hide behind. */
    const plain = [even, odd].map((x) => {
      const ct = encrypt(42n, modPow(TOY_GROUP.g, x, TOY_GROUP.p), TOY_GROUP).ciphertext;
      try {
        decrypt({ ...ct, c1: TOY_GROUP.p - 1n }, x, TOY_GROUP);
        return 'accepted';
      } catch (e) {
        return (e as Error).message;
      }
    });
    expect(plain[0]).toBe(plain[1]);
    expect(plain[0]).toMatch(/Invalid c1/);
  });
});

describe('encryption refuses an invalid public key', () => {
  for (const [groupLabel, group, nonSub] of GROUPS) {
    for (const [name, value] of [['1', 1n], ['p-1', group.p - 1n], ['a non-subgroup element', nonSub]] as Array<[string, bigint]>) {
      it(`${groupLabel}: encrypt with y = ${name}`, () => {
        expect(() => encrypt(42n, value, group)).toThrow(/Invalid publicKey/);
      });

      it(`${groupLabel}: encryptWithEphemeral with y = ${name}`, () => {
        expect(() => encryptWithEphemeral(42n, value, group, 5n)).toThrow(/Invalid publicKey/);
      });

      it(`${groupLabel}: authEncrypt with y = ${name}`, async () => {
        await expect(authEncrypt(42n, value, group)).rejects.toThrow(/Invalid publicKey/);
      });

      it(`${groupLabel}: rerandomize with y = ${name}`, () => {
        const keys = generateKeyPair(group);
        const { ciphertext } = encrypt(42n, keys.publicKey, group);
        expect(() => rerandomize(ciphertext, value, group)).toThrow(/Invalid publicKey/);
      });
    }
  }
});

describe('the q trap: an uninitialised group must not pass the check', () => {
  /* RFC3526_GROUP14 is exported with q: 0n and only initializeGroup14() fills
     it. With q = 0 the subgroup test reads x^0 mod p === 1, which is true for
     every x -- a check that passes everything while looking like a check. */
  it('the raw RFC3526_GROUP14 constant still carries q: 0n', () => {
    expect(RFC3526_GROUP14.q).toBe(0n);
    expect(GROUP14.q).toBe((GROUP14.p - 1n) / 2n);
  });

  it('assertGroupElement throws on the raw constant, for a value that is otherwise valid', () => {
    expect(() => assertGroupElement(GROUP14.g, GROUP14, 'c1')).not.toThrow();
    expect(() => assertGroupElement(GROUP14.g, RFC3526_GROUP14, 'c1')).toThrow(/no subgroup order q/);
  });

  it('and on a group object whose q is missing entirely', () => {
    const { p, g, label, bitLength, isToy } = TOY_GROUP;
    const noQ = { p, g, label, bitLength, isToy } as unknown as ElGamalGroup;
    expect(() => assertGroupElement(g, noQ, 'c1')).toThrow(/no subgroup order q/);
  });

  it('x^0 mod p === 1 for arbitrary x, which is why q = 0 cannot be allowed to run', () => {
    for (const x of [0n, 1n, 7n, TOY_GROUP.p - 1n, 1234n]) {
      expect(modPow(x, 0n, TOY_GROUP.p)).toBe(1n);
    }
  });
});

describe('valid ciphertexts still decrypt', () => {
  it.each(GROUPS)('%s: round-trip through encrypt/decrypt', (_label, group) => {
    const keys = generateKeyPair(group);
    const { ciphertext } = encrypt(123456n % (group.p - 1n) || 42n, keys.publicKey, group);
    expect(decrypt(ciphertext, keys.privateKey, group)).toBe(123456n % (group.p - 1n) || 42n);
  });

  it.each(GROUPS)('%s: round-trip through authEncrypt/authDecrypt', async (_label, group) => {
    const keys = generateKeyPair(group);
    const ct = await authEncrypt(42n, keys.publicKey, group);
    const result = await authDecrypt(ct, keys.privateKey, group);
    expect(result.authentic).toBe(true);
    expect(result.message).toBe(42n);
  });

  it.each(GROUPS)('%s: a re-randomized ciphertext is still a valid group element', (_label, group) => {
    const keys = generateKeyPair(group);
    const { ciphertext } = encrypt(42n, keys.publicKey, group);
    const refreshed = rerandomize(ciphertext, keys.publicKey, group);
    expect(() => assertGroupElement(refreshed.c1, group, 'c1')).not.toThrow();
    expect(decrypt(refreshed, keys.privateKey, group)).toBe(42n);
  });
});
