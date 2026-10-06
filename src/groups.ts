import { isProbablePrime, modPow } from './modular';

export interface ElGamalGroup {
  p: bigint;
  q: bigint;
  g: bigint;
  label: string;
  bitLength: number;
  isToy: boolean;
}

export const RFC3526_GROUP14: ElGamalGroup = {
  p: BigInt(
    '0x' +
      'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
      '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
      'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
      'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
      'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
      'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
      '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
      '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
      'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
      'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
      '15728E5A8AACAA68FFFFFFFFFFFFFFFF'
  ),
  q: 0n,
  g: 2n,
  label: 'RFC 3526 Group 14 (2048-bit)',
  bitLength: 2048,
  isToy: false,
};

export const TOY_GROUP: ElGamalGroup = {
  p: 2039n,
  q: 1019n,
  g: 2n,
  label: 'TOY (11-bit) - NOT SECURE - for visualization only',
  bitLength: 11,
  isToy: true,
};

export function initializeGroup14(verifyPrime = false): ElGamalGroup {
  const q = (RFC3526_GROUP14.p - 1n) / 2n;

  if (verifyPrime) {
    if (!isProbablePrime(RFC3526_GROUP14.p, 12)) {
      throw new Error('RFC 3526 Group 14 p failed primality test.');
    }
    if (!isProbablePrime(q, 12)) {
      throw new Error('RFC 3526 Group 14 q failed primality test.');
    }
  }

  return {
    ...RFC3526_GROUP14,
    q,
  };
}

export const GROUP14 = initializeGroup14();

/**
 * Fail closed on a group element that arrived from OUTSIDE this module, before
 * it reaches any private-key operation or any encryption.
 *
 * Why this is not optional. ElGamal's decryption computes c1^x mod p, so the
 * sender chooses the base of an exponentiation by the recipient's private key.
 * Two choices are free wins for an attacker:
 *
 *   c1 = 1      -> the shared secret is 1^x = 1 for EVERY x. The attacker knows
 *                  the secret without knowing the key, so in the authenticated
 *                  construction they can derive the HMAC key and forge a tag
 *                  that verifies.
 *   c1 = p - 1  -> the shared secret is (-1)^x, which is 1 when x is even and
 *                  p-1 when it is odd. Whether the recipient accepts therefore
 *                  reveals x mod 2 -- one bit of the private key per query,
 *                  leaked by nothing more than the accept/reject outcome.
 *
 * A base outside the prime-order subgroup is the general case of the second:
 * exponentiating it confines the result to a small subgroup and leaks x modulo
 * that subgroup's order. Both groups here are safe primes (p = 2q + 1) with
 * p = 7 mod 8, so g = 2 really does generate the order-q subgroup and every
 * honestly produced c1 and public key is inside it -- the check refuses attack
 * values without refusing anything the lab itself computes.
 *
 * Order matters: the range test has to run as well as the subgroup test, not
 * instead of it. 1^q mod p == 1, so the subgroup test ALONE accepts c1 = 1,
 * which is the stronger of the two attacks.
 */
export function assertGroupElement(x: bigint, group: ElGamalGroup, label: string): void {
  /* Read q defensively rather than trusting the declared type. RFC3526_GROUP14
   * is exported as a literal carrying `q: 0n` and only initializeGroup14()
   * fills it in, so a caller reaching for the raw constant would hand us a
   * group whose subgroup test is `x^0 mod p === 1` -- true for every x, a check
   * that passes everything while looking like a check. Refuse instead. */
  const q = (group as { q?: bigint }).q;
  if (typeof q !== 'bigint' || q <= 0n) {
    throw new Error(
      `Cannot validate ${label}: this group carries no subgroup order q, so the ` +
        'subgroup test would accept every value. RFC3526_GROUP14 is exported with ' +
        'q: 0n and only initializeGroup14() fills it -- use GROUP14, not the raw constant.'
    );
  }

  if (x <= 1n || x >= group.p - 1n) {
    throw new Error(
      `Invalid ${label}: must satisfy 1 < ${label} < p-1. Refused 0, 1, p-1 and ` +
        'anything at or above p -- see the note on why 1 and p-1 are attacks rather ' +
        'than edge cases.'
    );
  }

  if (modPow(x, q, group.p) !== 1n) {
    throw new Error(
      `Invalid ${label}: not in the prime-order subgroup (${label}^q mod p != 1), ` +
        'so exponentiating it would leak the private key modulo a small order.'
    );
  }
}

export function validateGroupGenerator(group: ElGamalGroup): boolean {
  return modPow(group.g, group.q, group.p) === 1n;
}
