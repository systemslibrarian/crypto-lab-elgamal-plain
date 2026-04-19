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

export function validateGroupGenerator(group: ElGamalGroup): boolean {
  return modPow(group.g, group.q, group.p) === 1n;
}
