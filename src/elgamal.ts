import type { ElGamalGroup } from './groups';
import { modInverse, modPow, randomBigInt } from './modular';

export interface ElGamalKeyPair {
  privateKey: bigint;
  publicKey: bigint;
  group: ElGamalGroup;
}

export interface ElGamalCiphertext {
  c1: bigint;
  c2: bigint;
  group: ElGamalGroup;
}

function assertMessageInGroup(message: bigint, group: ElGamalGroup): void {
  if (message <= 0n || message >= group.p) {
    throw new Error('Message must be in [1, p-1].');
  }
}

function sameGroup(a: ElGamalGroup, b: ElGamalGroup): boolean {
  return a.p === b.p && a.q === b.q && a.g === b.g;
}

export function generateKeyPair(group: ElGamalGroup): ElGamalKeyPair {
  const privateKey = randomBigInt(group.q);
  const publicKey = modPow(group.g, privateKey, group.p);

  return {
    privateKey,
    publicKey,
    group,
  };
}

/**
 * Encrypt with a caller-supplied ephemeral exponent k.
 *
 * Exposed mainly so the teaching UI can demonstrate the catastrophic
 * consequence of REUSING k across two encryptions. Production code must
 * never reuse k; always draw a fresh random value per message.
 */
export function encryptWithEphemeral(
  message: bigint,
  publicKey: bigint,
  group: ElGamalGroup,
  ephemeralK: bigint
): ElGamalCiphertext {
  assertMessageInGroup(message, group);

  const c1 = modPow(group.g, ephemeralK, group.p);
  const yk = modPow(publicKey, ephemeralK, group.p);
  const c2 = (message * yk) % group.p;

  return { c1, c2, group };
}

export function encrypt(
  message: bigint,
  publicKey: bigint,
  group: ElGamalGroup
): { ciphertext: ElGamalCiphertext; ephemeralK: bigint } {
  const ephemeralK = randomBigInt(group.q);
  return {
    ciphertext: encryptWithEphemeral(message, publicKey, group, ephemeralK),
    ephemeralK,
  };
}

export function decrypt(
  ciphertext: ElGamalCiphertext,
  privateKey: bigint,
  group: ElGamalGroup
): bigint {
  if (!sameGroup(ciphertext.group, group)) {
    throw new Error('Ciphertext group does not match decryption group.');
  }

  const sharedSecret = modPow(ciphertext.c1, privateKey, group.p);
  const inverse = modInverse(sharedSecret, group.p);
  return (ciphertext.c2 * inverse) % group.p;
}

export function textToMessage(text: string, group: ElGamalGroup): bigint {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length === 0) {
    throw new Error('Text message must be non-empty.');
  }

  let m = 1n;
  for (const byte of bytes) {
    m = (m << 8n) | BigInt(byte);
  }

  assertMessageInGroup(m, group);
  return m;
}

export function messageToText(m: bigint, group: ElGamalGroup): string {
  assertMessageInGroup(m, group);

  const bytes: number[] = [];
  let value = m;

  while (value > 1n) {
    bytes.push(Number(value & 0xffn));
    value >>= 8n;
  }

  bytes.reverse();

  return new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
}

export function multiplyHomomorphic(
  ct1: ElGamalCiphertext,
  ct2: ElGamalCiphertext
): ElGamalCiphertext {
  if (!sameGroup(ct1.group, ct2.group)) {
    throw new Error('Ciphertexts are from different groups.');
  }

  const group = ct1.group;

  return {
    c1: (ct1.c1 * ct2.c1) % group.p,
    c2: (ct1.c2 * ct2.c2) % group.p,
    group,
  };
}

export function rerandomize(
  ciphertext: ElGamalCiphertext,
  publicKey: bigint,
  group: ElGamalGroup
): ElGamalCiphertext {
  if (!sameGroup(ciphertext.group, group)) {
    throw new Error('Ciphertext group does not match rerandomization group.');
  }

  const kPrime = randomBigInt(group.q);
  const delta1 = modPow(group.g, kPrime, group.p);
  const delta2 = modPow(publicKey, kPrime, group.p);

  return {
    c1: (ciphertext.c1 * delta1) % group.p,
    c2: (ciphertext.c2 * delta2) % group.p,
    group,
  };
}
