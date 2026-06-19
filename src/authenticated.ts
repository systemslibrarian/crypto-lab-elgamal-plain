import type { ElGamalGroup } from './groups';
import { modInverse, modPow, randomBigInt } from './modular';

/**
 * Authenticated ("hashed") ElGamal in the DHIES / ECIES style: the Diffie-Hellman
 * shared secret keys an HMAC that covers the ciphertext, so any tampering is
 * detected on decryption. This is how plain ElGamal's malleability is fixed in
 * practice — at the cost of the homomorphism (the MAC breaks if a ciphertext is
 * mauled or re-randomized).
 */
export interface AuthCiphertext {
  c1: bigint;
  c2: bigint;
  tag: string; // hex-encoded HMAC-SHA-256 over (c1 ‖ c2)
  group: ElGamalGroup;
}

export interface AuthDecryptResult {
  authentic: boolean;
  message: bigint | null;
}

function bigintToBytes(n: bigint): Uint8Array<ArrayBuffer> {
  let hex = n.toString(16);
  if (hex.length % 2 === 1) hex = '0' + hex;
  const bytes = new Uint8Array(new ArrayBuffer(hex.length / 2));
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer(hex.length / 2));
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Length-prefixed encoding of (c1, c2) so no two distinct pairs collide. */
function macInput(c1: bigint, c2: bigint): Uint8Array<ArrayBuffer> {
  const a = bigintToBytes(c1);
  const b = bigintToBytes(c2);
  const out = new Uint8Array(new ArrayBuffer(4 + a.length + b.length));
  out[0] = (a.length >> 8) & 0xff;
  out[1] = a.length & 0xff;
  out.set(a, 2);
  out[2 + a.length] = (b.length >> 8) & 0xff;
  out[3 + a.length] = b.length & 0xff;
  out.set(b, 4 + a.length);
  return out;
}

async function deriveMacKey(sharedSecret: bigint): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.digest('SHA-256', bigintToBytes(sharedSecret));
  return crypto.subtle.importKey('raw', keyMaterial, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function authEncrypt(
  message: bigint,
  publicKey: bigint,
  group: ElGamalGroup
): Promise<AuthCiphertext> {
  if (message <= 0n || message >= group.p) {
    throw new Error('Message must be in [1, p-1].');
  }

  const k = randomBigInt(group.q);
  const c1 = modPow(group.g, k, group.p);
  const sharedSecret = modPow(publicKey, k, group.p);
  const c2 = (message * sharedSecret) % group.p;

  const key = await deriveMacKey(sharedSecret);
  const tag = toHex(await crypto.subtle.sign('HMAC', key, macInput(c1, c2)));

  return { c1, c2, tag, group };
}

export async function authDecrypt(
  ciphertext: AuthCiphertext,
  privateKey: bigint,
  group: ElGamalGroup
): Promise<AuthDecryptResult> {
  const sharedSecret = modPow(ciphertext.c1, privateKey, group.p);
  const key = await deriveMacKey(sharedSecret);
  
  let isValid = false;
  try {
    const signature = fromHex(ciphertext.tag);
    isValid = await crypto.subtle.verify('HMAC', key, signature, macInput(ciphertext.c1, ciphertext.c2));
  } catch (e) {
    isValid = false;
  }

  if (!isValid) {
    return { authentic: false, message: null };
  }

  const message = (ciphertext.c2 * modInverse(sharedSecret, group.p)) % group.p;
  return { authentic: true, message };
}
