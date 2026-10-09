import { describe, expect, it } from 'vitest';
import { authDecrypt, authEncrypt } from './authenticated';
import { generateKeyPair } from './elgamal';
import { GROUP14, TOY_GROUP } from './groups';
import { randomBigInt } from './modular';

function encoded(n: bigint): Uint8Array<ArrayBuffer> {
  let hex = n.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const out = new Uint8Array(new ArrayBuffer(hex.length / 2));
  hex.match(/../g)!.forEach((part, index) => { out[index] = Number.parseInt(part, 16); });
  return out;
}

async function attackerTag(shared: bigint, c1: bigint, c2: bigint): Promise<string> {
  const a = encoded(c1), b = encoded(c2);
  const input = new Uint8Array(4 + a.length + b.length);
  input[0] = a.length >> 8; input[1] = a.length & 255;
  input.set(a, 2);
  input[2 + a.length] = b.length >> 8; input[3 + a.length] = b.length & 255;
  input.set(b, 4 + a.length);
  const material = await crypto.subtle.digest('SHA-256', encoded(shared));
  const key = await crypto.subtle.importKey('raw', material, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return Array.from(new Uint8Array(await crypto.subtle.sign('HMAC', key, input)))
    .map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

describe('authenticated ElGamal', () => {
  it('round-trips and reports authenticity', async () => {
    for (let i = 0; i < 100; i += 1) {
      const keys = generateKeyPair(TOY_GROUP);
      const m = randomBigInt(TOY_GROUP.p);
      const ct = await authEncrypt(m, keys.publicKey, TOY_GROUP);
      const result = await authDecrypt(ct, keys.privateKey, TOY_GROUP);
      expect(result.authentic).toBe(true);
      expect(result.message).toBe(m);
    }
  });

  it('rejects a malleability attack (the unauthenticated weakness)', async () => {
    for (let i = 0; i < 100; i += 1) {
      const keys = generateKeyPair(TOY_GROUP);
      const m = randomBigInt(TOY_GROUP.p);
      const ct = await authEncrypt(m, keys.publicKey, TOY_GROUP);
      // Same tampering that succeeds against plain ElGamal: multiply c2 by 2.
      const mauled = { ...ct, c2: (ct.c2 * 2n) % TOY_GROUP.p };
      const result = await authDecrypt(mauled, keys.privateKey, TOY_GROUP);
      expect(result.authentic).toBe(false);
      expect(result.message).toBeNull();
    }
  });

  it('rejects a forged tag', async () => {
    const keys = generateKeyPair(TOY_GROUP);
    const ct = await authEncrypt(50n, keys.publicKey, TOY_GROUP);
    const forged = { ...ct, tag: ct.tag.replace(/.$/, (c) => (c === '0' ? '1' : '0')) };
    const result = await authDecrypt(forged, keys.privateKey, TOY_GROUP);
    expect(result.authentic).toBe(false);
  });

  it('refuses attacker-tagged identity and order-two c1 values in both groups', async () => {
    for (const group of [TOY_GROUP, GROUP14]) {
      const keys = generateKeyPair(group);
      for (const c1 of [1n, group.p - 1n, 0n, group.p]) {
        // Both order-two guesses are attacker-computable. The correct one
        // would verify if the subgroup check were removed.
        for (const guessedSecret of c1 === group.p - 1n ? [1n, group.p - 1n] : [1n]) {
          const tag = await attackerTag(guessedSecret, c1, 1n);
          await expect(authDecrypt({ c1, c2: 1n, tag, group }, keys.privateKey, group)).rejects.toThrow('Invalid c1');
        }
      }
    }
  });
});
