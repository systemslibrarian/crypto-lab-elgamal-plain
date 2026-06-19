import { describe, expect, it } from 'vitest';
import { authDecrypt, authEncrypt } from './authenticated';
import { generateKeyPair } from './elgamal';
import { TOY_GROUP } from './groups';
import { randomBigInt } from './modular';

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
});
