import querySource from './csQueries.ts?raw';
import { describe, expect, it } from 'vitest';
import { csAlpha, csDecrypt, csEncodeMessage, csEncrypt, csKeygen, type CsCiphertext, type CsPublicKey, type CsSecretKey } from './cramerShoup';
import { findToyAlphaCollision, makeInvalidQuery, multiplyCs } from './csQueries';
import { ToyKeySpace } from './csToyProof';
import { GROUP14, TOY_GROUP } from './groups';
import { modPow } from './modular';

function fixedKeys(): { publicKey: CsPublicKey; secretKey: CsSecretKey } {
  const group = TOY_GROUP;
  const g1 = group.g;
  const g2 = modPow(g1, 17n, group.p);
  const secretKey = { x1: 7n, x2: 11n, y1: 13n, y2: 19n, z: 23n };
  const publicKey = {
    group, g1, g2,
    c: modPow(g1, 7n + 17n * 11n, group.p),
    d: modPow(g1, 13n + 17n * 19n, group.p),
    h: modPow(g1, 23n, group.p),
  };
  return { publicKey, secretKey };
}

describe('Cramer–Shoup', () => {
  it('round-trips boundary encodings and Group 14 messages', async () => {
    const keys = csKeygen(TOY_GROUP);
    for (const m of [1n, 2n, 42n, 509n, 1018n, TOY_GROUP.q]) {
      const { ciphertext } = await csEncrypt(m, keys.publicKey, 7n);
      const result = await csDecrypt(ciphertext, keys.secretKey, TOY_GROUP);
      expect(result.valid).toBe(true);
      expect(result.message).toBe(m);
    }
    const large = csKeygen(GROUP14);
    for (const m of [1n, 42n, GROUP14.q]) {
      const { ciphertext } = await csEncrypt(m, large.publicKey);
      expect((await csDecrypt(ciphertext, large.secretKey, GROUP14)).message).toBe(m);
    }
    expect(() => csEncodeMessage(0n, TOY_GROUP)).toThrow('[1, 1019]');
    expect(() => csEncodeMessage(1020n, TOY_GROUP)).toThrow('[1, 1019]');
  }, 20000);

  it('rejects every malformed component before the check equation', async () => {
    for (const group of [TOY_GROUP, GROUP14]) {
      const keys = csKeygen(group);
      const { ciphertext } = await csEncrypt(42n, keys.publicKey);
      for (const component of ['u1', 'u2', 'e', 'v'] as const) {
        for (const value of [0n, group.p, group.p - 1n, group.p - group.g, group.p + 1n]) {
          const result = await csDecrypt({ ...ciphertext, [component]: value }, keys.secretKey, group);
          expect(result).toMatchObject({ valid: false, message: null, alpha: null });
          expect(result.reason).toContain(component);
        }
      }
    }
  }, 20000);

  it('counts q² keys; valid queries have one bar and invalid queries q bars of q', async () => {
    const { publicKey, secretKey } = fixedKeys();
    const space = new ToyKeySpace(publicKey);
    expect(space.remaining).toBe(1019 ** 2);
    expect(space.w).toBe(17);
    const valid = (await csEncrypt(42n, publicKey, 31n)).ciphertext;
    const validAlpha = await csAlpha(valid, TOY_GROUP);
    const validBins = space.histogram(valid, validAlpha).filter(Boolean);
    expect(validBins).toEqual([1019 ** 2]);
    const invalid = makeInvalidQuery(publicKey, 31n, 32n);
    const invalidAlpha = await csAlpha(invalid, TOY_GROUP);
    const invalidBins = space.histogram(invalid, invalidAlpha).filter(Boolean);
    expect(invalidBins).toHaveLength(1019);
    expect(new Set(invalidBins)).toEqual(new Set([1019]));

    const tuple = space.tuple(Number(secretKey.x2), Number(secretKey.y2));
    expect(tuple).toEqual({ x1: secretKey.x1, x2: secretKey.x2, y1: secretKey.y1, y2: secretKey.y2 });
    const predicted = modPow(publicKey.g1, BigInt(space.prediction(invalid, invalidAlpha, Number(secretKey.x2), Number(secretKey.y2))), TOY_GROUP.p);
    const verdict = await csDecrypt(invalid, secretKey, TOY_GROUP);
    expect(verdict.valid).toBe(predicted === invalid.v);
    expect(verdict.expected).toBe(predicted);
    expect(() => new ToyKeySpace({ ...publicKey, group: GROUP14 })).toThrow('computationally infeasible');
  });

  it('removes only predicted pass keys on rejection, including overlapping exclusion lines', async () => {
    const { publicKey, secretKey } = fixedKeys();
    const space = new ToyKeySpace(publicKey);
    for (let i = 1; i <= 20; i++) {
      let ct = makeInvalidQuery(publicKey, BigInt(i + 1), BigInt(i + 2));
      let actual = await csDecrypt(ct, secretKey, TOY_GROUP);
      if (actual.valid) {
        ct = { ...ct, v: publicKey.g1 };
        actual = await csDecrypt(ct, secretKey, TOY_GROUP);
      }
      expect(actual.valid).toBe(false);
      const observation = space.observe(ct, actual.alpha!, false);
      expect(observation.remaining).toBe(observation.before - observation.passing);
      expect(observation.passing / observation.before).toBeLessThanOrEqual(1 / (Number(TOY_GROUP.q) - i + 1));
    }
    expect(space.remaining).toBeGreaterThan(0);
    expect(space.remaining).toBeLessThan(1019 ** 2);
  });

  it('rejects a componentwise product and demonstrates a toy α collision', async () => {
    const { publicKey, secretKey } = fixedKeys();
    let product: CsCiphertext | null = null;
    for (let r = 2n; r < 10n; r++) {
      const a = (await csEncrypt(3n, publicKey, r)).ciphertext;
      const b = (await csEncrypt(7n, publicKey, r + 20n)).ciphertext;
      product = multiplyCs(a, b, publicKey);
      if (!(await csDecrypt(product, secretKey, TOY_GROUP)).valid) break;
    }
    expect((await csDecrypt(product!, secretKey, TOY_GROUP)).valid).toBe(false);

    let collision = null;
    let original: CsCiphertext | null = null;
    for (let r = 2n; r < 10n && !collision; r++) {
      original = (await csEncrypt(100n, publicKey, r)).ciphertext;
      collision = await findToyAlphaCollision(original, publicKey);
    }
    expect(collision).not.toBeNull();
    expect(collision!.forged.e).not.toBe(original!.e);
    expect(await csAlpha(collision!.forged, TOY_GROUP)).toBe(await csAlpha(original!, TOY_GROUP));
    expect((await csDecrypt(collision!.forged, secretKey, TOY_GROUP)).valid).toBe(true);
    await expect(findToyAlphaCollision(original!, { ...publicKey, group: GROUP14 })).rejects.toThrow('Toy-size α only');
  });

  it('keeps attacker query code separate from private-key fields', () => {
    expect(querySource).not.toMatch(/secretKey|privateKey|\.x1|\.x2|\.y1|\.y2|\.z\b/);
  });
});
