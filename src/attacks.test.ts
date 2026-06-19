import { describe, expect, it } from 'vitest';
import { discreteLog } from './attacks';
import { generateKeyPair } from './elgamal';
import { GROUP14, TOY_GROUP } from './groups';
import { modPow } from './modular';

describe('discreteLog (baby-step/giant-step)', () => {
  it('recovers the private key from the public key in the toy group', () => {
    for (let i = 0; i < 300; i += 1) {
      const keys = generateKeyPair(TOY_GROUP);
      const { x } = discreteLog(TOY_GROUP, keys.publicKey);
      expect(x).toBe(keys.privateKey);
      expect(modPow(TOY_GROUP.g, x as bigint, TOY_GROUP.p)).toBe(keys.publicKey);
    }
  });

  it('reports a bounded operation count (O(sqrt(order)))', () => {
    const { steps } = discreteLog(TOY_GROUP, generateKeyPair(TOY_GROUP).publicKey);
    expect(steps).toBeLessThan(200); // sqrt(1019) ~ 32 baby + giant steps
  });

  it('refuses the cryptographically large RFC 3526 group', () => {
    expect(() => discreteLog(GROUP14, 12345n)).toThrow(/infeasible/i);
  });
});
