import { describe, expect, it } from 'vitest';
import {
  decrypt,
  encrypt,
  encryptWithEphemeral,
  generateKeyPair,
  messageToText,
  multiplyHomomorphic,
  rerandomize,
  textToMessage,
} from './elgamal';
import { GROUP14, TOY_GROUP } from './groups';
import { randomBigInt } from './modular';

describe('encrypt/decrypt round-trip', () => {
  it('recovers random messages in the toy group', () => {
    for (let i = 0; i < 500; i += 1) {
      const keys = generateKeyPair(TOY_GROUP);
      const m = randomBigInt(TOY_GROUP.p);
      const { ciphertext } = encrypt(m, keys.publicKey, TOY_GROUP);
      expect(decrypt(ciphertext, keys.privateKey, TOY_GROUP)).toBe(m);
    }
  });

  it('recovers a message in RFC 3526 Group 14', () => {
    const keys = generateKeyPair(GROUP14);
    const m = 123456789n;
    const { ciphertext } = encrypt(m, keys.publicKey, GROUP14);
    expect(decrypt(ciphertext, keys.privateKey, GROUP14)).toBe(m);
  });

  it('is non-deterministic: same message, different ciphertexts', () => {
    const keys = generateKeyPair(TOY_GROUP);
    const a = encrypt(7n, keys.publicKey, TOY_GROUP).ciphertext;
    const b = encrypt(7n, keys.publicKey, TOY_GROUP).ciphertext;
    expect(a.c1 === b.c1 && a.c2 === b.c2).toBe(false);
  });

  it('rejects out-of-range messages', () => {
    const keys = generateKeyPair(TOY_GROUP);
    expect(() => encrypt(0n, keys.publicKey, TOY_GROUP)).toThrow();
    expect(() => encrypt(TOY_GROUP.p, keys.publicKey, TOY_GROUP)).toThrow();
  });
});

describe('encryptWithEphemeral', () => {
  it('is deterministic for a fixed k and matches encrypt structure', () => {
    const keys = generateKeyPair(TOY_GROUP);
    const ct1 = encryptWithEphemeral(9n, keys.publicKey, TOY_GROUP, 5n);
    const ct2 = encryptWithEphemeral(9n, keys.publicKey, TOY_GROUP, 5n);
    expect(ct1.c1).toBe(ct2.c1);
    expect(ct1.c2).toBe(ct2.c2);
    expect(decrypt(ct1, keys.privateKey, TOY_GROUP)).toBe(9n);
  });
});

describe('multiplicative homomorphism', () => {
  it('E(m1) ⊗ E(m2) decrypts to m1·m2 mod p', () => {
    for (let i = 0; i < 200; i += 1) {
      const keys = generateKeyPair(TOY_GROUP);
      const m1 = randomBigInt(TOY_GROUP.p);
      const m2 = randomBigInt(TOY_GROUP.p);
      const ct1 = encrypt(m1, keys.publicKey, TOY_GROUP).ciphertext;
      const ct2 = encrypt(m2, keys.publicKey, TOY_GROUP).ciphertext;
      const product = multiplyHomomorphic(ct1, ct2);
      expect(decrypt(product, keys.privateKey, TOY_GROUP)).toBe((m1 * m2) % TOY_GROUP.p);
    }
  });
});

describe('rerandomize', () => {
  it('changes the ciphertext but preserves the plaintext', () => {
    const keys = generateKeyPair(TOY_GROUP);
    const original = encrypt(15n, keys.publicKey, TOY_GROUP).ciphertext;
    const refreshed = rerandomize(original, keys.publicKey, TOY_GROUP);
    expect(original.c1 === refreshed.c1 && original.c2 === refreshed.c2).toBe(false);
    expect(decrypt(refreshed, keys.privateKey, TOY_GROUP)).toBe(15n);
  });
});

describe('text encoding', () => {
  it('round-trips UTF-8 text through the group', () => {
    for (const text of ['yes', 'no', 'Ada', 'π≈3']) {
      const m = textToMessage(text, GROUP14);
      expect(messageToText(m, GROUP14)).toBe(text);
    }
  });

  it('rejects empty text', () => {
    expect(() => textToMessage('', GROUP14)).toThrow();
  });
});
