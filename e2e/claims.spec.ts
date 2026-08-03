import { expect, test, type Page } from '@playwright/test';

/**
 * Functional gate for the claims this lab makes on screen.
 *
 * The a11y spec proves the page is reachable; this one proves it is *right*.
 * Every headline verdict ("Recovered original: Yes", "Key recovered: Yes",
 * "Tampering REJECTED") is re-derived here from the numbers the page itself
 * rendered, so a broken primitive cannot pass by printing a cheerful string.
 * All arithmetic below is recomputed in the test with BigInt against the toy
 * group (p = 2039, g = 2, q = 1019) and the toy signature group (g = 7,
 * n = p-1 = 2038) — the same parameters the UI advertises.
 */

const P = 2039n; // toy prime
const G = 2n; // toy subgroup generator (order q)
const Q = 1019n; // toy subgroup order
const SIGN_G = 7n; // primitive root mod p, used by the signature exhibits
const SIGN_N = 2038n; // p - 1

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  let b = ((base % m) + m) % m;
  let e = exp;
  while (e > 0n) {
    if ((e & 1n) === 1n) result = (result * b) % m;
    e >>= 1n;
    b = (b * b) % m;
  }
  return result;
}

function mod(a: bigint, n: bigint): bigint {
  return ((a % n) + n) % n;
}

/** Integer ceil(sqrt(n)) — mirrors the baby-step/giant-step table size. */
function sqrtCeil(n: bigint): bigint {
  if (n < 2n) return n;
  let x = n;
  let y = (x + 1n) / 2n;
  while (y < x) {
    x = y;
    y = (x + n / x) / 2n;
  }
  return x * x === n ? x : x + 1n;
}

/** The ElGamal verification identity g^h ≡ y^r · r^s (mod p). */
function signatureIdentityHolds(h: bigint, r: bigint, s: bigint, y: bigint): boolean {
  const left = modPow(SIGN_G, h, P);
  const right = (modPow(y, r, P) * modPow(r, s, P)) % P;
  return left === right;
}

/** Full ElGamal signature verification, recomputed independently of the app. */
function verifySignature(h: bigint, r: bigint, s: bigint, y: bigint): boolean {
  if (r <= 0n || r >= P) return false;
  if (s <= 0n || s >= SIGN_N) return false;
  return signatureIdentityHolds(h, r, s, y);
}

// --- rendered-output parsing ------------------------------------------------

async function textOf(page: Page, id: string): Promise<string> {
  const value = await page.locator(`#${id}`).textContent();
  expect(value, `#${id} should have rendered text`).toBeTruthy();
  return value ?? '';
}

/** The first line of `text` containing `needle`. */
function lineOf(text: string, needle: string): string {
  const line = text.split('\n').find((l) => l.includes(needle));
  expect(line, `expected a line containing ${JSON.stringify(needle)} in:\n${text}`).toBeDefined();
  return line ?? '';
}

/** First integer appearing after `needle` on the line that holds it. */
function numAfter(text: string, needle: string): bigint {
  const line = lineOf(text, needle);
  const tail = line.slice(line.indexOf(needle) + needle.length);
  const m = tail.match(/-?\d+/);
  expect(m, `expected a number after ${JSON.stringify(needle)} in ${JSON.stringify(line)}`).not.toBeNull();
  return BigInt(m![0]);
}

/** First "(a, b)" integer pair on the line that holds `needle`. */
function pairAfter(text: string, needle: string): { c1: bigint; c2: bigint } {
  const line = lineOf(text, needle);
  const m = line.match(/\((\d+),\s*(\d+)\)/);
  expect(m, `expected an (a, b) pair on ${JSON.stringify(line)}`).not.toBeNull();
  return { c1: BigInt(m![1]), c2: BigInt(m![2]) };
}

/** Digit count the app reports for a value too long to print in full. */
function digitsAfter(text: string, needle: string): number {
  const line = lineOf(text, needle);
  const m = line.match(/digits=(\d+)/);
  expect(m, `expected "(digits=N)" on ${JSON.stringify(line)}`).not.toBeNull();
  return Number(m![1]);
}

async function stateOf(page: Page, id: string): Promise<string | null> {
  return page.locator(`#${id}`).getAttribute('data-state');
}

// --- Guided walkthrough -----------------------------------------------------

test('guided walkthrough steps through a full encrypt/decrypt whose arithmetic checks out', async ({ page }) => {
  await page.goto('.');

  await expect(page.locator('#wt-progress')).toHaveText('Step 1 of 10');
  await expect(page.locator('.wt-step')).toHaveCount(1);
  await expect(page.locator('#wt-prev')).toBeDisabled();
  await expect(page.locator('#wt-next')).toBeEnabled();

  for (let i = 2; i <= 10; i += 1) {
    await page.locator('#wt-next').click();
    await expect(page.locator('#wt-progress')).toHaveText(`Step ${i} of 10`);
    await expect(page.locator('.wt-step')).toHaveCount(i);
  }
  await expect(page.locator('#wt-next')).toBeDisabled();
  await expect(page.locator('#wt-prev')).toBeEnabled();

  const verifyWalkthrough = async (): Promise<bigint> => {
    const panes = page.locator('.wt-step pre.output');
    const step = async (n: number): Promise<string> => (await panes.nth(n - 1).textContent()) ?? '';

    // 1. public parameters, as advertised in the lesson copy.
    expect(numAfter(await step(1), 'p =')).toBe(P);
    expect(numAfter(await step(1), 'g =')).toBe(G);

    // 2. the published public key really is g^x mod p.
    const s2 = await step(2);
    const x = numAfter(s2, 'private  x =');
    const y = numAfter(s2, 'public   y = g^x mod p =');
    expect(x).toBeGreaterThan(0n);
    expect(x).toBeLessThan(Q);
    expect(y).toBe(modPow(G, x, P));

    // 3-6. encryption: c1 = g^k, c2 = m·y^k.
    const m = numAfter(await step(3), 'm =');
    const k = numAfter(await step(4), 'k =');
    expect(k).toBeGreaterThan(0n);
    expect(k).toBeLessThan(Q);
    const c1 = numAfter(await step(5), 'c1 = g^k mod p =');
    expect(c1).toBe(modPow(G, k, P));
    const s6 = await step(6);
    const yk = numAfter(s6, 'y^k mod p =');
    const c2 = numAfter(s6, 'c2 = m · y^k mod p =');
    expect(yk).toBe(modPow(y, k, P));
    expect(c2).toBe((m * yk) % P);

    // 7. the transmitted pair is the pair just derived.
    expect(pairAfter(await step(7), 'ciphertext (c1, c2)')).toEqual({ c1, c2 });

    // 8-10. decryption rebuilds the mask and divides it out.
    const s8 = await step(8);
    const s = numAfter(s8, 's = c1^x mod p =');
    expect(s).toBe(modPow(c1, x, P));
    expect(s).toBe(yk); // the whole point of step 8
    expect(s8).toContain('same value as y^k: Yes');

    const sInv = numAfter(await step(9), 's⁻¹ mod p =');
    expect((s * sInv) % P).toBe(1n);

    const s10 = await step(10);
    const mRec = numAfter(s10, 'm = c2 · s⁻¹ mod p =');
    expect(mRec).toBe((c2 * sInv) % P);
    expect(mRec).toBe(m);
    expect(s10).toContain('recovered original message: Yes');
    return x;
  };

  const firstX = await verifyWalkthrough();

  // "New random run" resets to step 1 and rebuilds a fresh, still-consistent run.
  await page.locator('#wt-restart').click();
  await expect(page.locator('#wt-progress')).toHaveText('Step 1 of 10');
  await expect(page.locator('.wt-step')).toHaveCount(1);
  await expect(page.locator('#wt-prev')).toBeDisabled();
  for (let i = 0; i < 9; i += 1) await page.locator('#wt-next').click();
  await expect(page.locator('.wt-step')).toHaveCount(10);
  const secondX = await verifyWalkthrough();
  expect(secondX).toBeGreaterThan(0n); // fresh run, re-verified end to end
  expect(firstX).toBeGreaterThan(0n);
});

// --- Exhibit 1: keygen / encrypt / decrypt -----------------------------------

test('toy keygen, encryption and decryption agree with the group arithmetic', async ({ page }) => {
  await page.goto('.');

  await page.locator('#keygen-btn').click();
  const x = BigInt((await page.locator('#private-key').textContent()) ?? '0');
  const y = BigInt((await page.locator('#public-key').textContent()) ?? '0');
  expect(x).toBeGreaterThan(0n);
  expect(x).toBeLessThan(Q);
  expect(y).toBe(modPow(G, x, P)); // the page's own y, re-derived from its own x

  await page.locator('#message-input').fill('42');
  await page.locator('#encrypt-btn').click();
  const enc = await textOf(page, 'encrypt-output');
  expect(await stateOf(page, 'encrypt-output')).toBe('ok');
  const m = numAfter(enc, 'Message m =');
  const k = numAfter(enc, 'k =');
  const c1 = numAfter(enc, 'c1 = g^k mod p =');
  const c2 = numAfter(enc, 'c2 = m · y^k mod p =');
  expect(m).toBe(42n);
  expect(c1).toBe(modPow(G, k, P));
  expect(c2).toBe((m * modPow(y, k, P)) % P);
  expect(pairAfter(enc, 'Ciphertext')).toEqual({ c1, c2 });

  await page.locator('#decrypt-btn').click();
  const dec = await textOf(page, 'decrypt-output');
  expect(await stateOf(page, 'decrypt-output')).toBe('ok');
  expect(pairAfter(dec, 'Ciphertext')).toEqual({ c1, c2 });
  const s = numAfter(dec, 's = c1^x mod p =');
  const sInv = numAfter(dec, 's⁻¹ mod p =');
  const recovered = numAfter(dec, 'm = c2 · s⁻¹ mod p =');
  expect(s).toBe(modPow(c1, x, P));
  expect((s * sInv) % P).toBe(1n);
  expect(recovered).toBe((c2 * sInv) % P);
  expect(recovered).toBe(m);
  expect(dec).toContain('Recovered original: Yes');
});

test('text mode encodes UTF-8 to a group element and decodes it back', async ({ page }) => {
  await page.goto('.');
  await page.locator('#keygen-btn').click();
  await page.locator('#message-mode').selectOption('text');
  // The toy group only fits a single byte (m = 0x01 ‖ byte), so the default
  // "yes" must be refused rather than silently truncated.
  await expect(page.locator('#message-input')).toHaveValue('yes');
  await page.locator('#encrypt-btn').click();
  expect(await stateOf(page, 'encrypt-output')).toBe('error');
  expect(await textOf(page, 'encrypt-output')).toContain('Message must be in [1, p-1]');

  await page.locator('#message-input').fill('A');
  await page.locator('#encrypt-btn').click();
  expect(await stateOf(page, 'encrypt-output')).toBe('ok');
  const m = numAfter(await textOf(page, 'encrypt-output'), 'Message m =');
  expect(m).toBe((1n << 8n) | 65n); // length-prefixed 'A'

  await page.locator('#decrypt-btn').click();
  const dec = await textOf(page, 'decrypt-output');
  expect(numAfter(dec, 'm = c2 · s⁻¹ mod p =')).toBe(m);
  expect(dec).toContain('Recovered original: Yes');
  expect(dec).toContain('Decoded text: "A"');
});

test('encryption is non-deterministic and still decrypts in RFC 3526 Group 14', async ({ page }) => {
  test.setTimeout(60000);
  await page.goto('.');

  // Switching groups must clear the old keys rather than mix parameter sets.
  await page.locator('#keygen-btn').click();
  await expect(page.locator('#private-key')).not.toHaveText('Not generated');
  await page.locator('#group-select').selectOption('rfc3526');
  await expect(page.locator('#private-key')).toHaveText('Not generated');
  await expect(page.locator('#public-key')).toHaveText('Not generated');
  expect(await textOf(page, 'encrypt-output')).toContain('RFC 3526 Group 14 (2048-bit) selected');

  await page.locator('#keygen-btn').click();
  const pub = (await page.locator('#public-key').textContent()) ?? '';
  // A real 2048-bit modulus: p has 617 decimal digits, so y must be in that range.
  expect(digitsAfter(pub, 'digits=')).toBeGreaterThan(600);

  await page.locator('#message-input').fill('42');
  await page.locator('#encrypt-btn').click();
  const first = await textOf(page, 'encrypt-output');
  expect(first).toContain('Run "Encrypt Again" to observe non-determinism directly.');
  const firstC1 = lineOf(first, 'c1 = g^k mod p =');

  await page.locator('#encrypt-again-btn').click();
  const again = await textOf(page, 'encrypt-output');
  expect(again).toContain('Same plaintext encrypted again.');
  expect(again).toContain('Different: Yes');
  // The verdict is backed by the two rendered c1 values actually differing.
  const prevLine = lineOf(again, 'Previous c1 =');
  const newLine = lineOf(again, 'New c1      =');
  expect(prevLine.replace('Previous c1 =', '').trim()).not.toBe(newLine.replace('New c1      =', '').trim());
  expect(lineOf(again, 'c1 = g^k mod p =')).not.toBe(firstC1);

  await page.locator('#decrypt-btn').click();
  const dec = await textOf(page, 'decrypt-output');
  expect(await stateOf(page, 'decrypt-output')).toBe('ok');
  expect(numAfter(dec, 'm = c2 · s⁻¹ mod p =')).toBe(42n);
  expect(dec).toContain('Recovered original: Yes');
});

test('exhibit 1 refuses every invalid input with a reason', async ({ page }) => {
  await page.goto('.');

  for (const id of ['encrypt-btn', 'decrypt-btn'] as const) {
    await page.locator(`#${id}`).click();
  }
  expect(await stateOf(page, 'encrypt-output')).toBe('error');
  expect(await textOf(page, 'encrypt-output')).toContain('Generate a keypair first.');
  expect(await stateOf(page, 'decrypt-output')).toBe('error');
  expect(await textOf(page, 'decrypt-output')).toContain('Generate a keypair first.');

  await page.locator('#rerand-btn').click();
  expect(await stateOf(page, 'rerand-output')).toBe('error');
  expect(await textOf(page, 'rerand-output')).toContain('Generate a keypair first.');

  await page.locator('#keygen-btn').click();

  await page.locator('#decrypt-btn').click();
  expect(await stateOf(page, 'decrypt-output')).toBe('error');
  expect(await textOf(page, 'decrypt-output')).toContain('No ciphertext available. Encrypt first.');

  await page.locator('#rerand-btn').click();
  expect(await stateOf(page, 'rerand-output')).toBe('error');
  expect(await textOf(page, 'rerand-output')).toContain('Encrypt first to create a ciphertext to re-randomize.');

  await page.locator('#message-input').fill('abc');
  await page.locator('#encrypt-btn').click();
  expect(await stateOf(page, 'encrypt-output')).toBe('error');
  expect(await textOf(page, 'encrypt-output')).toContain('Integer mode requires a positive decimal integer.');

  await page.locator('#message-input').fill('2039'); // == p, one past the legal range
  await page.locator('#encrypt-btn').click();
  expect(await stateOf(page, 'encrypt-output')).toBe('error');
  expect(await textOf(page, 'encrypt-output')).toContain('Message must satisfy 1 <= m <= p-1 (p=2039).');

  await page.locator('#message-input').fill('0');
  await page.locator('#encrypt-btn').click();
  expect(await stateOf(page, 'encrypt-output')).toBe('error');
  expect(await textOf(page, 'encrypt-output')).toContain('Message must satisfy 1 <= m <= p-1');
});

// --- Discrete-log visualization ---------------------------------------------

test('the discrete-log scatter plots the whole subgroup and the marker sits on it', async ({ page }) => {
  await page.goto('.');

  const dots = page.locator('#viz-container circle.viz-pt');
  await expect(dots).toHaveCount(Number(Q)); // one point per exponent 0..q-1
  const cxs = await dots.evaluateAll((els) => els.map((e) => e.getAttribute('cx')));
  expect(new Set(cxs).size).toBe(Number(Q)); // every exponent has its own column

  const slider = page.locator('#viz-exp');
  await expect(slider).toHaveAttribute('max', String(Q - 1n));

  for (const exp of [0n, 1n, 500n, 1018n]) {
    await slider.fill(String(exp));
    await slider.dispatchEvent('input');
    const expected = modPow(G, exp, P);
    await expect(page.locator('#viz-exp-out')).toHaveText(String(exp));
    await expect(page.locator('#viz-readout')).toHaveText(`x = ${exp}, y = g^${exp} mod p = ${expected}`);

    // The highlighted marker must land on an actual plotted point, not near it.
    const cx = await page.locator('#viz-marker').getAttribute('cx');
    const cy = await page.locator('#viz-marker').getAttribute('cy');
    await expect(page.locator(`#viz-container circle.viz-pt[cx="${cx}"][cy="${cy}"]`).first()).toHaveCount(1);
  }

  await page.locator('#viz-random').click();
  const randomExp = BigInt(await slider.inputValue());
  expect(randomExp).toBeGreaterThan(0n);
  expect(randomExp).toBeLessThan(Q);
  await expect(page.locator('#viz-readout')).toHaveText(
    `x = ${randomExp}, y = g^${randomExp} mod p = ${modPow(G, randomExp, P)}`
  );
});

// --- Exhibit 2: multiplicative homomorphism ---------------------------------

test('homomorphic product decrypts to m1·m2 mod p, including when it wraps', async ({ page }) => {
  await page.goto('.');

  const run = async (m1: bigint, m2: bigint): Promise<void> => {
    await page.locator('#homo-m1').fill(String(m1));
    await page.locator('#homo-m2').fill(String(m2));
    await page.locator('#homo-btn').click();
    const out = await textOf(page, 'homo-output');
    expect(await stateOf(page, 'homo-output')).toBe('ok');

    const ct1 = pairAfter(out, 'CT1 =');
    const ct2 = pairAfter(out, 'CT2 =');
    const ct3 = pairAfter(out, 'CT3 = CT1 ⊗ CT2 =');
    // The combined ciphertext is the componentwise product of the two shown.
    expect(ct3.c1).toBe((ct1.c1 * ct2.c1) % P);
    expect(ct3.c2).toBe((ct1.c2 * ct2.c2) % P);

    const decrypted = numAfter(out, 'Decrypt(CT3) =');
    const expected = numAfter(out, 'Expected m1·m2 mod p =');
    expect(expected).toBe((m1 * m2) % P);
    expect(decrypted).toBe(expected);
    expect(out).toContain('Match: Yes');
  };

  await run(3n, 7n); // 21, no reduction
  await run(1000n, 1000n); // 1000000 mod 2039 = 890, reduction is visible
  await run(2038n, 2038n); // (p-1)^2 mod p = 1

  await page.locator('#homo-m1').fill('0');
  await page.locator('#homo-btn').click();
  expect(await stateOf(page, 'homo-output')).toBe('error');
  expect(await textOf(page, 'homo-output')).toContain('Use values in range 1..2038 for toy homomorphic demo.');
});

// --- Exhibit 3: re-randomization and mix-nets -------------------------------

test('re-randomization changes the ciphertext but not the plaintext', async ({ page }) => {
  await page.goto('.');
  await page.locator('#keygen-btn').click();
  await page.locator('#message-input').fill('42');
  await page.locator('#encrypt-btn').click();
  const original = pairAfter(await textOf(page, 'encrypt-output'), 'Ciphertext');

  await page.locator('#rerand-btn').click();
  const out = await textOf(page, 'rerand-output');
  expect(await stateOf(page, 'rerand-output')).toBe('ok');

  expect(pairAfter(out, 'Original:')).toEqual(original);
  const refreshed = pairAfter(out, 'Re-random.:');
  expect(refreshed).not.toEqual(original); // c1 = c1·g^k' with k' >= 1 always moves
  expect(out).toContain('Ciphertext changed: Yes');

  const before = numAfter(out, 'Decrypt(original) =');
  const after = numAfter(out, 'Decrypt(rerandom) =');
  expect(before).toBe(42n);
  expect(after).toBe(before);
  expect(out).toContain('Same plaintext: Yes');
});

test('the mix-net shuffles and refreshes three ballots without losing them', async ({ page }) => {
  await page.goto('.');
  await page.locator('#mixnet-btn').click();
  const out = await textOf(page, 'mixnet-output');
  expect(await stateOf(page, 'mixnet-output')).toBe('ok');

  const inputs = ['Alice:', 'Bob:', 'Charlie:'].map((label) => pairAfter(out, label));
  const outputs = ['Out1:', 'Out2:', 'Out3:'].map((label) => pairAfter(out, label));
  const decrypted = ['Out1:', 'Out2:', 'Out3:'].map((label) => numAfter(lineOf(out, label), 'decrypts to'));

  // Every ballot survives the mix, and the multiset is preserved.
  expect([...decrypted].sort((a, b) => Number(a - b))).toEqual([11n, 19n, 29n]);
  // ...but the order is not the input order (Charlie, Alice, Bob).
  expect(decrypted).toEqual([29n, 11n, 19n]);
  // ...and no output ciphertext is byte-identical to any input ciphertext.
  const inputKeys = new Set(inputs.map((c) => `${c.c1},${c.c2}`));
  for (const o of outputs) expect(inputKeys.has(`${o.c1},${o.c2}`)).toBe(false);
  expect(new Set(outputs.map((c) => `${c.c1},${c.c2}`)).size).toBe(3);
});

// --- Security Lab: cracking the toy key -------------------------------------

test('the discrete-log attack recovers the toy private key in a countable number of steps', async ({ page }) => {
  await page.goto('.');
  await page.locator('#crack-btn').click();
  const out = await textOf(page, 'crack-output');
  expect(await stateOf(page, 'crack-output')).toBe('ok');

  const y = numAfter(out, 'Public key y =');
  const recovered = numAfter(out, 'Recovered x =');
  const actual = numAfter(out, 'Actual x    =');
  expect(recovered).toBe(actual);
  expect(modPow(G, recovered, P)).toBe(y); // the recovered exponent really opens y
  expect(out).toContain('Key recovered: Yes');

  // The step counter is baby-step/giant-step's own cost, not decoration:
  // m table insertions, then floor(x/m)+1 giant steps before the hit.
  const m = sqrtCeil(Q); // 32
  const steps = numAfter(out, 'Baby-step/giant-step operations:');
  expect(steps).toBe(m + recovered / m + 1n);
  expect(steps).toBeLessThan(Q); // strictly cheaper than the naive scan it cites
  expect(out).toContain(`naive search would scan up to ${Q}`);
});

// --- Security Lab: ephemeral-key reuse --------------------------------------

test('reusing k leaks the secret plaintext to an attacker with no private key', async ({ page }) => {
  await page.goto('.');
  await page.locator('#kreuse-m1').fill('123');
  await page.locator('#kreuse-m2').fill('1337');
  await page.locator('#kreuse-btn').click();
  const out = await textOf(page, 'kreuse-output');
  expect(await stateOf(page, 'kreuse-output')).toBe('ok');

  const ct1 = pairAfter(out, 'CT1 =');
  const ct2 = pairAfter(out, 'CT2 =');
  expect(ct1.c1).toBe(ct2.c1); // the tell: one k, one c1
  expect(out).toContain('Shared c1 (the tell): Yes');

  // With a shared mask, c2 = m·y^k gives m1·c2₂ ≡ m2·c2₁ (mod p) — the identity
  // the attack turns into a single division. Checked without any inverse here.
  expect((123n * ct2.c2) % P).toBe((1337n * ct1.c2) % P);

  expect(numAfter(out, 'Recovered m2 =')).toBe(1337n);
  expect(numAfter(out, 'Actual m2    =')).toBe(1337n);
  expect(out).toContain('Secret leaked: Yes');

  await page.locator('#kreuse-m2').fill('9999');
  await page.locator('#kreuse-btn').click();
  expect(await stateOf(page, 'kreuse-output')).toBe('error');
  expect(await textOf(page, 'kreuse-output')).toContain('Use values in range 1..2038 for the toy group.');
});

// --- Security Lab: malleability ---------------------------------------------

test('mauling c2 by t silently turns the decryption into m·t mod p', async ({ page }) => {
  await page.goto('.');

  const maul = async (m: bigint, t: bigint): Promise<string> => {
    await page.locator('#maul-secret').fill(String(m));
    await page.locator('#maul-factor').fill(String(t));
    await page.locator('#maul-btn').click();
    const out = await textOf(page, 'maul-output');
    expect(await stateOf(page, 'maul-output')).toBe('ok');

    const honest = pairAfter(out, 'Honest ciphertext');
    const forged = pairAfter(out, 'Forged ciphertext');
    expect(forged.c1).toBe(honest.c1); // c1 untouched — no key, no fresh k
    expect(forged.c2).toBe((honest.c2 * t) % P);

    const decrypted = numAfter(out, 'Owner decrypts forged CT →');
    const predicted = numAfter(out, 'Predicted m·t mod p     →');
    expect(predicted).toBe((m * t) % P);
    expect(decrypted).toBe(predicted);
    return out;
  };

  expect(await maul(100n, 2n)).toContain('Decryption silently altered: Yes');
  // Wrapping case: 1500·3 = 4500 ≡ 422 (mod 2039).
  expect(await maul(1500n, 3n)).toContain('Decryption silently altered: Yes');
  // t = 1 is the identity, so the verdict must honestly say nothing changed.
  expect(await maul(100n, 1n)).toContain('Decryption silently altered: No');

  await page.locator('#maul-factor').fill('2039');
  await page.locator('#maul-btn').click();
  expect(await stateOf(page, 'maul-output')).toBe('error');
  expect(await textOf(page, 'maul-output')).toContain('Use values in range 1..2038 for the toy group.');
});

// --- Defense: authenticated ElGamal -----------------------------------------

test('authenticated ElGamal accepts the honest ciphertext and rejects the mauled one', async ({ page }) => {
  await page.goto('.');
  await page.locator('#auth-secret').fill('100');
  await page.locator('#auth-factor').fill('2');
  await page.locator('#auth-btn').click();
  await expect(page.locator('#auth-output')).toContainText('Owner verifies MAC');
  const out = await textOf(page, 'auth-output');
  expect(await stateOf(page, 'auth-output')).toBe('ok');

  const honest = pairAfter(out, 'Authenticated ciphertext');
  const forged = pairAfter(out, 'Forged ciphertext');
  expect(forged.c1).toBe(honest.c1);
  expect(forged.c2).toBe((honest.c2 * 2n) % P); // the exact exhibit-6 attack
  expect(lineOf(out, 'MAC tag =')).toMatch(/MAC tag = [0-9a-f]{32}…/);

  expect(out).toContain('Honest decrypt → authentic: Yes');
  expect(numAfter(out, 'authentic: Yes, m =')).toBe(100n);
  expect(out).toContain('Owner verifies MAC → authentic: No');
  expect(out).toContain('Tampering REJECTED — the recomputed MAC does not match, so decryption is refused.');
  expect(out).not.toContain('still verifies');

  // t = 1 does not modify the ciphertext, so the tag must still verify —
  // the exhibit has to say so rather than claim a detection it did not make.
  await page.locator('#auth-factor').fill('1');
  await page.locator('#auth-btn').click();
  await expect(page.locator('#auth-output')).toContainText('t = 1 leaves the ciphertext unchanged');
  const unchanged = await textOf(page, 'auth-output');
  const honest1 = pairAfter(unchanged, 'Authenticated ciphertext');
  expect(pairAfter(unchanged, 'Forged ciphertext')).toEqual(honest1);
  expect(unchanged).toContain('Owner verifies MAC → authentic: Yes');
  expect(unchanged).not.toContain('Tampering REJECTED');

  await page.locator('#auth-secret').fill('0');
  await page.locator('#auth-btn').click();
  await expect(page.locator('#auth-output')).toHaveAttribute('data-state', 'error');
  expect(await textOf(page, 'auth-output')).toContain('Use values in range 1..2038 for the toy group.');
});

// --- Part 2: signatures ------------------------------------------------------

test('a signature verifies against the rendered (r, s) and fails on a changed message', async ({ page }) => {
  await page.goto('.');
  await page.locator('#sign-msg').fill('1234');
  await page.locator('#sign-btn').click();
  const out = await textOf(page, 'sign-output');
  expect(await stateOf(page, 'sign-output')).toBe('ok');

  const y = numAfter(out, 'Public key y = g^x mod p =');
  const x = numAfter(out, '(private x =');
  const h = numAfter(out, 'Sign h =');
  const k = numAfter(out, 'ephemeral k =');
  const { c1: r, c2: s } = pairAfter(out, 'Signature (r, s) =');

  expect(h).toBe(1234n);
  expect(y).toBe(modPow(SIGN_G, x, P)); // primitive-root group, g = 7
  expect(r).toBe(modPow(SIGN_G, k, P));
  expect(mod(s * k, SIGN_N)).toBe(mod(h - x * r, SIGN_N)); // the signing congruence
  expect(verifySignature(h, r, s, y)).toBe(true); // recomputed, not trusted
  expect(out).toContain('Verify g^h ≡ y^r · r^s (mod p): Yes');

  const tamperedH = numAfter(out, 'different message h =');
  expect(tamperedH).not.toBe(h);
  expect(verifySignature(tamperedH, r, s, y)).toBe(false);
  expect(lineOf(out, 'different message h =')).toContain(': No');

  for (const bad of ['0', '2038']) {
    await page.locator('#sign-msg').fill(bad);
    await page.locator('#sign-btn').click();
    expect(await stateOf(page, 'sign-output')).toBe('error');
    expect(await textOf(page, 'sign-output')).toContain('Use values in range 1..2037 for the signature demo.');
  }
});

test('nonce reuse across two signatures hands over the whole private key', async ({ page }) => {
  await page.goto('.');
  await page.locator('#sigreuse-m1').fill('111');
  await page.locator('#sigreuse-m2').fill('222');
  await page.locator('#sigreuse-btn').click();
  const out = await textOf(page, 'sigreuse-output');
  expect(await stateOf(page, 'sigreuse-output')).toBe('ok');

  const sig1 = pairAfter(out, 'Signature 1 on h1');
  const sig2 = pairAfter(out, 'Signature 2 on h2');
  const h1 = numAfter(out, 'Signature 1 on h1 =');
  const h2 = numAfter(out, 'Signature 2 on h2 =');
  expect(h1).toBe(111n);
  expect(h2).toBe(222n);
  expect(sig1.c1).toBe(sig2.c1); // shared r is the tell
  expect(out).toContain('Shared r (the tell): Yes');

  const r = sig1.c1;
  const s1 = sig1.c2;
  const s2 = sig2.c2;
  const recoveredK = numAfter(out, 'Recovered k =');
  const actualK = numAfter(out, '(actual');
  const recoveredX = numAfter(out, 'Recovered private key x =');
  const actualX = numAfter(out, 'Actual private key x    =');

  expect(recoveredK).toBe(actualK);
  expect(r).toBe(modPow(SIGN_G, recoveredK, P)); // g^k = r, so k is the real nonce
  expect(mod((s1 - s2) * recoveredK, SIGN_N)).toBe(mod(h1 - h2, SIGN_N)); // the solved congruence
  expect(recoveredX).toBe(actualX);
  expect(mod(r * recoveredX, SIGN_N)).toBe(mod(h1 - s1 * recoveredK, SIGN_N));
  // Both signatures satisfy the verification identity under the public key the
  // stolen x implies — i.e. the recovered key really is the signer's key.
  const y = modPow(SIGN_G, recoveredX, P);
  expect(signatureIdentityHolds(h1, r, s1, y)).toBe(true);
  expect(signatureIdentityHolds(h2, r, s2, y)).toBe(true);
  expect(out).toContain('Full key compromised: Yes');

  await page.locator('#sigreuse-m2').fill('111');
  await page.locator('#sigreuse-btn').click();
  expect(await stateOf(page, 'sigreuse-output')).toBe('error');
  expect(await textOf(page, 'sigreuse-output')).toContain('Use two different messages so the signatures differ.');
});

// --- Page-level promises -----------------------------------------------------

test('the ElGamal vs RSA exhibit contrasts both hard problems', async ({ page }) => {
  await page.goto('.');
  const rows = page.locator('table tbody tr');
  await expect(rows).toHaveCount(6);
  await expect(rows.nth(0)).toContainText('Discrete Logarithm Problem');
  await expect(rows.nth(0)).toContainText('Integer Factorization');
  await expect(rows.nth(1)).toContainText('Pair (c1, c2)');
  await expect(rows.nth(2)).toContainText('Yes (fresh k each encryption)');
  await expect(page.locator('#group-select option')).toHaveCount(2);
});

test.describe('copy buttons', () => {
  test.use({ permissions: ['clipboard-read', 'clipboard-write'] });

  test('copying an output puts exactly the rendered text on the clipboard', async ({ page }) => {
    await page.goto('.');
    await page.locator('#crack-btn').click();
    const rendered = (await textOf(page, 'crack-output')).trim();

    await page.locator('.copy-btn[data-copy="crack-output"]').click();
    await expect(page.locator('.copy-btn[data-copy="crack-output"]')).toHaveText('Copied');
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    expect(clip).toBe(rendered);
  });
});
