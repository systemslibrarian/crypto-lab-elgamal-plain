import './style.css';
import { decrypt, encrypt, generateKeyPair, messageToText, multiplyHomomorphic, rerandomize, textToMessage, type ElGamalCiphertext, type ElGamalKeyPair } from './elgamal';
import { GROUP14, TOY_GROUP, type ElGamalGroup } from './groups';
import { modInverse, modPow } from './modular';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app root element.');
}

app.innerHTML = `
  <main class="page" aria-labelledby="page-title">
    <header class="hero">
      <p class="kicker">crypto-lab-elgamal-plain</p>
      <h1 id="page-title">ElGamal: The First Practical Public-Key Encryption</h1>
      <p class="subtitle">
        Live, browser-only ElGamal over a toy group and RFC 3526 Group 14. Watch non-determinism,
        decryption math, homomorphic multiplication, and ciphertext re-randomization.
      </p>
      <div class="hero-actions">
        <button id="theme-toggle" type="button" aria-label="Toggle color theme">Toggle Theme</button>
      </div>
    </header>

    <section class="card" aria-labelledby="exhibit1-title">
      <h2 id="exhibit1-title">Exhibit 1: How ElGamal Works</h2>
      <div class="grid two">
        <label>
          Group
          <select id="group-select" aria-describedby="group-note">
            <option value="toy">TOY (p = 2039) - NOT SECURE</option>
            <option value="rfc3526">RFC 3526 Group 14 (2048-bit)</option>
          </select>
        </label>
        <button id="keygen-btn" type="button">Generate Keypair</button>
      </div>
      <p id="group-note" class="note">TOY mode is for visualization only and is completely insecure.</p>

      <div class="keybox">
        <p><strong>Private key x:</strong> <span id="private-key" aria-live="polite">Not generated</span></p>
        <p><strong>Public key y = g<sup>x</sup> mod p:</strong> <span id="public-key" aria-live="polite">Not generated</span></p>
      </div>

      <div class="grid two">
        <label>
          Message mode
          <select id="message-mode">
            <option value="integer">Integer</option>
            <option value="text">Text (UTF-8)</option>
          </select>
        </label>
        <label>
          Message m
          <input id="message-input" type="text" value="42" />
        </label>
      </div>

      <div class="actions">
        <button id="encrypt-btn" type="button">Encrypt</button>
        <button id="encrypt-again-btn" type="button">Encrypt Again</button>
        <button id="decrypt-btn" type="button">Decrypt Last Ciphertext</button>
      </div>

      <pre id="encrypt-output" class="output" aria-live="polite">Generate keys, then encrypt a message.</pre>
      <pre id="decrypt-output" class="output" aria-live="polite"></pre>
    </section>

    <section class="card" aria-labelledby="exhibit2-title">
      <h2 id="exhibit2-title">Exhibit 2: Multiplicative Homomorphism</h2>
      <p class="note">This exhibit uses the toy group so every step is human-readable.</p>
      <div class="grid three">
        <label>m1 <input id="homo-m1" type="number" value="3" min="1" max="2038" /></label>
        <label>m2 <input id="homo-m2" type="number" value="7" min="1" max="2038" /></label>
        <button id="homo-btn" type="button">Compute E(m1) ⊗ E(m2)</button>
      </div>
      <pre id="homo-output" class="output" aria-live="polite">Set m1 and m2, then run the homomorphic demo.</pre>
    </section>

    <section class="card" aria-labelledby="exhibit3-title">
      <h2 id="exhibit3-title">Exhibit 3: Re-randomization and Mix-Nets</h2>
      <div class="actions">
        <button id="rerand-btn" type="button">Re-randomize Last Ciphertext</button>
        <button id="mixnet-btn" type="button">Run 3-message Mix-Net Simulation</button>
      </div>
      <pre id="rerand-output" class="output" aria-live="polite">Encrypt a message first, then re-randomize.</pre>
      <pre id="mixnet-output" class="output" aria-live="polite">Run simulation to see shuffled, re-randomized ciphertexts.</pre>
    </section>

    <section class="card" aria-labelledby="exhibit4-title">
      <h2 id="exhibit4-title">Exhibit 4: ElGamal vs RSA</h2>
      <div class="table-wrap" role="region" aria-label="ElGamal versus RSA comparison" tabindex="0">
        <table>
          <thead>
            <tr>
              <th>Property</th>
              <th>ElGamal (1985)</th>
              <th>RSA (1977)</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>Security assumption</td><td>Discrete Logarithm Problem</td><td>Integer Factorization</td></tr>
            <tr><td>Ciphertext shape</td><td>Pair (c1, c2)</td><td>Single integer</td></tr>
            <tr><td>Native non-determinism</td><td>Yes (fresh k each encryption)</td><td>No (needs OAEP)</td></tr>
            <tr><td>Homomorphism</td><td>Multiplicative</td><td>Multiplicative (textbook)</td></tr>
            <tr><td>Post-quantum</td><td>No (Shor breaks DLP)</td><td>No (Shor breaks factoring)</td></tr>
            <tr><td>Common direct usage</td><td>E-voting, mix-nets, threshold systems</td><td>General PKI, legacy encryption/signatures</td></tr>
          </tbody>
        </table>
      </div>
      <p class="note">Taher ElGamal also designed SSL 3.0 at Netscape, a direct ancestor of modern TLS.</p>
    </section>

    <section class="card" aria-labelledby="exhibit5-title">
      <h2 id="exhibit5-title">Exhibit 5: Why ElGamal Matters Today</h2>
      <ul class="list">
        <li><strong>DSA:</strong> ElGamal signature variant standardized in FIPS 186.</li>
        <li><strong>Threshold ElGamal:</strong> t-of-n distributed decryption for robust trust.</li>
        <li><strong>Exponential ElGamal:</strong> Additive tallying in e-voting systems.</li>
        <li><strong>Cramer-Shoup:</strong> ElGamal-style structure hardened for IND-CCA2.</li>
        <li><strong>Elliptic Curve ElGamal:</strong> Same design with smaller key sizes.</li>
      </ul>
      <p class="note">Cross-links: crypto-lab-threshold-decrypt, crypto-lab-rsa-forge, crypto-lab-blind-sign, crypto-lab-ecdsa-forge, crypto-lab-zk-proof-lab.</p>
    </section>
  </main>
`;

const groupSelect = must<HTMLSelectElement>('group-select');
const messageModeSelect = must<HTMLSelectElement>('message-mode');
const messageInput = must<HTMLInputElement>('message-input');
const privateKeyOut = must<HTMLSpanElement>('private-key');
const publicKeyOut = must<HTMLSpanElement>('public-key');
const encryptOut = must<HTMLElement>('encrypt-output');
const decryptOut = must<HTMLElement>('decrypt-output');
const rerandOut = must<HTMLElement>('rerand-output');
const homoOut = must<HTMLElement>('homo-output');
const mixnetOut = must<HTMLElement>('mixnet-output');

let selectedGroup: ElGamalGroup = TOY_GROUP;
let keypair: ElGamalKeyPair | null = null;
let lastCiphertext: ElGamalCiphertext | null = null;
let lastMessage: bigint | null = null;
let lastK: bigint | null = null;
let previousCiphertext: ElGamalCiphertext | null = null;

function must<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element #${id}`);
  return el as T;
}

function formatBig(n: bigint, maxLen = 96): string {
  const value = n.toString();
  if (value.length <= maxLen) return value;
  return `${value.slice(0, 40)}...${value.slice(-40)} (digits=${value.length})`;
}

function currentGroup(): ElGamalGroup {
  return groupSelect.value === 'rfc3526' ? GROUP14 : TOY_GROUP;
}

function renderKeypair(): void {
  if (!keypair) return;
  privateKeyOut.textContent = selectedGroup.isToy ? keypair.privateKey.toString() : `${formatBig(keypair.privateKey, 40)} [hidden by default in production]`;
  publicKeyOut.textContent = formatBig(keypair.publicKey);
}

function parseMessage(): bigint {
  if (messageModeSelect.value === 'text') {
    return textToMessage(messageInput.value, selectedGroup);
  }

  const trimmed = messageInput.value.trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new Error('Integer mode requires a positive decimal integer.');
  }

  const parsed = BigInt(trimmed);
  if (parsed <= 0n || parsed >= selectedGroup.p) {
    throw new Error(`Message must satisfy 1 <= m <= p-1 (p=${selectedGroup.p}).`);
  }
  return parsed;
}

function describeCiphertext(ct: ElGamalCiphertext): string {
  return `(c1, c2) = (${formatBig(ct.c1)}, ${formatBig(ct.c2)})`;
}

function ensureKeypair(): ElGamalKeyPair {
  if (!keypair) {
    throw new Error('Generate a keypair first.');
  }
  return keypair;
}

must<HTMLButtonElement>('theme-toggle').addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
});

groupSelect.addEventListener('change', () => {
  selectedGroup = currentGroup();
  keypair = null;
  lastCiphertext = null;
  previousCiphertext = null;
  privateKeyOut.textContent = 'Not generated';
  publicKeyOut.textContent = 'Not generated';
  encryptOut.textContent = `${selectedGroup.label} selected. Generate keys to begin.`;
  decryptOut.textContent = '';
  rerandOut.textContent = 'Encrypt a message first, then re-randomize.';
});

messageModeSelect.addEventListener('change', () => {
  if (messageModeSelect.value === 'text') {
    messageInput.value = 'yes';
  } else {
    messageInput.value = '42';
  }
});

must<HTMLButtonElement>('keygen-btn').addEventListener('click', () => {
  selectedGroup = currentGroup();
  keypair = generateKeyPair(selectedGroup);
  renderKeypair();
  encryptOut.textContent = `Keypair generated in ${selectedGroup.label}.`;
});

function runEncrypt(compareOnly = false): void {
  try {
    const keys = ensureKeypair();
    const message = parseMessage();
    const result = encrypt(message, keys.publicKey, selectedGroup);

    previousCiphertext = lastCiphertext;
    lastCiphertext = result.ciphertext;
    lastMessage = message;
    lastK = result.ephemeralK;

    const yk = modPow(keys.publicKey, result.ephemeralK, selectedGroup.p);
    const nonDetLine = previousCiphertext
      ? `Previous c1=${formatBig(previousCiphertext.c1)} | New c1=${formatBig(result.ciphertext.c1)} | Different=${previousCiphertext.c1 !== result.ciphertext.c1}`
      : 'Run Encrypt Again to observe non-determinism directly.';

    encryptOut.textContent = [
      `Message m = ${formatBig(message)}`,
      `k = ${formatBig(result.ephemeralK)}`,
      `c1 = g^k mod p = ${formatBig(result.ciphertext.c1)}`,
      `c2 = m * y^k mod p = ${formatBig((message * yk) % selectedGroup.p)}`,
      `Ciphertext ${describeCiphertext(result.ciphertext)}`,
      compareOnly ? `Same plaintext encrypted again.` : '',
      nonDetLine,
    ].filter(Boolean).join('\n');
  } catch (error) {
    encryptOut.textContent = toError(error);
  }
}

must<HTMLButtonElement>('encrypt-btn').addEventListener('click', () => runEncrypt(false));
must<HTMLButtonElement>('encrypt-again-btn').addEventListener('click', () => runEncrypt(true));

must<HTMLButtonElement>('decrypt-btn').addEventListener('click', () => {
  try {
    const keys = ensureKeypair();
    if (!lastCiphertext || lastMessage === null || lastK === null) {
      throw new Error('No ciphertext available. Encrypt first.');
    }

    const s = modPow(lastCiphertext.c1, keys.privateKey, selectedGroup.p);
    const sInv = modInverse(s, selectedGroup.p);
    const recovered = decrypt(lastCiphertext, keys.privateKey, selectedGroup);

    const decoded = messageModeSelect.value === 'text'
      ? `\nDecoded text: "${messageToText(recovered, selectedGroup)}"`
      : '';

    decryptOut.textContent = [
      `Ciphertext ${describeCiphertext(lastCiphertext)}`,
      `s = c1^x mod p = ${formatBig(s)}`,
      `s^-1 mod p = ${formatBig(sInv)}`,
      `m = c2 * s^-1 mod p = ${formatBig(recovered)}`,
      `Recovered original: ${recovered === lastMessage}`,
      decoded,
    ].join('\n');
  } catch (error) {
    decryptOut.textContent = toError(error);
  }
});

must<HTMLButtonElement>('homo-btn').addEventListener('click', () => {
  try {
    const m1 = BigInt(must<HTMLInputElement>('homo-m1').value);
    const m2 = BigInt(must<HTMLInputElement>('homo-m2').value);
    if (m1 <= 0n || m2 <= 0n || m1 >= TOY_GROUP.p || m2 >= TOY_GROUP.p) {
      throw new Error('Use values in range 1..2038 for toy homomorphic demo.');
    }

    const keys = generateKeyPair(TOY_GROUP);
    const ct1 = encrypt(m1, keys.publicKey, TOY_GROUP).ciphertext;
    const ct2 = encrypt(m2, keys.publicKey, TOY_GROUP).ciphertext;
    const ct3 = multiplyHomomorphic(ct1, ct2);
    const out = decrypt(ct3, keys.privateKey, TOY_GROUP);

    homoOut.textContent = [
      `CT1 = ${describeCiphertext(ct1)}`,
      `CT2 = ${describeCiphertext(ct2)}`,
      `CT3 = CT1 ⊗ CT2 = ${describeCiphertext(ct3)}`,
      `Decrypt(CT3) = ${out}`,
      `Expected m1*m2 mod p = ${(m1 * m2) % TOY_GROUP.p}`,
    ].join('\n');
  } catch (error) {
    homoOut.textContent = toError(error);
  }
});

must<HTMLButtonElement>('rerand-btn').addEventListener('click', () => {
  try {
    const keys = ensureKeypair();
    if (!lastCiphertext || lastMessage === null) {
      throw new Error('Encrypt first to create a ciphertext to re-randomize.');
    }

    const refreshed = rerandomize(lastCiphertext, keys.publicKey, selectedGroup);
    const originalPlain = decrypt(lastCiphertext, keys.privateKey, selectedGroup);
    const refreshedPlain = decrypt(refreshed, keys.privateKey, selectedGroup);

    rerandOut.textContent = [
      `Original:   ${describeCiphertext(lastCiphertext)}`,
      `Re-random.: ${describeCiphertext(refreshed)}`,
      `Ciphertext changed: ${lastCiphertext.c1 !== refreshed.c1 || lastCiphertext.c2 !== refreshed.c2}`,
      `Decrypt(original) = ${formatBig(originalPlain)}`,
      `Decrypt(rerandom) = ${formatBig(refreshedPlain)}`,
      `Same plaintext: ${originalPlain === refreshedPlain}`,
    ].join('\n');

    lastCiphertext = refreshed;
  } catch (error) {
    rerandOut.textContent = toError(error);
  }
});

must<HTMLButtonElement>('mixnet-btn').addEventListener('click', () => {
  try {
    const keys = generateKeyPair(TOY_GROUP);
    const labels = ['Alice', 'Bob', 'Charlie'];
    const messages = [11n, 19n, 29n];

    const encrypted = messages.map((m, i) => ({
      label: labels[i],
      ct: encrypt(m, keys.publicKey, TOY_GROUP).ciphertext,
      m,
    }));

    const rerandomized = encrypted.map((entry) => ({
      ...entry,
      ct: rerandomize(entry.ct, keys.publicKey, TOY_GROUP),
    }));

    const shuffled = [rerandomized[2], rerandomized[0], rerandomized[1]];

    mixnetOut.textContent = [
      'Inputs:',
      ...encrypted.map((e) => `${e.label}: ${describeCiphertext(e.ct)}`),
      '',
      'Outputs after re-randomize + shuffle:',
      ...shuffled.map((e, idx) => `Out${idx + 1}: ${describeCiphertext(e.ct)} -> decrypts to ${decrypt(e.ct, keys.privateKey, TOY_GROUP)}`),
      '',
      'Observer sees changed bytes and changed order, but cannot link sender to output without secret permutation info.',
    ].join('\n');
  } catch (error) {
    mixnetOut.textContent = toError(error);
  }
});

function toError(error: unknown): string {
  if (error instanceof Error) {
    return `Error: ${error.message}`;
  }
  return 'Error: Unknown failure.';
}
