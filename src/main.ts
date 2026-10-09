import './style.css';
import { decrypt, encrypt, encryptWithEphemeral, generateKeyPair, messageToText, multiplyHomomorphic, rerandomize, textToMessage, type ElGamalCiphertext, type ElGamalKeyPair } from './elgamal';
import { GROUP14, TOY_GROUP, type ElGamalGroup } from './groups';
import { modInverse, modPow, randomBigInt } from './modular';
import { discreteLog } from './attacks';
import { authEncrypt, authDecrypt } from './authenticated';
import { TOY_SIGN_GROUP, generateSignKeyPair, sign, signWithK, verify as verifySignature, recoverKeyFromReusedNonce } from './signatures';
import { csAlpha, csDecrypt, csEncodeMessage, csEncrypt, csKeygen, type CsCiphertext, type CsKeyPair } from './cramerShoup';
import { findToyAlphaCollision, makeInvalidQuery, maulCs, multiplyCs } from './csQueries';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app root element.');
}

app.innerHTML = `
  <main id="main-content" class="page" tabindex="-1" aria-labelledby="page-title">
    <header class="cl-hero">
      <div class="cl-hero-main">
        <h1 class="cl-hero-title" id="page-title">ElGamal</h1>
        <p class="cl-hero-sub">Public-Key Encryption · Discrete-Log Problem</p>
        <p class="cl-hero-desc">
          Encrypt, decrypt, multiply ciphertexts homomorphically, and re-randomize them in a
          browser-only lab over a toy group and RFC 3526 Group 14 &mdash; every value computed on your device.
        </p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">
          The discrete-log problem underpins ElGamal, DSA, and Diffie-Hellman. Homomorphic,
          non-deterministic ciphertexts power mix-nets and e-voting &mdash; yet weak groups, reused
          nonces, and malleability turn that same math into real breaks.
        </p>
      </aside>
    </header>

    <ul class="legend" aria-label="Color key for the variables used below">
        <li><span class="swatch pub" aria-hidden="true"></span> public key y</li>
        <li><span class="swatch priv" aria-hidden="true"></span> private key x</li>
        <li><span class="swatch k" aria-hidden="true"></span> ephemeral k</li>
        <li><span class="swatch c1" aria-hidden="true"></span> c1</li>
        <li><span class="swatch c2" aria-hidden="true"></span> c2</li>
        <li><span class="swatch m" aria-hidden="true"></span> message m</li>
      </ul>

    <section class="card walkthrough" aria-labelledby="walkthrough-title">
      <h2 id="walkthrough-title"><span class="badge" aria-hidden="true"></span> Guided Walkthrough</h2>
      <p class="lesson">New to ElGamal? Step through one complete encryption and decryption with every value computed
        live in the toy group. Move at your own pace with Previous and Next; the math builds up as you go.</p>
      <div class="wt-controls">
        <button id="wt-prev" type="button">&larr; Previous</button>
        <button id="wt-next" type="button">Next &rarr;</button>
        <span id="wt-progress" class="wt-progress" role="status" aria-live="polite">Step 1 of 10</span>
        <button id="wt-restart" type="button" class="wt-restart">New random run</button>
      </div>
      <div id="wt-steps" class="wt-steps"></div>
    </section>

    <section class="card" aria-labelledby="exhibit1-title">
      <h2 id="exhibit1-title"><span class="badge" aria-hidden="true"></span> How ElGamal Works</h2>
      <p class="lesson">Security rests on the <strong>discrete logarithm problem</strong>: the public key is
        <code>y = g<sup>x</sup> mod p</code>, yet recovering the private key <code>x</code> from <code>y</code>
        is believed infeasible for large <code>p</code>. Each encryption draws a fresh ephemeral <code>k</code>,
        so the same message never produces the same ciphertext twice.</p>
      <div class="grid two">
        <label for="group-select">
          Group
          <select id="group-select" aria-describedby="group-note">
            <option value="toy">TOY (p = 2039) — NOT SECURE</option>
            <option value="rfc3526">RFC 3526 Group 14 (2048-bit)</option>
          </select>
        </label>
        <div class="field-actions">
          <button id="keygen-btn" type="button">Generate Keypair</button>
        </div>
      </div>
      <p id="group-note" class="note">TOY mode is for visualization only and is completely insecure.</p>

      <div class="keybox">
        <p><strong>Private key x:</strong> <span id="private-key" class="tok priv" aria-live="polite">Not generated</span></p>
        <p><strong>Public key y = g<sup>x</sup> mod p:</strong> <span id="public-key" class="tok pub" aria-live="polite">Not generated</span></p>
      </div>

      <div class="grid two">
        <label for="message-mode">
          Message mode
          <select id="message-mode">
            <option value="integer">Integer</option>
            <option value="text">Text (UTF-8)</option>
          </select>
        </label>
        <label for="message-input">
          Message m
          <input id="message-input" type="text" value="42" autocomplete="off" inputmode="numeric" enterkeyhint="go" />
        </label>
      </div>

      <div class="actions">
        <button id="encrypt-btn" type="button">Encrypt</button>
        <button id="encrypt-again-btn" type="button">Encrypt Again</button>
        <button id="decrypt-btn" type="button">Decrypt Last Ciphertext</button>
      </div>

      <div class="output-wrap">
        <pre id="encrypt-output" class="output" aria-live="polite" aria-atomic="true">Generate keys, then encrypt a message.</pre>
        <button class="copy-btn" type="button" data-copy="encrypt-output">Copy</button>
      </div>
      <div class="output-wrap">
        <pre id="decrypt-output" class="output" aria-live="polite" aria-atomic="true"></pre>
        <button class="copy-btn" type="button" data-copy="decrypt-output">Copy</button>
      </div>
    </section>

    <section class="card" aria-labelledby="exhibit-dlog-title">
      <h2 id="exhibit-dlog-title"><span class="badge" aria-hidden="true"></span> Visualizing the Hard Problem</h2>
      <p class="lesson">Forward is easy: pick an exponent <code>x</code> and compute <code>y = g<sup>x</sup> mod p</code>.
        Backward &mdash; finding <code>x</code> from <code>y</code> &mdash; has no shortcut. The plot shows
        <code>g<sup>x</sup></code> for every <code>x</code> in the toy group: no line, curve, or pattern to exploit,
        so recovering <code>x</code> means searching. Drag the slider and watch the point leap unpredictably.</p>
      <label for="viz-exp">Exponent x = <output id="viz-exp-out">1</output>
        <input id="viz-exp" type="range" min="0" max="1018" value="1" step="1" />
      </label>
      <div class="actions">
        <button id="viz-random" type="button">Random exponent</button>
      </div>
      <div id="viz-container" class="viz-container" role="img"
        aria-label="Scatter plot of g to the power x modulo p across the toy group, showing no exploitable pattern."></div>
      <p id="viz-readout" class="note" aria-live="polite">x = 1, y = g^1 mod p = 2</p>
    </section>

    <section class="card" aria-labelledby="exhibit2-title">
      <h2 id="exhibit2-title"><span class="badge" aria-hidden="true"></span> Multiplicative Homomorphism</h2>
      <p class="lesson">Multiplying two ciphertexts componentwise yields an encryption of the <em>product</em> of the
        plaintexts &mdash; no key required. This algebraic structure is the foundation of e-voting tallies and
        threshold systems, and &mdash; as the malleability attack in the Security Lab shows &mdash; also a liability.</p>
      <p class="note">This exhibit uses the toy group so every step is human-readable.</p>
      <div class="grid three">
        <label for="homo-m1">m1 <input id="homo-m1" type="number" value="3" min="1" max="2038" inputmode="numeric" /></label>
        <label for="homo-m2">m2 <input id="homo-m2" type="number" value="7" min="1" max="2038" inputmode="numeric" /></label>
        <div class="field-actions">
          <button id="homo-btn" type="button">Compute E(m1) &otimes; E(m2)</button>
        </div>
      </div>
      <div class="output-wrap">
        <pre id="homo-output" class="output" aria-live="polite" aria-atomic="true">Set m1 and m2, then run the homomorphic demo.</pre>
        <button class="copy-btn" type="button" data-copy="homo-output">Copy</button>
      </div>
    </section>

    <section class="card" aria-labelledby="exhibit3-title">
      <h2 id="exhibit3-title"><span class="badge" aria-hidden="true"></span> Re-randomization and Mix-Nets</h2>
      <p class="lesson">Anyone holding only the public key can refresh a ciphertext into a brand-new one that decrypts to the
        <em>same</em> plaintext. Chain this with shuffling and an observer cannot link inputs to outputs &mdash;
        the engine behind anonymous mix-nets and private ballots.</p>
      <div class="actions">
        <button id="rerand-btn" type="button">Re-randomize Last Ciphertext</button>
        <button id="mixnet-btn" type="button">Run 3-message Mix-Net Simulation</button>
      </div>
      <div class="output-wrap">
        <pre id="rerand-output" class="output" aria-live="polite" aria-atomic="true">Encrypt a message first, then re-randomize.</pre>
        <button class="copy-btn" type="button" data-copy="rerand-output">Copy</button>
      </div>
      <div class="output-wrap">
        <pre id="mixnet-output" class="output" aria-live="polite" aria-atomic="true">Run simulation to see shuffled, re-randomized ciphertexts.</pre>
        <button class="copy-btn" type="button" data-copy="mixnet-output">Copy</button>
      </div>
    </section>

    <div class="section-divider" role="presentation">
      <span class="section-divider-label">Security Lab &mdash; break it yourself</span>
    </div>

    <section class="card attack" aria-labelledby="exhibit4-title">
      <h2 id="exhibit4-title"><span class="badge attack-badge" aria-hidden="true"></span> Attack: Cracking the Key</h2>
      <p class="lesson">ElGamal is only as strong as the discrete logarithm is hard. The toy group's subgroup order is
        ~1019, so we can recover the private key from the public key directly with baby-step/giant-step.
        The <em>identical</em> algorithm against RFC 3526 Group 14 would need ~2<sup>1023</sup> operations.</p>
      <div class="actions">
        <button id="crack-btn" type="button">Crack a Fresh Toy Private Key</button>
      </div>
      <div class="output-wrap">
        <pre id="crack-output" class="output" aria-live="polite" aria-atomic="true">Generate and break a toy keypair to see why key size is everything.</pre>
        <button class="copy-btn" type="button" data-copy="crack-output">Copy</button>
      </div>
    </section>

    <section class="card attack" aria-labelledby="exhibit5-title">
      <h2 id="exhibit5-title"><span class="badge attack-badge" aria-hidden="true"></span> Attack: Ephemeral-Key Reuse</h2>
      <p class="lesson">The ephemeral <code>k</code> must be fresh and secret for every message. Reuse it across two
        messages and the ciphertexts share <code>c1</code>; anyone who learns one plaintext recovers the other
        with a single division &mdash; no private key needed. This is the same class of bug that broke the PS3.</p>
      <div class="grid three">
        <label for="kreuse-m1">m1 (known to attacker) <input id="kreuse-m1" type="number" value="123" min="1" max="2038" inputmode="numeric" /></label>
        <label for="kreuse-m2">m2 (secret) <input id="kreuse-m2" type="number" value="1337" min="1" max="2038" inputmode="numeric" /></label>
        <div class="field-actions">
          <button id="kreuse-btn" type="button">Reuse k and Recover m2</button>
        </div>
      </div>
      <div class="output-wrap">
        <pre id="kreuse-output" class="output" aria-live="polite" aria-atomic="true">Encrypt two messages under one reused k, then recover the secret.</pre>
        <button class="copy-btn" type="button" data-copy="kreuse-output">Copy</button>
      </div>
    </section>

    <section class="card attack" aria-labelledby="exhibit6-title">
      <h2 id="exhibit6-title"><span class="badge attack-badge" aria-hidden="true"></span> Attack: Ciphertext Malleability</h2>
      <p class="lesson">Plain ElGamal is <strong>not</strong> CCA-secure. Without the key &mdash; without even knowing the
        plaintext &mdash; an attacker multiplies <code>c2</code> by a factor <code>t</code> and the owner's
        decryption silently becomes <code>m·t</code>. This is why real systems use a chosen-ciphertext-secure
        construction (the authenticated ElGamal below, or Cramer–Shoup) or use ElGamal only inside protocols
        that expect the homomorphism.</p>
      <div class="grid three">
        <label for="maul-secret">Secret message m <input id="maul-secret" type="number" value="100" min="1" max="2038" inputmode="numeric" /></label>
        <label for="maul-factor">Attacker factor t <input id="maul-factor" type="number" value="2" min="1" max="2038" inputmode="numeric" /></label>
        <div class="field-actions">
          <button id="maul-btn" type="button">Tamper Without the Key</button>
        </div>
      </div>
      <div class="output-wrap">
        <pre id="maul-output" class="output" aria-live="polite" aria-atomic="true">Forge a related ciphertext the owner will decrypt without noticing.</pre>
        <button class="copy-btn" type="button" data-copy="maul-output">Copy</button>
      </div>
    </section>

    <section class="card defense" aria-labelledby="exhibit7-title">
      <h2 id="exhibit7-title"><span class="badge defense-badge" aria-hidden="true"></span> Defense: Authenticated ElGamal</h2>
      <p class="lesson">The real-world fix (ECIES / DHIES): derive a MAC key from the Diffie-Hellman shared secret
        and tag the ciphertext. Now the <em>exact</em> malleability attack above is detected and the decryption is
        refused. The price is the homomorphism &mdash; the MAC breaks under mauling or re-randomization, which is
        why systems that <em>need</em> rerandomization or homomorphic tallying (mix-nets, e-voting) keep plain
        ElGamal and add zero-knowledge proofs of correct encryption and shuffling instead. Cramer–Shoup does
        not help there: it gives up the same properties.</p>
      <div class="grid three">
        <label for="auth-secret">Secret message m <input id="auth-secret" type="number" value="100" min="1" max="2038" inputmode="numeric" /></label>
        <label for="auth-factor">Attacker factor t <input id="auth-factor" type="number" value="2" min="1" max="2038" inputmode="numeric" /></label>
        <div class="field-actions">
          <button id="auth-btn" type="button">Authenticate, Then Tamper</button>
        </div>
      </div>
      <div class="output-wrap">
        <pre id="auth-output" class="output" aria-live="polite" aria-atomic="true">Encrypt with integrity, then watch the same malleability attack get rejected.</pre>
        <button class="copy-btn" type="button" data-copy="auth-output">Copy</button>
      </div>
    </section>

    <section id="exhibit-cs" class="card defense cs-card" aria-labelledby="exhibit-cs-title">
      <h2 id="exhibit-cs-title"><span class="badge defense-badge cs-badge" aria-hidden="true"></span> Defense: Cramer–Shoup — A Check the Attacker Cannot Learn From</h2>
      <p class="lesson">A valid ciphertext's check value is already fixed by public data. A malformed one's
        value is spread across the private keys that fit the same public key. Explore both outcomes, then
        ask the decryptor what an attacker could learn.</p>
      <details class="cs-equation"><summary>See the exact Cramer–Shoup check</summary>
        <p><code>u1^(x1+y1·α) · u2^(x2+y2·α) = v</code>, where <code>α = SHA-256(u1,u2,e) mod q</code>.
          This is the hash-proof idea behind chosen-ciphertext security, not the full IND-CCA2 proof.</p>
      </details>
      <nav class="cs-chapters" aria-label="Cramer–Shoup chapters">
        <button type="button" data-cs-chapter="1" aria-controls="cs-stage-1" aria-pressed="true">1 · Round trip</button>
        <button type="button" data-cs-chapter="2" aria-controls="cs-stage-2" aria-pressed="false">2 · Hidden keys</button>
        <button type="button" data-cs-chapter="3" aria-controls="cs-stage-3" aria-pressed="false">3 · Oracle queries</button>
        <button type="button" data-cs-chapter="4" aria-controls="cs-stage-4" aria-pressed="false">4 · Toy collision</button>
        <button type="button" data-cs-chapter="5" aria-controls="cs-stage-5" aria-pressed="false">5 · Tradeoff</button>
      </nav>
      <p id="cs-step-status" class="cs-step-status" aria-live="polite">Chapter 1 of 5 · Start with an honest encryption.</p>

      <section id="cs-stage-1" class="cs-stage" aria-labelledby="cs-stage-1-title">
      <h3 id="cs-stage-1-title" tabindex="-1">1. Round trip</h3>
      <p class="note">This is not a MAC: there is no tag key and the decryptor never recovers r. The check tests whether u1 and u2 use the same exponent.</p>
      <p class="note">Group 14 shows the arithmetic at a real key size; this browser implementation is a learning demo.</p>
      <div class="grid three">
        <label for="cs-group">Group<select id="cs-group"><option value="toy">TOY (p = 2039)</option><option value="group14">RFC 3526 Group 14</option></select></label>
        <label for="cs-message">Message m (1..q)<input id="cs-message" type="number" value="42" min="1" inputmode="numeric" /></label>
        <div class="field-actions"><button id="cs-round-btn" type="button">Encrypt and decrypt</button></div>
      </div>
      <div id="cs-round-takeaway" class="cs-takeaway" role="status">Run the round trip to see the two check values agree.</div>
      <div class="output-wrap"><pre id="cs-round-output" class="output" aria-live="polite">Choose a group and run the round trip.</pre><button class="copy-btn" type="button" data-copy="cs-round-output">Copy</button></div>
      <div class="actions"><button type="button" class="cs-next" data-cs-next="2">Next: what the public key hides →</button></div>
      </section>

      <section id="cs-stage-2" class="cs-stage" aria-labelledby="cs-stage-2-title" hidden>
      <h3 id="cs-stage-2-title" tabindex="-1">2. What the public key does not pin down</h3>
      <p class="note">Toy group only. The proof viewpoint computes w = log_g1(g2) and lists every key consistent with c and d. In a real-size group, an attacker cannot compute w. The printed toy key lets you audit the result; query-building code cannot use it. z is fixed by h.</p>
      <div class="actions"><button id="cs-session-btn" type="button">Start toy proof session</button><button id="cs-valid-btn" type="button">Plot valid query</button></div>
      <label for="cs-r2">Second exponent r2: <output id="cs-r2-value">32</output> <span class="note">(r1 = 31; set r2 to 31 for a valid query)</span>
        <input id="cs-r2" type="range" min="1" max="1018" value="32" /></label>
      <div class="actions"><button id="cs-invalid-btn" type="button">Plot selected query</button></div>
      <div id="cs-proof-takeaway" class="cs-takeaway" role="status">Start a toy session, then compare a valid and an invalid query.</div>
      <div id="cs-public-strip" class="cs-keyline">Public c and d appear when the toy session starts.</div>
      <details class="cs-audit"><summary>Inspect the public key and all calculations</summary>
        <div class="output-wrap"><pre id="cs-proof-output" class="output" aria-live="polite">Start a toy session to count the keys.</pre><button class="copy-btn" type="button" data-copy="cs-proof-output">Copy</button></div>
      </details>
      <div id="cs-histogram" class="cs-histogram" role="img" tabindex="0" aria-label="Check-value histogram; start a session to populate it">The check-value histogram appears here.</div>
      <p class="note">Valid: the answer is already public. Invalid: the answer depends on key bits the public key leaves free.</p>
      <div class="actions"><button type="button" class="cs-next" data-cs-next="3">Next: query the decryptor →</button></div>
      </section>

      <section id="cs-stage-3" class="cs-stage" aria-labelledby="cs-stage-3-title" hidden>
      <h3 id="cs-stage-3-title" tabindex="-1">3. Rejections teach almost nothing</h3>
      <p class="note">Each rejection rules out about 1/q of the keys that fit the public key; it does not narrow the key down the way a padding oracle does. A rare accepted invalid query is shown honestly.</p>
      <div class="grid two"><label for="cs-query-count">Invalid queries<select id="cs-query-count"><option value="20">20</option><option value="50">50</option></select></label><div class="field-actions"><button id="cs-queries-btn" type="button">Fire queries at decryptor</button></div></div>
      <div id="cs-query-progress" class="note" role="status" aria-live="polite"></div>
      <div id="cs-ledger-summary" class="cs-takeaway" role="status">Start a toy proof session in chapter 2, then fire invalid queries.</div>
      <label id="cs-survival-wrap" class="cs-survival-label" for="cs-survival-progress" hidden>Compatible keys remaining
        <progress id="cs-survival-progress" max="1038361" value="1038361">100%</progress>
      </label>
      <details class="cs-audit"><summary>Show the query-by-query audit ledger</summary>
        <div class="output-wrap"><pre id="cs-ledger-output" class="output" aria-live="polite">Start a toy session, then fire invalid queries.</pre><button class="copy-btn" type="button" data-copy="cs-ledger-output">Copy</button></div>
      </details>
      <p class="note">Plain ElGamal would return e·u1⁻ᶻ on every such query. Cramer–Shoup refuses a failed check. See the <a href="https://systemslibrarian.github.io/crypto-lab-hidden-bit/">Hidden Bit CCA2 game</a> for the chosen-ciphertext definition.</p>
      <div class="actions"><button type="button" class="cs-next" data-cs-next="4">Next: test the toy hash →</button></div>
      </section>

      <section id="cs-stage-4" class="cs-stage" aria-labelledby="cs-stage-4-title" hidden>
      <h3 id="cs-stage-4-title" tabindex="-1">4. Why α matters</h3>
      <p class="note">Toy-size α only. Change e to e·t; the new α normally breaks the check. Search the toy group's 1018 nonidentity factors for a second preimage of α. A success is a break of the tiny teaching group, not of Cramer–Shoup with SHA-256 and Group 14.</p>
      <div class="grid three"><label for="cs-maul-message">Challenge m<input id="cs-maul-message" type="number" value="100" min="1" max="1019" /></label><label for="cs-maul-factor">Factor t<input id="cs-maul-factor" type="number" value="2" min="1" max="2038" /></label><div class="field-actions"><button id="cs-maul-btn" type="button">Try e·t</button></div></div>
      <div class="actions"><button id="cs-collision-btn" type="button">Search toy α collision</button><button id="cs-retry-btn" type="button" hidden>Try a fresh challenge</button></div>
      <div id="cs-collision-takeaway" class="cs-takeaway" role="status">Try an ordinary maul, then search for a collision in the tiny hash range.</div>
      <div class="output-wrap"><pre id="cs-collision-output" class="output" aria-live="polite">Start a toy session, then try a maul or collision search.</pre><button class="copy-btn" type="button" data-copy="cs-collision-output">Copy</button></div>
      <div class="actions"><button type="button" class="cs-next" data-cs-next="5">Next: what security costs →</button></div>
      </section>

      <section id="cs-stage-5" class="cs-stage" aria-labelledby="cs-stage-5-title" hidden>
      <h3 id="cs-stage-5-title" tabindex="-1">5. The tradeoff</h3>
      <div class="table-wrap" role="region" aria-label="Cramer–Shoup and authenticated ElGamal comparison" tabindex="0"><table><thead><tr><th scope="col">Construction</th><th scope="col">Security basis</th><th scope="col">Public algebra</th></tr></thead><tbody>
        <tr><th scope="row">Cramer–Shoup</th><td>Standard model: DDH plus target-collision-resistant hash (universal one-way hash)</td><td>No rerandomization or homomorphism</td></tr>
        <tr><th scope="row">DH + HMAC</th><td>DHIES-style hybrid; Oracle DH plus MAC/encryption security</td><td>No rerandomization or homomorphism</td></tr>
      </tbody></table></div>
      <p class="note cs-table-hint">Swipe the table sideways to see every column.</p>
      <div class="actions"><button id="cs-product-btn" type="button">Multiply two CS ciphertexts</button></div>
      <div id="cs-product-takeaway" class="cs-takeaway" role="status">Start a toy session in chapter 2, then try the product.</div>
      <div class="output-wrap"><pre id="cs-product-output" class="output" aria-live="polite">Try the public multiplication that worked for plain ElGamal.</pre><button class="copy-btn" type="button" data-copy="cs-product-output">Copy</button></div>
      <p class="note">The full IND-CCA2 proof also uses DDH challenge masking and target-collision resistance at α = α*. The histogram isolates only the information-theoretic check step. The hash-free lunch-time variant is CCA1 only. For rerandomization under a weaker replayable-CCA notion, see <a href="https://eprint.iacr.org/2007/119">double-strand Cramer–Shoup</a>. <a href="https://eprint.iacr.org/1998/006">Cramer–Shoup (1998)</a> · <a href="https://eprint.iacr.org/2001/085">Universal hash proofs</a> · <a href="https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/">Threshold Decrypt</a> · <a href="https://systemslibrarian.github.io/crypto-lab-zk-proof-lab/">ZK Proof Lab</a> · <a href="https://systemslibrarian.github.io/crypto-lab-kem-trap/">KEM Trap</a> · <a href="https://systemslibrarian.github.io/crypto-lab-hpke-envelope/">HPKE Envelope</a>.</p>
      </section>
    </section>

    <div class="section-divider sign" role="presentation">
      <span class="section-divider-label">Part 2 &mdash; the signature scheme</span>
    </div>

    <section class="card" aria-labelledby="exhibit8-title">
      <h2 id="exhibit8-title"><span class="badge sign-badge" aria-hidden="true"></span> ElGamal Signatures</h2>
      <p class="lesson">ElGamal's 1985 paper also defined a <em>signature</em> scheme &mdash; the direct ancestor of DSA.
        Signing uses the full group <code>Z<sub>p</sub>*</code> (generator <code>g = 7</code>, a primitive root),
        producing a pair <code>(r, s)</code>. Verification checks <code>g<sup>h</sup> ≡ y<sup>r</sup>·r<sup>s</sup> (mod p)</code>.
        Here the message integer plays the role of the hash <code>h</code> so the arithmetic stays visible.</p>
      <div class="grid three">
        <label for="sign-msg">Message h (1..2037) <input id="sign-msg" type="number" value="1234" min="1" max="2037" inputmode="numeric" /></label>
        <div class="field-actions">
          <button id="sign-btn" type="button">Generate Key, Sign &amp; Verify</button>
        </div>
      </div>
      <div class="output-wrap">
        <pre id="sign-output" class="output" aria-live="polite" aria-atomic="true">Sign a message and watch verification accept it — then reject a tampered one.</pre>
        <button class="copy-btn" type="button" data-copy="sign-output">Copy</button>
      </div>
    </section>

    <section class="card attack" aria-labelledby="exhibit9-title">
      <h2 id="exhibit9-title"><span class="badge attack-badge" aria-hidden="true"></span> Attack: Signature Nonce Reuse &rarr; Key Recovery</h2>
      <p class="lesson">Reusing <code>k</code> leaked a single <em>message</em> in the encryption demo above. In signatures it is far worse:
        two signatures that reuse <code>k</code> share <code>r</code>, and a little algebra recovers the signer's
        <strong>entire private key</strong>. This is exactly how Sony's PS3 ECDSA master key was extracted in 2010.</p>
      <div class="grid three">
        <label for="sigreuse-m1">Message h1 <input id="sigreuse-m1" type="number" value="111" min="1" max="2037" inputmode="numeric" /></label>
        <label for="sigreuse-m2">Message h2 <input id="sigreuse-m2" type="number" value="222" min="1" max="2037" inputmode="numeric" /></label>
        <div class="field-actions">
          <button id="sigreuse-btn" type="button">Sign Both With One k, Recover x</button>
        </div>
      </div>
      <div class="output-wrap">
        <pre id="sigreuse-output" class="output" aria-live="polite" aria-atomic="true">Sign two messages under a reused nonce, then steal the private key.</pre>
        <button class="copy-btn" type="button" data-copy="sigreuse-output">Copy</button>
      </div>
    </section>

    <section class="card" aria-labelledby="exhibit10-title">
      <h2 id="exhibit10-title"><span class="badge" aria-hidden="true"></span> ElGamal vs RSA</h2>
      <div class="table-wrap" role="region" aria-label="ElGamal versus RSA comparison, scrollable" tabindex="0">
        <table id="elgamal-rsa-table">
          <caption class="visually-hidden">Comparison of ElGamal and RSA cryptosystems across six properties.</caption>
          <thead>
            <tr>
              <th scope="col">Property</th>
              <th scope="col">ElGamal (1985)</th>
              <th scope="col">RSA (1977)</th>
            </tr>
          </thead>
          <tbody>
            <tr><th scope="row">Security assumption</th><td>Discrete Logarithm Problem</td><td>Integer Factorization</td></tr>
            <tr><th scope="row">Ciphertext shape</th><td>Pair (c1, c2)</td><td>Single integer</td></tr>
            <tr><th scope="row">Native non-determinism</th><td>Yes (fresh k each encryption)</td><td>No (needs OAEP)</td></tr>
            <tr><th scope="row">Homomorphism</th><td>Multiplicative</td><td>Multiplicative (textbook)</td></tr>
            <tr><th scope="row">Post-quantum</th><td>No (Shor breaks DLP)</td><td>No (Shor breaks factoring)</td></tr>
            <tr><th scope="row">Common direct usage</th><td>E-voting, mix-nets, threshold systems</td><td>General PKI, legacy encryption/signatures</td></tr>
          </tbody>
        </table>
      </div>
      <p class="note">Taher ElGamal was Netscape's chief scientist and led the SSL effort there, which is why he is often called the father of SSL — a direct ancestor of modern TLS. The SSL 3.0 specification itself was written by Alan Freier, Philip Karlton, and Paul Kocher, later published as RFC 6101.</p>
    </section>

    <section class="card" aria-labelledby="exhibit11-title">
      <h2 id="exhibit11-title"><span class="badge" aria-hidden="true"></span> Why ElGamal Matters Today</h2>
      <ul class="list">
        <li><strong>DSA:</strong> ElGamal signature variant standardized in FIPS 186.</li>
        <li><strong>Threshold ElGamal:</strong> t-of-n distributed decryption for robust trust.</li>
        <li><strong>Exponential ElGamal:</strong> Additive tallying in e-voting systems.</li>
        <li><strong>Cramer-Shoup:</strong> ElGamal-style structure hardened for IND-CCA2.</li>
        <li><strong>Elliptic Curve ElGamal:</strong> Same design with smaller key sizes.</li>
      </ul>
      <p class="note">Cross-links: crypto-lab-threshold-decrypt, crypto-lab-rsa-forge, crypto-lab-blind-sign, crypto-lab-ecdsa-forge, crypto-lab-zk-proof-lab.</p>
    </section>

    <footer class="site-footer">
      <p>Related demos:
        <a href="https://systemslibrarian.github.io/crypto-lab-rsa-forge/" target="_blank" rel="noopener noreferrer">crypto-lab-rsa-forge</a> ·
        <a href="https://systemslibrarian.github.io/crypto-lab-paillier-gate/" target="_blank" rel="noopener noreferrer">crypto-lab-paillier-gate</a> ·
        <a href="https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/" target="_blank" rel="noopener noreferrer">crypto-lab-threshold-decrypt</a> ·
        <a href="https://systemslibrarian.github.io/crypto-lab-key-exchange/" target="_blank" rel="noopener noreferrer">crypto-lab-key-exchange</a>
      </p>
      <p>All computation runs locally in your browser. No data leaves your device. Toy group is intentionally insecure &mdash; for learning only.</p>
    </footer>
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
const crackOut = must<HTMLElement>('crack-output');
const kreuseOut = must<HTMLElement>('kreuse-output');
const maulOut = must<HTMLElement>('maul-output');
const authOut = must<HTMLElement>('auth-output');
const signOut = must<HTMLElement>('sign-output');
const sigreuseOut = must<HTMLElement>('sigreuse-output');

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

const ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function esc(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ESC[c]);
}

/** Wrap a value in a color-coded token span (value is escaped). */
function tok(value: string | bigint | number, cls = ''): string {
  return `<span class="tok${cls ? ' ' + cls : ''}">${esc(String(value))}</span>`;
}

/** Color-coded yes/no for boolean assertions in the output. */
function flag(ok: boolean): string {
  return `<span class="tok ${ok ? 'ok' : 'bad'}">${ok ? 'Yes' : 'No'}</span>`;
}

function setOutput(el: HTMLElement, html: string): void {
  el.dataset.state = 'ok';
  el.innerHTML = html;
}

function setError(el: HTMLElement, error: unknown): void {
  el.dataset.state = 'error';
  const message = error instanceof Error ? error.message : 'Unknown failure.';
  el.innerHTML = `<span class="tok bad">⚠ Error:</span> ${esc(message)}`;
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

/** Color-coded "(c1, c2)" rendering. */
function describeCiphertext(ct: ElGamalCiphertext): string {
  return `(${tok(formatBig(ct.c1), 'c1')}, ${tok(formatBig(ct.c2), 'c2')})`;
}

function ensureKeypair(): ElGamalKeyPair {
  if (!keypair) {
    throw new Error('Generate a keypair first.');
  }
  return keypair;
}

// --- Copy buttons -----------------------------------------------------------

document.querySelectorAll<HTMLButtonElement>('.copy-btn').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const targetId = btn.dataset.copy;
    if (!targetId) return;
    const target = document.getElementById(targetId);
    const text = target?.textContent?.trim();
    if (!text) return;

    try {
      await navigator.clipboard.writeText(text);
      const original = btn.textContent;
      btn.textContent = 'Copied';
      btn.classList.add('copied');
      window.setTimeout(() => {
        btn.textContent = original;
        btn.classList.remove('copied');
      }, 1400);
    } catch {
      btn.textContent = 'Copy failed';
      window.setTimeout(() => { btn.textContent = 'Copy'; }, 1400);
    }
  });
});

// --- Exhibit: discrete-log visualization ------------------------------------

(() => {
  const container = document.getElementById('viz-container');
  const slider = document.getElementById('viz-exp') as HTMLInputElement | null;
  const expOut = document.getElementById('viz-exp-out');
  const readout = document.getElementById('viz-readout');
  if (!container || !slider || !expOut || !readout) return;

  const { g, p, q } = TOY_GROUP; // g = 2, p = 2039, order q = 1019
  const W = 760;
  const H = 380;
  const ml = 46;
  const mr = 14;
  const mt = 14;
  const mb = 34;
  const plotW = W - ml - mr;
  const plotH = H - mt - mb;
  const xMax = Number(q - 1n);
  const yMax = Number(p - 1n);

  const px = (x: number): number => ml + (x / xMax) * plotW;
  const py = (y: number): number => mt + plotH - (y / yMax) * plotH;

  // Base scatter: g^x mod p for every exponent, built once.
  let dots = '';
  let val = 1n; // g^0
  for (let x = 0; x <= xMax; x += 1) {
    dots += `<circle cx="${px(x).toFixed(1)}" cy="${py(Number(val)).toFixed(1)}" r="1.4" class="viz-pt"/>`;
    val = (val * g) % p;
  }

  container.innerHTML = `
    <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
      <line class="viz-axis" x1="${ml}" y1="${mt}" x2="${ml}" y2="${mt + plotH}"/>
      <line class="viz-axis" x1="${ml}" y1="${mt + plotH}" x2="${ml + plotW}" y2="${mt + plotH}"/>
      <text class="viz-tick" x="${ml - 6}" y="${mt + 4}" text-anchor="end">${yMax}</text>
      <text class="viz-tick" x="${ml - 6}" y="${mt + plotH}" text-anchor="end">0</text>
      <text class="viz-tick" x="${ml}" y="${mt + plotH + 22}" text-anchor="middle">0</text>
      <text class="viz-tick" x="${ml + plotW}" y="${mt + plotH + 22}" text-anchor="end">${xMax}</text>
      <text class="viz-axis-label" x="${ml - 30}" y="${mt + plotH / 2}" transform="rotate(-90 ${ml - 30} ${mt + plotH / 2})" text-anchor="middle">g^x mod p</text>
      <text class="viz-axis-label" x="${ml + plotW / 2}" y="${H - 4}" text-anchor="middle">exponent x</text>
      ${dots}
      <line id="viz-vline" class="viz-guide" x1="0" y1="0" x2="0" y2="0"/>
      <line id="viz-hline" class="viz-guide" x1="0" y1="0" x2="0" y2="0"/>
      <circle id="viz-marker" class="viz-marker" cx="0" cy="0" r="5.5"/>
    </svg>`;

  const marker = container.querySelector<SVGCircleElement>('#viz-marker');
  const vline = container.querySelector<SVGLineElement>('#viz-vline');
  const hline = container.querySelector<SVGLineElement>('#viz-hline');

  function update(xNum: number): void {
    const y = modPow(g, BigInt(xNum), p);
    const cx = px(xNum);
    const cy = py(Number(y));
    marker?.setAttribute('cx', cx.toFixed(1));
    marker?.setAttribute('cy', cy.toFixed(1));
    vline?.setAttribute('x1', cx.toFixed(1));
    vline?.setAttribute('y1', cy.toFixed(1));
    vline?.setAttribute('x2', cx.toFixed(1));
    vline?.setAttribute('y2', String(mt + plotH));
    hline?.setAttribute('x1', String(ml));
    hline?.setAttribute('y1', cy.toFixed(1));
    hline?.setAttribute('x2', cx.toFixed(1));
    hline?.setAttribute('y2', cy.toFixed(1));
    if (expOut) expOut.textContent = String(xNum);
    if (readout) readout.textContent = `x = ${xNum}, y = g^${xNum} mod p = ${y}`;
  }

  slider.addEventListener('input', () => update(Number(slider.value)));

  document.getElementById('viz-random')?.addEventListener('click', () => {
    const x = Number(randomBigInt(q)); // 1..q-1
    slider.value = String(x);
    update(x);
  });

  update(Number(slider.value));
})();

// --- Guided walkthrough -----------------------------------------------------

(() => {
  const stepsEl = document.getElementById('wt-steps');
  const prevBtn = document.getElementById('wt-prev') as HTMLButtonElement | null;
  const nextBtn = document.getElementById('wt-next') as HTMLButtonElement | null;
  const restartBtn = document.getElementById('wt-restart') as HTMLButtonElement | null;
  const progressEl = document.getElementById('wt-progress');
  if (!stepsEl || !prevBtn || !nextBtn || !restartBtn || !progressEl) return;

  // Narrowed non-null aliases so the nested render() closure stays type-safe.
  const stepsRoot = stepsEl;
  const progress = progressEl;
  const prev = prevBtn;
  const next = nextBtn;

  const { p, g, q } = TOY_GROUP;

  interface WalkState {
    x: bigint; y: bigint; m: bigint; k: bigint;
    c1: bigint; yk: bigint; c2: bigint;
    s: bigint; sInv: bigint; mRec: bigint;
  }

  function build(): WalkState {
    const x = randomBigInt(q);
    const y = modPow(g, x, p);
    const m = 42n;
    const k = randomBigInt(q);
    const c1 = modPow(g, k, p);
    const yk = modPow(y, k, p);
    const c2 = (m * yk) % p;
    const s = modPow(c1, x, p);
    const sInv = modInverse(s, p);
    const mRec = (c2 * sInv) % p;
    return { x, y, m, k, c1, yk, c2, s, sInv, mRec };
  }

  const steps: Array<{ title: string; narration: string; math: (s: WalkState) => string }> = [
    {
      title: 'Public parameters',
      narration: 'ElGamal lives in a cyclic group. Everyone publicly agrees on a large prime p and a generator g. (We use the toy group so the numbers stay small and readable.)',
      math: () => `p = ${tok(p)}\ng = ${tok(g)}`,
    },
    {
      title: 'Key generation',
      narration: 'Alice picks a secret private key x at random, then publishes her public key y = g^x mod p. Recovering x from y is the discrete-log problem — infeasible at real key sizes.',
      math: (s) => `private  x = ${tok(s.x, 'priv')}\npublic   y = g^x mod p = ${tok(s.y, 'pub')}`,
    },
    {
      title: 'The message',
      narration: 'Bob wants to send the secret value m to Alice, encoded as a number with 1 ≤ m < p.',
      math: (s) => `m = ${tok(s.m, 'm')}`,
    },
    {
      title: 'Ephemeral key',
      narration: 'For THIS message only, Bob draws a fresh random k. Reusing k across messages is catastrophic — the Security Lab below shows exactly how it breaks.',
      math: (s) => `k = ${tok(s.k, 'k')}`,
    },
    {
      title: 'First ciphertext component',
      narration: 'Bob computes the first half of the ciphertext from the ephemeral key alone.',
      math: (s) => `c1 = g^k mod p = ${tok(s.c1, 'c1')}`,
    },
    {
      title: 'Second ciphertext component',
      narration: 'Bob masks the message with the shared value y^k, which only someone who knows x (or k) can reproduce.',
      math: (s) => `y^k mod p = ${tok(s.yk)}\nc2 = m · y^k mod p = ${tok(s.c2, 'c2')}`,
    },
    {
      title: 'Transmit',
      narration: 'Bob sends the ciphertext pair. An eavesdropper sees only these two numbers — never m, x, or k.',
      math: (s) => `ciphertext (c1, c2) = (${tok(s.c1, 'c1')}, ${tok(s.c2, 'c2')})`,
    },
    {
      title: 'Reconstruct the mask',
      narration: 'Alice uses her private key to rebuild the same mask: s = c1^x = g^(kx) = y^k. Only the holder of x can do this.',
      math: (s) => `s = c1^x mod p = ${tok(s.s)}\nsame value as y^k: ${flag(s.s === s.yk)}`,
    },
    {
      title: 'Invert the mask',
      narration: 'Alice computes the modular inverse of the mask so she can divide it back out.',
      math: (s) => `s⁻¹ mod p = ${tok(s.sInv)}`,
    },
    {
      title: 'Recover the message',
      narration: 'Multiplying the inverse mask back out reveals the plaintext — and it matches what Bob sent.',
      math: (s) => `m = c2 · s⁻¹ mod p = ${tok(s.mRec, 'm')}\nrecovered original message: ${flag(s.mRec === s.m)}`,
    },
  ];

  let state = build();
  let idx = 0;

  function render(): void {
    stepsRoot.innerHTML = steps
      .slice(0, idx + 1)
      .map((st, i) => `
        <div class="wt-step${i === idx ? ' current' : ''}">
          <h3>${i + 1}. ${esc(st.title)}</h3>
          <p class="wt-narr">${esc(st.narration)}</p>
          <pre class="output">${st.math(state)}</pre>
        </div>`)
      .join('');
    progress.textContent = `Step ${idx + 1} of ${steps.length}`;
    prev.disabled = idx === 0;
    next.disabled = idx === steps.length - 1;
  }

  nextBtn.addEventListener('click', () => {
    if (idx < steps.length - 1) { idx += 1; render(); }
  });
  prevBtn.addEventListener('click', () => {
    if (idx > 0) { idx -= 1; render(); }
  });
  restartBtn.addEventListener('click', () => {
    state = build();
    idx = 0;
    render();
  });

  render();
})();

// --- Exhibit 1: keygen / encrypt / decrypt ----------------------------------

groupSelect.addEventListener('change', () => {
  selectedGroup = currentGroup();
  keypair = null;
  lastCiphertext = null;
  previousCiphertext = null;
  privateKeyOut.textContent = 'Not generated';
  publicKeyOut.textContent = 'Not generated';
  setOutput(encryptOut, `${esc(selectedGroup.label)} selected. Generate keys to begin.`);
  decryptOut.textContent = '';
  decryptOut.removeAttribute('data-state');
  setOutput(rerandOut, 'Encrypt a message first, then re-randomize.');
});

messageModeSelect.addEventListener('change', () => {
  if (messageModeSelect.value === 'text') {
    messageInput.value = 'yes';
    messageInput.setAttribute('inputmode', 'text');
  } else {
    messageInput.value = '42';
    messageInput.setAttribute('inputmode', 'numeric');
  }
});

must<HTMLButtonElement>('keygen-btn').addEventListener('click', () => {
  selectedGroup = currentGroup();
  keypair = generateKeyPair(selectedGroup);
  renderKeypair();
  setOutput(encryptOut, `Keypair generated in ${esc(selectedGroup.label)}.`);
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
      ? `Previous c1 = ${tok(formatBig(previousCiphertext.c1), 'c1')}\nNew c1      = ${tok(formatBig(result.ciphertext.c1), 'c1')}\nDifferent: ${flag(previousCiphertext.c1 !== result.ciphertext.c1)}`
      : 'Run "Encrypt Again" to observe non-determinism directly.';

    setOutput(encryptOut, [
      `Message m = ${tok(formatBig(message), 'm')}`,
      `k = ${tok(formatBig(result.ephemeralK), 'k')}`,
      `c1 = g^k mod p = ${tok(formatBig(result.ciphertext.c1), 'c1')}`,
      `c2 = m · y^k mod p = ${tok(formatBig((message * yk) % selectedGroup.p), 'c2')}`,
      `Ciphertext ${describeCiphertext(result.ciphertext)}`,
      compareOnly ? `Same plaintext encrypted again.` : '',
      nonDetLine,
    ].filter(Boolean).join('\n'));
  } catch (error) {
    setError(encryptOut, error);
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

    /* decrypt() FIRST, because it is what validates c1. The two lines below
     * re-derive s and s-inverse only to show the reader the intermediate
     * values, and computing them above this call would perform the private-key
     * exponentiation on an unvalidated c1 -- the library check, stepped around
     * by the page that calls it. */
    const recovered = decrypt(lastCiphertext, keys.privateKey, selectedGroup);
    const s = modPow(lastCiphertext.c1, keys.privateKey, selectedGroup.p);
    const sInv = modInverse(s, selectedGroup.p);

    const decoded = messageModeSelect.value === 'text'
      ? `\nDecoded text: "${esc(messageToText(recovered, selectedGroup))}"`
      : '';

    setOutput(decryptOut, [
      `Ciphertext ${describeCiphertext(lastCiphertext)}`,
      `s = c1^x mod p = ${tok(formatBig(s))}`,
      `s⁻¹ mod p = ${tok(formatBig(sInv))}`,
      `m = c2 · s⁻¹ mod p = ${tok(formatBig(recovered), 'm')}`,
      `Recovered original: ${flag(recovered === lastMessage)}`,
      decoded,
    ].join('\n'));
  } catch (error) {
    setError(decryptOut, error);
  }
});

// --- Exhibit 2: homomorphism ------------------------------------------------

must<HTMLButtonElement>('homo-btn').addEventListener('click', () => {
  try {
    const m1 = BigInt(must<HTMLInputElement>('homo-m1').value);
    const m2 = BigInt(must<HTMLInputElement>('homo-m2').value);
    if (m1 <= 0n || m2 <= 0n || m1 >= TOY_GROUP.p || m2 >= TOY_GROUP.p) {
      throw new Error('Use values in range 1..2038 for toy homomorphic demo.');
    }

    const keys = generateKeyPair(TOY_GROUP);
    const k1 = randomBigInt(TOY_GROUP.q);
    let k2 = randomBigInt(TOY_GROUP.q);
    while ((k1 + k2) % TOY_GROUP.q === 0n) k2 = randomBigInt(TOY_GROUP.q);
    const ct1 = encryptWithEphemeral(m1, keys.publicKey, TOY_GROUP, k1);
    const ct2 = encryptWithEphemeral(m2, keys.publicKey, TOY_GROUP, k2);
    const ct3 = multiplyHomomorphic(ct1, ct2);
    const out = decrypt(ct3, keys.privateKey, TOY_GROUP);
    const expected = (m1 * m2) % TOY_GROUP.p;

    setOutput(homoOut, [
      `CT1 = E(${tok(m1, 'm')}) = ${describeCiphertext(ct1)}`,
      `CT2 = E(${tok(m2, 'm')}) = ${describeCiphertext(ct2)}`,
      `CT3 = CT1 ⊗ CT2 = ${describeCiphertext(ct3)}`,
      `Decrypt(CT3) = ${tok(out, 'm')}`,
      `Expected m1·m2 mod p = ${tok(expected, 'm')}`,
      `Match: ${flag(out === expected)}`,
    ].join('\n'));
  } catch (error) {
    setError(homoOut, error);
  }
});

// --- Exhibit 3: re-randomization & mix-net ----------------------------------

must<HTMLButtonElement>('rerand-btn').addEventListener('click', () => {
  try {
    const keys = ensureKeypair();
    if (!lastCiphertext || lastMessage === null) {
      throw new Error('Encrypt first to create a ciphertext to re-randomize.');
    }

    const refreshed = rerandomize(lastCiphertext, keys.publicKey, selectedGroup);
    const originalPlain = decrypt(lastCiphertext, keys.privateKey, selectedGroup);
    const refreshedPlain = decrypt(refreshed, keys.privateKey, selectedGroup);

    setOutput(rerandOut, [
      `Original:    ${describeCiphertext(lastCiphertext)}`,
      `Re-random.:  ${describeCiphertext(refreshed)}`,
      `Ciphertext changed: ${flag(lastCiphertext.c1 !== refreshed.c1 || lastCiphertext.c2 !== refreshed.c2)}`,
      `Decrypt(original) = ${tok(formatBig(originalPlain), 'm')}`,
      `Decrypt(rerandom) = ${tok(formatBig(refreshedPlain), 'm')}`,
      `Same plaintext: ${flag(originalPlain === refreshedPlain)}`,
    ].join('\n'));

    lastCiphertext = refreshed;
  } catch (error) {
    setError(rerandOut, error);
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

    setOutput(mixnetOut, [
      'Inputs:',
      ...encrypted.map((e) => `${esc(e.label)}: ${describeCiphertext(e.ct)}`),
      '',
      'Outputs after re-randomize + shuffle:',
      ...shuffled.map((e, idx) => `Out${idx + 1}: ${describeCiphertext(e.ct)} → decrypts to ${tok(decrypt(e.ct, keys.privateKey, TOY_GROUP), 'm')}`),
      '',
      'Observer sees changed bytes and changed order, but cannot link sender to output without secret permutation info.',
    ].join('\n'));
  } catch (error) {
    setError(mixnetOut, error);
  }
});

// --- Security Lab: attacks --------------------------------------------------

/** Parse a toy-group integer input in [1, p-1]. */
function parseToyInput(id: string): bigint {
  const raw = must<HTMLInputElement>(id).value.trim();
  if (!/^\d+$/.test(raw)) {
    throw new Error('Enter a positive integer.');
  }
  const value = BigInt(raw);
  if (value <= 0n || value >= TOY_GROUP.p) {
    throw new Error('Use values in range 1..2038 for the toy group.');
  }
  return value;
}

// Security Lab — cracking the key: recover the private key by solving the discrete log.
must<HTMLButtonElement>('crack-btn').addEventListener('click', () => {
  try {
    const keys = generateKeyPair(TOY_GROUP);
    const { x: recovered, steps } = discreteLog(TOY_GROUP, keys.publicKey);
    const verified = recovered !== null && modPow(TOY_GROUP.g, recovered, TOY_GROUP.p) === keys.publicKey;

    setOutput(crackOut, [
      `Public key y = ${tok(keys.publicKey, 'pub')}   (this is all the attacker sees)`,
      `Goal: find x such that g^x ≡ y (mod ${TOY_GROUP.p}),  g = ${TOY_GROUP.g}`,
      '',
      `Recovered x = ${tok(recovered ?? 'not found', 'priv')}`,
      `Actual x    = ${tok(keys.privateKey, 'priv')}`,
      `Key recovered: ${flag(verified && recovered === keys.privateKey)}`,
      `Baby-step/giant-step operations: ${tok(steps)}  (naive search would scan up to ${TOY_GROUP.q})`,
      '',
      'The toy subgroup order is ~1019, so this finishes instantly.',
      'RFC 3526 Group 14 has order ≈ 2^2047 — the same attack would need more',
      'operations than there are atoms in the observable universe. That gap is the security.',
    ].join('\n'));
  } catch (error) {
    setError(crackOut, error);
  }
});

// Security Lab — ephemeral-key reuse leaks a secret plaintext.
must<HTMLButtonElement>('kreuse-btn').addEventListener('click', () => {
  try {
    const m1 = parseToyInput('kreuse-m1'); // attacker knows this plaintext
    const m2 = parseToyInput('kreuse-m2'); // the secret the attacker wants

    const keys = generateKeyPair(TOY_GROUP);
    const reusedK = randomBigInt(TOY_GROUP.q); // the fatal mistake: one k, two messages
    const ct1 = encryptWithEphemeral(m1, keys.publicKey, TOY_GROUP, reusedK);
    const ct2 = encryptWithEphemeral(m2, keys.publicKey, TOY_GROUP, reusedK);

    // Attacker sees ct1, ct2 and knows m1. Since c2 = m·y^k with a shared y^k:
    //   m2 = m1 · c2₂ · c2₁⁻¹  (mod p)
    const recovered = (((m1 * ct2.c2) % TOY_GROUP.p) * modInverse(ct1.c2, TOY_GROUP.p)) % TOY_GROUP.p;

    setOutput(kreuseOut, [
      `CT1 = E(${tok(m1, 'm')}) = ${describeCiphertext(ct1)}`,
      `CT2 = E(${tok(m2, 'm')}) = ${describeCiphertext(ct2)}`,
      `Shared c1 (the tell): ${flag(ct1.c1 === ct2.c1)} → ${tok(ct1.c1, 'c1')} = ${tok(ct2.c1, 'c1')}`,
      '',
      'Attacker knows only m1 and both ciphertexts, then computes',
      'm2 = m1 · c2₂ · c2₁⁻¹ mod p:',
      `Recovered m2 = ${tok(recovered, 'm')}`,
      `Actual m2    = ${tok(m2, 'm')}`,
      `Secret leaked: ${flag(recovered === m2)}  — no private key was used.`,
    ].join('\n'));
  } catch (error) {
    setError(kreuseOut, error);
  }
});

// Security Lab — ciphertext malleability: tamper without the key.
must<HTMLButtonElement>('maul-btn').addEventListener('click', () => {
  try {
    const m = parseToyInput('maul-secret');
    const t = parseToyInput('maul-factor');

    const keys = generateKeyPair(TOY_GROUP);
    const ct = encrypt(m, keys.publicKey, TOY_GROUP).ciphertext;

    // Attacker has only (c1, c2) and the public key. Multiply c2 by t:
    const mauled: ElGamalCiphertext = { c1: ct.c1, c2: (ct.c2 * t) % TOY_GROUP.p, group: TOY_GROUP };

    // The owner decrypts the tampered ciphertext, unaware anything changed.
    const decrypted = decrypt(mauled, keys.privateKey, TOY_GROUP);
    const expected = (m * t) % TOY_GROUP.p;

    setOutput(maulOut, [
      `Honest ciphertext  E(${tok(m, 'm')}) = ${describeCiphertext(ct)}`,
      `Attacker multiplies c2 by t = ${tok(t)} (private key never touched):`,
      `Forged ciphertext  ${describeCiphertext(mauled)}`,
      '',
      `Owner decrypts forged CT → ${tok(decrypted, 'm')}`,
      `Predicted m·t mod p     → ${tok(expected, 'm')}`,
      `Decryption silently altered: ${flag(decrypted === expected && t !== 1n)}`,
      '',
      'The owner has no way to detect tampering — plain ElGamal provides no integrity.',
      '(The authenticated-ElGamal exhibit below fixes exactly this.)',
    ].join('\n'));
  } catch (error) {
    setError(maulOut, error);
  }
});

// Defense — authenticated ElGamal detects and rejects the malleability attack.
must<HTMLButtonElement>('auth-btn').addEventListener('click', async () => {
  try {
    const m = parseToyInput('auth-secret');
    const t = parseToyInput('auth-factor');

    const keys = generateKeyPair(TOY_GROUP);
    const ct = await authEncrypt(m, keys.publicKey, TOY_GROUP);
    const honest = await authDecrypt(ct, keys.privateKey, TOY_GROUP);

    // Same malleability attack: multiply c2 by t, leaving the MAC tag untouched.
    const mauled = { ...ct, c2: (ct.c2 * t) % TOY_GROUP.p };
    const tampered = await authDecrypt(mauled, keys.privateKey, TOY_GROUP);

    setOutput(authOut, [
      `Authenticated ciphertext ${describeCiphertext(ct)}`,
      `MAC tag = ${tok(ct.tag.slice(0, 32) + '…')}  (keyed by the shared secret)`,
      '',
      `Honest decrypt → authentic: ${flag(honest.authentic)}, m = ${tok(honest.message ?? 0n, 'm')}`,
      '',
      `Attacker multiplies c2 by t = ${tok(t)} (the same malleability attack):`,
      `Forged ciphertext ${describeCiphertext(mauled)}`,
      `Owner verifies MAC → authentic: ${flag(tampered.authentic)}`,
      tampered.authentic
        ? `t = 1 leaves the ciphertext unchanged, so it still verifies. Try t ≥ 2.`
        : `Tampering REJECTED — the recomputed MAC does not match, so decryption is refused.`,
      '',
      'Integrity restored. The tradeoff: this ciphertext can no longer be re-randomized',
      'or homomorphically multiplied without breaking the tag.',
    ].join('\n'));
  } catch (error) {
    setError(authOut, error);
  }
});

// --- Cramer–Shoup: real decryptor plus a separate toy proof worker ----------

type ProofReply = { id: number; result?: unknown; error?: string };
const proofWorker = new Worker(new URL('./csProof.worker.ts', import.meta.url), { type: 'module' });
const proofPending = new Map<number, { resolve: (value: unknown) => void; reject: (reason: Error) => void }>();
let proofId = 0;
proofWorker.onmessage = (event: MessageEvent<ProofReply>) => {
  const { id, result, error } = event.data;
  const pending = proofPending.get(id);
  if (!pending) return;
  proofPending.delete(id);
  if (error) pending.reject(new Error(error));
  else pending.resolve(result);
};
function proofRequest<T>(payload: Record<string, unknown>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const id = ++proofId;
    proofPending.set(id, { resolve: (value) => resolve(value as T), reject });
    proofWorker.postMessage({ id, ...payload });
  });
}

let csSession: CsKeyPair | null = null;
let csChallenge: { ct: CsCiphertext; message: bigint; alpha: bigint } | null = null;
let csActiveOperations = 0;
const csRoundOut = must<HTMLElement>('cs-round-output');
const csProofOut = must<HTMLElement>('cs-proof-output');
const csLedgerOut = must<HTMLElement>('cs-ledger-output');
const csCollisionOut = must<HTMLElement>('cs-collision-output');
const csProductOut = must<HTMLElement>('cs-product-output');
const csStepStatus = must<HTMLElement>('cs-step-status');
const csStageDescriptions = [
  'Start with an honest encryption.',
  'Compare the keys behind valid and malformed checks.',
  'Ask what repeated decryption queries reveal.',
  'See why the hash must resist a second preimage.',
  'Test the algebraic tradeoff.',
];

function showCsStage(stage: number): void {
  for (let i = 1; i <= 5; i++) {
    must<HTMLElement>(`cs-stage-${i}`).hidden = i !== stage;
  }
  document.querySelectorAll<HTMLButtonElement>('[data-cs-chapter]').forEach((button) => {
    button.setAttribute('aria-pressed', String(Number(button.dataset.csChapter) === stage));
  });
  csStepStatus.textContent = `Chapter ${stage} of 5 · ${csStageDescriptions[stage - 1]}`;
  const panel = must<HTMLElement>(`cs-stage-${stage}`);
  panel.scrollIntoView({ block: 'start' });
  panel.querySelector<HTMLElement>('h3')?.focus({ preventScroll: true });
}
document.querySelectorAll<HTMLButtonElement>('[data-cs-chapter]').forEach((button) => {
  button.addEventListener('click', () => showCsStage(Number(button.dataset.csChapter)));
});
document.querySelectorAll<HTMLButtonElement>('[data-cs-next]').forEach((button) => {
  button.addEventListener('click', () => showCsStage(Number(button.dataset.csNext)));
});

function setCsSessionReady(ready: boolean): void {
  for (const id of ['cs-valid-btn', 'cs-invalid-btn', 'cs-queries-btn', 'cs-maul-btn', 'cs-collision-btn', 'cs-product-btn']) {
    must<HTMLButtonElement>(id).disabled = !ready;
  }
}
setCsSessionReady(false);
function beginCsOperation(): void {
  csActiveOperations++;
  must<HTMLButtonElement>('cs-session-btn').disabled = true;
}
function endCsOperation(): void {
  csActiveOperations--;
  if (csActiveOperations === 0) must<HTMLButtonElement>('cs-session-btn').disabled = false;
}

function requireCsSession(): CsKeyPair {
  if (!csSession) throw new Error('Start a toy proof session first.');
  return csSession;
}
function csNumbers(ct: CsCiphertext): string {
  return `(u1=${ct.u1}, u2=${ct.u2}, e=${ct.e}, v=${ct.v})`;
}
function parseCsMessage(id: string): bigint {
  const raw = must<HTMLInputElement>(id).value.trim();
  if (!/^\d+$/.test(raw)) throw new Error('Enter a positive decimal message.');
  return BigInt(raw);
}
function renderCsHistogram(bins: number[]): void {
  const root = must<HTMLElement>('cs-histogram');
  const occupied = bins.map((count, index) => ({ count, index })).filter((entry) => entry.count > 0);
  const max = Math.max(...bins);
  root.classList.toggle('spread', occupied.length > 1);
  const bars = occupied.length === 1
    ? `<rect x="40" y="10" width="160" height="90"/><text x="120" y="118" text-anchor="middle">check value ${occupied[0].index}: ${occupied[0].count} keys</text>`
    : bins.map((count, index) => `<rect x="${index}" y="${100 - 75 * count / max}" width="0.55" height="${75 * count / max}"/>`).join('')
      + `<text x="0" y="118">value 0</text><text x="1018" y="118" text-anchor="end">value 1018</text>`;
  root.innerHTML = `<svg viewBox="0 0 ${occupied.length === 1 ? 240 : bins.length} 130" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">${bars}</svg>`
    + `<p class="note">${occupied.length === 1 ? 'One exact check value.' : '1,019 exact bars: one for every possible check value. Scroll sideways on a small screen.'} Heights use each view's own scale; the labels give exact key counts.</p>`;
  root.setAttribute('aria-label', occupied.length === 1
    ? `One determined check value predicted by ${occupied[0].count} keys`
    : `${occupied.length} check values, each predicted by ${occupied[0].count} keys`);
}

must<HTMLButtonElement>('cs-round-btn').addEventListener('click', async () => {
  const button = must<HTMLButtonElement>('cs-round-btn');
  const takeaway = must<HTMLElement>('cs-round-takeaway');
  button.disabled = true;
  takeaway.textContent = 'Computing the check and decryption…';
  try {
    const group = must<HTMLSelectElement>('cs-group').value === 'group14' ? GROUP14 : TOY_GROUP;
    const message = parseCsMessage('cs-message');
    const keys = csKeygen(group);
    const { ciphertext: ct, alpha, r } = await csEncrypt(message, keys.publicKey);
    const result = await csDecrypt(ct, keys.secretKey, group);
    takeaway.textContent = result.valid
      ? `Check passed: both sides equal ${formatBig(ct.v, 40)}. The decryptor recovered m = ${formatBig(result.message ?? 0n, 40)}.`
      : `Check failed: ${result.reason}`;
    const { x1, x2, y1, y2, z } = keys.secretKey;
    setOutput(csRoundOut, [
      `Group: ${esc(group.label)}`,
      `m = ${tok(formatBig(message), 'm')}; encoded m in G = ${tok(formatBig(csEncodeMessage(message, group)))}`,
      `r = ${tok(formatBig(r), 'k')}`,
      `u1 = ${tok(formatBig(ct.u1), 'c1')}; u2 = ${tok(formatBig(ct.u2), 'c1')}`,
      `e = ${tok(formatBig(ct.e), 'c2')}; v = ${tok(formatBig(ct.v), 'c2')}`,
      `α = ${tok(formatBig(alpha))}`,
      group.isToy ? `toy secret x1=${x1}, x2=${x2}, y1=${y1}, y2=${y2}, z=${z}` : 'Private exponents hidden in Group 14.',
      `check left = ${tok(formatBig(result.expected ?? 0n))}; right v = ${tok(formatBig(ct.v))}`,
      `check ${result.valid ? 'equal' : 'unequal'}; recovered m = ${tok(formatBig(result.message ?? 0n), 'm')}`,
    ].join('\n'));
  } catch (error) {
    setError(csRoundOut, error);
    takeaway.textContent = `Round trip could not run: ${error instanceof Error ? error.message : 'Unknown failure.'}`;
  } finally { button.disabled = false; }
});

must<HTMLButtonElement>('cs-session-btn').addEventListener('click', async () => {
  const button = must<HTMLButtonElement>('cs-session-btn');
  button.disabled = true;
  csSession = null;
  csChallenge = null;
  setCsSessionReady(false);
  must<HTMLElement>('cs-survival-wrap').hidden = true;
  try {
    const keys = csKeygen(TOY_GROUP);
    const info = await proofRequest<{ q: number; w: number; C: number; D: number; remaining: number }>({ kind: 'init', publicKey: keys.publicKey });
    csSession = keys;
    setCsSessionReady(true);
    csChallenge = null;
    const { publicKey: pk, secretKey: sk } = keys;
    setOutput(csProofOut, [
      `Public g1=${pk.g1}, g2=${pk.g2}, c=${pk.c}, d=${pk.d}, h=${pk.h}`,
      `Proof viewpoint w=${info.w}, log_g1(c)=${info.C}, log_g1(d)=${info.D}`,
      `Toy real key x1=${sk.x1}, x2=${sk.x2}, y1=${sk.y1}, y2=${sk.y2}; z=${sk.z} (fixed by h)`,
      `Consistent check keys = q² = ${info.remaining} (${info.q}²)`,
      'w is known to this toy enumerator, not to a real attacker.',
    ].join('\n'));
    setOutput(csLedgerOut, 'Fresh session. Fire invalid queries to see the remaining-key count.');
    setOutput(csCollisionOut, 'Fresh session. Try a maul or collision search.');
    must<HTMLElement>('cs-histogram').textContent = 'The check-value histogram appears here.';
    must<HTMLElement>('cs-histogram').classList.remove('spread');
    must<HTMLElement>('cs-histogram').setAttribute('aria-label', 'Check-value histogram; plot a query to populate it');
    must<HTMLElement>('cs-public-strip').textContent = `Public c = ${pk.c}, d = ${pk.d}; g2 = ${pk.g2}; compatible keys = ${info.remaining.toLocaleString()}.`;
    must<HTMLElement>('cs-proof-takeaway').textContent = `${info.remaining.toLocaleString()} check-key tuples fit the same public (c, d). Plot a query to see how they vote.`;
    must<HTMLElement>('cs-ledger-summary').textContent = 'The new toy session is ready. Fire invalid queries to measure what the oracle reveals.';
    must<HTMLElement>('cs-collision-takeaway').textContent = 'Try an ordinary maul, then search for a collision in the tiny hash range.';
    must<HTMLElement>('cs-collision-takeaway').removeAttribute('data-state');
    must<HTMLButtonElement>('cs-retry-btn').hidden = true;
    must<HTMLElement>('cs-product-takeaway').textContent = 'Multiply two valid ciphertexts and check the result.';
    must<HTMLElement>('cs-query-progress').textContent = '';
    must<HTMLElement>('cs-survival-wrap').hidden = false;
    must<HTMLProgressElement>('cs-survival-progress').value = info.remaining;
  } catch (error) {
    setError(csProofOut, error);
    must<HTMLElement>('cs-proof-takeaway').textContent = `Toy session could not start: ${error instanceof Error ? error.message : 'Unknown failure.'}`;
  }
  finally { button.disabled = false; }
});

must<HTMLInputElement>('cs-r2').addEventListener('input', (event) => {
  const value = (event.target as HTMLInputElement).value;
  must<HTMLOutputElement>('cs-r2-value').textContent = value;
  if (csSession) must<HTMLElement>('cs-proof-takeaway').textContent = `r2 is now ${value}. Plot the selected query to update the histogram.`;
});

async function plotCs(validButton: boolean): Promise<void> {
  const keys = requireCsSession();
  beginCsOperation();
  try {
    const r2 = validButton ? 31n : BigInt(must<HTMLInputElement>('cs-r2').value);
    const ct = r2 === 31n
      ? (await csEncrypt(42n, keys.publicKey, 31n)).ciphertext
      : makeInvalidQuery(keys.publicKey, 31n, r2);
    const alpha = await csAlpha(ct, TOY_GROUP);
    const bins = await proofRequest<number[]>({ kind: 'histogram', ct, alpha });
    const result = await csDecrypt(ct, keys.secretKey, TOY_GROUP);
    renderCsHistogram(bins);
    const occupied = bins.filter((count) => count > 0);
    must<HTMLElement>('cs-proof-takeaway').textContent = occupied.length === 1
      ? `Valid query: all ${TOY_GROUP.q ** 2n} compatible keys predict the same check value. That answer was already public.`
      : `Malformed query: ${occupied.length} check values, ${occupied[0]} keys each. The best guess passes for 1 in ${TOY_GROUP.q} keys.`;
    setOutput(csProofOut, [
      `Public g1=${keys.publicKey.g1}, g2=${keys.publicKey.g2}, c=${keys.publicKey.c}, d=${keys.publicKey.d}, h=${keys.publicKey.h}`,
      `Proof viewpoint w=${keys.proofW}; consistent keys = ${TOY_GROUP.q ** 2n}`,
      `Toy real key x1=${keys.secretKey.x1}, x2=${keys.secretKey.x2}, y1=${keys.secretKey.y1}, y2=${keys.secretKey.y2}; z=${keys.secretKey.z}`,
      `Query r1=31, r2=${r2}; ${csNumbers(ct)}; α=${alpha}`,
      `Histogram: ${occupied.length} occupied check values; counts=${occupied.length === 1 ? occupied[0] : `${occupied[0]} each`}; total=${bins.reduce((a, b) => a + b, 0)}`,
      `Attacker's best v passes for ${Math.max(...bins)}/${TOY_GROUP.q ** 2n} consistent keys.`,
      `Real decryptor: ${result.valid ? 'ACCEPTED' : `REJECTED (${result.reason}) — working as intended`}`,
      'w is proof viewpoint only; a real attacker cannot compute it.',
    ].join('\n'));
  } finally { endCsOperation(); }
}
function showCsProofError(error: unknown): void {
  setError(csProofOut, error);
  must<HTMLElement>('cs-proof-takeaway').textContent = `Query could not be plotted: ${error instanceof Error ? error.message : 'Unknown failure.'}`;
}
must<HTMLButtonElement>('cs-valid-btn').addEventListener('click', () => { void plotCs(true).catch(showCsProofError); });
must<HTMLButtonElement>('cs-invalid-btn').addEventListener('click', () => { void plotCs(false).catch(showCsProofError); });

must<HTMLButtonElement>('cs-queries-btn').addEventListener('click', async () => {
  const button = must<HTMLButtonElement>('cs-queries-btn');
  button.disabled = true;
  beginCsOperation();
  try {
    const keys = requireCsSession();
    const n = Number(must<HTMLSelectElement>('cs-query-count').value);
    must<HTMLElement>('cs-query-progress').textContent = `Checking ${n} queries…`;
    const lines = ['i | r1,r2 | v | CS verdict | pass chance before query | remaining keys | bound if rejected | plain ElGamal m'];
    let rejections = 0;
    let acceptances = 0;
    let acceptedBefore = false;
    let remaining = Number(TOY_GROUP.q ** 2n);
    for (let i = 1; i <= n; i++) {
      const r1 = randomBigInt(TOY_GROUP.q);
      let r2 = randomBigInt(TOY_GROUP.q);
      while (r2 === r1) r2 = randomBigInt(TOY_GROUP.q);
      const ct = makeInvalidQuery(keys.publicKey, r1, r2);
      const result = await csDecrypt(ct, keys.secretKey, TOY_GROUP);
      const plain = decrypt({ c1: ct.u1, c2: ct.e, group: TOY_GROUP }, keys.secretKey.z, TOY_GROUP);
      const alpha = result.alpha ?? await csAlpha(ct, TOY_GROUP);
      const observation = await proofRequest<{ before: number; passing: number; remaining: number }>({ kind: 'observe', ct, alpha, accepted: result.valid });
      if (!result.valid) rejections++;
      else { acceptedBefore = true; acceptances++; }
      remaining = observation.remaining;
      const bound = acceptedBefore ? '— (acceptance changed posterior)' : `1/${TOY_GROUP.q - BigInt(rejections) + 1n}`;
      lines.push(`${i} | ${r1},${r2} | ${ct.v} | ${result.valid ? 'ACCEPTED' : 'rejected'} | ${observation.passing}/${observation.before} | ${observation.remaining} | ${bound} | ${plain}`);
      if (i % 5 === 0 || i === n) must<HTMLElement>('cs-query-progress').textContent = `${i} of ${n} queries checked`;
    }
    lines.push('CS rejection is working as intended. Plain ElGamal returns e·u1^(-z) on every one of these queries; CS checked them before decryption.');
    setOutput(csLedgerOut, lines.join('\n'));
    const percent = (100 * remaining / Number(TOY_GROUP.q ** 2n)).toFixed(1);
    must<HTMLProgressElement>('cs-survival-progress').value = remaining;
    must<HTMLElement>('cs-ledger-summary').textContent = acceptances === 0
      ? `${rejections} CS rejections; ${remaining.toLocaleString()} of 1,038,361 compatible keys remain (${percent}%). Plain ElGamal returned ${n} key-dependent answers.`
      : `${rejections} CS rejections and ${acceptances} rare acceptance${acceptances === 1 ? '' : 's'}; ${remaining.toLocaleString()} compatible keys remain. An acceptance changes the posterior sharply. Start a new session to study rejections alone.`;
  } catch (error) {
    setError(csLedgerOut, error);
    must<HTMLElement>('cs-ledger-summary').textContent = `Queries could not run: ${error instanceof Error ? error.message : 'Unknown failure.'}`;
  }
  finally { button.disabled = false; endCsOperation(); }
});

async function ensureCsChallenge(keys: CsKeyPair): Promise<{ ct: CsCiphertext; message: bigint; alpha: bigint }> {
  const message = parseCsMessage('cs-maul-message');
  if (csChallenge && csChallenge.message === message) return csChallenge;
  const { ciphertext: ct, alpha } = await csEncrypt(message, keys.publicKey);
  csChallenge = { ct, message, alpha };
  return csChallenge;
}

must<HTMLButtonElement>('cs-maul-btn').addEventListener('click', async () => {
  beginCsOperation();
  try {
    const keys = requireCsSession();
    const challenge = await ensureCsChallenge(keys);
    const factor = parseCsMessage('cs-maul-factor');
    const forged = maulCs(challenge.ct, factor, keys.publicKey);
    const result = await csDecrypt(forged, keys.secretKey, TOY_GROUP);
    const takeaway = must<HTMLElement>('cs-collision-takeaway');
    takeaway.textContent = factor === 1n
      ? 't = 1 left the ciphertext unchanged.'
      : result.valid
        ? 'A rare toy collision made this maul pass. The tiny hash range is the weakness.'
        : 'The new α changed the check. The decryptor rejected this maul.';
    if (factor !== 1n && result.valid) takeaway.dataset.state = 'alarm';
    else takeaway.removeAttribute('data-state');
    setOutput(csCollisionOut, [
      `Challenge ${csNumbers(challenge.ct)}; α*=${challenge.alpha}`,
      `Mauled e·t with t=${factor}: ${csNumbers(forged)}; α=${result.alpha}`,
      `Decryptor: ${result.valid ? 'ACCEPTED (unchanged or rare toy collision)' : `REJECTED (${result.reason})`}`,
    ].join('\n'));
  } catch (error) {
    setError(csCollisionOut, error);
    const takeaway = must<HTMLElement>('cs-collision-takeaway');
    takeaway.removeAttribute('data-state');
    takeaway.textContent = `Maul could not run: ${error instanceof Error ? error.message : 'Unknown failure.'}`;
  }
  finally { endCsOperation(); }
});

must<HTMLButtonElement>('cs-collision-btn').addEventListener('click', async () => {
  const button = must<HTMLButtonElement>('cs-collision-btn');
  button.disabled = true;
  beginCsOperation();
  try {
    const keys = requireCsSession();
    const challenge = await ensureCsChallenge(keys);
    setOutput(csCollisionOut, 'Searching the toy-size α range…');
    const collision = await findToyAlphaCollision(challenge.ct, keys.publicKey);
    if (!collision) {
      const takeaway = must<HTMLElement>('cs-collision-takeaway');
      takeaway.removeAttribute('data-state');
      takeaway.textContent = 'No second preimage for this challenge. Try a fresh challenge with one click.';
      must<HTMLButtonElement>('cs-retry-btn').hidden = false;
      setOutput(csCollisionOut, `Challenge ${csNumbers(challenge.ct)}; α*=${challenge.alpha}\nNo second preimage found among the toy group's ${TOY_GROUP.q - 1n} nonidentity factors. Generate another challenge or session and retry.`);
      return;
    }
    const verdict = await csDecrypt(collision.forged, keys.secretKey, TOY_GROUP);
    if (!verdict.valid) throw new Error('Collision prediction disagrees with the real decryptor.');
    const takeaway = must<HTMLElement>('cs-collision-takeaway');
    must<HTMLButtonElement>('cs-retry-btn').hidden = true;
    takeaway.dataset.state = 'alarm';
    takeaway.textContent = `Toy-only break: a second preimage kept α unchanged, so the forged message was accepted after ${collision.attempts} tries.`;
    csCollisionOut.dataset.state = 'alarm';
    csCollisionOut.innerHTML = [
      `<span class="tok bad cs-alarm">⚠ FORGED — ACCEPTED</span>`,
      `Challenge ${csNumbers(challenge.ct)}; α*=${challenge.alpha}`,
      `Factor t=${collision.factor}; attempts=${collision.attempts}`,
      `Forged ${csNumbers(collision.forged)}; α=${collision.alpha}`,
      `Decoded encoded(m)·t = ${verdict.message}; original m=${challenge.message}`,
      'Toy-size α only: this second-preimage search does not scale to SHA-256 with Group 14.',
    ].join('\n');
  } catch (error) {
    setError(csCollisionOut, error);
    const takeaway = must<HTMLElement>('cs-collision-takeaway');
    takeaway.removeAttribute('data-state');
    takeaway.textContent = `Collision search could not run: ${error instanceof Error ? error.message : 'Unknown failure.'}`;
  }
  finally { button.disabled = false; endCsOperation(); }
});

must<HTMLButtonElement>('cs-retry-btn').addEventListener('click', () => {
  const input = must<HTMLInputElement>('cs-maul-message');
  const previous = /^\d+$/.test(input.value) ? BigInt(input.value) : 0n;
  let next = randomBigInt(TOY_GROUP.q + 1n);
  if (next === previous) next = next % TOY_GROUP.q + 1n;
  input.value = String(next);
  csChallenge = null;
  must<HTMLButtonElement>('cs-retry-btn').hidden = true;
  must<HTMLButtonElement>('cs-collision-btn').click();
});

must<HTMLButtonElement>('cs-product-btn').addEventListener('click', async () => {
  beginCsOperation();
  try {
    const keys = requireCsSession();
    let a = (await csEncrypt(3n, keys.publicKey)).ciphertext;
    let b = (await csEncrypt(7n, keys.publicKey)).ciphertext;
    let product = multiplyCs(a, b, keys.publicKey);
    let verdict = await csDecrypt(product, keys.secretKey, TOY_GROUP);
    for (let attempt = 1; attempt < 8 && verdict.valid; attempt++) {
      a = (await csEncrypt(3n, keys.publicKey)).ciphertext;
      b = (await csEncrypt(7n, keys.publicKey)).ciphertext;
      product = multiplyCs(a, b, keys.publicKey);
      verdict = await csDecrypt(product, keys.secretKey, TOY_GROUP);
      if (!verdict.valid) break;
    }
    if (verdict.valid) throw new Error('Toy hash happened to accept the products; retry with fresh ciphertexts.');
    must<HTMLElement>('cs-product-takeaway').textContent = 'Product rejected: componentwise multiplication no longer gives a usable ciphertext.';
    setOutput(csProductOut, [
      `E(3) ${csNumbers(a)}`,
      `E(7) ${csNumbers(b)}`,
      `Componentwise product ${csNumbers(product)}`,
      `Decryptor: REJECTED (${verdict.reason})`,
      'The product has no computable v update without the ephemeral exponents; CS is not homomorphic.',
    ].join('\n'));
  } catch (error) {
    setError(csProductOut, error);
    must<HTMLElement>('cs-product-takeaway').textContent = `Product probe could not run: ${error instanceof Error ? error.message : 'Unknown failure.'}`;
  }
  finally { endCsOperation(); }
});

// --- Part 2: ElGamal signatures --------------------------------------------

/** Parse a signature-message integer h in [1, n-1] (n = p-1 = 2038). */
function parseSignInput(id: string): bigint {
  const raw = must<HTMLInputElement>(id).value.trim();
  if (!/^\d+$/.test(raw)) {
    throw new Error('Enter a positive integer.');
  }
  const value = BigInt(raw);
  if (value <= 0n || value >= TOY_SIGN_GROUP.n) {
    throw new Error('Use values in range 1..2037 for the signature demo.');
  }
  return value;
}

// Signatures — sign a message and verify it (then reject a tampered message).
must<HTMLButtonElement>('sign-btn').addEventListener('click', () => {
  try {
    const h = parseSignInput('sign-msg');
    const keys = generateSignKeyPair();
    const { sig, k } = sign(h, keys.x);

    const valid = verifySignature(h, sig, keys.y);
    const tamperedH = (h % (TOY_SIGN_GROUP.n - 1n)) + 1n; // a different message
    const tamperValid = verifySignature(tamperedH, sig, keys.y);

    setOutput(signOut, [
      `Public key y = g^x mod p = ${tok(keys.y, 'pub')}   (private x = ${tok(keys.x, 'priv')})`,
      '',
      `Sign h = ${tok(h, 'm')}  (ephemeral k = ${tok(k, 'k')}, kept secret)`,
      `Signature (r, s) = (${tok(sig.r, 'c1')}, ${tok(sig.s, 'c2')})`,
      '',
      `Verify g^h ≡ y^r · r^s (mod p): ${flag(valid)}`,
      `Same signature on a different message h = ${tok(tamperedH, 'm')}: ${flag(tamperValid)}`,
      '',
      'A valid signature binds the message to the private key; changing the message breaks it.',
    ].join('\n'));
  } catch (error) {
    setError(signOut, error);
  }
});

// Signatures — reuse the nonce across two signatures and recover the private key.
must<HTMLButtonElement>('sigreuse-btn').addEventListener('click', () => {
  try {
    const h1 = parseSignInput('sigreuse-m1');
    const h2 = parseSignInput('sigreuse-m2');
    if (h1 === h2) {
      throw new Error('Use two different messages so the signatures differ.');
    }

    const keys = generateSignKeyPair();

    // The fatal mistake: one ephemeral k signs both messages.
    let reusedK: bigint | null = null;
    let sig1 = null;
    let sig2 = null;
    for (let attempt = 0; attempt < 2000 && sig1 === null; attempt += 1) {
      const k = randomBigInt(TOY_SIGN_GROUP.n);
      try {
        sig1 = signWithK(h1, keys.x, k);
        sig2 = signWithK(h2, keys.x, k);
        reusedK = k;
      } catch {
        sig1 = null; // k not coprime to p-1; resample
      }
    }
    if (!sig1 || !sig2 || reusedK === null) {
      throw new Error('Could not sample a usable nonce; try again.');
    }

    const { k: recoveredK, x: recoveredX } = recoverKeyFromReusedNonce(h1, sig1.s, h2, sig2.s, sig1.r, keys.y);

    setOutput(sigreuseOut, [
      `Signature 1 on h1 = ${tok(h1, 'm')}: (r, s) = (${tok(sig1.r, 'c1')}, ${tok(sig1.s, 'c2')})`,
      `Signature 2 on h2 = ${tok(h2, 'm')}: (r, s) = (${tok(sig2.r, 'c1')}, ${tok(sig2.s, 'c2')})`,
      `Shared r (the tell): ${flag(sig1.r === sig2.r)}`,
      '',
      'From s1 - s2 ≡ (h1 - h2)·k⁻¹ the attacker solves for k, then for x:',
      `Recovered k = ${tok(recoveredK ?? 'none', 'k')}   (actual ${tok(reusedK, 'k')})`,
      `Recovered private key x = ${tok(recoveredX ?? 'none', 'priv')}`,
      `Actual private key x    = ${tok(keys.x, 'priv')}`,
      `Full key compromised: ${flag(recoveredX === keys.x)}  — every future signature is now forgeable.`,
    ].join('\n'));
  } catch (error) {
    setError(sigreuseOut, error);
  }
});
