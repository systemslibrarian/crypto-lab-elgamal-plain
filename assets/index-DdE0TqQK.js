(function(){let e=document.createElement(`link`).relList;if(e&&e.supports&&e.supports(`modulepreload`))return;for(let e of document.querySelectorAll(`link[rel="modulepreload"]`))n(e);new MutationObserver(e=>{for(let t of e)if(t.type===`childList`)for(let e of t.addedNodes)e.tagName===`LINK`&&e.rel===`modulepreload`&&n(e)}).observe(document,{childList:!0,subtree:!0});function t(e){let t={};return e.integrity&&(t.integrity=e.integrity),e.referrerPolicy&&(t.referrerPolicy=e.referrerPolicy),e.crossOrigin===`use-credentials`?t.credentials=`include`:e.crossOrigin===`anonymous`?t.credentials=`omit`:t.credentials=`same-origin`,t}function n(e){if(e.ep)return;e.ep=!0;let n=t(e);fetch(e.href,n)}})();function e(e,t,n){if(n<=0n)throw Error(`Modulus must be positive.`);if(n===1n)return 0n;let r=1n,i=(e%n+n)%n,a=t;for(;a>0n;)(a&1n)==1n&&(r=r*i%n),a>>=1n,i=i*i%n;return r}function t(e,t){let n=e,r=t,i=1n,a=0n,o=0n,s=1n;for(;r!==0n;){let e=n/r,t=n-e*r;n=r,r=t;let c=i-e*a;i=a,a=c;let l=o-e*s;o=s,s=l}let c=n<0n?-n:n,l=n<0n?-1n:1n;return{gcd:c,x:i*l,y:o*l}}function n(e,n){if(n<=0n)throw Error(`Modulus must be positive.`);let{gcd:r,x:i}=t((e%n+n)%n,n);if(r!==1n)throw Error(`Inverse does not exist because gcd(a, m) != 1.`);return(i%n+n)%n}function r(e){let t=e.toString(2).length;return Math.ceil(t/8)}function i(e){let t=new Uint8Array(e);crypto.getRandomValues(t);let n=0n;for(let e of t)n=n<<8n|BigInt(e);return n}function a(e){if(e<=1n)throw Error(`max must be > 1.`);let t=r(e-1n);for(;;){let n=i(t);if(n>0n&&n<e)return n}}function o(t,n=16){if(t<=1n)return!1;if(t<=3n)return!0;if((t&1n)==0n)return!1;let r=t-1n,i=0;for(;(r&1n)==0n;)r>>=1n,i+=1;for(let o=0;o<n;o+=1){let n=e(a(t-3n)+2n,r,t);if(n===1n||n===t-1n)continue;let o=!0;for(let r=1;r<i;r+=1)if(n=e(n,2n,t),n===t-1n){o=!1;break}if(o)return!1}return!0}function s(e,t){if(e<=0n||e>=t.p)throw Error(`Message must be in [1, p-1].`)}function c(e,t){return e.p===t.p&&e.q===t.q&&e.g===t.g}function l(t){let n=a(t.q);return{privateKey:n,publicKey:e(t.g,n,t.p),group:t}}function u(t,n,r,i){return s(t,r),{c1:e(r.g,i,r.p),c2:t*e(n,i,r.p)%r.p,group:r}}function d(e,t,n){let r=a(n.q);return{ciphertext:u(e,t,n,r),ephemeralK:r}}function f(t,r,i){if(!c(t.group,i))throw Error(`Ciphertext group does not match decryption group.`);let a=n(e(t.c1,r,i.p),i.p);return t.c2*a%i.p}function p(e,t){let n=new TextEncoder().encode(e);if(n.length===0)throw Error(`Text message must be non-empty.`);let r=1n;for(let e of n)r=r<<8n|BigInt(e);return s(r,t),r}function m(e,t){s(e,t);let n=[],r=e;for(;r>1n;)n.push(Number(r&255n)),r>>=8n;return n.reverse(),new TextDecoder(`utf-8`,{fatal:!0}).decode(new Uint8Array(n))}function h(e,t){if(!c(e.group,t.group))throw Error(`Ciphertexts are from different groups.`);let n=e.group;return{c1:e.c1*t.c1%n.p,c2:e.c2*t.c2%n.p,group:n}}function g(t,n,r){if(!c(t.group,r))throw Error(`Ciphertext group does not match rerandomization group.`);let i=a(r.q),o=e(r.g,i,r.p),s=e(n,i,r.p);return{c1:t.c1*o%r.p,c2:t.c2*s%r.p,group:r}}var _={p:BigInt(`0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF`),q:0n,g:2n,label:`RFC 3526 Group 14 (2048-bit)`,bitLength:2048,isToy:!1},v={p:2039n,q:1019n,g:2n,label:`TOY (11-bit) - NOT SECURE - for visualization only`,bitLength:11,isToy:!0};function y(e=!1){let t=(_.p-1n)/2n;if(e){if(!o(_.p,12))throw Error(`RFC 3526 Group 14 p failed primality test.`);if(!o(t,12))throw Error(`RFC 3526 Group 14 q failed primality test.`)}return{..._,q:t}}var b=y(),ee=1n<<26n;function te(e){if(e<2n)return e;let t=e,n=(t+1n)/2n;for(;n<t;)t=n,n=(t+e/t)/2n;return t*t===e?t:t+1n}function ne(t,r){let{g:i,p:a,q:o}=t;if(o>ee)throw Error(`Subgroup order ~2^${o.toString(2).length} is computationally infeasible to brute-force — that infeasibility is precisely what keeps real ElGamal secure.`);let s=te(o),c=new Map,l=1n,u=0;for(let e=0n;e<s;e+=1n){let t=l.toString();c.has(t)||c.set(t,e),l=l*i%a,u+=1}let d=n(e(i,s,a),a),f=(r%a+a)%a;for(let e=0n;e<=s;e+=1n){u+=1;let t=c.get(f.toString());if(t!==void 0)return{x:e*s+t,steps:u};f=f*d%a}return{x:null,steps:u}}function x(e){let t=e.toString(16);t.length%2==1&&(t=`0`+t);let n=new Uint8Array(new ArrayBuffer(t.length/2));for(let e=0;e<n.length;e+=1)n[e]=parseInt(t.slice(e*2,e*2+2),16);return n}function re(e){return Array.from(new Uint8Array(e)).map(e=>e.toString(16).padStart(2,`0`)).join(``)}function ie(e){let t=new Uint8Array(new ArrayBuffer(e.length/2));for(let n=0;n<t.length;n+=1)t[n]=parseInt(e.slice(n*2,n*2+2),16);return t}function ae(e,t){let n=x(e),r=x(t),i=new Uint8Array(new ArrayBuffer(4+n.length+r.length));return i[0]=n.length>>8&255,i[1]=n.length&255,i.set(n,2),i[2+n.length]=r.length>>8&255,i[3+n.length]=r.length&255,i.set(r,4+n.length),i}async function oe(e){let t=await crypto.subtle.digest(`SHA-256`,x(e));return crypto.subtle.importKey(`raw`,t,{name:`HMAC`,hash:`SHA-256`},!1,[`sign`,`verify`])}async function se(t,n,r){if(t<=0n||t>=r.p)throw Error(`Message must be in [1, p-1].`);let i=a(r.q),o=e(r.g,i,r.p),s=e(n,i,r.p),c=t*s%r.p,l=await oe(s);return{c1:o,c2:c,tag:re(await crypto.subtle.sign(`HMAC`,l,ae(o,c))),group:r}}async function ce(t,r,i){let a=e(t.c1,r,i.p),o=await oe(a),s=!1;try{let e=ie(t.tag);s=await crypto.subtle.verify(`HMAC`,o,e,ae(t.c1,t.c2))}catch{s=!1}return s?{authentic:!0,message:t.c2*n(a,i.p)%i.p}:{authentic:!1,message:null}}var S={p:2039n,g:7n,n:2038n,label:`Toy signature group — p = 2039, g = 7 (primitive root), n = p-1 = 2038`};function C(e,t){for(e=e<0n?-e:e,t=t<0n?-t:t;t;){let n=e%t;e=t,t=n}return e}function w(e,t){return(e%t+t)%t}function le(e,t,r){e=w(e,r),t=w(t,r);let i=C(e,r);if(w(t,i)!==0n)return[];let a=e/i,o=t/i,s=r/i,c=w(o*n(w(a,s),s),s),l=[];for(let e=0n;e<i;e+=1n)l.push(w(c+e*s,r));return l}function ue(t=S){let n=a(t.n);return{x:n,y:e(t.g,n,t.p)}}function T(t,r,i,a=S){let{p:o,g:s,n:c}=a;if(C(i,c)!==1n)throw Error(`k must be coprime to p-1.`);let l=e(s,i,o);return{r:l,s:w(w(t-r*l,c)*n(i,c),c)}}function de(e,t,n=S){for(;;){let r=a(n.n);if(C(r,n.n)!==1n)continue;let i=T(e,t,r,n);if(i.s!==0n)return{sig:i,k:r}}}function fe(t,n,r,i=S){let{p:a,g:o,n:s}=i;return n.r<=0n||n.r>=a||n.s<=0n||n.s>=s?!1:e(o,t,a)===e(r,n.r,a)*e(n.r,n.s,a)%a}function pe(t,n,r,i,a,o,s=S){let{p:c,g:l,n:u}=s,d=le(n-i,t-r,u).find(t=>e(l,t,c)===a)??null;return d===null?{k:null,x:null}:{k:d,x:le(a,t-w(n*d,u),u).find(t=>e(l,t,c)===o)??null}}if(e(S.g,S.n/2n,S.p)===1n||e(S.g,S.n/1019n,S.p)===1n)throw Error(`TOY_SIGN_GROUP.g is not a primitive root mod p.`);var me=document.querySelector(`#app`);if(!me)throw Error(`Missing #app root element.`);me.innerHTML=`
  <main id="main-content" class="page" tabindex="-1" aria-labelledby="page-title">
    <header class="hero">
      <div class="hero-top">
        <p class="kicker">crypto-lab · elgamal-plain</p>
        <button id="theme-toggle" class="theme-toggle" type="button" aria-pressed="false">
          <span class="theme-icon" aria-hidden="true"></span>
          <span id="theme-label">Dark</span>
        </button>
      </div>
      <h1 id="page-title">ElGamal: The First Practical Public-Key Encryption</h1>
      <p class="subtitle">
        Live, browser-only ElGamal over a toy group and RFC 3526 Group 14. Watch non-determinism,
        decryption math, homomorphic multiplication, and ciphertext re-randomization &mdash; every
        value computed on your device, nothing sent anywhere.
      </p>
      <ul class="legend" aria-label="Color key for the variables used below">
        <li><span class="swatch pub" aria-hidden="true"></span> public key y</li>
        <li><span class="swatch priv" aria-hidden="true"></span> private key x</li>
        <li><span class="swatch k" aria-hidden="true"></span> ephemeral k</li>
        <li><span class="swatch c1" aria-hidden="true"></span> c1</li>
        <li><span class="swatch c2" aria-hidden="true"></span> c2</li>
        <li><span class="swatch m" aria-hidden="true"></span> message m</li>
      </ul>
    </header>

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
        decryption silently becomes <code>m·t</code>. This is why real systems wrap ElGamal in authentication
        (e.g. Cramer-Shoup) or use it only inside protocols that expect the homomorphism.</p>
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
        why systems that <em>need</em> malleability (e-voting) reach for Cramer-Shoup or zero-knowledge proofs instead.</p>
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
        <table>
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
      <p class="note">Taher ElGamal also designed SSL 3.0 at Netscape, a direct ancestor of modern TLS.</p>
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
      <p>All computation runs locally in your browser. No data leaves your device. Toy group is intentionally insecure &mdash; for learning only.</p>
    </footer>
  </main>
`;var he=H(`group-select`),E=H(`message-mode`),D=H(`message-input`),ge=H(`private-key`),_e=H(`public-key`),O=H(`encrypt-output`),k=H(`decrypt-output`),A=H(`rerand-output`),ve=H(`homo-output`),j=H(`mixnet-output`),M=H(`crack-output`),N=H(`kreuse-output`),P=H(`maul-output`),F=H(`auth-output`),I=H(`sign-output`),ye=H(`sigreuse-output`),L=v,R=null,z=null,B=null,be=null,V=null;function H(e){let t=document.getElementById(e);if(!t)throw Error(`Missing element #${e}`);return t}var xe={"&":`&amp;`,"<":`&lt;`,">":`&gt;`,'"':`&quot;`,"'":`&#39;`};function U(e){return e.replace(/[&<>"']/g,e=>xe[e])}function W(e,t=``){return`<span class="tok${t?` `+t:``}">${U(String(e))}</span>`}function G(e){return`<span class="tok ${e?`ok`:`bad`}">${e?`Yes`:`No`}</span>`}function K(e,t){e.dataset.state=`ok`,e.innerHTML=t}function q(e,t){e.dataset.state=`error`,e.innerHTML=`<span class="tok bad">⚠ Error:</span> ${U(t instanceof Error?t.message:`Unknown failure.`)}`}function J(e,t=96){let n=e.toString();return n.length<=t?n:`${n.slice(0,40)}...${n.slice(-40)} (digits=${n.length})`}function Se(){return he.value===`rfc3526`?b:v}function Ce(){R&&(ge.textContent=L.isToy?R.privateKey.toString():`${J(R.privateKey,40)} [hidden by default in production]`,_e.textContent=J(R.publicKey))}function we(){if(E.value===`text`)return p(D.value,L);let e=D.value.trim();if(!/^\d+$/.test(e))throw Error(`Integer mode requires a positive decimal integer.`);let t=BigInt(e);if(t<=0n||t>=L.p)throw Error(`Message must satisfy 1 <= m <= p-1 (p=${L.p}).`);return t}function Y(e){return`(${W(J(e.c1),`c1`)}, ${W(J(e.c2),`c2`)})`}function X(){if(!R)throw Error(`Generate a keypair first.`);return R}var Z=H(`theme-toggle`),Te=H(`theme-label`);function Ee(){let e=(document.documentElement.getAttribute(`data-theme`)??`dark`)===`dark`;Te.textContent=e?`Dark`:`Light`,Z.setAttribute(`aria-pressed`,String(e)),Z.setAttribute(`aria-label`,e?`Switch to light theme`:`Switch to dark theme`)}Ee(),Z.addEventListener(`click`,()=>{let e=(document.documentElement.getAttribute(`data-theme`)??`dark`)===`dark`?`light`:`dark`;document.documentElement.setAttribute(`data-theme`,e),localStorage.setItem(`theme`,e),Ee()}),document.querySelectorAll(`.copy-btn`).forEach(e=>{e.addEventListener(`click`,async()=>{let t=e.dataset.copy;if(!t)return;let n=document.getElementById(t)?.textContent?.trim();if(n)try{await navigator.clipboard.writeText(n);let t=e.textContent;e.textContent=`Copied`,e.classList.add(`copied`),window.setTimeout(()=>{e.textContent=t,e.classList.remove(`copied`)},1400)}catch{e.textContent=`Copy failed`,window.setTimeout(()=>{e.textContent=`Copy`},1400)}})}),(()=>{let t=document.getElementById(`viz-container`),n=document.getElementById(`viz-exp`),r=document.getElementById(`viz-exp-out`),i=document.getElementById(`viz-readout`);if(!t||!n||!r||!i)return;let{g:o,p:s,q:c}=v,l=Number(c-1n),u=Number(s-1n),d=e=>46+e/l*700,f=e=>346-e/u*332,p=``,m=1n;for(let e=0;e<=l;e+=1)p+=`<circle cx="${d(e).toFixed(1)}" cy="${f(Number(m)).toFixed(1)}" r="1.4" class="viz-pt"/>`,m=m*o%s;t.innerHTML=`
    <svg viewBox="0 0 760 380" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
      <line class="viz-axis" x1="46" y1="14" x2="46" y2="346"/>
      <line class="viz-axis" x1="46" y1="346" x2="746" y2="346"/>
      <text class="viz-tick" x="40" y="18" text-anchor="end">${u}</text>
      <text class="viz-tick" x="40" y="346" text-anchor="end">0</text>
      <text class="viz-tick" x="46" y="368" text-anchor="middle">0</text>
      <text class="viz-tick" x="746" y="368" text-anchor="end">${l}</text>
      <text class="viz-axis-label" x="16" y="180" transform="rotate(-90 16 180)" text-anchor="middle">g^x mod p</text>
      <text class="viz-axis-label" x="396" y="376" text-anchor="middle">exponent x</text>
      ${p}
      <line id="viz-vline" class="viz-guide" x1="0" y1="0" x2="0" y2="0"/>
      <line id="viz-hline" class="viz-guide" x1="0" y1="0" x2="0" y2="0"/>
      <circle id="viz-marker" class="viz-marker" cx="0" cy="0" r="5.5"/>
    </svg>`;let h=t.querySelector(`#viz-marker`),g=t.querySelector(`#viz-vline`),_=t.querySelector(`#viz-hline`);function y(t){let n=e(o,BigInt(t),s),a=d(t),c=f(Number(n));h?.setAttribute(`cx`,a.toFixed(1)),h?.setAttribute(`cy`,c.toFixed(1)),g?.setAttribute(`x1`,a.toFixed(1)),g?.setAttribute(`y1`,c.toFixed(1)),g?.setAttribute(`x2`,a.toFixed(1)),g?.setAttribute(`y2`,`346`),_?.setAttribute(`x1`,`46`),_?.setAttribute(`y1`,c.toFixed(1)),_?.setAttribute(`x2`,a.toFixed(1)),_?.setAttribute(`y2`,c.toFixed(1)),r&&(r.textContent=String(t)),i&&(i.textContent=`x = ${t}, y = g^${t} mod p = ${n}`)}n.addEventListener(`input`,()=>y(Number(n.value))),document.getElementById(`viz-random`)?.addEventListener(`click`,()=>{let e=Number(a(c));n.value=String(e),y(e)}),y(Number(n.value))})(),(()=>{let t=document.getElementById(`wt-steps`),r=document.getElementById(`wt-prev`),i=document.getElementById(`wt-next`),o=document.getElementById(`wt-restart`),s=document.getElementById(`wt-progress`);if(!t||!r||!i||!o||!s)return;let c=t,l=s,u=r,d=i,{p:f,g:p,q:m}=v;function h(){let t=a(m),r=e(p,t,f),i=42n,o=a(m),s=e(p,o,f),c=e(r,o,f),l=i*c%f,u=e(s,t,f),d=n(u,f);return{x:t,y:r,m:i,k:o,c1:s,yk:c,c2:l,s:u,sInv:d,mRec:l*d%f}}let g=[{title:`Public parameters`,narration:`ElGamal lives in a cyclic group. Everyone publicly agrees on a large prime p and a generator g. (We use the toy group so the numbers stay small and readable.)`,math:()=>`p = ${W(f)}\ng = ${W(p)}`},{title:`Key generation`,narration:`Alice picks a secret private key x at random, then publishes her public key y = g^x mod p. Recovering x from y is the discrete-log problem — infeasible at real key sizes.`,math:e=>`private  x = ${W(e.x,`priv`)}\npublic   y = g^x mod p = ${W(e.y,`pub`)}`},{title:`The message`,narration:`Bob wants to send the secret value m to Alice, encoded as a number with 1 ≤ m < p.`,math:e=>`m = ${W(e.m,`m`)}`},{title:`Ephemeral key`,narration:`For THIS message only, Bob draws a fresh random k. Reusing k across messages is catastrophic — the Security Lab below shows exactly how it breaks.`,math:e=>`k = ${W(e.k,`k`)}`},{title:`First ciphertext component`,narration:`Bob computes the first half of the ciphertext from the ephemeral key alone.`,math:e=>`c1 = g^k mod p = ${W(e.c1,`c1`)}`},{title:`Second ciphertext component`,narration:`Bob masks the message with the shared value y^k, which only someone who knows x (or k) can reproduce.`,math:e=>`y^k mod p = ${W(e.yk)}\nc2 = m · y^k mod p = ${W(e.c2,`c2`)}`},{title:`Transmit`,narration:`Bob sends the ciphertext pair. An eavesdropper sees only these two numbers — never m, x, or k.`,math:e=>`ciphertext (c1, c2) = (${W(e.c1,`c1`)}, ${W(e.c2,`c2`)})`},{title:`Reconstruct the mask`,narration:`Alice uses her private key to rebuild the same mask: s = c1^x = g^(kx) = y^k. Only the holder of x can do this.`,math:e=>`s = c1^x mod p = ${W(e.s)}\nsame value as y^k: ${G(e.s===e.yk)}`},{title:`Invert the mask`,narration:`Alice computes the modular inverse of the mask so she can divide it back out.`,math:e=>`s⁻¹ mod p = ${W(e.sInv)}`},{title:`Recover the message`,narration:`Multiplying the inverse mask back out reveals the plaintext — and it matches what Bob sent.`,math:e=>`m = c2 · s⁻¹ mod p = ${W(e.mRec,`m`)}\nrecovered original message: ${G(e.mRec===e.m)}`}],_=h(),y=0;function b(){c.innerHTML=g.slice(0,y+1).map((e,t)=>`
        <div class="wt-step${t===y?` current`:``}">
          <h3>${t+1}. ${U(e.title)}</h3>
          <p class="wt-narr">${U(e.narration)}</p>
          <pre class="output">${e.math(_)}</pre>
        </div>`).join(``),l.textContent=`Step ${y+1} of ${g.length}`,u.disabled=y===0,d.disabled=y===g.length-1}i.addEventListener(`click`,()=>{y<g.length-1&&(y+=1,b())}),r.addEventListener(`click`,()=>{y>0&&(--y,b())}),o.addEventListener(`click`,()=>{_=h(),y=0,b()}),b()})(),he.addEventListener(`change`,()=>{L=Se(),R=null,z=null,V=null,ge.textContent=`Not generated`,_e.textContent=`Not generated`,K(O,`${U(L.label)} selected. Generate keys to begin.`),k.textContent=``,k.removeAttribute(`data-state`),K(A,`Encrypt a message first, then re-randomize.`)}),E.addEventListener(`change`,()=>{E.value===`text`?(D.value=`yes`,D.setAttribute(`inputmode`,`text`)):(D.value=`42`,D.setAttribute(`inputmode`,`numeric`))}),H(`keygen-btn`).addEventListener(`click`,()=>{L=Se(),R=l(L),Ce(),K(O,`Keypair generated in ${U(L.label)}.`)});function De(t=!1){try{let n=X(),r=we(),i=d(r,n.publicKey,L);V=z,z=i.ciphertext,B=r,be=i.ephemeralK;let a=e(n.publicKey,i.ephemeralK,L.p),o=V?`Previous c1 = ${W(J(V.c1),`c1`)}\nNew c1      = ${W(J(i.ciphertext.c1),`c1`)}\nDifferent: ${G(V.c1!==i.ciphertext.c1)}`:`Run "Encrypt Again" to observe non-determinism directly.`;K(O,[`Message m = ${W(J(r),`m`)}`,`k = ${W(J(i.ephemeralK),`k`)}`,`c1 = g^k mod p = ${W(J(i.ciphertext.c1),`c1`)}`,`c2 = m · y^k mod p = ${W(J(r*a%L.p),`c2`)}`,`Ciphertext ${Y(i.ciphertext)}`,t?`Same plaintext encrypted again.`:``,o].filter(Boolean).join(`
`))}catch(e){q(O,e)}}H(`encrypt-btn`).addEventListener(`click`,()=>De(!1)),H(`encrypt-again-btn`).addEventListener(`click`,()=>De(!0)),H(`decrypt-btn`).addEventListener(`click`,()=>{try{let t=X();if(!z||B===null||be===null)throw Error(`No ciphertext available. Encrypt first.`);let r=e(z.c1,t.privateKey,L.p),i=n(r,L.p),a=f(z,t.privateKey,L),o=E.value===`text`?`\nDecoded text: "${U(m(a,L))}"`:``;K(k,[`Ciphertext ${Y(z)}`,`s = c1^x mod p = ${W(J(r))}`,`s⁻¹ mod p = ${W(J(i))}`,`m = c2 · s⁻¹ mod p = ${W(J(a),`m`)}`,`Recovered original: ${G(a===B)}`,o].join(`
`))}catch(e){q(k,e)}}),H(`homo-btn`).addEventListener(`click`,()=>{try{let e=BigInt(H(`homo-m1`).value),t=BigInt(H(`homo-m2`).value);if(e<=0n||t<=0n||e>=v.p||t>=v.p)throw Error(`Use values in range 1..2038 for toy homomorphic demo.`);let n=l(v),r=d(e,n.publicKey,v).ciphertext,i=d(t,n.publicKey,v).ciphertext,a=h(r,i),o=f(a,n.privateKey,v),s=e*t%v.p;K(ve,[`CT1 = E(${W(e,`m`)}) = ${Y(r)}`,`CT2 = E(${W(t,`m`)}) = ${Y(i)}`,`CT3 = CT1 ⊗ CT2 = ${Y(a)}`,`Decrypt(CT3) = ${W(o,`m`)}`,`Expected m1·m2 mod p = ${W(s,`m`)}`,`Match: ${G(o===s)}`].join(`
`))}catch(e){q(ve,e)}}),H(`rerand-btn`).addEventListener(`click`,()=>{try{let e=X();if(!z||B===null)throw Error(`Encrypt first to create a ciphertext to re-randomize.`);let t=g(z,e.publicKey,L),n=f(z,e.privateKey,L),r=f(t,e.privateKey,L);K(A,[`Original:    ${Y(z)}`,`Re-random.:  ${Y(t)}`,`Ciphertext changed: ${G(z.c1!==t.c1||z.c2!==t.c2)}`,`Decrypt(original) = ${W(J(n),`m`)}`,`Decrypt(rerandom) = ${W(J(r),`m`)}`,`Same plaintext: ${G(n===r)}`].join(`
`)),z=t}catch(e){q(A,e)}}),H(`mixnet-btn`).addEventListener(`click`,()=>{try{let e=l(v),t=[`Alice`,`Bob`,`Charlie`],n=[11n,19n,29n].map((n,r)=>({label:t[r],ct:d(n,e.publicKey,v).ciphertext,m:n})),r=n.map(t=>({...t,ct:g(t.ct,e.publicKey,v)})),i=[r[2],r[0],r[1]];K(j,[`Inputs:`,...n.map(e=>`${U(e.label)}: ${Y(e.ct)}`),``,`Outputs after re-randomize + shuffle:`,...i.map((t,n)=>`Out${n+1}: ${Y(t.ct)} → decrypts to ${W(f(t.ct,e.privateKey,v),`m`)}`),``,`Observer sees changed bytes and changed order, but cannot link sender to output without secret permutation info.`].join(`
`))}catch(e){q(j,e)}});function Q(e){let t=H(e).value.trim();if(!/^\d+$/.test(t))throw Error(`Enter a positive integer.`);let n=BigInt(t);if(n<=0n||n>=v.p)throw Error(`Use values in range 1..2038 for the toy group.`);return n}H(`crack-btn`).addEventListener(`click`,()=>{try{let t=l(v),{x:n,steps:r}=ne(v,t.publicKey),i=n!==null&&e(v.g,n,v.p)===t.publicKey;K(M,[`Public key y = ${W(t.publicKey,`pub`)}   (this is all the attacker sees)`,`Goal: find x such that g^x ≡ y (mod ${v.p}),  g = ${v.g}`,``,`Recovered x = ${W(n??`not found`,`priv`)}`,`Actual x    = ${W(t.privateKey,`priv`)}`,`Key recovered: ${G(i&&n===t.privateKey)}`,`Baby-step/giant-step operations: ${W(r)}  (naive search would scan up to ${v.q})`,``,`The toy subgroup order is ~1019, so this finishes instantly.`,`RFC 3526 Group 14 has order ≈ 2^2047 — the same attack would need more`,`operations than there are atoms in the observable universe. That gap is the security.`].join(`
`))}catch(e){q(M,e)}}),H(`kreuse-btn`).addEventListener(`click`,()=>{try{let e=Q(`kreuse-m1`),t=Q(`kreuse-m2`),r=l(v),i=a(v.q),o=u(e,r.publicKey,v,i),s=u(t,r.publicKey,v,i),c=e*s.c2%v.p*n(o.c2,v.p)%v.p;K(N,[`CT1 = E(${W(e,`m`)}) = ${Y(o)}`,`CT2 = E(${W(t,`m`)}) = ${Y(s)}`,`Shared c1 (the tell): ${G(o.c1===s.c1)} → ${W(o.c1,`c1`)} = ${W(s.c1,`c1`)}`,``,`Attacker knows only m1 and both ciphertexts, then computes`,`m2 = m1 · c2₂ · c2₁⁻¹ mod p:`,`Recovered m2 = ${W(c,`m`)}`,`Actual m2    = ${W(t,`m`)}`,`Secret leaked: ${G(c===t)}  — no private key was used.`].join(`
`))}catch(e){q(N,e)}}),H(`maul-btn`).addEventListener(`click`,()=>{try{let e=Q(`maul-secret`),t=Q(`maul-factor`),n=l(v),r=d(e,n.publicKey,v).ciphertext,i={c1:r.c1,c2:r.c2*t%v.p,group:v},a=f(i,n.privateKey,v),o=e*t%v.p;K(P,[`Honest ciphertext  E(${W(e,`m`)}) = ${Y(r)}`,`Attacker multiplies c2 by t = ${W(t)} (private key never touched):`,`Forged ciphertext  ${Y(i)}`,``,`Owner decrypts forged CT → ${W(a,`m`)}`,`Predicted m·t mod p     → ${W(o,`m`)}`,`Decryption silently altered: ${G(a===o&&t!==1n)}`,``,`The owner has no way to detect tampering — plain ElGamal provides no integrity.`,`(The authenticated-ElGamal exhibit below fixes exactly this.)`].join(`
`))}catch(e){q(P,e)}}),H(`auth-btn`).addEventListener(`click`,async()=>{try{let e=Q(`auth-secret`),t=Q(`auth-factor`),n=l(v),r=await se(e,n.publicKey,v),i=await ce(r,n.privateKey,v),a={...r,c2:r.c2*t%v.p},o=await ce(a,n.privateKey,v);K(F,[`Authenticated ciphertext ${Y(r)}`,`MAC tag = ${W(r.tag.slice(0,32)+`…`)}  (keyed by the shared secret)`,``,`Honest decrypt → authentic: ${G(i.authentic)}, m = ${W(i.message??0n,`m`)}`,``,`Attacker multiplies c2 by t = ${W(t)} (the same malleability attack):`,`Forged ciphertext ${Y(a)}`,`Owner verifies MAC → authentic: ${G(o.authentic)}`,o.authentic?`t = 1 leaves the ciphertext unchanged, so it still verifies. Try t ≥ 2.`:`Tampering REJECTED — the recomputed MAC does not match, so decryption is refused.`,``,`Integrity restored. The tradeoff: this ciphertext can no longer be re-randomized`,`or homomorphically multiplied without breaking the tag.`].join(`
`))}catch(e){q(F,e)}});function $(e){let t=H(e).value.trim();if(!/^\d+$/.test(t))throw Error(`Enter a positive integer.`);let n=BigInt(t);if(n<=0n||n>=S.n)throw Error(`Use values in range 1..2037 for the signature demo.`);return n}H(`sign-btn`).addEventListener(`click`,()=>{try{let e=$(`sign-msg`),t=ue(),{sig:n,k:r}=de(e,t.x),i=fe(e,n,t.y),a=e%(S.n-1n)+1n,o=fe(a,n,t.y);K(I,[`Public key y = g^x mod p = ${W(t.y,`pub`)}   (private x = ${W(t.x,`priv`)})`,``,`Sign h = ${W(e,`m`)}  (ephemeral k = ${W(r,`k`)}, kept secret)`,`Signature (r, s) = (${W(n.r,`c1`)}, ${W(n.s,`c2`)})`,``,`Verify g^h ≡ y^r · r^s (mod p): ${G(i)}`,`Same signature on a different message h = ${W(a,`m`)}: ${G(o)}`,``,`A valid signature binds the message to the private key; changing the message breaks it.`].join(`
`))}catch(e){q(I,e)}}),H(`sigreuse-btn`).addEventListener(`click`,()=>{try{let e=$(`sigreuse-m1`),t=$(`sigreuse-m2`);if(e===t)throw Error(`Use two different messages so the signatures differ.`);let n=ue(),r=null,i=null,o=null;for(let s=0;s<2e3&&i===null;s+=1){let s=a(S.n);try{i=T(e,n.x,s),o=T(t,n.x,s),r=s}catch{i=null}}if(!i||!o||r===null)throw Error(`Could not sample a usable nonce; try again.`);let{k:s,x:c}=pe(e,i.s,t,o.s,i.r,n.y);K(ye,[`Signature 1 on h1 = ${W(e,`m`)}: (r, s) = (${W(i.r,`c1`)}, ${W(i.s,`c2`)})`,`Signature 2 on h2 = ${W(t,`m`)}: (r, s) = (${W(o.r,`c1`)}, ${W(o.s,`c2`)})`,`Shared r (the tell): ${G(i.r===o.r)}`,``,`From s1 - s2 ≡ (h1 - h2)·k⁻¹ the attacker solves for k, then for x:`,`Recovered k = ${W(s??`none`,`k`)}   (actual ${W(r,`k`)})`,`Recovered private key x = ${W(c??`none`,`priv`)}`,`Actual private key x    = ${W(n.x,`priv`)}`,`Full key compromised: ${G(c===n.x)}  — every future signature is now forgeable.`].join(`
`))}catch(e){q(ye,e)}});