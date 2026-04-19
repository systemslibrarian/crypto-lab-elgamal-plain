(function(){let e=document.createElement(`link`).relList;if(e&&e.supports&&e.supports(`modulepreload`))return;for(let e of document.querySelectorAll(`link[rel="modulepreload"]`))n(e);new MutationObserver(e=>{for(let t of e)if(t.type===`childList`)for(let e of t.addedNodes)e.tagName===`LINK`&&e.rel===`modulepreload`&&n(e)}).observe(document,{childList:!0,subtree:!0});function t(e){let t={};return e.integrity&&(t.integrity=e.integrity),e.referrerPolicy&&(t.referrerPolicy=e.referrerPolicy),e.crossOrigin===`use-credentials`?t.credentials=`include`:e.crossOrigin===`anonymous`?t.credentials=`omit`:t.credentials=`same-origin`,t}function n(e){if(e.ep)return;e.ep=!0;let n=t(e);fetch(e.href,n)}})();function e(e,t,n){if(n<=0n)throw Error(`Modulus must be positive.`);if(n===1n)return 0n;let r=1n,i=(e%n+n)%n,a=t;for(;a>0n;)(a&1n)==1n&&(r=r*i%n),a>>=1n,i=i*i%n;return r}function t(e,t){let n=e,r=t,i=1n,a=0n,o=0n,s=1n;for(;r!==0n;){let e=n/r,t=n-e*r;n=r,r=t;let c=i-e*a;i=a,a=c;let l=o-e*s;o=s,s=l}let c=n<0n?-n:n,l=n<0n?-1n:1n;return{gcd:c,x:i*l,y:o*l}}function n(e,n){if(n<=0n)throw Error(`Modulus must be positive.`);let{gcd:r,x:i}=t((e%n+n)%n,n);if(r!==1n)throw Error(`Inverse does not exist because gcd(a, m) != 1.`);return(i%n+n)%n}function r(e){let t=e.toString(2).length;return Math.ceil(t/8)}function i(e){let t=new Uint8Array(e);crypto.getRandomValues(t);let n=0n;for(let e of t)n=n<<8n|BigInt(e);return n}function a(e){if(e<=1n)throw Error(`max must be > 1.`);let t=r(e-1n);for(;;){let n=i(t);if(n>0n&&n<e)return n}}function o(t,n=16){if(t<=1n)return!1;if(t<=3n)return!0;if((t&1n)==0n)return!1;let r=t-1n,i=0;for(;(r&1n)==0n;)r>>=1n,i+=1;for(let o=0;o<n;o+=1){let n=e(a(t-3n)+2n,r,t);if(n===1n||n===t-1n)continue;let o=!0;for(let r=1;r<i;r+=1)if(n=e(n,2n,t),n===t-1n){o=!1;break}if(o)return!1}return!0}function s(e,t){if(e<=0n||e>=t.p)throw Error(`Message must be in [1, p-1].`)}function c(e,t){return e.p===t.p&&e.q===t.q&&e.g===t.g}function l(t){let n=a(t.q);return{privateKey:n,publicKey:e(t.g,n,t.p),group:t}}function u(t,n,r){s(t,r);let i=a(r.q);return{ciphertext:{c1:e(r.g,i,r.p),c2:t*e(n,i,r.p)%r.p,group:r},ephemeralK:i}}function d(t,r,i){if(!c(t.group,i))throw Error(`Ciphertext group does not match decryption group.`);let a=n(e(t.c1,r,i.p),i.p);return t.c2*a%i.p}function f(e,t){let n=new TextEncoder().encode(e);if(n.length===0)throw Error(`Text message must be non-empty.`);let r=0n;for(let e of n)r=r<<8n|BigInt(e);return s(r,t),r}function p(e,t){s(e,t);let n=[],r=e;for(;r>0n;)n.push(Number(r&255n)),r>>=8n;return n.reverse(),new TextDecoder(`utf-8`,{fatal:!0}).decode(new Uint8Array(n))}function m(e,t){if(!c(e.group,t.group))throw Error(`Ciphertexts are from different groups.`);let n=e.group;return{c1:e.c1*t.c1%n.p,c2:e.c2*t.c2%n.p,group:n}}function h(t,n,r){if(!c(t.group,r))throw Error(`Ciphertext group does not match rerandomization group.`);let i=a(r.q),o=e(r.g,i,r.p),s=e(n,i,r.p);return{c1:t.c1*o%r.p,c2:t.c2*s%r.p,group:r}}var g={p:BigInt(`0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF`),q:0n,g:2n,label:`RFC 3526 Group 14 (2048-bit)`,bitLength:2048,isToy:!1},_={p:2039n,q:1019n,g:2n,label:`TOY (11-bit) - NOT SECURE - for visualization only`,bitLength:11,isToy:!0};function v(e=!1){let t=(g.p-1n)/2n;if(e){if(!o(g.p,12))throw Error(`RFC 3526 Group 14 p failed primality test.`);if(!o(t,12))throw Error(`RFC 3526 Group 14 q failed primality test.`)}return{...g,q:t}}var y=v(),b=document.querySelector(`#app`);if(!b)throw Error(`Missing #app root element.`);b.innerHTML=`
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
`;var x=L(`group-select`),S=L(`message-mode`),C=L(`message-input`),w=L(`private-key`),T=L(`public-key`),E=L(`encrypt-output`),D=L(`decrypt-output`),O=L(`rerand-output`),k=L(`homo-output`),A=L(`mixnet-output`),j=_,M=null,N=null,P=null,F=null,I=null;function L(e){let t=document.getElementById(e);if(!t)throw Error(`Missing element #${e}`);return t}function R(e,t=96){let n=e.toString();return n.length<=t?n:`${n.slice(0,40)}...${n.slice(-40)} (digits=${n.length})`}function z(){return x.value===`rfc3526`?y:_}function B(){M&&(w.textContent=j.isToy?M.privateKey.toString():`${R(M.privateKey,40)} [hidden by default in production]`,T.textContent=R(M.publicKey))}function V(){if(S.value===`text`)return f(C.value,j);let e=C.value.trim();if(!/^\d+$/.test(e))throw Error(`Integer mode requires a positive decimal integer.`);let t=BigInt(e);if(t<=0n||t>=j.p)throw Error(`Message must satisfy 1 <= m <= p-1 (p=${j.p}).`);return t}function H(e){return`(c1, c2) = (${R(e.c1)}, ${R(e.c2)})`}function U(){if(!M)throw Error(`Generate a keypair first.`);return M}L(`theme-toggle`).addEventListener(`click`,()=>{let e=(document.documentElement.getAttribute(`data-theme`)??`dark`)===`dark`?`light`:`dark`;document.documentElement.setAttribute(`data-theme`,e),localStorage.setItem(`theme`,e)}),x.addEventListener(`change`,()=>{j=z(),M=null,N=null,I=null,w.textContent=`Not generated`,T.textContent=`Not generated`,E.textContent=`${j.label} selected. Generate keys to begin.`,D.textContent=``,O.textContent=`Encrypt a message first, then re-randomize.`}),S.addEventListener(`change`,()=>{S.value===`text`?C.value=`yes`:C.value=`42`}),L(`keygen-btn`).addEventListener(`click`,()=>{j=z(),M=l(j),B(),E.textContent=`Keypair generated in ${j.label}.`});function W(t=!1){try{let n=U(),r=V(),i=u(r,n.publicKey,j);I=N,N=i.ciphertext,P=r,F=i.ephemeralK;let a=e(n.publicKey,i.ephemeralK,j.p),o=I?`Previous c1=${R(I.c1)} | New c1=${R(i.ciphertext.c1)} | Different=${I.c1!==i.ciphertext.c1}`:`Run Encrypt Again to observe non-determinism directly.`;E.textContent=[`Message m = ${R(r)}`,`k = ${R(i.ephemeralK)}`,`c1 = g^k mod p = ${R(i.ciphertext.c1)}`,`c2 = m * y^k mod p = ${R(r*a%j.p)}`,`Ciphertext ${H(i.ciphertext)}`,t?`Same plaintext encrypted again.`:``,o].filter(Boolean).join(`
`)}catch(e){E.textContent=G(e)}}L(`encrypt-btn`).addEventListener(`click`,()=>W(!1)),L(`encrypt-again-btn`).addEventListener(`click`,()=>W(!0)),L(`decrypt-btn`).addEventListener(`click`,()=>{try{let t=U();if(!N||P===null||F===null)throw Error(`No ciphertext available. Encrypt first.`);let r=e(N.c1,t.privateKey,j.p),i=n(r,j.p),a=d(N,t.privateKey,j),o=S.value===`text`?`\nDecoded text: "${p(a,j)}"`:``;D.textContent=[`Ciphertext ${H(N)}`,`s = c1^x mod p = ${R(r)}`,`s^-1 mod p = ${R(i)}`,`m = c2 * s^-1 mod p = ${R(a)}`,`Recovered original: ${a===P}`,o].join(`
`)}catch(e){D.textContent=G(e)}}),L(`homo-btn`).addEventListener(`click`,()=>{try{let e=BigInt(L(`homo-m1`).value),t=BigInt(L(`homo-m2`).value);if(e<=0n||t<=0n||e>=_.p||t>=_.p)throw Error(`Use values in range 1..2038 for toy homomorphic demo.`);let n=l(_),r=u(e,n.publicKey,_).ciphertext,i=u(t,n.publicKey,_).ciphertext,a=m(r,i),o=d(a,n.privateKey,_);k.textContent=[`CT1 = ${H(r)}`,`CT2 = ${H(i)}`,`CT3 = CT1 ⊗ CT2 = ${H(a)}`,`Decrypt(CT3) = ${o}`,`Expected m1*m2 mod p = ${e*t%_.p}`].join(`
`)}catch(e){k.textContent=G(e)}}),L(`rerand-btn`).addEventListener(`click`,()=>{try{let e=U();if(!N||P===null)throw Error(`Encrypt first to create a ciphertext to re-randomize.`);let t=h(N,e.publicKey,j),n=d(N,e.privateKey,j),r=d(t,e.privateKey,j);O.textContent=[`Original:   ${H(N)}`,`Re-random.: ${H(t)}`,`Ciphertext changed: ${N.c1!==t.c1||N.c2!==t.c2}`,`Decrypt(original) = ${R(n)}`,`Decrypt(rerandom) = ${R(r)}`,`Same plaintext: ${n===r}`].join(`
`),N=t}catch(e){O.textContent=G(e)}}),L(`mixnet-btn`).addEventListener(`click`,()=>{try{let e=l(_),t=[`Alice`,`Bob`,`Charlie`],n=[11n,19n,29n].map((n,r)=>({label:t[r],ct:u(n,e.publicKey,_).ciphertext,m:n})),r=n.map(t=>({...t,ct:h(t.ct,e.publicKey,_)})),i=[r[2],r[0],r[1]];A.textContent=[`Inputs:`,...n.map(e=>`${e.label}: ${H(e.ct)}`),``,`Outputs after re-randomize + shuffle:`,...i.map((t,n)=>`Out${n+1}: ${H(t.ct)} -> decrypts to ${d(t.ct,e.privateKey,_)}`),``,`Observer sees changed bytes and changed order, but cannot link sender to output without secret permutation info.`].join(`
`)}catch(e){A.textContent=G(e)}});function G(e){return e instanceof Error?`Error: ${e.message}`:`Error: Unknown failure.`}