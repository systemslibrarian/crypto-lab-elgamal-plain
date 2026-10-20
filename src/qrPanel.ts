import { GROUP14, TOY_GROUP } from './groups';
import { legendre, encodeToSubgroup } from './residuosity';
import { runIndCpaGame, type Setting } from './qrGame';
export const qrMarkup = `
<section id="exhibit-qr" class="card attack qr-card" aria-labelledby="qr-title">
  <h2 id="qr-title"><span class="badge attack-badge qr-badge" aria-hidden="true"></span>Attack: The Bit ElGamal Leaks</h2>
  <p class="lesson">A ciphertext can hide the full message while revealing one property of it. Here an attacker uses only the public key and ciphertext to tell a square from a non-square. Moving the key into a prime-order subgroup does not fix messages encoded outside that subgroup.</p>
  <div class="grid two">
    <label for="qr-group">Group<select id="qr-group"><option value="toy">Toy: p = 2039 — NOT SECURE</option><option value="group14">RFC 3526 Group 14 (2048-bit)</option></select></label>
    <label for="qr-euler-input">Try Euler’s criterion<input id="qr-euler-input" value="7" inputmode="numeric"></label>
  </div>
  <p id="qr-euler" class="qr-numbers" aria-live="polite"></p>
  <div class="qr-settings" role="group" aria-label="Encryption setting">
    <button type="button" data-qr-setting="A" aria-pressed="false">A · Full group — deliberately broken</button>
    <button type="button" data-qr-setting="B" aria-pressed="false">B · Existing subgroup + raw message — leaks</button>
    <button type="button" data-qr-setting="C" aria-pressed="true">C · Subgroup + subgroup encoding</button>
  </div>
  <p id="qr-setting-note" class="note"></p>
  <div class="grid three">
    <label for="qr-m0">Challenge message m₀<input id="qr-m0" value="2" inputmode="numeric"></label>
    <label for="qr-m1">Challenge message m₁<input id="qr-m1" value="7" inputmode="numeric"></label>
    <label for="qr-trials">Trials<input id="qr-trials" type="number" min="1" max="1000" value="200"></label>
  </div>
  <p id="qr-symbols" class="qr-numbers" aria-live="polite"></p>
  <p class="note" title="If the two messages have the same quadratic character, this one-bit adversary cannot distinguish them.">Equal Legendre symbols produce a tie: this adversary guesses 0. A small run can deviate far from 50%; a lucky tally is not a security proof.</p>
  <div class="actions"><button id="qr-run" type="button">Run the public-value attack</button><button id="qr-stop" type="button" disabled>Stop</button></div>
  <p id="qr-status" role="status"></p>
  <div id="qr-result" aria-live="polite"></div>
  <div id="qr-transcripts"></div>
  <details><summary>What this experiment does not cover</summary>
    <p>Prime-order elliptic-curve groups do not have this Legendre-character leak. Composite-modulus quadratic residuosity belongs to Goldwasser–Micali. Small-subgroup private-key attacks are a separate issue addressed by this lab’s c₁ validation. For formal advantage estimates and the DDH reduction, visit <a href="https://systemslibrarian.github.io/crypto-lab-hidden-bit/">Hidden Bit</a>.</p>
  </details>
  <p class="note">Source: <a href="https://crypto.stanford.edu/~dabo/papers/DDH.pdf">Boneh, The Decision Diffie-Hellman Problem (1998), §1.1</a>; <a href="https://www.rfc-editor.org/rfc/rfc3526.html#section-3">RFC 3526 §3</a> supplies the Group 14 parameters. This toy group is easily broken even when the message encoding defeats this particular adversary.</p>
</section>`;

export function mountQRPanel() {
  const el = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(`qr-${id}`) as T;
  const value = (id: string) => el<HTMLInputElement>(id).value;
  let setting: Setting = 'C', epoch = 0, context = '';
  const group = () => value('group') === 'toy' ? TOY_GROUP : GROUP14;
  function retire(message = 'Inputs changed: previous run retired.') {
    epoch++; el('result').replaceChildren(); el('transcripts').replaceChildren();
    el('status').textContent = message; el<HTMLButtonElement>('run').disabled = false; el<HTMLButtonElement>('stop').disabled = true;
  }
  function symbols() {
    const g = group();
    try {
      const a = BigInt(value('euler-input')), symbol = legendre(a,g.p);
      const reduced = ((a % g.p) + g.p) % g.p;
      el('euler').textContent = `${reduced}^${g.q} mod ${g.p} = ${symbol === -1 ? g.p-1n : BigInt(symbol)}; Legendre = ${symbol}. ${symbol===1 ? 'A nonzero square (quadratic residue).' : symbol===-1 ? 'A non-square (quadratic non-residue).' : 'Zero has symbol 0.'}`;
    } catch { el('euler').textContent = 'Enter an integer for Euler’s criterion.'; }
    try {
      const m0=BigInt(value('m0')),m1=BigInt(value('m1'));
      el('symbols').textContent = `Raw messages: Legendre(m₀) = ${legendre(m0,g.p)}; Legendre(m₁) = ${legendre(m1,g.p)}.`;
      if(setting==='C')el('symbols').textContent += ` Encoded: m₀ → ${encodeToSubgroup(m0,g.p)}; m₁ → ${encodeToSubgroup(m1,g.p)}; both symbols are 1.`;
    } catch(error) { el('symbols').textContent = (error as Error).message; }
    el('setting-note').textContent = setting==='A' ? 'Deliberately broken full group: public Legendre(y) and Legendre(c₁) reveal the mask’s character.' : setting==='B' ? 'This uses Exhibit 1’s existing encrypt() unchanged. Its mask is a square, so Legendre(c₂) = Legendre(m).' : 'Map m to m or p − m, whichever is a square; decode with min(x, p − x). The one-bit adversary now sees equal symbols. This observation does not establish security.';
  }
  function changed() {
    const next = [setting,value('group'),value('m0'),value('m1'),value('trials')].join('|');
    if(next !== context) { context=next; retire(); }
    symbols();
  }
  document.querySelectorAll<HTMLButtonElement>('[data-qr-setting]').forEach(button => button.addEventListener('click',()=>{
    if(setting===button.dataset.qrSetting)return;
    setting=button.dataset.qrSetting as Setting;
    document.querySelectorAll('[data-qr-setting]').forEach(b=>b.setAttribute('aria-pressed',String(b===button)));
    changed();
  }));
  el('group').addEventListener('change',()=>{
    // 7 is a non-residue for 2039, but a residue in Group 14; 11 is the
    // first small non-residue there. Keep the default contrast informative.
    if(value('m0')==='2' && ['7','11'].includes(value('m1'))) el<HTMLInputElement>('m1').value=group().isToy?'7':'11';
    const max=group().isToy?1000:30;el<HTMLInputElement>('trials').max=String(max);el<HTMLInputElement>('trials').value=group().isToy?'200':'8'; changed();
  });
  for(const id of ['m0','m1','trials'])el(id).addEventListener('input',changed);
  el('euler-input').addEventListener('input',symbols);
  el('stop').addEventListener('click',()=>retire('Run stopped; incomplete results discarded.'));
  el('run').addEventListener('click',async()=>{
    retire('Computing real encryptions…');const version=epoch;
    el<HTMLButtonElement>('run').disabled=true;el<HTMLButtonElement>('stop').disabled=false;
    try {
      const result=await runIndCpaGame(setting,BigInt(value('m0')),BigInt(value('m1')),Number(value('trials')),{group:group(),cancelled:()=>version!==epoch});
      if(version!==epoch)return;
      const {rows,wins}=result, n=rows.length, distinct=legendre(result.encoded[0],result.group.p)!==legendre(result.encoded[1],result.group.p);
      const alarm=result.setting!=='C' && distinct && wins===n;
      const verdict=document.createElement('p');verdict.className=alarm?'qr-verdict qr-alarm':'qr-verdict';verdict.dataset.verdict=alarm?'leaked':'limited';
      verdict.textContent=alarm?'⚠ VALID AND RANDOMISED — AND ONE BIT LEAKED':'ℹ This distinguisher sees equal message characters; its tally is not a security verdict.';
      const tally=document.createElement('p');tally.id='qr-tally';tally.textContent=`${wins} / ${n} correct guesses (${(100*wins/n).toFixed(1)}%).`;
      const checks=document.createElement('p');checks.id='qr-checks';checks.className=rows.every(r=>r.roundTrip && r.subgroupChecks!==false)?'qr-checks':'qr-alarm';
      checks.textContent=`${rows.filter(r=>r.roundTrip).length} / ${n} decryption round-trips. ${result.setting==='A'?'Full-group mode: subgroup checks are inapplicable.':`${rows.filter(r=>r.subgroupChecks).length} / ${n} public-key and c₁ subgroup checks passed; c₂ is not checked by assertGroupElement.`} Fresh ephemeral k drawn for every encryption; ${rows.filter(r=>r.repeated).length} repeated ciphertexts observed (repeats are possible).`;
      const params=document.createElement('p');params.id='qr-params';params.className='qr-numbers';params.textContent=`p=${result.group.p}; g=${rows[0].g}; y=${rows[0].y}; raw m0=${result.m0}; raw m1=${result.m1}; challenge m0=${result.encoded[0]}; challenge m1=${result.encoded[1]}.`;
      el('result').append(verdict,tally,checks,params);
      if(result.setting==='B') {
        const negative=document.createElement('p');negative.id='qr-negative';negative.textContent='Fresh randomness and a prime-order subgroup do not by themselves hide the message: in this lab’s Exhibit 1 encryption, the quadratic character of m passes straight through to c₂.';el('result').append(negative);
      }
      if(result.setting==='C') {
        const limit=document.createElement('p');limit.id='qr-limit';limit.textContent='This distinguisher learns nothing from the Legendre bit: both encoded messages and every c₂ are quadratic residues. Security of properly instantiated ElGamal relies on the DDH assumption and its reduction, not on this measured win rate. Toy parameters remain insecure.';el('result').append(limit);
      }
      rows.forEach((r,i)=>{
        const details=document.createElement('details');details.open=i<3;details.className='qr-trial';
        const summary=document.createElement('summary');summary.textContent=`Trial ${i+1}: guess ${r.guess}, truth ${r.truth} — ${r.correct?'correct':'incorrect'}`;
        const transcript=document.createElement('pre');transcript.className='output';transcript.tabIndex=0;
        transcript.textContent=`c1=${r.c1}\nc2=${r.c2}\nLegendre(y)=${r.ly}\nLegendre(c1)=${r.lc1}\nLegendre(c2)=${r.lc2}\nguess=${r.guess}\ntruth=${r.truth}\ncorrect=${r.correct}\nroundTrip=${r.roundTrip}\nsubgroupChecks=${r.subgroupChecks}\nrepeated=${r.repeated}`;
        details.append(summary,transcript);el('transcripts').append(details);
      });
      el('status').textContent=`Completed ${n} trials in ${result.elapsedMs.toFixed(1)} ms. All trials are available below; the first three are expanded.`;
    } catch(error) { if(version===epoch)el('status').textContent=(error as Error).message; }
    finally { if(version===epoch){el<HTMLButtonElement>('run').disabled=false;el<HTMLButtonElement>('stop').disabled=true;} }
  });
  changed();el('status').textContent='Choose two messages, then run. Setting C is the default.';
}
