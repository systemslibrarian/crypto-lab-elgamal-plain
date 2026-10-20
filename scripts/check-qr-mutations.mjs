// Mutations run only on a committed, clean source baseline. Each is built, killed,
// restored byte-for-byte, rebuilt and tested green before the next begins.
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..'); process.chdir(root);
const config = process.env.PLAYWRIGHT_CONFIG;
const browser = title => ['npx', ['playwright','test','e2e/claims.spec.ts','--project=chromium','--grep',title,'--workers=1','--retries=0',...(config ? ['--config',config] : [])]];
const unit = title => ['npx',['vitest','run','src/residuosity.test.ts','-t',title]];
const build = ['npm',['run','build']];
const run = ([cmd,args]) => spawnSync(cmd,args,{cwd:root,encoding:'utf8',env:{...process.env,CI:'1'}});
const pass = (cmd,label) => { const r=run(cmd); if(r.status!==0) throw Error(`${label}\n${r.stdout}\n${r.stderr}`); return r; };
const hash = () => { const h=createHash('sha256'); const walk=d=>{for(const e of readdirSync(d,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){const p=join(d,e.name); if(e.isDirectory())walk(p);else {h.update(p);h.update(readFileSync(p));}}};walk('dist');return h.digest('hex'); };
const source = 'src/qrGame.ts';
const negative = 'Fresh randomness and a prime-order subgroup do not by themselves hide the message: in this lab’s Exhibit 1 encryption, the quadratic character of m passes straight through to c₂.';
const cases = [
 ['missing full-group mask correction',source,"const mask = legendre(y, p) === -1 && legendre(c1, p) === -1 ? -1 : 1;","const mask = 1; void y; void c1;",unit('full-group public correction')],
 ['missing subgroup decode','src/residuosity.ts','return x <= (p - 1n) / 2n ? x : p - x;','return x;',unit('subgroup encoding round-trips')],
 ['B quietly encodes the message',source,"const messages = setting === 'C' ?", "const messages = setting !== 'A' ?",browser('QR setting B:')],
 ['tally counts guesses',source,'wins:rows.filter(row=>row.correct).length','wins:rows.filter(row=>row.guess===1).length',browser('QR setting C:')],
 ['calm leak verdict','src/qrPanel.ts',"verdict.className=alarm?'qr-verdict qr-alarm':'qr-verdict';","verdict.className='qr-verdict';",browser('QR setting B:')],
 ['wrong limited marker','src/qrPanel.ts',"verdict.dataset.verdict=alarm?'leaked':'limited';","verdict.dataset.verdict=alarm?'leaked':'secure';",browser('QR setting C:')],
 ['missing negative claim','src/qrPanel.ts',negative,'',browser('QR negative claim:')],
];
const dirty=spawnSync('git',['diff','--exit-code','--',...new Set(cases.map(x=>x[1]))],{encoding:'utf8'});
if(dirty.status!==0)throw Error('Commit the source baseline before mutation checks.');
pass(build,'baseline build');const baseline=hash();const evidence=[];
mkdirSync('mutation-logs',{recursive:true});
for(const [name,file,before,after,command] of cases){
 pass(command,`${name}: baseline test`);
 const original=readFileSync(file,'utf8');if(original.split(before).length!==2)throw Error(`${name}: expected one mutation site`);
 let mutant;
 try{
  writeFileSync(file,original.replace(before,after));
  const diff=spawnSync('git',['diff','--',file],{encoding:'utf8'}).stdout;if(!diff.trim())throw Error(`${name}: empty diff`);
  pass(build,`${name}: mutant build`); mutant=hash();if(mutant===baseline)throw Error(`${name}: bundle did not move`);
  const r=run(command);writeFileSync(`mutation-logs/${name.replaceAll(' ','-')}.log`,r.stdout+r.stderr);
  if(r.status===0 || !/expect\(|AssertionError|Error: expect/.test(r.stdout+r.stderr))throw Error(`${name}: no assertion kill\n${r.stdout}\n${r.stderr}`);
  evidence.push({name,sourceDiff:diff,baseline,mutant,namedTest:command[1].includes('--grep') ? command[1][command[1].indexOf('--grep')+1] : command[1].at(-1),assertionFailure:true,retries:0});
 }finally{writeFileSync(file,original);pass(build,`${name}: restore build`);if(hash()!==baseline)throw Error(`${name}: restored hash differs`);pass(command,`${name}: restored test`);}
 evidence.at(-1).restoredGreen=true;console.log(`${name}: killed; exact artifact restored; owning test green`);
}
writeFileSync('mutation-evidence.json',JSON.stringify(evidence,null,2)+'\n');
