import { it, expect } from 'vitest';
import { legendre, encodeToSubgroup, decodeFromSubgroup } from './residuosity';
import { TOY_GROUP, GROUP14, assertGroupElement } from './groups';
import { generateKeyPair, encrypt, decrypt } from './elgamal';
import { FULL_GROUP14_G } from './fullGroupBroken';
import { legendreDistinguisher, runIndCpaGame } from './qrGame';
import { modPow } from './modular';
const p=2039n;
function bits(seed=7021) { let state=seed>>>0; return ():0|1 => { state=(Math.imul(state,1664525)+1013904223)>>>0;return (state>>>31) as 0|1; }; }
it('Euler agrees with independent brute-force squares for every residue modulo 2039',()=>{
  const squares=new Set<bigint>();for(let x=1n;x<p;x++)squares.add(x*x%p);
  for(let a=0n;a<p;a++)expect(legendre(a,p)).toBe(a===0n?0:squares.has(a)?1:-1);
});
it('subgroup encoding round-trips every encodable toy message',()=>{
  const images=new Set<bigint>();
  for(let m=1n;m<=1019n;m++){const x=encodeToSubgroup(m,p);expect(legendre(x,p)).toBe(1);expect(decodeFromSubgroup(x,p)).toBe(m);images.add(x);}
  expect(images.size).toBe(1019);
  for(const m of [0n,1020n,2039n])expect(()=>encodeToSubgroup(m,p)).toThrow('encodable range');
});
it('Group 14 p−2 has full order p−1, while 2 has order q',()=>{
  expect(modPow(FULL_GROUP14_G,GROUP14.q,GROUP14.p)).toBe(GROUP14.p-1n);
  expect(modPow(FULL_GROUP14_G,2n,GROUP14.p)).not.toBe(1n);
  expect(modPow(FULL_GROUP14_G,GROUP14.p-1n,GROUP14.p)).toBe(1n);
  expect(modPow(2n,GROUP14.q,GROUP14.p)).toBe(1n);
});
it('1000 original encryptions leak raw message character despite valid c1 and round-trip',()=>{
  const key=generateKeyPair(TOY_GROUP);
  for(let i=0;i<1000;i++){
    const m=BigInt((i*733)%2038+1),{ciphertext}=encrypt(m,key.publicKey,TOY_GROUP);
    assertGroupElement(ciphertext.c1,TOY_GROUP,'c1');expect(decrypt(ciphertext,key.privateKey,TOY_GROUP)).toBe(m);
    expect(legendre(ciphertext.c2,p)).toBe(legendre(m,p));
  }
});
it('full-group public correction wins all 200 seeded challenges including odd masks',()=>{
  const random=bits(),g=7n,x=17n,y=modPow(g,x,p);
  for(let i=1;i<=200;i++){
    const truth=random(),k=BigInt(i),m=[2n,7n][truth];
    const c1=modPow(g,k,p),c2=m*modPow(y,k,p)%p;
    expect(legendreDistinguisher({p,g,y,c1,c2,m0:2n,m1:7n})).toBe(truth);
  }
});
it('A and B win every seeded trial; encoded C stays within a conservative binomial bound',async()=>{
  for(const setting of ['A','B','C'] as const){
    const result=await runIndCpaGame(setting,2n,7n,200,{bit:bits()});
    expect(result.rows.every(r=>r.roundTrip)).toBe(true);
    expect(result.wins).toBe(result.rows.filter(r=>r.guess===r.truth).length);
    if(setting==='C'){expect(result.rows.every(r=>r.lc2===1)).toBe(true);expect(result.wins).toBeGreaterThanOrEqual(60);expect(result.wins).toBeLessThanOrEqual(140);}
    else expect(result.wins).toBe(200);
  }
});
it('same-character messages produce ties and bad inputs are refused',async()=>{
  const result=await runIndCpaGame('B',2n,4n,20,{bit:bits()});expect(result.rows.every(r=>r.guess===0)).toBe(true);
  await expect(runIndCpaGame('C',1020n,2n,5)).rejects.toThrow('encodable range');
  await expect(runIndCpaGame('B',0n,2n,5)).rejects.toThrow('[1, p-1]');
  await expect(runIndCpaGame('B',2n,7n,0)).rejects.toThrow('[1, 1000]');
  await expect(runIndCpaGame('B',2n,7n,31,{group:GROUP14})).rejects.toThrow('[1, 30]');
});
it('Group 14 uses the same raw-message leak and encoded round-trip',async()=>{
  const raw=await runIndCpaGame('B',2n,11n,2,{group:GROUP14,bit:()=>1});
  expect(raw.rows.every(r=>r.roundTrip&&r.subgroupChecks)).toBe(true);expect(raw.wins).toBe(2);
  const encoded=await runIndCpaGame('C',2n,11n,2,{group:GROUP14,bit:()=>1});
  expect(encoded.rows.every(r=>r.roundTrip&&r.lc2===1)).toBe(true);
});
