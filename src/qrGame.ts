import { assertGroupElement, TOY_GROUP, type ElGamalGroup } from './groups';
import { encrypt, decrypt, generateKeyPair } from './elgamal';
import { fullGroupKeygen, fullGroupEncrypt, fullGroupDecrypt } from './fullGroupBroken';
import { legendre, encodeToSubgroup, decodeFromSubgroup } from './residuosity';
export type Setting = 'A' | 'B' | 'C';
export interface PublicChallenge { p: bigint; g: bigint; y: bigint; c1: bigint; c2: bigint; m0: bigint; m1: bigint }
/** Public transcript only: no key, nonce or hidden-bit input. Equal symbols tie to 0. */
export function legendreDistinguisher({p, y, c1, c2, m0, m1}: PublicChallenge): 0 | 1 {
  const mask = legendre(y, p) === -1 && legendre(c1, p) === -1 ? -1 : 1;
  const observed = legendre(c2, p) * mask;
  return legendre(m0, p) === legendre(m1, p) || observed === legendre(m0, p) ? 0 : 1;
}
export interface Trial extends PublicChallenge {
  truth: 0 | 1; guess: 0 | 1; correct: boolean; roundTrip: boolean;
  subgroupChecks: boolean | null; repeated: boolean; ly: number; lc1: number; lc2: number;
}
// [extension] point: Hidden Bit's formal advantage/interval estimator can consume these trials.
export async function runIndCpaGame(setting: Setting, m0: bigint, m1: bigint, trials: number,
  options: { group?: ElGamalGroup; bit?: () => 0 | 1; cancelled?: () => boolean } = {}) {
  const group = options.group ?? TOY_GROUP, max = group.isToy ? 1000 : 30;
  if (!['A','B','C'].includes(setting)) throw new Error('Choose setting A, B or C.');
  if (!Number.isInteger(trials) || trials < 1 || trials > max) throw new Error(`Trial count must be in [1, ${max}].`);
  for (const m of [m0,m1]) if (m < 1n || m >= group.p) throw new Error('Message must be in [1, p-1].');
  const messages = setting === 'C' ? [encodeToSubgroup(m0, group.p), encodeToSubgroup(m1, group.p)] : [m0,m1];
  const normal = setting === 'A' ? null : generateKeyPair(group);
  const full = setting === 'A' ? fullGroupKeygen(group) : null;
  const y = full?.y ?? normal!.publicKey, g = full?.g ?? group.g;
  const rows: Trial[] = []; const seen = new Set<string>();
  const start = performance.now();
  for (let i = 0; i < trials; i++) {
    if (options.cancelled?.()) throw new Error('Run retired because its inputs changed.');
    const truth = options.bit?.() ?? (crypto.getRandomValues(new Uint8Array(1))[0] & 1) as 0 | 1;
    let c1: bigint, c2: bigint, recovered: bigint, subgroupChecks: boolean | null = null;
    if (full) {
      ({c1,c2} = fullGroupEncrypt(messages[truth], y, g, group.p));
      recovered = fullGroupDecrypt(c1,c2,full.x,group.p);
    } else {
      // Setting B deliberately reaches the original, unmodified encryption route.
      const {ciphertext} = encrypt(messages[truth], y, group);
      ({c1,c2} = ciphertext);
      assertGroupElement(y, group, 'public key'); assertGroupElement(c1, group, 'c1'); subgroupChecks = true;
      recovered = decrypt(ciphertext, normal!.privateKey, group);
      if (setting === 'C') recovered = decodeFromSubgroup(recovered, group.p);
    }
    const publicInput = { p:group.p,g,y,c1,c2,m0:messages[0],m1:messages[1] };
    const guess = legendreDistinguisher(publicInput), tag = `${c1}:${c2}`;
    rows.push({...publicInput,truth,guess,correct:guess===truth,roundTrip:recovered===[m0,m1][truth],subgroupChecks,repeated:seen.has(tag),ly:legendre(y,group.p),lc1:legendre(c1,group.p),lc2:legendre(c2,group.p)});
    seen.add(tag);
    if (i % 10 === 9 || !group.isToy) await new Promise<void>(resolve => setTimeout(resolve, 0));
  }
  return {setting,group,m0,m1,encoded:messages,rows,wins:rows.filter(row=>row.correct).length,elapsedMs:performance.now()-start};
}
