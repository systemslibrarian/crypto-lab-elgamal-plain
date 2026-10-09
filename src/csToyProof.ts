import { discreteLog } from './attacks';
import type { CsCiphertext, CsPublicKey } from './cramerShoup';
import { modInverse } from './modular';

export interface ProofTuple { x1: bigint; x2: bigint; y1: bigint; y2: bigint }

function mod(x: number, q: number): number { return (x % q + q) % q; }

/** The q² tuples are represented by free coordinates x2,y2. */
export class ToyKeySpace {
  readonly q: number;
  readonly w: number;
  readonly C: number;
  readonly D: number;
  readonly alive: Uint8Array;
  remaining: number;
  private readonly publicKey: CsPublicKey;

  constructor(publicKey: CsPublicKey) {
    if (!publicKey.group.isToy) {
      // Reuse the lab's explicit feasibility explanation.
      discreteLog(publicKey.group, publicKey.g2);
      throw new Error('Consistent-key enumeration is toy-only.');
    }
    this.publicKey = publicKey;
    this.q = Number(publicKey.group.q);
    const log = (value: bigint): number => {
      const found = discreteLog({ ...publicKey.group, g: publicKey.g1 }, value).x;
      if (found === null) throw new Error('Public key contains an element outside G.');
      return Number(found);
    };
    this.w = log(publicKey.g2);
    this.C = log(publicKey.c);
    this.D = log(publicKey.d);
    this.alive = new Uint8Array(this.q * this.q).fill(1);
    this.remaining = this.alive.length;
  }

  tuple(x2: number, y2: number): ProofTuple {
    const { q, w, C, D } = this;
    return {
      x1: BigInt(mod(C - w * x2, q)), x2: BigInt(x2),
      y1: BigInt(mod(D - w * y2, q)), y2: BigInt(y2),
    };
  }

  /** Predicts a check from public logs, not by calling the decryptor. */
  prediction(ct: CsCiphertext, alpha: bigint, x2: number, y2: number): number {
    const { q, w, C, D } = this;
    const group = { ...this.publicKey.group, g: this.publicKey.g1 };
    const log = (value: bigint): number => {
      const found = discreteLog(group, value).x;
      if (found === null) throw new Error('Query component is outside G.');
      return Number(found);
    };
    const R1 = log(ct.u1), R2 = log(ct.u2);
    return mod(R1 * (C + Number(alpha) * D) + (R2 - R1 * w) * (x2 + Number(alpha) * y2), q);
  }

  private terms(ct: CsCiphertext, alpha: bigint): { base: number; delta: number; a: number; target: number } {
    const group = { ...this.publicKey.group, g: this.publicKey.g1 };
    const log = (value: bigint): number => {
      const found = discreteLog(group, value).x;
      if (found === null) throw new Error('Query component is outside G.');
      return Number(found);
    };
    const R1 = log(ct.u1), R2 = log(ct.u2);
    return {
      base: mod(R1 * (this.C + Number(alpha) * this.D), this.q),
      delta: mod(R2 - R1 * this.w, this.q), a: Number(alpha), target: log(ct.v),
    };
  }

  histogram(ct: CsCiphertext, alpha: bigint): number[] {
    const { base, delta, a } = this.terms(ct, alpha);
    const bins = Array<number>(this.q).fill(0);
    // [extension] point: this is the elementary hash-proof-system example.
    for (let y2 = 0; y2 < this.q; y2++) {
      for (let x2 = 0; x2 < this.q; x2++) {
        bins[mod(base + delta * (x2 + a * y2), this.q)]++;
      }
    }
    return bins;
  }

  observe(ct: CsCiphertext, alpha: bigint, accepted: boolean): { before: number; passing: number; remaining: number } {
    const { base, delta, a, target } = this.terms(ct, alpha);
    const before = this.remaining;
    if (delta === 0) {
      const passing = base === target ? before : 0;
      if (accepted !== (base === target)) {
        this.alive.fill(0);
        this.remaining = 0;
      }
      return { before, passing, remaining: this.remaining };
    }

    // For each y2, exactly one x2 can predict v. Solve that line directly
    // instead of scanning q² keys after every oracle query.
    const inverse = Number(modInverse(BigInt(delta), BigInt(this.q)));
    const intercept = mod((target - base) * inverse, this.q);
    const kept = accepted ? new Uint8Array(this.alive.length) : null;
    let passing = 0;
    for (let y2 = 0; y2 < this.q; y2++) {
      const x2 = mod(intercept - a * y2, this.q);
      const index = y2 * this.q + x2;
      if (!this.alive[index]) continue;
      passing++;
      if (kept) kept[index] = 1;
      else this.alive[index] = 0;
    }
    if (kept) {
      this.alive.set(kept);
      this.remaining = passing;
    } else {
      this.remaining -= passing;
    }
    return { before, passing, remaining: this.remaining };
  }
}
