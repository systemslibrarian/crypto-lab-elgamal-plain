import type { ElGamalGroup } from './groups';
import { modInverse, modPow } from './modular';

/** Largest subgroup order we are willing to brute-force in the browser. */
const MAX_FEASIBLE_ORDER = 1n << 26n; // ~67M baby steps worst case

export interface DiscreteLogResult {
  /** Recovered exponent x with g^x = target (mod p), or null if not found. */
  x: bigint | null;
  /** Total table insertions + lookups performed. */
  steps: number;
}

/** Integer ceil(sqrt(n)) for BigInt via Newton's method. */
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

/**
 * Solve the discrete logarithm g^x = target (mod p) over the order-q subgroup
 * using baby-step/giant-step: O(sqrt(q)) time and space.
 *
 * This is exactly the computation an attacker must perform to recover a private
 * key from a public key. It is tractable for the toy group (q ~ 1019) and
 * astronomically infeasible for RFC 3526 Group 14 (q ~ 2^2047) — hence the
 * feasibility guard, which encodes the security argument as code.
 */
export function discreteLog(group: ElGamalGroup, target: bigint): DiscreteLogResult {
  const { g, p, q } = group;

  if (q > MAX_FEASIBLE_ORDER) {
    throw new Error(
      `Subgroup order ~2^${q.toString(2).length} is computationally infeasible to brute-force — ` +
        'that infeasibility is precisely what keeps real ElGamal secure.'
    );
  }

  const m = sqrtCeil(q);

  // Baby steps: table of g^j for j in [0, m).
  const table = new Map<string, bigint>();
  let e = 1n;
  let steps = 0;
  for (let j = 0n; j < m; j += 1n) {
    const key = e.toString();
    if (!table.has(key)) table.set(key, j);
    e = (e * g) % p;
    steps += 1;
  }

  // Giant steps: walk target * (g^-m)^i until it lands in the baby-step table.
  const factor = modInverse(modPow(g, m, p), p);
  let gamma = ((target % p) + p) % p;
  for (let i = 0n; i <= m; i += 1n) {
    steps += 1;
    const found = table.get(gamma.toString());
    if (found !== undefined) {
      return { x: i * m + found, steps };
    }
    gamma = (gamma * factor) % p;
  }

  return { x: null, steps };
}
