export interface ExtendedGcdResult {
  gcd: bigint;
  x: bigint;
  y: bigint;
}

/**
 * Modular exponentiation: base^exp mod m.
 * Square-and-multiply — O(log exp) multiplications.
 */
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  if (m <= 0n) {
    throw new Error('Modulus must be positive.');
  }
  if (m === 1n) {
    return 0n;
  }

  let result = 1n;
  let b = ((base % m) + m) % m;
  let e = exp;

  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = (result * b) % m;
    }
    e >>= 1n;
    b = (b * b) % m;
  }

  return result;
}

/**
 * Extended Euclidean algorithm — returns { gcd, x, y } such that
 * a·x + b·y = gcd(a, b).
 */
export function extendedGcd(a: bigint, b: bigint): ExtendedGcdResult {
  let oldR = a;
  let r = b;
  let oldS = 1n;
  let s = 0n;
  let oldT = 0n;
  let t = 1n;

  while (r !== 0n) {
    const q = oldR / r;

    const nextR = oldR - q * r;
    oldR = r;
    r = nextR;

    const nextS = oldS - q * s;
    oldS = s;
    s = nextS;

    const nextT = oldT - q * t;
    oldT = t;
    t = nextT;
  }

  const gcd = oldR < 0n ? -oldR : oldR;
  const sign = oldR < 0n ? -1n : 1n;

  return {
    gcd,
    x: oldS * sign,
    y: oldT * sign,
  };
}

/**
 * Modular inverse: a^-1 mod m. Uses extended Euclidean algorithm.
 */
export function modInverse(a: bigint, m: bigint): bigint {
  if (m <= 0n) {
    throw new Error('Modulus must be positive.');
  }

  const normalizedA = ((a % m) + m) % m;
  const { gcd, x } = extendedGcd(normalizedA, m);

  if (gcd !== 1n) {
    throw new Error('Inverse does not exist because gcd(a, m) != 1.');
  }

  return ((x % m) + m) % m;
}

function byteLength(n: bigint): number {
  const bits = n.toString(2).length;
  return Math.ceil(bits / 8);
}

function randomBigIntWithBytes(bytes: number): bigint {
  const random = new Uint8Array(bytes);
  crypto.getRandomValues(random);

  let value = 0n;
  for (const byte of random) {
    value = (value << 8n) | BigInt(byte);
  }

  return value;
}

/**
 * Cryptographically random BigInt in [1, max).
 * Uses rejection sampling to avoid modulo bias.
 */
export function randomBigInt(max: bigint): bigint {
  if (max <= 1n) {
    throw new Error('max must be > 1.');
  }

  const bytes = byteLength(max - 1n);

  while (true) {
    const candidate = randomBigIntWithBytes(bytes);
    if (candidate > 0n && candidate < max) {
      return candidate;
    }
  }
}

/**
 * Miller-Rabin primality test.
 */
export function isProbablePrime(n: bigint, k = 16): boolean {
  if (n <= 1n) return false;
  if (n <= 3n) return true;
  if ((n & 1n) === 0n) return false;

  let d = n - 1n;
  let r = 0;

  while ((d & 1n) === 0n) {
    d >>= 1n;
    r += 1;
  }

  for (let i = 0; i < k; i += 1) {
    const a = randomBigInt(n - 3n) + 2n;
    let x = modPow(a, d, n);

    if (x === 1n || x === n - 1n) {
      continue;
    }

    let witnessFound = true;
    for (let j = 1; j < r; j += 1) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) {
        witnessFound = false;
        break;
      }
    }

    if (witnessFound) {
      return false;
    }
  }

  return true;
}
