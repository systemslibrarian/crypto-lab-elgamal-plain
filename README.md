# crypto-lab-elgamal-plain

## What It Is

This project is an educational, no-backend lab for plain ElGamal encryption, implementing Taher ElGamal's 1985 scheme over RFC 3526 Group 14 (2048-bit) and a toy 11-bit group for transparent arithmetic:

- Opens with a **guided walkthrough** that steps through one full encrypt/decrypt with live values
- Uses BigInt for all modular arithmetic
- Uses square-and-multiply modular exponentiation
- Uses `crypto.getRandomValues` for all randomness
- Demonstrates natural non-determinism (fresh ephemeral `k`)
- Visualizes the discrete-log hardness with an interactive `g^x mod p` scatter plot
- Demonstrates multiplicative homomorphism
- Demonstrates ciphertext re-randomization for mix-net style unlinkability
- Implements the **ElGamal signature scheme** (sign / verify) over a primitive-root group
- Includes an interactive **Security Lab** that lets you break the scheme yourself
- Includes a side-by-side ElGamal vs RSA exhibit

The app includes two parameter sets:

- TOY group (`p = 2039`) for visible math in the UI
- RFC 3526 Group 14 for realistic large-prime behavior

## When to Use It

Use this project when you want to:

- Understand why ElGamal is the direct ancestor of DSA and, structurally, ECDSA
- Learn discrete-log public-key encryption by stepping through concrete arithmetic
- See core homomorphic behavior: multiply ciphertexts, decrypt a product
- Understand how re-randomization supports mix-nets and private e-voting
- Build intuition for threshold ElGamal and related distributed decryption systems

Do not use this for bulk file encryption. Plain ElGamal ciphertexts are large and malleable; production systems use hybrid authenticated encryption.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-elgamal-plain](https://systemslibrarian.github.io/crypto-lab-elgamal-plain/)**

The demo opens with a guided encrypt/decrypt walkthrough showing live values, plots the discrete-log hardness as a `g^x mod p` scatter, and demonstrates multiplicative homomorphism and ciphertext re-randomization. A Security Lab lets you trigger the failure modes yourself — discrete-log key recovery on the toy group, ephemeral-key reuse, ciphertext malleability, and signature nonce reuse — and an authenticated ElGamal exhibit shows the fix. You can switch between the toy group (`p = 2039`) and RFC 3526 Group 14.

## What Can Go Wrong

- Plain ElGamal is malleable. An attacker can transform ciphertexts algebraically into related plaintexts. (Exhibit 6)
- Reusing ephemeral `k` is catastrophic: it leaks a message in encryption (Exhibit 5) and the entire private key in signatures (Exhibit 9).
- Weak message encodings can leak structure (`m=0`, `m=1`, or low-entropy domains).
- The toy group is intentionally insecure and brute-force breakable. (Exhibit 4)
- Post-quantum note: ElGamal over finite fields is broken by Shor's algorithm on a large quantum computer.

## Real-World Usage

Taher ElGamal's 1985 paper, _A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms_, introduced a practical DLP-based public-key design that strongly influenced modern cryptography.

- DSA standardized ElGamal's signature lineage
- Threshold ElGamal is used in distributed decryption and voting pipelines
- Exponential ElGamal appears in privacy-preserving vote tally systems
- Cramer-Shoup can be seen as a hardened ElGamal-family construction
- RFC 3526 Group 14 is widely deployed in historical DH deployments (IPsec, SSH, TLS 1.2 finite-field DH)

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-elgamal-plain
cd crypto-lab-elgamal-plain
npm install
npm run dev
```

## Related Demos

- [crypto-lab-rsa-forge](https://systemslibrarian.github.io/crypto-lab-rsa-forge/) — the other classic public-key family, contrasted with ElGamal in the demo.
- [crypto-lab-paillier-gate](https://systemslibrarian.github.io/crypto-lab-paillier-gate/) — additively homomorphic encryption for private voting and aggregation.
- [crypto-lab-threshold-decrypt](https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/) — t-of-n threshold ElGamal decryption with NIZK proofs.
- [crypto-lab-key-exchange](https://systemslibrarian.github.io/crypto-lab-key-exchange/) — Diffie-Hellman, the discrete-log key agreement ElGamal is built on.

## Development & Tests

```bash
npm install
npm run dev     # local dev server
npm run build   # type-check (tsc) + production build
npm test        # Vitest suite (run once)
npm run test:watch
```

A committed Vitest suite proves the correctness of every primitive and every attack, so the
educational claims are permanent and regression-checked, not ad hoc:

- `modular.test.ts` — modexp, extended GCD, modular inverse, rejection-sampled randomness, primality
- `elgamal.test.ts` — encrypt/decrypt round-trips, non-determinism, homomorphism, re-randomization, text codec
- `attacks.test.ts` — baby-step/giant-step key recovery, and the feasibility guard refusing the 2048-bit group
- `authenticated.test.ts` — authenticated round-trip plus rejection of malleability and forged tags
- `signatures.test.ts` — sign/verify, forgery rejection, the congruence solver, and full key recovery from a reused nonce

CI runs the suite on every pull request (`.github/workflows/ci.yml`) and gates the GitHub Pages
deploy on a green run (`.github/workflows/deploy.yml`).

## Security Lab

The app does not just describe the failure modes — it lets you trigger them and watch the math:

- **Cracking the key (Exhibit 4):** recovers a toy private key from its public key with a
  baby-step/giant-step discrete-log solver (`src/attacks.ts`). The same routine is hard-guarded
  against the 2048-bit group, encoding the security argument as code.
- **Ephemeral-key reuse (Exhibit 5):** encrypts two messages under one reused `k`; the shared `c1`
  lets an attacker who knows one plaintext recover the other with a single modular division — no
  private key involved.
- **Ciphertext malleability (Exhibit 6):** an attacker multiplies `c2` by a factor `t` with no key
  and no knowledge of the plaintext, and the owner's decryption silently becomes `m·t`, showing why
  plain ElGamal is not CCA-secure.
- **Authenticated ElGamal — the fix (Exhibit 7):** a DHIES/ECIES-style construction
  (`src/authenticated.ts`) derives an HMAC-SHA-256 key from the Diffie-Hellman shared secret and tags
  the ciphertext. The exact Exhibit 6 attack is now detected and decryption is refused — at the cost of
  the homomorphism, the tradeoff that pushes voting systems toward Cramer-Shoup or zero-knowledge proofs.
- **Signature nonce reuse — total key recovery (Exhibit 9):** signing two messages with the same `k`
  (`src/signatures.ts`) makes the signatures share `r`; solving the resulting linear congruences recovers
  the signer's entire private key. This is the real Sony PS3 ECDSA break, and a far worse outcome than the
  single-message leak from encryption-side reuse (Exhibit 5).

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
