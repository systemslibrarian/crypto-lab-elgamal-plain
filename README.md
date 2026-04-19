# crypto-lab-elgamal-plain

Browser-based ElGamal public-key encryption demo implementing Taher ElGamal's 1985 scheme over RFC 3526 Group 14 (2048-bit) and a toy 11-bit group for transparent arithmetic.

## What It Is

This project is an educational, no-backend lab for plain ElGamal encryption:

- Uses BigInt for all modular arithmetic
- Uses square-and-multiply modular exponentiation
- Uses `crypto.getRandomValues` for all randomness
- Demonstrates natural non-determinism (fresh ephemeral `k`)
- Demonstrates multiplicative homomorphism
- Demonstrates ciphertext re-randomization for mix-net style unlinkability
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

https://systemslibrarian.github.io/crypto-lab-elgamal-plain/

## What Can Go Wrong

- Plain ElGamal is malleable. An attacker can transform ciphertexts algebraically into related plaintexts.
- Reusing ephemeral `k` is catastrophic and can leak key material.
- Weak message encodings can leak structure (`m=0`, `m=1`, or low-entropy domains).
- The toy group is intentionally insecure and brute-force breakable.
- Post-quantum note: ElGamal over finite fields is broken by Shor's algorithm on a large quantum computer.

## Real-World Usage

Taher ElGamal's 1985 paper, _A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms_, introduced a practical DLP-based public-key design that strongly influenced modern cryptography.

- DSA standardized ElGamal's signature lineage
- Threshold ElGamal is used in distributed decryption and voting pipelines
- Exponential ElGamal appears in privacy-preserving vote tally systems
- Cramer-Shoup can be seen as a hardened ElGamal-family construction
- RFC 3526 Group 14 is widely deployed in historical DH deployments (IPsec, SSH, TLS 1.2 finite-field DH)
