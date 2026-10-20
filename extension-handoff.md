# ElGamal Plain — quadratic-character extension

Brief: `brief-extension.md`, copied from `extension-crypto-lab-elgamal-plain.md`.
Slug: `crypto-lab-elgamal-plain`.
Starting main: `207b757ca04d4d70c6937decac22b28cf9c34424`.
Pages: https://systemslibrarian.github.io/crypto-lab-elgamal-plain/

## Findings checked before implementation

The pinned implementation matches the stated raw-integer message leak. Two
qualifications matter: `assertGroupElement` validates public keys and c1, not c2;
fresh random choices can repeat, especially in the toy group. The card reports
those exact checks and observed repeats, and the old “never twice” sentence is
corrected rather than repeated. In Group 14, 7 is a quadratic residue; its default
opposite-character challenge therefore uses 11. The toy challenge uses 7.

The 320px scan found an existing eight-pixel page-grid overflow, also present
when the new card was removed. A minmax(0, 1fr) page track fixes the intrinsic
width without rebuilding the layout, header or panels.

## Delivered

An unnumbered QR card after Exhibit 6 preserves all existing exhibit numbers.
Setting C is the default. A is isolated in `fullGroupBroken.ts`; B calls the
original `encrypt()` at `src/qrGame.ts:39`; C encodes messages into quadratic
residues and decodes them after the existing decryption. Euler's criterion,
public-only guesses, true hidden-bit comparisons, round-trips, scoped validation,
observed repeats, timing and every trial are rendered. Input changes retire runs;
no-op selection preserves them; Group 14 has a lower limit and cancellation.

`src/elgamal.ts`, `src/groups.ts`, and `src/signatures.ts` are unchanged. Existing
claims are unchanged except the requested text-mode test title. README Security
Lab and the Exhibit 1 lesson disclose the semantic-security limitation.

## Verification

- Build passed; 135 unit tests passed; all 28 Chromium browser tests passed.
- Exhaustive Euler/squaring agreement on all 2039 residues, exhaustive encoding
  round-trips on all 1019 messages, 1000 encryptions through the original route,
  full-generator order checks, 200 seeded challenge-bit trials, and Group 14 checks.
- §4.1a: no setup-helper product copy; this lab has no gate.ts.
- §4.1b: existing claims file extended. Its own modular exponentiation derives
  every shown Legendre value and guess; it recounts the tally and repeated
  ciphertexts, validates c1/public keys, checks marker tones and retirement.
  A declared fixture controls only hidden-bit RNG calls; encryption remains real.
- §4.1c: 7/7 mutations killed, including all four requested faults, calm alarm
  styling, wrong limited-result marker, and removal of the negative claim.
  `scripts/check-qr-mutations.mjs` records source diffs, successful builds,
  changed artifact digests, named assertion failures with zero retries, exact
  restored digests and restored passing tests in `mutation-evidence.json`.
- §4.1d: Setting B shows valid c1/public keys, successful decryption, fresh
  ephemeral sampling and T/T public guesses together with the message-bit warning.
- Accessibility: all three settings and errors pass at 320px; existing desktop
  gate passes. The rendered narrow card was visually inspected.
- Local browser is installed Chromium 153.0.8010.0 via an ignored local config;
  pinned download endpoint was unavailable. Original CI/config remain unchanged.
- Primary sources checked: Boneh, DDH (1998), §1.1, at
  https://crypto.stanford.edu/~dabo/papers/DDH.pdf, and RFC 3526 §3.

## Catalog handoff — no shared catalog edits

Card copy suggestion: “Discover the message bit ElGamal leaks even with fresh
randomness and valid subgroup keys. Compare full-group, raw-message subgroup,
and explicitly encoded subgroup encryption.”
Chips: add `Legendre Symbol` and `vs. DDH in Z*p`.
Implemented call sites: Euler/Legendre at `src/residuosity.ts:2`, encoding at :7,
decoding at :13, public distinguisher at `src/qrGame.ts:8`, experiment at :18,
isolated full-group key/encrypt/decrypt at `src/fullGroupBroken.ts:9/:14/:19`.
Only prose: prime-order elliptic curves, Goldwasser–Micali, formal advantage
estimation and the DDH reduction (linked to Hidden Bit, not implemented here).
Concept deepened: **8. Discrete logarithm**.

Summary: 135 unit and 28 browser tests passed; §4.1c 7/7 killed; a11y gate passed.
Final remote SHA and served-byte proof are recorded after publication.
