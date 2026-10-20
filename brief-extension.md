# Extension brief — `crypto-lab-elgamal-plain`

**2026-10-20. Extension to a live lab; no new repository.** Written against
`crypto-lab-elgamal-plain` at `207b757ca04d` and `audits/_MASTER-TEMPLATE.md` (catalog
`f48d9d2f2f06`). Template §5: "Extend, never restructure." Source of the gap: Katz–Lindell,
*Introduction to Modern Cryptography*, 3rd ed. (CRC Press, 2021), §9.3.3 "Working in (Subgroups
of) Z*p" and Exercise 15.16 ("Prove that the DDH problem is not hard" when `g` generates `Z*p`;
hint: quadratic residuosity is decidable mod a prime).

**Verdict: extension — one new attack card, placed after Exhibit 6, unnumbered like the
Cramer–Shoup card.**

## What the lab has now (read at `207b757ca04d`)

- Encryption groups (`src/groups.ts`): `TOY_GROUP` `p = 2039, q = 1019, g = 2` and RFC 3526
  Group 14 via `initializeGroup14()`; both safe primes with `p ≡ 7 (mod 8)`, so `g = 2`
  generates the order-`q` subgroup of quadratic residues. `assertGroupElement` (:80–125)
  refuses `c1`/public keys outside that subgroup.
- Signatures (`src/signatures.ts:1–37`) deliberately use the **full** group: `TOY_SIGN_GROUP`
  `p = 2039, g = 7` (a primitive root, order asserted at module load).
- `src/elgamal.ts`: `encrypt`/`decrypt`/`encryptWithEphemeral` accept **any** message
  `m ∈ [1, p−1]` (`assertMessageInGroup`, :16–20) — they check range, not subgroup membership.
  `textToMessage` (:92) length-prefixes bytes into an integer in that range.
- Exhibit numbers come from a CSS counter (`src/style.css:113–124`); the Cramer–Shoup card opts
  out with `.card.cs-card { counter-increment: none; }` (:441) and a `CS` badge. The README cites
  exhibits by number ("Exhibit 4", "Exhibit 9", `README.md:112–138`).
- Tests: Vitest beside each module (`src/*.test.ts`); `e2e/claims.spec.ts` (e.g. :254
  "text mode encodes UTF-8 to a group element…"); `e2e/a11y.spec.ts`. No `e2e/gate.ts`,
  no verdict markers, no mutation script.

## A finding that changes the original recommendation

The gap analysis proposed a deliberately broken "full group" mode, with the prime-order subgroup
as the fix. Reading `elgamal.ts` shows the subgroup is **necessary but not sufficient here**: in
the lab's own default encryption, `c1 = g^k` and `y^k` are both quadratic residues, so
`Legendre(c2) = Legendre(m)` exactly. A message that is not itself in the subgroup leaks its
quadratic character straight through `c2`, and an IND-CPA adversary that submits one residue
and one non-residue wins every time **against the lab's current Exhibit 1 encryption**, with
every check the lab runs passing. K-L's ElGamal (Construction 12.16) takes `m ∈ G`; this lab encodes `m` into
`Z*p`, not into `G`. The card below therefore shows three settings, and only the third is safe.

## What to add — card "Attack: The Bit ElGamal Leaks" (badge `QR`)

Placed directly after Exhibit 6 (Ciphertext Malleability), with `counter-increment: none` and a
`QR` badge, so no existing exhibit number moves and the README's exhibit references stay true.

1. **The tool: Euler's criterion.** `m^((p−1)/2) mod p` is `1` for a residue, `p−1` for a
   non-residue. Let the learner test a few numbers by hand.
2. **Setting A — full group (deliberately broken, never the default).** Encrypt with a primitive
   root: reuse `TOY_SIGN_GROUP.g = 7` for the toy prime; for Group 14 derive `g = p − 2` (a
   non-residue whose order is `2q = p − 1` because `p ≡ 7 (mod 8)`) and assert its order at
   module load as `signatures.ts` does. Exponents drawn from `[1, p − 2]`. The distinguisher:
   `Legendre(y^k) = −1` iff `Legendre(y) = −1` and `Legendre(c1) = −1`; then
   `Legendre(m) = Legendre(c2) · Legendre(y^k)`. Run the IND-CPA game with `m0` a residue and
   `m1` a non-residue for `T` trials (default 200): wins `T/T`.
3. **Setting B — this lab's own subgroup encryption, raw integer message.** Call the existing,
   unmodified `encrypt()` from `src/elgamal.ts`. The distinguisher simplifies to
   `Legendre(c2) = Legendre(m)`. Wins `T/T` again — and `assertGroupElement` passes on every
   ciphertext, decryption round-trips, encryption is non-deterministic.
4. **Setting C — subgroup plus a subgroup encoding.** Encode `m ∈ [1, q]` as `m` if it is a
   residue and `p − m` otherwise (exactly one of them is, because `p ≡ 3 mod 4`); decode as
   `x ≤ q ? x : p − x`. Now `Legendre(c2) = 1` always and the same distinguisher wins about half
   the time. The page says what that measurement does and does not show: this adversary fails;
   the security claim comes from the DDH reduction, not from the measurement (link Hidden Bit).

**Headline mechanism:** one Legendre symbol computed from public values tells you a bit of the
plaintext. **Break-it-yourself:** the learner picks the two challenge messages and watches the
win rate, then switches settings.

## Why it belongs here and not in a new lab

ElGamal Plain already owns both groups the attack needs — the subgroup for encryption and the
full group for signatures — and already explains why `c1` must be in the subgroup. The missing
piece is that the *message* must be too. A new lab would duplicate both groups and the
encryption code.

## SECURITY / CORRECTNESS INVARIANTS

1. `src/elgamal.ts`, `src/groups.ts` and every existing exhibit are unchanged. Setting B calls
   the existing `encrypt()`; it does not copy it.
2. Setting A lives in its own module, is visibly marked broken, is never the arrival state, and
   cannot be selected from any other exhibit.
3. The distinguisher receives only public values `(p, g, y, c1, c2, m0, m1)`; its signature has
   no private-key parameter.
4. Every win/loss is computed by comparing the distinguisher's guess with the hidden bit drawn
   by the challenger in the same run; the tally renders from those comparisons.
5. Setting C's encode/decode round-trips for every `m ∈ [1, q]` on the toy group (exhaustive)
   and is the only encoding used inside this card.

## ARCHITECTURE

- `src/residuosity.ts` — `legendre(a, p)` via Euler's criterion (reuse `modPow` from
  `src/modular.ts`), `encodeToSubgroup`, `decodeFromSubgroup`.
- `src/fullGroupBroken.ts` — the Setting A key generation and encryption (full-group generator,
  exponents mod `p − 1`), named so nobody imports it by mistake.
- `src/qrGame.ts` — `runIndCpaGame(setting, m0, m1, trials)` and `legendreDistinguisher(...)`.
- UI in `src/main.ts` beside the other attack cards; card class `card attack qr-card`, CSS
  `.card.qr-card { counter-increment: none; }` and a `.qr-badge::before { content: 'QR'; }`.
- `// [extension] point` in `qrGame.ts`: a Hidden Bit scheme (`elgamal-zp`) could reuse the game
  with that lab's `estimateAdvantage` and confidence intervals.

## UI

Toy / Group 14 selector (Group 14 runs fewer trials by default, timed). Message pickers for
`m0`, `m1` with their Legendre symbols shown. Three setting buttons (A, B, C), a trial count,
Run. Per run: the first three trials expanded (`c1`, `c2`, the Legendre values, guess, truth),
then the tally `wins / trials`. Stacks below 640 px.

## VISUAL SEMANTICS

Settings A and B with a 100% win rate are **ALARM** — the encryption leaked a bit — even though
decryption and the subgroup checks all show success. Setting C at about 50% is shown as "this
distinguisher learns nothing", never as "secure". Icon + text + colour.

## EDGE CASES

- `m0` and `m1` with the same Legendre symbol → the distinguisher cannot separate them; run it
  anyway and let the ~50% result teach that, with a tooltip.
- Setting C with `m > q` → refused: "outside the encodable range [1, q]".
- `m = 0` or `m ≥ p` → the existing range refusal.
- Trial count outside the allowed range → refused with the range.

## Tests

- **Vitest:** `legendre` agrees with brute-force squaring for every `a` mod 2039; Group 14's
  `p − 2` has order `p − 1`; encode/decode round-trip exhaustively on the toy group;
  `Legendre(c2) = Legendre(m)` for 1,000 encryptions with the **unmodified** `encrypt()`;
  distinguisher wins 100% in A and B over 200 seeded trials; in C it wins within a binomial
  bound of 50%.
- **`e2e/claims.spec.ts` additions:** for the expanded trials, parse `p, y, c1, c2, m0, m1` and
  recompute the Legendre symbols in the test with its own `modPow` (not imported), asserting
  the page's guesses; recompute the tally from the expanded rows where the page shows all rows
  (small `T`); retirement when the setting changes; no-op guard.
- **§4.1c mutations (five-step checklist, recorded in the PR):** (M1) the distinguisher drops
  the `Legendre(y^k)` correction in Setting A → A's win-rate test fails; (M2) `decodeFromSubgroup`
  returns `x` unconditionally → round-trip test fails; (M3) Setting B quietly calls the encoded
  path → B's 100% claim fails; (M4) tally counts guesses instead of correct guesses → tally
  re-derivation fails.
- **§4.1d negative claim:** *"Fresh randomness and a prime-order subgroup do not by themselves
  hide the message: in this lab's Exhibit 1 encryption, the quadratic character of `m` passes
  straight through to `c2`."* Fixture: Setting B — every ciphertext passes
  `assertGroupElement`, decrypts correctly and differs from the last one (all rendered green),
  and the distinguisher's tally reads `T/T`. Verdict shape: `VALID AND RANDOMISED — AND ONE BIT
  LEAKED`.

## README and card follow-up

- `Security Lab` (`README.md:112–138`): add a bullet "**The bit ElGamal leaks (after Exhibit 6)**".
- Exhibit 1's lesson text says "the same message never produces the same ciphertext twice" —
  true; add one sentence that non-determinism alone is not semantic security, linking the card.
- `e2e/claims.spec.ts:254`'s test title says "a group element": the encoded `m` is an element
  of `Z*p`, not of the subgroup. Rename the title only.
- **Maintainer decision, not made here:** whether Exhibit 1's default encoding should move to the
  subgroup encoding. It changes Exhibit 2's homomorphism readout (products decode up to sign)
  and pinned test values, so this brief leaves the default alone and discloses instead.
- Catalog handoff (do not edit `../crypto-lab`): chips may gain `Legendre Symbol` and
  `vs. DDH in Z*p`.

## Do not touch

Exhibits 1–11 and the Cramer–Shoup chapters, `assertGroupElement`, `TOY_SIGN_GROUP`, existing
claims tests (except the one title), theme, header.

## Non-goals (each gets a one-line in-page note)

Elliptic-curve groups (no Legendre leak in a prime-order curve group) · quadratic residuosity mod
a composite (that is Goldwasser–Micali, a separate lab in this batch) · small-subgroup attacks on
the private key (already covered by `assertGroupElement`'s note) · a formal advantage estimate
with intervals (Hidden Bit).

## Links

crypto-lab-hidden-bit (at `734bd6ee7329`): `src/reduction/ddh.ts` runs the ElGamal-from-DDH
reduction over ristretto255 (a prime-order group where this leak cannot occur), and
`src/game/advantage.ts` holds the advantage estimator. This card is the negative half of that
story: in a group where DDH is easy, the reduction gives nothing and the attack is real.

## Sources

- Katz & Lindell, *Introduction to Modern Cryptography*, 3rd ed., CRC Press 2021,
  ISBN 9780815354369 — §9.3.3 (DDH "not hard" in groups like `Z*p`; work in a prime-order
  subgroup), Construction 12.16 (`m ∈ G`), Exercise 15.16, and §15.4.1 (quadratic residues
  modulo a prime) — checked against
  the book text.
- D. Boneh, "The Decision Diffie-Hellman Problem", Proceedings of the Third Algorithmic Number
  Theory Symposium (ANTS-III), LNCS 1423, pp. 48–63, Springer, 1998.
  https://crypto.stanford.edu/~dabo/pubs/abstracts/DDH.html
- RFC 3526 (Group 14 prime), already cited by the lab.
