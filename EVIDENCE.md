# EVIDENCE — Gate 0: in-browser PKCS#12 handling

Date: 2026-09-24 · Workdir: `/home/panther/Projects/certkit`

## Environment (actually used)

| Thing | Version / path |
|---|---|
| node-forge | **1.4.0** (vendored, 280 KB minified) |
| OpenSSL | 3.5.5 (fixture generation + ground truth) |
| Node | 24.18.0 |
| Browser | Chromium 1243 headless via playwright-core 1.63, page loaded from `file://` |

## Method

1. `scripts/make-fixtures.sh` generates PKCS#12 fixtures; `fixtures/openssl-inspect.txt` records
   what OpenSSL says is inside each one (ground truth algorithms).
2. `tests/node-smoke.mjs` runs the same `lib/certkit.js` in Node (fast channel).
3. `tests/browser-test.mjs` drives the real page in headless Chromium: file picker → password →
   Parse button, then reads the rendered UI + the in-page result, and round-trips the exported PEM
   back through forge in Node.
4. `tests/write-path.mjs` builds a PKCS#12 from PEM with forge, then OpenSSL reads it back.

Raw outputs: `tests/out/node-results.json`, `tests/out/browser-results.json`,
`tests/out/write-path-results.json`.

## Results — browser (headless Chromium, `file://`)

| Fixture | Inside (OpenSSL ground truth) | Parse | Key↔cert | Certs | Wall time | Notes |
|---|---|---|---|---|---|---|
| `modern-aes256.p12` (2.9 KB) | PBES2/PBKDF2/AES-256-CBC, SHA-256 MAC | ✅ | ✅ yes | 1 | ~95–100 ms | subject/issuer/SAN/serial/fingerprint rendered |
| `legacy-3des.p12` (2.7 KB) | pbeWithSHA1And3-KeyTripleDES-CBC | ✅ | ✅ yes | 1 | ~71–77 ms | |
| `legacy-rc2-40.p12` (2.7 KB) | certs: pbeWithSHA1And40BitRC2-CBC; key: 3DES | ✅ | ✅ yes | 1 | ~66–71 ms | forge reads RC2-40 (**OpenSSL 3 default provider cannot** — it needs `-legacy`) |
| `nopass.p12` (2.8 KB) | AES-256-CBC, empty password | ✅ | ✅ yes | 1 | ~82–87 ms | empty password handled |
| `nomac.p12` (2.8 KB) | AES-256-CBC, **no MAC** | ✅ | ✅ yes | 1 | ~72–73 ms | unauthenticated file still parsed |
| `chain-aes256.p12` (3.5 KB) | AES-256-CBC, leaf+intermediate chain | ✅ | ✅ yes | 2 | ~76–89 ms | export order preserved; leaf.issuer == inter.subject verified; PEM round-trip in Node: key matches cert |
| `modern-aes256-rsa4096.p12` (4.3 KB) | AES-256-CBC, RSA-4096 | ✅ | ✅ yes | 1 | 210–255 ms wall, **170–214 ms parse-only** (10 runs) | "typical 4 KB file" |
| `ec-p256-aes256.p12` | AES-256-CBC, EC P-256 key+cert | ❌ | n/a | 0 | ~27 ms | clear error: *"Certificate bag #1 could not be parsed… node-forge handles RSA certificates only"* |
| `modern-aes256.p12` + wrong password | — | ❌ | n/a | — | ~3–6 ms | *"PKCS#12 MAC could not be verified. Invalid password?"* |

- Console errors: **0**, page errors: **0**.
- Memory (Chromium `performance.memory`): usedJSHeap **17.4 MB before → 17.4 MB after** ten 4 KB parses
  (GC keeps up; no growth observed).
- Everything (crypto, rendering, PEM export) works offline from `file://`; forge is vendored.

## Key-match logic (verified both ways)

`lib/certkit.js` checks (a) RSA modulus + exponent equality and (b) a real SHA-256 sign→verify
round-trip with the private key against the certificate's public key. Negative control in
`node-smoke.mjs`: key from one fixture vs certificate from another → **no match**, as expected.
Positive cases: modulus equal + sign/verify true on every RSA fixture.

## Exports (verified, not just rendered)

- Private key PEM parses back with `forge.pki.privateKeyFromPem` (Node) → exact same key.
- Certificate PEM parses back; chain order retained; leaf issuer equals intermediate subject.
- Example lengths (2.9 KB modern file): key PEM 1702 chars, cert PEM 1468 chars, bundle 3171 chars.

## What fails / limitations (honest list)

1. **EC / Ed25519 keys and certificates are not supported.** An EC P-256 PKCS#12 fails with a clear
   error (cert bag is unparsable; the key bag decodes to a non-RSA object). node-forge 1.4 has some
   Ed25519 primitives, but the X.509/PKCS#12 path is RSA-only in practice; no EC fixture passes.
   A mixed RSA-key/EC-cert fixture could not even be generated — OpenSSL refuses to export a
   key/cert mismatch, so that specific combination is untested.
2. **Forge version matters a lot.** PBES2 (AES-CBC key/cert encryption, `pbe.js`) only works in
   forge **1.4.x**. The widely-known 1.3.1 would have failed on the AES-256 fixtures — the spike
   caught this; the vendored copy must stay pinned at 1.4.0.
3. Forge 1.4 API differences found and handled in code: `bag.cert` is returned pre-parsed
   (no `certificateFromAsn1` needed), `pki.certificateToDer` is gone (use
   `asn1.toDer(certificateToAsn1(...))`), `getBags()` takes one `bagType` per call (no arrays),
   `e` is a BigInteger (compare with `compareTo`, not `===`).
4. **Write path (`toPkcs12Asn1`) is real but weaker than OpenSSL:** AES-256-CBC key bag, **SHA-1
   MAC**, certificate bags in unencrypted SafeContents. OpenSSL reads it, extracted key modulus
   matches the cert (`tests/write-path.mjs`). Fine for v1; document the difference.
5. Legacy RC2-40 **key** encryption (not just cert) was not covered — the fixture uses RC2-40 for
   certs and 3DES for the key, which is what real-world legacy files usually do.
6. Password-protected files use the *same* password for key and cert bags (industry norm); separate
   passwords per bag are not tested.
7. Timing on a 4 KB RSA-4096 file is ~0.2 s — fine for an interactive tool; a 16 KB RSA-8192 +
   long chain would need a progress indicator, not a redesign. Untested here.

## Write path evidence (pem → pfx)

`tests/write-path.mjs` output: OpenSSL reads forge's output (`Shrouded Keybag: PBES2, PBKDF2,
AES-256-CBC`), extracts 2 certs, key modulus md5 == cert modulus md5 == original key md5
(`8306efe7…`), and forge re-reads its own file (1 key bag, 2 cert bags).

## Effort estimate — full toolkit v1 (static pages, RSA-first)

| Item | Estimate | Basis |
|---|---|---|
| PKCS#12 parse → PEM export (this spike) | **done** | working page + tests |
| PEM → PKCS#12 write UI (alg choice, warnings) | 0.5 d | write path already proven |
| Certificate + CSR decode views | 0.5 d | cert view done; CSR parse is the same forge API family |
| Chain order/build + signature verification | 0.5–1 d | `isIssuer`/`verify` exist; needs careful UX for broken chains |
| DER/hex + JWK inspection views | 0.5 d | pure formatting |
| UI shell (tabs, drag&drop, downloads, error states, a11y) | 1 d | |
| Cross-browser tests (Firefox/WebKit) + more fixtures | 0.5–1 d | Chromium green now |
| **Total remaining** | **≈ 3.5–4.5 focused days** | |
| Optional EC/Ed25519 support via openssl-wasm fallback | +2–4 d | bundle + init complexity, separate risk |

## Verdict

**GO for Gate 1.** Everything the Gate-1 toolkit needs for the RSA path is demonstrated working
in a real browser with zero server involvement: modern (AES-256) and legacy (RC2-40/3DES) files,
passwordless and MAC-less edge cases, chain handling, key↔cert verification, and valid PEM export.
The main scope decision to make early: **RSA-only v1 with a clear error for EC** (cheap, honest) vs
**openssl-wasm fallback for EC** (adds 2–4 days + bundle weight). Recommendation: ship RSA-first,
treat EC as v1.1.
