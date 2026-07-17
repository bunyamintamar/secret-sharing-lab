# Secret Sharing — Shamir & Feldman VSS

Split a secret so that any **k** of **n** shares can reconstruct it, while fewer
than k reveal **nothing**. Two schemes, each available as a friendly console app
**and** a single self-contained HTML page — pure standard library, zero
dependencies, all computation local.

> **(k, n) threshold scheme:** any **k** shares reconstruct the secret exactly;
> **fewer than k** shares leak zero information — every possible secret stays
> equally likely. For basic Shamir this guarantee is information-theoretic
> (independent of computing power).

| Scheme | What it's for | Console | Browser |
|--------|---------------|---------|---------|
| **Shamir (GF(256))** | Fast backup/recovery of a password, key, or seed phrase | `python3 sss.py` | `shamir.html` |
| **Feldman VSS** | Same, **without trusting the dealer** — shares are verifiable, cheating is caught | `python3 vss.py` | `vss.html` |

## Live demo

The two browser tools run fully client-side, so they work as static pages on
GitHub Pages (or any static host). Once Pages is enabled for this repository:

- **Landing page:** `https://<user>.github.io/secret-sharing-lab/`
- **Shamir:** `.../shamir.html` · **VSS:** `.../vss.html`

Nothing is ever uploaded — the secret never leaves the browser tab. On HTTPS
(GitHub Pages) the "copy" buttons use the native clipboard API.

## Browser tools (no install)

Just open `index.html` (or `shamir.html` / `vss.html`) — double-click the file
or serve the folder statically. Everything runs in JavaScript:

- **Shamir** works byte-by-byte in the `GF(256)` field (addition = XOR,
  multiplication modulo the AES polynomial).
- **VSS** works in a 2048-bit prime field using `BigInt`, and publishes
  `g^coefficient` commitments so every share is verifiable.

Randomness is cryptographic (`crypto.getRandomValues`). The wire format matches
the console apps exactly, so a share made in the browser can be combined in the
CLI and vice versa (checksums match `zlib.crc32`).

## Console apps

```bash
python3 sss.py      # basic Shamir Secret Sharing
python3 vss.py      # verifiable secret sharing (Feldman)
```

Colors are automatic: colored in a real terminal, plain text when piped or
redirected (also disableable with `NO_COLOR=1`).

`sss.py` menu: split a secret · combine shares · explanation.
`vss.py` menu: split (with commitments) · **verify my share** · combine
(optionally verified — bad shares are dropped) · explanation.

### Share format

Each share is a single line, carrying its own metadata and a checksum:

```
SSS1-dba9-3-2-88cfe0cad01d356751...-b15f      (Shamir)
VSS1-2cf1-3-2-93687d934ffdf1...-34dc          (VSS share)
VCOM1-2cf1-3-<C0>.<C1>.<C2>-1815              (VSS commitments, public)
 │    │    │ │  │                   └ CRC-16 checksum (catches typos)
 │    │    │ │  └ payload
 │    │    │ └ share number (x)
 │    │    └ threshold (k)
 │    └ set id (same for all shares of one split; catches mix-ups)
 └ version tag
```

## How it works

The secret is the constant term of a random polynomial of degree `k-1`. Each
share is a point on that curve. Any `k` points determine the polynomial uniquely
(Lagrange interpolation → the constant term = the secret); `k-1` points fit
infinitely many curves, so they reveal nothing.

**Feldman VSS** adds verifiability. The dealer publishes commitments
`C_j = g^(a_j) mod p` (in a group where the discrete log is hard, so the secret
stays hidden). Anyone checks their share with `g^share == Π C_j^(x^j) mod p`. A
corrupted share or a cheating dealer is caught immediately — before combining.
Parameters are the RFC 3526 2048-bit MODP group (a verified safe prime).

## Project structure

```
index.html             Landing page (links the two browser tools)
shamir.html            Single-file, serverless browser UI (basic Shamir)
vss.html               Single-file, serverless browser UI (Feldman VSS)
sss.py                 Basic Shamir console app (GF(256))
vss.py                 Verifiable SS console app (Feldman VSS)
run_tests.py           Runs every test suite
shamir/
  gf256.py             GF(256) arithmetic (log/antilog tables)
  core.py              Basic SSS: split / combine (Lagrange)
  encoding.py          SSS share string encode/decode (set id + CRC)
  vss.py               Feldman VSS: split / verify_share / combine (Z_q)
  vss_encoding.py      VSS share + commitment string encode/decode
  ui.py                Colored console helpers
tests/
  test_core.py         Field axioms + split/combine round-trip
  test_encoding.py     SSS encoding round-trip + checksum + format
  test_vss.py          VSS round-trip + verification + cheating detection
  test_vss_encoding.py VSS share/commitment encoding round-trip
```

## Tests

```bash
python3 run_tests.py
```

## Security notes

- **Combining is the one weak moment:** when shares come together, the secret
  briefly exists whole in memory. For continuous-use scenarios (e.g. a crypto
  wallet) multisig is a better fit; these tools are ideal for secure
  **backup/recovery**.
- **Store shares in separate places.** If they all sit in one place the scheme
  is pointless.
- **If you lose more than n−k shares the secret is unrecoverable** — a deliberate
  trade-off.
- **If you don't trust the dealer**, use the VSS tools: corrupted or cheating
  shares are caught by verifying them against the commitments.
- This is an **educational** project. For production, prefer a reviewed, audited
  library (e.g. SLIP-0039 implementations).
