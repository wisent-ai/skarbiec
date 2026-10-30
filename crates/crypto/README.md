# skarbiec-crypto

The cryptography Skarbiec runs, written here and depending on nothing but the
Rust standard library. No other crate, no `gpg`, no `gpg-agent`, no
`keyboxd`, no `openssl`, no process of any kind.

## Why nothing else

Every dependency is code that runs with the vault's secrets in reach and that
someone else can change. A crate's next release, a maintainer account taken
over, a build script, a transitive dependency nobody reviewed: each is a way
into every vault that updates. Libraries are now also being changed by
automated agents faster than anyone reads the changes. The surest way for a
vault not to inherit that is not to depend on it. Everything below is a
published standard with published test vectors, so it can be written once,
checked against those vectors, and then changes only when this repository
changes it.

The external programs went for a second reason: a vault that decrypted by
running `gpg` depended on `gpg-agent` and `keyboxd` answering. When they did
not, every read waited, the vault held hundreds of connections and children,
and nothing could be read for two weeks. A function call cannot leave a
daemon behind.

## What is here

| Primitive | Standard | Checked against |
| --- | --- | --- |
| SHA-1, SHA-256, SHA-512 | FIPS 180-4 | NIST CAVP byte-oriented short, long and Monte Carlo vectors |
| AES-128, AES-192, AES-256 | FIPS 197 | NIST CAVP ECB KAT and MMT vectors |
| AES-CFB (OpenPGP) | SP 800-38A / RFC 4880 13.9 | NIST CAVP CFB128 KAT and MMT vectors |
| AES key wrap | RFC 3394 | RFC 3394 section 4 |
| OCB | RFC 7253 | RFC 7253 Appendix A |
| HMAC-SHA256, HKDF-SHA256 | RFC 2104, RFC 5869 | RFC 4231, RFC 5869 Appendix A |
| ChaCha20, Poly1305, ChaCha20-Poly1305 | RFC 8439 | RFC 8439 section 2 and Appendix A |
| X25519 | RFC 7748 | RFC 7748 section 5.2 and 6.1 |
| Ed25519 | RFC 8032 | RFC 8032 section 7.1 |
| inflate (zlib, deflate) | RFC 1950, RFC 1951 | streams written by zlib, decoded and compared |
| radix-64, CRC-24 | RFC 4880 6 | RFC 4880 armor of known keys |
| OpenPGP: v3 PKESK (ECDH over Curve25519), SEIPD v1 with MDC, AEAD packet (OCB), compressed and literal data, v4 keys, S2K | RFC 4880, RFC 6637, RFC 9580 | messages and keys written by GnuPG |

The OpenPGP part is exactly what Skarbiec vaults were written in, and no
more: keys are Ed25519 with a Curve25519 encryption subkey, items are
encrypted to that subkey with ECDH (SHA-256, AES-128 key wrap), and the data
is AES-256 in OCB (the AEAD packet) or CFB with an MDC (older items), ZLIB
compressed. A message in any other algorithm is refused naming the algorithm.
It only reads OpenPGP; new items are written in Skarbiec's own format
(`sealed`), below.

## The sealed format

One item, encrypted to one or more recipients:

```
"skarbiec-sealed-1" NUL
count (u8)
per recipient: key id (8 bytes, the first 8 of SHA-256 over the recipient's X25519 public key)
               ephemeral X25519 public key (32)
               wrapped content key (32 + 16 tag)
nonce (12)
ciphertext + tag (ChaCha20-Poly1305)
```

The content key is 32 random bytes. For each recipient a fresh ephemeral
X25519 key agrees a shared secret with the recipient's key; HKDF-SHA256
(salt: ephemeral public || recipient public, info: `skarbiec-sealed-1 wrap`)
turns it into a wrapping key, and ChaCha20-Poly1305 with an all-zero nonce
(each wrapping key is used once) seals the content key. The content is
sealed with the content key and a random nonce, the header before the nonce
as associated data, so a recipient list cannot be changed without the
content failing to open.

Random bytes come from the operating system (`getentropy` on macOS, the
`getrandom` system call on Linux) through the standard library's file and
`libc`-free system interfaces only: `/dev/urandom` read whole.

## Threat model

It protects:

- an item at rest, in the vault file, in a backup, in a Git mirror and in
  transit to a replica: without a recipient's secret key nothing in it can
  be read, and a changed byte anywhere fails to open rather than opening to
  something else;
- against a supply-chain change in a dependency: there is none.

It does not protect against:

- someone who can read the owner's secret key file or the macOS Keychain
  item it is kept in, or run code as the account the vault runs as;
- someone who can read the process's memory while it runs: secrets are
  zeroed when dropped, but a running vault holds them while it uses them;
- side channels beyond timing: the code takes no branch and makes no table
  lookup on secret data (AES is computed as a bitsliced circuit, field
  arithmetic in constant time), but power, electromagnetic and cache-sharing
  attacks on the host are out of scope;
- a weak operating-system random source;
- a reader who obtained ciphertext and, later, a secret key: there is no
  forward secrecy for stored items, by design, since the owner must be able
  to read them later.

## Tests

`cargo test -p skarbiec-crypto` runs every vector above from the files under
`tests/vectors/`, taken verbatim from the documents named. A vector that
does not match fails the build.
