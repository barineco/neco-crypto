# neco crypto

[日本語](README-ja.md)

neco crypto is a set of Rust crates for cryptographic hashing, key derivation, elliptic-curve signing, and signing-key storage.

## Crates

| Crate | Description |
|---|---|
| [`neco-sha1`](neco-sha1) | The SHA-1 hash function |
| [`neco-sha2`](neco-sha2) | Hashing, message authentication codes, and key derivation with SHA-256, plus deterministic nonce derivation per RFC 6979 |
| [`neco-base64`](neco-base64) | Base64 encoding and decoding with the standard and URL-safe alphabets |
| [`neco-p256`](neco-p256) | ECDSA signing and verification on the P-256 elliptic curve |
| [`neco-secp`](neco-secp) | Signing on the secp256k1 elliptic curve, and Nostr event signing |
| [`neco-argon2`](neco-argon2) | Password hashing and key derivation with Argon2id |
| [`neco-vault`](neco-vault) | A vault for Nostr clients that holds signing keys in memory only |
| [`neco-nostr-wasm`](neco-nostr-wasm) | WebAssembly bindings that expose signing and vault-backed encryption to JavaScript |

Each crate's README describes its usage, features, and public API.

A feature is a name, chosen in Cargo settings, that enables a part of a crate's functionality or dependencies.

## Scope

This repository contains the implementations of curve constants, nonce derivation, hashing, and signing, along with the Nostr and WebAssembly applications built on them. For general-purpose building blocks, it uses two crates from other repositories.

- Finite-field arithmetic: `neco-galois` from [neco-algebra](https://github.com/barineco/neco-algebra)
- JSON grammar and string escaping: `neco-json` from [neco-parser](https://github.com/barineco/neco-parser)

## Security

- [Reporting procedure and limitations](SECURITY.md)

## License

[MIT](LICENSE)
