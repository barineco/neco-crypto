# neco-p256

[日本語](README-ja.md)

neco-p256 is a crate that signs hashes and verifies signatures with ECDSA over
the elliptic curve P-256.

- Curve: P-256 (secp256r1), as defined by NIST
- Range of the signature component s: signing normalizes s to at most half the curve order (low-S), and verification rejects signatures whose s exceeds half the order (high-S)
- Public key format: SEC1 compressed form, 33 bytes made of a 1-byte prefix that indicates the parity of the y coordinate and the 32-byte x coordinate
- Written entirely in safe Rust (the subset of Rust whose memory safety the compiler checks)

The arithmetic used for signing is implemented across three crates.

- Prime field (Fp) arithmetic: `neco-galois`
- P-256 curve constants and curve-point arithmetic (addition, doubling, scalar multiplication, and conversion to and from SEC1 forms): this crate
- ECDSA nonce derivation with RFC 6979: `neco-sha2`

## Features

| Feature | Default | Enables |
|---------|---------|---------|
| `std` | enabled | linkage against the standard library (including the dependency crates), and `alloc` |
| `alloc` | enabled (via `std`) | conversion to and from hexadecimal strings (hex strings) |
| `getrandom` | enabled | key generation from the OS random source |

`SecretKey::generate_with_rng` generates a key from a closure supplied by the
caller that fills the given buffer with random bytes. On embedded targets that
lack an OS random source, keys can be generated with this method.

## Usage

This example signs a hash and verifies the signature.

```rust
use neco_p256::{EcdsaSignature, P256Error, SecretKey};

fn run() -> Result<(), P256Error> {
    let secret = SecretKey::generate()?;
    let public = secret.public_key()?;
    let hash: [u8; 32] = [0x42; 32]; // SHA-256 hash value

    let sig: EcdsaSignature = secret.sign_ecdsa_prehash(hash)?;
    public.verify_ecdsa_prehash(hash, &sig)?;
    Ok(())
}
```

Keys can also be converted to and from hex strings. This conversion requires `alloc`.

```rust
use neco_p256::{P256Error, SecretKey};

fn run() -> Result<(), P256Error> {
    let secret = SecretKey::generate()?;
    let hex = secret.to_hex()?;
    let restored = SecretKey::from_hex(&hex)?;
    assert_eq!(secret, restored);
    Ok(())
}
```

A public key can be converted to bytes in SEC1 compressed form and restored to
the original value from them.

```rust
use neco_p256::{P256Error, PublicKey, SecretKey};

fn run() -> Result<(), P256Error> {
    let secret = SecretKey::generate()?;
    let public = secret.public_key()?;
    let bytes: [u8; 33] = public.to_sec1_bytes();
    let restored = PublicKey::from_sec1_bytes(&bytes)?;
    assert_eq!(public, restored);
    Ok(())
}
```

This example generates a key from a closure supplied by the caller.

```rust
use neco_p256::{P256Error, SecretKey};

fn run() -> Result<(), P256Error> {
    let secret = SecretKey::generate_with_rng(&mut |bytes: &mut [u8]| {
        bytes.fill(0x7a); // a real closure writes unpredictable bytes
        Ok(())
    })?;
    let _ = secret;
    Ok(())
}
```

## API

Values of `SecretKey` and `PublicKey` are created only through constructors
that validate their input.

### `SecretKey`

| Method | Description |
|--------|-------------|
| `generate() -> Result<Self, P256Error>` | Generate a key from the OS random source |
| `generate_with_rng(rng: &mut F) -> Result<Self, P256Error>` | Generate a key from a closure supplied by the caller |
| `from_bytes(bytes: [u8; 32]) -> Result<Self, P256Error>` | Construct from a 32-byte array |
| `from_hex(hex: &str) -> Result<Self, P256Error>` | Construct from a 64-character hex string |
| `to_bytes() -> [u8; 32]` | Return the 32-byte array |
| `to_hex() -> Result<String, P256Error>` | Return a hex string |
| `public_key() -> Result<PublicKey, P256Error>` | Derive the corresponding public key |
| `sign_ecdsa_prehash(digest32: [u8; 32]) -> Result<EcdsaSignature, P256Error>` | Sign with an RFC 6979 nonce and normalize to low-S |

### `PublicKey`

| Method | Description |
|--------|-------------|
| `from_sec1_bytes(bytes: &[u8]) -> Result<Self, P256Error>` | Construct from SEC1 compressed form |
| `from_hex(hex: &str) -> Result<Self, P256Error>` | Construct from a 66-character hex string |
| `to_sec1_bytes() -> [u8; 33]` | Return the bytes in SEC1 compressed form |
| `to_hex() -> Result<String, P256Error>` | Return a hex string |
| `verify_ecdsa_prehash(digest32: [u8; 32], sig: &EcdsaSignature) -> Result<(), P256Error>` | Verify, rejecting high-S signatures |

### `EcdsaSignature`

A fixed-length 64-byte ECDSA signature that concatenates the 32-byte r and the
32-byte s (raw compact).

| Method | Description |
|--------|-------------|
| `from_bytes(bytes: [u8; 64]) -> Self` | Construct from a 64-byte array |
| `from_hex(hex: &str) -> Result<Self, P256Error>` | Construct from a 128-character hex string |
| `to_bytes() -> [u8; 64]` | Return the 64-byte array |
| `to_hex() -> Result<String, P256Error>` | Return a hex string |

### `P256Error`

| Variant | Description |
|---------|-------------|
| `Field(FieldError)` | A prime-field operation in `neco-galois` failed |
| `Nonce(Rfc6979Error)` | RFC 6979 nonce derivation by `neco-sha2` failed |
| `RandomUnavailable` | The OS random source returned a failure |
| `CapacityOverflow { input_len }` | The hex string length for `input_len` input bytes exceeds the addressable range |
| `AllocationFailed { required }` | Allocating `required` bytes failed during hex conversion |
| `InvalidSecretKey` | The secret key is out of range, or deriving its public key failed |
| `InvalidPublicKey` | The length, prefix, or x-coordinate range of the public key bytes is invalid, or the bytes cannot be restored to a point on the curve |
| `InvalidSignature` | Verification failed, or signing failed to produce a valid value |
| `InvalidHex(&'static str)` | The hex string has an invalid length or character |

## License

MIT
