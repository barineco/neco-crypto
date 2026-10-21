# neco-sha2

[日本語](README-ja.md)

neco-sha2 is a crate that implements the SHA-256 hash function, along with
authentication, key derivation, and nonce derivation built on it.

- SHA-256: the hash function, compliant with RFC 6234 and FIPS 180-4
- HMAC-SHA256: a keyed message authentication code that uses SHA-256, compliant with RFC 2104
- HKDF-SHA256: a key derivation function that uses HMAC-SHA256, compliant with RFC 5869
- RFC 6979 deterministic nonce: derives the secret value used once per signature in schemes such as ECDSA (the nonce) from the secret key and the message hash, with byte arrays as inputs and outputs

The implementation uses only `core` and `alloc`, which are built into Rust.

## Usage

```rust
use neco_sha2::{Hkdf, Hmac, Sha256};

fn examples() -> Result<(), Box<dyn std::error::Error>> {
    // Compute SHA-256 in one call
    let hash = Sha256::digest(b"hello")?;

    // Feed split input to SHA-256 in order
    let mut h = Sha256::new();
    h.update(b"hel")?;
    h.update(b"lo")?;
    assert_eq!(h.finalize(), hash);

    // HMAC-SHA256
    let mut h = Hmac::new(b"key")?;
    h.update(b"message")?;
    let mac = h.finalize();

    // HKDF-SHA256
    let prk = Hkdf::extract(b"salt", b"input keying material")?;
    let okm = prk.expand(b"info", 32)?;
    Ok(())
}
```

The functions that take input in parts return different values for the hash
and for HMAC, so the calls are written differently as well.

```text
Sha256::update(&mut self, data: &[u8]) -> Result<(), Sha256Error>
Hmac::update(&mut self, data: &[u8]) -> Result<&mut Self, Sha256Error>
Hmac::finalize(self) -> [u8; 32]
```

- `Sha256::update`: returns `()` on success, so put each call in its own statement
- `Hmac::update`: returns a reference to itself on success, so calls can be chained with `?` in between
- `Hmac::finalize`: consumes the value, so call it in a statement separate from the chain

## Input length limit

Because RFC 6234 limits SHA-256 messages to fewer than 2^64 bits, the accepted
input is capped at 2^61 - 1 bytes, the value of the constant
`MAX_MESSAGE_BYTES`.

When the input exceeds the limit, `Sha256Error::MessageTooLong` is returned.
Which input length is compared with the limit depends on the function.

- `Sha256::update`: when the accumulated input exceeds the limit; after it returns the failure, the state stays as it was before the call
- `Sha256::digest`: when the input passed in one call exceeds the limit

The inner HMAC hash is computed over a 64-byte key block followed by the input.
Keys longer than 64 bytes are first hashed with SHA-256, and the hash is used
as the key. The key limit and the input limit are therefore different values.

- Key: the same as `MAX_MESSAGE_BYTES`
- Input: `MAX_MESSAGE_BYTES` minus 64, in total

The HMAC functions also return `Sha256Error::MessageTooLong` when the key or
the input exceeds its limit.

- `Hmac::new`: the key exceeds its limit
- `Hmac::update`: the accumulated input exceeds its limit
- `Hmac::mac`: the key or the input exceeds its limit

## HKDF output length and failures

The derived key material can either be written into a caller-provided buffer
or be returned in an allocated buffer.

- `Prk::expand_into`: writes using only the caller's buffer
- `Prk::expand`: returns the result in an allocated buffer; requires the `alloc` feature

```rust
use neco_sha2::{Hkdf, HkdfError};

fn derive() -> Result<(), HkdfError> {
    let prk = Hkdf::extract(b"salt", b"input keying material")?;

    let mut okm = [0u8; 32];
    prk.expand_into(b"info", &mut okm)?;

    let okm = prk.expand(b"info", 32)?;
    Ok(())
}
```

The HKDF functions report failures as `HkdfError`. RFC 5869 limits the output
length to 255 times the 32-byte hash length, that is, 8160 bytes.

- `HkdfError::OutputTooLong { requested, maximum }`: the requested length exceeds 8160 bytes
- `HkdfError::AllocationFailed { required }`: allocating the output buffer failed; `required` is the number of bytes it tried to allocate
- `HkdfError::Hash(Sha256Error)`: an HMAC key or input exceeds its limit. Extraction uses the salt as the key and the input keying material as the input. Expansion computes one HMAC per 32 bytes of output, each taking as input the concatenation of the previous output block, the info, and a 1-byte block number

## RFC 6979 deterministic nonce

`rfc6979::generate_k` derives a deterministic nonce for signatures such as
ECDSA. It targets elliptic curves whose order is 256 bits. The caller passes
the secret key, the message hash, and the curve order, each as a big-endian
32-byte array.

- Order (`order`): a 256-bit value whose most significant bit is 1
- Secret key (`secret`): a value satisfying `0 < secret < order`
- Hash (`digest`): `generate_k` reduces it modulo the order internally (bits2octets); the caller passes the unreduced value

The return type is `Result<[u8; 32], Rfc6979Error>`.

- `Rfc6979Error::InvalidOrder`: the order is shorter than 256 bits
- `Rfc6979Error::InvalidSecretKey`: the secret key is 0, or greater than or equal to the order

The same secret key, hash, and order always yield the same nonce.

The following example sets the secret key to 1 and derives a nonce from the
SHA-256 hash of `b"sample"`.

```rust
use neco_sha2::{rfc6979::generate_k, Sha256};

fn nonce_for_sample(order: &[u8; 32]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut secret = [0u8; 32];
    secret[31] = 1;
    let hash = Sha256::digest(b"sample")?;
    Ok(generate_k(&secret, &hash, order)?)
}
```

## Features

| Feature | Enables |
|---------|---------|
| `std` (default) | linkage against the standard library, and `alloc` |
| `alloc` | `Prk::expand` |

The following types and functions run on `core` alone and are available with
any combination of features.

- `Sha256`
- `Hmac`
- `Hkdf::extract`
- `Prk::expand_into`
- `Prk::from_bytes`
- `Prk::as_bytes`
- `rfc6979::generate_k`

Removing the standard library linkage builds the crate in a `no_std`
configuration for embedded and bare-metal targets.

## License

MIT
