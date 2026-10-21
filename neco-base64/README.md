# neco-base64

[日本語](README-ja.md)

neco-base64 is a crate that encodes and decodes Base64.

It supports the standard alphabet defined by RFC 4648 and the URL-safe
alphabet, which uses `-` and `_` for characters 62 and 63.

The implementation uses only `core` and `alloc`.

## Usage

```rust
use neco_base64::{decode, decode_url, encode, encode_url, Base64Error};

fn examples() -> Result<(), Base64Error> {
    let encoded = encode(b"hello")?; // "aGVsbG8="
    let decoded = decode(&encoded)?; // b"hello"

    let url_encoded = encode_url(b"hello")?; // "aGVsbG8"
    let url_decoded = decode_url(&url_encoded)?; // b"hello"
    Ok(())
}
```

Every function reports failures as `Base64Error`. Encoding and decoding first
compute the exact output length and allocate exactly that length. An output
length beyond the addressable range and an allocation failure each return a
distinct variant.

## API

### Encoding

| Function | Returns |
|----------|---------|
| `encode(input: &[u8])` | padded standard Base64 |
| `encode_url(input: &[u8])` | unpadded URL-safe Base64 |
| `encode_url_padded(input: &[u8])` | padded URL-safe Base64 |

Each function returns `Result<String, Base64Error>`.

### Decoding

| Function | Accepts |
|----------|---------|
| `decode(input: &str)` | standard Base64 |
| `decode_url(input: &str)` | URL-safe Base64 |
| `decode_url_strict(input: &str)` | unpadded URL-safe Base64 with zero remainder bits |

Each function returns `Result<Vec<u8>, Base64Error>`.

- `decode`, `decode_url`: trailing padding in the input is optional; the low-order bits of the final character left over after the output bytes (the remainder bits) are ignored
- `decode_url_strict`: rejects input containing `=`, and checks that the remainder bits of the final character are 0

The remainder-bit check (pad bits in RFC 4648) follows section 3.5.
Section 3.5 requires encoders to set the remainder bits to zero and allows decoders
to reject input whose remainder bits are nonzero.

Rejecting `=` is a choice of this crate to accept the unpadded form alone.
Section 5 of RFC 4648 allows the padding of URL-safe Base64 to be
skipped when the data length is known implicitly.

## Error type

```rust
pub enum Base64Error {
    InvalidCharacter,
    InvalidLength,
    NonZeroPaddingBits,
    CapacityOverflow { input_len: usize },
    AllocationFailed { required: usize },
}
```

| Variant | Meaning |
|---------|---------|
| `InvalidCharacter` | the input contains a character absent from the alphabet, or `=` at a position the function rejects |
| `InvalidLength` | the length excluding padding leaves a remainder of 1 when divided by 4 |
| `NonZeroPaddingBits` | in `decode_url_strict`, the remainder bits of the final character contain a nonzero bit |
| `CapacityOverflow` | the output length exceeds the addressable range; `input_len` is the input length, excluding padding when decoding |
| `AllocationFailed` | allocating the output buffer failed; `required` is the requested byte count |

## Features

| Feature | Enables |
|---------|---------|
| `std` (default) | linkage against the standard library, and `alloc` |
| `alloc` | the encoding and decoding functions |

Because `Base64Error` is defined on `core` alone, it is available with any
combination of features.

Removing the standard library linkage builds the crate in a `no_std`
configuration for embedded targets.

## License

MIT
