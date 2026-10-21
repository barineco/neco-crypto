# neco-sha1

[日本語](README-ja.md)

neco-sha1 is a crate that implements the SHA-1 hash function in compliance
with RFC 3174.

This crate serves interoperability with existing protocols that require SHA-1.
SHA-1 has known weaknesses in collision resistance.

For new applications that need collision resistance, a modern hash function
such as SHA-256 from [neco-sha2](https://docs.rs/neco-sha2) is the better fit.

## Usage

```rust
use neco_sha1::{Sha1, Sha1Error};

fn hash_examples() -> Result<(), Sha1Error> {
    // Compute in one call
    let hash = Sha1::digest(b"hello")?;

    // Feed split input in order
    let mut h = Sha1::new();
    h.update(b"hel")?;
    h.update(b"lo")?;
    assert_eq!(h.finalize(), hash);
    Ok(())
}
```

`update` can be called any number of times with chunks of any length.
`finalize` consumes the state and returns the 20-byte hash.

Because RFC 3174 limits messages to fewer than 2^64 bits, the accepted input
is capped at 2^61 - 1 bytes, the value of the constant `MAX_MESSAGE_BYTES`.

The condition for returning `Sha1Error::MessageTooLong` on input beyond this
limit differs by function.

- `update`: when the accumulated input exceeds the limit; after it returns the failure, the state stays as it was before the call
- `digest`: when the input passed in one call exceeds the limit

## Features

| Feature | Enables |
|---------|---------|
| `std` (default) | linkage against the standard library |

The hash computation uses only `core` and fixed-size buffers. Disabling the
default feature therefore builds the crate in a `no_std` configuration for
embedded and bare-metal targets.

## License

MIT
