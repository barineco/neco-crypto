# neco-argon2

[日本語](README-ja.md)

neco-argon2 provides password hashing and key derivation with Argon2id. It uses Blake2b as its internal hash function.

- Argon2id: compliant with RFC 9106 (version 19)
- Blake2b: compliant with RFC 7693
- PHC string: a single string that joins the algorithm, version, parameters, salt, and hash with `$` (`$argon2id$v=19$m=...,t=...,p=...$...`)
- Failure type: invalid arguments, exceeding the addressable range, allocation failure, random-source failure, and Base64 failure in a PHC string are returned as separate variants of `Argon2Error`

## Features

| Feature | Enables |
|---------|---------|
| `std` (default) | Linking against the standard library, and `alloc` |
| `alloc` | The whole Argon2id API, which allocates working memory |
| `phc` (default) | Functions that handle PHC strings |
| `getrandom` (default) | A salt from the OS random source, used by `argon2id_hash_encoded` |

## Usage

```rust
use neco_argon2::{argon2id_hash_encoded, argon2id_verify, Argon2Error, Argon2Params};

fn run() -> Result<(), Argon2Error> {
    let password = b"hunter2";
    let params = Argon2Params::default(); // m=19456, t=2, p=1

    let encoded = argon2id_hash_encoded(password, params)?;
    // => "$argon2id$v=19$m=19456,t=2,p=1$<salt_b64>$<hash_b64>"

    assert!(argon2id_verify(&encoded, password)?);
    assert!(!argon2id_verify(&encoded, b"wrong")?);
    Ok(())
}
```

- `argon2id_hash_encoded`: draws a 16-byte salt from the OS random source and returns a PHC string
- `argon2id_verify`: returns `Ok(false)` when the password differs

### Low-level API

`argon2id_hash_into` writes the derived bytes into a caller-supplied buffer.

```rust
use neco_argon2::{argon2id_hash_into, Argon2Error};

fn run() -> Result<(), Argon2Error> {
    let mut key = [0u8; 32];
    argon2id_hash_into(
        b"password",
        b"randomsalt12345!", // at least 8 bytes
        65536,               // m_cost (KiB)
        3,                   // t_cost (iterations)
        4,                   // p_cost (parallelism)
        &mut key,
    )?;
    Ok(())
}
```

`argon2id_hash` allocates the output buffer and returns the derived bytes as a `Vec`.

```rust
use neco_argon2::{argon2id_hash, Argon2Error};

fn run() -> Result<(), Argon2Error> {
    let hash = argon2id_hash(
        b"password",
        b"randomsalt12345!", // at least 8 bytes
        19456,               // m_cost (KiB)
        2,                   // t_cost (iterations)
        1,                   // p_cost (parallelism)
        32,                  // output length (bytes)
    )?;
    Ok(())
}
```

`argon2id_hash_with_secret` takes the costs and the output length as `Argon2Params`, and adds a secret and associated data to the input.

```rust
use neco_argon2::{argon2id_hash_with_secret, Argon2Error, Argon2Params};

fn run() -> Result<(), Argon2Error> {
    let params = Argon2Params { m_cost: 19456, t_cost: 2, p_cost: 1, output_len: 32 };
    let hash = argon2id_hash_with_secret(
        b"password",
        b"randomsalt12345!", // at least 8 bytes
        params,
        b"secret",
        b"associated data",
    )?;
    Ok(())
}
```

### PHC functions with a choice of salt source

Three functions return a PHC string, and each takes its salt from a different source.

| Function | Salt source |
|----------|-------------|
| `argon2id_hash_encoded_with_salt` | A 16-byte array supplied by the caller |
| `argon2id_hash_encoded_with_rng` | A closure supplied by the caller that writes the salt |
| `argon2id_hash_encoded` | The OS random source, read through `argon2id_hash_encoded_with_rng` |

The closure passed to `argon2id_hash_encoded_with_rng` receives the buffer to write the salt into and returns a `Result`.

```text
FnMut(&mut [u8]) -> Result<(), Argon2Error>
```

When the closure returns `Err`, the function returns that failure unchanged.

## Argument checks and failures

Each function checks its arguments before it allocates working memory.

| Argument | Violation | Result |
|----------|-----------|--------|
| `p_cost` | Below 1, or above 2^24 − 1 (RFC 9106 §3.1) | `InvalidParameter` |
| `t_cost` | Below 1 | `InvalidParameter` |
| `m_cost` | Below 8 times the parallelism | `InvalidParameter` |
| `m_cost` | The working-memory size in bytes exceeds the addressable range | `CapacityOverflow` |
| `output_len` | Below 4 bytes | `InvalidParameter` |
| `output_len` | Above 4,294,967,295 bytes and within the addressable range | `InvalidParameter` |
| `output_len` | Beyond the addressable range | `CapacityOverflow` |
| `salt` | Below 8 bytes | `InvalidParameter` |
| `salt` | Above 4,294,967,295 bytes | `InvalidParameter` |
| `password` | Above 4,294,967,295 bytes | `InvalidParameter` |
| `secret` | Above 4,294,967,295 bytes | `InvalidParameter` |
| `associated_data` | Above 4,294,967,295 bytes | `InvalidParameter` |

The value of `InvalidParameter` is the name of the violating argument.

A requested quantity that exceeds the addressable range and an allocator refusal return different variants. Both identify the kind of quantity being allocated through `AllocationOperation`.

| `AllocationOperation` | Quantity |
|------------------------|----------|
| `MemoryBlocks` | Number of working-memory blocks |
| `OutputBytes` | Number of bytes in the hash output |
| `PhcBytes` | Number of bytes in the PHC string |

| `Argon2Error` variant | Meaning |
|----------------------------|---------|
| `CapacityOverflow { operation, required }` | The requested quantity exceeds the addressable range |
| `AllocationFailed { operation, required }` | The global allocator refused the allocation |
| `RandomUnavailable` | The OS random source returned a failure |
| `Base64(Base64Error)` | During Base64 encoding or decoding of a PHC string, the output length exceeded the addressable range or the allocation failed |

The `Base64` variant is defined when `phc` is enabled.

`argon2id_hash_encoded` returns the same failures as the low-level API, plus the failures that occur while obtaining the salt and building the PHC string.

| Cause | Variant |
|-------|---------|
| The OS random source failed | `RandomUnavailable` |
| The length of the PHC string exceeds the addressable range | `CapacityOverflow` (`PhcBytes`) |
| The allocation for the PHC string failed | `AllocationFailed` (`PhcBytes`) |
| Base64 encoding of the salt and the hash failed | `Base64` |

`argon2id_verify` returns `Ok(false)` for a mismatched password, and also for a string that violates the PHC format or carries an invalid argument, including a salt shorter than 8 bytes.
In contrast, exceeding the addressable range and allocation failure, including those that occur while decoding Base64 in the PHC string, return as `Err`.

## Base64 in PHC strings

| Property | Value |
|----------|-------|
| Alphabet | Standard (`+` and `/`) |
| Padding | Omitted when encoding; optional and accepted when decoding |
| Functions used | The standard `encode` and `decode` from neco-base64 |
| URL-safe alphabet (`-`, `_`) | Treated as a string that violates the PHC format |

## Erasure

The working memory is a matrix of blocks allocated on the heap with `try_reserve_exact`. Once hashing finishes, on success and on failure alike, this matrix is erased.

Fixed-size intermediate values live on the stack inside `zeroize::Zeroizing` and are erased on drop.

- The initial hash and the header used to compute it
- The seed blocks for each lane and the inputs that derive them
- The final block and its bytes

The PHC functions also wrap the hash bytes in `Zeroizing`. They are erased after being encoded into the PHC string.

Like the intermediate values, the working memory is wrapped in `Zeroizing`, and its contents are erased when that value is dropped. The outcome of erasure therefore depends on how execution ends.

- An unwinding panic: the `Zeroizing` values are dropped during unwinding and erase their contents
- `panic = "abort"` or an abnormal process exit: execution ends before the drop code runs, and the contents remain

This crate borrows the password, salt, secret, and associated data as the caller's slices throughout the computation, and passes them directly to the hash function.

The output holds the actual hash result, so erasing it is the caller's responsibility.

- `argon2id_hash_into`: the buffer supplied by the caller
- `argon2id_hash`: the returned `Vec<u8>`
- `argon2id_hash_with_secret`: the returned `Vec<u8>`

## Defaults

| Parameter | Value in `Argon2Params::default()` |
|-----------|------------------------------------|
| `m_cost` (memory cost, KiB) | 19456 (19 MiB) |
| `t_cost` (iterations) | 2 |
| `p_cost` (parallelism) | 1 |
| `output_len` (output length, bytes) | 32 |

## Dependencies

| Crate | Role |
|-------|------|
| [`zeroize`](https://docs.rs/zeroize) | Erasure of the working memory and heap buffers |
| [`getrandom`](https://docs.rs/getrandom) | Salt generation for `argon2id_hash_encoded` |
| [`neco-base64`](https://docs.rs/neco-base64) | Encoding and decoding of PHC strings when `phc` is enabled |

## License

MIT
