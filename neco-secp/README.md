# neco-secp

[日本語](README-ja.md)

neco-secp is a crate that implements secp256k1 keys and signatures, along with Nostr event signing, on a small set of dependencies.

The crate is written entirely in Rust and can be used to build Nostr clients and tools.

There are two signature schemes, and Nostr event signing and verification use Schnorr signatures.

- Schnorr signatures: signatures under BIP340 (the Bitcoin Schnorr signature specification)
- ECDSA (the Elliptic Curve Digital Signature Algorithm): signatures with a nonce derived by RFC 6979

Storage, browser integration, and key isolation policy are decisions left to the user of this crate.

There are three key types, and each keeps its bytes in private fields. Their values can therefore be created only through the validating constructors in the [Keys](#keys) tables below.

- `SecretKey`: a secret key
- `PublicKey`: a public key in compressed SEC1 form
- `XOnlyPublicKey`: a public key represented by the x coordinate alone (an x-only public key)

The compressed SEC1 form is one of the public key encodings defined by SEC 1, a standard for elliptic curve cryptography. It represents a public key in 33 bytes: a 1-byte prefix for the parity of the y coordinate, followed by the 32 bytes of the x coordinate.

## Features

| Feature | Default | Enables |
|---------|---------|---------|
| `std`     | on | the standard library (std) in this crate and its dependencies (includes `alloc`) |
| `alloc`   | on (via `std`) | APIs that return values allocated on the heap (strings and growable arrays), including key and hex string conversion and the event types |
| `getrandom` | on | key generation, signing, key search (mining), and encryption from the OS random source |
| `nostr`   | on | Nostr event construction, signing, verification, JSON writing and parsing, and NIP-42 authentication events |
| `nip19`   | off | encoding and decoding of strings from the Nostr NIP-19 specification (npub and others) |
| `nip04`   | off | encryption and decryption of event content under NIP-04 |
| `nip44`   | off | NIP-44 v2 conversation key derivation, and encryption and decryption of event content |
| `nip17`   | off | creating and decrypting NIP-17 direct messages (see [NIP-17](#nip-17-sealed-and-gift-wrapped-direct-messages)) |
| `batch`   | off | batch key generation and mining |
| `serde`   | off | Serde serialization and deserialization of the types listed below |

NIP-19 strings come in two forms. The bare form encodes the value alone in Bech32 (an alphanumeric encoding that detects errors). The TLV form encodes a sequence of type, length, and value entries. `nip19` supports seven prefixes, each with its own value and form.

- `npub`: a public key (bare form)
- `nsec`: a secret key (bare form)
- `note`: an event ID (bare form)
- `nprofile`: a public key and relays (TLV form)
- `nevent`: an event ID, relays, author, and kind (TLV form)
- `naddr`: an identifier, relays, author, and kind (TLV form)
- `nrelay`: a relay (TLV form)

With `serde` enabled, events and the types they are built from support Serde serialization and deserialization. Each type is represented either as a hex string or as a struct.

- `EventId`: a hex string
- `XOnlyPublicKey`: a hex string
- `SchnorrSignature`: a hex string
- `UnsignedEvent`: a struct keyed by field name
- `SignedEvent`: a struct keyed by field name
- `Rumor`: a struct keyed by field name

Signing, key generation, mining, and encryption can also fill bytes with randomness through a caller-supplied function in place of the OS random source. Such a function is a byte provider.

A function that takes a byte provider has the name of the function that uses the OS random source with `_with_rng` appended; for example, key generation uses `generate_with_rng`.

Each function is listed in the [API](#api) tables below.

## Nostr Event Shape

The three types that represent Nostr events follow the same shape rules.

- `UnsignedEvent`: an unsigned event
- `SignedEvent`: a signed event
- `Rumor`: an unsigned event that represents the message encrypted and sent in a NIP-17 direct message (see [NIP-17](#nip-17-sealed-and-gift-wrapped-direct-messages))

The rules are defined per field and are checked during JSON parsing, JSON writing, signing, and verification.

- `kind`: a u32 value for the event kind, with the accepted range `0..=65535`
- `tags`: zero or more entries in the outer array
- each inner array of `tags`: one or more strings
- `created_at`: a Unix timestamp of type `u64`

A failed check returns the `SecpError` variant (one of the kinds of value of an enum) that corresponds to the failed rule.

- `InvalidEventKind { kind }`: `kind` exceeds 65535
- `EmptyEventTag { index }`: the inner tag at position `index` is empty

Some NIP-19 TLV values also carry a kind. This kind takes any value in the full `u32` range, beyond the range above.

- `NAddr`: the kind has type `u32`
- `NEvent`: the kind is optional, with type `Option<u32>`

## Usage

### Signing and Verifying Events

```rust
use neco_secp::{nostr, SecretKey, SecpError, UnsignedEvent};

fn run() -> Result<(), SecpError> {
    let secret = SecretKey::generate()?;
    let event = UnsignedEvent {
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![],
        content: "hello".to_string(),
    };

    let signed = nostr::finalize_event(event, &secret)?;
    nostr::verify_event(&signed)
}
```

### Key Pairs

A key pair is a secret key together with its x-only public key. The type for a key pair is `KeyBundle`.

```rust
use neco_secp::{KeyBundle, SecpError};

fn run() -> Result<(), SecpError> {
    let bundle = KeyBundle::generate()?;
    let secret = bundle.secret();
    let xonly = bundle.xonly_public_key();
    let _ = (secret, xonly);
    Ok(())
}
```

To use a byte provider in place of the OS random source, generate the key pair with `KeyBundle::generate_with_rng`.

```rust
use neco_secp::{KeyBundle, SecpError};

fn run() -> Result<(), SecpError> {
    let bundle = KeyBundle::generate_with_rng(&mut |bytes: &mut [u8]| {
        bytes.fill(0x7a); // a real provider fills the buffer with unpredictable bytes
        Ok(())
    })?;
    let _ = bundle;
    Ok(())
}
```

With the `nip19` feature enabled, a key pair also yields its npub and nsec strings.

```rust
use neco_secp::{KeyBundle, SecpError};

fn run() -> Result<(), SecpError> {
    let bundle = KeyBundle::generate()?;
    let npub = bundle.npub()?;
    let nsec = bundle.nsec()?;
    let _ = (npub, nsec);
    Ok(())
}
```

### Mining

The `batch` feature enables batch generation of key pairs, and a search for a key whose x-only public key starts with a given number of zero nibbles (a nibble is 4 bits, one hex digit).

Below, this search is called PoW (Proof of Work) mining.

```rust
use neco_secp::{KeyBundle, SecpError, mine_pow};

fn run() -> Result<(), SecpError> {
    // batch generation of key pairs
    let bundles = KeyBundle::generate_batch(100)?;

    // PoW mining: find a key whose x-only public key starts with 4 zero nibbles
    let bundle = mine_pow(4, 1_000_000)?;
    let _ = (bundles, bundle);
    Ok(())
}
```

A search for a key whose npub starts with a chosen string requires both the `batch` and `nip19` features.

`mine_vanity_npub` matches the prefix argument against the data part after `npub1`. It accepts only characters from the Bech32 data-part character set:

```text
qpzry9x8gf2tvdw0s3jn54khce6mua7l
```

- A prefix with any other character, including uppercase letters, returns `SecpError::InvalidNip19`
- Using up all `max_attempts` attempts returns `SecpError::ExhaustedAttempts`

```rust
use neco_secp::{mine_vanity_npub, SecpError};

fn run() -> Result<(), SecpError> {
    // find a key whose npub starts with "npub1qq"
    let bundle = mine_vanity_npub("qq", 1_000_000)?;
    let _ = bundle;
    Ok(())
}
```

### NIP-19

With the `nip19` feature enabled, values such as secret keys and `NProfile` can be encoded into NIP-19 strings and decoded from those strings.

```rust
use neco_secp::{nip19, NProfile, SecretKey, SecpError};

fn run() -> Result<(), SecpError> {
    let secret = SecretKey::generate()?;
    let nsec = nip19::encode_nsec(&secret)?;
    let decoded = nip19::decode(&nsec)?;

    assert!(matches!(decoded, neco_secp::Nip19::Nsec(_)));

    let profile = NProfile {
        pubkey: secret.xonly_public_key()?,
        relays: vec!["wss://relay.example".to_string()],
    };
    let nprofile = nip19::encode_nprofile(&profile)?;
    let decoded = nip19::decode(&nprofile)?;

    assert!(matches!(decoded, neco_secp::Nip19::NProfile(_)));
    Ok(())
}
```

### NIP-44 and NIP-04

The `nip44` feature derives a conversation key shared by two parties from your own secret key and the peer's public key, and encrypts event content with that conversation key.

```rust
use neco_secp::{nip44, SecretKey, SecpError};

fn run() -> Result<(), SecpError> {
    let secret = SecretKey::from_bytes([0x11; 32])?;
    let peer = SecretKey::from_bytes([0x22; 32])?;
    let peer_pubkey = peer.xonly_public_key()?;
    let conversation_key = nip44::get_conversation_key(&secret, &peer_pubkey)?;
    let payload = nip44::encrypt("hello", &conversation_key, Some([0x33; 32]))?;
    let plaintext = nip44::decrypt(&payload, &conversation_key)?;

    assert_eq!(plaintext, "hello");
    Ok(())
}
```

NIP-04 encryption and decryption are available through the `nip04` feature.

```rust
use neco_secp::{nip04, SecretKey, SecpError};

fn run() -> Result<(), SecpError> {
    let secret = SecretKey::from_bytes([0x11; 32])?;
    let peer = SecretKey::from_bytes([0x22; 32])?;
    let peer_pubkey = peer.xonly_public_key()?;
    let payload = nip04::encrypt(&secret, &peer_pubkey, "hello", Some([0x44; 16]))?;
    let plaintext = nip04::decrypt(&peer, &secret.xonly_public_key()?, &payload)?;

    assert_eq!(plaintext, "hello");
    Ok(())
}
```

## JSON Serialization

With the `nostr` feature enabled, signed events and rumors can be written and parsed as JSON.

```rust
use neco_secp::{nostr, SecretKey, SecpError, UnsignedEvent};

fn run() -> Result<(), SecpError> {
    let secret = SecretKey::generate()?;
    let event = UnsignedEvent {
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![],
        content: "hello".to_string(),
    };
    let signed = nostr::finalize_event(event, &secret)?;

    let json = nostr::serialize_signed_event(&signed)?;
    let parsed = nostr::parse_signed_event(&json)?;
    assert_eq!(parsed, signed);
    Ok(())
}
```

Parsing checks the event shape described above. The duplicate check covers the seven keys known as event fields:

```
id, pubkey, created_at, kind, tags, content, sig
```

Unknown keys are accepted, duplicates included.

### `EventJsonError`

A parsing failure in the JSON structure returns an `EventJsonError` wrapped in `SecpError::Json`.

`ParseError` and `StringDecodeError` in the table are types defined by the neco-json dependency.

| Variant | Description |
|---------|-------------|
| `Syntax(ParseError)` | The input is syntactically invalid JSON |
| `Decode(StringDecodeError)` | Decoding a string value failed (a capacity overflow, an allocation failure, or an invalid character such as a malformed escape) |
| `MissingField(&'static str)` | A required event field is missing |
| `DuplicateField { field, position }` | A known event field appears more than once |
| `InvalidField { field, position }` | A value has the wrong JSON type (for example, an id written as a number) |
| `InvalidNumber { field, position }` | A numeric field holds a non-integer, or a value beyond the range of its type as defined in the event shape above |

A field with the correct JSON type and an invalid value returns the `SecpError` variant that matches the problem.

- `InvalidEvent`: an invalid string format, or an invalid set of Rumor fields
  - the id, pubkey, or sig string has an invalid length or invalid hex characters
  - the JSON of a Rumor has a sig field
- `InvalidPublicKey`: pubkey gives an x coordinate that lies off the curve
- `InvalidEventKind` / `EmptyEventTag`: the event shape check above failed

## NIP-17: Sealed and Gift-Wrapped Direct Messages

NIP-17 seals an unsigned `Rumor` in a signed event, encrypts that seal to the recipient, and wraps it in a second signed event. The first event is the seal, and the second event is the gift wrap.

- Required features: `nostr` and `nip44`
- Feature that enables both: `nip17`
- Seal event kind: 13
- Gift-wrap event kind: 1059
- `Rumor`: an unsigned event with six fields in total, the four fields of `UnsignedEvent` plus id and pubkey

```
Rumor { id, pubkey, created_at, kind, tags, content }
```

A scan key is a key that the recipient holds apart from the signing key.

`create_gift_wrap_with_scan_tag` takes the scan key's public key in addition to the recipient's public key. From the gift wrap's ephemeral key and the scan key, the function derives a 16-byte value by HMAC (a keyed hash) and returns it along with the gift wrap; that value is the scan tag.

A recipient who holds the scan key's secret key can compute the same value from the gift wrap's ephemeral public key with `compute_scan_tag` and compare the two. This tells the recipient whether the gift wrap is addressed to them before decrypting it.

| Item | Description |
|------|-------------|
| `create_seal` / `create_seal_with_rng` | Build a Rumor from the caller's unsigned event, then seal and sign it |
| `open_seal` | Decrypt a seal, parse the Rumor inside, and check that the Rumor's pubkey matches the seal's signing key |
| `create_gift_wrap` / `create_gift_wrap_with_rng` | Wrap a seal for the recipient with a fresh ephemeral key |
| `create_gift_wrap_with_scan_tag` / `..._with_rng` | Wrap a seal and also return a scan tag for the recipient's scan key |
| `GiftWrapWithScanTag` | The return value of `create_gift_wrap_with_scan_tag`, pairing the gift wrap with the scan tag |
| `open_gift_wrap` | Decrypt the gift wrap and the seal with the recipient's secret key, and return the `Rumor` inside |
| `compute_scan_tag` | Derive the scan tag from the scan key's secret key and the gift wrap's ephemeral public key |

Among the functions that create seals and gift wraps, those whose names end in `_with_rng` take a byte provider. The others use the OS random source and also require the `getrandom` feature, which is on by default.

```rust
use neco_secp::{nip17, SecretKey, SecpError, UnsignedEvent};

fn run() -> Result<(), SecpError> {
    let sender = SecretKey::generate()?;
    let recipient = SecretKey::generate()?;
    let recipient_pub = recipient.xonly_public_key()?;

    let inner = UnsignedEvent {
        created_at: 1_700_000_000,
        kind: 14,
        tags: vec![],
        content: "hello".to_string(),
    };

    let seal = nip17::create_seal(inner, &sender, &recipient_pub, 1_700_000_000)?;
    let gift_wrap = nip17::create_gift_wrap(&seal, &recipient_pub, 1_700_000_000)?;

    let rumor = nip17::open_gift_wrap(&gift_wrap, &recipient)?;
    assert_eq!(rumor.content, "hello");
    Ok(())
}
```

The seal and the gift wrap each take as timestamp the caller-supplied base time minus a random number of seconds between 0 and 2 days inclusive. A result below 0 becomes 0 (the Unix epoch).

## Testing

A normal test run skips the 5 mining tests marked `#[ignore]`.

These tests exercise the public mining functions (such as `mine_pow_with_rng` and `mine_vanity_npub_with_rng`), and take a long time because they search the key space.

```bash
# normal tests
cargo test -p neco-secp

# also run the ignored mining tests
cargo test -p neco-secp --features "batch nip19" -- --ignored
```

## ECDSA Signing

ECDSA signing and verification use dedicated functions. The curve is secp256k1.

- `SecretKey::sign_ecdsa_prehash`: signs with a nonce derived by RFC 6979, and normalizes s to at most half the curve order (low-S)
- `PublicKey::verify_ecdsa_prehash`: verifies a signature, and rejects one whose s exceeds half the order (high-S)

```rust
use neco_secp::{SecretKey, EcdsaSignature, SecpError};

fn run() -> Result<(), SecpError> {
    let secret = SecretKey::generate()?;
    let public = secret.public_key()?;
    let hash: [u8; 32] = [0x42; 32]; // a SHA-256 hash value

    let sig: EcdsaSignature = secret.sign_ecdsa_prehash(hash)?;
    public.verify_ecdsa_prehash(hash, &sig)
}
```

## API

Parentheses in the tables name the features each item requires.

### Keys

The word prehash in the signing and verification method names means that the method takes a 32-byte hash value computed by the caller (the `digest32` argument). `SecretKey` is a validated 32-byte secp256k1 secret key.

| Method | Description |
|--------|-------------|
| `generate()` | Generates a key from the OS random source (`getrandom`) |
| `generate_with_rng(fill)` | Generates a key from a byte provider |
| `from_bytes(bytes)` | Builds a key from a 32-byte array; 0 or a value at or above the curve order returns `InvalidSecretKey` |
| `from_hex(hex)` | Builds a key from a 64-digit hex string (`alloc`), with the same range check |
| `to_bytes()` / `to_hex()` | Returns the 32-byte array or a lowercase hex string |
| `public_key()` | Derives the compressed SEC1 `PublicKey` |
| `xonly_public_key()` | Derives the BIP340 `XOnlyPublicKey` |
| `sign_schnorr_prehash(digest32)` | Signs under BIP340 with auxiliary randomness from the OS random source (`getrandom`) |
| `sign_schnorr_prehash_with_aux(digest32, aux)` | Signs under BIP340 with auxiliary randomness supplied by the caller |
| `sign_schnorr_prehash_with_rng(digest32, fill)` | Signs under BIP340 with auxiliary randomness from a byte provider |
| `sign_schnorr_prehash_deterministic(digest32)` | Signs under BIP340 with all-zero auxiliary randomness |
| `sign_ecdsa_prehash(digest32)` | Signs with ECDSA and normalizes to low-S |

`PublicKey` represents a validated 33-byte public key in compressed SEC1 form, and is used to verify ECDSA signatures.

| Method | Description |
|--------|-------------|
| `from_sec1_bytes(bytes)` | Builds a key from a 33-byte compressed SEC1 value; an invalid length, prefix, or point returns `InvalidPublicKey` |
| `from_hex(hex)` | Builds a key from a 66-digit hex string (`alloc`) |
| `to_sec1_bytes()` / `to_hex()` | Returns the 33-byte SEC1 value or a hex string |
| `verify_ecdsa_prehash(digest32, sig)` | Verifies an ECDSA signature and rejects high-S |

`XOnlyPublicKey` is a validated 32-byte BIP340 x-only public key.

| Method | Description |
|--------|-------------|
| `from_bytes(bytes)` | Builds a key from a 32-byte x coordinate; a value that lies off the curve as an x coordinate returns `InvalidPublicKey` |
| `from_hex(hex)` | Builds a key from a 64-digit hex string (`alloc`) |
| `to_bytes()` / `to_hex()` | Returns the 32-byte array or a hex string |
| `verify_schnorr_prehash(digest32, sig)` | Verifies a BIP340 signature |

### Signatures

Both signature types represent a signature as 64 bytes formed by concatenating r and s (compact form).

| Item | Description |
|------|-------------|
| `SchnorrSignature` | A BIP340 signature |
| `EcdsaSignature` | An ECDSA signature |
| `EcdsaSignature::from_bytes(bytes)` | Builds an ECDSA signature from a 64-byte array |
| `to_bytes()` | Returns the 64-byte array of the signature, on both types |

### Key Pairs

`KeyBundle` is the type for a validated secret key paired with its x-only public key. The batch generation methods require the `batch` feature.

| Method | Description |
|--------|-------------|
| `generate()` | Generates a key pair from the OS random source (`getrandom`) |
| `generate_with_rng(fill)` | Generates a key pair from a byte provider |
| `secret()` / `xonly_public_key()` | Returns references to the secret key and the x-only public key |
| `npub()` | Returns the npub string (`nip19`) |
| `nsec()` | Returns the nsec string (`nip19`) |
| `generate_batch(n)` | Generates n key pairs from the OS random source (`getrandom`) |
| `generate_batch_with_rng(n, fill)` | Generates n key pairs from a byte provider |

### Mining

The mining functions require the `batch` feature, and the functions that search by npub prefix, along with their candidate type, also require `nip19`.

The argument n is the maximum number of attempts. When n attempts end with zero keys that meet the condition, the functions that return a key pair return `ExhaustedAttempts`, and the functions that return candidates return an empty list.

| Item | Description |
|------|-------------|
| `mine_pow(d, n)` | Searches for a key whose x-only public key starts with d zero nibbles, and returns the first key pair found (`getrandom`) |
| `mine_pow_with_rng(d, n, fill)` | Runs the same search as `mine_pow` with a byte provider |
| `mine_pow_best(d, n)` | Runs all n attempts, and returns the key pair with the most leading zero nibbles among those with at least d, along with that count (`getrandom`) |
| `mine_pow_best_with_rng(d, n, fill)` | Runs the same search as `mine_pow_best` with a byte provider |
| `mine_vanity_npub(p, n)` | Searches for a key whose npub data part after npub1 starts with p, and returns the first key pair found (`getrandom`) |
| `mine_vanity_npub_with_rng(p, n, fill)` | Runs the same search as `mine_vanity_npub` with a byte provider |
| `mine_vanity_npub_candidates(p, n, k)` | Runs all n attempts, and returns up to k keys whose data part matches p in at least one leading character, ordered by the number of matching characters (`getrandom`) |
| `mine_vanity_npub_candidates_with_rng(p, n, k, fill)` | Runs the same search as `mine_vanity_npub_candidates` with a byte provider |
| `VanityCandidate` | A candidate returned by `mine_vanity_npub_candidates` |
| `VanityCandidate::bundle()` | Returns the candidate key pair |
| `VanityCandidate::matched_len()` | Returns the number of leading characters that match p |

### Nostr Events

The event types require the `alloc` feature, and the functions that handle events require the `nostr` feature.

NIP-42 events, which a client uses to authenticate itself to a relay, are created and validated with the nip42 module.

| Item | Description |
|------|-------------|
| `UnsignedEvent` | An unsigned Nostr event (`alloc`) |
| `SignedEvent` | A signed Nostr event (`alloc`) |
| `Rumor` | An unsigned event used as the content of a NIP-17 seal (`alloc`) |
| `EventId` | A 32-byte Nostr event ID (`alloc`) |
| `hex::hex_encode(bytes)` | Converts bytes to a lowercase hex string (`alloc`) |
| `hex::hex_decode(hex)` | Converts a hex string (uppercase accepted) to bytes (`alloc`) |
| `nostr::serialize_event` | Writes the JSON array in NIP-01 form that is used to compute the event ID |
| `nostr::compute_event_id` | Returns the SHA-256 hash of that JSON as the event ID |
| `nostr::finalize_event` | Computes the event ID and signs with auxiliary randomness from the OS random source (`getrandom`) |
| `nostr::finalize_event_with_rng` | Signs with auxiliary randomness from a byte provider |
| `nostr::finalize_event_with_aux` | Signs with auxiliary randomness supplied by the caller |
| `nostr::finalize_event_deterministic` | Signs with all-zero auxiliary randomness |
| `nostr::verify_event` | Verifies the event ID and the signature |
| `nostr::create_rumor` | Computes the event ID from an unsigned event and a public key, and builds a Rumor |
| `nostr::serialize_signed_event` / `parse_signed_event` | Writes and parses a signed event as JSON |
| `nostr::serialize_rumor` / `parse_rumor` | Writes and parses the event inside a seal as JSON |
| `nostr::verify_rumor` | Checks that a Rumor's id matches the hash of its content |
| `EventJsonError` | A JSON parsing failure for an event or a Rumor |
| `nip42::create_auth_event` | Builds and signs an authentication event (kind 22242) tagged with the relay URL and the challenge string (`getrandom`) |
| `nip42::create_auth_event_with_rng` | Signs the same event as `create_auth_event` with auxiliary randomness from a byte provider |
| `nip42::validate_auth_event` | Verifies the signature, the kind, and the relay and challenge tags, and returns the signer's public key |

### NIP-19, NIP-04, and NIP-44

The modules nip19, nip04, and nip44 are each enabled by the feature of the same name.

The functions for seals and gift wraps are listed in the [NIP-17](#nip-17-sealed-and-gift-wrapped-direct-messages) table.

| Function | Description |
|----------|-------------|
| `nip19::encode_npub` | Encodes a public key as an npub string |
| `nip19::encode_nsec` | Encodes a secret key as an nsec string |
| `nip19::encode_note` | Encodes an event ID as a note string |
| `nip19::encode_nprofile` | Encodes an `NProfile` as an nprofile string |
| `nip19::encode_nevent` | Encodes an `NEvent` as an nevent string |
| `nip19::encode_naddr` | Encodes an `NAddr` as an naddr string |
| `nip19::encode_nrelay` | Encodes an `NRelay` as an nrelay string |
| `nip19::decode` | Decodes a NIP-19 string and returns the `Nip19` value for its prefix |
| `nip04::encrypt` / `encrypt_with_rng` | Encrypts content with a shared key derived from your own secret key and the peer's public key |
| `nip04::decrypt` | Decrypts content with the same shared key |
| `nip44::get_conversation_key` | Derives a conversation key from your own secret key and the peer's public key |
| `nip44::encrypt` / `encrypt_with_rng` | Encrypts content with a conversation key |
| `nip44::decrypt` | Decrypts content with a conversation key |
| `nip44::calc_padded_len` | Computes the padded length from the plaintext length by the NIP-44 padding rule |

### `SecpError`

Failures from dependency crates and lower-level processing are wrapped in a variant for each source. Parentheses name the features that enable each variant.

| Source | Wrapped as |
|--------|------------|
| `neco-galois` finite-field (Fp) arithmetic used in curve-point computation | `Field` |
| RFC 6979 nonce derivation by `neco-sha2` | `Nonce` |
| SHA-256 and HMAC from `neco-sha2` | `Hash` |
| `EventJsonError` (nostr) | `Json` |
| Base64 handling of content (nip04 or nip44) | `Base64` |
| Key derivation by the NIP-44 key derivation function (nip04 or nip44) | `Hkdf` |

A failure in SHA-256 or HMAC, used in signing, encryption, and event ID computation, is wrapped in `Hash`.

- Schnorr signing and verification: the BIP340 tagged hash
- NIP-44 encryption and decryption: the content HMAC
- NIP-17 scan tag derivation: HMAC
- Nostr event signing and verification: the SHA-256 of the event ID

Failures in randomness and memory allocation each return a dedicated variant.

- `RandomUnavailable`: the OS random source failed
- `EntropyRequired`: in a build with getrandom disabled, `None` was passed for an encryption value
  - the NIP-04 IV (initialization vector)
  - the NIP-44 nonce
- `CapacityOverflow { input_len }`: a buffer size computation overflowed
- `AllocationFailed { required }`: allocating memory for `required` elements failed

## License

MIT
