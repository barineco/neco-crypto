# neco-vault

[日本語](README-ja.md)

neco-vault is a crate for Nostr client apps that sign events while the signing secret keys stay in an in-memory vault.
It uses `neco-secp` for signing and for Nostr encryption and decryption.

The public API covers signing, Nostr encryption and decryption, public-key lookup, and adding, switching, and removing accounts (secret keys held under labels). In addition, for group messaging, it has functions that generate a group key (a 32-byte key that members share to encrypt messages), encrypt and decrypt that key for a recipient, and update the key generation (epoch). The vault performs every operation that uses a secret key internally and returns only the results, such as signed events, ciphertexts, plaintexts, and public keys.

## Features

| Feature | Enables |
|---------|---------|
| `std` (default) | Linkage against the standard library; also turns on alloc |
| `alloc` | Every API of the crate; keeps labels and accounts in heap collections; alloc alone gives a no_std build |
| `getrandom` (default) | The plain-form functions, which read the OS random source; the plain form is the one whose name lacks `_with_rng` (see [Random source](#random-source-plain-and-_with_rng-forms)) |
| `nostr` (default) | Event signing through neco-secp, and NIP-42 authentication events (events that authenticate a client to a relay) |
| `nip04` | NIP-04 encryption and decryption through the vault |
| `nip44` | NIP-44 encryption and decryption through the vault |
| `nip17` | NIP-17 direct messages (DMs) in gift wraps (a format that encrypts a sealed message again and wraps it); also turns on nip44 and nostr |
| `dm-epoch` | Derivation of epoch keys and group-key helpers. An epoch key is derived per generation from a conversation key (the shared key of two parties, derived with NIP-44 from one's own secret key and the peer's public key); also turns on nip44 |
| `encrypted` | Authenticated encrypted export and import with Argon2id and XChaCha20-Poly1305 |
| `legacy-migration` | One-way migration from the legacy (v1, v2) encrypted blobs to v3; also turns on encrypted; removed in the next compatibility-breaking release (0.3.0) |
| `security-hardening` | Individually switchable hooks around secret-key use (reading the secret key bytes, a pseudo delay, and dummy operations) |
| `wasm` | The js backend of getrandom, so that on wasm32 targets the plain functions run on a JavaScript host such as a browser |

Turning on `wasm` also turns on getrandom.

## Usage

### Basic signing

```rust
use neco_secp::{SecretKey, UnsignedEvent};
use neco_vault::{Vault, VaultConfig, VaultError};

fn sign_hello() -> Result<(), VaultError> {
    let mut vault = Vault::new(VaultConfig::default())?;
    let secret = SecretKey::generate()?;

    vault.import_plaintext("main", secret, 100)?;

    let signed = vault.sign_event(
        "main",
        UnsignedEvent {
            created_at: 101,
            kind: 1,
            tags: vec![],
            content: "hello".to_string(),
        },
        102,
    )?;

    assert_eq!(signed.kind, 1);
    Ok(())
}
```

### Active account

A caller can make one of the accounts the active account with `set_active`.
Functions whose names contain `_active` (such as `sign_event_active`) use the active account in place of a label.
The first account imported into an empty vault becomes the active account automatically.

```rust
use neco_secp::{SecretKey, UnsignedEvent};
use neco_vault::{Vault, VaultError};

fn use_active_account(
    vault: &mut Vault,
    secret: SecretKey,
    event: UnsignedEvent,
) -> Result<(), VaultError> {
    vault.import_plaintext("alice", secret, 100)?;
    // If this is the first import into an empty vault, "alice" becomes active

    vault.set_active("alice")?;
    let _label = vault.active_label(); // Some("alice")

    let _signed = vault.sign_event_active(event, 102)?;
    Ok(())
}
```

Removing the active account makes `active_label()` return `None`.

```rust
use neco_vault::{Vault, VaultError};

fn remove_active_account(vault: &mut Vault) -> Result<(), VaultError> {
    vault.remove("alice")?;
    assert_eq!(vault.active_label(), None);
    Ok(())
}
```

`labels()` returns all stored labels in sorted order.

### Cache timeout

The vault keeps imported accounts in memory as a cache and records the time of last use for each account. The recorded time is the Unix time that the caller passes to these calls:

- Imports: `import_plaintext`, `import_encrypted`
- Signing and NIP-42 calls
- NIP-04, NIP-44, and NIP-17 calls

Expired accounts and all accounts can each be discarded with a separate function. When either function discards the active account, `active_label()` returns `None` afterward.

- `clear_expired_cache(now)`: discards the accounts whose time elapsed from last use to `now` exceeds the cache timeout
- `clear_cache`: discards every account

The timeout is set in seconds in the `cache_timeout_seconds` field of `VaultConfig`, and defaults to 300 seconds.

### Random source: plain and `_with_rng` forms

Each operation that uses randomness comes in two forms. The randomness serves as auxiliary randomness for signing (32 bytes mixed with the secret key in a BIP340 signature), encryption nonces, key derivation salts, ephemeral keys, and so on.

- Plain form (`sign_event`, `export_encrypted`, and so on): reads bytes from the OS random source through the getrandom feature
- `_with_rng` form: draws randomness from a closure that the caller passes, and serves builds that leave out getrandom and environment-specific random sources (for example, the browser's `crypto.getRandomValues`)

The closure fills the buffer it receives with random bytes. The closure returns `SecpError` or `VaultError`, matching the implementation that uses the randomness.
The rest of this README calls the groups of functions for each type the `SecpError` family and the `VaultError` family.

- `SecpError` family: these operations, delegated to neco-secp
  - Signing and NIP-42 authentication events
  - NIP-04, NIP-44, and NIP-17 encryption and decryption
  - Group-key encryption of dm-epoch (`encrypt_group_key_with_rng`): creates the ephemeral key and the NIP-44 nonce with neco-secp functions
- `VaultError` family: these functions, in which the vault uses randomness itself
  - `export_encrypted_with_rng`: encrypted export
  - `migrate_legacy_encrypted_with_rng`: legacy migration
  - `create_group_key_with_rng`: group-key generation
  - `encrypt_with_epoch_with_rng`, `encrypt_group_message_with_rng`: encryption with an epoch key

When the random source is missing, the caller returns `EntropyRequired` of the matching error type from the closure. The shape of the value returned to the caller depends on the family of the error type.

- `VaultError` family: `VaultError::EntropyRequired` is returned as it is
- `SecpError` family: the error is wrapped in a variant, and `Crypto(SecpError::EntropyRequired)` is returned

A failure of the OS random source in a plain form takes the same two shapes.

- `VaultError` family: `VaultError::RandomUnavailable`
- `SecpError` family: `Crypto(SecpError::RandomUnavailable)`

```rust
use neco_vault::{Vault, VaultError};

fn group_key_from(source: &[u8]) -> Result<[u8; 32], VaultError> {
    Vault::create_group_key_with_rng(&mut |buf| {
        source
            .get(..buf.len())
            .ok_or(VaultError::EntropyRequired)
            .map(|bytes| buf.copy_from_slice(bytes))
    })
}
```

The plain forms require the `getrandom` feature. The decryption functions, however, use the closure only for the pseudo delay of security-hardening, so their plain forms are also available in these builds that leave out getrandom.

- NIP-04 and NIP-44 decryption: the plain forms also exist in builds that leave out both getrandom and security-hardening
  - `nip04_decrypt`, `nip04_decrypt_active`
  - `nip44_decrypt`, `nip44_decrypt_active`
- NIP-17 decryption: the plain form `open_gift_wrap_dm` exists in every build with nip17

In builds that leave out getrandom, these plain forms pass a closure that returns `SecpError::EntropyRequired` to the `_with_rng` form.

### Encrypted export and import (`encrypted` feature)

`export_encrypted` returns a 105-byte encrypted blob that is authenticated as a whole.
`import_encrypted` reads this format and imports the secret key under a new label.
Passing an existing label fails with `DuplicateLabel` before key derivation. In addition, a wrong passphrase and a blob modification found by the tag verification of authenticated encryption (AEAD) both result in `AuthenticationFailed`.

```rust
use neco_vault::{Vault, VaultError};

fn export_and_import(vault: &mut Vault) -> Result<(), VaultError> {
    let blob = vault.export_encrypted("alice", b"passphrase")?;
    vault.import_encrypted("bob", b"passphrase", &blob, 200)?;
    Ok(())
}
```

When an import fails, the labels and the active account stay as they were before the call.

### Format (v3)

An encrypted blob has a fixed length of 105 bytes, and integers are written in little-endian order.

| Offset | Length | Name | Content |
|--------|--------|------|---------|
| 0 | 4 | `magic` | ASCII `NVLT` |
| 4 | 1 | `version` | `03` |
| 5 | 4 | `m_cost` | u32, in KiB |
| 9 | 4 | `t_cost` | u32 |
| 13 | 4 | `p_cost` | u32 |
| 17 | 16 | `salt` | Key derivation salt; bytes from the selected random source |
| 33 | 24 | `nonce` | Encryption nonce; bytes from the selected random source |
| 57 | 32 | `ciphertext` | The encrypted secret key |
| 89 | 16 | `tag` | Poly1305 tag |

To create an encrypted blob, the vault derives a key from the passphrase and encrypts the secret key with that key.

- Key derivation: Argon2id version 0x13 with a 32-byte output; its optional inputs, the secret and the associated data, are empty
- Encryption: XChaCha20-Poly1305, keyed directly by the Argon2id output
- Associated data of the encryption (data that is authenticated and left unencrypted): the 57 header bytes (offsets 0 through 56)
- Plaintext: the 32-byte secret key

### Key derivation policy

Export uses the default key derivation cost (memory, iterations, and parallelism), and import checks the cost written in the blob before key derivation. The cost is capped at 256 MiB of memory, 8 iterations, and 8 parallel lanes. A value below the lower bound or above the upper bound returns `KdfParamsOutOfPolicy`, which carries the three values written in the blob.

| Parameter | Lower bound | Upper bound | Default |
|-----------|-------------|-------------|---------|
| `m_cost` (KiB) | 19,456 | 262,144 | 65,536 |
| `t_cost` | 2 | 8 | 3 |
| `p_cost` | 1 | 8 | 4 |

### Passphrases

- Format: a passphrase is a byte string and is used as given. NUL and non-UTF-8 bytes are accepted. The caller decides whether to apply Unicode normalization and encoding checks
- Empty passphrase: rejected with `EmptyPassphrase`
- Passphrase longer than 1,024 bytes: rejected with `PassphraseTooLong`
- Normalization for v3 blobs: the caller passes the passphrase in the same normalized form on export and on import. JavaScript callers normalize it with `String.prototype.normalize("NFKC")`
- Normalization for legacy blobs: legacy blobs were written with unnormalized passphrases, so pass the old passphrase as entered. If the migration fails, the caller retries with the NFC, NFD, and NFKC forms in turn

### Legacy migration (`legacy-migration` feature)

`migrate_legacy_encrypted` is a function that converts a legacy encrypted blob into a v3 encrypted blob.
It can be called without creating a `Vault`. Because it takes bytes in memory and returns the converted bytes, the caller reads and writes any files.
The input length and its first byte determine the legacy kind.

- v2: 100 bytes whose first byte is `0x02`
- v1: 64 bytes

```rust
use neco_vault::{migrate_legacy_encrypted, VaultError};

fn migrate(legacy: &[u8]) -> Result<Vec<u8>, VaultError> {
    migrate_legacy_encrypted(legacy, b"old passphrase", b"new passphrase")
}
```

- Decryption failures of a legacy blob (padding, plaintext length, secret key range): all return `AuthenticationFailed`
- Old passphrase: may be empty and may have any length. An old passphrase above the SHA-256 input limit of neco-sha2 returns `Hash`
- New passphrase: follows the passphrase rules above
- Key derivation cost of v2: a v2 blob is accepted only with the original cost of scrypt, the function that derives a key from the passphrase (`log_n=15, r=8, p=1`). Other costs return `MalformedEncrypted(LegacyParams)`
- scrypt work area: 32 MiB is allocated after a capacity check. A rejected allocation returns `AllocationFailed`
- Verification after migration: the new blob is opened again with the new passphrase. An authentication failure or a public key mismatch returns `MigrationVerificationFailed`
- Other input: input other than the two legacy formats above returns `NotLegacyFormat`. A v3 blob falls into this case
- Public key check after migration: legacy formats lack an authentication tag that detects modification, so compare the migrated public key with a separately recorded value (for example, the npub string, the NIP-19 form of a public key) before trusting it
- Choice of the new passphrase: for a legacy blob that may have been exposed, choose a new passphrase that differs from every passphrase used with the legacy format

`legacy-migration` will be removed in 0.3.0. Complete the migration before updating to 0.3.0.

A caller that keeps encrypted blobs in files migrates them in these steps.

1. Make a backup: copy the legacy blob under another name and confirm that the copy has the same content as the original.
2. Convert: pass the legacy blob, the old passphrase, and the new passphrase to `migrate_legacy_encrypted`. If it fails, stop and leave the legacy blob as it is.
3. Write a temporary file: create it in the same directory as the legacy blob, write the new blob, and sync it to disk.
4. Verify: read the temporary file back, import it into an empty vault with the new passphrase, and confirm that `public_key` matches the public key recorded before the migration.
5. Replace: rename the temporary file over the legacy blob within the same directory. This is an atomic replacement.
6. Delete the backup: delete it after confirming that the new blob imports. A legacy blob that opens with the old passphrase is a weakly protected ciphertext, so delete every copy of it as well.

### NIP-04 and NIP-44 through the vault

The NIP-44 functions require the `nip44` feature.
The NIP-04 functions become available with the `nip04` feature and take the same arguments as the NIP-44 functions.

```rust
use neco_vault::{Vault, VaultError};

fn roundtrip_nip44(vault: &mut Vault) -> Result<(), VaultError> {
    let bob = vault.public_key("bob")?;
    let payload = vault.nip44_encrypt_active(&bob, "hello", 101)?;
    let text = vault.nip44_decrypt_active(&bob, &payload, 102)?;
    assert_eq!(text, "hello");
    Ok(())
}
```

### Security hardening (`security-hardening` feature)

`SecurityConfig` turns on three hooks individually.

- `enable_dummy_operations`: runs a dummy signature with fixed inputs. Encryption and decryption calls also add a dummy encryption that matches the NIP of the call
  - NIP-04 calls: a dummy NIP-04 encryption
  - NIP-44 and NIP-17 calls: a dummy NIP-44 encryption
- `enable_random_delay`: spins `core::hint::spin_loop` 64 to 127 times, with the count set by one byte from the random source of the call
- `enable_constant_time`: reads the secret key bytes and passes them through `core::hint::black_box`
  - Scope of the effect: it only keeps the compiler from optimizing this read away, and the neco-secp arithmetic sets the execution time of the surrounding processing

The vault runs the enabled hooks before and after these calls that use a signing secret key.

- Signing and NIP-42 authentication events
- NIP-04, NIP-44, and NIP-17 encryption and decryption

Use `set_security_config` to replace the settings at run time.
`SecurityConfig::default()` turns on only `enable_constant_time`.

The effect of the three hooks as a defense against side channels is unproven.

## Failures

`VaultError` is an enum marked `#[non_exhaustive]`, so that later versions can add failure kinds.

| Failure | Condition |
|---------|-----------|
| `DuplicateLabel` | The label already exists |
| `MissingLabel` | The label is absent |
| `NoActiveAccount` | There is no active account |
| `Crypto(error)` | A failure of neco-secp, including the failure of a closure that returns SecpError |
| `MalformedEncrypted(kind)` | A length mismatch, a `magic` mismatch, input shorter than the minimum length, malformed content, or a legacy v2 scrypt cost that differs from the value migration accepts |
| `UnsupportedEncryptedVersion { found }` | The `magic` matches and the version is other than 3 |
| `KdfParamsOutOfPolicy { m_cost, t_cost, p_cost }` | A parameter is beyond the policy range |
| `LegacyFormat(kind)` | A legacy v1 or v2 blob |
| `EmptyPassphrase` | The passphrase is empty |
| `PassphraseTooLong { max }` | The passphrase for export or import, or the new passphrase for migration, exceeds 1,024 bytes |
| `AuthenticationFailed` | A wrong passphrase, or a modification of a blob that passes the structure checks |
| `InvalidSecretKey` | The authenticated plaintext is not a valid secret key |
| `RandomUnavailable` | The OS random source failed in a plain form of the VaultError family |
| `CapacityOverflow { required }` | A label, account, or output buffer would require more than `isize::MAX` bytes |
| `AllocationFailed { required }` | `try_reserve_exact` could not allocate the requested elements |
| `EntropyRequired` | A closure that returns VaultError has no random source |
| `SealFailed` | The AEAD encryption step failed |
| `NotLegacyFormat` | The input of `migrate_legacy_encrypted` is not in a legacy format |
| `MigrationVerificationFailed` | Verification of the migrated blob failed |
| `Argon2(error)` | Argon2id key derivation failed in export, import, or migration |
| `Hkdf(error)` | Expansion of the key derivation function HKDF failed in an epoch-key derivation or a group epoch rotation |
| `Hash(error)` | The input of the legacy key derivation exceeded the SHA-256 input limit |

The variants that wrap the failure of a lower crate as it is exist only in builds that turn on the matching feature.

- `VaultError::Argon2`: `encrypted`
- `VaultError::Hkdf`: `dm-epoch`
- `VaultError::Hash`: `legacy-migration`

The failures of the blob structure check and the key derivation policy check depend only on the blob and the caller's input.

- `MalformedEncrypted`, `UnsupportedEncryptedVersion`: the structure check
- `KdfParamsOutOfPolicy`: the key derivation policy check

The following failures, in contrast, come from the size of the request or from the runtime environment.

- `CapacityOverflow`: the requested amount exceeds `isize::MAX` bytes
- `RandomUnavailable`: the random source failed
- `AllocationFailed`: the allocation of the requested capacity failed
- `SealFailed`: the encryption step failed

In builds with `legacy-migration`, the message of `LegacyFormat` also names the migration function.

`MalformedKind` represents the kind of a structure failure.

- `Magic`: the `magic` differs
- `Length { expected, actual }`: the length differs from the format
- `TooShort { minimum, actual }`: an epoch ciphertext or an encrypted group key is shorter than its minimum length
- `Payload`: the content is malformed
- `LegacyParams`: the scrypt cost of a legacy v2 blob differs from `log_n=15, r=8, p=1`

`LegacyKind` represents the kind of a legacy format.

- `V1Sha256`: the 64-byte format that uses the SHA-256 hash of the passphrase as its key
- `V2ScryptCbc`: the 100-byte format that uses a key derived with scrypt

The `dm-epoch` helpers return failures of the same type.

- `create_group_key`: `RandomUnavailable` when random bytes are unavailable
- `encrypt_with_epoch`: `RandomUnavailable` when random bytes for the nonce are unavailable
- `encrypt_with_epoch`: `SealFailed` when encryption fails
- `encrypt_group_key`: `Crypto` for a failure of the random source or of NIP-44
- `decrypt_with_epoch`: `MalformedEncrypted` for input shorter than 28 bytes
- `decrypt_with_epoch`: `AuthenticationFailed` for a wrong key or a modification
- `decrypt_group_key`: `MissingLabel` when the label is absent
- `decrypt_group_key`: `MalformedEncrypted` for input shorter than 33 bytes or for malformed content
- `decrypt_group_key`: `Crypto` for a failure of conversation key derivation, NIP-44 decryption, or hex decoding
- `derive_epoch_key`: `MissingLabel` when the label is absent
- `derive_epoch_key`: `Crypto` for a failure of conversation key derivation
- `derive_epoch_key`: `Hkdf` when HKDF expansion fails
- `rotate_group_epoch`: `Hkdf` when HKDF expansion fails

## Safety scope

### Guaranteed

- Confidentiality of the secret key: the 32-byte secret key is encrypted with XChaCha20-Poly1305
- Integrity of the whole blob: the 57-byte header is authenticated as associated data, and a modification anywhere in the blob, header included, is rejected
- Kinds of authentication failure: a wrong passphrase and a blob modification found by the AEAD tag verification both return `AuthenticationFailed`. When the tag verifies and the decrypted result is an invalid secret key, `InvalidSecretKey` is returned instead
- Resource bounds: before derivation, the key derivation cost is limited to 256 MiB of memory, 8 iterations, and 8 parallel lanes
- Allocation bounds: before holding labels, accounts, or output, the vault computes the required capacity and allocates exactly that much with `try_reserve_exact`
- Requests beyond the bounds: a request above `isize::MAX` bytes returns `CapacityOverflow`
- Rejected allocations: a rejection of the allocation itself returns `AllocationFailed`. Both failures carry the required count
- Random failures: when the random source is unavailable, the operation fails with `RandomUnavailable`
- Erasure: derived keys, plaintext copies, AEAD buffers, and the Argon2id working memory are overwritten on both success and failure
- Erasure in legacy migration: the legacy key (the SHA-256 hash of v1, the scrypt output of v2), the scrypt work area, and the decrypted legacy plaintext are wrapped in `Zeroizing`
- Erasure of the Salsa20 internal state in legacy migration: it is overwritten on drop through the `zeroize` feature of the salsa20 dependency
- Diagnostic output: the `Debug` output of the vault shows `<redacted>` in place of secret keys

### Left to the caller and the runtime environment

- Passphrase strength and Unicode normalization
- Attempt limits and lockout
- Rollback and replay detection: a blob lacks any value that represents a generation
- Erasure of the memory of the secret keys that the vault holds (`SecretKey` is a type that implements `Copy`)
- Erasure on panic: on a panic that unwinds the stack, the drop handlers perform the same overwrite. With the `panic = "abort"` setting and on process termination, execution ends before the overwrite
- External exposure of memory: swap, core dumps, hibernation, cold boot attacks, and pinning pages with `mlock`
- Side channels beyond the constant-time tag comparison of `chacha20poly1305`: the three security-hardening hooks remain aids whose effect is unproven
- Erasure of stack temporaries and registers
- Erasure of the AES internal state and the SHA-256/HMAC internal state that legacy migration uses
- Key commitment: a blob lacks any value that pins down the single key used to encrypt it, so an attacker can use a crafted blob to test several passphrases in one query. If you let untrusted parties call `import_encrypted`, limit attempts on the caller side
- Label binding: a blob omits the label and can be imported under any label
- Browser memory: the work area that key derivation uses follows the key derivation policy table above. The linear memory of the wasm instance grows to match, and its page count only ever increases

## API

Every function marked "yes" in the RNG column of the table also has a form with `_with_rng` appended to the name.
That form takes the closure described in the random source section.
To pass a closure for signing, encrypted export, or legacy migration, call the following `_with_rng` forms.

- `Vault::sign_event_with_rng`, `Vault::sign_event_active_with_rng`: signing
- `Vault::export_encrypted_with_rng`: encrypted export
- `migrate_legacy_encrypted_with_rng`: legacy migration

Except for the decryption functions listed in the random source section, the plain forms of the functions marked "yes" require the `getrandom` feature to read the OS random source.

Some NIP-17 functions use a scan key and a scan tag.
A scan key is a key that the recipient holds apart from the signing key. The sender passes the scan key's public key to `create_sealed_dm_with_scan_tag` in addition to the recipient's public key.
A scan tag is a 16-byte value derived by HMAC (a keyed hash) from the gift wrap's ephemeral key and the scan key.
The recipient can pass the scan key's secret key to `compute_scan_tag`, compute the same value, and check whether a gift wrap is addressed to it.

| Item | Feature | RNG | Description |
|------|---------|-----|-------------|
| `SecurityConfig` | | | Settings for the hooks added before and after calls that use a secret key |
| `VaultConfig` | | | Settings for the cache timeout and the hooks |
| `Vault` | | | A vault that holds secret keys in memory and performs signing and other operations |
| `VaultError` | | | The failure type that vault operations return |
| `MalformedKind` | | | The kind of structure failure in `VaultError::MalformedEncrypted` |
| `LegacyKind` | | | The legacy format kind in `VaultError::LegacyFormat` |
| `SealedDmResult` | `nip17` | | A gift wrap event and the scan tag that lets a recipient tell whether the event is addressed to it |
| `Vault::new` | | | Create an empty vault |
| `Vault::import_plaintext` | | | Import a secret key under a label |
| `Vault::contains` | | | Return whether a label exists |
| `Vault::remove` | | | Remove an account by label |
| `Vault::labels` | | | Return all stored labels in sorted order |
| `Vault::set_active` | | | Set the active account |
| `Vault::active_label` | | | Return the label of the active account |
| `Vault::public_key` | | | Return the x-only public key (the 32-byte BIP340 public key) of the given label |
| `Vault::public_key_active` | | | Return the x-only public key of the active account |
| `Vault::set_security_config` | | | Replace the hook settings at run time |
| `Vault::security_config` | | | Return the current hook settings |
| `Vault::clear_cache` | | | Discard every account |
| `Vault::clear_expired_cache` | | | Discard the accounts whose time since last use exceeds the cache timeout |
| `Vault::sign_event` | `nostr` | yes | Sign a Nostr event with the given account |
| `Vault::sign_event_active` | `nostr` | yes | Sign a Nostr event with the active account |
| `Vault::create_auth_event` | `nostr` | yes | Create a NIP-42 authentication event with the given account |
| `Vault::create_auth_event_active` | `nostr` | yes | Create a NIP-42 authentication event with the active account |
| `Vault::nip04_encrypt` | `nip04` | yes | Encrypt with NIP-04 using the given account |
| `Vault::nip04_decrypt` | `nip04` | yes | Decrypt with NIP-04 using the given account |
| `Vault::nip04_encrypt_active` | `nip04` | yes | Encrypt with NIP-04 using the active account |
| `Vault::nip04_decrypt_active` | `nip04` | yes | Decrypt with NIP-04 using the active account |
| `Vault::nip44_encrypt` | `nip44` | yes | Encrypt with NIP-44 using the given account |
| `Vault::nip44_decrypt` | `nip44` | yes | Decrypt with NIP-44 using the given account |
| `Vault::nip44_encrypt_active` | `nip44` | yes | Encrypt with NIP-44 using the active account |
| `Vault::nip44_decrypt_active` | `nip44` | yes | Decrypt with NIP-44 using the active account |
| `Vault::create_sealed_dm` | `nip17` | yes | Create a gift-wrapped NIP-17 DM |
| `Vault::create_sealed_dm_with_scan_tag` | `nip17` | yes | Create a gift-wrapped NIP-17 DM and also return a scan tag for the recipient's scan key |
| `Vault::compute_scan_tag` | `nip17` | | Compute a scan tag from a scan key's secret key that the caller passes and a gift wrap's ephemeral public key |
| `Vault::open_gift_wrap_dm` | `nip17` | yes | Open a gift wrap and return the unsigned event (Rumor) |
| `Vault::derive_epoch_key` | `dm-epoch` | | Derive an epoch key from a conversation key |
| `Vault::encrypt_with_epoch` | `dm-epoch` | yes | Perform authenticated encryption with an epoch key |
| `Vault::decrypt_with_epoch` | `dm-epoch` | | Perform authenticated decryption with an epoch key |
| `Vault::create_group_key` | `dm-epoch` | yes | Return a 32-byte group key made from random bytes |
| `Vault::encrypt_group_key` | `dm-epoch` | yes | Encrypt a group key with NIP-44 |
| `Vault::decrypt_group_key` | `dm-epoch` | | Decrypt a group key with NIP-44 |
| `Vault::encrypt_group_message` | `dm-epoch` | yes | Encrypt a group message with an epoch key |
| `Vault::decrypt_group_message` | `dm-epoch` | | Decrypt a group message with an epoch key |
| `Vault::rotate_group_epoch` | `dm-epoch` | | Derive the next group epoch key |
| `Vault::export_encrypted` | `encrypted` | yes | Export a secret key as a v3 encrypted blob |
| `Vault::import_encrypted` | `encrypted` | | Import a secret key from a v3 encrypted blob |
| `migrate_legacy_encrypted` | `legacy-migration` | yes | Convert a legacy encrypted blob into a v3 encrypted blob |

## License

MIT
