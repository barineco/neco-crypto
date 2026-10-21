# neco-nostr-wasm

[日本語](README-ja.md)

neco-nostr-wasm provides WebAssembly bindings for [neco-secp](../neco-secp) and [neco-vault](../neco-vault).

Through `wasm-bindgen`, JavaScript can use the features that a Nostr client needs to handle keys and signatures.

- Nostr signing
- Vault-backed encryption
- Helpers that follow the NIPs (the documents that define the Nostr specifications)
- Key mining helpers (a search that keeps generating keys until it finds a public key that meets a condition)

Values passed between JavaScript and Rust are mainly hex strings (strings that represent bytes in hexadecimal), JSON strings, and encrypted bytes.

## JavaScript bindings

- `NostrSigner`: a vault wrapper that combines account management, signing, NIP-04/44, NIP-17, NIP-42, encrypted import and export, and security settings
- Free functions (functions exported at the top level of the module): Bech32 and NIP-19 helpers, public-key conversion, event helpers (finalization, verification, serialization, event ID computation, NIP-42 validation), mining and key generation helpers, and migration of legacy encrypted data

Two bindings share the name `decode_nsec`.

- The free function `decode_nsec(nsec)`: returns the secret key as a hex string
- The method `NostrSigner.decode_nsec(nsec, label)`: imports the secret key into the vault as an account with the given label, and returns undefined

## Value formats

- Keys: hex strings
- Events: JSON strings
- Encrypted export: `Uint8Array`
- Errors: a `JsValue` holding a string message (a failure to read the clock is the one exception, which yields the `Error` object described below)
- Plaintext secret key output: the free function `decode_nsec` and the results of vanity mining (a search for keys whose npub starts with a given string), for use when the JavaScript side needs the plaintext secret key
- Plaintext secret key refusal: `generate_secret_key` always returns the following fixed failure

```text
plaintext secret export is disabled; use vanity mining output if needed
```

## JSON for events and NIP-19 identifiers

The event helpers and the functions that encode NIP-19 identifiers read and write JSON in the same way.

- Input: parses the JSON string while keeping it borrowed
- Output: counts the required bytes first, reserves exactly that capacity, and then writes. When the counted length exceeds the addressable range or the allocation fails, it returns a failure

An unsigned event is a JSON object made up of four fields.

- `created_at`: the creation time in Unix seconds
- `kind`: the numeric event kind
- `content`: the content string
- `tags`: the tags, as an array of string arrays

Functions that also need the public key read `pubkey` as well.

Each function that builds a NIP-19 identifier takes one JSON object. Each entry in the listing below gives the names accepted for one field, in order of precedence.

- Precedence: decided by the presence of a field alone. When the field whose name comes first in the listing below is present, that field wins, even when its value is `null` or has the wrong type
- When the winning field holds `null` or a value of the wrong type: the call fails. The exceptions are the author and the event kind of `encode_nevent`, which are treated as absent
- Range of the event kind in `encode_nevent`: an integer from 4,294,967,296 up to 2^64 − 1 fails with `kind out of range`
- Duplicate keys: within one JSON object, the last occurrence wins

```text
encode_nevent:   id_hex > id,  author_hex > author,  kind > event_kind
encode_nprofile: pubkey_hex > pubkey
encode_naddr:    author_hex > author > pubkey_hex > pubkey,  kind > event_kind
```

`encode_naddr` also requires the string field `identifier`.

`relays` is optional in every function, and an omitted `relays` becomes an empty array.

The object that `decode_bech32` returns has one of six field sets, chosen by the identifier type.

```text
npub:     kind, pubkey_hex
note:     kind, id_hex
nprofile: kind, pubkey_hex, relays
nevent:   kind, id_hex, author_hex (string or null), event_kind (number or null), relays
naddr:    kind, identifier, author_hex, event_kind (number), relays
nrelay:   kind, relay
```

In the output, `kind` represents the identifier type, unlike `kind` in the input.

- `kind`: a string naming the identifier type
- `event_kind`: the numeric event kind

When `decode_bech32` receives an `nsec` string, the call always fails with the same error message.

```text
nsec decode is disabled in wasm boundary
```

To read a plaintext secret key from an `nsec`, use the free function `decode_nsec`.

## Time

The `NostrSigner` methods that add accounts, sign, encrypt and decrypt, and clear expired cache entries read the current time from the runtime environment. The free functions, by contrast, use only the timestamps in their input JSON.

- The vault records this time as each account's last-use time
- `clear_expired_cache` compares this time with `cache_timeout_seconds`
- `create_auth_event` and `create_sealed_dm` also use this time in the events they create

The source of the current time depends on the build target. On `wasm32`, the source is the following inline JavaScript, which computes Unix seconds.

```js
const milliseconds = Date.now();
if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) {
  throw new Error("invalid system clock");
}
return BigInt(milliseconds) / 1000n;
```

When the check finds the clock value invalid, this code throws a JavaScript `Error`. The declaration marked `#[wasm_bindgen(catch)]` catches the exception, and the method returns that exception object as its failure.

Targets other than `wasm32` (native test runs) use `SystemTime` from the standard library, and return the following failure for a time before the Unix epoch.

```text
system clock precedes Unix epoch
```

## Errors

This crate formats the display text of a Rust error type inside a fixed-length 512-byte stack buffer, and then returns it as a JavaScript string.

- When the formatted string fits in 512 bytes: that string is returned as is
- When the formatting exceeds 512 bytes, or the written bytes are invalid UTF-8: one of the following fallback messages is returned

```text
error message could not be formatted in 512 bytes
error message contains invalid UTF-8
```

The 512-byte limit applies to message formatting. The following allocations, which accompany value conversion, are made by the code that wasm-bindgen generates and by the JavaScript runtime, in proportion to the size of the values.

- Allocations that convert arguments passed from JavaScript into Rust values
- Allocations that convert Rust outputs and errors into JavaScript values, and allocations on the JavaScript engine side

## Mining

Each mining and key generation function calls a key generation or search function of `neco-secp`, and returns the result encoded as JSON.

- `generate_keypair` uses `KeyBundle::generate`
- `generate_keypairs_batch` uses `KeyBundle::generate_batch`
- `mine_pow_batch` uses `mine_pow_best`
- `mine_vanity_batch` uses `mine_vanity_npub`
- `mine_vanity_with_candidates` uses `mine_vanity_npub_candidates`

In the result of every function, three fields represent the public key of the generated key.

- `npub`: the string in NIP-19 npub form
- `pubkey_hex`: the hex string of the x-coordinate-only form (32 bytes)
- `public_key_hex`: the hex string of SEC1 compressed form (33 bytes)

- `generate_keypair` and `generate_keypairs_batch`: return only the public-key fields, and discard the generated secret key when the call ends
- `mine_pow_batch`: the public-key fields and `difficulty`, which is the number of leading zero nibbles (4 bits each) in the x-coordinate-only public key bytes of the best key found
- `mine_vanity_batch`: the public-key fields and `secret_hex`
- `mine_vanity_with_candidates`: an array of candidate objects
  - Each candidate: the public-key fields, `secret_hex`, and the matched length `matched_len`

Vanity mining matches the given prefix against the data part of the npub that follows `npub1`. A prefix may use the 32 characters of the Bech32 data part.

```text
qpzry9x8gf2tvdw0s3jn54khce6mua7l
```

- A prefix containing any other character fails with `invalid npub vanity prefix`
- `mine_vanity_batch` fails with `exhausted attempts` when it uses up its attempts before finding a match
- `mine_pow_batch` fails with `exhausted attempts` when every attempt falls below the requested difficulty

## Encrypted import and export

- `encrypt_secret_key`: returns 105 bytes of v3-format encrypted data as a `Uint8Array`
- `add_account`: accepts the v3 format only
- Legacy (v1, v2) encrypted data: rejected with an exception whose message begins with `legacy encrypted format`
- `migrate_legacy_encrypted`: converts legacy encrypted data into v3-format encrypted data in memory
- New passphrases: the caller normalizes them with `String.prototype.normalize("NFKC")` and uses the same form for export and import
- The old passphrase of legacy data: legacy data was written with the passphrase as entered, so the caller first passes it unmodified
- Retrying the old passphrase: `migrate_legacy_encrypted` makes a single decryption attempt with the bytes it receives
- On an authentication failure: the caller calls it again, passing the NFC, NFD, and NFKC forms in that order
- Authenticity of legacy data: the legacy formats are unauthenticated and leave tampering undetected, so compare the migrated public key with a separately recorded value (for example, the npub)
- Work area in linear memory (the contiguous memory region that a wasm module uses): the Argon2id work area follows the ceiling of the key derivation policy. Imported encrypted data uses up to the 262,144 KiB ceiling, and encrypted data created by export and migration uses 65,536 KiB
- Additional linear memory: depends on how much freed space the memory allocator inside the wasm module reuses
- Page count of linear memory: only ever increases

`migrate_legacy_encrypted` is exported under its Rust name, like the other free functions. The example below tries the old passphrase unmodified, then in each normalized form.

```js
import init, { migrate_legacy_encrypted } from "./pkg/neco_nostr_wasm.js";

await init();

const candidates = [
  oldPassphrase,
  oldPassphrase.normalize("NFC"),
  oldPassphrase.normalize("NFD"),
  oldPassphrase.normalize("NFKC"),
];
let v3;
for (const candidate of candidates) {
  try {
    v3 = migrate_legacy_encrypted(legacyBytes, candidate, newPassphrase.normalize("NFKC"));
    break;
  } catch (error) {
    if (!String(error).startsWith("authentication failed")) throw error;
  }
}
```

Failure messages are the display text of the vault error type.

- A wrong passphrase, or tampered encrypted data

  ```text
  authentication failed: wrong passphrase or modified data
  ```

- Legacy encrypted data passed to `add_account` (one line each for v1 and v2; both begin with `legacy encrypted format`, followed by the format version)

  ```text
  legacy encrypted format ( v1, SHA-256 key ); convert it with migrate_legacy_encrypted
  legacy encrypted format ( v2, scrypt key ); convert it with migrate_legacy_encrypted
  ```

- Input to `migrate_legacy_encrypted` whose shape differs from the legacy shapes (64 bytes, or 100 bytes starting with 02)

  ```text
  data is not in a legacy encrypted format
  ```

- An empty passphrase

  ```text
  passphrase is empty
  ```

## Usage

First build with `wasm-pack build --target web`, then import the generated package from JavaScript.

The free functions and the `NostrSigner` methods are all synchronous.

```js
import init, { NostrSigner, encode_npub, mine_vanity_batch } from "./pkg/neco_nostr_wasm.js";

await init();

const signer = new NostrSigner(300n);
signer.add_account_with_plaintext("main", "<secret-hex>");

const signed = signer.sign_event(
  JSON.stringify({
    created_at: 1,
    kind: 1,
    tags: [],
    content: "hello",
  }),
);

const npub = encode_npub(signer.get_public_key("main"));
const vanity = JSON.parse(mine_vanity_batch("ac", 100000));
```

## API

| Item | Description |
|------|-------------|
| `NostrSigner` | A wrapper that signs and encrypts with the vault |
| `encode_npub`, `encode_note` | Encode the hex string of a public key or an event ID into a NIP-19 identifier |
| `encode_nsec` | Encodes the hex string of a secret key into a NIP-19 `nsec` |
| `encode_nevent`, `encode_nprofile` | Build the NIP-19 identifier of an event or a profile from a JSON object |
| `encode_naddr` | Builds, from a JSON object, a NIP-19 identifier that points to the combination of author, kind, and `identifier` |
| `decode_nsec` | Decodes an `nsec` and returns the plaintext secret key as a hex string |
| `decode_bech32` | Decodes a NIP-19 identifier other than `nsec` and returns it as a JSON object |
| `encode_lnurl` | Encodes the input string as is into Bech32 with the prefix `lnurl`; URL validation is the caller's responsibility |
| `generate_secret_key` | Always returns the fixed failure |
| `derive_public_key`, `derive_public_key_sec1` | Derive the public key from a secret key, in x-coordinate-only (x-only) form and in SEC1 form |
| `parse_public_key_hex` | Validates the hex string of a public key and returns it as a hex string |
| `finalize_event`, `verify_event` | Sign a Nostr event, and verify its signature |
| `serialize_event`, `get_event_hash` | Return the serialized string used to compute the event ID, and the event ID |
| `validate_auth_event` | Validates a NIP-42 authentication event |
| `generate_keypair`, `generate_keypairs_batch` | Generate keys and return only the public-key fields |
| `mine_pow_batch` | Proof-of-work mining; returns the public-key fields and `difficulty` |
| `mine_vanity_batch`, `mine_vanity_with_candidates` | Vanity mining; returns results that include the hex string of the secret key |
| `migrate_legacy_encrypted` | Converts legacy encrypted data into v3-format encrypted data |

### `NostrSigner` methods

| Method | Description |
|--------|-------------|
| `new(cache_timeout_seconds)` | Creates an empty vault with the given cache timeout in seconds |
| `add_account_with_plaintext(label, secret_hex)` | Imports the hex string of a secret key as an account with a label |
| `add_account(label, encrypted, passphrase)` | Decrypts v3-format encrypted data and imports it as an account |
| `decode_nsec(nsec, label)` | Decodes an `nsec` and imports it as an account |
| `remove_account(label)` | Removes an account |
| `get_accounts()` | Returns the labels of all accounts as a sorted JSON array of strings |
| `get_active_account()` | Returns the label of the active account, or undefined while the active account is unset |
| `set_active_account(label)` | Switches the active account |
| `get_public_key(label)` | Returns the public key of an account as a hex string |
| `encrypt_secret_key(label, passphrase)` | Returns the secret key of an account as v3-format encrypted data |
| `sign_event(json)`, `sign_event_with(label, json)` | Sign an unsigned event with the active account or with the given account |
| `nip04_encrypt`, `nip04_decrypt` | NIP-04 encryption and decryption with the active account's secret key and the peer's public key |
| `nip44_encrypt`, `nip44_decrypt` | NIP-44 encryption and decryption with the active account's secret key and the peer's public key |
| `create_sealed_dm(content, recipient_hex)` | Creates a direct message from the active account to the recipient as a NIP-17 gift wrap |
| `open_gift_wrap(json)` | Opens a gift wrap with the active account and returns the wrapped event as a JSON string |
| `create_auth_event(challenge, relay_url)` | Creates a NIP-42 authentication event signed by the active account |
| `clear_cache()`, `clear_expired_cache()` | Discard all accounts, or the accounts whose cache timeout has passed |
| `set_security_config(json)` | Selects, from JSON, the protective steps added before and after each use of a secret key |

In the JSON passed to `set_security_config`, each step is turned on or off with a boolean. An omitted field takes the default shown below.

- `enable_constant_time`: reads the secret key bytes in a way that optimization keeps; defaults to true
- `enable_random_delay`: a wait whose repeat count comes from random bytes; defaults to false
- `enable_dummy_operations`: dummy signing and encryption; defaults to false

## License

MIT
