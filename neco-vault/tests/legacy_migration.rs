#![cfg(feature = "legacy-migration")]

mod common;

use common::probe::watch;
use common::{
    test_entropy, unhex, KAT_A_BLOB, KAT_A_PASSPHRASE, LEGACY_PASSPHRASE, LEGACY_V1_BLOB,
    LEGACY_V2_BLOB, PUBLIC_1, SECRET_1,
};
use neco_sha2::Sha256;
use neco_vault::{
    migrate_legacy_encrypted_with_rng, MalformedKind, Vault, VaultConfig, VaultError,
};

const NEW_PASSPHRASE: &[u8] = b"new passphrase";
const NEW_PASSPHRASE_CANARY: &[u8] = b"migration-new-passphrase-canary!";
const WRONG_PASSPHRASE_CANARY: &[u8] = b"migration-wrong-passphrase-canar";
const LEGACY_V1_LONG_BLOB: &str = concat!(
    "707172737475767778797a7b7c7d7e7f6e4faae307e18fafd3befb0e64c0dbae",
    "102359c8f5c932b3b2fbcf4c8ca43d654dde36fd6207c189672a5e42ad294969",
);
const LEGACY_V2_LONG_BLOB: &str = concat!(
    "020f0801404142434445464748494a4b4c4d4e4f505152535455565758595a5b",
    "5c5d5e5f707172737475767778797a7b7c7d7e7fcdc634f62219bf1b0bea300b",
    "6ae38fb1860fd81aa5d50358400a19d65bb96bf957bce60c1d28db174ce683b7",
    "4c2fbaea",
);

const LEGACY_V2_KEY: &str = "3ff0e41f1ef4f2ceb6dee18a9f707c0c58533fa8bfc079045e0e304235eff62b";
const WRONG_V2_KEY: &str = "215c5315b928c450814b94b1bef502b49fb88fe64b162d25a92d03de1eb44c5c";

fn empty_vault() -> Vault {
    Vault::new(VaultConfig::default()).expect("vault")
}

fn random_passphrase() -> Vec<u8> {
    let mut length_byte = [0u8; 1];
    test_entropy(&mut length_byte).expect("entropy");
    let mut passphrase = vec![0u8; 1 + usize::from(length_byte[0]) % 32];
    test_entropy(&mut passphrase).expect("entropy");
    passphrase
}

#[test]
fn migration_converts_known_answer_blobs() {
    for blob_hex in [LEGACY_V2_BLOB, LEGACY_V1_BLOB] {
        let migrated = migrate_legacy_encrypted_with_rng(
            &unhex(blob_hex),
            LEGACY_PASSPHRASE,
            NEW_PASSPHRASE,
            &mut test_entropy,
        )
        .expect("migrate");
        assert_eq!(migrated.len(), 105);
        assert_eq!(migrated[..5], [0x4e, 0x56, 0x4c, 0x54, 0x03]);

        let mut vault = empty_vault();
        vault
            .import_encrypted("main", NEW_PASSPHRASE, &migrated, 200)
            .expect("import the migrated blob");
        assert_eq!(
            vault
                .public_key("main")
                .expect("public key")
                .to_hex()
                .expect("public hex"),
            PUBLIC_1
        );
    }
}

#[test]
fn migration_wrong_passphrase_is_always_authentication_failed() {
    let v1 = unhex(LEGACY_V1_BLOB);
    let mut failures = 0usize;
    while failures < 20_000 {
        let passphrase = random_passphrase();
        if passphrase == LEGACY_PASSPHRASE {
            continue;
        }
        assert_eq!(
            migrate_legacy_encrypted_with_rng(&v1, &passphrase, NEW_PASSPHRASE, &mut test_entropy),
            Err(VaultError::AuthenticationFailed)
        );
        failures += 1;
    }

    let v2 = unhex(LEGACY_V2_BLOB);
    for index in 0..8 {
        let passphrase = format!("wrong-{index}");
        assert_eq!(
            migrate_legacy_encrypted_with_rng(
                &v2,
                passphrase.as_bytes(),
                NEW_PASSPHRASE,
                &mut test_entropy
            ),
            Err(VaultError::AuthenticationFailed)
        );
    }
}

#[test]
fn migration_requires_legacy_blob_and_new_passphrase() {
    assert_eq!(
        migrate_legacy_encrypted_with_rng(
            &unhex(KAT_A_BLOB),
            KAT_A_PASSPHRASE,
            NEW_PASSPHRASE,
            &mut test_entropy
        ),
        Err(VaultError::NotLegacyFormat)
    );
    assert_eq!(
        migrate_legacy_encrypted_with_rng(
            &[1, 2, 3, 4, 5, 6, 7],
            LEGACY_PASSPHRASE,
            NEW_PASSPHRASE,
            &mut test_entropy
        ),
        Err(VaultError::NotLegacyFormat)
    );
    assert_eq!(
        migrate_legacy_encrypted_with_rng(
            &unhex(LEGACY_V1_BLOB),
            LEGACY_PASSPHRASE,
            b"",
            &mut test_entropy
        ),
        Err(VaultError::EmptyPassphrase)
    );
    assert_eq!(
        migrate_legacy_encrypted_with_rng(
            &unhex(LEGACY_V1_BLOB),
            b"",
            NEW_PASSPHRASE,
            &mut test_entropy
        ),
        Err(VaultError::AuthenticationFailed)
    );

    let too_long = [b'a'; 1_025];
    assert_eq!(
        migrate_legacy_encrypted_with_rng(
            &unhex(LEGACY_V1_BLOB),
            LEGACY_PASSPHRASE,
            &too_long,
            &mut test_entropy
        ),
        Err(VaultError::PassphraseTooLong { max: 1_024 })
    );
    assert_eq!(
        migrate_legacy_encrypted_with_rng(
            &unhex(LEGACY_V1_BLOB),
            &too_long,
            NEW_PASSPHRASE,
            &mut test_entropy
        ),
        Err(VaultError::AuthenticationFailed)
    );

    let mut other_scrypt_cost = unhex(LEGACY_V2_BLOB);
    other_scrypt_cost[1] = 40;
    assert_eq!(
        migrate_legacy_encrypted_with_rng(
            &other_scrypt_cost,
            LEGACY_PASSPHRASE,
            NEW_PASSPHRASE,
            &mut test_entropy
        ),
        Err(VaultError::MalformedEncrypted(MalformedKind::LegacyParams))
    );
}

#[test]
fn migration_accepts_old_passphrases_of_any_length() {
    let long_passphrase = vec![b'x'; 2_000];
    for blob_hex in [LEGACY_V1_LONG_BLOB, LEGACY_V2_LONG_BLOB] {
        let migrated = migrate_legacy_encrypted_with_rng(
            &unhex(blob_hex),
            &long_passphrase,
            NEW_PASSPHRASE,
            &mut test_entropy,
        )
        .expect("a long legacy passphrase migrates");
        let mut vault = empty_vault();
        vault
            .import_encrypted("main", NEW_PASSPHRASE, &migrated, 200)
            .expect("import the migrated blob");
        assert_eq!(
            vault
                .public_key("main")
                .expect("public key")
                .to_hex()
                .expect("public hex"),
            PUBLIC_1
        );
    }
}

#[test]
fn migration_changes_passphrase_and_salt() {
    let legacy = unhex(LEGACY_V1_BLOB);
    let first = migrate_legacy_encrypted_with_rng(
        &legacy,
        LEGACY_PASSPHRASE,
        NEW_PASSPHRASE,
        &mut test_entropy,
    )
    .expect("first migration");
    let second = migrate_legacy_encrypted_with_rng(
        &legacy,
        LEGACY_PASSPHRASE,
        NEW_PASSPHRASE,
        &mut test_entropy,
    )
    .expect("second migration");
    assert_ne!(first[17..33], second[17..33], "salt");
    assert_ne!(first[33..57], second[33..57], "nonce");

    for migrated in [&first, &second] {
        let mut vault = empty_vault();
        vault
            .import_encrypted("main", NEW_PASSPHRASE, migrated, 200)
            .expect("the new passphrase opens the migrated blob");
        assert_eq!(
            vault
                .public_key("main")
                .expect("public key")
                .to_hex()
                .expect("public hex"),
            PUBLIC_1
        );

        let mut other = empty_vault();
        assert_eq!(
            other.import_encrypted("main", LEGACY_PASSPHRASE, migrated, 200),
            Err(VaultError::AuthenticationFailed)
        );
    }
}

#[test]
fn migration_keeps_passphrases_keys_and_plaintext_out_of_freed_heap_blocks() {
    assert_eq!(NEW_PASSPHRASE_CANARY.len(), 32);
    assert_eq!(WRONG_PASSPHRASE_CANARY.len(), 32);
    let secret = unhex(SECRET_1);

    let v1 = unhex(LEGACY_V1_BLOB);
    let v1_key = Sha256::digest(LEGACY_PASSPHRASE).expect("passphrase within SHA-256 limit");
    let (result, leaks) = watch(
        &[
            LEGACY_PASSPHRASE,
            NEW_PASSPHRASE_CANARY,
            &secret,
            v1_key.as_slice(),
        ],
        || {
            migrate_legacy_encrypted_with_rng(
                &v1,
                LEGACY_PASSPHRASE,
                NEW_PASSPHRASE_CANARY,
                &mut test_entropy,
            )
        },
    );
    result.expect("migrate v1");
    assert_eq!(leaks, 0, "v1");

    let v2 = unhex(LEGACY_V2_BLOB);
    let v2_key = unhex(LEGACY_V2_KEY);
    let (result, leaks) = watch(
        &[
            LEGACY_PASSPHRASE,
            NEW_PASSPHRASE_CANARY,
            &secret,
            v2_key.as_slice(),
        ],
        || {
            migrate_legacy_encrypted_with_rng(
                &v2,
                LEGACY_PASSPHRASE,
                NEW_PASSPHRASE_CANARY,
                &mut test_entropy,
            )
        },
    );
    result.expect("migrate v2");
    assert_eq!(leaks, 0, "v2");

    let wrong_v1_key =
        Sha256::digest(WRONG_PASSPHRASE_CANARY).expect("passphrase within SHA-256 limit");
    let (result, leaks) = watch(
        &[
            WRONG_PASSPHRASE_CANARY,
            NEW_PASSPHRASE_CANARY,
            wrong_v1_key.as_slice(),
        ],
        || {
            migrate_legacy_encrypted_with_rng(
                &v1,
                WRONG_PASSPHRASE_CANARY,
                NEW_PASSPHRASE_CANARY,
                &mut test_entropy,
            )
        },
    );
    assert_eq!(result, Err(VaultError::AuthenticationFailed));
    assert_eq!(leaks, 0, "v1 with a wrong passphrase");

    let wrong_v2_key = unhex(WRONG_V2_KEY);
    let (result, leaks) = watch(
        &[
            WRONG_PASSPHRASE_CANARY,
            NEW_PASSPHRASE_CANARY,
            wrong_v2_key.as_slice(),
        ],
        || {
            migrate_legacy_encrypted_with_rng(
                &v2,
                WRONG_PASSPHRASE_CANARY,
                NEW_PASSPHRASE_CANARY,
                &mut test_entropy,
            )
        },
    );
    assert_eq!(result, Err(VaultError::AuthenticationFailed));
    assert_eq!(leaks, 0, "v2 with a wrong passphrase");
}
