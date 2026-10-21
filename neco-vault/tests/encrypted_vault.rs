#![cfg(feature = "encrypted")]

mod common;

use common::probe::watch;
use common::{
    test_entropy, unhex, KAT_A_BLOB, KAT_A_PASSPHRASE, LEGACY_PASSPHRASE, LEGACY_V1_BLOB,
    LEGACY_V2_BLOB, PUBLIC_1, SECRET_1,
};
use neco_secp::SecretKey;
use neco_vault::{LegacyKind, MalformedKind, Vault, VaultConfig, VaultError};

const SECRET_2: &str = "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9";
const PUBLIC_2: &str = "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8";
const KAT_A_KEY: &str = "1cd84e588c72f1d0bb3041fdd8a32de5ec738487c23ac9c5d84f119e05858bf8";
const PASSPHRASE_CANARY: &[u8] = b"vault-passphrase-canary-01234567";
const KAT_A_INITIAL_HASH: &str = "bac8f66faf11409787f3766a0be69e94b2bcaa45acc9de5d6b2caa1b5792030b";
const CANARY_INITIAL_HASH: &str =
    "7bf95a9b3eaf00adcfc4f48b657a6314516b3b11712e940d43e7657362951ad7";
const KAT_C_PASSPHRASE: &[u8] = b"kat-c";
const KAT_C_BLOB: &str = concat!(
    "4e564c5403400000000100000001000000101112131415161718191a1b1c1d1e",
    "1f303132333435363738393a3b3c3d3e3f40414243444546474d984f7df2ddef",
    "2a41e69b9cb3ea8a14b46a0548162659d4fa309258f09893fc0ecce9bbfc7ce1",
    "c73911b282fafe5041",
);

fn empty_vault() -> Vault {
    Vault::new(VaultConfig::default()).expect("vault")
}

fn vault_with(label: &str, secret_hex: &str) -> Vault {
    let mut vault = empty_vault();
    vault
        .import_plaintext(
            label,
            SecretKey::from_hex(secret_hex).expect("secret key"),
            100,
        )
        .expect("import plaintext");
    vault
}

fn public_hex(vault: &Vault, label: &str) -> String {
    vault
        .public_key(label)
        .expect("public key")
        .to_hex()
        .expect("public hex")
}

fn snapshot(vault: &Vault) -> (Vec<String>, Option<String>) {
    (
        vault
            .labels()
            .expect("labels")
            .into_iter()
            .map(str::to_string)
            .collect(),
        vault.active_label().map(str::to_string),
    )
}

fn assert_import_fails_without_change(
    vault: &mut Vault,
    label: &str,
    passphrase: &[u8],
    data: &[u8],
    expected: &VaultError,
) {
    let before = snapshot(vault);
    let error = vault
        .import_encrypted(label, passphrase, data, 200)
        .expect_err("the import must fail");
    assert_eq!(&error, expected);
    assert_eq!(snapshot(vault), before, "{expected:?}");
}

#[test]
fn export_import_roundtrip_restores_independent_public_keys() {
    for (secret_hex, expected_public) in [(SECRET_1, PUBLIC_1), (SECRET_2, PUBLIC_2)] {
        let source = vault_with("main", secret_hex);
        let blob = source
            .export_encrypted_with_rng("main", b"round trip passphrase", &mut test_entropy)
            .expect("export");
        assert_eq!(blob.len(), 105);
        assert_eq!(
            blob[..17],
            [
                0x4e, 0x56, 0x4c, 0x54, 0x03, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
                0x00, 0x00, 0x00
            ]
        );

        let mut dest = empty_vault();
        dest.import_encrypted("main", b"round trip passphrase", &blob, 200)
            .expect("import");
        assert_eq!(public_hex(&dest, "main"), expected_public);
        assert_eq!(dest.active_label(), Some("main"));
    }
}

#[test]
fn import_authenticates_known_answer_blob() {
    let blob = unhex(KAT_A_BLOB);

    let mut vault = empty_vault();
    vault
        .import_encrypted("main", KAT_A_PASSPHRASE, &blob, 200)
        .expect("the independent blob opens");
    assert_eq!(public_hex(&vault, "main"), PUBLIC_1);

    let mut other = empty_vault();
    let error = other
        .import_encrypted("main", b"correct horse battery stapl3", &blob, 200)
        .expect_err("a wrong passphrase must fail");
    assert_eq!(error, VaultError::AuthenticationFailed);
}

#[test]
fn import_leaves_vault_unchanged_on_every_failure() {
    let valid = unhex(KAT_A_BLOB);
    let mut tampered_ciphertext = valid.clone();
    tampered_ciphertext[60] ^= 0x01;
    let mut tampered_version = valid.clone();
    tampered_version[4] = 0x02;

    let failures: Vec<(&[u8], Vec<u8>, VaultError)> = vec![
        (
            b"wrong passphrase",
            valid.clone(),
            VaultError::AuthenticationFailed,
        ),
        (
            KAT_A_PASSPHRASE,
            tampered_ciphertext,
            VaultError::AuthenticationFailed,
        ),
        (
            KAT_A_PASSPHRASE,
            tampered_version,
            VaultError::UnsupportedEncryptedVersion { found: 2 },
        ),
        (
            KAT_A_PASSPHRASE,
            valid[..104].to_vec(),
            VaultError::MalformedEncrypted(MalformedKind::Length {
                expected: 105,
                actual: 104,
            }),
        ),
        (
            LEGACY_PASSPHRASE,
            unhex(LEGACY_V2_BLOB),
            VaultError::LegacyFormat(LegacyKind::V2ScryptCbc),
        ),
        (
            LEGACY_PASSPHRASE,
            unhex(LEGACY_V1_BLOB),
            VaultError::LegacyFormat(LegacyKind::V1Sha256),
        ),
    ];

    let mut empty = empty_vault();
    let mut occupied = vault_with("keep", SECRET_2);
    for (passphrase, data, expected) in &failures {
        assert_import_fails_without_change(&mut empty, "new", passphrase, data, expected);
        assert_import_fails_without_change(&mut occupied, "new", passphrase, data, expected);
    }
    assert_import_fails_without_change(
        &mut occupied,
        "keep",
        KAT_A_PASSPHRASE,
        &valid,
        &VaultError::DuplicateLabel,
    );

    assert!(empty.labels().expect("labels").is_empty());
    assert_eq!(empty.active_label(), None);
    assert_eq!(occupied.labels().expect("labels"), vec!["keep"]);
    assert_eq!(occupied.active_label(), Some("keep"));
}

#[test]
fn exports_of_the_same_key_differ() {
    let source = vault_with("main", SECRET_1);
    let first = source
        .export_encrypted_with_rng("main", b"same passphrase", &mut test_entropy)
        .expect("first export");
    let second = source
        .export_encrypted_with_rng("main", b"same passphrase", &mut test_entropy)
        .expect("second export");

    assert_eq!(first.len(), 105);
    assert_eq!(second.len(), 105);
    assert_ne!(first[17..33], second[17..33], "salt");
    assert_ne!(first[33..57], second[33..57], "nonce");
    assert_ne!(first[57..89], second[57..89], "ciphertext");
    assert_ne!(first[89..105], second[89..105], "tag");
}

#[test]
fn public_import_applies_the_production_policy() {
    let mut vault = empty_vault();
    assert_eq!(
        vault
            .import_encrypted("main", KAT_C_PASSPHRASE, &unhex(KAT_C_BLOB), 200)
            .expect_err("the floor of the test policy is below the production floor"),
        VaultError::KdfParamsOutOfPolicy {
            m_cost: 64,
            t_cost: 1,
            p_cost: 1,
        }
    );

    let mut above_ceiling = unhex(KAT_A_BLOB);
    above_ceiling[5..9].copy_from_slice(&[0x01, 0x00, 0x04, 0x00]);
    assert_eq!(
        vault
            .import_encrypted("main", KAT_A_PASSPHRASE, &above_ceiling, 200)
            .expect_err("m_cost 262145 is above the production ceiling"),
        VaultError::KdfParamsOutOfPolicy {
            m_cost: 262_145,
            t_cost: 3,
            p_cost: 4,
        }
    );

    for (m_cost, t_cost, p_cost) in [
        (u32::MAX, 3, 4),
        (65_536, 9, 4),
        (65_536, 3, 9),
        (19_455, 3, 4),
        (65_536, 1, 4),
        (65_536, 3, 0),
        (0, 0, 0),
        (u32::MAX, u32::MAX, u32::MAX),
    ] {
        let mut blob = unhex(KAT_A_BLOB);
        blob[5..9].copy_from_slice(&m_cost.to_le_bytes());
        blob[9..13].copy_from_slice(&t_cost.to_le_bytes());
        blob[13..17].copy_from_slice(&p_cost.to_le_bytes());
        assert_eq!(
            vault
                .import_encrypted("main", KAT_A_PASSPHRASE, &blob, 200)
                .expect_err("out of policy"),
            VaultError::KdfParamsOutOfPolicy {
                m_cost,
                t_cost,
                p_cost,
            }
        );
    }

    assert!(vault.labels().expect("labels").is_empty());
    assert_eq!(vault.active_label(), None);
}

#[test]
fn legacy_blobs_are_refused_by_import() {
    for (blob_hex, kind) in [
        (LEGACY_V2_BLOB, LegacyKind::V2ScryptCbc),
        (LEGACY_V1_BLOB, LegacyKind::V1Sha256),
    ] {
        let mut vault = empty_vault();
        let error = vault
            .import_encrypted("main", LEGACY_PASSPHRASE, &unhex(blob_hex), 100)
            .expect_err("a legacy blob must be refused even with its passphrase");
        assert_eq!(error, VaultError::LegacyFormat(kind));
        assert!(
            error.to_string().starts_with("legacy encrypted format"),
            "{error}"
        );
        assert!(vault.labels().expect("labels").is_empty());
        assert_eq!(vault.active_label(), None);
    }
}

#[test]
fn passphrase_and_keys_stay_out_of_freed_heap_blocks() {
    let ((), leaks) = watch(&[PASSPHRASE_CANARY], || {
        drop(std::hint::black_box(PASSPHRASE_CANARY.to_vec()));
    });
    assert!(leaks >= 1, "the probe must see a canary in a freed block");

    let secret = unhex(SECRET_1);
    let source = vault_with("main", SECRET_1);
    let (exported, leaks) = watch(&[PASSPHRASE_CANARY, &secret], || {
        source.export_encrypted_with_rng("main", PASSPHRASE_CANARY, &mut test_entropy)
    });
    let blob = exported.expect("export");
    assert_eq!(leaks, 0, "export");

    let mut dest = empty_vault();
    let (imported, leaks) = watch(&[PASSPHRASE_CANARY, &secret], || {
        dest.import_encrypted("main", PASSPHRASE_CANARY, &blob, 200)
    });
    imported.expect("import");
    assert_eq!(leaks, 0, "import");

    let known_blob = unhex(KAT_A_BLOB);
    let known_key = unhex(KAT_A_KEY);
    let known_initial_hash = unhex(KAT_A_INITIAL_HASH);
    let mut known = empty_vault();
    let (imported, leaks) = watch(
        &[KAT_A_PASSPHRASE, &known_key, &secret, &known_initial_hash],
        || known.import_encrypted("main", KAT_A_PASSPHRASE, &known_blob, 200),
    );
    imported.expect("import of the known answer blob");
    assert_eq!(leaks, 0, "import with a known derived key");

    let canary_initial_hash = unhex(CANARY_INITIAL_HASH);
    let mut rejected = empty_vault();
    let (result, leaks) = watch(&[PASSPHRASE_CANARY, &canary_initial_hash], || {
        rejected.import_encrypted("main", PASSPHRASE_CANARY, &known_blob, 200)
    });
    assert_eq!(result, Err(VaultError::AuthenticationFailed));
    assert_eq!(leaks, 0, "failed import");
}

#[test]
#[should_panic(expected = "watches at most 4 patterns")]
fn probe_refuses_more_patterns_than_it_watches() {
    let ((), leaks) = watch(&[PASSPHRASE_CANARY; 5], || ());
    assert_eq!(leaks, 0);
}
