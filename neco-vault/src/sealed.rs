use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::{Zeroize, Zeroizing};

use crate::kdf::{KdfParams, KdfPolicy, KeyDerivation, KEY_LEN, SALT_LEN};
use crate::legacy;
use crate::{MalformedKind, VaultError};

const MAGIC: [u8; 4] = *b"NVLT";
const FORMAT_VERSION: u8 = 3;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const SECRET_LEN: usize = 32;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 57;
pub(crate) const ENCRYPTED_LEN: usize = 105;
const MAX_PASSPHRASE_LEN: usize = 1_024;

pub(crate) struct Header {
    pub(crate) params: KdfParams,
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) nonce: [u8; NONCE_LEN],
}

fn read_u32(bytes: &[u8]) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(bytes);
    u32::from_le_bytes(word)
}

pub(crate) fn parse(data: &[u8], policy: &KdfPolicy) -> Result<Header, VaultError> {
    if data.len() == ENCRYPTED_LEN {
        if data[..4] != MAGIC {
            return Err(VaultError::MalformedEncrypted(MalformedKind::Magic));
        }
        if data[4] != FORMAT_VERSION {
            return Err(VaultError::UnsupportedEncryptedVersion { found: data[4] });
        }
        let params = policy.admit(
            read_u32(&data[5..9]),
            read_u32(&data[9..13]),
            read_u32(&data[13..17]),
        )?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&data[17..33]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&data[33..HEADER_LEN]);
        return Ok(Header {
            params,
            salt,
            nonce,
        });
    }
    if let Some(kind) = legacy::classify(data) {
        return Err(VaultError::LegacyFormat(kind));
    }
    Err(VaultError::MalformedEncrypted(MalformedKind::Length {
        expected: ENCRYPTED_LEN,
        actual: data.len(),
    }))
}

pub(crate) fn check_passphrase(passphrase: &[u8]) -> Result<(), VaultError> {
    if passphrase.is_empty() {
        return Err(VaultError::EmptyPassphrase);
    }
    if passphrase.len() > MAX_PASSPHRASE_LEN {
        return Err(VaultError::PassphraseTooLong {
            max: MAX_PASSPHRASE_LEN,
        });
    }
    Ok(())
}

pub(crate) fn open(
    data: &[u8],
    passphrase: &[u8],
    policy: &KdfPolicy,
    kdf: &dyn KeyDerivation,
) -> Result<Zeroizing<[u8; SECRET_LEN]>, VaultError> {
    let header = parse(data, policy)?;
    check_passphrase(passphrase)?;
    let key = kdf.derive(passphrase, &header.salt, &header.params)?;
    let mut buf = Zeroizing::new([0u8; SECRET_LEN]);
    buf.copy_from_slice(&data[HEADER_LEN..HEADER_LEN + SECRET_LEN]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&data[HEADER_LEN + SECRET_LEN..]);
    aead_open_in_place(&key, &header.nonce, &data[..HEADER_LEN], &mut buf[..], &tag)?;
    Ok(buf)
}

pub(crate) fn seal_with_entropy(
    secret: &[u8; SECRET_LEN],
    passphrase: &[u8],
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    kdf: &dyn KeyDerivation,
) -> Result<[u8; ENCRYPTED_LEN], VaultError> {
    check_passphrase(passphrase)?;
    let mut blob = [0u8; ENCRYPTED_LEN];
    blob[..4].copy_from_slice(&MAGIC);
    blob[4] = FORMAT_VERSION;
    blob[5..9].copy_from_slice(&params.m_cost().to_le_bytes());
    blob[9..13].copy_from_slice(&params.t_cost().to_le_bytes());
    blob[13..17].copy_from_slice(&params.p_cost().to_le_bytes());
    blob[17..33].copy_from_slice(&salt);
    blob[33..HEADER_LEN].copy_from_slice(&nonce);
    let key = kdf.derive(passphrase, &salt, &params)?;
    let mut buf = Zeroizing::new(*secret);
    let tag = aead_seal_in_place(&key, &nonce, &blob[..HEADER_LEN], &mut buf[..])?;
    blob[HEADER_LEN..HEADER_LEN + SECRET_LEN].copy_from_slice(&buf[..]);
    blob[HEADER_LEN + SECRET_LEN..].copy_from_slice(&tag);
    Ok(blob)
}

pub(crate) fn seal(
    secret: &[u8; SECRET_LEN],
    passphrase: &[u8],
    params: KdfParams,
    kdf: &dyn KeyDerivation,
    fill: &mut dyn FnMut(&mut [u8]) -> Result<(), VaultError>,
) -> Result<[u8; ENCRYPTED_LEN], VaultError> {
    check_passphrase(passphrase)?;
    let mut salt = [0u8; SALT_LEN];
    fill(&mut salt)?;
    let mut nonce = [0u8; NONCE_LEN];
    fill(&mut nonce)?;
    seal_with_entropy(secret, passphrase, params, salt, nonce, kdf)
}

fn aead_seal_in_place(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], VaultError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt_in_place_detached(nonce.into(), aad, buf)
        .map(Into::into)
        .map_err(|_| VaultError::SealFailed)
}

fn aead_open_in_place(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), VaultError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    if cipher
        .decrypt_in_place_detached(nonce.into(), aad, buf, tag.into())
        .is_err()
    {
        buf.zeroize();
        return Err(VaultError::AuthenticationFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use neco_secp::SecretKey;

    use super::*;
    use crate::kat;
    use crate::kdf::test_support::{CountingDerivation, FixedKeyDerivation};
    use crate::kdf::Argon2idDerivation;
    use std::{format, vec};

    fn assert_zeroizing(_: &Zeroizing<[u8; 32]>) {}

    fn test_entropy(bytes: &mut [u8]) -> Result<(), VaultError> {
        use core::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let counter = NEXT.fetch_add(1, Ordering::Relaxed);
        let mut state = counter.wrapping_add(0x9e37_79b9_7f4a_7c15);
        for byte in bytes.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        if bytes.len() >= 8 {
            let start = bytes.len() - 8;
            bytes[start..].copy_from_slice(&counter.to_le_bytes());
        }
        Ok(())
    }

    fn secret_1() -> [u8; SECRET_LEN] {
        kat::unhex(kat::SECRET_1)
            .try_into()
            .expect("32-byte secret key")
    }

    fn salt() -> [u8; SALT_LEN] {
        kat::unhex(kat::SALT).try_into().expect("16-byte salt")
    }

    fn nonce() -> [u8; NONCE_LEN] {
        kat::unhex(kat::NONCE).try_into().expect("24-byte nonce")
    }

    fn test_params(m_cost: u32, t_cost: u32, p_cost: u32) -> KdfParams {
        KdfPolicy::TEST
            .admit(m_cost, t_cost, p_cost)
            .expect("parameters inside the test policy")
    }

    fn production_params(m_cost: u32, t_cost: u32, p_cost: u32) -> KdfParams {
        KdfPolicy::PRODUCTION
            .admit(m_cost, t_cost, p_cost)
            .expect("parameters inside the production policy")
    }

    fn failing_entropy(fail_on_call: usize) -> impl FnMut(&mut [u8]) -> Result<(), VaultError> {
        let mut calls = 0usize;
        move |buf: &mut [u8]| {
            calls += 1;
            if calls == fail_on_call {
                return Err(VaultError::RandomUnavailable);
            }
            buf.fill(0xa5);
            Ok(())
        }
    }

    #[test]
    fn kat_a_seal_matches_independent_reference() {
        let blob = seal_with_entropy(
            &secret_1(),
            kat::KAT_A_PASSPHRASE,
            production_params(65_536, 3, 4),
            salt(),
            nonce(),
            &Argon2idDerivation,
        )
        .expect("seal");
        assert_eq!(blob.to_vec(), kat::unhex(kat::KAT_A_BLOB));
    }

    #[test]
    fn kat_a_open_returns_secret_with_bip340_public_key() {
        let secret = open(
            &kat::unhex(kat::KAT_A_BLOB),
            kat::KAT_A_PASSPHRASE,
            &KdfPolicy::PRODUCTION,
            &Argon2idDerivation,
        )
        .expect("open");
        assert_eq!(secret[..], secret_1()[..]);
        let public_key = SecretKey::from_bytes(*secret)
            .expect("valid secret key")
            .xonly_public_key()
            .expect("public key");
        assert_eq!(public_key.to_hex().expect("public hex"), kat::PUBLIC_1);
    }

    #[test]
    fn kat_b_floor_parameters_and_utf8_passphrase() {
        let passphrase = kat::unhex(kat::KAT_B_PASSPHRASE);
        assert_eq!(passphrase, "pässwörd 🔑".as_bytes());
        assert_eq!(passphrase.len(), 15);

        let blob = seal_with_entropy(
            &secret_1(),
            &passphrase,
            production_params(19_456, 2, 1),
            salt(),
            nonce(),
            &Argon2idDerivation,
        )
        .expect("seal");
        assert_eq!(blob.to_vec(), kat::unhex(kat::KAT_B_BLOB));

        let secret = open(
            &blob,
            &passphrase,
            &KdfPolicy::PRODUCTION,
            &Argon2idDerivation,
        )
        .expect("open with the production policy");
        assert_eq!(secret[..], secret_1()[..]);
    }

    #[test]
    fn kat_c_matches_reference_and_production_policy_rejects_it() {
        let blob = seal_with_entropy(
            &secret_1(),
            kat::KAT_C_PASSPHRASE,
            test_params(64, 1, 1),
            salt(),
            nonce(),
            &Argon2idDerivation,
        )
        .expect("seal");
        assert_eq!(blob.to_vec(), kat::unhex(kat::KAT_C_BLOB));

        let secret = open(
            &blob,
            kat::KAT_C_PASSPHRASE,
            &KdfPolicy::TEST,
            &Argon2idDerivation,
        )
        .expect("open with the test policy");
        assert_eq!(secret[..], secret_1()[..]);

        let counting = CountingDerivation::new([0u8; KEY_LEN]);
        let error = open(
            &blob,
            kat::KAT_C_PASSPHRASE,
            &KdfPolicy::PRODUCTION,
            &counting,
        )
        .expect_err("the production policy must refuse the floor of the test policy");
        assert_eq!(
            error,
            VaultError::KdfParamsOutOfPolicy {
                m_cost: 64,
                t_cost: 1,
                p_cost: 1,
            }
        );
        assert_eq!(counting.calls(), 0);
    }

    #[test]
    fn xchacha20poly1305_matches_published_vector() {
        let key: [u8; KEY_LEN] = kat::unhex(kat::XCHACHA_KEY)
            .try_into()
            .expect("32-byte key");
        let nonce: [u8; NONCE_LEN] = kat::unhex(kat::XCHACHA_NONCE)
            .try_into()
            .expect("24-byte nonce");
        let aad = kat::unhex(kat::XCHACHA_AAD);
        let mut buf = kat::unhex(kat::XCHACHA_PLAINTEXT);
        assert_eq!(buf.len(), 114);

        let tag = aead_seal_in_place(&key, &nonce, &aad, &mut buf).expect("seal");
        assert_eq!(buf, kat::unhex(kat::XCHACHA_CIPHERTEXT));
        assert_eq!(tag.to_vec(), kat::unhex(kat::XCHACHA_TAG));

        aead_open_in_place(&key, &nonce, &aad, &mut buf, &tag).expect("open");
        assert_eq!(buf, kat::unhex(kat::XCHACHA_PLAINTEXT));
    }

    #[test]
    fn header_fields_sit_at_documented_offsets() {
        let mut distinct_salt = [0u8; SALT_LEN];
        for (index, byte) in distinct_salt.iter_mut().enumerate() {
            *byte = 0xa0 + index as u8;
        }
        let mut distinct_nonce = [0u8; NONCE_LEN];
        for (index, byte) in distinct_nonce.iter_mut().enumerate() {
            *byte = 0xc0 + index as u8;
        }
        let blob = seal_with_entropy(
            &secret_1(),
            b"passphrase",
            test_params(65, 2, 3),
            distinct_salt,
            distinct_nonce,
            &FixedKeyDerivation([7u8; KEY_LEN]),
        )
        .expect("seal");

        assert_eq!(blob.len(), 105);
        assert_eq!(blob[0..4], [0x4e, 0x56, 0x4c, 0x54]);
        assert_eq!(blob[4], 0x03);
        assert_eq!(blob[5..9], [0x41, 0x00, 0x00, 0x00]);
        assert_eq!(blob[9..13], [0x02, 0x00, 0x00, 0x00]);
        assert_eq!(blob[13..17], [0x03, 0x00, 0x00, 0x00]);
        assert_eq!(
            blob[17..33],
            [
                0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
                0xae, 0xaf
            ]
        );
        assert_eq!(
            blob[33..57],
            [
                0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
                0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7
            ]
        );
    }

    #[test]
    fn every_single_bit_flip_is_rejected_by_region() {
        let original = kat::unhex(kat::KAT_C_BLOB);
        assert_eq!(original.len(), ENCRYPTED_LEN);
        let in_policy = |m_cost: u32, t_cost: u32, p_cost: u32| {
            (64..=1_024).contains(&m_cost) && (1..=3).contains(&t_cost) && (1..=4).contains(&p_cost)
        };

        let mut accepted = 0usize;
        let mut magic = 0usize;
        let mut version = 0usize;
        let mut parameters_out_of_policy = 0usize;
        let mut parameters_in_policy = 0usize;
        let mut authenticated_region = 0usize;

        for index in 0..original.len() {
            for bit in 0..8u32 {
                let mut flipped = original.clone();
                flipped[index] ^= 1 << bit;
                let result = open(
                    &flipped,
                    kat::KAT_C_PASSPHRASE,
                    &KdfPolicy::TEST,
                    &Argon2idDerivation,
                );
                let error = match result {
                    Ok(_) => {
                        accepted += 1;
                        continue;
                    }
                    Err(error) => error,
                };
                match index {
                    0..=3 => {
                        magic += 1;
                        assert_eq!(error, VaultError::MalformedEncrypted(MalformedKind::Magic));
                    }
                    4 => {
                        version += 1;
                        assert_eq!(
                            error,
                            VaultError::UnsupportedEncryptedVersion {
                                found: 3 ^ (1u8 << bit)
                            }
                        );
                    }
                    5..=16 => {
                        let field = (index - 5) / 4;
                        let position = (((index - 5) % 4) * 8) as u32 + bit;
                        let mut values = [64u32, 1, 1];
                        values[field] ^= 1 << position;
                        if in_policy(values[0], values[1], values[2]) {
                            parameters_in_policy += 1;
                            assert_eq!(error, VaultError::AuthenticationFailed);
                        } else {
                            parameters_out_of_policy += 1;
                            assert_eq!(
                                error,
                                VaultError::KdfParamsOutOfPolicy {
                                    m_cost: values[0],
                                    t_cost: values[1],
                                    p_cost: values[2],
                                }
                            );
                        }
                    }
                    _ => {
                        authenticated_region += 1;
                        assert_eq!(error, VaultError::AuthenticationFailed);
                    }
                }
            }
        }

        assert_eq!(accepted, 0);
        assert_eq!(magic, 32);
        assert_eq!(version, 8);
        assert_eq!(parameters_out_of_policy, 85);
        assert_eq!(parameters_in_policy, 11);
        assert_eq!(authenticated_region, 704);

        let mut high_bit_of_m_cost = original.clone();
        high_bit_of_m_cost[8] ^= 0x80;
        assert_eq!(
            open(
                &high_bit_of_m_cost,
                kat::KAT_C_PASSPHRASE,
                &KdfPolicy::TEST,
                &Argon2idDerivation
            )
            .expect_err("m_cost 2147483712 is out of policy"),
            VaultError::KdfParamsOutOfPolicy {
                m_cost: 2_147_483_712,
                t_cost: 1,
                p_cost: 1,
            }
        );
        let mut low_bit_of_m_cost = original;
        low_bit_of_m_cost[5] ^= 0x01;
        assert_eq!(
            open(
                &low_bit_of_m_cost,
                kat::KAT_C_PASSPHRASE,
                &KdfPolicy::TEST,
                &Argon2idDerivation
            )
            .expect_err("m_cost 65 changes the derived key"),
            VaultError::AuthenticationFailed
        );
    }

    #[test]
    fn lengths_outside_the_format_are_structural_failures() {
        let original = kat::unhex(kat::KAT_C_BLOB);
        for length in 0..=300usize {
            let mut input = original.clone();
            input.resize(length, 0);

            let counting = CountingDerivation::new([0u8; KEY_LEN]);
            let result = open(&input, kat::KAT_C_PASSPHRASE, &KdfPolicy::TEST, &counting);
            if length == ENCRYPTED_LEN {
                let secret = open(
                    &input,
                    kat::KAT_C_PASSPHRASE,
                    &KdfPolicy::TEST,
                    &Argon2idDerivation,
                )
                .expect("the well-formed blob opens");
                assert_eq!(secret[..], secret_1()[..]);
                assert_eq!(counting.calls(), 1);
                continue;
            }
            let expected = if length == 64 {
                VaultError::LegacyFormat(crate::LegacyKind::V1Sha256)
            } else {
                VaultError::MalformedEncrypted(MalformedKind::Length {
                    expected: ENCRYPTED_LEN,
                    actual: length,
                })
            };
            assert_eq!(result.expect_err("length outside the format"), expected);
            assert_eq!(counting.calls(), 0, "length {length}");
        }

        let mut legacy_v2_shape = vec![0x11u8; 100];
        legacy_v2_shape[0] = 0x02;
        let counting = CountingDerivation::new([0u8; KEY_LEN]);
        assert_eq!(
            open(
                &legacy_v2_shape,
                kat::KAT_C_PASSPHRASE,
                &KdfPolicy::TEST,
                &counting
            )
            .expect_err("legacy shape"),
            VaultError::LegacyFormat(crate::LegacyKind::V2ScryptCbc)
        );
        assert_eq!(counting.calls(), 0);
    }

    #[test]
    fn structural_failures_never_run_the_kdf() {
        let well_formed = kat::unhex(kat::KAT_C_BLOB);
        let mut wrong_magic = well_formed.clone();
        wrong_magic[0] ^= 0x01;
        let mut wrong_version = well_formed.clone();
        wrong_version[4] = 0x02;
        let mut legacy_v2_shape = vec![0x11u8; 100];
        legacy_v2_shape[0] = 0x02;

        let cases: [(&[u8], &KdfPolicy, VaultError, usize); 7] = [
            (
                &well_formed[..104],
                &KdfPolicy::TEST,
                VaultError::MalformedEncrypted(MalformedKind::Length {
                    expected: ENCRYPTED_LEN,
                    actual: 104,
                }),
                0,
            ),
            (
                &wrong_magic,
                &KdfPolicy::TEST,
                VaultError::MalformedEncrypted(MalformedKind::Magic),
                0,
            ),
            (
                &wrong_version,
                &KdfPolicy::TEST,
                VaultError::UnsupportedEncryptedVersion { found: 2 },
                0,
            ),
            (
                &well_formed,
                &KdfPolicy::PRODUCTION,
                VaultError::KdfParamsOutOfPolicy {
                    m_cost: 64,
                    t_cost: 1,
                    p_cost: 1,
                },
                0,
            ),
            (
                &legacy_v2_shape,
                &KdfPolicy::TEST,
                VaultError::LegacyFormat(crate::LegacyKind::V2ScryptCbc),
                0,
            ),
            (
                &well_formed[..64],
                &KdfPolicy::TEST,
                VaultError::LegacyFormat(crate::LegacyKind::V1Sha256),
                0,
            ),
            (
                &well_formed,
                &KdfPolicy::TEST,
                VaultError::AuthenticationFailed,
                1,
            ),
        ];
        for (data, policy, expected, kdf_calls) in cases {
            let counting = CountingDerivation::new([0u8; KEY_LEN]);
            let error = open(data, kat::KAT_C_PASSPHRASE, policy, &counting)
                .expect_err("each input fails with the fixed key");
            assert_eq!(error, expected);
            assert_eq!(counting.calls(), kdf_calls, "{expected:?}");
        }

        let counting = CountingDerivation::new([0u8; KEY_LEN]);
        assert_eq!(
            open(&well_formed[..104], b"", &KdfPolicy::TEST, &counting)
                .expect_err("structure is checked before the passphrase"),
            VaultError::MalformedEncrypted(MalformedKind::Length {
                expected: ENCRYPTED_LEN,
                actual: 104,
            })
        );
        assert_eq!(
            open(&well_formed, b"", &KdfPolicy::TEST, &counting)
                .expect_err("the passphrase is checked before the key derivation"),
            VaultError::EmptyPassphrase
        );
        assert_eq!(counting.calls(), 0);
    }

    #[test]
    fn random_wrong_keys_never_authenticate() {
        let blob = kat::unhex(kat::KAT_A_BLOB);
        let header = &blob[..HEADER_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&blob[33..HEADER_LEN]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&blob[HEADER_LEN + SECRET_LEN..]);
        let ciphertext = &blob[HEADER_LEN..HEADER_LEN + SECRET_LEN];

        let correct_key: [u8; KEY_LEN] =
            kat::unhex(kat::KAT_A_KEY).try_into().expect("32-byte key");
        let mut control = [0u8; SECRET_LEN];
        control.copy_from_slice(ciphertext);
        aead_open_in_place(&correct_key, &nonce, header, &mut control, &tag)
            .expect("the independent key authenticates");
        assert_eq!(control, secret_1());

        let mut failures = 0usize;
        for _ in 0..10_000 {
            let mut key = [0u8; KEY_LEN];
            test_entropy(&mut key).expect("entropy");
            let mut buf = [0u8; SECRET_LEN];
            buf.copy_from_slice(ciphertext);
            match aead_open_in_place(&key, &nonce, header, &mut buf, &tag) {
                Err(VaultError::AuthenticationFailed) => failures += 1,
                other => panic!("a random key must fail authentication, got {other:?}"),
            }
        }
        assert_eq!(failures, 10_000);
    }

    #[test]
    fn wrong_passphrases_through_the_kdf_fail_authentication() {
        let blob = kat::unhex(kat::KAT_C_BLOB);
        open(
            &blob,
            kat::KAT_C_PASSPHRASE,
            &KdfPolicy::TEST,
            &Argon2idDerivation,
        )
        .expect("the correct passphrase authenticates");

        let mut failures = 0usize;
        for index in 0..10_000 {
            let passphrase = format!("wrong-{index}");
            match open(
                &blob,
                passphrase.as_bytes(),
                &KdfPolicy::TEST,
                &Argon2idDerivation,
            ) {
                Err(VaultError::AuthenticationFailed) => failures += 1,
                other => panic!("{passphrase} must fail authentication, got {other:?}"),
            }
        }
        assert_eq!(failures, 10_000);
    }

    #[test]
    fn repeated_seal_authenticates_only_the_correct_passphrase() {
        let params = test_params(64, 1, 1);
        let secret = [0x22u8; SECRET_LEN];
        let mut failures = 0usize;
        for _ in 0..2_000 {
            let blob = seal(
                &secret,
                b"correct",
                params,
                &Argon2idDerivation,
                &mut test_entropy,
            )
            .expect("seal");
            let opened = open(&blob, b"correct", &KdfPolicy::TEST, &Argon2idDerivation)
                .expect("the correct passphrase authenticates");
            assert_eq!(opened[..], secret[..]);
            match open(&blob, b"wrong", &KdfPolicy::TEST, &Argon2idDerivation) {
                Err(VaultError::AuthenticationFailed) => failures += 1,
                other => panic!("the wrong passphrase must fail authentication, got {other:?}"),
            }
        }
        assert_eq!(failures, 2_000);
    }

    #[test]
    fn authentication_failure_zeroes_the_buffer() {
        let blob = kat::unhex(kat::KAT_A_BLOB);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&blob[33..HEADER_LEN]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&blob[HEADER_LEN + SECRET_LEN..]);
        let mut buf = [0u8; SECRET_LEN];
        buf.copy_from_slice(&blob[HEADER_LEN..HEADER_LEN + SECRET_LEN]);
        assert_ne!(buf, [0u8; SECRET_LEN]);

        let error = aead_open_in_place(
            &[0x99u8; KEY_LEN],
            &nonce,
            &blob[..HEADER_LEN],
            &mut buf,
            &tag,
        )
        .expect_err("a wrong key must fail");
        assert_eq!(error, VaultError::AuthenticationFailed);
        assert_eq!(buf, [0u8; SECRET_LEN]);
    }

    #[test]
    fn opened_secret_has_zeroizing_type() {
        let secret = open(
            &kat::unhex(kat::KAT_C_BLOB),
            kat::KAT_C_PASSPHRASE,
            &KdfPolicy::TEST,
            &Argon2idDerivation,
        )
        .expect("open");
        assert_zeroizing(&secret);
    }

    #[test]
    fn seal_draws_fresh_salt_and_nonce() {
        let kdf = FixedKeyDerivation([7u8; KEY_LEN]);
        let mut salts = HashSet::new();
        let mut nonces = HashSet::new();
        for _ in 0..4_096 {
            let blob = seal(
                &secret_1(),
                b"passphrase",
                test_params(64, 1, 1),
                &kdf,
                &mut test_entropy,
            )
            .expect("seal");
            salts.insert(blob[17..33].to_vec());
            nonces.insert(blob[33..57].to_vec());
        }
        assert_eq!(salts.len(), 4_096);
        assert_eq!(nonces.len(), 4_096);
    }

    #[test]
    fn seal_fails_closed_when_entropy_fails() {
        let kdf = FixedKeyDerivation([7u8; KEY_LEN]);
        for fail_on_call in [1, 2] {
            let mut fill = failing_entropy(fail_on_call);
            let result = seal(
                &secret_1(),
                b"passphrase",
                test_params(64, 1, 1),
                &kdf,
                &mut fill,
            );
            assert_eq!(
                result,
                Err(VaultError::RandomUnavailable),
                "call {fail_on_call}"
            );
        }

        let mut fill = failing_entropy(3);
        let blob = seal(
            &secret_1(),
            b"passphrase",
            test_params(64, 1, 1),
            &kdf,
            &mut fill,
        )
        .expect("two draws succeed when the third would fail");
        assert_eq!(blob[17..33], [0xa5u8; SALT_LEN]);
    }

    #[test]
    fn passphrase_length_and_bytes() {
        let kdf = FixedKeyDerivation([5u8; KEY_LEN]);
        let seal_with = |passphrase: &[u8]| {
            seal_with_entropy(
                &secret_1(),
                passphrase,
                test_params(64, 1, 1),
                salt(),
                nonce(),
                &kdf,
            )
        };
        assert_eq!(seal_with(b""), Err(VaultError::EmptyPassphrase));
        assert_eq!(
            seal_with(&[b'a'; 1_025]),
            Err(VaultError::PassphraseTooLong { max: 1_024 })
        );
        assert!(seal_with(&[b'a'; 1_024]).is_ok());

        let odd_bytes = [0xff, 0x00, 0xfe];
        let blob = seal_with_entropy(
            &secret_1(),
            &odd_bytes,
            test_params(64, 1, 1),
            salt(),
            nonce(),
            &Argon2idDerivation,
        )
        .expect("seal with bytes that are not UTF-8 and contain NUL");
        let opened = open(&blob, &odd_bytes, &KdfPolicy::TEST, &Argon2idDerivation)
            .expect("open with the same bytes");
        assert_eq!(opened[..], secret_1()[..]);
        assert_eq!(
            open(
                &blob,
                &odd_bytes[..1],
                &KdfPolicy::TEST,
                &Argon2idDerivation
            )
            .expect_err("a prefix of the passphrase is another passphrase"),
            VaultError::AuthenticationFailed
        );

        let well_formed = kat::unhex(kat::KAT_C_BLOB);
        assert_eq!(
            open(&well_formed, b"", &KdfPolicy::TEST, &kdf).expect_err("empty passphrase"),
            VaultError::EmptyPassphrase
        );
        assert_eq!(
            open(&well_formed, &[b'a'; 1_025], &KdfPolicy::TEST, &kdf)
                .expect_err("passphrase over the limit"),
            VaultError::PassphraseTooLong { max: 1_024 }
        );
    }

    #[test]
    fn random_inputs_never_panic_or_authenticate() {
        let kdf = FixedKeyDerivation([9u8; KEY_LEN]);
        let random_byte = || {
            let mut byte = [0u8; 1];
            test_entropy(&mut byte).expect("entropy");
            byte[0]
        };

        for _ in 0..20_000 {
            let length = usize::from(u16::from_le_bytes([random_byte(), random_byte()])) % 301;
            let mut data = vec![0u8; length];
            test_entropy(&mut data).expect("entropy");
            let error = open(&data, b"passphrase", &KdfPolicy::TEST, &kdf)
                .expect_err("random bytes must not authenticate");
            assert!(
                matches!(
                    error,
                    VaultError::MalformedEncrypted(_)
                        | VaultError::LegacyFormat(_)
                        | VaultError::UnsupportedEncryptedVersion { .. }
                        | VaultError::KdfParamsOutOfPolicy { .. }
                        | VaultError::AuthenticationFailed
                ),
                "{error:?}"
            );
        }

        for _ in 0..5_000 {
            let mut data = vec![0u8; ENCRYPTED_LEN];
            test_entropy(&mut data).expect("entropy");
            data[..4].copy_from_slice(b"NVLT");
            data[4] = 3;
            let m_cost = 64 + u32::from(u16::from_le_bytes([random_byte(), random_byte()])) % 961;
            let t_cost = 1 + u32::from(random_byte()) % 3;
            let p_cost = 1 + u32::from(random_byte()) % 4;
            data[5..9].copy_from_slice(&m_cost.to_le_bytes());
            data[9..13].copy_from_slice(&t_cost.to_le_bytes());
            data[13..17].copy_from_slice(&p_cost.to_le_bytes());
            assert_eq!(
                open(&data, b"passphrase", &KdfPolicy::TEST, &kdf)
                    .expect_err("a random body must not authenticate"),
                VaultError::AuthenticationFailed
            );
        }
    }
}
