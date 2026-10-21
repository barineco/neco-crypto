use crate::LegacyKind;
#[cfg(all(test, feature = "legacy-migration"))]
use alloc::vec::Vec;

const V2_LEN: usize = 100;
const V2_VERSION: u8 = 0x02;
const V1_LEN: usize = 64;

pub(crate) fn classify(data: &[u8]) -> Option<LegacyKind> {
    if data.len() == V2_LEN && data[0] == V2_VERSION {
        Some(LegacyKind::V2ScryptCbc)
    } else if data.len() == V1_LEN {
        Some(LegacyKind::V1Sha256)
    } else {
        None
    }
}

#[cfg(all(feature = "legacy-migration", feature = "getrandom"))]
pub use migration::migrate_legacy_encrypted;
#[cfg(feature = "legacy-migration")]
pub use migration::migrate_legacy_encrypted_with_rng;

#[cfg(feature = "legacy-migration")]
mod migration {
    use aes::Aes256;
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    use neco_secp::{SecretKey, XOnlyPublicKey};
    use neco_sha2::Sha256;
    use zeroize::{Zeroize, Zeroizing};

    use super::{classify, V1_LEN, V2_LEN};
    use crate::kdf::{Argon2idDerivation, KdfParams, KdfPolicy, KeyDerivation, KEY_LEN};
    #[cfg(feature = "getrandom")]
    use crate::os_entropy;
    use crate::sealed::{self, ENCRYPTED_LEN, SECRET_LEN};
    use crate::{LegacyKind, MalformedKind, VaultError};
    use alloc::vec::Vec;

    const V2_LOG_N: u8 = 15;
    const V2_R: u8 = 8;
    const V2_P: u8 = 1;
    const IV_LEN: usize = 16;
    const LEGACY_CIPHERTEXT_LEN: usize = 48;

    type Sealed = Result<[u8; ENCRYPTED_LEN], VaultError>;

    fn legacy_params_error() -> VaultError {
        VaultError::MalformedEncrypted(MalformedKind::LegacyParams)
    }

    pub(super) fn decrypt(
        kind: LegacyKind,
        data: &[u8],
        passphrase: &[u8],
    ) -> Result<Zeroizing<[u8; SECRET_LEN]>, VaultError> {
        let expected = match kind {
            LegacyKind::V2ScryptCbc => V2_LEN,
            LegacyKind::V1Sha256 => V1_LEN,
        };
        if data.len() != expected {
            return Err(VaultError::MalformedEncrypted(MalformedKind::Length {
                expected,
                actual: data.len(),
            }));
        }

        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        let (iv, ciphertext) = match kind {
            LegacyKind::V2ScryptCbc => {
                if (data[1], data[2], data[3]) != (V2_LOG_N, V2_R, V2_P) {
                    return Err(legacy_params_error());
                }
                key = crate::legacy_kdf::derive(passphrase, &data[4..36])?;
                (&data[36..52], &data[52..])
            }
            LegacyKind::V1Sha256 => {
                let mut digest = Sha256::digest(passphrase)?;
                key.copy_from_slice(&digest);
                digest.as_mut_slice().zeroize();
                (&data[..IV_LEN], &data[IV_LEN..])
            }
        };

        let mut iv_bytes = [0u8; IV_LEN];
        iv_bytes.copy_from_slice(iv);
        let mut buf = Zeroizing::new([0u8; LEGACY_CIPHERTEXT_LEN]);
        buf.copy_from_slice(ciphertext);
        let plaintext = cbc::Decryptor::<Aes256>::new((&*key).into(), (&iv_bytes).into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf[..])
            .map_err(|_| VaultError::AuthenticationFailed)?;
        if plaintext.len() != SECRET_LEN {
            return Err(VaultError::AuthenticationFailed);
        }
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        secret.copy_from_slice(plaintext);
        Ok(secret)
    }

    fn public_key_of(secret: &[u8; SECRET_LEN]) -> Result<XOnlyPublicKey, VaultError> {
        let key = SecretKey::from_bytes(*secret).map_err(|error| match error {
            neco_secp::SecpError::InvalidSecretKey => VaultError::AuthenticationFailed,
            error => VaultError::Crypto(error),
        })?;
        key.xonly_public_key().map_err(VaultError::Crypto)
    }

    pub(super) fn migrate_with(
        legacy: &[u8],
        old_passphrase: &[u8],
        new_passphrase: &[u8],
        kdf: &dyn KeyDerivation,
        policy: &KdfPolicy,
        seal: &mut dyn FnMut(&[u8; SECRET_LEN], &[u8]) -> Sealed,
    ) -> Result<Vec<u8>, VaultError> {
        let kind = classify(legacy).ok_or(VaultError::NotLegacyFormat)?;
        sealed::check_passphrase(new_passphrase)?;

        let plaintext = decrypt(kind, legacy, old_passphrase)?;
        let legacy_public = public_key_of(&plaintext)?;

        let blob = seal(&plaintext, new_passphrase)?;
        let reopened = match sealed::open(&blob, new_passphrase, policy, kdf) {
            Ok(reopened) => reopened,
            Err(VaultError::AuthenticationFailed) => {
                return Err(VaultError::MigrationVerificationFailed)
            }
            Err(error) => return Err(error),
        };
        if public_key_of(&reopened)? != legacy_public {
            return Err(VaultError::MigrationVerificationFailed);
        }
        crate::bytes(&blob)
    }

    /// 旧形式 ( v1 の 64 バイト、v2 の 100 バイト ) の暗号化データを、v3 の暗号化データへ変換します。入力と出力は、どちらもメモリ上のバイト列です。
    /// 旧形式の復号の失敗 ( パディング、平文の長さ、秘密鍵の範囲 ) は、すべて `AuthenticationFailed` になります。旧パスフレーズには、空の値と任意の長さの値を渡せます。新パスフレーズには、エクスポートと同じ条件 ( 空でなく、1,024 バイト以下 ) が適用されます。
    /// 変換後の暗号化データは新パスフレーズで開き直して公開鍵を照合し、認証に失敗した場合と公開鍵が一致しない場合は `MigrationVerificationFailed` で失敗します。また、旧形式と一致しない入力では、v3 の暗号化データを含めて `NotLegacyFormat` を返します。
    #[cfg(feature = "getrandom")]
    pub fn migrate_legacy_encrypted(
        legacy: &[u8],
        old_passphrase: &[u8],
        new_passphrase: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        migrate_legacy_encrypted_with_rng(legacy, old_passphrase, new_passphrase, &mut os_entropy)
    }

    pub fn migrate_legacy_encrypted_with_rng<F>(
        legacy: &[u8],
        old_passphrase: &[u8],
        new_passphrase: &[u8],
        fill: &mut F,
    ) -> Result<Vec<u8>, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), VaultError>,
    {
        migrate_with(
            legacy,
            old_passphrase,
            new_passphrase,
            &Argon2idDerivation,
            &KdfPolicy::PRODUCTION,
            &mut |secret, passphrase| {
                sealed::seal(
                    secret,
                    passphrase,
                    KdfParams::DEFAULT,
                    &Argon2idDerivation,
                    fill,
                )
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[cfg(feature = "legacy-migration")]
    use std::cell::Cell;

    #[cfg(feature = "legacy-migration")]
    use aes::Aes256;
    #[cfg(feature = "legacy-migration")]
    use cbc::cipher::block_padding::Pkcs7;
    #[cfg(feature = "legacy-migration")]
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    #[cfg(feature = "legacy-migration")]
    use neco_sha2::Sha256;

    #[cfg(feature = "legacy-migration")]
    use crate::kdf::test_support::FixedKeyDerivation;
    #[cfg(feature = "legacy-migration")]
    use crate::kdf::{KdfPolicy, KEY_LEN, SALT_LEN};
    #[cfg(feature = "legacy-migration")]
    use crate::sealed::{seal_with_entropy, ENCRYPTED_LEN, SECRET_LEN};
    #[cfg(feature = "legacy-migration")]
    use crate::{kat, MalformedKind, VaultError};

    #[cfg(feature = "legacy-migration")]
    fn legacy_v1_blob(passphrase: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let key = Sha256::digest(passphrase).expect("passphrase within SHA-256 limit");
        let iv = [0x70u8; 16];
        let mut buf = plaintext.to_vec();
        let length = buf.len();
        buf.resize(length + 16, 0);
        let ciphertext = cbc::Encryptor::<Aes256>::new((&key).into(), &iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, length)
            .expect("buffer holds the padded plaintext");
        let mut blob = iv.to_vec();
        blob.extend_from_slice(ciphertext);
        blob
    }

    #[test]
    fn classification_follows_length_and_first_byte() {
        let mut v2_shape = vec![0x11u8; 100];
        v2_shape[0] = 0x02;
        assert_eq!(classify(&v2_shape), Some(LegacyKind::V2ScryptCbc));

        let mut other_version = vec![0x11u8; 100];
        other_version[0] = 0x01;
        assert_eq!(classify(&other_version), None);

        assert_eq!(classify(&[0x01u8; 64]), Some(LegacyKind::V1Sha256));
        assert_eq!(classify(&[0x02u8; 64]), Some(LegacyKind::V1Sha256));

        assert_eq!(classify(&[0x02u8; 105]), None);
        assert_eq!(classify(&[0x4eu8; 105]), None);
        assert_eq!(classify(&[0x02u8; 99]), None);
        assert_eq!(classify(&[0x02u8; 101]), None);
        assert_eq!(classify(&[]), None);
    }

    #[cfg(feature = "legacy-migration")]
    #[test]
    fn v2_with_other_scrypt_parameters_is_rejected_before_scrypt() {
        for (log_n, r, p) in [(40u8, 8u8, 1u8), (15, 8, 255)] {
            let mut data = vec![0x11u8; 100];
            data[..4].copy_from_slice(&[0x02, log_n, r, p]);
            let error = migration::decrypt(LegacyKind::V2ScryptCbc, &data, b"legacy passphrase")
                .expect_err("parameters other than the legacy ones must be refused");
            assert_eq!(
                error,
                VaultError::MalformedEncrypted(MalformedKind::LegacyParams),
                "log_n {log_n}, r {r}, p {p}"
            );
        }
    }

    #[cfg(feature = "legacy-migration")]
    #[test]
    fn migration_reports_verification_failure() {
        let legacy = kat::unhex(kat::LEGACY_V1_BLOB);
        let fixed = FixedKeyDerivation([3u8; KEY_LEN]);
        let params = KdfPolicy::TEST.admit(64, 1, 1).expect("parameters");
        let mut seal_secret = |secret: &[u8; SECRET_LEN], passphrase: &[u8]| {
            seal_with_entropy(
                secret,
                passphrase,
                params,
                [1u8; SALT_LEN],
                [2u8; 24],
                &fixed,
            )
        };
        let migrated = migration::migrate_with(
            &legacy,
            kat::LEGACY_PASSPHRASE,
            b"new passphrase",
            &fixed,
            &KdfPolicy::TEST,
            &mut seal_secret,
        )
        .expect("sealing the migrated secret verifies");
        assert_eq!(migrated.len(), ENCRYPTED_LEN);

        let mut seal_foreign_secret = |_: &[u8; SECRET_LEN], passphrase: &[u8]| {
            seal_with_entropy(
                &[0x33u8; SECRET_LEN],
                passphrase,
                params,
                [1u8; SALT_LEN],
                [2u8; 24],
                &fixed,
            )
        };
        let error = migration::migrate_with(
            &legacy,
            kat::LEGACY_PASSPHRASE,
            b"new passphrase",
            &fixed,
            &KdfPolicy::TEST,
            &mut seal_foreign_secret,
        )
        .expect_err("another secret key must not verify");
        assert_eq!(error, VaultError::MigrationVerificationFailed);

        let mut seal_corrupted = |secret: &[u8; SECRET_LEN],
                                  passphrase: &[u8]|
         -> Result<[u8; ENCRYPTED_LEN], VaultError> {
            let mut blob = seal_secret(secret, passphrase)?;
            blob[ENCRYPTED_LEN - 1] ^= 0x01;
            Ok(blob)
        };
        let error = migration::migrate_with(
            &legacy,
            kat::LEGACY_PASSPHRASE,
            b"new passphrase",
            &fixed,
            &KdfPolicy::TEST,
            &mut seal_corrupted,
        )
        .expect_err("a blob that does not open must not verify");
        assert_eq!(error, VaultError::MigrationVerificationFailed);
    }

    #[cfg(feature = "legacy-migration")]
    #[test]
    fn every_legacy_decryption_failure_is_authentication_failed() {
        let passphrase = b"legacy passphrase";
        let fixed = FixedKeyDerivation([3u8; KEY_LEN]);
        let sealed_calls = Cell::new(0usize);
        let params = KdfPolicy::TEST.admit(64, 1, 1).expect("parameters");
        let mut seal_secret = |secret: &[u8; SECRET_LEN], passphrase: &[u8]| {
            sealed_calls.set(sealed_calls.get() + 1);
            seal_with_entropy(
                secret,
                passphrase,
                params,
                [1u8; SALT_LEN],
                [2u8; 24],
                &fixed,
            )
        };
        let mut migrate = |legacy: &[u8], old_passphrase: &[u8]| {
            migration::migrate_with(
                legacy,
                old_passphrase,
                b"new passphrase",
                &fixed,
                &KdfPolicy::TEST,
                &mut seal_secret,
            )
        };

        let valid_secret = [0x22u8; SECRET_LEN];
        assert_eq!(
            migrate(&legacy_v1_blob(passphrase, &valid_secret), passphrase)
                .expect("a valid secret migrates")
                .len(),
            ENCRYPTED_LEN
        );
        assert_eq!(sealed_calls.get(), 1);

        let failing = [
            legacy_v1_blob(passphrase, &[0u8; SECRET_LEN]),
            legacy_v1_blob(passphrase, &[0xffu8; SECRET_LEN]),
            legacy_v1_blob(passphrase, &[0x22u8; SECRET_LEN + 1]),
            legacy_v1_blob(passphrase, &[0x22u8; 47]),
            legacy_v1_blob(passphrase, &valid_secret),
        ];
        for (index, blob) in failing.iter().enumerate() {
            let old_passphrase: &[u8] = if index == failing.len() - 1 {
                b"another passphrase"
            } else {
                passphrase
            };
            assert_eq!(
                migrate(blob, old_passphrase).expect_err("the legacy plaintext is not usable"),
                VaultError::AuthenticationFailed,
                "case {index}"
            );
        }
        assert_eq!(sealed_calls.get(), 1);
    }
}
