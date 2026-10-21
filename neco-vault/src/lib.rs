//! `neco-secp` の上に構築した、メモリ上の署名用保管庫 ( vault ) です。

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg(feature = "alloc")]

extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(test)]
use alloc::{format, string::ToString, vec};
#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};
#[cfg(feature = "security-hardening")]
use core::hint::spin_loop;

#[cfg(feature = "nip17")]
use neco_secp::Rumor;
#[cfg(feature = "nostr")]
use neco_secp::{nostr, SignedEvent, UnsignedEvent};
use neco_secp::{SecpError, SecretKey, XOnlyPublicKey};
#[cfg(feature = "encrypted")]
use zeroize::Zeroizing;

#[cfg(feature = "encrypted")]
use kdf::{Argon2idDerivation, KdfParams, KdfPolicy, KeyDerivation};

#[cfg(all(test, feature = "encrypted"))]
mod kat;
#[cfg(feature = "encrypted")]
mod kdf;
#[cfg(feature = "encrypted")]
mod legacy;
#[cfg(feature = "legacy-migration")]
mod legacy_kdf;
#[cfg(feature = "encrypted")]
mod sealed;

#[cfg(all(feature = "legacy-migration", feature = "getrandom"))]
pub use legacy::migrate_legacy_encrypted;
#[cfg(feature = "legacy-migration")]
pub use legacy::migrate_legacy_encrypted_with_rng;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityConfig {
    pub enable_constant_time: bool,
    pub enable_random_delay: bool,
    pub enable_dummy_operations: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_constant_time: true,
            enable_random_delay: false,
            enable_dummy_operations: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VaultConfig {
    pub cache_timeout_seconds: u64,
    pub security: SecurityConfig,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            cache_timeout_seconds: 300,
            security: SecurityConfig::default(),
        }
    }
}

/// `Vault` の操作が返す失敗です。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultError {
    /// ラベルが既に存在します。
    DuplicateLabel,
    /// ラベルが存在しません。
    MissingLabel,
    /// アクティブアカウントがありません。
    NoActiveAccount,
    /// `neco-secp` の失敗です。`SecpError` を返すクロージャの失敗も含みます。
    Crypto(SecpError),
    /// `VaultError` を返す系列の通常形で、OS の乱数源が失敗しました。
    RandomUnavailable,
    /// パスフレーズが空です。
    EmptyPassphrase,
    /// パスフレーズが 1,024 バイトの上限を超えています。
    PassphraseTooLong { max: usize },
    /// 暗号化データの構造が不正です。
    MalformedEncrypted(MalformedKind),
    /// 先頭 4 バイトの識別子 `magic` が一致し、版が 3 以外です。
    UnsupportedEncryptedVersion { found: u8 },
    /// 鍵導出のパラメータがポリシーの範囲を外れています。各フィールドには、暗号化データに書かれた値が入ります。
    KdfParamsOutOfPolicy {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    },
    /// 旧形式の暗号化データです。
    LegacyFormat(LegacyKind),
    /// 移行の入力が、どちらの旧形式の形とも一致しません。
    NotLegacyFormat,
    /// 誤ったパスフレーズ、または改ざんされたデータです。
    AuthenticationFailed,
    /// 認証後の平文が、有効な秘密鍵の範囲を外れています。
    InvalidSecretKey,
    /// 認証付き暗号 ( AEAD ) の暗号化に失敗しました。
    SealFailed,
    /// 移行した暗号化データの検証に失敗しました。
    MigrationVerificationFailed,
    /// 要求した容量が `isize::MAX` バイトを超えます。
    CapacityOverflow { required: usize },
    /// `try_reserve_exact` で、要求した容量を確保できませんでした。
    AllocationFailed { required: usize },
    /// `VaultError` を返すクロージャに、乱数源が欠けています。
    EntropyRequired,
    /// エクスポート、インポート、移行の Argon2id の鍵導出の失敗です。
    #[cfg(feature = "encrypted")]
    Argon2(neco_argon2::Argon2Error),
    /// エポック鍵の導出とグループのエポックの更新で、鍵導出関数 HKDF の展開が失敗しました。
    #[cfg(feature = "dm-epoch")]
    Hkdf(neco_sha2::HkdfError),
    /// 旧形式の鍵導出に渡した入力が、SHA-256 の入力の上限を超えました。
    #[cfg(feature = "legacy-migration")]
    Hash(neco_sha2::Sha256Error),
}

/// 暗号化データの構造の失敗の種別です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedKind {
    /// `magic` が一致しません。
    Magic,
    /// 長さが形式と一致しません。
    Length { expected: usize, actual: usize },
    /// エポックの暗号文、または暗号化したグループ鍵が最小の長さより短い入力です。
    TooShort { minimum: usize, actual: usize },
    /// 内容の形が不正です。
    Payload,
    /// 旧 v2 の scrypt のコストが、移行で受理する値と異なります。
    LegacyParams,
}

/// 旧形式の種別です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyKind {
    /// 先頭に初期化ベクトル ( IV ) を置く 64 バイトの形式です。鍵は SHA-256 で導出します。
    V1Sha256,
    /// 先頭バイトが `0x02` の 100 バイトの形式です。鍵は、パスフレーズを入力とする鍵導出関数 scrypt で導出します。
    V2ScryptCbc,
}

/// 走査タグを伴うギフトラップの結果です。
#[cfg(feature = "nip17")]
pub struct SealedDmResult {
    pub event: SignedEvent,
    pub scanning_tag: [u8; 16],
}

impl core::fmt::Display for MalformedKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Magic => f.write_str("unrecognized magic"),
            Self::Length { expected, actual } => {
                write!(f, "length {actual}, expected {expected}")
            }
            Self::TooShort { minimum, actual } => {
                write!(f, "length {actual}, minimum {minimum}")
            }
            Self::Payload => f.write_str("invalid payload"),
            Self::LegacyParams => f.write_str("unsupported legacy key derivation parameters"),
        }
    }
}

impl core::fmt::Display for LegacyKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::V1Sha256 => f.write_str("v1, SHA-256 key"),
            Self::V2ScryptCbc => f.write_str("v2, scrypt key"),
        }
    }
}

impl core::fmt::Display for VaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateLabel => f.write_str("duplicate label"),
            Self::MissingLabel => f.write_str("missing label"),
            Self::NoActiveAccount => f.write_str("no active account"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::RandomUnavailable => f.write_str("random number generator unavailable"),
            Self::EmptyPassphrase => f.write_str("passphrase is empty"),
            Self::PassphraseTooLong { max } => {
                write!(f, "passphrase is longer than {max} bytes")
            }
            Self::MalformedEncrypted(kind) => write!(f, "malformed encrypted data: {kind}"),
            Self::UnsupportedEncryptedVersion { found } => {
                write!(f, "unsupported encrypted format version {found}")
            }
            Self::KdfParamsOutOfPolicy {
                m_cost,
                t_cost,
                p_cost,
            } => write!(
                f,
                "key derivation parameters out of policy ( m_cost={m_cost}, t_cost={t_cost}, p_cost={p_cost} )"
            ),
            Self::LegacyFormat(kind) => {
                write!(f, "legacy encrypted format ( {kind} )")?;
                #[cfg(feature = "legacy-migration")]
                f.write_str("; convert it with migrate_legacy_encrypted")?;
                Ok(())
            }
            Self::NotLegacyFormat => f.write_str("data is not in a legacy encrypted format"),
            Self::AuthenticationFailed => {
                f.write_str("authentication failed: wrong passphrase or modified data")
            }
            Self::InvalidSecretKey => f.write_str("decrypted data is not a valid secret key"),
            Self::SealFailed => f.write_str("encryption failed"),
            Self::MigrationVerificationFailed => f.write_str("migrated data failed verification"),
            Self::CapacityOverflow { required } => write!(f, "capacity exceeds addressable limit: {required}"),
            Self::AllocationFailed { required } => write!(f, "allocation failed for {required} units"),
            Self::EntropyRequired => f.write_str("an entropy provider is required"),
            #[cfg(feature = "encrypted")]
            Self::Argon2(error) => write!(f, "{error}"),
            #[cfg(feature = "dm-epoch")]
            Self::Hkdf(error) => write!(f, "{error}"),
            #[cfg(feature = "legacy-migration")]
            Self::Hash(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for VaultError {}

#[cfg(feature = "legacy-migration")]
impl From<neco_sha2::Sha256Error> for VaultError {
    fn from(value: neco_sha2::Sha256Error) -> Self {
        Self::Hash(value)
    }
}

impl From<SecpError> for VaultError {
    fn from(value: SecpError) -> Self {
        Self::Crypto(value)
    }
}

fn vector<T>(required: usize) -> Result<Vec<T>, VaultError> {
    let bytes = required
        .checked_mul(core::mem::size_of::<T>())
        .ok_or(VaultError::CapacityOverflow { required })?;
    if bytes > isize::MAX as usize {
        return Err(VaultError::CapacityOverflow { required });
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(required)
        .map_err(|_| VaultError::AllocationFailed { required })?;
    Ok(values)
}

fn text(value: &str) -> Result<String, VaultError> {
    let required = value.len();
    if required > isize::MAX as usize {
        return Err(VaultError::CapacityOverflow { required });
    }
    let mut output = String::new();
    output
        .try_reserve_exact(required)
        .map_err(|_| VaultError::AllocationFailed { required })?;
    output.push_str(value);
    Ok(output)
}

#[cfg(any(feature = "encrypted", feature = "dm-epoch"))]
fn bytes(value: &[u8]) -> Result<Vec<u8>, VaultError> {
    let mut output = vector(value.len())?;
    output.extend_from_slice(value);
    Ok(output)
}

#[cfg(feature = "dm-epoch")]
fn combined_capacity(left: usize, right: usize) -> Result<usize, VaultError> {
    match left.checked_add(right) {
        Some(required) if required <= isize::MAX as usize => Ok(required),
        Some(required) => Err(VaultError::CapacityOverflow { required }),
        None => Err(VaultError::CapacityOverflow {
            required: usize::MAX,
        }),
    }
}

fn entry_index(entries: &[(String, Entry)], label: &str) -> Option<usize> {
    entries.iter().position(|(stored, _)| stored == label)
}

struct Entry {
    secret: SecretKey,
    last_used_unix_seconds: u64,
}

impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entry")
            .field("secret", &"<redacted>")
            .field("last_used_unix_seconds", &self.last_used_unix_seconds)
            .finish()
    }
}

#[cfg(feature = "security-hardening")]
fn apply_random_delay<F>(fill: &mut F) -> Result<(), VaultError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    let mut byte = [0u8; 1];
    fill(&mut byte).map_err(VaultError::from)?;
    let loops = 64 + usize::from(byte[0] & 0x3f);
    for _ in 0..loops {
        spin_loop();
    }
    Ok(())
}

#[cfg(feature = "security-hardening")]
fn apply_dummy_sign(secret: &SecretKey) -> Result<(), VaultError> {
    secret
        .sign_schnorr_prehash_with_aux([0x5a; 32], [0u8; 32])
        .map(|_| ())
        .map_err(VaultError::from)
}

#[cfg(all(feature = "security-hardening", feature = "nip04"))]
fn apply_dummy_nip04(secret: &SecretKey) -> Result<(), VaultError> {
    let peer = secret.xonly_public_key().map_err(VaultError::from)?;
    neco_secp::nip04::encrypt_with_rng(secret, &peer, "", Some([0u8; 16]), &mut |_| {
        Err(SecpError::EntropyRequired)
    })
    .map(|_| ())
    .map_err(VaultError::from)
}

#[cfg(all(feature = "security-hardening", feature = "nip44"))]
fn apply_dummy_nip44(secret: &SecretKey) -> Result<(), VaultError> {
    let peer = secret.xonly_public_key().map_err(VaultError::from)?;
    let conversation_key =
        neco_secp::nip44::get_conversation_key(secret, &peer).map_err(VaultError::from)?;
    neco_secp::nip44::encrypt_with_rng("_", &conversation_key, Some([0u8; 32]), &mut |_| {
        Err(SecpError::EntropyRequired)
    })
    .map(|_| ())
    .map_err(VaultError::from)
}

#[cfg(feature = "security-hardening")]
fn apply_security_before<F>(
    security: SecurityConfig,
    secret: &SecretKey,
    fill: &mut F,
) -> Result<(), VaultError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    if security.enable_dummy_operations {
        apply_dummy_sign(secret)?;
    }
    if security.enable_random_delay {
        apply_random_delay(fill)?;
    }
    if security.enable_constant_time {
        core::hint::black_box(secret.to_bytes());
    }
    Ok(())
}

#[cfg(feature = "security-hardening")]
fn apply_security_after<F>(
    security: SecurityConfig,
    secret: &SecretKey,
    fill: &mut F,
) -> Result<(), VaultError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    if security.enable_constant_time {
        core::hint::black_box(secret.to_bytes());
    }
    if security.enable_dummy_operations {
        apply_dummy_sign(secret)?;
    }
    if security.enable_random_delay {
        apply_random_delay(fill)?;
    }
    Ok(())
}

#[cfg(feature = "getrandom")]
fn secp_os_entropy(buf: &mut [u8]) -> Result<(), SecpError> {
    getrandom::getrandom(buf).map_err(|_| SecpError::RandomUnavailable)
}

#[cfg(all(
    feature = "getrandom",
    any(feature = "encrypted", feature = "dm-epoch")
))]
fn os_entropy(buf: &mut [u8]) -> Result<(), VaultError> {
    map_entropy(getrandom::getrandom(buf))
}

#[cfg(all(
    feature = "getrandom",
    any(feature = "encrypted", feature = "dm-epoch")
))]
fn map_entropy(result: Result<(), getrandom::Error>) -> Result<(), VaultError> {
    result.map_err(|_| VaultError::RandomUnavailable)
}

#[derive(Debug)]
pub struct Vault {
    config: VaultConfig,
    entries: Vec<(String, Entry)>,
    active_label: Option<String>,
}

impl Vault {
    pub fn new(config: VaultConfig) -> Result<Self, VaultError> {
        Ok(Self {
            config,
            entries: Vec::new(),
            active_label: None,
        })
    }

    fn active_label_copy(&self) -> Result<String, VaultError> {
        let label = self
            .active_label
            .as_deref()
            .ok_or(VaultError::NoActiveAccount)?;
        if entry_index(&self.entries, label).is_none() {
            return Err(VaultError::MissingLabel);
        }
        text(label)
    }

    pub fn import_plaintext(
        &mut self,
        label: &str,
        secret: SecretKey,
        now_unix_seconds: u64,
    ) -> Result<(), VaultError> {
        if entry_index(&self.entries, label).is_some() {
            return Err(VaultError::DuplicateLabel);
        }
        let set_active = self.entries.is_empty();
        let stored_label = text(label)?;
        let active_label = if set_active { Some(text(label)?) } else { None };
        let required = self
            .entries
            .len()
            .checked_add(1)
            .ok_or(VaultError::CapacityOverflow {
                required: usize::MAX,
            })?;
        let allocation_bytes = required
            .checked_mul(core::mem::size_of::<(String, Entry)>())
            .ok_or(VaultError::CapacityOverflow { required })?;
        if allocation_bytes > isize::MAX as usize {
            return Err(VaultError::CapacityOverflow { required });
        }
        if self.entries.capacity() < required {
            self.entries
                .try_reserve_exact(required - self.entries.len())
                .map_err(|_| VaultError::AllocationFailed { required })?;
        }
        self.entries.push((
            stored_label,
            Entry {
                secret,
                last_used_unix_seconds: now_unix_seconds,
            },
        ));
        if set_active {
            self.active_label = active_label;
        }
        Ok(())
    }

    pub fn contains(&self, label: &str) -> bool {
        entry_index(&self.entries, label).is_some()
    }

    pub fn set_active(&mut self, label: &str) -> Result<(), VaultError> {
        if entry_index(&self.entries, label).is_none() {
            return Err(VaultError::MissingLabel);
        }
        let copied = text(label)?;
        self.active_label = Some(copied);
        Ok(())
    }

    pub fn active_label(&self) -> Option<&str> {
        self.active_label.as_deref()
    }

    pub fn set_security_config(&mut self, security: SecurityConfig) {
        self.config.security = security;
    }

    pub fn security_config(&self) -> SecurityConfig {
        self.config.security
    }

    pub fn remove(&mut self, label: &str) -> Result<(), VaultError> {
        let index = entry_index(&self.entries, label).ok_or(VaultError::MissingLabel)?;
        self.entries.remove(index);
        if self.active_label.as_deref() == Some(label) {
            self.active_label = None;
        }
        Ok(())
    }

    pub fn labels(&self) -> Result<Vec<&str>, VaultError> {
        let mut labels = vector(self.entries.len())?;
        labels.extend(self.entries.iter().map(|(label, _)| label.as_str()));
        labels.sort_unstable();
        Ok(labels)
    }

    pub fn public_key(&self, label: &str) -> Result<XOnlyPublicKey, VaultError> {
        let index = entry_index(&self.entries, label).ok_or(VaultError::MissingLabel)?;
        self.entries[index]
            .1
            .secret
            .xonly_public_key()
            .map_err(VaultError::from)
    }

    pub fn public_key_active(&self) -> Result<XOnlyPublicKey, VaultError> {
        let label = self
            .active_label
            .as_deref()
            .ok_or(VaultError::NoActiveAccount)?;
        self.public_key(label)
    }

    #[cfg(all(feature = "nostr", feature = "getrandom"))]
    pub fn sign_event(
        &mut self,
        label: &str,
        unsigned: UnsignedEvent,
        now_unix_seconds: u64,
    ) -> Result<SignedEvent, VaultError> {
        self.sign_event_with_rng(label, unsigned, now_unix_seconds, &mut secp_os_entropy)
    }

    #[cfg(feature = "nostr")]
    pub fn sign_event_with_rng<F>(
        &mut self,
        label: &str,
        unsigned: UnsignedEvent,
        now_unix_seconds: u64,
        fill: &mut F,
    ) -> Result<SignedEvent, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        #[cfg(feature = "security-hardening")]
        let security = self.config.security;
        let index = entry_index(&self.entries, label).ok_or(VaultError::MissingLabel)?;
        let entry = &mut self.entries[index].1;
        entry.last_used_unix_seconds = now_unix_seconds;
        #[cfg(feature = "security-hardening")]
        apply_security_before(security, &entry.secret, fill)?;
        let signed = nostr::finalize_event_with_rng(unsigned, &entry.secret, fill)
            .map_err(VaultError::from)?;
        #[cfg(feature = "security-hardening")]
        apply_security_after(security, &entry.secret, fill)?;
        Ok(signed)
    }

    #[cfg(all(feature = "nostr", feature = "getrandom"))]
    pub fn sign_event_active(
        &mut self,
        unsigned: UnsignedEvent,
        now_unix_seconds: u64,
    ) -> Result<SignedEvent, VaultError> {
        self.sign_event_active_with_rng(unsigned, now_unix_seconds, &mut secp_os_entropy)
    }

    #[cfg(feature = "nostr")]
    pub fn sign_event_active_with_rng<F>(
        &mut self,
        unsigned: UnsignedEvent,
        now_unix_seconds: u64,
        fill: &mut F,
    ) -> Result<SignedEvent, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        let label = self.active_label_copy()?;
        self.sign_event_with_rng(&label, unsigned, now_unix_seconds, fill)
    }

    #[cfg(all(feature = "nostr", feature = "getrandom"))]
    pub fn create_auth_event(
        &mut self,
        label: &str,
        challenge: &str,
        relay_url: &str,
        now_unix_seconds: u64,
    ) -> Result<SignedEvent, VaultError> {
        self.create_auth_event_with_rng(
            label,
            challenge,
            relay_url,
            now_unix_seconds,
            &mut secp_os_entropy,
        )
    }

    #[cfg(feature = "nostr")]
    pub fn create_auth_event_with_rng<F>(
        &mut self,
        label: &str,
        challenge: &str,
        relay_url: &str,
        now_unix_seconds: u64,
        fill: &mut F,
    ) -> Result<SignedEvent, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        #[cfg(feature = "security-hardening")]
        let security = self.config.security;
        let index = entry_index(&self.entries, label).ok_or(VaultError::MissingLabel)?;
        let entry = &mut self.entries[index].1;
        entry.last_used_unix_seconds = now_unix_seconds;
        #[cfg(feature = "security-hardening")]
        apply_security_before(security, &entry.secret, fill)?;
        let event = neco_secp::nip42::create_auth_event_with_rng(
            challenge,
            relay_url,
            &entry.secret,
            now_unix_seconds,
            fill,
        )
        .map_err(VaultError::from)?;
        #[cfg(feature = "security-hardening")]
        apply_security_after(security, &entry.secret, fill)?;
        Ok(event)
    }

    #[cfg(all(feature = "nostr", feature = "getrandom"))]
    pub fn create_auth_event_active(
        &mut self,
        challenge: &str,
        relay_url: &str,
        now_unix_seconds: u64,
    ) -> Result<SignedEvent, VaultError> {
        self.create_auth_event_active_with_rng(
            challenge,
            relay_url,
            now_unix_seconds,
            &mut secp_os_entropy,
        )
    }

    #[cfg(feature = "nostr")]
    pub fn create_auth_event_active_with_rng<F>(
        &mut self,
        challenge: &str,
        relay_url: &str,
        now_unix_seconds: u64,
        fill: &mut F,
    ) -> Result<SignedEvent, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        let label = self.active_label_copy()?;
        self.create_auth_event_with_rng(&label, challenge, relay_url, now_unix_seconds, fill)
    }

    pub fn clear_cache(&mut self) {
        self.entries.clear();
        self.active_label = None;
    }

    pub fn clear_expired_cache(&mut self, now_unix_seconds: u64) {
        let timeout = self.config.cache_timeout_seconds;
        self.entries.retain(|(_, entry)| {
            now_unix_seconds.saturating_sub(entry.last_used_unix_seconds) <= timeout
        });
        if self
            .active_label
            .as_deref()
            .is_some_and(|label| entry_index(&self.entries, label).is_none())
        {
            self.active_label = None;
        }
    }
}

#[cfg(feature = "nip04")]
impl Vault {
    #[cfg(feature = "getrandom")]
    pub fn nip04_encrypt(
        &mut self,
        label: &str,
        peer: &XOnlyPublicKey,
        plaintext: &str,
        now: u64,
    ) -> Result<String, VaultError> {
        self.nip04_encrypt_with_rng(label, peer, plaintext, now, &mut secp_os_entropy)
    }

    pub fn nip04_encrypt_with_rng<F>(
        &mut self,
        label: &str,
        peer: &XOnlyPublicKey,
        plaintext: &str,
        now: u64,
        fill: &mut F,
    ) -> Result<String, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        #[cfg(feature = "security-hardening")]
        let security = self.config.security;
        let index = entry_index(&self.entries, label).ok_or(VaultError::MissingLabel)?;
        let entry = &mut self.entries[index].1;
        entry.last_used_unix_seconds = now;
        #[cfg(feature = "security-hardening")]
        {
            apply_security_before(security, &entry.secret, fill)?;
            if security.enable_dummy_operations {
                apply_dummy_nip04(&entry.secret)?;
            }
        }
        let payload =
            neco_secp::nip04::encrypt_with_rng(&entry.secret, peer, plaintext, None, fill)
                .map_err(VaultError::from)?;
        #[cfg(feature = "security-hardening")]
        apply_security_after(security, &entry.secret, fill)?;
        Ok(payload)
    }

    #[cfg(feature = "getrandom")]
    pub fn nip04_decrypt(
        &mut self,
        label: &str,
        peer: &XOnlyPublicKey,
        payload: &str,
        now: u64,
    ) -> Result<String, VaultError> {
        self.nip04_decrypt_with_rng(label, peer, payload, now, &mut secp_os_entropy)
    }

    #[cfg(all(not(feature = "getrandom"), not(feature = "security-hardening")))]
    pub fn nip04_decrypt(
        &mut self,
        label: &str,
        peer: &XOnlyPublicKey,
        payload: &str,
        now: u64,
    ) -> Result<String, VaultError> {
        self.nip04_decrypt_with_rng(label, peer, payload, now, &mut |_| {
            Err(SecpError::EntropyRequired)
        })
    }

    pub fn nip04_decrypt_with_rng<F>(
        &mut self,
        label: &str,
        peer: &XOnlyPublicKey,
        payload: &str,
        now: u64,
        _fill: &mut F,
    ) -> Result<String, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        #[cfg(feature = "security-hardening")]
        let security = self.config.security;
        let index = entry_index(&self.entries, label).ok_or(VaultError::MissingLabel)?;
        let entry = &mut self.entries[index].1;
        entry.last_used_unix_seconds = now;
        #[cfg(feature = "security-hardening")]
        {
            apply_security_before(security, &entry.secret, _fill)?;
            if security.enable_dummy_operations {
                apply_dummy_nip04(&entry.secret)?;
            }
        }
        let plaintext =
            neco_secp::nip04::decrypt(&entry.secret, peer, payload).map_err(VaultError::from)?;
        #[cfg(feature = "security-hardening")]
        apply_security_after(security, &entry.secret, _fill)?;
        Ok(plaintext)
    }

    #[cfg(feature = "getrandom")]
    pub fn nip04_encrypt_active(
        &mut self,
        peer: &XOnlyPublicKey,
        plaintext: &str,
        now: u64,
    ) -> Result<String, VaultError> {
        self.nip04_encrypt_active_with_rng(peer, plaintext, now, &mut secp_os_entropy)
    }

    pub fn nip04_encrypt_active_with_rng<F>(
        &mut self,
        peer: &XOnlyPublicKey,
        plaintext: &str,
        now: u64,
        fill: &mut F,
    ) -> Result<String, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        let label = self.active_label_copy()?;
        self.nip04_encrypt_with_rng(&label, peer, plaintext, now, fill)
    }

    #[cfg(feature = "getrandom")]
    pub fn nip04_decrypt_active(
        &mut self,
        peer: &XOnlyPublicKey,
        payload: &str,
        now: u64,
    ) -> Result<String, VaultError> {
        self.nip04_decrypt_active_with_rng(peer, payload, now, &mut secp_os_entropy)
    }

    #[cfg(all(not(feature = "getrandom"), not(feature = "security-hardening")))]
    pub fn nip04_decrypt_active(
        &mut self,
        peer: &XOnlyPublicKey,
        payload: &str,
        now: u64,
    ) -> Result<String, VaultError> {
        self.nip04_decrypt_active_with_rng(peer, payload, now, &mut |_| {
            Err(SecpError::EntropyRequired)
        })
    }

    pub fn nip04_decrypt_active_with_rng<F>(
        &mut self,
        peer: &XOnlyPublicKey,
        payload: &str,
        now: u64,
        fill: &mut F,
    ) -> Result<String, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        let label = self.active_label_copy()?;
        self.nip04_decrypt_with_rng(&label, peer, payload, now, fill)
    }
}

#[cfg(feature = "nip44")]
impl Vault {
    #[cfg(feature = "getrandom")]
    pub fn nip44_encrypt(
        &mut self,
        label: &str,
        peer: &XOnlyPublicKey,
        plaintext: &str,
        now: u64,
    ) -> Result<String, VaultError> {
        self.nip44_encrypt_with_rng(label, peer, plaintext, now, &mut secp_os_entropy)
    }

    pub fn nip44_encrypt_with_rng<F>(
        &mut self,
        label: &str,
        peer: &XOnlyPublicKey,
        plaintext: &str,
        now: u64,
        fill: &mut F,
    ) -> Result<String, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        #[cfg(feature = "security-hardening")]
        let security = self.config.security;
        let index = entry_index(&self.entries, label).ok_or(VaultError::MissingLabel)?;
        let entry = &mut self.entries[index].1;
        entry.last_used_unix_seconds = now;
        #[cfg(feature = "security-hardening")]
        {
            apply_security_before(security, &entry.secret, fill)?;
            if security.enable_dummy_operations {
                apply_dummy_nip44(&entry.secret)?;
            }
        }
        let conversation_key = neco_secp::nip44::get_conversation_key(&entry.secret, peer)
            .map_err(VaultError::from)?;
        let payload = neco_secp::nip44::encrypt_with_rng(plaintext, &conversation_key, None, fill)
            .map_err(VaultError::from)?;
        #[cfg(feature = "security-hardening")]
        apply_security_after(security, &entry.secret, fill)?;
        Ok(payload)
    }

    #[cfg(feature = "getrandom")]
    pub fn nip44_decrypt(
        &mut self,
        label: &str,
        peer: &XOnlyPublicKey,
        payload: &str,
        now: u64,
    ) -> Result<String, VaultError> {
        self.nip44_decrypt_with_rng(label, peer, payload, now, &mut secp_os_entropy)
    }

    #[cfg(all(not(feature = "getrandom"), not(feature = "security-hardening")))]
    pub fn nip44_decrypt(
        &mut self,
        label: &str,
        peer: &XOnlyPublicKey,
        payload: &str,
        now: u64,
    ) -> Result<String, VaultError> {
        self.nip44_decrypt_with_rng(label, peer, payload, now, &mut |_| {
            Err(SecpError::EntropyRequired)
        })
    }

    pub fn nip44_decrypt_with_rng<F>(
        &mut self,
        label: &str,
        peer: &XOnlyPublicKey,
        payload: &str,
        now: u64,
        _fill: &mut F,
    ) -> Result<String, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        #[cfg(feature = "security-hardening")]
        let security = self.config.security;
        let index = entry_index(&self.entries, label).ok_or(VaultError::MissingLabel)?;
        let entry = &mut self.entries[index].1;
        entry.last_used_unix_seconds = now;
        #[cfg(feature = "security-hardening")]
        {
            apply_security_before(security, &entry.secret, _fill)?;
            if security.enable_dummy_operations {
                apply_dummy_nip44(&entry.secret)?;
            }
        }
        let conversation_key = neco_secp::nip44::get_conversation_key(&entry.secret, peer)
            .map_err(VaultError::from)?;
        let plaintext =
            neco_secp::nip44::decrypt(payload, &conversation_key).map_err(VaultError::from)?;
        #[cfg(feature = "security-hardening")]
        apply_security_after(security, &entry.secret, _fill)?;
        Ok(plaintext)
    }

    #[cfg(feature = "getrandom")]
    pub fn nip44_encrypt_active(
        &mut self,
        peer: &XOnlyPublicKey,
        plaintext: &str,
        now: u64,
    ) -> Result<String, VaultError> {
        self.nip44_encrypt_active_with_rng(peer, plaintext, now, &mut secp_os_entropy)
    }

    pub fn nip44_encrypt_active_with_rng<F>(
        &mut self,
        peer: &XOnlyPublicKey,
        plaintext: &str,
        now: u64,
        fill: &mut F,
    ) -> Result<String, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        let label = self.active_label_copy()?;
        self.nip44_encrypt_with_rng(&label, peer, plaintext, now, fill)
    }

    #[cfg(feature = "getrandom")]
    pub fn nip44_decrypt_active(
        &mut self,
        peer: &XOnlyPublicKey,
        payload: &str,
        now: u64,
    ) -> Result<String, VaultError> {
        self.nip44_decrypt_active_with_rng(peer, payload, now, &mut secp_os_entropy)
    }

    #[cfg(all(not(feature = "getrandom"), not(feature = "security-hardening")))]
    pub fn nip44_decrypt_active(
        &mut self,
        peer: &XOnlyPublicKey,
        payload: &str,
        now: u64,
    ) -> Result<String, VaultError> {
        self.nip44_decrypt_active_with_rng(peer, payload, now, &mut |_| {
            Err(SecpError::EntropyRequired)
        })
    }

    pub fn nip44_decrypt_active_with_rng<F>(
        &mut self,
        peer: &XOnlyPublicKey,
        payload: &str,
        now: u64,
        fill: &mut F,
    ) -> Result<String, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        let label = self.active_label_copy()?;
        self.nip44_decrypt_with_rng(&label, peer, payload, now, fill)
    }
}

#[cfg(feature = "nip17")]
fn nip17_unsigned_event(
    content: &str,
    recipient: &XOnlyPublicKey,
    now_unix_seconds: u64,
) -> Result<UnsignedEvent, VaultError> {
    let mut recipient_tag = vector(2)?;
    recipient_tag.push(text("p")?);
    recipient_tag.push(recipient.to_hex().map_err(VaultError::from)?);
    let mut tags = vector(1)?;
    tags.push(recipient_tag);
    Ok(UnsignedEvent {
        created_at: now_unix_seconds,
        kind: 14,
        tags,
        content: text(content)?,
    })
}

#[cfg(feature = "nip17")]
impl Vault {
    #[cfg(feature = "getrandom")]
    pub fn create_sealed_dm(
        &mut self,
        label: &str,
        content: &str,
        recipient: &XOnlyPublicKey,
        now_unix_seconds: u64,
    ) -> Result<SignedEvent, VaultError> {
        self.create_sealed_dm_with_rng(
            label,
            content,
            recipient,
            now_unix_seconds,
            &mut secp_os_entropy,
        )
    }

    pub fn create_sealed_dm_with_rng<F>(
        &mut self,
        label: &str,
        content: &str,
        recipient: &XOnlyPublicKey,
        now_unix_seconds: u64,
        fill: &mut F,
    ) -> Result<SignedEvent, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        #[cfg(feature = "security-hardening")]
        let security = self.config.security;
        let index = entry_index(&self.entries, label).ok_or(VaultError::MissingLabel)?;
        let entry = &mut self.entries[index].1;
        entry.last_used_unix_seconds = now_unix_seconds;
        #[cfg(feature = "security-hardening")]
        {
            apply_security_before(security, &entry.secret, fill)?;
            if security.enable_dummy_operations {
                apply_dummy_nip44(&entry.secret)?;
            }
        }
        let inner = nip17_unsigned_event(content, recipient, now_unix_seconds)?;
        let seal = neco_secp::nip17::create_seal_with_rng(
            inner,
            &entry.secret,
            recipient,
            now_unix_seconds,
            fill,
        )
        .map_err(VaultError::from)?;
        let gift_wrap =
            neco_secp::nip17::create_gift_wrap_with_rng(&seal, recipient, now_unix_seconds, fill)
                .map_err(VaultError::from)?;
        #[cfg(feature = "security-hardening")]
        apply_security_after(security, &entry.secret, fill)?;
        Ok(gift_wrap)
    }

    #[cfg(feature = "getrandom")]
    pub fn create_sealed_dm_with_scan_tag(
        &mut self,
        label: &str,
        content: &str,
        recipient: &XOnlyPublicKey,
        recipient_scan_pub: &XOnlyPublicKey,
        now_unix_seconds: u64,
    ) -> Result<SealedDmResult, VaultError> {
        self.create_sealed_dm_with_scan_tag_with_rng(
            label,
            content,
            recipient,
            recipient_scan_pub,
            now_unix_seconds,
            &mut secp_os_entropy,
        )
    }

    pub fn create_sealed_dm_with_scan_tag_with_rng<F>(
        &mut self,
        label: &str,
        content: &str,
        recipient: &XOnlyPublicKey,
        recipient_scan_pub: &XOnlyPublicKey,
        now_unix_seconds: u64,
        fill: &mut F,
    ) -> Result<SealedDmResult, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        #[cfg(feature = "security-hardening")]
        let security = self.config.security;
        let index = entry_index(&self.entries, label).ok_or(VaultError::MissingLabel)?;
        let entry = &mut self.entries[index].1;
        entry.last_used_unix_seconds = now_unix_seconds;
        #[cfg(feature = "security-hardening")]
        {
            apply_security_before(security, &entry.secret, fill)?;
            if security.enable_dummy_operations {
                apply_dummy_nip44(&entry.secret)?;
            }
        }
        let inner = nip17_unsigned_event(content, recipient, now_unix_seconds)?;
        let seal = neco_secp::nip17::create_seal_with_rng(
            inner,
            &entry.secret,
            recipient,
            now_unix_seconds,
            fill,
        )
        .map_err(VaultError::from)?;
        let result = neco_secp::nip17::create_gift_wrap_with_scan_tag_with_rng(
            &seal,
            recipient,
            recipient_scan_pub,
            now_unix_seconds,
            fill,
        )
        .map_err(VaultError::from)?;
        #[cfg(feature = "security-hardening")]
        apply_security_after(security, &entry.secret, fill)?;
        Ok(SealedDmResult {
            event: result.event,
            scanning_tag: result.scanning_tag,
        })
    }

    /// 呼び出し側が渡す走査鍵の秘密鍵と、ギフトラップの一時公開鍵から走査タグを計算します。走査鍵は、署名鍵とは別の鍵です。
    pub fn compute_scan_tag(
        scan_priv: &SecretKey,
        ephemeral_pubkey: &XOnlyPublicKey,
    ) -> Result<[u8; 16], VaultError> {
        neco_secp::nip17::compute_scan_tag(scan_priv, ephemeral_pubkey).map_err(VaultError::from)
    }

    pub fn open_gift_wrap_dm(
        &mut self,
        label: &str,
        gift_wrap: &SignedEvent,
        now_unix_seconds: u64,
    ) -> Result<Rumor, VaultError> {
        self.open_gift_wrap_dm_with_rng(label, gift_wrap, now_unix_seconds, &mut |bytes| {
            #[cfg(feature = "getrandom")]
            {
                secp_os_entropy(bytes)
            }
            #[cfg(not(feature = "getrandom"))]
            {
                let _ = bytes;
                Err(SecpError::EntropyRequired)
            }
        })
    }

    pub fn open_gift_wrap_dm_with_rng<F>(
        &mut self,
        label: &str,
        gift_wrap: &SignedEvent,
        now_unix_seconds: u64,
        _fill: &mut F,
    ) -> Result<Rumor, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        #[cfg(feature = "security-hardening")]
        let security = self.config.security;
        let index = entry_index(&self.entries, label).ok_or(VaultError::MissingLabel)?;
        let entry = &mut self.entries[index].1;
        entry.last_used_unix_seconds = now_unix_seconds;
        #[cfg(feature = "security-hardening")]
        {
            apply_security_before(security, &entry.secret, _fill)?;
            if security.enable_dummy_operations {
                apply_dummy_nip44(&entry.secret)?;
            }
        }
        let rumor =
            neco_secp::nip17::open_gift_wrap(gift_wrap, &entry.secret).map_err(VaultError::from)?;
        #[cfg(feature = "security-hardening")]
        apply_security_after(security, &entry.secret, _fill)?;
        Ok(rumor)
    }
}

#[cfg(feature = "encrypted")]
impl Vault {
    #[cfg(feature = "getrandom")]
    pub fn export_encrypted(&self, label: &str, passphrase: &[u8]) -> Result<Vec<u8>, VaultError> {
        self.export_encrypted_with_rng(label, passphrase, &mut os_entropy)
    }

    pub fn export_encrypted_with_rng<F>(
        &self,
        label: &str,
        passphrase: &[u8],
        fill: &mut F,
    ) -> Result<Vec<u8>, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), VaultError>,
    {
        let index = entry_index(&self.entries, label).ok_or(VaultError::MissingLabel)?;
        let secret = Zeroizing::new(self.entries[index].1.secret.to_bytes());
        let blob = sealed::seal(
            &secret,
            passphrase,
            KdfParams::DEFAULT,
            &Argon2idDerivation,
            fill,
        )?;
        bytes(&blob)
    }

    pub fn import_encrypted(
        &mut self,
        label: &str,
        passphrase: &[u8],
        data: &[u8],
        now_unix_seconds: u64,
    ) -> Result<(), VaultError> {
        self.import_encrypted_with(
            label,
            passphrase,
            data,
            now_unix_seconds,
            &KdfPolicy::PRODUCTION,
            &Argon2idDerivation,
        )
    }

    pub(crate) fn import_encrypted_with(
        &mut self,
        label: &str,
        passphrase: &[u8],
        data: &[u8],
        now_unix_seconds: u64,
        policy: &KdfPolicy,
        kdf: &dyn KeyDerivation,
    ) -> Result<(), VaultError> {
        if entry_index(&self.entries, label).is_some() {
            return Err(VaultError::DuplicateLabel);
        }
        let secret_bytes = sealed::open(data, passphrase, policy, kdf)?;
        let secret =
            SecretKey::from_bytes(*secret_bytes).map_err(|_| VaultError::InvalidSecretKey)?;
        self.import_plaintext(label, secret, now_unix_seconds)
    }
}

#[cfg(feature = "dm-epoch")]
impl Vault {
    pub fn derive_epoch_key(
        &self,
        label: &str,
        peer_pubkey: &XOnlyPublicKey,
        epoch_number: u32,
    ) -> Result<[u8; 32], VaultError> {
        let index = entry_index(&self.entries, label).ok_or(VaultError::MissingLabel)?;
        let conversation_key =
            neco_secp::nip44::get_conversation_key(&self.entries[index].1.secret, peer_pubkey)?;
        let mut key = Self::hkdf_rotate(&conversation_key, b"dm-epoch-0")?;
        for _ in 0..epoch_number {
            key = Self::hkdf_rotate(&key, b"dm-epoch-rotate")?;
        }
        Ok(key)
    }

    #[cfg(feature = "getrandom")]
    pub fn encrypt_with_epoch(
        epoch_key: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        Self::encrypt_with_epoch_with_rng(epoch_key, plaintext, &mut os_entropy)
    }

    pub fn encrypt_with_epoch_with_rng<F>(
        epoch_key: &[u8; 32],
        plaintext: &[u8],
        fill: &mut F,
    ) -> Result<Vec<u8>, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), VaultError>,
    {
        use chacha20poly1305::aead::{AeadInPlace, KeyInit};
        use chacha20poly1305::ChaCha20Poly1305;

        let payload_len = combined_capacity(plaintext.len(), 16)?;
        let required = combined_capacity(12, payload_len)?;
        let mut out = vector(required)?;
        let mut nonce = [0u8; 12];
        fill(&mut nonce)?;
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plaintext);
        let cipher = ChaCha20Poly1305::new(epoch_key.into());
        let tag = cipher
            .encrypt_in_place_detached(
                chacha20poly1305::Nonce::from_slice(&nonce),
                b"",
                &mut out[12..],
            )
            .map_err(|_| VaultError::SealFailed)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    pub fn decrypt_with_epoch(
        epoch_key: &[u8; 32],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        use chacha20poly1305::aead::{AeadInPlace, KeyInit};
        use chacha20poly1305::ChaCha20Poly1305;

        if ciphertext.len() < 12 + 16 {
            return Err(VaultError::MalformedEncrypted(MalformedKind::TooShort {
                minimum: 12 + 16,
                actual: ciphertext.len(),
            }));
        }
        let tag_start = ciphertext.len() - 16;
        let nonce = chacha20poly1305::Nonce::from_slice(&ciphertext[..12]);
        let tag = chacha20poly1305::Tag::from_slice(&ciphertext[tag_start..]);
        let mut plaintext = bytes(&ciphertext[12..tag_start])?;
        let cipher = ChaCha20Poly1305::new(epoch_key.into());
        cipher
            .decrypt_in_place_detached(nonce, b"", &mut plaintext, tag)
            .map_err(|_| VaultError::AuthenticationFailed)?;
        Ok(plaintext)
    }

    #[cfg(feature = "getrandom")]
    pub fn create_group_key() -> Result<[u8; 32], VaultError> {
        Self::create_group_key_with_rng(&mut os_entropy)
    }

    pub fn create_group_key_with_rng<F>(fill: &mut F) -> Result<[u8; 32], VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), VaultError>,
    {
        let mut key = [0u8; 32];
        fill(&mut key)?;
        Ok(key)
    }

    #[cfg(feature = "getrandom")]
    pub fn encrypt_group_key(
        group_key: &[u8; 32],
        recipient_pubkey: &XOnlyPublicKey,
    ) -> Result<Vec<u8>, VaultError> {
        Self::encrypt_group_key_with_rng(group_key, recipient_pubkey, &mut secp_os_entropy)
    }

    pub fn encrypt_group_key_with_rng<F>(
        group_key: &[u8; 32],
        recipient_pubkey: &XOnlyPublicKey,
        fill: &mut F,
    ) -> Result<Vec<u8>, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), SecpError>,
    {
        let ephemeral = SecretKey::generate_with_rng(fill)?;
        let ephemeral_pub = ephemeral.xonly_public_key()?;
        let conversation_key =
            neco_secp::nip44::get_conversation_key(&ephemeral, recipient_pubkey)?;
        let hex_payload = neco_secp::hex::hex_encode(group_key)?;
        let encrypted =
            neco_secp::nip44::encrypt_with_rng(&hex_payload, &conversation_key, None, fill)?;
        let encrypted_bytes = encrypted.as_bytes();
        let required = combined_capacity(32, encrypted_bytes.len())?;
        let mut out = vector(required)?;
        out.extend_from_slice(&ephemeral_pub.to_bytes());
        out.extend_from_slice(encrypted_bytes);
        Ok(out)
    }

    pub fn decrypt_group_key(&self, label: &str, encrypted: &[u8]) -> Result<[u8; 32], VaultError> {
        if encrypted.len() < 33 {
            return Err(VaultError::MalformedEncrypted(MalformedKind::TooShort {
                minimum: 33,
                actual: encrypted.len(),
            }));
        }
        let index = entry_index(&self.entries, label).ok_or(VaultError::MissingLabel)?;
        let ephemeral_pub_bytes: [u8; 32] = encrypted[..32]
            .try_into()
            .map_err(|_| VaultError::MalformedEncrypted(MalformedKind::Payload))?;
        let ephemeral_pub =
            XOnlyPublicKey::from_bytes(ephemeral_pub_bytes).map_err(|error| match error {
                SecpError::InvalidPublicKey => {
                    VaultError::MalformedEncrypted(MalformedKind::Payload)
                }
                error => VaultError::Crypto(error),
            })?;
        let conversation_key =
            neco_secp::nip44::get_conversation_key(&self.entries[index].1.secret, &ephemeral_pub)?;
        let payload = core::str::from_utf8(&encrypted[32..])
            .map_err(|_| VaultError::MalformedEncrypted(MalformedKind::Payload))?;
        let hex = neco_secp::nip44::decrypt(payload, &conversation_key)?;
        let decoded = neco_secp::hex::hex_decode(&hex).map_err(VaultError::from)?;
        if decoded.len() != 32 {
            return Err(VaultError::MalformedEncrypted(MalformedKind::Payload));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    }

    #[cfg(feature = "getrandom")]
    pub fn encrypt_group_message(
        group_epoch_key: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        Self::encrypt_with_epoch(group_epoch_key, plaintext)
    }

    pub fn encrypt_group_message_with_rng<F>(
        group_epoch_key: &[u8; 32],
        plaintext: &[u8],
        fill: &mut F,
    ) -> Result<Vec<u8>, VaultError>
    where
        F: FnMut(&mut [u8]) -> Result<(), VaultError>,
    {
        Self::encrypt_with_epoch_with_rng(group_epoch_key, plaintext, fill)
    }

    pub fn decrypt_group_message(
        group_epoch_key: &[u8; 32],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        Self::decrypt_with_epoch(group_epoch_key, ciphertext)
    }

    pub fn rotate_group_epoch(current_key: &[u8; 32]) -> Result<[u8; 32], VaultError> {
        Self::hkdf_rotate(current_key, b"group-epoch-rotate")
    }

    fn hkdf_rotate(key: &[u8; 32], info: &[u8]) -> Result<[u8; 32], VaultError> {
        let prk = neco_sha2::Prk::from_bytes(key);
        let mut out = [0u8; 32];
        prk.expand_into(info, &mut out).map_err(VaultError::Hkdf)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated_secret(seed: u8) -> Result<SecretKey, SecpError> {
        SecretKey::generate_with_rng(&mut |output| {
            output.fill(seed);
            Ok(())
        })
    }

    fn secp_entropy(output: &mut [u8]) -> Result<(), SecpError> {
        output.fill(0x5a);
        Ok(())
    }

    fn vault_entropy(output: &mut [u8]) -> Result<(), VaultError> {
        output.fill(0xa5);
        Ok(())
    }

    fn counted_vault_entropy(counter: &mut u64, output: &mut [u8]) -> Result<(), VaultError> {
        let block = counter.to_le_bytes();
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = block[index % block.len()];
        }
        *counter = counter.wrapping_add(1);
        Ok(())
    }

    #[test]
    fn first_import_sets_active() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let secret = generated_secret(0x11).expect("secret");
        vault.import_plaintext("main", secret, 100).expect("import");
        assert_eq!(vault.active_label(), Some("main"));
    }

    #[test]
    fn second_import_does_not_change_active() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        vault
            .import_plaintext("main", generated_secret(0x11).expect("main secret"), 100)
            .expect("first import");
        vault
            .import_plaintext(
                "backup",
                generated_secret(0x22).expect("backup secret"),
                101,
            )
            .expect("second import");
        assert_eq!(vault.active_label(), Some("main"));
    }

    #[test]
    fn set_active_switches_label() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        vault
            .import_plaintext("main", generated_secret(0x11).expect("main secret"), 100)
            .expect("first import");
        vault
            .import_plaintext(
                "backup",
                generated_secret(0x22).expect("backup secret"),
                101,
            )
            .expect("second import");
        vault.set_active("backup").expect("set active");
        assert_eq!(vault.active_label(), Some("backup"));
    }

    #[test]
    fn set_active_missing_label_fails() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let error = vault
            .set_active("missing")
            .expect_err("missing label must fail");
        assert!(matches!(error, VaultError::MissingLabel));
    }

    #[test]
    fn remove_active_sets_none() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        vault
            .import_plaintext("main", generated_secret(0x11).expect("secret"), 100)
            .expect("import");
        vault.remove("main").expect("remove");
        assert_eq!(vault.active_label(), None);
    }

    #[test]
    fn remove_non_active_keeps_active() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        vault
            .import_plaintext("main", generated_secret(0x11).expect("main secret"), 100)
            .expect("first import");
        vault
            .import_plaintext(
                "backup",
                generated_secret(0x22).expect("backup secret"),
                101,
            )
            .expect("second import");
        vault.remove("backup").expect("remove");
        assert_eq!(vault.active_label(), Some("main"));
    }

    #[test]
    fn labels_returns_all() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        vault
            .import_plaintext("main", generated_secret(0x11).expect("main secret"), 100)
            .expect("first import");
        vault
            .import_plaintext(
                "backup",
                generated_secret(0x22).expect("backup secret"),
                101,
            )
            .expect("second import");
        assert_eq!(vault.labels().expect("labels"), vec!["backup", "main"]);
    }

    #[test]
    fn public_key_returns_expected_xonly() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let secret = generated_secret(0x11).expect("secret");
        let expected = secret.xonly_public_key().expect("public key");
        vault.import_plaintext("main", secret, 100).expect("import");
        assert_eq!(
            vault.public_key("main").expect("vault public key"),
            expected
        );
    }

    #[test]
    fn public_key_active_returns_expected_xonly() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let secret = generated_secret(0x11).expect("secret");
        let expected = secret.xonly_public_key().expect("public key");
        vault.import_plaintext("main", secret, 100).expect("import");
        assert_eq!(
            vault.public_key_active().expect("active public key"),
            expected
        );
    }

    #[test]
    fn public_key_missing_label_fails() {
        let vault = Vault::new(VaultConfig::default()).expect("vault");
        let error = vault
            .public_key("missing")
            .expect_err("missing label must fail");
        assert!(matches!(error, VaultError::MissingLabel));
    }

    #[test]
    fn public_key_active_without_active_fails() {
        let vault = Vault::new(VaultConfig::default()).expect("vault");
        let error = vault
            .public_key_active()
            .expect_err("active label must exist");
        assert!(matches!(error, VaultError::NoActiveAccount));
    }

    #[test]
    fn default_security_config_enables_only_constant_time() {
        let vault = Vault::new(VaultConfig::default()).expect("vault");
        assert_eq!(
            vault.security_config(),
            SecurityConfig {
                enable_constant_time: true,
                enable_random_delay: false,
                enable_dummy_operations: false,
            }
        );
    }

    #[test]
    fn set_security_config_updates_vault_immediately() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let security = SecurityConfig {
            enable_constant_time: false,
            enable_random_delay: true,
            enable_dummy_operations: true,
        };
        vault.set_security_config(security);
        assert_eq!(vault.security_config(), security);
    }

    #[test]
    fn clear_cache_resets_active() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        vault
            .import_plaintext("main", generated_secret(0x11).expect("secret"), 100)
            .expect("import");
        vault.clear_cache();
        assert_eq!(vault.active_label(), None);
    }

    #[test]
    fn clear_expired_resets_active_when_expired() {
        let mut vault = Vault::new(VaultConfig {
            cache_timeout_seconds: 10,
            security: SecurityConfig::default(),
        })
        .expect("vault");
        vault
            .import_plaintext("main", generated_secret(0x11).expect("secret"), 100)
            .expect("import");
        vault.clear_expired_cache(111);
        assert_eq!(vault.active_label(), None);
    }

    #[test]
    fn clear_expired_keeps_active_when_fresh() {
        let mut vault = Vault::new(VaultConfig {
            cache_timeout_seconds: 10,
            security: SecurityConfig::default(),
        })
        .expect("vault");
        vault
            .import_plaintext("main", generated_secret(0x11).expect("secret"), 100)
            .expect("import");
        vault.clear_expired_cache(110);
        assert_eq!(vault.active_label(), Some("main"));
    }

    #[test]
    #[cfg(feature = "nostr")]
    fn sign_event_active_works() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let secret = generated_secret(0x11).expect("secret");
        vault.import_plaintext("main", secret, 100).expect("import");

        let unsigned = UnsignedEvent {
            created_at: 101,
            kind: 1,
            tags: Vec::new(),
            content: "hello".to_string(),
        };

        let signed = vault
            .sign_event_active_with_rng(unsigned, 102, &mut secp_entropy)
            .expect("sign");
        nostr::verify_event(&signed).expect("verify");
    }

    #[test]
    #[cfg(feature = "nostr")]
    fn signing_preserves_the_entropy_provider_failure() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        vault
            .import_plaintext("main", generated_secret(0x11).expect("secret"), 100)
            .expect("import");
        let unsigned = UnsignedEvent {
            created_at: 101,
            kind: 1,
            tags: Vec::new(),
            content: "hello".to_string(),
        };
        let error = vault
            .sign_event_with_rng("main", unsigned, 102, &mut |_| {
                Err(SecpError::RandomUnavailable)
            })
            .expect_err("entropy failure");
        assert_eq!(error, VaultError::Crypto(SecpError::RandomUnavailable));
    }

    #[test]
    fn duplicate_label_is_rejected() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let secret = generated_secret(0x11).expect("secret");
        vault
            .import_plaintext("main", secret, 100)
            .expect("first import");
        let error = vault
            .import_plaintext("main", secret, 101)
            .expect_err("must reject duplicate");
        assert!(matches!(error, VaultError::DuplicateLabel));
    }

    #[test]
    #[cfg(feature = "nostr")]
    fn sign_event_active_no_active_fails() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let unsigned = UnsignedEvent {
            created_at: 101,
            kind: 1,
            tags: Vec::new(),
            content: "hello".to_string(),
        };
        let error = vault
            .sign_event_active_with_rng(unsigned, 102, &mut secp_entropy)
            .expect_err("active label must exist");
        assert!(matches!(error, VaultError::NoActiveAccount));
    }

    #[test]
    #[cfg(feature = "nostr")]
    fn missing_label_is_rejected() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let unsigned = UnsignedEvent {
            created_at: 101,
            kind: 1,
            tags: Vec::new(),
            content: "hello".to_string(),
        };
        let error = vault
            .sign_event_with_rng("missing", unsigned, 102, &mut secp_entropy)
            .expect_err("missing label must fail");
        assert!(matches!(error, VaultError::MissingLabel));
    }

    #[test]
    fn clear_expired_cache_removes_old_entries() {
        let mut vault = Vault::new(VaultConfig {
            cache_timeout_seconds: 10,
            security: SecurityConfig::default(),
        })
        .expect("vault");
        let secret = generated_secret(0x11).expect("secret");
        vault.import_plaintext("main", secret, 100).expect("import");
        vault.clear_expired_cache(111);
        assert!(!vault.contains("main"));
    }

    #[test]
    fn clear_expired_cache_keeps_entry_at_timeout_boundary() {
        let mut vault = Vault::new(VaultConfig {
            cache_timeout_seconds: 10,
            security: SecurityConfig::default(),
        })
        .expect("vault");
        let secret = generated_secret(0x11).expect("secret");
        vault.import_plaintext("main", secret, 100).expect("import");
        vault.clear_expired_cache(110);
        assert!(vault.contains("main"));
    }

    #[test]
    fn clear_expired_cache_removes_only_expired_labels() {
        let mut vault = Vault::new(VaultConfig {
            cache_timeout_seconds: 10,
            security: SecurityConfig::default(),
        })
        .expect("vault");
        vault
            .import_plaintext("old", generated_secret(0x11).expect("old secret"), 100)
            .expect("old import");
        vault
            .import_plaintext("fresh", generated_secret(0x22).expect("fresh secret"), 105)
            .expect("fresh import");
        vault.clear_expired_cache(111);
        assert!(!vault.contains("old"));
        assert!(vault.contains("fresh"));
    }

    #[test]
    #[cfg(feature = "nostr")]
    fn vault_sign_matches_core_finalize_event() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let secret = generated_secret(0x11).expect("secret");
        vault.import_plaintext("main", secret, 100).expect("import");

        let unsigned = UnsignedEvent {
            created_at: 101,
            kind: 7,
            tags: vec![vec!["t".to_string(), "rust".to_string()]],
            content: "hello".to_string(),
        };

        let from_vault = vault
            .sign_event_with_rng("main", unsigned.clone(), 102, &mut secp_entropy)
            .expect("vault sign");
        let from_core = nostr::finalize_event_with_rng(unsigned, &secret, &mut secp_entropy)
            .expect("core sign");
        assert_eq!(from_vault.id, from_core.id);
        assert_eq!(from_vault.pubkey, from_core.pubkey);
        assert_eq!(from_vault.created_at, from_core.created_at);
        assert_eq!(from_vault.kind, from_core.kind);
        assert_eq!(from_vault.tags, from_core.tags);
        assert_eq!(from_vault.content, from_core.content);
        nostr::verify_event(&from_vault).expect("verify vault");
        nostr::verify_event(&from_core).expect("verify core");
    }

    #[test]
    #[cfg(feature = "nostr")]
    fn vault_nip42_create_auth() {
        let mut vault = Vault::new(VaultConfig {
            cache_timeout_seconds: 10,
            security: SecurityConfig::default(),
        })
        .expect("vault");
        let secret = generated_secret(0x11).expect("secret");
        let expected = secret.xonly_public_key().expect("pubkey");
        vault.import_plaintext("main", secret, 100).expect("import");

        let event = vault
            .create_auth_event_with_rng(
                "main",
                "challenge-123",
                "wss://relay.example.com",
                105,
                &mut secp_entropy,
            )
            .expect("create auth event");

        assert_eq!(
            neco_secp::nip42::validate_auth_event(
                &event,
                "challenge-123",
                "wss://relay.example.com"
            )
            .expect("validate auth event"),
            expected
        );

        vault.clear_expired_cache(115);
        assert!(vault.contains("main"));
    }

    #[test]
    #[cfg(feature = "nostr")]
    fn vault_nip42_active_auth() {
        let mut vault = Vault::new(VaultConfig {
            cache_timeout_seconds: 10,
            security: SecurityConfig::default(),
        })
        .expect("vault");
        let secret = generated_secret(0x11).expect("secret");
        let expected = secret.xonly_public_key().expect("pubkey");
        vault.import_plaintext("main", secret, 100).expect("import");

        let event = vault
            .create_auth_event_active_with_rng(
                "challenge-456",
                "wss://relay.example.com",
                105,
                &mut secp_entropy,
            )
            .expect("create auth event");

        assert_eq!(
            neco_secp::nip42::validate_auth_event(
                &event,
                "challenge-456",
                "wss://relay.example.com"
            )
            .expect("validate auth event"),
            expected
        );

        vault.clear_expired_cache(115);
        assert!(vault.contains("main"));
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn encrypted_import_sets_active_on_empty_vault() {
        let mut dest = Vault::new(VaultConfig::default()).expect("dest vault");
        dest.import_encrypted(
            "main",
            kat::KAT_A_PASSPHRASE,
            &kat::unhex(kat::KAT_A_BLOB),
            200,
        )
        .expect("import encrypted");
        assert_eq!(dest.active_label(), Some("main"));
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn encrypted_export_missing_label_fails() {
        let vault = Vault::new(VaultConfig::default()).expect("vault");
        let error = vault
            .export_encrypted_with_rng("missing", b"passphrase", &mut vault_entropy)
            .expect_err("missing label must fail");
        assert!(matches!(error, VaultError::MissingLabel));
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn import_checks_duplicate_label_before_the_kdf() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let secret = SecretKey::from_bytes([0x11; 32]).expect("secret");
        let expected = secret.xonly_public_key().expect("public key");
        vault
            .import_plaintext("main", secret, 100)
            .expect("import plaintext");

        let counting = kdf::test_support::CountingDerivation::new([0u8; 32]);
        let error = vault
            .import_encrypted_with(
                "main",
                kat::KAT_C_PASSPHRASE,
                &kat::unhex(kat::KAT_C_BLOB),
                200,
                &KdfPolicy::TEST,
                &counting,
            )
            .expect_err("a registered label must be refused");
        assert_eq!(error, VaultError::DuplicateLabel);
        assert_eq!(counting.calls(), 0);
        assert_eq!(vault.labels().expect("labels"), vec!["main"]);
        assert_eq!(vault.public_key("main").expect("public key"), expected);
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn authenticated_plaintext_that_is_not_a_secret_key_is_refused() {
        let order = kat::unhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let below_order =
            kat::unhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
        let fixed = kdf::test_support::FixedKeyDerivation([7u8; 32]);
        let params = KdfPolicy::TEST.admit(64, 1, 1).expect("parameters");
        let seal = |secret: [u8; 32]| {
            sealed::seal_with_entropy(&secret, b"passphrase", params, [1u8; 16], [2u8; 24], &fixed)
                .expect("seal")
        };
        let import = |vault: &mut Vault, blob: &[u8]| {
            vault.import_encrypted_with("new", b"passphrase", blob, 200, &KdfPolicy::TEST, &fixed)
        };

        for invalid in [[0u8; 32], [0xff; 32], order.try_into().expect("32 bytes")] {
            let mut vault = Vault::new(VaultConfig::default()).expect("vault");
            vault
                .import_plaintext(
                    "keep",
                    SecretKey::from_bytes([0x11; 32]).expect("secret"),
                    100,
                )
                .expect("import plaintext");
            assert_eq!(
                import(&mut vault, &seal(invalid)),
                Err(VaultError::InvalidSecretKey)
            );
            assert_eq!(vault.labels().expect("labels"), vec!["keep"]);
            assert_eq!(vault.active_label(), Some("keep"));
        }

        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let valid: [u8; 32] = below_order.try_into().expect("32 bytes");
        assert_eq!(import(&mut vault, &seal(valid)), Ok(()));
        assert_eq!(vault.labels().expect("labels"), vec!["new"]);
    }

    #[test]
    fn legacy_format_message_names_the_migration_only_when_it_exists() {
        let message = VaultError::LegacyFormat(LegacyKind::V1Sha256).to_string();
        assert_eq!(
            message.contains("migrate_legacy_encrypted"),
            cfg!(feature = "legacy-migration"),
            "{message}"
        );
    }

    #[test]
    #[cfg(all(
        feature = "getrandom",
        any(feature = "encrypted", feature = "dm-epoch")
    ))]
    fn entropy_failures_become_random_unavailable() {
        for failure in [getrandom::Error::UNSUPPORTED, getrandom::Error::UNEXPECTED] {
            assert_eq!(
                map_entropy(Err(failure)),
                Err(VaultError::RandomUnavailable)
            );
        }
        assert_eq!(map_entropy(Ok(())), Ok(()));
    }

    #[test]
    fn debug_output_redacts_secret_keys() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        vault
            .import_plaintext(
                "main",
                SecretKey::from_bytes([0x22; 32]).expect("secret"),
                100,
            )
            .expect("import");

        let output = format!("{vault:?}");
        assert!(output.contains("main"), "{output}");
        assert!(output.contains("<redacted>"), "{output}");
        assert!(!output.contains("34, 34"), "{output}");
        assert!(!output.contains("2222"), "{output}");
    }

    #[test]
    fn entry_debug_redacts_the_secret_key() {
        let entry = Entry {
            secret: SecretKey::from_bytes([0x22; 32]).expect("secret"),
            last_used_unix_seconds: 4_242,
        };

        let output = format!("{entry:?}");
        assert!(output.contains("<redacted>"), "{output}");
        assert!(output.contains("last_used_unix_seconds: 4242"), "{output}");
        assert!(!output.contains("34, 34"), "{output}");
        assert!(!output.contains("2222"), "{output}");
        assert!(!format!("{entry:#?}").contains("34"), "{entry:#?}");
    }

    #[test]
    #[cfg(feature = "nip04")]
    fn nip04_roundtrip_between_vaults() {
        let mut alice = Vault::new(VaultConfig::default()).expect("alice vault");
        let mut bob = Vault::new(VaultConfig::default()).expect("bob vault");
        let alice_secret = generated_secret(0x11).expect("alice secret");
        let bob_secret = generated_secret(0x22).expect("bob secret");
        let alice_pubkey = alice_secret.xonly_public_key().expect("alice pubkey");
        let bob_pubkey = bob_secret.xonly_public_key().expect("bob pubkey");
        alice
            .import_plaintext("alice", alice_secret, 100)
            .expect("alice import");
        bob.import_plaintext("bob", bob_secret, 100)
            .expect("bob import");

        let payload = alice
            .nip04_encrypt_with_rng("alice", &bob_pubkey, "hello", 101, &mut secp_entropy)
            .expect("encrypt");
        let plaintext = bob
            .nip04_decrypt_with_rng("bob", &alice_pubkey, &payload, 102, &mut secp_entropy)
            .expect("decrypt");
        assert_eq!(plaintext, "hello");
    }

    #[test]
    #[cfg(feature = "nip04")]
    fn nip04_active_roundtrip_between_vaults() {
        let mut alice = Vault::new(VaultConfig::default()).expect("alice vault");
        let mut bob = Vault::new(VaultConfig::default()).expect("bob vault");
        let alice_secret = generated_secret(0x11).expect("alice secret");
        let bob_secret = generated_secret(0x22).expect("bob secret");
        let alice_pubkey = alice_secret.xonly_public_key().expect("alice pubkey");
        let bob_pubkey = bob_secret.xonly_public_key().expect("bob pubkey");
        alice
            .import_plaintext("alice", alice_secret, 100)
            .expect("alice import");
        bob.import_plaintext("bob", bob_secret, 100)
            .expect("bob import");

        let payload = alice
            .nip04_encrypt_active_with_rng(&bob_pubkey, "hello", 101, &mut secp_entropy)
            .expect("encrypt");
        let plaintext = bob
            .nip04_decrypt_active_with_rng(&alice_pubkey, &payload, 102, &mut secp_entropy)
            .expect("decrypt");
        assert_eq!(plaintext, "hello");
    }

    #[test]
    #[cfg(feature = "nip04")]
    fn nip04_missing_label_fails() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let peer = generated_secret(0x11)
            .expect("peer secret")
            .xonly_public_key()
            .expect("peer pubkey");
        let error = vault
            .nip04_encrypt_with_rng("missing", &peer, "hello", 100, &mut secp_entropy)
            .expect_err("missing label must fail");
        assert!(matches!(error, VaultError::MissingLabel));
    }

    #[test]
    #[cfg(feature = "nip04")]
    fn nip04_active_without_active_fails() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let peer = generated_secret(0x11)
            .expect("peer secret")
            .xonly_public_key()
            .expect("peer pubkey");
        let error = vault
            .nip04_encrypt_active_with_rng(&peer, "hello", 100, &mut secp_entropy)
            .expect_err("active label must exist");
        assert!(matches!(error, VaultError::NoActiveAccount));
    }

    #[test]
    #[cfg(feature = "nip44")]
    fn nip44_roundtrip_between_vaults() {
        let mut alice = Vault::new(VaultConfig::default()).expect("alice vault");
        let mut bob = Vault::new(VaultConfig::default()).expect("bob vault");
        let alice_secret = generated_secret(0x11).expect("alice secret");
        let bob_secret = generated_secret(0x22).expect("bob secret");
        let alice_pubkey = alice_secret.xonly_public_key().expect("alice pubkey");
        let bob_pubkey = bob_secret.xonly_public_key().expect("bob pubkey");
        alice
            .import_plaintext("alice", alice_secret, 100)
            .expect("alice import");
        bob.import_plaintext("bob", bob_secret, 100)
            .expect("bob import");

        let payload = alice
            .nip44_encrypt_with_rng("alice", &bob_pubkey, "hello", 101, &mut secp_entropy)
            .expect("encrypt");
        let plaintext = bob
            .nip44_decrypt_with_rng("bob", &alice_pubkey, &payload, 102, &mut secp_entropy)
            .expect("decrypt");
        assert_eq!(plaintext, "hello");
    }

    #[test]
    #[cfg(feature = "nip44")]
    fn nip44_active_roundtrip_between_vaults() {
        let mut alice = Vault::new(VaultConfig::default()).expect("alice vault");
        let mut bob = Vault::new(VaultConfig::default()).expect("bob vault");
        let alice_secret = generated_secret(0x11).expect("alice secret");
        let bob_secret = generated_secret(0x22).expect("bob secret");
        let alice_pubkey = alice_secret.xonly_public_key().expect("alice pubkey");
        let bob_pubkey = bob_secret.xonly_public_key().expect("bob pubkey");
        alice
            .import_plaintext("alice", alice_secret, 100)
            .expect("alice import");
        bob.import_plaintext("bob", bob_secret, 100)
            .expect("bob import");

        let payload = alice
            .nip44_encrypt_active_with_rng(&bob_pubkey, "hello", 101, &mut secp_entropy)
            .expect("encrypt");
        let plaintext = bob
            .nip44_decrypt_active_with_rng(&alice_pubkey, &payload, 102, &mut secp_entropy)
            .expect("decrypt");
        assert_eq!(plaintext, "hello");
    }

    #[test]
    #[cfg(feature = "nip44")]
    fn nip44_missing_label_fails() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let peer = generated_secret(0x11)
            .expect("peer secret")
            .xonly_public_key()
            .expect("peer pubkey");
        let error = vault
            .nip44_encrypt_with_rng("missing", &peer, "hello", 100, &mut secp_entropy)
            .expect_err("missing label must fail");
        assert!(matches!(error, VaultError::MissingLabel));
    }

    #[test]
    #[cfg(feature = "nip44")]
    fn nip44_active_without_active_fails() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let peer = generated_secret(0x11)
            .expect("peer secret")
            .xonly_public_key()
            .expect("peer pubkey");
        let error = vault
            .nip44_encrypt_active_with_rng(&peer, "hello", 100, &mut secp_entropy)
            .expect_err("active label must exist");
        assert!(matches!(error, VaultError::NoActiveAccount));
    }

    #[test]
    #[cfg(all(feature = "security-hardening", feature = "nip44"))]
    fn security_hardening_preserves_nip44_roundtrip() {
        let mut alice = Vault::new(VaultConfig::default()).expect("alice vault");
        let mut bob = Vault::new(VaultConfig::default()).expect("bob vault");
        let alice_secret = generated_secret(0x11).expect("alice secret");
        let bob_secret = generated_secret(0x22).expect("bob secret");
        let alice_pubkey = alice_secret.xonly_public_key().expect("alice pubkey");
        let bob_pubkey = bob_secret.xonly_public_key().expect("bob pubkey");
        let security = SecurityConfig {
            enable_constant_time: true,
            enable_random_delay: true,
            enable_dummy_operations: true,
        };
        alice.set_security_config(security);
        bob.set_security_config(security);
        alice
            .import_plaintext("alice", alice_secret, 100)
            .expect("alice import");
        bob.import_plaintext("bob", bob_secret, 100)
            .expect("bob import");

        let payload = alice
            .nip44_encrypt_with_rng("alice", &bob_pubkey, "hello", 101, &mut secp_entropy)
            .expect("encrypt");
        let plaintext = bob
            .nip44_decrypt_with_rng("bob", &alice_pubkey, &payload, 102, &mut secp_entropy)
            .expect("decrypt");
        assert_eq!(plaintext, "hello");
    }

    #[test]
    #[cfg(feature = "nip17")]
    fn vault_nip17_dm_roundtrip() {
        let mut vault_sender = Vault::new(VaultConfig::default()).expect("vault");
        let mut vault_recipient = Vault::new(VaultConfig::default()).expect("vault");
        let sender_secret = generated_secret(0x31).expect("sender");
        let recipient_secret = generated_secret(0x32).expect("recipient");
        vault_sender
            .import_plaintext("sender", sender_secret, 100)
            .expect("import");
        vault_recipient
            .import_plaintext("recipient", recipient_secret, 100)
            .expect("import");
        let recipient_pubkey = vault_recipient.public_key("recipient").expect("pubkey");
        let gift_wrap = vault_sender
            .create_sealed_dm_with_rng(
                "sender",
                "hello via vault",
                &recipient_pubkey,
                101,
                &mut secp_entropy,
            )
            .expect("create dm");
        assert_eq!(gift_wrap.kind, 1059);
        let inner = vault_recipient
            .open_gift_wrap_dm_with_rng("recipient", &gift_wrap, 102, &mut secp_entropy)
            .expect("open dm");
        assert_eq!(inner.kind, 14);
        assert_eq!(inner.content, "hello via vault");
    }

    #[test]
    #[cfg(feature = "nip17")]
    fn vault_nip17_missing_label_fails() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let peer = generated_secret(0x11)
            .expect("s")
            .xonly_public_key()
            .expect("x");
        assert!(vault
            .create_sealed_dm_with_rng("missing", "test", &peer, 100, &mut secp_entropy)
            .is_err());
    }

    #[test]
    #[cfg(feature = "nip17")]
    fn vault_nip17_scan_tag_roundtrip() {
        let mut vault_sender = Vault::new(VaultConfig::default()).expect("vault");
        let mut vault_recipient = Vault::new(VaultConfig::default()).expect("vault");
        let sender_secret = generated_secret(0x31).expect("sender");
        let recipient_secret = generated_secret(0x32).expect("recipient");
        vault_sender
            .import_plaintext("sender", sender_secret, 100)
            .expect("import");
        vault_recipient
            .import_plaintext("recipient", recipient_secret, 100)
            .expect("import");
        let recipient_pubkey = vault_recipient.public_key("recipient").expect("pubkey");
        let result = vault_sender
            .create_sealed_dm_with_scan_tag_with_rng(
                "sender",
                "hello via scan tag",
                &recipient_pubkey,
                &recipient_pubkey,
                101,
                &mut secp_entropy,
            )
            .expect("create dm");
        assert_eq!(result.event.kind, 1059);
        let computed =
            Vault::compute_scan_tag(&recipient_secret, &result.event.pubkey).expect("compute tag");
        assert_eq!(result.scanning_tag, computed);
        let inner = vault_recipient
            .open_gift_wrap_dm_with_rng("recipient", &result.event, 102, &mut secp_entropy)
            .expect("open dm");
        assert_eq!(inner.kind, 14);
        assert_eq!(inner.content, "hello via scan tag");
    }

    #[test]
    #[cfg(feature = "dm-epoch")]
    fn epoch_key_derivation_is_deterministic() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let secret = generated_secret(0x11).expect("secret");
        let peer = generated_secret(0x22).expect("peer");
        let peer_pub = peer.xonly_public_key().expect("peer pubkey");
        vault.import_plaintext("a", secret, 100).expect("import");

        let k1 = vault.derive_epoch_key("a", &peer_pub, 3).expect("k1");
        let k2 = vault.derive_epoch_key("a", &peer_pub, 3).expect("k2");
        assert_eq!(k1, k2);
    }

    #[test]
    #[cfg(feature = "dm-epoch")]
    fn epoch_key_rotation_produces_distinct_keys() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let secret = generated_secret(0x11).expect("secret");
        let peer = generated_secret(0x22).expect("peer");
        let peer_pub = peer.xonly_public_key().expect("peer pubkey");
        vault.import_plaintext("a", secret, 100).expect("import");

        let k0 = vault.derive_epoch_key("a", &peer_pub, 0).expect("k0");
        let k1 = vault.derive_epoch_key("a", &peer_pub, 1).expect("k1");
        let k2 = vault.derive_epoch_key("a", &peer_pub, 2).expect("k2");
        assert_ne!(k0, k1);
        assert_ne!(k1, k2);
        assert_ne!(k0, k2);
    }

    #[test]
    #[cfg(feature = "dm-epoch")]
    fn encrypt_decrypt_epoch_roundtrip() {
        let key = [0xab; 32];
        let plaintext = b"hello epoch encryption";
        let ct = Vault::encrypt_with_epoch_with_rng(&key, plaintext, &mut vault_entropy)
            .expect("encrypt");
        let pt = Vault::decrypt_with_epoch(&key, &ct).expect("decrypt");
        assert_eq!(pt, plaintext);
    }

    #[test]
    #[cfg(feature = "dm-epoch")]
    fn epoch_decrypt_wrong_key_fails() {
        let key = [0xab; 32];
        let wrong = [0xcd; 32];
        let ct = Vault::encrypt_with_epoch_with_rng(&key, b"secret", &mut vault_entropy)
            .expect("encrypt");
        assert!(Vault::decrypt_with_epoch(&wrong, &ct).is_err());
    }

    #[test]
    #[cfg(feature = "dm-epoch")]
    fn create_group_key_fails_closed_when_entropy_fails() {
        let error = Vault::create_group_key_with_rng(&mut |_| Err(VaultError::RandomUnavailable))
            .expect_err("an unavailable entropy source must fail");
        assert_eq!(error, VaultError::RandomUnavailable);

        let key = Vault::create_group_key_with_rng(&mut |buf| {
            buf.fill(0x5a);
            Ok(())
        })
        .expect("a working entropy source fills the key");
        assert_eq!(key, [0x5a; 32]);
    }

    #[test]
    #[cfg(feature = "dm-epoch")]
    fn create_group_key_is_unique_and_non_zero() {
        let mut seen = std::collections::HashSet::new();
        let mut counter = 1u64;
        for _ in 0..1_000 {
            let key = Vault::create_group_key_with_rng(&mut |output| {
                counted_vault_entropy(&mut counter, output)
            })
            .expect("group key");
            assert_ne!(key, [0u8; 32]);
            seen.insert(key);
        }
        assert_eq!(seen.len(), 1_000);
    }

    #[test]
    #[cfg(feature = "dm-epoch")]
    fn epoch_encryption_takes_its_nonce_from_the_entropy_source() {
        let key = [0xab; 32];
        assert_eq!(
            Vault::encrypt_with_epoch_with_rng(&key, b"secret", &mut |_| Err(
                VaultError::RandomUnavailable
            )),
            Err(VaultError::RandomUnavailable)
        );

        let ciphertext = Vault::encrypt_with_epoch_with_rng(&key, b"secret", &mut |buf| {
            buf.fill(0x5a);
            Ok(())
        })
        .expect("a working entropy source");
        assert_eq!(ciphertext[..12], [0x5a; 12]);
        assert_eq!(
            Vault::decrypt_with_epoch(&key, &ciphertext),
            Ok(b"secret".to_vec())
        );
    }

    #[test]
    #[cfg(feature = "dm-epoch")]
    fn epoch_encryption_draws_a_fresh_nonce_each_time() {
        let key = [0xab; 32];
        let mut nonces = std::collections::HashSet::new();
        let mut counter = 1u64;
        for _ in 0..1_000 {
            let ciphertext = Vault::encrypt_with_epoch_with_rng(&key, b"secret", &mut |output| {
                counted_vault_entropy(&mut counter, output)
            })
            .expect("encrypt");
            nonces.insert(ciphertext[..12].to_vec());
        }
        assert_eq!(nonces.len(), 1_000);
    }

    #[test]
    #[cfg(feature = "dm-epoch")]
    fn hex_decoding_accepts_only_ascii_hex_digit_pairs() {
        assert_eq!(
            neco_secp::hex::hex_decode("00ffAb").expect("valid hex"),
            vec![0x00, 0xff, 0xab]
        );
        assert_eq!(
            neco_secp::hex::hex_decode("").expect("empty hex"),
            Vec::new()
        );
        for rejected in [
            "0", "abc", "+f", "-1", "0x", "zz", " f", "f ", "aéb", "a€", "é", "éé", "𝟘𝟘",
        ] {
            assert!(
                neco_secp::hex::hex_decode(rejected).is_err(),
                "{rejected:?}"
            );
        }
    }

    #[test]
    #[cfg(feature = "dm-epoch")]
    fn epoch_failures_are_typed() {
        let key = [0xab; 32];
        let wrong = [0xcd; 32];
        assert_eq!(
            Vault::decrypt_with_epoch(&key, &[0u8; 27]),
            Err(VaultError::MalformedEncrypted(MalformedKind::TooShort {
                minimum: 28,
                actual: 27,
            }))
        );

        let ciphertext = Vault::encrypt_with_epoch_with_rng(&key, b"secret", &mut vault_entropy)
            .expect("encrypt");
        assert_eq!(
            Vault::decrypt_with_epoch(&key, &ciphertext),
            Ok(b"secret".to_vec())
        );
        assert_eq!(
            Vault::decrypt_with_epoch(&wrong, &ciphertext),
            Err(VaultError::AuthenticationFailed)
        );

        let empty = Vault::encrypt_with_epoch_with_rng(&key, b"", &mut vault_entropy)
            .expect("encrypt empty plaintext");
        assert_eq!(empty.len(), 28);
        assert_eq!(Vault::decrypt_with_epoch(&key, &empty), Ok(Vec::new()));
        assert_eq!(
            Vault::decrypt_with_epoch(&key, &[0u8; 28]),
            Err(VaultError::AuthenticationFailed)
        );

        let vault = Vault::new(VaultConfig::default()).expect("vault");
        assert_eq!(
            vault.decrypt_group_key("missing", &[0u8; 32]),
            Err(VaultError::MalformedEncrypted(MalformedKind::TooShort {
                minimum: 33,
                actual: 32,
            }))
        );
    }

    #[test]
    #[cfg(feature = "dm-epoch")]
    fn decrypt_group_key_failures_are_typed() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let recipient = SecretKey::from_bytes([0x11; 32]).expect("recipient");
        let recipient_pub = recipient.xonly_public_key().expect("recipient public key");
        vault.import_plaintext("r", recipient, 100).expect("import");
        let payload_failure = Err(VaultError::MalformedEncrypted(MalformedKind::Payload));

        let mut invalid_pubkey = vec![0xff; 32];
        invalid_pubkey.push(b'x');
        assert_eq!(
            vault.decrypt_group_key("r", &invalid_pubkey),
            payload_failure
        );

        let ephemeral = SecretKey::from_bytes([0x22; 32]).expect("ephemeral");
        let ephemeral_pub = ephemeral.xonly_public_key().expect("ephemeral public key");
        let conversation_key =
            neco_secp::nip44::get_conversation_key(&ephemeral, &recipient_pub).expect("key");
        let seal = |plaintext: &str| {
            let payload = neco_secp::nip44::encrypt_with_rng(
                plaintext,
                &conversation_key,
                None,
                &mut secp_entropy,
            )
            .expect("payload");
            let mut out = ephemeral_pub.to_bytes().to_vec();
            out.extend_from_slice(payload.as_bytes());
            out
        };

        assert_eq!(
            vault.decrypt_group_key("r", &seal(&"ab".repeat(32))),
            Ok([0xab; 32])
        );

        let mut not_utf8 = ephemeral_pub.to_bytes().to_vec();
        not_utf8.extend_from_slice(&[0xff, 0xfe, 0xfd]);
        assert_eq!(vault.decrypt_group_key("r", &not_utf8), payload_failure);
        assert!(matches!(
            vault.decrypt_group_key("r", &seal(&"zz".repeat(32))),
            Err(VaultError::Crypto(_))
        ));
        assert_eq!(
            vault.decrypt_group_key("r", &seal(&"ab".repeat(31))),
            payload_failure
        );
        for plaintext in [
            "aéb".to_string(),
            "a€".to_string(),
            format!("+f{}", "ab".repeat(31)),
        ] {
            assert!(
                matches!(
                    vault.decrypt_group_key("r", &seal(&plaintext)),
                    Err(VaultError::Crypto(_))
                ),
                "{plaintext:?}"
            );
        }

        let mut not_nip44 = ephemeral_pub.to_bytes().to_vec();
        not_nip44.extend_from_slice(b"not a nip44 payload");
        assert!(matches!(
            vault.decrypt_group_key("r", &not_nip44),
            Err(VaultError::Crypto(_))
        ));
    }

    #[test]
    #[cfg(feature = "dm-epoch")]
    fn encrypt_decrypt_group_key_roundtrip() {
        let mut vault = Vault::new(VaultConfig::default()).expect("vault");
        let secret = generated_secret(0x11).expect("secret");
        let pubkey = secret.xonly_public_key().expect("pubkey");
        vault.import_plaintext("r", secret, 100).expect("import");

        let group_key = Vault::create_group_key_with_rng(&mut vault_entropy).expect("group key");
        let encrypted = Vault::encrypt_group_key_with_rng(&group_key, &pubkey, &mut secp_entropy)
            .expect("encrypt group key");
        let decrypted = vault
            .decrypt_group_key("r", &encrypted)
            .expect("decrypt group key");
        assert_eq!(group_key, decrypted);
    }

    #[test]
    #[cfg(feature = "dm-epoch")]
    fn group_message_roundtrip() {
        let key = Vault::create_group_key_with_rng(&mut vault_entropy).expect("group key");
        let msg = b"group message content";
        let ct =
            Vault::encrypt_group_message_with_rng(&key, msg, &mut vault_entropy).expect("encrypt");
        let pt = Vault::decrypt_group_message(&key, &ct).expect("decrypt");
        assert_eq!(pt, msg);
    }

    #[test]
    #[cfg(feature = "dm-epoch")]
    fn rotate_group_epoch_deterministic_and_distinct() {
        let k0 = [0x42; 32];
        let k1 = Vault::rotate_group_epoch(&k0).expect("rotation");
        let k1_again = Vault::rotate_group_epoch(&k0).expect("rotation");
        assert_eq!(k1, k1_again, "rotation must be deterministic");
        assert_ne!(k0, k1, "rotated key must differ from input");
    }
}
