use crate::types::{
    copy_text, js_error, now_unix_seconds, parse_secret_key, parse_security_config,
    parse_signed_event, parse_unsigned_event, parse_xonly_public_key, stringify_signed_event,
};
use neco_secp::Nip19;
use neco_vault::{Vault, VaultConfig};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct NostrSigner {
    inner: Vault,
}

#[wasm_bindgen]
impl NostrSigner {
    #[wasm_bindgen(constructor)]
    pub fn new(cache_timeout_seconds: u64) -> Result<NostrSigner, JsValue> {
        let vault = Vault::new(VaultConfig {
            cache_timeout_seconds,
            security: neco_vault::SecurityConfig::default(),
        })
        .map_err(js_error)?;
        Ok(Self { inner: vault })
    }

    pub fn add_account_with_plaintext(
        &mut self,
        label: &str,
        secret_hex: &str,
    ) -> Result<(), JsValue> {
        let secret = parse_secret_key(secret_hex)?;
        self.inner
            .import_plaintext(label, secret, now_unix_seconds()?)
            .map_err(js_error)
    }

    pub fn add_account(
        &mut self,
        label: &str,
        encrypted: &[u8],
        passphrase: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .import_encrypted(label, passphrase.as_bytes(), encrypted, now_unix_seconds()?)
            .map_err(js_error)
    }

    pub fn remove_account(&mut self, label: &str) -> Result<(), JsValue> {
        self.inner.remove(label).map_err(js_error)
    }

    pub fn get_accounts(&self) -> Result<String, JsValue> {
        let labels = self.inner.labels().map_err(js_error)?;
        crate::json::encode(|output| crate::json::write_strings(output, &labels)).map_err(js_error)
    }

    pub fn get_active_account(&self) -> Result<Option<String>, JsValue> {
        self.inner.active_label().map(copy_text).transpose()
    }

    pub fn set_active_account(&mut self, label: &str) -> Result<(), JsValue> {
        self.inner.set_active(label).map_err(js_error)
    }

    pub fn get_public_key(&self, label: &str) -> Result<String, JsValue> {
        self.inner
            .public_key(label)
            .and_then(|pubkey| pubkey.to_hex().map_err(neco_vault::VaultError::Crypto))
            .map_err(js_error)
    }

    pub fn encrypt_secret_key(&self, label: &str, passphrase: &str) -> Result<Vec<u8>, JsValue> {
        self.inner
            .export_encrypted(label, passphrase.as_bytes())
            .map_err(js_error)
    }

    pub fn sign_event(&mut self, json: &str) -> Result<String, JsValue> {
        let unsigned = parse_unsigned_event(json)?;
        let signed = self
            .inner
            .sign_event_active(unsigned, now_unix_seconds()?)
            .map_err(js_error)?;
        stringify_signed_event(&signed)
    }

    pub fn sign_event_with(&mut self, label: &str, json: &str) -> Result<String, JsValue> {
        let unsigned = parse_unsigned_event(json)?;
        let signed = self
            .inner
            .sign_event(label, unsigned, now_unix_seconds()?)
            .map_err(js_error)?;
        stringify_signed_event(&signed)
    }

    pub fn nip04_encrypt(&mut self, peer_hex: &str, plaintext: &str) -> Result<String, JsValue> {
        let peer = parse_xonly_public_key(peer_hex)?;
        self.inner
            .nip04_encrypt_active(&peer, plaintext, now_unix_seconds()?)
            .map_err(js_error)
    }

    pub fn nip04_decrypt(&mut self, peer_hex: &str, payload: &str) -> Result<String, JsValue> {
        let peer = parse_xonly_public_key(peer_hex)?;
        self.inner
            .nip04_decrypt_active(&peer, payload, now_unix_seconds()?)
            .map_err(js_error)
    }

    pub fn nip44_encrypt(&mut self, peer_hex: &str, plaintext: &str) -> Result<String, JsValue> {
        let peer = parse_xonly_public_key(peer_hex)?;
        self.inner
            .nip44_encrypt_active(&peer, plaintext, now_unix_seconds()?)
            .map_err(js_error)
    }

    pub fn nip44_decrypt(&mut self, peer_hex: &str, payload: &str) -> Result<String, JsValue> {
        let peer = parse_xonly_public_key(peer_hex)?;
        self.inner
            .nip44_decrypt_active(&peer, payload, now_unix_seconds()?)
            .map_err(js_error)
    }

    pub fn create_sealed_dm(
        &mut self,
        content: &str,
        recipient_hex: &str,
    ) -> Result<String, JsValue> {
        let recipient = parse_xonly_public_key(recipient_hex)?;
        let label = copy_text(
            self.inner
                .active_label()
                .ok_or_else(|| JsValue::from_str("no active account"))?,
        )?;
        let gift_wrap = self
            .inner
            .create_sealed_dm(&label, content, &recipient, now_unix_seconds()?)
            .map_err(js_error)?;
        stringify_signed_event(&gift_wrap)
    }

    pub fn open_gift_wrap(&mut self, json: &str) -> Result<String, JsValue> {
        let gift_wrap = parse_signed_event(json)?;
        let label = copy_text(
            self.inner
                .active_label()
                .ok_or_else(|| JsValue::from_str("no active account"))?,
        )?;
        let event = self
            .inner
            .open_gift_wrap_dm(&label, &gift_wrap, now_unix_seconds()?)
            .map_err(js_error)?;
        neco_secp::nostr::serialize_rumor(&event).map_err(js_error)
    }

    pub fn create_auth_event(
        &mut self,
        challenge: &str,
        relay_url: &str,
    ) -> Result<String, JsValue> {
        let event = self
            .inner
            .create_auth_event_active(challenge, relay_url, now_unix_seconds()?)
            .map_err(js_error)?;
        stringify_signed_event(&event)
    }

    /// `nsec` を復号し、秘密鍵を `label` のアカウントとして保管庫へ取り込む。
    /// 平文の秘密鍵を hex 文字列で返す関数は、自由関数の `decode_nsec` が担う。
    pub fn decode_nsec(&mut self, nsec: &str, label: &str) -> Result<(), JsValue> {
        match neco_secp::nip19::decode(nsec).map_err(js_error)? {
            Nip19::Nsec(secret) => self
                .inner
                .import_plaintext(label, secret, now_unix_seconds()?)
                .map_err(js_error),
            _ => Err(JsValue::from_str("expected nsec string")),
        }
    }

    pub fn clear_cache(&mut self) {
        self.inner.clear_cache();
    }

    pub fn clear_expired_cache(&mut self) -> Result<(), JsValue> {
        self.inner.clear_expired_cache(now_unix_seconds()?);
        Ok(())
    }

    pub fn set_security_config(&mut self, json: &str) -> Result<(), JsValue> {
        let security = parse_security_config(json)?;
        self.inner.set_security_config(security);
        Ok(())
    }
}

/// 旧形式 ( v1、v2 ) の暗号化された秘密鍵を v3 形式へ変換する。入力と出力はメモリ上のバイト列。
/// 旧パスフレーズでの復号は 1 回だけ試す。正規化した形での再試行は呼び出し側が行う。
#[wasm_bindgen]
pub fn migrate_legacy_encrypted(
    legacy: &[u8],
    old_passphrase: &str,
    new_passphrase: &str,
) -> Result<Vec<u8>, JsValue> {
    neco_vault::migrate_legacy_encrypted(
        legacy,
        old_passphrase.as_bytes(),
        new_passphrase.as_bytes(),
    )
    .map_err(js_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neco_json::JsonValue;

    const SECRET_1: &str = "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef";
    const PUBLIC_1: &str = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659";
    const LEGACY_V2_BLOB: &str = concat!(
        "020f0801404142434445464748494a4b4c4d4e4f505152535455565758595a5b",
        "5c5d5e5f707172737475767778797a7b7c7d7e7feae62227360ab5cf874d7c74",
        "26c053376f489ed02560a92e65015c88f078406b845494532f04a8efe8cfe797",
        "2d2bf7f0",
    );

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit pair"))
            .collect()
    }

    #[test]
    fn signer_signs_with_active_account() {
        let mut signer = NostrSigner::new(300).expect("signer");
        let secret = neco_secp::SecretKey::generate().expect("secret");
        signer
            .add_account_with_plaintext("main", &secret.to_hex().expect("hex"))
            .expect("add account");

        let json = r#"{"created_at":1,"kind":1,"tags":[],"content":"hello"}"#;
        let signed = signer.sign_event(json).expect("sign event");
        let signed = neco_secp::nostr::parse_signed_event(&signed).expect("parse");
        neco_secp::nostr::verify_event(&signed).expect("verify");
    }

    #[test]
    fn signer_roundtrips_gift_wrap() {
        let sender_secret = neco_secp::SecretKey::generate().expect("sender");
        let recipient_secret = neco_secp::SecretKey::generate().expect("recipient");
        let recipient_hex = recipient_secret
            .xonly_public_key()
            .expect("pubkey")
            .to_hex()
            .expect("hex");

        let mut sender = NostrSigner::new(300).expect("sender signer");
        sender
            .add_account_with_plaintext("sender", &sender_secret.to_hex().expect("hex"))
            .expect("add sender");
        let mut recipient = NostrSigner::new(300).expect("recipient signer");
        recipient
            .add_account_with_plaintext("recipient", &recipient_secret.to_hex().expect("hex"))
            .expect("add recipient");

        let gift_wrap = sender
            .create_sealed_dm("hello", &recipient_hex)
            .expect("create dm");
        let opened = recipient.open_gift_wrap(&gift_wrap).expect("open");
        let opened = neco_secp::nostr::parse_rumor(&opened).expect("parse");
        assert_eq!(opened.content, "hello");
    }

    #[test]
    fn signer_sets_security_config() {
        let mut signer = NostrSigner::new(300).expect("signer");
        signer
            .set_security_config(
                r#"{"enable_constant_time":false,"enable_random_delay":true,"enable_dummy_operations":true}"#,
            )
            .expect("set config");
    }

    #[test]
    fn signer_create_auth_event_matches_validate_boundary() {
        let mut signer = NostrSigner::new(300).expect("signer");
        let secret = neco_secp::SecretKey::from_bytes([0x21; 32]).expect("secret");
        let pubkey = secret
            .xonly_public_key()
            .expect("pubkey")
            .to_hex()
            .expect("hex");
        signer
            .add_account_with_plaintext("main", &secret.to_hex().expect("hex"))
            .expect("add account");

        let json = signer
            .create_auth_event("challenge-123", "wss://relay.example.com")
            .expect("auth");
        let validated =
            crate::secp::validate_auth_event(&json, "challenge-123", "wss://relay.example.com")
                .expect("validate");

        assert_eq!(validated, pubkey);
    }

    #[test]
    fn signer_get_accounts_returns_json_array() {
        let mut signer = NostrSigner::new(300).expect("signer");
        let alice = neco_secp::SecretKey::from_bytes([0x22; 32]).expect("alice");
        let bob = neco_secp::SecretKey::from_bytes([0x23; 32]).expect("bob");
        signer
            .add_account_with_plaintext("alice", &alice.to_hex().expect("hex"))
            .expect("add alice");
        signer
            .add_account_with_plaintext("bob", &bob.to_hex().expect("hex"))
            .expect("add bob");

        let labels = signer.get_accounts().expect("accounts");
        let labels = neco_json::parse(labels.as_bytes()).expect("json");
        let labels = labels.as_array().expect("array");
        assert_eq!(labels.len(), 2);
        assert!(labels
            .iter()
            .any(|item| item == &JsonValue::String("alice".to_string())));
        assert!(labels
            .iter()
            .any(|item| item == &JsonValue::String("bob".to_string())));
    }

    #[test]
    fn signer_exports_and_imports_account() {
        let mut signer = NostrSigner::new(300).expect("signer");
        signer
            .add_account_with_plaintext("main", SECRET_1)
            .expect("add account");
        let blob = signer
            .encrypt_secret_key("main", "correct horse battery staple")
            .expect("export");
        assert_eq!(blob.len(), 105);

        let mut restored = NostrSigner::new(300).expect("restored signer");
        restored
            .add_account("main", &blob, "correct horse battery staple")
            .expect("import");
        assert_eq!(
            restored.get_public_key("main").expect("public key"),
            PUBLIC_1
        );
    }

    #[test]
    fn migrate_binding_produces_importable_blob() {
        let legacy = unhex(LEGACY_V2_BLOB);
        let blob = migrate_legacy_encrypted(&legacy, "legacy passphrase", "new passphrase")
            .expect("migrate");
        assert_eq!(blob.len(), 105);

        let mut signer = NostrSigner::new(300).expect("signer");
        signer
            .add_account("main", &blob, "new passphrase")
            .expect("import");
        assert_eq!(signer.get_public_key("main").expect("public key"), PUBLIC_1);
    }
}
