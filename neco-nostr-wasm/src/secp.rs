use crate::types::{
    js_error, nip19_to_json, parse_event_id, parse_event_with_pubkey, parse_naddr, parse_nevent,
    parse_nprofile, parse_public_key, parse_secret_key, parse_signed_event, parse_unsigned_event,
    parse_xonly_public_key, stringify_signed_event,
};
use bech32::{Bech32Writer, ToBase32, Variant};
use neco_secp::SecpError;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn encode_npub(hex: &str) -> Result<String, JsValue> {
    let pubkey = parse_xonly_public_key(hex)?;
    neco_secp::nip19::encode_npub(&pubkey).map_err(js_error)
}

#[wasm_bindgen]
pub fn encode_note(hex: &str) -> Result<String, JsValue> {
    let id = parse_event_id(hex)?;
    neco_secp::nip19::encode_note(&id).map_err(js_error)
}

#[wasm_bindgen]
pub fn encode_nevent(json: &str) -> Result<String, JsValue> {
    let event = parse_nevent(json)?;
    neco_secp::nip19::encode_nevent(&event).map_err(js_error)
}

#[wasm_bindgen]
pub fn encode_nprofile(json: &str) -> Result<String, JsValue> {
    let profile = parse_nprofile(json)?;
    neco_secp::nip19::encode_nprofile(&profile).map_err(js_error)
}

#[wasm_bindgen]
pub fn encode_naddr(json: &str) -> Result<String, JsValue> {
    let addr = parse_naddr(json)?;
    neco_secp::nip19::encode_naddr(&addr).map_err(js_error)
}

#[wasm_bindgen]
pub fn encode_nsec(secret_hex: &str) -> Result<String, JsValue> {
    let secret = parse_secret_key(secret_hex)?;
    neco_secp::nip19::encode_nsec(&secret).map_err(js_error)
}

/// `nsec` を復号し、平文の秘密鍵を hex 文字列で返す。
/// 保管庫へ取り込むメソッドは `NostrSigner::decode_nsec` が担う。
#[wasm_bindgen]
pub fn decode_nsec(nsec: &str) -> Result<String, JsValue> {
    match neco_secp::nip19::decode(nsec).map_err(js_error)? {
        neco_secp::Nip19::Nsec(secret) => secret.to_hex().map_err(js_error),
        _ => Err(js_error(SecpError::InvalidNip19("expected nsec string"))),
    }
}

#[wasm_bindgen]
pub fn encode_lnurl(url: &str) -> Result<String, JsValue> {
    let input_len = url.len();
    let data_len = input_len
        .checked_mul(8)
        .and_then(|bits| bits.checked_add(4))
        .map(|bits| bits / 5)
        .ok_or_else(|| js_error(SecpError::CapacityOverflow { input_len }))?;
    let total = data_len
        .checked_add(5)
        .and_then(|len| len.checked_add(1))
        .and_then(|len| len.checked_add(6))
        .ok_or_else(|| js_error(SecpError::CapacityOverflow { input_len }))?;
    if total > isize::MAX as usize {
        return Err(js_error(SecpError::CapacityOverflow { input_len }));
    }

    let mut output = String::new();
    output
        .try_reserve_exact(total)
        .map_err(|_| js_error(SecpError::AllocationFailed { required: total }))?;
    let mut writer = Bech32Writer::new("lnurl", Variant::Bech32, &mut output)
        .map_err(|_| js_error(SecpError::InvalidNip19("failed to encode lnurl")))?;
    url.as_bytes()
        .write_base32(&mut writer)
        .map_err(|_| js_error(SecpError::InvalidNip19("failed to encode lnurl")))?;
    writer
        .finalize()
        .map_err(|_| js_error(SecpError::InvalidNip19("failed to encode lnurl")))?;
    Ok(output)
}

/// NIP-19 の識別子を復号し、JSON の文字列で返す。`nsec` は失敗として拒否する。
#[wasm_bindgen]
pub fn decode_bech32(bech32: &str) -> Result<String, JsValue> {
    let decoded = neco_secp::nip19::decode(bech32).map_err(js_error)?;
    nip19_to_json(decoded, false)
}

#[wasm_bindgen]
pub fn generate_secret_key() -> Result<String, JsValue> {
    Err(JsValue::from_str(
        "plaintext secret export is disabled; use vanity mining output if needed",
    ))
}

#[wasm_bindgen]
pub fn derive_public_key(secret_hex: &str) -> Result<String, JsValue> {
    let secret = parse_secret_key(secret_hex)?;
    secret
        .xonly_public_key()
        .and_then(|pubkey| pubkey.to_hex())
        .map_err(js_error)
}

#[wasm_bindgen]
pub fn derive_public_key_sec1(secret_hex: &str) -> Result<String, JsValue> {
    let secret = parse_secret_key(secret_hex)?;
    secret
        .public_key()
        .and_then(|pubkey| pubkey.to_hex())
        .map_err(js_error)
}

#[wasm_bindgen]
pub fn parse_public_key_hex(public_key_hex: &str) -> Result<String, JsValue> {
    let public = parse_public_key(public_key_hex)?;
    public.to_hex().map_err(js_error)
}

#[wasm_bindgen]
pub fn finalize_event(json: &str, secret_hex: &str) -> Result<String, JsValue> {
    let event = parse_unsigned_event(json)?;
    let secret = parse_secret_key(secret_hex)?;
    let signed = neco_secp::nostr::finalize_event(event, &secret).map_err(js_error)?;
    stringify_signed_event(&signed)
}

#[wasm_bindgen]
pub fn verify_event(json: &str) -> Result<bool, JsValue> {
    let event = parse_signed_event(json)?;
    match neco_secp::nostr::verify_event(&event) {
        Ok(()) => Ok(true),
        Err(SecpError::InvalidSignature | SecpError::InvalidEvent(_)) => Ok(false),
        Err(error) => Err(js_error(error)),
    }
}

#[wasm_bindgen]
pub fn serialize_event(json: &str) -> Result<String, JsValue> {
    let (pubkey, event) = parse_event_with_pubkey(json)?;
    neco_secp::nostr::serialize_event(&pubkey, &event).map_err(js_error)
}

#[wasm_bindgen]
pub fn get_event_hash(json: &str) -> Result<String, JsValue> {
    let (pubkey, event) = parse_event_with_pubkey(json)?;
    neco_secp::nostr::compute_event_id(&pubkey, &event)
        .and_then(|id| id.to_hex())
        .map_err(js_error)
}

#[wasm_bindgen]
pub fn validate_auth_event(
    json: &str,
    challenge: &str,
    relay_url: &str,
) -> Result<String, JsValue> {
    let event = parse_signed_event(json)?;
    neco_secp::nip42::validate_auth_event(&event, challenge, relay_url)
        .and_then(|pubkey| pubkey.to_hex())
        .map_err(js_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neco_secp::{nip19, EventId, NAddr, NEvent, NProfile, NRelay, SecretKey, UnsignedEvent};

    #[test]
    fn finalize_and_verify_event_roundtrip() {
        let secret = SecretKey::generate().expect("secret");
        let unsigned = r#"{"created_at":10,"kind":1,"tags":[],"content":"hello"}"#;
        let secret_hex = secret.to_hex().expect("secret hex");
        let signed = finalize_event(unsigned, &secret_hex).expect("finalize");
        assert!(verify_event(&signed).expect("verify"));
    }

    #[test]
    fn finalize_event_matches_core_output() {
        let secret = SecretKey::from_bytes([0x11; 32]).expect("secret");
        let unsigned = UnsignedEvent {
            created_at: 1_700_000_000,
            kind: 1,
            tags: vec![vec!["p".to_string(), "abc".to_string()]],
            content: "hello".to_string(),
        };
        let json = r#"{"created_at":1700000000,"kind":1,"tags":[["p","abc"]],"content":"hello"}"#;

        let secret_hex = secret.to_hex().expect("secret hex");
        let wasm_signed = finalize_event(json, &secret_hex).expect("wasm finalize");
        let wasm_signed = neco_secp::nostr::parse_signed_event(&wasm_signed).expect("parse wasm");
        let core_signed = neco_secp::nostr::finalize_event(unsigned, &secret).expect("core");

        assert_eq!(wasm_signed.id, core_signed.id);
        assert_eq!(wasm_signed.pubkey, core_signed.pubkey);
        assert_eq!(wasm_signed.created_at, core_signed.created_at);
        assert_eq!(wasm_signed.kind, core_signed.kind);
        assert_eq!(wasm_signed.tags, core_signed.tags);
        assert_eq!(wasm_signed.content, core_signed.content);
        neco_secp::nostr::verify_event(&wasm_signed).expect("verify wasm");
        neco_secp::nostr::verify_event(&core_signed).expect("verify core");
    }

    #[test]
    fn wasm_matches_known_nostr_tools_fixture() {
        let secret = SecretKey::from_hex(
            "d217c1ff2f8a65c3e3a1740db3b9f58b\
             8c848bb45e26d00ed4714e4a0f4ceecf",
        )
        .expect("secret");
        let pubkey = secret.xonly_public_key().expect("pubkey");
        let unsigned_json =
            r#"{"created_at":1617932115,"kind":1,"tags":[],"content":"Hello, world!"}"#;
        let with_pubkey = format!(
            r#"{{"pubkey":"{}","created_at":1617932115,"kind":1,"tags":[],"content":"Hello, world!"}}"#,
            pubkey.to_hex().expect("pubkey hex")
        );

        let secret_hex = secret.to_hex().expect("secret hex");
        let finalized = finalize_event(unsigned_json, &secret_hex).expect("finalize");
        let serialized = serialize_event(&with_pubkey).expect("serialize");
        let hash = get_event_hash(&with_pubkey).expect("hash");
        let decoded_npub =
            decode_bech32("npub1dtc0nhjc3uk98nkuhgnvtcjq9cxs4fjwc768e8udj76mc43t4d0sw73h32")
                .expect("decode npub");
        let decoded_npub = neco_json::parse(decoded_npub.as_bytes()).expect("npub json");
        let decoded_nprofile = decode_bech32(
            "nprofile1qy28wumn8ghj7un9d3shjtnyv9kh2uewd9hsz9mhwden5te0dehhxarj9ejhsctdwpkx2tnrdaksqgr27ruauky093fuah96ymz7yspwp592vnk8k37flrvhkk79v2attuwkrkwx",
        )
        .expect("decode nprofile");
        let decoded_nprofile = neco_json::parse(decoded_nprofile.as_bytes()).expect("json");

        let finalized_value = neco_json::parse(finalized.as_bytes()).expect("signed json");
        assert_eq!(
            serialized,
            r#"[0,"6af0f9de588f2c53cedcba26c5e2402e0d0aa64ec7b47c9f8d97b5bc562bab5f",1617932115,1,[],"Hello, world!"]"#
        );
        assert_eq!(
            hash,
            "b2a44af84ca99b14820ae91c44e1ef0908f8aadc4e10620a6e6caa344507f03c"
        );
        assert_eq!(
            finalized_value.required_str("id").expect("id"),
            "b2a44af84ca99b14820ae91c44e1ef0908f8aadc4e10620a6e6caa344507f03c"
        );
        assert_eq!(finalized_value.required_str("sig").expect("sig").len(), 128);
        assert_eq!(decoded_npub.required_str("kind").expect("kind"), "npub");
        assert_eq!(
            decoded_npub.required_str("pubkey_hex").expect("pubkey_hex"),
            "6af0f9de588f2c53cedcba26c5e2402e0d0aa64ec7b47c9f8d97b5bc562bab5f"
        );
        assert_eq!(
            decoded_nprofile.required_str("kind").expect("kind"),
            "nprofile"
        );
        assert_eq!(
            decoded_nprofile
                .required_str("pubkey_hex")
                .expect("pubkey_hex"),
            "6af0f9de588f2c53cedcba26c5e2402e0d0aa64ec7b47c9f8d97b5bc562bab5f"
        );
        let relays = decoded_nprofile.required_array("relays").expect("relays");
        assert_eq!(relays.len(), 2);
        assert_eq!(relays[0].as_str().expect("relay"), "wss://relay.damus.io");
        assert_eq!(
            relays[1].as_str().expect("relay"),
            "wss://nostr.example.com"
        );
        assert!(verify_event(&finalized).expect("verify"));
    }

    #[test]
    fn serialize_and_hash_match_core() {
        let secret = SecretKey::from_bytes([0x12; 32]).expect("secret");
        let pubkey = secret.xonly_public_key().expect("pubkey");
        let json = format!(
            r#"{{"pubkey":"{}","created_at":42,"kind":1,"tags":[["e","deadbeef"]],"content":"hi"}}"#,
            pubkey.to_hex().expect("pubkey hex")
        );
        let unsigned = UnsignedEvent {
            created_at: 42,
            kind: 1,
            tags: vec![vec!["e".to_string(), "deadbeef".to_string()]],
            content: "hi".to_string(),
        };

        let wasm_serialized = serialize_event(&json).expect("wasm serialize");
        let wasm_hash = get_event_hash(&json).expect("wasm hash");
        let core_serialized = neco_secp::nostr::serialize_event(&pubkey, &unsigned).expect("core");
        let core_hash = neco_secp::nostr::compute_event_id(&pubkey, &unsigned).expect("core id");

        assert_eq!(wasm_serialized, core_serialized);
        assert_eq!(wasm_hash, core_hash.to_hex().expect("core hash hex"));
    }

    #[test]
    fn decode_bech32_returns_full_nprofile_json() {
        let pubkey = SecretKey::from_bytes([0x13; 32])
            .expect("secret")
            .xonly_public_key()
            .expect("pubkey");
        let encoded = nip19::encode_nprofile(&NProfile {
            pubkey,
            relays: vec![
                "wss://relay.example".to_string(),
                "wss://relay2.example".to_string(),
            ],
        })
        .expect("encode");

        let decoded = decode_bech32(&encoded).expect("decode");
        let decoded = neco_json::parse(decoded.as_bytes()).expect("json");
        assert_eq!(decoded.required_str("kind").expect("kind"), "nprofile");
        assert_eq!(
            decoded.required_str("pubkey_hex").expect("pubkey_hex"),
            pubkey.to_hex().expect("pubkey hex")
        );
        let relays = decoded.required_array("relays").expect("relays");
        assert_eq!(relays.len(), 2);
        assert_eq!(relays[0].as_str().expect("relay"), "wss://relay.example");
        assert_eq!(relays[1].as_str().expect("relay"), "wss://relay2.example");
    }

    #[test]
    fn decode_bech32_returns_full_nevent_json() {
        let author = SecretKey::from_bytes([0x14; 32])
            .expect("secret")
            .xonly_public_key()
            .expect("author");
        let encoded = nip19::encode_nevent(&NEvent {
            id: EventId::from_bytes([0x22; 32]),
            relays: vec!["wss://relay.example".to_string()],
            author: Some(author),
            kind: Some(30_023),
        })
        .expect("encode");

        let decoded = decode_bech32(&encoded).expect("decode");
        let decoded = neco_json::parse(decoded.as_bytes()).expect("json");
        assert_eq!(decoded.required_str("kind").expect("kind"), "nevent");
        assert_eq!(
            decoded.required_str("id_hex").expect("id_hex"),
            "22".repeat(32)
        );
        assert_eq!(
            decoded.required_str("author_hex").expect("author_hex"),
            author.to_hex().expect("author hex")
        );
        assert_eq!(
            decoded.get("event_kind").and_then(|v| v.as_f64()),
            Some(30_023.0)
        );
        let relays = decoded.required_array("relays").expect("relays");
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0].as_str().expect("relay"), "wss://relay.example");
    }

    #[test]
    fn decode_bech32_returns_full_naddr_and_nrelay_json() {
        let author = SecretKey::from_bytes([0x15; 32])
            .expect("secret")
            .xonly_public_key()
            .expect("author");
        let naddr = nip19::encode_naddr(&NAddr {
            identifier: "article".to_string(),
            relays: vec!["wss://relay.example".to_string()],
            author,
            kind: 30_023,
        })
        .expect("naddr");
        let nrelay = nip19::encode_nrelay(&NRelay {
            relay: "wss://relay.example".to_string(),
        })
        .expect("nrelay");

        let naddr = neco_json::parse(decode_bech32(&naddr).expect("decode naddr").as_bytes())
            .expect("naddr json");
        let nrelay = neco_json::parse(decode_bech32(&nrelay).expect("decode nrelay").as_bytes())
            .expect("nrelay json");

        assert_eq!(naddr.required_str("kind").expect("kind"), "naddr");
        assert_eq!(
            naddr.required_str("identifier").expect("identifier"),
            "article"
        );
        assert_eq!(
            naddr.required_str("author_hex").expect("author_hex"),
            author.to_hex().expect("author hex")
        );
        assert_eq!(
            naddr.get("event_kind").and_then(|v| v.as_f64()),
            Some(30_023.0)
        );
        assert_eq!(nrelay.required_str("kind").expect("kind"), "nrelay");
        assert_eq!(
            nrelay.required_str("relay").expect("relay"),
            "wss://relay.example"
        );
    }

    #[test]
    fn encode_profile_addr_and_nsec_match_core() {
        let secret = SecretKey::from_bytes([0x31; 32]).expect("secret");
        let pubkey = secret.xonly_public_key().expect("pubkey");
        let pubkey_hex = pubkey.to_hex().expect("pubkey hex");

        let nprofile_json = format!(
            r#"{{"pubkey":"{}","relays":["wss://relay.example","wss://relay2.example"]}}"#,
            pubkey_hex
        );
        let naddr_json = format!(
            r#"{{"identifier":"article","pubkey":"{}","kind":30023,"relays":["wss://relay.example"]}}"#,
            pubkey_hex
        );

        let wasm_nprofile = encode_nprofile(&nprofile_json).expect("wasm nprofile");
        let wasm_naddr = encode_naddr(&naddr_json).expect("wasm naddr");
        let secret_hex = secret.to_hex().expect("secret hex");
        let wasm_nsec = encode_nsec(&secret_hex).expect("wasm nsec");

        let core_nprofile = neco_secp::nip19::encode_nprofile(&NProfile {
            pubkey,
            relays: vec![
                "wss://relay.example".to_string(),
                "wss://relay2.example".to_string(),
            ],
        })
        .expect("core nprofile");
        let core_naddr = neco_secp::nip19::encode_naddr(&NAddr {
            identifier: "article".to_string(),
            relays: vec!["wss://relay.example".to_string()],
            author: pubkey,
            kind: 30_023,
        })
        .expect("core naddr");
        let core_nsec = neco_secp::nip19::encode_nsec(&secret).expect("core nsec");

        assert_eq!(wasm_nprofile, core_nprofile);
        assert_eq!(wasm_naddr, core_naddr);
        assert_eq!(wasm_nsec, core_nsec);
        assert_eq!(decode_nsec(&wasm_nsec).expect("decode nsec"), secret_hex);
    }

    #[test]
    fn validate_auth_event_returns_signer_pubkey() {
        let secret = SecretKey::from_bytes([0x16; 32]).expect("secret");
        let signed = neco_secp::nip42::create_auth_event(
            "challenge-123",
            "wss://relay.example.com",
            &secret,
            1_700_000_000,
        )
        .expect("create auth");
        let json = neco_secp::nostr::serialize_signed_event(&signed).expect("json");

        let validated =
            validate_auth_event(&json, "challenge-123", "wss://relay.example.com").expect("ok");
        assert_eq!(
            validated,
            secret
                .xonly_public_key()
                .expect("pubkey")
                .to_hex()
                .expect("pubkey hex")
        );
    }

    #[test]
    fn encode_lnurl_matches_known_output() {
        let lnurl = encode_lnurl("https://example.com/.well-known/lnurlp/alice").expect("lnurl");
        assert_eq!(
            lnurl,
            "lnurl1dp68gurn8ghj7etcv9khqmr99e3k7mf09emk2mrv944kummhdchkcmn4wfk8qtmpd35kxeg9saevq"
        );
    }
}
