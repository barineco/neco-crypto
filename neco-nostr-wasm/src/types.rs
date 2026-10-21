use core::fmt::{self, Write};
use neco_json::JsonString;
use neco_secp::{
    nostr, EventId, NAddr, NProfile, Nip19, PublicKey, SecretKey, SignedEvent, UnsignedEvent,
    XOnlyPublicKey,
};
use neco_vault::SecurityConfig;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(
    inline_js = "export function read_unix_seconds() { const milliseconds = Date.now(); if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) throw new Error('invalid system clock'); return BigInt(milliseconds) / 1000n; }"
)]
extern "C" {
    #[wasm_bindgen(catch)]
    fn read_unix_seconds() -> Result<u64, JsValue>;
}

pub fn js_error<E: core::fmt::Display>(error: E) -> JsValue {
    crate::json::js_error(error)
}

pub fn copy_text(value: &str) -> Result<String, JsValue> {
    let required = value.len();
    if required > isize::MAX as usize {
        return Err(js_error(neco_secp::SecpError::CapacityOverflow {
            input_len: required,
        }));
    }
    let mut result = String::new();
    result
        .try_reserve_exact(required)
        .map_err(|_| js_error(neco_secp::SecpError::AllocationFailed { required }))?;
    result.push_str(value);
    Ok(result)
}

pub fn now_unix_seconds() -> Result<u64, JsValue> {
    #[cfg(target_arch = "wasm32")]
    {
        read_unix_seconds()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| JsValue::from_str("system clock precedes Unix epoch"))
    }
}

pub fn parse_secret_key(secret_hex: &str) -> Result<SecretKey, JsValue> {
    SecretKey::from_hex(secret_hex).map_err(js_error)
}

pub fn parse_public_key(public_hex: &str) -> Result<PublicKey, JsValue> {
    PublicKey::from_hex(public_hex).map_err(js_error)
}

pub fn parse_xonly_public_key(public_hex: &str) -> Result<XOnlyPublicKey, JsValue> {
    XOnlyPublicKey::from_hex(public_hex).map_err(js_error)
}

pub fn parse_event_id(id_hex: &str) -> Result<EventId, JsValue> {
    EventId::from_hex(id_hex).map_err(js_error)
}

fn object_field<'a>(
    object: neco_json::JsonRef<'a>,
    name: &str,
) -> Result<Option<neco_json::JsonRef<'a>>, JsValue> {
    let mut found = None;
    let entries = object
        .object_entries()
        .ok_or_else(|| JsValue::from_str("expected a JSON object"))?;
    for entry in entries {
        let (key, value) = entry.map_err(js_error)?;
        if key.string_eq(name).map_err(js_error)? {
            found = Some(value);
        }
    }
    Ok(found)
}

fn copy_json_string(value: neco_json::JsonRef<'_>) -> Result<String, JsValue> {
    let decoded = value
        .as_str()
        .map_err(js_error)?
        .ok_or_else(|| JsValue::from_str("invalid string"))?;
    match decoded {
        std::borrow::Cow::Borrowed(text) => copy_text(text),
        std::borrow::Cow::Owned(text) => Ok(text),
    }
}

fn reserve_one<T>(values: &mut Vec<T>) -> Result<(), JsValue> {
    let required = values.len().checked_add(1).ok_or_else(|| {
        js_error(neco_secp::SecpError::CapacityOverflow {
            input_len: values.len(),
        })
    })?;
    let bytes = required
        .checked_mul(core::mem::size_of::<T>())
        .ok_or_else(|| {
            js_error(neco_secp::SecpError::CapacityOverflow {
                input_len: required,
            })
        })?;
    if bytes > isize::MAX as usize {
        return Err(js_error(neco_secp::SecpError::CapacityOverflow {
            input_len: required,
        }));
    }
    values
        .try_reserve_exact(1)
        .map_err(|_| js_error(neco_secp::SecpError::AllocationFailed { required }))
}

fn parse_event_tags(value: neco_json::JsonRef<'_>) -> Result<Vec<Vec<String>>, JsValue> {
    let arrays = value
        .array_items()
        .ok_or_else(|| JsValue::from_str("invalid tags"))?;
    let mut tags = Vec::new();
    for tag in arrays {
        let tag = tag.map_err(js_error)?;
        let items = tag
            .array_items()
            .ok_or_else(|| JsValue::from_str("invalid tags"))?;
        let mut strings = Vec::new();
        for item in items {
            let item = item.map_err(js_error)?;
            let text = copy_json_string(item)?;
            reserve_one(&mut strings)?;
            strings.push(text);
        }
        reserve_one(&mut tags)?;
        tags.push(strings);
    }
    Ok(tags)
}

fn unsigned_event_fields(value: neco_json::JsonRef<'_>) -> Result<UnsignedEvent, JsValue> {
    if value.kind() != neco_json::JsonKind::Object {
        return Err(JsValue::from_str("event must be a JSON object"));
    }
    let tags = object_field(value, "tags")?.ok_or_else(|| JsValue::from_str("missing tags"))?;
    let tags = parse_event_tags(tags)?;
    let created_at = object_field(value, "created_at")?
        .ok_or_else(|| JsValue::from_str("missing created_at"))?
        .as_u64()
        .ok_or_else(|| JsValue::from_str("invalid created_at"))?;
    let kind = object_field(value, "kind")?
        .ok_or_else(|| JsValue::from_str("missing kind"))?
        .as_u64()
        .ok_or_else(|| JsValue::from_str("invalid kind"))?
        .try_into()
        .map_err(|_| JsValue::from_str("kind out of range"))?;
    let content =
        object_field(value, "content")?.ok_or_else(|| JsValue::from_str("missing content"))?;
    if content.kind() != neco_json::JsonKind::String {
        return Err(JsValue::from_str("invalid content"));
    }
    Ok(UnsignedEvent {
        created_at,
        kind,
        tags,
        content: copy_json_string(content)?,
    })
}

pub fn parse_unsigned_event(json_str: &str) -> Result<UnsignedEvent, JsValue> {
    let value = neco_json::parse_borrowed(json_str).map_err(js_error)?;
    unsigned_event_fields(value)
}

pub fn parse_signed_event(json_str: &str) -> Result<SignedEvent, JsValue> {
    nostr::parse_signed_event(json_str).map_err(js_error)
}

pub fn stringify_signed_event(event: &SignedEvent) -> Result<String, JsValue> {
    nostr::serialize_signed_event(event).map_err(js_error)
}

pub fn parse_security_config(json_str: &str) -> Result<SecurityConfig, JsValue> {
    let value = neco_json::parse_borrowed(json_str).map_err(js_error)?;
    if value.kind() != neco_json::JsonKind::Object {
        return Err(JsValue::from_str("security config must be a JSON object"));
    }
    let boolean = |name, default| -> Result<bool, JsValue> {
        Ok(object_field(value, name)?
            .and_then(|field| field.as_bool())
            .unwrap_or(default))
    };
    Ok(SecurityConfig {
        enable_constant_time: boolean("enable_constant_time", true)?,
        enable_random_delay: boolean("enable_random_delay", false)?,
        enable_dummy_operations: boolean("enable_dummy_operations", false)?,
    })
}

fn required_string(
    value: neco_json::JsonRef<'_>,
    message: &'static str,
) -> Result<String, JsValue> {
    if value.kind() != neco_json::JsonKind::String {
        return Err(JsValue::from_str(message));
    }
    copy_json_string(value)
}

fn parse_relays(object: neco_json::JsonRef<'_>) -> Result<Vec<String>, JsValue> {
    let Some(value) = object_field(object, "relays")? else {
        return Ok(Vec::new());
    };
    let items = value
        .array_items()
        .ok_or_else(|| JsValue::from_str("invalid relays"))?;
    let mut relays = Vec::new();
    for item in items {
        let item = item.map_err(js_error)?;
        let relay = required_string(item, "invalid relays")?;
        reserve_one(&mut relays)?;
        relays.push(relay);
    }
    Ok(relays)
}

pub fn parse_event_with_pubkey(json_str: &str) -> Result<(XOnlyPublicKey, UnsignedEvent), JsValue> {
    let value = neco_json::parse_borrowed(json_str).map_err(js_error)?;
    if value.kind() != neco_json::JsonKind::Object {
        return Err(JsValue::from_str("event must be a JSON object"));
    }
    let pubkey =
        object_field(value, "pubkey")?.ok_or_else(|| JsValue::from_str("missing pubkey"))?;
    let pubkey = required_string(pubkey, "invalid pubkey")?;
    Ok((
        parse_xonly_public_key(&pubkey)?,
        unsigned_event_fields(value)?,
    ))
}

pub fn nip19_to_json(value: Nip19, allow_secret: bool) -> Result<String, JsValue> {
    let output = match value {
        Nip19::Npub(pubkey) => {
            let pubkey = pubkey.to_hex().map_err(js_error)?;
            crate::json::encode(|out| {
                write!(out, "{{\"kind\":\"npub\",\"pubkey_hex\":{}}}", JsonString::new(&pubkey))
            })
        }
        Nip19::Nsec(secret) => {
            if !allow_secret {
                return Err(JsValue::from_str("nsec decode is disabled in wasm boundary"));
            }
            let secret = secret.to_hex().map_err(js_error)?;
            crate::json::encode(|out| {
                write!(out, "{{\"kind\":\"nsec\",\"secret_hex\":{}}}", JsonString::new(&secret))
            })
        }
        Nip19::Note(id) => {
            let id = id.to_hex().map_err(js_error)?;
            crate::json::encode(|out| {
                write!(out, "{{\"id_hex\":{},\"kind\":\"note\"}}", JsonString::new(&id))
            })
        }
        Nip19::NProfile(profile) => {
            let pubkey = profile.pubkey.to_hex().map_err(js_error)?;
            crate::json::encode(|out| {
                write!(out, "{{\"kind\":\"nprofile\",\"pubkey_hex\":{},\"relays\":", JsonString::new(&pubkey))?;
                crate::json::write_strings(out, &profile.relays)?;
                out.write_char('}')
            })
        }
        Nip19::NEvent(event) => {
            let id = event.id.to_hex().map_err(js_error)?;
            let author = event.author.map(|key| key.to_hex()).transpose().map_err(js_error)?;
            crate::json::encode(|out| {
                write!(out, "{{\"author_hex\":")?;
                if let Some(author) = &author {
                    write!(out, "{}", JsonString::new(author))?;
                } else {
                    out.write_str("null")?;
                }
                out.write_str(",\"event_kind\":")?;
                if let Some(kind) = event.kind {
                    write!(out, "{kind}")?;
                } else {
                    out.write_str("null")?;
                }
                write!(out, ",\"id_hex\":{},\"kind\":\"nevent\",\"relays\":", JsonString::new(&id))?;
                crate::json::write_strings(out, &event.relays)?;
                out.write_char('}')
            })
        }
        Nip19::NAddr(addr) => {
            let author = addr.author.to_hex().map_err(js_error)?;
            crate::json::encode(|out| {
                write!(out, "{{\"author_hex\":{},\"event_kind\":{},\"identifier\":{},\"kind\":\"naddr\",\"relays\":", JsonString::new(&author), addr.kind, JsonString::new(&addr.identifier))?;
                crate::json::write_strings(out, &addr.relays)?;
                out.write_char('}')
            })
        }
        Nip19::NRelay(relay) => {
            crate::json::encode(|out| {
                write!(out, "{{\"kind\":\"nrelay\",\"relay\":{}}}", JsonString::new(&relay.relay))
            })
        }
    }
    .map_err(js_error)?;
    Ok(output)
}

fn first_present<'a>(
    object: neco_json::JsonRef<'a>,
    names: &[&str],
) -> Result<Option<neco_json::JsonRef<'a>>, JsValue> {
    for name in names {
        if let Some(value) = object_field(object, name)? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

pub fn parse_nevent(json_str: &str) -> Result<neco_secp::NEvent, JsValue> {
    let value = neco_json::parse_borrowed(json_str).map_err(js_error)?;
    if value.kind() != neco_json::JsonKind::Object {
        return Err(JsValue::from_str("nevent must be a JSON object"));
    }
    let id = first_present(value, &["id_hex", "id"])?
        .ok_or_else(|| JsValue::from_str("missing id_hex"))?;
    let id = required_string(id, "invalid id_hex")?;
    let relays = parse_relays(value)?;
    let author = first_present(value, &["author_hex", "author"])?
        .filter(|field| field.kind() == neco_json::JsonKind::String)
        .map(copy_json_string)
        .transpose()?
        .map(|author| parse_xonly_public_key(&author))
        .transpose()?;
    let kind = first_present(value, &["kind", "event_kind"])?
        .and_then(|field| field.as_u64())
        .map(|kind| u32::try_from(kind).map_err(|_| JsValue::from_str("kind out of range")))
        .transpose()?;
    Ok(neco_secp::NEvent {
        id: parse_event_id(&id)?,
        relays,
        author,
        kind,
    })
}

pub fn parse_nprofile(json_str: &str) -> Result<NProfile, JsValue> {
    let value = neco_json::parse_borrowed(json_str).map_err(js_error)?;
    if value.kind() != neco_json::JsonKind::Object {
        return Err(JsValue::from_str("nprofile must be a JSON object"));
    }
    let pubkey = first_present(value, &["pubkey_hex", "pubkey"])?
        .ok_or_else(|| JsValue::from_str("missing pubkey_hex"))?;
    let pubkey = required_string(pubkey, "invalid pubkey_hex")?;
    Ok(NProfile {
        pubkey: parse_xonly_public_key(&pubkey)?,
        relays: parse_relays(value)?,
    })
}

pub fn parse_naddr(json_str: &str) -> Result<NAddr, JsValue> {
    let value = neco_json::parse_borrowed(json_str).map_err(js_error)?;
    if value.kind() != neco_json::JsonKind::Object {
        return Err(JsValue::from_str("naddr must be a JSON object"));
    }
    let identifier = object_field(value, "identifier")?
        .ok_or_else(|| JsValue::from_str("missing identifier"))?;
    let identifier = required_string(identifier, "invalid identifier")?;
    let relays = parse_relays(value)?;
    let author = first_present(value, &["author_hex", "author", "pubkey_hex", "pubkey"])?
        .ok_or_else(|| JsValue::from_str("missing author_hex"))?;
    let author = required_string(author, "invalid author_hex")?;
    let kind = first_present(value, &["kind", "event_kind"])?
        .ok_or_else(|| JsValue::from_str("missing event_kind"))?
        .as_u64()
        .ok_or_else(|| JsValue::from_str("invalid event_kind"))?
        .try_into()
        .map_err(|_| JsValue::from_str("kind out of range"))?;
    Ok(NAddr {
        identifier,
        relays,
        author: parse_xonly_public_key(&author)?,
        kind,
    })
}

pub(crate) struct PublicKeyFields {
    npub: String,
    pubkey_hex: String,
    public_key_hex: String,
}

impl PublicKeyFields {
    pub(crate) fn write_fields(&self, output: &mut dyn Write) -> fmt::Result {
        write!(
            output,
            "\"npub\":{},\"pubkey_hex\":{},\"public_key_hex\":{}",
            JsonString::new(&self.npub),
            JsonString::new(&self.pubkey_hex),
            JsonString::new(&self.public_key_hex),
        )
    }
}

pub(crate) fn public_key_json(secret: &SecretKey) -> Result<PublicKeyFields, JsValue> {
    let pubkey = secret.xonly_public_key().map_err(js_error)?;
    let public = secret.public_key().map_err(js_error)?;
    Ok(PublicKeyFields {
        npub: neco_secp::nip19::encode_npub(&pubkey).map_err(js_error)?,
        pubkey_hex: pubkey.to_hex().map_err(js_error)?,
        public_key_hex: public.to_hex().map_err(js_error)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_json_keeps_exact_integers_and_last_decoded_duplicate_fields() {
        let event = parse_unsigned_event(
            r#"{"created_at":0,"\u0063reated_at":18446744073709551615,"kind":1,"tags":[["p","é\n"]],"content":"first","content":"last\u001fé"}"#,
        )
        .expect("unsigned event");
        assert_eq!(event.created_at, u64::MAX);
        assert_eq!(event.content, "last\u{001f}é");
        assert_eq!(event.tags, vec![vec!["p".to_string(), "é\n".to_string()]]);
    }

    #[test]
    fn identifier_aliases_preserve_first_present_optional_and_default_meanings() {
        let json = format!(
            "{{\"id_hex\":\"{}\",\"id\":\"{}\",\"kind\":4294967295,\"event_kind\":1,\"author_hex\":null,\"author\":\"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"}}",
            "11".repeat(32),
            "22".repeat(32),
        );
        let event = parse_nevent(&json).expect("event identifier");
        assert_eq!(event.id, EventId::from_bytes([0x11; 32]));
        assert_eq!(event.kind, Some(u32::MAX));
        assert_eq!(event.author, None);
        assert!(event.relays.is_empty());
        let security = parse_security_config(
            r#"{"enable_constant_time":"false","enable_random_delay":true,"enable_random_delay":false,"enable_dummy_operations":null}"#,
        )
        .expect("security config");
        assert!(security.enable_constant_time);
        assert!(!security.enable_random_delay);
        assert!(!security.enable_dummy_operations);
    }

    #[test]
    fn identifier_output_preserves_null_fields_order_and_escaped_bytes() {
        let json = nip19_to_json(
            Nip19::NEvent(neco_secp::NEvent {
                id: EventId::from_bytes([0; 32]),
                relays: vec!["wss://relay.example/\u{001f}é".to_string()],
                author: None,
                kind: None,
            }),
            false,
        )
        .expect("identifier JSON");
        assert_eq!(
            json,
            format!(
                "{{\"author_hex\":null,\"event_kind\":null,\"id_hex\":\"{}\",\"kind\":\"nevent\",\"relays\":[\"wss://relay.example/\\u001fé\"]}}",
                "00".repeat(32)
            )
        );
    }
}
