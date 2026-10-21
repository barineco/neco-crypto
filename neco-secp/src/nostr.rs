use crate::{
    storage, EventId, Rumor, SchnorrSignature, SecpError, SecretKey, SignedEvent, UnsignedEvent,
    XOnlyPublicKey,
};
use alloc::{string::String, vec::Vec};
use core::fmt::{self, Write};
use neco_json::JsonString;
use neco_sha2::Sha256;

pub(crate) fn validate_event_shape(kind: u32, tags: &[Vec<String>]) -> Result<(), SecpError> {
    if kind > u32::from(u16::MAX) {
        return Err(SecpError::InvalidEventKind { kind });
    }
    if let Some(index) = tags.iter().position(Vec::is_empty) {
        return Err(SecpError::EmptyEventTag { index });
    }
    Ok(())
}

pub fn serialize_event(
    pubkey: &XOnlyPublicKey,
    event: &UnsignedEvent,
) -> Result<String, SecpError> {
    validate_event_shape(event.kind, &event.tags)?;
    encode(|writer| {
        write_unsigned(
            writer,
            pubkey,
            event.created_at,
            event.kind,
            &event.tags,
            &event.content,
        )
    })
}

pub fn compute_event_id(
    pubkey: &XOnlyPublicKey,
    event: &UnsignedEvent,
) -> Result<EventId, SecpError> {
    hash_parts(
        pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    )
}

fn hash_parts(
    pubkey: &XOnlyPublicKey,
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> Result<EventId, SecpError> {
    validate_event_shape(kind, tags)?;
    let serialized =
        encode(|writer| write_unsigned(writer, pubkey, created_at, kind, tags, content))?;
    Ok(EventId::from_bytes(Sha256::digest(serialized.as_bytes())?))
}

#[cfg(feature = "getrandom")]
pub fn finalize_event(event: UnsignedEvent, secret: &SecretKey) -> Result<SignedEvent, SecpError> {
    finalize_event_with_rng(event, secret, &mut |bytes| {
        getrandom::getrandom(bytes).map_err(|_| SecpError::RandomUnavailable)
    })
}

pub fn finalize_event_with_rng<F>(
    event: UnsignedEvent,
    secret: &SecretKey,
    fill: &mut F,
) -> Result<SignedEvent, SecpError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    validate_event_shape(event.kind, &event.tags)?;
    let mut aux = [0u8; 32];
    fill(&mut aux)?;
    finalize_event_with_aux(event, secret, aux)
}

pub fn finalize_event_with_aux(
    event: UnsignedEvent,
    secret: &SecretKey,
    aux: [u8; 32],
) -> Result<SignedEvent, SecpError> {
    let pubkey = secret.xonly_public_key()?;
    let id = compute_event_id(&pubkey, &event)?;
    let sig = secret.sign_schnorr_prehash_with_aux(id.to_bytes(), aux)?;
    Ok(SignedEvent {
        id,
        pubkey,
        created_at: event.created_at,
        kind: event.kind,
        tags: event.tags,
        content: event.content,
        sig,
    })
}

pub fn finalize_event_deterministic(
    event: UnsignedEvent,
    secret: &SecretKey,
) -> Result<SignedEvent, SecpError> {
    finalize_event_with_aux(event, secret, [0u8; 32])
}

pub fn create_rumor(event: UnsignedEvent, pubkey: XOnlyPublicKey) -> Result<Rumor, SecpError> {
    let id = compute_event_id(&pubkey, &event)?;
    Ok(Rumor {
        id,
        pubkey,
        created_at: event.created_at,
        kind: event.kind,
        tags: event.tags,
        content: event.content,
    })
}

pub fn serialize_signed_event(event: &SignedEvent) -> Result<String, SecpError> {
    write_object(ObjectFields {
        id: &event.id,
        pubkey: &event.pubkey,
        created_at: event.created_at,
        kind: event.kind,
        tags: &event.tags,
        content: &event.content,
        sig: Some(&event.sig),
    })
}

pub fn serialize_rumor(event: &Rumor) -> Result<String, SecpError> {
    write_object(ObjectFields {
        id: &event.id,
        pubkey: &event.pubkey,
        created_at: event.created_at,
        kind: event.kind,
        tags: &event.tags,
        content: &event.content,
        sig: None,
    })
}

struct ObjectFields<'a> {
    id: &'a EventId,
    pubkey: &'a XOnlyPublicKey,
    created_at: u64,
    kind: u32,
    tags: &'a [Vec<String>],
    content: &'a str,
    sig: Option<&'a SchnorrSignature>,
}

fn write_object(event: ObjectFields<'_>) -> Result<String, SecpError> {
    validate_event_shape(event.kind, event.tags)?;
    encode(|writer| {
        writer.write_str("{\"id\":")?;
        write_hex(writer, &event.id.to_bytes())?;
        writer.write_str(",\"pubkey\":")?;
        write_hex(writer, &event.pubkey.to_bytes())?;
        write!(
            writer,
            ",\"created_at\":{},\"kind\":{},\"tags\":",
            event.created_at, event.kind
        )?;
        write_tags(writer, event.tags)?;
        writer.write_str(",\"content\":")?;
        write_text(writer, event.content)?;
        if let Some(sig) = event.sig {
            writer.write_str(",\"sig\":")?;
            write_hex(writer, &sig.to_bytes())?;
        }
        writer.write_char('}')
    })
}

pub fn parse_rumor(json: &str) -> Result<Rumor, SecpError> {
    crate::event_json::parse_rumor(json)
}

pub fn verify_rumor(event: &Rumor) -> Result<(), SecpError> {
    let expected = hash_parts(
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    )?;
    if expected != event.id {
        return Err(SecpError::InvalidEvent("rumor id mismatch"));
    }
    Ok(())
}

pub fn parse_signed_event(json: &str) -> Result<SignedEvent, SecpError> {
    crate::event_json::parse_signed_event(json)
}

pub fn verify_event(event: &SignedEvent) -> Result<(), SecpError> {
    let expected = hash_parts(
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    )?;
    if expected != event.id {
        return Err(SecpError::InvalidEvent("event id mismatch"));
    }
    event
        .pubkey
        .verify_schnorr_prehash(event.id.to_bytes(), &event.sig)
}

fn write_unsigned(
    writer: &mut dyn Write,
    pubkey: &XOnlyPublicKey,
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> fmt::Result {
    writer.write_str("[0,")?;
    write_hex(writer, &pubkey.to_bytes())?;
    write!(writer, ",{created_at},{kind},")?;
    write_tags(writer, tags)?;
    writer.write_char(',')?;
    write_text(writer, content)?;
    writer.write_char(']')
}

fn write_hex(writer: &mut dyn Write, bytes: &[u8]) -> fmt::Result {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    writer.write_char('"')?;
    for &byte in bytes {
        writer.write_char(char::from(HEX[usize::from(byte >> 4)]))?;
        writer.write_char(char::from(HEX[usize::from(byte & 15)]))?;
    }
    writer.write_char('"')
}

fn write_tags(writer: &mut dyn Write, tags: &[Vec<String>]) -> fmt::Result {
    writer.write_char('[')?;
    for (index, tag) in tags.iter().enumerate() {
        if index > 0 {
            writer.write_char(',')?;
        }
        writer.write_char('[')?;
        for (index, text) in tag.iter().enumerate() {
            if index > 0 {
                writer.write_char(',')?;
            }
            write_text(writer, text)?;
        }
        writer.write_char(']')?;
    }
    writer.write_char(']')
}

fn write_text(writer: &mut dyn Write, text: &str) -> fmt::Result {
    write!(writer, "{}", JsonString::new(text))
}

#[derive(Default)]
struct ByteCount {
    length: usize,
}

impl Write for ByteCount {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.length = self
            .length
            .checked_add(value.len())
            .filter(|&len| len <= isize::MAX as usize)
            .ok_or(fmt::Error)?;
        Ok(())
    }
}

fn encode<F>(write_value: F) -> Result<String, SecpError>
where
    F: Fn(&mut dyn Write) -> fmt::Result,
{
    let mut count = ByteCount::default();
    write_value(&mut count).map_err(|_| SecpError::CapacityOverflow {
        input_len: count.length,
    })?;
    let mut output = storage::string(count.length)?;
    write_value(&mut output).map_err(|_| SecpError::InvalidEvent("event encoding failed"))?;
    Ok(output)
}

pub(crate) fn tag_pair(name: &str, value: String) -> Result<Vec<String>, SecpError> {
    let mut result = storage::vector(2)?;
    result.push(storage::text(name)?);
    result.push(value);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn secret() -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        SecretKey::from_bytes(bytes).unwrap()
    }

    #[test]
    fn integer_fields_keep_all_u64_bits() {
        let key = secret();
        for created_at in [9_007_199_254_740_993, u64::MAX] {
            let event = UnsignedEvent {
                created_at,
                kind: u32::from(u16::MAX),
                tags: Vec::new(),
                content: String::new(),
            };
            let encoded = serialize_event(&key.xonly_public_key().unwrap(), &event).unwrap();
            assert!(encoded.contains(&alloc::format!(",{created_at},65535,")));
            let signed = finalize_event_deterministic(event, &key).unwrap();
            let restored = parse_signed_event(&serialize_signed_event(&signed).unwrap()).unwrap();
            assert_eq!(restored, signed);
        }
    }

    #[test]
    fn canonical_control_escapes_match_json_stringify() {
        let event = UnsignedEvent {
            created_at: 1,
            kind: 1,
            tags: vec![vec![String::from("a\n")]],
            content: String::from("\u{001f}\0\t\"\\ねこ"),
        };
        let encoded = serialize_event(&secret().xonly_public_key().unwrap(), &event).unwrap();
        assert!(encoded.ends_with("[[\"a\\n\"]],\"\\u001f\\u0000\\t\\\"\\\\ねこ\"]"));
    }

    #[test]
    fn signing_provider_failure_is_preserved() {
        let event = UnsignedEvent {
            created_at: 1,
            kind: 1,
            tags: Vec::new(),
            content: String::new(),
        };
        assert_eq!(
            finalize_event_with_rng(event, &secret(), &mut |_| Err(SecpError::RandomUnavailable)),
            Err(SecpError::RandomUnavailable)
        );
    }
    #[test]
    fn event_kind_and_tag_shape_failures_are_preserved_by_public_paths() {
        let key = secret();
        let pubkey = key.xonly_public_key().unwrap();
        for (kind, tags, error) in [
            (65536, vec![], SecpError::InvalidEventKind { kind: 65536 }),
            (
                u32::MAX,
                vec![],
                SecpError::InvalidEventKind { kind: u32::MAX },
            ),
            (1, vec![vec![]], SecpError::EmptyEventTag { index: 0 }),
            (
                1,
                vec![vec![String::from("x")], vec![]],
                SecpError::EmptyEventTag { index: 1 },
            ),
        ] {
            let event = UnsignedEvent {
                created_at: 1,
                kind,
                tags: tags.clone(),
                content: String::new(),
            };
            assert_eq!(serialize_event(&pubkey, &event), Err(error.clone()));
            assert_eq!(compute_event_id(&pubkey, &event), Err(error.clone()));
            assert_eq!(
                finalize_event_deterministic(event, &key),
                Err(error.clone())
            );
            let valid = UnsignedEvent {
                created_at: 1,
                kind: 1,
                tags: vec![],
                content: String::new(),
            };
            let mut signed = finalize_event_deterministic(valid, &key).unwrap();
            signed.kind = kind;
            signed.tags = tags;
            assert_eq!(serialize_signed_event(&signed), Err(error.clone()));
            assert_eq!(verify_event(&signed), Err(error));
        }
        for kind in [0, 65535] {
            let valid = UnsignedEvent {
                created_at: 1,
                kind,
                tags: vec![vec![String::new()]],
                content: String::new(),
            };
            assert!(serialize_event(&pubkey, &valid).is_ok());
        }
    }
}
