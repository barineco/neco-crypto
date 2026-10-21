use alloc::{borrow::Cow, string::String, vec::Vec};
use core::fmt;

use neco_json::{JsonRef, ParseError, StringDecodeError};

use crate::{EventId, Rumor, SchnorrSignature, SecpError, SignedEvent, XOnlyPublicKey};

const FIELD_ID: u8 = 1 << 0;
const FIELD_PUBKEY: u8 = 1 << 1;
const FIELD_CREATED_AT: u8 = 1 << 2;
const FIELD_KIND: u8 = 1 << 3;
const FIELD_TAGS: u8 = 1 << 4;
const FIELD_CONTENT: u8 = 1 << 5;
const FIELD_SIG: u8 = 1 << 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventJsonError {
    Syntax(ParseError),
    Decode(StringDecodeError),
    MissingField(&'static str),
    DuplicateField {
        field: &'static str,
        position: usize,
    },
    InvalidField {
        field: &'static str,
        position: usize,
    },
    InvalidNumber {
        field: &'static str,
        position: usize,
    },
}

impl fmt::Display for EventJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(formatter, "{error}"),
            Self::Decode(error) => write!(formatter, "{error}"),
            Self::MissingField(field) => write!(formatter, "missing event field {field}"),
            Self::DuplicateField { field, position } => write!(
                formatter,
                "duplicate event field {field} at byte {position}"
            ),
            Self::InvalidField { field, position } => {
                write!(formatter, "invalid event field {field} at byte {position}")
            }
            Self::InvalidNumber { field, position } => {
                write!(formatter, "invalid event number {field} at byte {position}")
            }
        }
    }
}

impl core::error::Error for EventJsonError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Syntax(error) => Some(error),
            Self::Decode(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ParseError> for EventJsonError {
    fn from(error: ParseError) -> Self {
        Self::Syntax(error)
    }
}

impl From<StringDecodeError> for EventJsonError {
    fn from(error: StringDecodeError) -> Self {
        Self::Decode(error)
    }
}

#[derive(Clone, Copy)]
enum EventField {
    Id,
    Pubkey,
    CreatedAt,
    Kind,
    Tags,
    Content,
    Sig,
    Unknown,
}

impl EventField {
    fn bit(self) -> u8 {
        match self {
            Self::Id => FIELD_ID,
            Self::Pubkey => FIELD_PUBKEY,
            Self::CreatedAt => FIELD_CREATED_AT,
            Self::Kind => FIELD_KIND,
            Self::Tags => FIELD_TAGS,
            Self::Content => FIELD_CONTENT,
            Self::Sig => FIELD_SIG,
            Self::Unknown => 0,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Id => "id",
            Self::Pubkey => "pubkey",
            Self::CreatedAt => "created_at",
            Self::Kind => "kind",
            Self::Tags => "tags",
            Self::Content => "content",
            Self::Sig => "sig",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy)]
enum EventMode {
    Signed,
    Rumor,
}

struct ParsedEvent {
    id: EventId,
    pubkey: XOnlyPublicKey,
    created_at: u64,
    kind: u32,
    tags: Vec<Vec<String>>,
    content: String,
    sig: Option<SchnorrSignature>,
}

pub(crate) fn parse_signed_event(json: &str) -> Result<SignedEvent, SecpError> {
    let parsed = parse_event(json, EventMode::Signed)?;
    let sig = parsed.sig.ok_or_else(|| missing("sig"))?;
    Ok(SignedEvent {
        id: parsed.id,
        pubkey: parsed.pubkey,
        created_at: parsed.created_at,
        kind: parsed.kind,
        tags: parsed.tags,
        content: parsed.content,
        sig,
    })
}

pub(crate) fn parse_rumor(json: &str) -> Result<Rumor, SecpError> {
    let parsed = parse_event(json, EventMode::Rumor)?;
    Ok(Rumor {
        id: parsed.id,
        pubkey: parsed.pubkey,
        created_at: parsed.created_at,
        kind: parsed.kind,
        tags: parsed.tags,
        content: parsed.content,
    })
}

fn parse_event(json: &str, mode: EventMode) -> Result<ParsedEvent, SecpError> {
    let object = neco_json::parse_borrowed(json).map_err(EventJsonError::from)?;
    let entries = object
        .object_entries()
        .ok_or_else(|| invalid("event", object.span().start))?;
    let mut seen = 0u8;
    let mut id = None;
    let mut pubkey = None;
    let mut created_at = None;
    let mut kind = None;
    let mut tags = None;
    let mut content = None;
    let mut sig = None;
    for entry in entries {
        let (key, value) = entry.map_err(EventJsonError::from)?;
        let field = event_field(&key)?;
        if field.bit() != 0 && seen & field.bit() != 0 {
            return Err(EventJsonError::DuplicateField {
                field: field.name(),
                position: key.span().start,
            }
            .into());
        }
        seen |= field.bit();
        match field {
            EventField::Id => {
                let encoded = required_string(value, "id")?;
                id = Some(EventId::from_bytes(decode_hex_array::<32>(&encoded, "id")?));
            }
            EventField::Pubkey => {
                let encoded = required_string(value, "pubkey")?;
                pubkey = Some(XOnlyPublicKey::from_bytes(decode_hex_array::<32>(
                    &encoded, "pubkey",
                )?)?);
            }
            EventField::CreatedAt => {
                created_at = Some(
                    value
                        .as_u64()
                        .ok_or_else(|| number("created_at", value.span().start))?,
                )
            }
            EventField::Kind => {
                let raw = value
                    .as_u64()
                    .ok_or_else(|| number("kind", value.span().start))?;
                kind = Some(u32::try_from(raw).map_err(|_| number("kind", value.span().start))?);
            }
            EventField::Tags => tags = Some(parse_tags(value)?),
            EventField::Content => content = Some(required_string(value, "content")?),
            EventField::Sig => {
                if matches!(mode, EventMode::Rumor) {
                    return Err(SecpError::InvalidEvent("rumor must be unsigned"));
                }
                sig = Some(SchnorrSignature {
                    bytes: decode_hex_array::<64>(&required_string(value, "sig")?, "sig")?,
                });
            }
            EventField::Unknown => {}
        }
    }
    let parsed = ParsedEvent {
        id: id.ok_or_else(|| missing("id"))?,
        pubkey: pubkey.ok_or_else(|| missing("pubkey"))?,
        created_at: created_at.ok_or_else(|| missing("created_at"))?,
        kind: kind.ok_or_else(|| missing("kind"))?,
        tags: tags.ok_or_else(|| missing("tags"))?,
        content: content.ok_or_else(|| missing("content"))?,
        sig,
    };
    if matches!(mode, EventMode::Signed) && parsed.sig.is_none() {
        return Err(missing("sig"));
    }
    crate::nostr::validate_event_shape(parsed.kind, &parsed.tags)?;
    Ok(parsed)
}

fn event_field(key: &JsonRef<'_>) -> Result<EventField, SecpError> {
    for (name, field) in [
        ("id", EventField::Id),
        ("pubkey", EventField::Pubkey),
        ("created_at", EventField::CreatedAt),
        ("kind", EventField::Kind),
        ("tags", EventField::Tags),
        ("content", EventField::Content),
        ("sig", EventField::Sig),
    ] {
        if key.string_eq(name).map_err(EventJsonError::from)? {
            return Ok(field);
        }
    }
    Ok(EventField::Unknown)
}

fn required_string(value: JsonRef<'_>, field: &'static str) -> Result<String, SecpError> {
    match value.as_str().map_err(EventJsonError::from)? {
        Some(Cow::Owned(value)) => Ok(value),
        Some(Cow::Borrowed(value)) => crate::storage::text(value),
        None => Err(invalid(field, value.span().start)),
    }
}

fn parse_tags(value: JsonRef<'_>) -> Result<Vec<Vec<String>>, SecpError> {
    let tag_count = value
        .array_items()
        .ok_or_else(|| invalid("tags", value.span().start))?
        .try_fold(0usize, |count, item| {
            item.map_err(EventJsonError::from)?;
            count.checked_add(1).ok_or(SecpError::CapacityOverflow {
                input_len: value.raw().len(),
            })
        })?;
    let mut tags = crate::storage::vector(tag_count)?;
    for item in value
        .array_items()
        .ok_or_else(|| invalid("tags", value.span().start))?
    {
        let item = item.map_err(EventJsonError::from)?;
        let value_count = item
            .array_items()
            .ok_or_else(|| invalid("tag", item.span().start))?
            .try_fold(0usize, |count, entry| {
                entry.map_err(EventJsonError::from)?;
                count.checked_add(1).ok_or(SecpError::CapacityOverflow {
                    input_len: item.raw().len(),
                })
            })?;
        let mut tag = crate::storage::vector(value_count)?;
        for entry in item
            .array_items()
            .ok_or_else(|| invalid("tag", item.span().start))?
        {
            let entry = entry.map_err(EventJsonError::from)?;
            tag.push(required_string(entry, "tag entry")?);
        }
        tags.push(tag);
    }
    Ok(tags)
}

fn missing(field: &'static str) -> SecpError {
    EventJsonError::MissingField(field).into()
}
fn invalid(field: &'static str, position: usize) -> SecpError {
    EventJsonError::InvalidField { field, position }.into()
}
fn number(field: &'static str, position: usize) -> SecpError {
    EventJsonError::InvalidNumber { field, position }.into()
}

fn decode_hex_array<const LENGTH: usize>(
    encoded: &str,
    field: &'static str,
) -> Result<[u8; LENGTH], SecpError> {
    let bytes = match crate::hex::hex_decode(encoded) {
        Ok(bytes) => bytes,
        Err(SecpError::InvalidHex(_)) => {
            return Err(SecpError::InvalidEvent(invalid_hex_field(field)))
        }
        Err(error) => return Err(error),
    };
    bytes
        .try_into()
        .map_err(|_| SecpError::InvalidEvent(invalid_hex_field(field)))
}

fn invalid_hex_field(field: &'static str) -> &'static str {
    match field {
        "id" => "id must be 64 hex characters",
        "pubkey" => "pubkey must be 64 hex characters",
        "sig" => "sig must be 128 hex characters",
        _ => "invalid hex field",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::ToString};

    const PUBLIC_KEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const ZERO_ID: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ZERO_SIG: &str = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    fn event_json(created_at: &str, extra: &str) -> String {
        format!("{{\"id\":\"{ZERO_ID}\",\"pubkey\":\"{PUBLIC_KEY}\",\"created_at\":{created_at},\"kind\":1,\"tags\":[[\"p\",\"peer\"]],\"content\":\"hello\",\"sig\":\"{ZERO_SIG}\"{extra}}}")
    }

    #[test]
    fn borrowed_strings_tags_and_u64_values_map_to_event() {
        for timestamp in ["9007199254740993", "18446744073709551615"] {
            let parsed = parse_signed_event(&event_json(timestamp, "")).expect("event");
            assert_eq!(parsed.created_at.to_string(), timestamp);
        }
        let parsed = parse_signed_event(&event_json("1", ",\"unknown\":{\"a\":[true,null]}"))
            .expect("event");
        assert_eq!(
            parsed.tags,
            alloc::vec![alloc::vec!["p".to_string(), "peer".to_string()]]
        );
    }

    #[test]
    fn escaped_known_keys_duplicate_and_invalid_numbers_keep_domain_errors() {
        assert!(parse_signed_event(&event_json("1", ",\"\\u0069d\":\"duplicate\"")).is_err());
        let non_integer = event_json("1.0", "");
        assert!(matches!(
            parse_signed_event(&non_integer),
            Err(SecpError::Json(EventJsonError::InvalidNumber {
                field: "created_at",
                ..
            }))
        ));
        let overflow = event_json("18446744073709551616", "");
        assert!(matches!(
            parse_signed_event(&overflow),
            Err(SecpError::Json(EventJsonError::InvalidNumber {
                field: "created_at",
                ..
            }))
        ));
    }

    #[test]
    fn syntax_failure_preserves_the_shared_parser_error() {
        let malformed = "{";
        let expected = neco_json::parse_borrowed(malformed)
            .err()
            .expect("parser rejection");
        assert_eq!(
            parse_signed_event(malformed),
            Err(SecpError::Json(EventJsonError::Syntax(expected)))
        );
        let invalid_unicode = event_json("1", "").replace("hello", "\\uD800");
        let expected = neco_json::parse_borrowed(&invalid_unicode)
            .err()
            .expect("parser rejection");
        assert_eq!(
            parse_signed_event(&invalid_unicode),
            Err(SecpError::Json(EventJsonError::Syntax(expected)))
        );
    }

    #[test]
    fn accepts_shuffled_fields_and_unicode_escapes() {
        let json = format!("{{\"content\":\"A\\u00df\\uD83D\\uDE00\",\"sig\":\"{ZERO_SIG}\",\"tags\":[[\"\\u03b1\"]],\"kind\":65535,\"created_at\":1,\"pubkey\":\"{PUBLIC_KEY}\",\"id\":\"{ZERO_ID}\"}}");
        let parsed = parse_signed_event(&json).expect("parse event");
        assert_eq!(parsed.content, "Aß😀");
        assert_eq!(parsed.tags, alloc::vec![alloc::vec!["α".to_string()]]);
        assert_eq!(parsed.kind, 65535);
    }

    #[test]
    fn rejects_duplicate_fields_and_trailing_data() {
        assert!(parse_signed_event(&event_json("7", ",\"kind\":2")).is_err());
        let mut trailing = event_json("7", "");
        trailing.push_str(" null");
        assert!(parse_signed_event(&trailing).is_err());
    }

    #[test]
    fn parses_unsigned_rumor_and_rejects_signature_field() {
        let json = format!("{{\"id\":\"{ZERO_ID}\",\"pubkey\":\"{PUBLIC_KEY}\",\"created_at\":9,\"kind\":14,\"tags\":[[\"p\",\"peer\"]],\"content\":\"rumor\"}}");
        let rumor = parse_rumor(&json).expect("parse rumor");
        assert_eq!(rumor.created_at, 9);
        assert_eq!(rumor.kind, 14);
        assert_eq!(rumor.content, "rumor");
        assert_eq!(
            parse_rumor(&event_json("9", "")),
            Err(SecpError::InvalidEvent("rumor must be unsigned"))
        );
    }

    #[test]
    fn rejects_nonstandard_event_kinds_and_empty_tags() {
        for kind in [65536, u32::MAX] {
            let json = event_json("7", "").replace("\"kind\":1", &format!("\"kind\":{kind}"));
            assert_eq!(
                parse_signed_event(&json),
                Err(SecpError::InvalidEventKind { kind })
            );
        }
        let json = event_json("7", "").replace("[[\"p\",\"peer\"]]", "[[]]");
        assert_eq!(
            parse_signed_event(&json),
            Err(SecpError::EmptyEventTag { index: 0 })
        );
        let rumor = format!("{{\"id\":\"{ZERO_ID}\",\"pubkey\":\"{PUBLIC_KEY}\",\"created_at\":9,\"kind\":14,\"tags\":[[]],\"content\":\"rumor\"}}");
        assert_eq!(
            parse_rumor(&rumor),
            Err(SecpError::EmptyEventTag { index: 0 })
        );
    }
}
