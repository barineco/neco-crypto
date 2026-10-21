use crate::{
    EventId, NAddr, NEvent, NProfile, NRelay, Nip19, SecpError, SecretKey, XOnlyPublicKey,
};
use alloc::{string::String, vec::Vec};
use bech32::{Bech32Writer, ToBase32, Variant};
use core::mem::size_of;

const BECH32_ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONSTANT: u32 = 0x2bc8_30a3;

pub fn encode_npub(pubkey: &XOnlyPublicKey) -> Result<String, SecpError> {
    encode_bech32("npub", &pubkey.to_bytes(), "failed to encode npub")
}

pub fn encode_nsec(secret: &SecretKey) -> Result<String, SecpError> {
    encode_bech32("nsec", &secret.to_bytes(), "failed to encode nsec")
}

pub fn encode_note(id: &EventId) -> Result<String, SecpError> {
    encode_bech32("note", &id.to_bytes(), "failed to encode note")
}

pub fn encode_nprofile(profile: &NProfile) -> Result<String, SecpError> {
    let pubkey = profile.pubkey.to_bytes();
    let mut total = tlv_total_add(0, pubkey.len())?;
    for relay in &profile.relays {
        total = tlv_total_add(total, relay.len())?;
    }

    let mut tlv = try_vec_with_capacity::<u8>(total, total)?;
    for relay in &profile.relays {
        append_tlv(&mut tlv, 1, relay.as_bytes());
    }
    append_tlv(&mut tlv, 0, &pubkey);
    encode_bech32("nprofile", &tlv, "failed to encode tlv entity")
}

pub fn encode_nevent(event: &NEvent) -> Result<String, SecpError> {
    let id = event.id.to_bytes();
    let author = event.author.map(|value| value.to_bytes());
    let kind = event.kind.map(u32::to_be_bytes);

    let mut total = tlv_total_add(0, id.len())?;
    for relay in &event.relays {
        total = tlv_total_add(total, relay.len())?;
    }
    if let Some(value) = author.as_ref() {
        total = tlv_total_add(total, value.len())?;
    }
    if let Some(value) = kind.as_ref() {
        total = tlv_total_add(total, value.len())?;
    }

    let mut tlv = try_vec_with_capacity::<u8>(total, total)?;
    if let Some(value) = kind.as_ref() {
        append_tlv(&mut tlv, 3, value);
    }
    if let Some(value) = author.as_ref() {
        append_tlv(&mut tlv, 2, value);
    }
    for relay in &event.relays {
        append_tlv(&mut tlv, 1, relay.as_bytes());
    }
    append_tlv(&mut tlv, 0, &id);
    encode_bech32("nevent", &tlv, "failed to encode tlv entity")
}

pub fn encode_naddr(addr: &NAddr) -> Result<String, SecpError> {
    let author = addr.author.to_bytes();
    let kind = addr.kind.to_be_bytes();

    let mut total = tlv_total_add(0, addr.identifier.len())?;
    for relay in &addr.relays {
        total = tlv_total_add(total, relay.len())?;
    }
    total = tlv_total_add(total, author.len())?;
    total = tlv_total_add(total, kind.len())?;

    let mut tlv = try_vec_with_capacity::<u8>(total, total)?;
    append_tlv(&mut tlv, 3, &kind);
    append_tlv(&mut tlv, 2, &author);
    for relay in &addr.relays {
        append_tlv(&mut tlv, 1, relay.as_bytes());
    }
    append_tlv(&mut tlv, 0, addr.identifier.as_bytes());
    encode_bech32("naddr", &tlv, "failed to encode tlv entity")
}

pub fn encode_nrelay(relay: &NRelay) -> Result<String, SecpError> {
    let total = tlv_total_add(0, relay.relay.len())?;
    let mut tlv = try_vec_with_capacity::<u8>(total, total)?;
    append_tlv(&mut tlv, 0, relay.relay.as_bytes());
    encode_bech32("nrelay", &tlv, "failed to encode tlv entity")
}

pub fn decode(s: &str) -> Result<Nip19, SecpError> {
    let decoded = decode_bech32(s)?;
    match decoded.prefix {
        Nip19Prefix::Npub => {
            let payload: [u8; 32] = decoded
                .payload
                .as_slice()
                .try_into()
                .map_err(|_| SecpError::InvalidNip19("expected 32-byte payload"))?;
            Ok(Nip19::Npub(XOnlyPublicKey::from_bytes(payload)?))
        }
        Nip19Prefix::Nsec => {
            let payload: [u8; 32] = decoded
                .payload
                .as_slice()
                .try_into()
                .map_err(|_| SecpError::InvalidNip19("expected 32-byte payload"))?;
            Ok(Nip19::Nsec(SecretKey::from_bytes(payload)?))
        }
        Nip19Prefix::Note => {
            let payload: [u8; 32] = decoded
                .payload
                .as_slice()
                .try_into()
                .map_err(|_| SecpError::InvalidNip19("expected 32-byte payload"))?;
            Ok(Nip19::Note(EventId::from_bytes(payload)))
        }
        Nip19Prefix::NProfile => decode_nprofile(&decoded.payload),
        Nip19Prefix::NEvent => decode_nevent(&decoded.payload),
        Nip19Prefix::NAddr => decode_naddr(&decoded.payload),
        Nip19Prefix::NRelay => decode_nrelay(&decoded.payload),
    }
}

fn decode_nprofile(bytes: &[u8]) -> Result<Nip19, SecpError> {
    let tlv = parse_tlv(bytes)?;
    let pubkey = required_bytes32(tlv, 0, "nprofile")?;
    let relays = utf8_entries(tlv, 1, "nprofile")?;
    Ok(Nip19::NProfile(NProfile {
        pubkey: XOnlyPublicKey::from_bytes(pubkey)?,
        relays,
    }))
}

fn decode_nevent(bytes: &[u8]) -> Result<Nip19, SecpError> {
    let tlv = parse_tlv(bytes)?;
    let id = required_bytes32(tlv, 0, "nevent")?;
    let relays = utf8_entries(tlv, 1, "nevent")?;
    let author = optional_bytes32(tlv, 2, "nevent")?
        .map(XOnlyPublicKey::from_bytes)
        .transpose()?;
    let kind = optional_u32(tlv, 3, "nevent")?;

    Ok(Nip19::NEvent(NEvent {
        id: EventId::from_bytes(id),
        relays,
        author,
        kind,
    }))
}

fn decode_naddr(bytes: &[u8]) -> Result<Nip19, SecpError> {
    let tlv = parse_tlv(bytes)?;
    let identifier = required_utf8(tlv, 0, "naddr")?;
    let relays = utf8_entries(tlv, 1, "naddr")?;
    let author = required_bytes32(tlv, 2, "naddr")?;
    let kind = required_u32(tlv, 3, "naddr")?;

    Ok(Nip19::NAddr(NAddr {
        identifier,
        relays,
        author: XOnlyPublicKey::from_bytes(author)?,
        kind,
    }))
}

fn decode_nrelay(bytes: &[u8]) -> Result<Nip19, SecpError> {
    let tlv = parse_tlv(bytes)?;
    let relay = required_utf8(tlv, 0, "nrelay")?;
    Ok(Nip19::NRelay(NRelay { relay }))
}

fn encode_bech32(
    prefix: &str,
    bytes: &[u8],
    failure_message: &'static str,
) -> Result<String, SecpError> {
    let data_bits = bytes
        .len()
        .checked_mul(8)
        .ok_or(SecpError::CapacityOverflow {
            input_len: bytes.len(),
        })?;
    let data_words = data_bits
        .checked_add(4)
        .ok_or(SecpError::CapacityOverflow {
            input_len: bytes.len(),
        })?
        / 5;
    let output_len = prefix
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(data_words))
        .and_then(|length| length.checked_add(6))
        .ok_or(SecpError::CapacityOverflow {
            input_len: bytes.len(),
        })?;
    let mut output = try_string_with_capacity(output_len, output_len)?;
    let mut writer = Bech32Writer::new(prefix, Variant::Bech32, &mut output)
        .map_err(|_| SecpError::InvalidNip19(failure_message))?;
    bytes
        .write_base32(&mut writer)
        .map_err(|_| SecpError::InvalidNip19(failure_message))?;
    writer
        .finalize()
        .map_err(|_| SecpError::InvalidNip19(failure_message))?;
    Ok(output)
}

fn tlv_total_add(total: usize, value_len: usize) -> Result<usize, SecpError> {
    if value_len > usize::from(u8::MAX) {
        return Err(SecpError::InvalidNip19("tlv value too long"));
    }
    total
        .checked_add(2)
        .and_then(|length| length.checked_add(value_len))
        .ok_or(SecpError::CapacityOverflow {
            input_len: value_len,
        })
}

fn append_tlv(output: &mut Vec<u8>, tag: u8, value: &[u8]) {
    output.push(tag);
    output.push(value.len() as u8);
    output.extend_from_slice(value);
}

#[derive(Clone, Copy)]
struct TlvEntries<'a> {
    bytes: &'a [u8],
}

impl<'a> TlvEntries<'a> {
    fn iter(self) -> TlvIter<'a> {
        TlvIter {
            bytes: self.bytes,
            offset: 0,
        }
    }

    fn first(self, requested_tag: u8) -> Option<&'a [u8]> {
        self.iter()
            .find_map(|(tag, value)| (tag == requested_tag).then_some(value))
    }
}

struct TlvIter<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let tag = *self.bytes.get(self.offset)?;
        let length = usize::from(*self.bytes.get(self.offset.checked_add(1)?)?);
        let value_start = self.offset.checked_add(2)?;
        let value_end = value_start.checked_add(length)?;
        let value = self.bytes.get(value_start..value_end)?;
        self.offset = value_end;
        Some((tag, value))
    }
}

fn parse_tlv(bytes: &[u8]) -> Result<TlvEntries<'_>, SecpError> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let header_end = offset
            .checked_add(2)
            .ok_or(SecpError::InvalidNip19("truncated tlv header"))?;
        if header_end > bytes.len() {
            return Err(SecpError::InvalidNip19("truncated tlv header"));
        }
        let length = usize::from(
            *bytes
                .get(offset + 1)
                .ok_or(SecpError::InvalidNip19("truncated tlv header"))?,
        );
        let value_end = header_end
            .checked_add(length)
            .ok_or(SecpError::InvalidNip19("not enough data for tlv entry"))?;
        if value_end > bytes.len() {
            return Err(SecpError::InvalidNip19("not enough data for tlv entry"));
        }
        offset = value_end;
    }
    Ok(TlvEntries { bytes })
}

fn required_bytes32(
    tlv: TlvEntries<'_>,
    tag: u8,
    entity: &'static str,
) -> Result<[u8; 32], SecpError> {
    let value = tlv
        .first(tag)
        .ok_or(SecpError::InvalidNip19(missing_required_field(
            entity,
            usize::from(tag),
        )))?;
    value
        .try_into()
        .map_err(|_| SecpError::InvalidNip19(expected_length(entity, usize::from(tag), 32)))
}

fn optional_bytes32(
    tlv: TlvEntries<'_>,
    tag: u8,
    entity: &'static str,
) -> Result<Option<[u8; 32]>, SecpError> {
    tlv.first(tag)
        .map(|value| {
            value
                .try_into()
                .map_err(|_| SecpError::InvalidNip19(expected_length(entity, usize::from(tag), 32)))
        })
        .transpose()
}

fn required_u32(tlv: TlvEntries<'_>, tag: u8, entity: &'static str) -> Result<u32, SecpError> {
    optional_u32(tlv, tag, entity)?.ok_or(SecpError::InvalidNip19(missing_required_field(
        entity,
        usize::from(tag),
    )))
}

fn optional_u32(
    tlv: TlvEntries<'_>,
    tag: u8,
    entity: &'static str,
) -> Result<Option<u32>, SecpError> {
    tlv.first(tag)
        .map(|value| {
            let bytes: [u8; 4] = value.try_into().map_err(|_| {
                SecpError::InvalidNip19(expected_length(entity, usize::from(tag), 4))
            })?;
            Ok(u32::from_be_bytes(bytes))
        })
        .transpose()
}

fn required_utf8(tlv: TlvEntries<'_>, tag: u8, entity: &'static str) -> Result<String, SecpError> {
    let value = tlv
        .first(tag)
        .ok_or(SecpError::InvalidNip19(missing_required_field(
            entity,
            usize::from(tag),
        )))?;
    let text = core::str::from_utf8(value)
        .map_err(|_| SecpError::InvalidNip19("invalid utf-8 payload"))?;
    checked_string_copy(text)
}

fn utf8_entries(
    tlv: TlvEntries<'_>,
    tag: u8,
    _entity: &'static str,
) -> Result<Vec<String>, SecpError> {
    let mut count = 0usize;
    for (entry_tag, value) in tlv.iter() {
        if entry_tag == tag {
            core::str::from_utf8(value)
                .map_err(|_| SecpError::InvalidNip19("invalid utf-8 payload"))?;
            count = count
                .checked_add(1)
                .ok_or(SecpError::CapacityOverflow { input_len: count })?;
        }
    }

    let mut strings = try_vec_with_capacity::<String>(count, count)?;
    for (entry_tag, value) in tlv.iter() {
        if entry_tag == tag {
            let text = core::str::from_utf8(value)
                .map_err(|_| SecpError::InvalidNip19("invalid utf-8 payload"))?;
            strings.push(checked_string_copy(text)?);
        }
    }
    Ok(strings)
}

fn checked_string_copy(value: &str) -> Result<String, SecpError> {
    let mut output = try_string_with_capacity(value.len(), value.len())?;
    output.push_str(value);
    Ok(output)
}

fn try_vec_with_capacity<T>(elements: usize, input_len: usize) -> Result<Vec<T>, SecpError> {
    checked_allocation_bytes::<T>(elements, input_len)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(elements)
        .map_err(|_| SecpError::AllocationFailed { required: elements })?;
    Ok(output)
}

fn try_string_with_capacity(capacity: usize, input_len: usize) -> Result<String, SecpError> {
    if capacity > isize::MAX as usize {
        return Err(SecpError::CapacityOverflow { input_len });
    }
    let mut output = String::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| SecpError::AllocationFailed { required: capacity })?;
    Ok(output)
}

fn checked_allocation_bytes<T>(elements: usize, input_len: usize) -> Result<usize, SecpError> {
    let required = elements
        .checked_mul(size_of::<T>())
        .ok_or(SecpError::CapacityOverflow { input_len })?;
    if required > isize::MAX as usize {
        return Err(SecpError::CapacityOverflow { input_len });
    }
    Ok(required)
}

#[derive(Clone, Copy)]
enum Nip19Prefix {
    Npub,
    Nsec,
    Note,
    NProfile,
    NEvent,
    NAddr,
    NRelay,
}

struct DecodedBech32 {
    prefix: Nip19Prefix,
    payload: Vec<u8>,
}

fn decode_bech32(input: &str) -> Result<DecodedBech32, SecpError> {
    let bytes = input.as_bytes();
    let mut has_lowercase = false;
    let mut has_uppercase = false;
    for byte in bytes {
        if !(33..=126).contains(byte) {
            return Err(SecpError::InvalidNip19("invalid bech32 string"));
        }
        has_lowercase |= byte.is_ascii_lowercase();
        has_uppercase |= byte.is_ascii_uppercase();
    }
    if has_lowercase && has_uppercase {
        return Err(SecpError::InvalidNip19("invalid bech32 string"));
    }

    let separator = bytes
        .iter()
        .rposition(|byte| *byte == b'1')
        .ok_or(SecpError::InvalidNip19("invalid bech32 string"))?;
    if separator == 0 {
        return Err(SecpError::InvalidNip19("invalid bech32 string"));
    }
    let data_start = separator
        .checked_add(1)
        .ok_or(SecpError::CapacityOverflow {
            input_len: input.len(),
        })?;
    let data = bytes
        .get(data_start..)
        .ok_or(SecpError::InvalidNip19("invalid bech32 string"))?;
    if data.len() < 6 {
        return Err(SecpError::InvalidNip19("invalid bech32 string"));
    }

    let hrp = bytes
        .get(..separator)
        .ok_or(SecpError::InvalidNip19("invalid bech32 string"))?;
    let polymod = bech32_polymod(hrp, data)?;
    if polymod == BECH32M_CONSTANT {
        return Err(SecpError::InvalidNip19("unexpected bech32 variant"));
    }
    if polymod != 1 {
        return Err(SecpError::InvalidNip19("invalid bech32 string"));
    }
    let prefix = parse_prefix(hrp)?;

    let payload_words = data
        .len()
        .checked_sub(6)
        .ok_or(SecpError::InvalidNip19("invalid bech32 string"))?;
    let words = data
        .get(..payload_words)
        .ok_or(SecpError::InvalidNip19("invalid bech32 string"))?;
    let payload = decode_base32(words)?;
    Ok(DecodedBech32 { prefix, payload })
}

fn parse_prefix(hrp: &[u8]) -> Result<Nip19Prefix, SecpError> {
    if hrp.eq_ignore_ascii_case(b"npub") {
        Ok(Nip19Prefix::Npub)
    } else if hrp.eq_ignore_ascii_case(b"nsec") {
        Ok(Nip19Prefix::Nsec)
    } else if hrp.eq_ignore_ascii_case(b"note") {
        Ok(Nip19Prefix::Note)
    } else if hrp.eq_ignore_ascii_case(b"nprofile") {
        Ok(Nip19Prefix::NProfile)
    } else if hrp.eq_ignore_ascii_case(b"nevent") {
        Ok(Nip19Prefix::NEvent)
    } else if hrp.eq_ignore_ascii_case(b"naddr") {
        Ok(Nip19Prefix::NAddr)
    } else if hrp.eq_ignore_ascii_case(b"nrelay") {
        Ok(Nip19Prefix::NRelay)
    } else {
        Err(SecpError::InvalidNip19("unsupported nip19 prefix"))
    }
}

fn bech32_polymod(hrp: &[u8], data: &[u8]) -> Result<u32, SecpError> {
    let mut checksum = 1u32;
    for byte in hrp {
        checksum = polymod_step(checksum, byte.to_ascii_lowercase() >> 5);
    }
    checksum = polymod_step(checksum, 0);
    for byte in hrp {
        checksum = polymod_step(checksum, byte.to_ascii_lowercase() & 0x1f);
    }
    for byte in data {
        let value = decode_bech32_character(*byte)
            .ok_or(SecpError::InvalidNip19("invalid bech32 string"))?;
        checksum = polymod_step(checksum, value);
    }
    Ok(checksum)
}

fn polymod_step(checksum: u32, value: u8) -> u32 {
    const GENERATORS: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];

    let high = checksum >> 25;
    let mut next = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(value);
    for (index, generator) in GENERATORS.iter().enumerate() {
        if ((high >> index) & 1) != 0 {
            next ^= generator;
        }
    }
    next
}

fn decode_bech32_character(byte: u8) -> Option<u8> {
    let lowercase = byte.to_ascii_lowercase();
    BECH32_ALPHABET
        .iter()
        .position(|candidate| *candidate == lowercase)
        .and_then(|index| u8::try_from(index).ok())
}

fn decode_base32(words: &[u8]) -> Result<Vec<u8>, SecpError> {
    let total_bits = words
        .len()
        .checked_mul(5)
        .ok_or(SecpError::CapacityOverflow {
            input_len: words.len(),
        })?;
    let output_len = total_bits / 8;
    let mut output = try_vec_with_capacity::<u8>(output_len, words.len())?;
    let mut accumulator = 0u32;
    let mut bits = 0u8;

    for word in words {
        let value = decode_bech32_character(*word)
            .ok_or(SecpError::InvalidNip19("invalid bech32 string"))?;
        accumulator = ((accumulator << 5) | u32::from(value)) & 0x0fff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((accumulator >> bits) & 0xff) as u8);
        }
    }

    if bits >= 5 || ((accumulator << (8 - bits)) & 0xff) != 0 {
        return Err(SecpError::InvalidNip19("invalid bech32 payload"));
    }
    Ok(output)
}

fn missing_required_field(entity: &'static str, tag: usize) -> &'static str {
    match (entity, tag) {
        ("nprofile", 0) => "missing TLV 0 for nprofile",
        ("nevent", 0) => "missing TLV 0 for nevent",
        ("naddr", 0) => "missing TLV 0 for naddr",
        ("naddr", 2) => "missing TLV 2 for naddr",
        ("naddr", 3) => "missing TLV 3 for naddr",
        ("nrelay", 0) => "missing TLV 0 for nrelay",
        _ => "missing required tlv field",
    }
}

fn expected_length(entity: &'static str, tag: usize, len: usize) -> &'static str {
    match (entity, tag, len) {
        ("nprofile", 0, 32) => "TLV 0 should be 32 bytes",
        ("nevent", 0, 32) => "TLV 0 should be 32 bytes",
        ("nevent", 2, 32) => "TLV 2 should be 32 bytes",
        ("nevent", 3, 4) => "TLV 3 should be 4 bytes",
        ("naddr", 2, 32) => "TLV 2 should be 32 bytes",
        ("naddr", 3, 4) => "TLV 3 should be 4 bytes",
        _ => "invalid tlv length",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::ToString, vec};
    use bech32::{u5, ToBase32};

    const GENERATOR_X: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    #[test]
    fn npub_roundtrip_accepts_uppercase() {
        let public = XOnlyPublicKey::from_bytes(GENERATOR_X).expect("generator x-coordinate");
        let encoded = encode_npub(&public).expect("encode npub");
        let uppercase = encoded.to_ascii_uppercase();
        assert_eq!(
            decode(&uppercase).expect("decode uppercase"),
            Nip19::Npub(public)
        );
    }

    #[test]
    fn mixed_case_is_rejected() {
        let public = XOnlyPublicKey::from_bytes(GENERATOR_X).expect("generator x-coordinate");
        let encoded = encode_npub(&public).expect("encode npub");
        let mixed = format!("N{}", &encoded[1..]);
        assert!(matches!(
            decode(&mixed),
            Err(SecpError::InvalidNip19("invalid bech32 string"))
        ));
    }

    #[test]
    fn bech32m_is_rejected() {
        let encoded = bech32::encode("note", [0x42u8; 32].to_base32(), Variant::Bech32m)
            .expect("encode bech32m fixture");
        assert!(matches!(
            decode(&encoded),
            Err(SecpError::InvalidNip19("unexpected bech32 variant"))
        ));
    }

    #[test]
    fn nonzero_padding_is_rejected() {
        let word = u5::try_from_u8(1).expect("five-bit word");
        let encoded =
            bech32::encode("note", vec![word], Variant::Bech32).expect("encode padding fixture");
        assert!(matches!(
            decode(&encoded),
            Err(SecpError::InvalidNip19("invalid bech32 payload"))
        ));
    }

    #[test]
    fn truncated_tlv_is_rejected() {
        let encoded = bech32::encode("nprofile", [0u8].to_base32(), Variant::Bech32)
            .expect("encode truncated tlv");
        assert!(matches!(
            decode(&encoded),
            Err(SecpError::InvalidNip19("truncated tlv header"))
        ));
    }

    #[test]
    fn profile_roundtrip_preserves_relay_order() {
        let profile = NProfile {
            pubkey: XOnlyPublicKey::from_bytes(GENERATOR_X).expect("generator x-coordinate"),
            relays: vec![
                "wss://first.example".to_string(),
                "wss://second.example".to_string(),
            ],
        };
        let encoded = encode_nprofile(&profile).expect("encode profile");
        assert_eq!(
            decode(&encoded).expect("decode profile"),
            Nip19::NProfile(profile)
        );
    }
}
