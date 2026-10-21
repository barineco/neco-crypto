use crate::{
    nip44, nostr, storage, Rumor, SecpError, SecretKey, SignedEvent, UnsignedEvent, XOnlyPublicKey,
};
use alloc::vec::Vec;
use neco_sha2::Hmac;

#[cfg(feature = "getrandom")]
pub fn create_seal(
    inner: UnsignedEvent,
    sender: &SecretKey,
    recipient: &XOnlyPublicKey,
    now_unix_seconds: u64,
) -> Result<SignedEvent, SecpError> {
    create_seal_with_rng(inner, sender, recipient, now_unix_seconds, &mut random_fill)
}

pub fn create_seal_with_rng<F>(
    inner: UnsignedEvent,
    sender: &SecretKey,
    recipient: &XOnlyPublicKey,
    now_unix_seconds: u64,
    fill: &mut F,
) -> Result<SignedEvent, SecpError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    let rumor = nostr::create_rumor(inner, sender.xonly_public_key()?)?;
    let json = nostr::serialize_rumor(&rumor)?;
    let conversation_key = nip44::get_conversation_key(sender, recipient)?;
    let content = nip44::encrypt_with_rng(&json, &conversation_key, None, fill)?;
    let created_at = randomized_timestamp(now_unix_seconds, fill)?;
    nostr::finalize_event_with_rng(
        UnsignedEvent {
            created_at,
            kind: 13,
            tags: Vec::new(),
            content,
        },
        sender,
        fill,
    )
}

pub fn open_seal(seal: &SignedEvent, recipient: &SecretKey) -> Result<Rumor, SecpError> {
    check_seal(seal)?;
    let conversation_key = nip44::get_conversation_key(recipient, &seal.pubkey)?;
    let json = nip44::decrypt(&seal.content, &conversation_key)?;
    let rumor = nostr::parse_rumor(&json)?;
    if rumor.pubkey != seal.pubkey {
        return Err(SecpError::InvalidEvent(
            "rumor author does not match seal author",
        ));
    }
    nostr::verify_rumor(&rumor)?;
    Ok(rumor)
}

pub struct GiftWrapWithScanTag {
    pub event: SignedEvent,
    pub scanning_tag: [u8; 16],
}

#[cfg(feature = "getrandom")]
pub fn create_gift_wrap(
    seal: &SignedEvent,
    recipient: &XOnlyPublicKey,
    now_unix_seconds: u64,
) -> Result<SignedEvent, SecpError> {
    create_gift_wrap_with_rng(seal, recipient, now_unix_seconds, &mut random_fill)
}

pub fn create_gift_wrap_with_rng<F>(
    seal: &SignedEvent,
    recipient: &XOnlyPublicKey,
    now_unix_seconds: u64,
    fill: &mut F,
) -> Result<SignedEvent, SecpError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    check_seal(seal)?;
    let ephemeral = SecretKey::generate_with_rng(fill)?;
    wrap_with_key(seal, recipient, now_unix_seconds, &ephemeral, fill)
}

#[cfg(feature = "getrandom")]
pub fn create_gift_wrap_with_scan_tag(
    seal: &SignedEvent,
    recipient: &XOnlyPublicKey,
    recipient_scan_pub: &XOnlyPublicKey,
    now_unix_seconds: u64,
) -> Result<GiftWrapWithScanTag, SecpError> {
    create_gift_wrap_with_scan_tag_with_rng(
        seal,
        recipient,
        recipient_scan_pub,
        now_unix_seconds,
        &mut random_fill,
    )
}

pub fn create_gift_wrap_with_scan_tag_with_rng<F>(
    seal: &SignedEvent,
    recipient: &XOnlyPublicKey,
    recipient_scan_pub: &XOnlyPublicKey,
    now_unix_seconds: u64,
    fill: &mut F,
) -> Result<GiftWrapWithScanTag, SecpError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    check_seal(seal)?;
    let ephemeral = SecretKey::generate_with_rng(fill)?;
    let scanning_tag = compute_scan_tag(&ephemeral, recipient_scan_pub)?;
    let event = wrap_with_key(seal, recipient, now_unix_seconds, &ephemeral, fill)?;
    Ok(GiftWrapWithScanTag {
        event,
        scanning_tag,
    })
}

fn wrap_with_key<F>(
    seal: &SignedEvent,
    recipient: &XOnlyPublicKey,
    now_unix_seconds: u64,
    ephemeral: &SecretKey,
    fill: &mut F,
) -> Result<SignedEvent, SecpError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    let json = nostr::serialize_signed_event(seal)?;
    let conversation_key = nip44::get_conversation_key(ephemeral, recipient)?;
    let content = nip44::encrypt_with_rng(&json, &conversation_key, None, fill)?;
    let created_at = randomized_timestamp(now_unix_seconds, fill)?;
    let mut tags = storage::vector(1)?;
    tags.push(nostr::tag_pair("p", recipient.to_hex()?)?);
    nostr::finalize_event_with_rng(
        UnsignedEvent {
            created_at,
            kind: 1059,
            tags,
            content,
        },
        ephemeral,
        fill,
    )
}

pub fn open_gift_wrap(gift_wrap: &SignedEvent, recipient: &SecretKey) -> Result<Rumor, SecpError> {
    if gift_wrap.kind != 1059 {
        return Err(SecpError::InvalidEvent("gift wrap must have kind 1059"));
    }
    nostr::verify_event(gift_wrap)?;
    let conversation_key = nip44::get_conversation_key(recipient, &gift_wrap.pubkey)?;
    let json = nip44::decrypt(&gift_wrap.content, &conversation_key)?;
    let seal = nostr::parse_signed_event(&json)?;
    open_seal(&seal, recipient)
}

pub fn compute_scan_tag(
    scan_priv: &SecretKey,
    ephemeral_pubkey: &XOnlyPublicKey,
) -> Result<[u8; 16], SecpError> {
    let conversation_key = nip44::get_conversation_key(scan_priv, ephemeral_pubkey)?;
    let full = Hmac::mac(&conversation_key, b"stealth-dm-tag")?;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&full[..16]);
    Ok(tag)
}

fn check_seal(seal: &SignedEvent) -> Result<(), SecpError> {
    if seal.kind != 13 {
        return Err(SecpError::InvalidEvent("seal must have kind 13"));
    }
    if !seal.tags.is_empty() {
        return Err(SecpError::InvalidEvent("seal tags must be empty"));
    }
    nostr::verify_event(seal)
}

fn randomized_timestamp<F>(base: u64, fill: &mut F) -> Result<u64, SecpError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    let mut bytes = [0u8; 4];
    fill(&mut bytes)?;
    Ok(base.saturating_sub(u64::from(u32::from_le_bytes(bytes) % 172_801)))
}

#[cfg(feature = "getrandom")]
fn random_fill(output: &mut [u8]) -> Result<(), SecpError> {
    getrandom::getrandom(output).map_err(|_| SecpError::RandomUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn key(value: u8) -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        SecretKey::from_bytes(bytes).unwrap()
    }

    fn fixed_random(bytes: &mut [u8]) -> Result<(), SecpError> {
        bytes.fill(1);
        Ok(())
    }

    fn message() -> UnsignedEvent {
        UnsignedEvent {
            created_at: 1_700_000_000,
            kind: 14,
            tags: Vec::new(),
            content: String::from("hello"),
        }
    }

    #[test]
    fn rumor_is_unsigned_and_survives_wrapping() {
        let sender = key(1);
        let receiver = key(2);
        let public = receiver.xonly_public_key().unwrap();
        let seal = create_seal_with_rng(
            message(),
            &sender,
            &public,
            1_700_000_000,
            &mut fixed_random,
        )
        .unwrap();
        let conversation = nip44::get_conversation_key(&receiver, &seal.pubkey).unwrap();
        let json = nip44::decrypt(&seal.content, &conversation).unwrap();
        assert!(!json.contains("\"sig\""));
        let wrap =
            create_gift_wrap_with_rng(&seal, &public, 1_700_000_000, &mut fixed_random).unwrap();
        let rumor = open_gift_wrap(&wrap, &receiver).unwrap();
        assert_eq!(rumor.pubkey, sender.xonly_public_key().unwrap());
        assert_eq!(rumor.content, "hello");
        assert!(seal.created_at <= 1_700_000_000);
        assert!(wrap.created_at <= 1_700_000_000);
    }

    #[test]
    fn unavailable_nonce_and_timestamp_sources_fail() {
        let sender = key(1);
        let peer = key(2).xonly_public_key().unwrap();
        assert_eq!(
            create_seal_with_rng(message(), &sender, &peer, 1_700_000_000, &mut |_| Err(
                SecpError::RandomUnavailable
            )),
            Err(SecpError::RandomUnavailable)
        );
        assert_eq!(
            randomized_timestamp(u64::MAX, &mut |_| Err(SecpError::RandomUnavailable)),
            Err(SecpError::RandomUnavailable)
        );
        assert_eq!(randomized_timestamp(0, &mut fixed_random).unwrap(), 0);
    }
}
