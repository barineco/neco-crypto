use crate::{nostr, storage, SecpError, SecretKey, SignedEvent, UnsignedEvent, XOnlyPublicKey};
use alloc::{string::String, vec::Vec};

#[cfg(feature = "getrandom")]
pub fn create_auth_event(
    challenge: &str,
    relay_url: &str,
    signer: &SecretKey,
    now_unix_seconds: u64,
) -> Result<SignedEvent, SecpError> {
    create_auth_event_with_rng(
        challenge,
        relay_url,
        signer,
        now_unix_seconds,
        &mut |bytes| getrandom::getrandom(bytes).map_err(|_| SecpError::RandomUnavailable),
    )
}

pub fn create_auth_event_with_rng<F>(
    challenge: &str,
    relay_url: &str,
    signer: &SecretKey,
    now_unix_seconds: u64,
    fill: &mut F,
) -> Result<SignedEvent, SecpError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    let mut tags = storage::vector(2)?;
    tags.push(nostr::tag_pair("relay", storage::text(relay_url)?)?);
    tags.push(nostr::tag_pair("challenge", storage::text(challenge)?)?);
    nostr::finalize_event_with_rng(
        UnsignedEvent {
            created_at: now_unix_seconds,
            kind: 22_242,
            tags,
            content: String::new(),
        },
        signer,
        fill,
    )
}

pub fn validate_auth_event(
    event: &SignedEvent,
    challenge: &str,
    relay_url: &str,
) -> Result<XOnlyPublicKey, SecpError> {
    nostr::verify_event(event)?;
    if event.kind != 22_242 {
        return Err(SecpError::InvalidEvent("auth event must have kind 22242"));
    }
    if tag_value(&event.tags, "relay") != Some(relay_url) {
        return Err(SecpError::InvalidEvent("auth event relay tag mismatch"));
    }
    if tag_value(&event.tags, "challenge") != Some(challenge) {
        return Err(SecpError::InvalidEvent("auth event challenge tag mismatch"));
    }
    Ok(event.pubkey)
}

fn tag_value<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|tag| tag.first().is_some_and(|value| value == name))
        .and_then(|tag| tag.get(1))
        .map(String::as_str)
}
