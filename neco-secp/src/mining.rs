use crate::{KeyBundle, SecpError};
#[cfg(feature = "nip19")]
use alloc::vec::Vec;

#[cfg(all(feature = "nip19", feature = "getrandom"))]
pub fn mine_vanity_npub(prefix: &str, max_attempts: u64) -> Result<KeyBundle, SecpError> {
    mine_vanity_npub_with_rng(prefix, max_attempts, &mut random_fill)
}

#[cfg(feature = "nip19")]
pub fn mine_vanity_npub_with_rng<F>(
    prefix: &str,
    max_attempts: u64,
    fill: &mut F,
) -> Result<KeyBundle, SecpError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    for _ in 0..max_attempts {
        let bundle = KeyBundle::generate_with_rng(fill)?;
        if count_npub_prefix_matches(&bundle.xonly_public_key().to_bytes(), prefix)? == prefix.len()
        {
            return Ok(bundle);
        }
    }
    Err(SecpError::ExhaustedAttempts)
}

#[cfg(feature = "nip19")]
#[derive(Debug, Clone)]
pub struct VanityCandidate {
    bundle: KeyBundle,
    matched_len: usize,
}

#[cfg(feature = "nip19")]
impl VanityCandidate {
    pub fn bundle(&self) -> &KeyBundle {
        &self.bundle
    }
    pub fn matched_len(&self) -> usize {
        self.matched_len
    }
}

#[cfg(all(feature = "nip19", feature = "getrandom"))]
pub fn mine_vanity_npub_candidates(
    prefix: &str,
    max_attempts: u64,
    top_k: usize,
) -> Result<Vec<VanityCandidate>, SecpError> {
    mine_vanity_npub_candidates_with_rng(prefix, max_attempts, top_k, &mut random_fill)
}

#[cfg(feature = "nip19")]
pub fn mine_vanity_npub_candidates_with_rng<F>(
    prefix: &str,
    max_attempts: u64,
    top_k: usize,
    fill: &mut F,
) -> Result<Vec<VanityCandidate>, SecpError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    if top_k == 0 || max_attempts == 0 {
        return Ok(Vec::new());
    }
    let attempts = match usize::try_from(max_attempts) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    };
    let limit = top_k.min(attempts);
    let mut candidates: Vec<VanityCandidate> = crate::storage::vector(limit)?;
    for _ in 0..max_attempts {
        let bundle = KeyBundle::generate_with_rng(fill)?;
        let matched_len = count_npub_prefix_matches(&bundle.xonly_public_key().to_bytes(), prefix)?;
        if matched_len == 0 {
            continue;
        }
        let position = candidates
            .iter()
            .position(|candidate| candidate.matched_len < matched_len)
            .unwrap_or(candidates.len());
        if candidates.len() == limit {
            if position == limit {
                continue;
            }
            candidates.pop();
        }
        candidates.insert(
            position,
            VanityCandidate {
                bundle,
                matched_len,
            },
        );
    }
    Ok(candidates)
}

#[cfg(feature = "nip19")]
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#[cfg(feature = "nip19")]
pub(crate) fn bech32_value(byte: u8) -> Result<u8, SecpError> {
    BECH32_CHARSET
        .iter()
        .position(|&candidate| candidate == byte)
        .map(|value| value as u8)
        .ok_or(SecpError::InvalidNip19("invalid npub vanity prefix"))
}

#[cfg(feature = "nip19")]
pub(crate) fn count_npub_prefix_matches(
    xonly_bytes: &[u8; 32],
    prefix: &str,
) -> Result<usize, SecpError> {
    let prefix_bytes = prefix.as_bytes();
    if prefix_bytes.is_empty() {
        return Ok(0);
    }
    for &byte in prefix_bytes {
        bech32_value(byte)?;
    }
    let mut matched = 0usize;
    let mut acc = 0u16;
    let mut bits = 0u8;
    for &byte in xonly_bytes {
        acc = (acc << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 && matched < prefix_bytes.len() {
            bits -= 5;
            let value = ((acc >> bits) & 0x1f) as usize;
            if BECH32_CHARSET[value] != prefix_bytes[matched] {
                return Ok(matched);
            }
            matched += 1;
        }
        if matched == prefix_bytes.len() {
            return Ok(matched);
        }
    }
    if bits > 0 && matched < prefix_bytes.len() {
        let value = ((acc << (5 - bits)) & 0x1f) as usize;
        if BECH32_CHARSET[value] == prefix_bytes[matched] {
            matched += 1;
        }
    }
    Ok(matched)
}

#[cfg(feature = "getrandom")]
pub fn mine_pow(difficulty: u8, max_attempts: u64) -> Result<KeyBundle, SecpError> {
    mine_pow_with_rng(difficulty, max_attempts, &mut random_fill)
}

pub fn mine_pow_with_rng<F>(
    difficulty: u8,
    max_attempts: u64,
    fill: &mut F,
) -> Result<KeyBundle, SecpError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    for _ in 0..max_attempts {
        let bundle = KeyBundle::generate_with_rng(fill)?;
        if count_leading_zero_nibbles(&bundle.xonly_public_key().to_bytes()) >= difficulty {
            return Ok(bundle);
        }
    }
    Err(SecpError::ExhaustedAttempts)
}

#[cfg(feature = "getrandom")]
pub fn mine_pow_best(min_difficulty: u8, max_attempts: u64) -> Result<(KeyBundle, u8), SecpError> {
    mine_pow_best_with_rng(min_difficulty, max_attempts, &mut random_fill)
}

pub fn mine_pow_best_with_rng<F>(
    min_difficulty: u8,
    max_attempts: u64,
    fill: &mut F,
) -> Result<(KeyBundle, u8), SecpError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    let mut best: Option<(KeyBundle, u8)> = None;
    for _ in 0..max_attempts {
        let bundle = KeyBundle::generate_with_rng(fill)?;
        let difficulty = count_leading_zero_nibbles(&bundle.xonly_public_key().to_bytes());
        if difficulty >= min_difficulty {
            match best {
                Some((_, previous)) if difficulty <= previous => {}
                _ => best = Some((bundle, difficulty)),
            }
        }
    }
    best.ok_or(SecpError::ExhaustedAttempts)
}

pub(crate) fn count_leading_zero_nibbles(bytes: &[u8]) -> u8 {
    let mut count = 0u8;
    for &byte in bytes {
        if byte >> 4 == 0 {
            count += 1;
        } else {
            break;
        }
        if byte & 15 == 0 {
            count += 1;
        } else {
            break;
        }
    }
    count
}

#[cfg(feature = "getrandom")]
fn random_fill(output: &mut [u8]) -> Result<(), SecpError> {
    getrandom::getrandom(output).map_err(|_| SecpError::RandomUnavailable)
}
