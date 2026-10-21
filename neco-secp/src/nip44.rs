use crate::keys::{decode_xonly_pubkey, ecdh_raw};
use crate::{storage, SecpError, SecretKey, XOnlyPublicKey};
use alloc::string::String;
use alloc::vec::Vec;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use neco_sha2::{Hkdf, Hmac};

const VERSION_V2: u8 = 2;
const MIN_PLAINTEXT_SIZE: usize = 1;
const MAX_PLAINTEXT_SIZE: usize = 65_535;
const MIN_RAW_PAYLOAD_SIZE: usize = 99;
const MAX_RAW_PAYLOAD_SIZE: usize = 65_603;
const MIN_ENCODED_PAYLOAD_SIZE: usize = 132;
const MAX_ENCODED_PAYLOAD_SIZE: usize = 87_472;

pub fn get_conversation_key(
    secret: &SecretKey,
    pubkey: &XOnlyPublicKey,
) -> Result<[u8; 32], SecpError> {
    let shared_x = ecdh_raw(&secret.to_bytes(), decode_xonly_pubkey(pubkey)?)?;
    Ok(*Hkdf::extract(b"nip44-v2", &shared_x)?.as_bytes())
}

pub fn calc_padded_len(len: usize) -> Result<usize, SecpError> {
    if len < MIN_PLAINTEXT_SIZE {
        return Err(SecpError::InvalidNip44("expected positive integer"));
    }
    if len <= 32 {
        return Ok(32);
    }
    let next_power = len
        .checked_next_power_of_two()
        .ok_or(SecpError::CapacityOverflow { input_len: len })?;
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk
        .checked_mul((len - 1) / chunk + 1)
        .ok_or(SecpError::CapacityOverflow { input_len: len })
}

pub fn encrypt(
    plaintext: &str,
    conversation_key: &[u8; 32],
    nonce: Option<[u8; 32]>,
) -> Result<String, SecpError> {
    encrypt_with_rng(plaintext, conversation_key, nonce, &mut random_fill)
}

pub fn encrypt_with_rng<F>(
    plaintext: &str,
    conversation_key: &[u8; 32],
    nonce: Option<[u8; 32]>,
    fill: &mut F,
) -> Result<String, SecpError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    let nonce = match nonce {
        Some(value) => value,
        None => {
            let mut value = [0u8; 32];
            fill(&mut value)?;
            value
        }
    };
    let mut ciphertext = pad(plaintext)?;
    let keys = get_message_keys(conversation_key, &nonce)?;
    chacha20_xor(&keys.chacha_key, &keys.chacha_nonce, &mut ciphertext)?;
    let mac = hmac_aad(&keys.hmac_key, &ciphertext, &nonce)?;
    let required = ciphertext
        .len()
        .checked_add(65)
        .ok_or(SecpError::CapacityOverflow {
            input_len: plaintext.len(),
        })?;
    let mut payload = storage::vector(required)?;
    payload.push(VERSION_V2);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&mac);
    neco_base64::encode(&payload).map_err(SecpError::Base64)
}

pub fn decrypt(payload: &str, conversation_key: &[u8; 32]) -> Result<String, SecpError> {
    let mut decoded = decode_payload(payload)?;
    let keys = get_message_keys(conversation_key, &decoded.nonce)?;
    if hmac_aad(&keys.hmac_key, &decoded.ciphertext, &decoded.nonce)? != decoded.mac {
        return Err(SecpError::InvalidNip44("invalid MAC"));
    }
    chacha20_xor(
        &keys.chacha_key,
        &keys.chacha_nonce,
        &mut decoded.ciphertext,
    )?;
    unpad(decoded.ciphertext)
}

struct MessageKeys {
    chacha_key: [u8; 32],
    chacha_nonce: [u8; 12],
    hmac_key: [u8; 32],
}

struct DecodedPayload {
    nonce: [u8; 32],
    ciphertext: Vec<u8>,
    mac: [u8; 32],
}

fn get_message_keys(
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<MessageKeys, SecpError> {
    let mut keys = [0u8; 76];
    neco_sha2::Prk::from_bytes(conversation_key)
        .expand_into(nonce, &mut keys)
        .map_err(SecpError::Hkdf)?;
    let mut chacha_key = [0u8; 32];
    chacha_key.copy_from_slice(&keys[..32]);
    let mut chacha_nonce = [0u8; 12];
    chacha_nonce.copy_from_slice(&keys[32..44]);
    let mut hmac_key = [0u8; 32];
    hmac_key.copy_from_slice(&keys[44..]);
    Ok(MessageKeys {
        chacha_key,
        chacha_nonce,
        hmac_key,
    })
}

fn random_fill(output: &mut [u8]) -> Result<(), SecpError> {
    #[cfg(feature = "getrandom")]
    {
        getrandom::getrandom(output).map_err(|_| SecpError::RandomUnavailable)
    }
    #[cfg(not(feature = "getrandom"))]
    {
        let _ = output;
        Err(SecpError::EntropyRequired)
    }
}

fn pad(plaintext: &str) -> Result<Vec<u8>, SecpError> {
    let raw = plaintext.as_bytes();
    let len = raw.len();
    if !(MIN_PLAINTEXT_SIZE..=MAX_PLAINTEXT_SIZE).contains(&len) {
        return Err(SecpError::InvalidNip44(
            "invalid plaintext size: must be between 1 and 65535 bytes",
        ));
    }
    let padded_len = calc_padded_len(len)?;
    let required = padded_len
        .checked_add(2)
        .ok_or(SecpError::CapacityOverflow { input_len: len })?;
    let mut result = storage::vector(required)?;
    let len_u16 =
        u16::try_from(len).map_err(|_| SecpError::InvalidNip44("invalid plaintext size"))?;
    result.extend_from_slice(&len_u16.to_be_bytes());
    result.extend_from_slice(raw);
    result.resize(required, 0);
    Ok(result)
}

fn unpad(mut padded: Vec<u8>) -> Result<String, SecpError> {
    if padded.len() < 2 {
        return Err(SecpError::InvalidNip44("invalid padding"));
    }
    let len = usize::from(u16::from_be_bytes([padded[0], padded[1]]));
    if !(MIN_PLAINTEXT_SIZE..=MAX_PLAINTEXT_SIZE).contains(&len) {
        return Err(SecpError::InvalidNip44("invalid padding"));
    }
    if padded.len() != 2 + calc_padded_len(len)? || 2 + len > padded.len() {
        return Err(SecpError::InvalidNip44("invalid padding"));
    }
    padded.copy_within(2..2 + len, 0);
    padded.truncate(len);
    String::from_utf8(padded).map_err(|_| SecpError::InvalidNip44("invalid utf-8 payload"))
}

fn hmac_aad(key: &[u8; 32], message: &[u8], aad: &[u8; 32]) -> Result<[u8; 32], SecpError> {
    let mut mac = Hmac::new(key)?;
    mac.update(aad)?.update(message)?;
    Ok(mac.finalize())
}

fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) -> Result<(), SecpError> {
    let mut cipher = chacha20::ChaCha20::new(key.into(), nonce.into());
    cipher
        .try_apply_keystream(data)
        .map_err(|_| SecpError::InvalidNip44("message exceeds cipher stream limit"))
}

fn decode_payload(payload: &str) -> Result<DecodedPayload, SecpError> {
    if !(MIN_ENCODED_PAYLOAD_SIZE..=MAX_ENCODED_PAYLOAD_SIZE).contains(&payload.len()) {
        return Err(SecpError::InvalidNip44("invalid payload length"));
    }
    if payload.starts_with('#') {
        return Err(SecpError::InvalidNip44("unknown encryption version"));
    }
    let mut data = neco_base64::decode(payload).map_err(SecpError::Base64)?;
    if !(MIN_RAW_PAYLOAD_SIZE..=MAX_RAW_PAYLOAD_SIZE).contains(&data.len()) {
        return Err(SecpError::InvalidNip44("invalid data length"));
    }
    if data[0] != VERSION_V2 {
        return Err(SecpError::InvalidNip44("unknown encryption version"));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&data[1..33]);
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&data[data.len() - 32..]);
    let ciphertext_len = data.len() - 65;
    data.copy_within(33..33 + ciphertext_len, 0);
    data.truncate(ciphertext_len);
    Ok(DecodedPayload {
        nonce,
        ciphertext: data,
        mac,
    })
}
