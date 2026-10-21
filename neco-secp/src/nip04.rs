use crate::keys::{decode_xonly_pubkey, ecdh_raw};
use crate::{storage, SecpError, SecretKey, XOnlyPublicKey};
use aes::Aes256;
use alloc::string::String;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub fn encrypt(
    secret: &SecretKey,
    pubkey: &XOnlyPublicKey,
    plaintext: &str,
    iv: Option<[u8; 16]>,
) -> Result<String, SecpError> {
    encrypt_with_rng(secret, pubkey, plaintext, iv, &mut random_fill)
}

pub fn encrypt_with_rng<F>(
    secret: &SecretKey,
    pubkey: &XOnlyPublicKey,
    plaintext: &str,
    iv: Option<[u8; 16]>,
    fill: &mut F,
) -> Result<String, SecpError>
where
    F: FnMut(&mut [u8]) -> Result<(), SecpError>,
{
    let key = get_shared_secret_x(secret, pubkey)?;
    let iv = match iv {
        Some(value) => value,
        None => {
            let mut value = [0u8; 16];
            fill(&mut value)?;
            value
        }
    };
    let plaintext = plaintext.as_bytes();
    let required = plaintext
        .len()
        .checked_add(16)
        .ok_or(SecpError::CapacityOverflow {
            input_len: plaintext.len(),
        })?;
    let mut buffer = storage::vector(required)?;
    buffer.extend_from_slice(plaintext);
    buffer.resize(required, 0);
    let ciphertext = Aes256CbcEnc::new((&key).into(), (&iv).into())
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .map_err(|_| SecpError::InvalidNip04("failed to encrypt"))?;
    let ciphertext = neco_base64::encode(ciphertext).map_err(SecpError::Base64)?;
    let encoded_iv = neco_base64::encode(&iv).map_err(SecpError::Base64)?;
    let required = ciphertext
        .len()
        .checked_add(4)
        .and_then(|n| n.checked_add(encoded_iv.len()))
        .ok_or(SecpError::CapacityOverflow {
            input_len: plaintext.len(),
        })?;
    let mut output = storage::string(required)?;
    output.push_str(&ciphertext);
    output.push_str("?iv=");
    output.push_str(&encoded_iv);
    Ok(output)
}

pub fn decrypt(
    secret: &SecretKey,
    pubkey: &XOnlyPublicKey,
    payload: &str,
) -> Result<String, SecpError> {
    let (ciphertext_b64, iv_b64) = payload
        .split_once("?iv=")
        .ok_or(SecpError::InvalidNip04("invalid payload"))?;
    let key = get_shared_secret_x(secret, pubkey)?;
    let iv = neco_base64::decode(iv_b64).map_err(SecpError::Base64)?;
    let mut ciphertext = neco_base64::decode(ciphertext_b64).map_err(SecpError::Base64)?;
    let iv: [u8; 16] = iv
        .try_into()
        .map_err(|_| SecpError::InvalidNip04("invalid iv"))?;
    let length = Aes256CbcDec::new((&key).into(), (&iv).into())
        .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
        .map_err(|_| SecpError::InvalidNip04("failed to decrypt"))?
        .len();
    ciphertext.truncate(length);
    String::from_utf8(ciphertext).map_err(|_| SecpError::InvalidNip04("invalid utf-8 payload"))
}

fn get_shared_secret_x(secret: &SecretKey, pubkey: &XOnlyPublicKey) -> Result<[u8; 32], SecpError> {
    ecdh_raw(&secret.to_bytes(), decode_xonly_pubkey(pubkey)?)
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
