use crate::hmac::Hmac;
use crate::sha256::Sha256Error;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

const HASH_LEN: usize = 32;
const MAX_OUTPUT: usize = 255 * HASH_LEN;

pub struct Prk([u8; HASH_LEN]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HkdfError {
    OutputTooLong { requested: usize, maximum: usize },
    AllocationFailed { required: usize },
    Hash(Sha256Error),
}

impl core::fmt::Display for HkdfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutputTooLong { requested, maximum } => {
                write!(f, "HKDF requested {requested} bytes; maximum is {maximum}")
            }
            Self::AllocationFailed { required } => {
                write!(f, "HKDF allocation failed for {required} bytes")
            }
            Self::Hash(error) => write!(f, "HKDF hash input failed: {error}"),
        }
    }
}

impl core::error::Error for HkdfError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Hash(error) => Some(error),
            _ => None,
        }
    }
}

impl From<Sha256Error> for HkdfError {
    fn from(value: Sha256Error) -> Self {
        Self::Hash(value)
    }
}

pub struct Hkdf;

impl Hkdf {
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Result<Prk, HkdfError> {
        let salt_used: &[u8] = if salt.is_empty() {
            &[0u8; HASH_LEN]
        } else {
            salt
        };
        Ok(Prk(Hmac::mac(salt_used, ikm)?))
    }
}

impl Prk {
    pub fn from_bytes(bytes: &[u8; HASH_LEN]) -> Self {
        Prk(*bytes)
    }

    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn expand_into(&self, info: &[u8], output: &mut [u8]) -> Result<(), HkdfError> {
        if output.len() > MAX_OUTPUT {
            return Err(HkdfError::OutputTooLong {
                requested: output.len(),
                maximum: MAX_OUTPUT,
            });
        }
        let mut previous = [0u8; HASH_LEN];
        let mut previous_len = 0;
        for (index, chunk) in output.chunks_mut(HASH_LEN).enumerate() {
            let mut h = Hmac::with_key(&self.0);
            h.update(&previous[..previous_len])?
                .update(info)?
                .update(&[(index + 1) as u8])?;
            previous = h.finalize();
            previous_len = HASH_LEN;
            chunk.copy_from_slice(&previous[..chunk.len()]);
        }
        Ok(())
    }

    #[cfg(feature = "alloc")]
    pub fn expand(&self, info: &[u8], len: usize) -> Result<Vec<u8>, HkdfError> {
        if len > MAX_OUTPUT {
            return Err(HkdfError::OutputTooLong {
                requested: len,
                maximum: MAX_OUTPUT,
            });
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(len)
            .map_err(|_| HkdfError::AllocationFailed { required: len })?;
        output.resize(len, 0);
        self.expand_into(info, &mut output)?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{format, string::String, vec, vec::Vec};

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn rfc5869_tc1() {
        let ikm = from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = from_hex("000102030405060708090a0b0c");
        let info = from_hex("f0f1f2f3f4f5f6f7f8f9");
        let len = 42;

        let prk = Hkdf::extract(&salt, &ikm).unwrap();
        assert_eq!(
            hex(&prk.0),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );

        let mut okm = vec![0u8; len];
        prk.expand_into(&info, &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn rfc5869_tc2() {
        let ikm = from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
        let salt = from_hex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        let info = from_hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let len = 82;

        let prk = Hkdf::extract(&salt, &ikm).unwrap();
        assert_eq!(
            hex(&prk.0),
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
        );

        let mut okm = vec![0u8; len];
        prk.expand_into(&info, &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
        );
    }

    #[test]
    fn rfc5869_tc3() {
        let ikm = from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = b"";
        let info = b"";
        let len = 42;

        let prk = Hkdf::extract(salt, &ikm).unwrap();
        assert_eq!(
            hex(&prk.0),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        );

        let mut okm = vec![0u8; len];
        prk.expand_into(info, &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn error_on_too_long() {
        let prk = Hkdf::extract(b"salt", b"ikm").unwrap();
        let mut output = [0u8; 8161];
        assert_eq!(
            prk.expand_into(b"info", &mut output),
            Err(HkdfError::OutputTooLong {
                requested: 8161,
                maximum: 8160
            })
        );
    }

    #[test]
    fn empty_output() {
        let prk = Hkdf::extract(b"salt", b"ikm").unwrap();
        assert_eq!(prk.expand_into(b"info", &mut []), Ok(()));
    }
}

#[cfg(test)]
mod output_tests {
    use super::*;

    #[test]
    fn caller_storage_supports_partial_blocks_and_limits() {
        let prk = Hkdf::extract(b"salt", b"input key material").unwrap();
        let mut full = [0u8; MAX_OUTPUT];
        prk.expand_into(b"info", &mut full).unwrap();
        for len in [0, 1, 31, 32, 33, 64, 65, MAX_OUTPUT] {
            let mut output = [0u8; MAX_OUTPUT];
            prk.expand_into(b"info", &mut output[..len]).unwrap();
            assert_eq!(&output[..len], &full[..len]);
            #[cfg(feature = "alloc")]
            assert_eq!(prk.expand(b"info", len).unwrap(), output[..len]);
        }
        let mut output = [0u8; MAX_OUTPUT + 1];
        assert_eq!(
            prk.expand_into(b"info", &mut output),
            Err(HkdfError::OutputTooLong {
                requested: MAX_OUTPUT + 1,
                maximum: MAX_OUTPUT
            })
        );
        assert_eq!(output, [0u8; MAX_OUTPUT + 1]);
    }
}
