use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecpError {
    InvalidSecretKey,
    InvalidPublicKey,
    InvalidSignature,
    ExhaustedAttempts,
    InvalidHex(&'static str),
    InvalidEvent(&'static str),
    #[cfg(feature = "nostr")]
    InvalidEventKind {
        kind: u32,
    },
    #[cfg(feature = "nostr")]
    EmptyEventTag {
        index: usize,
    },
    InvalidNip19(&'static str),
    InvalidNip04(&'static str),
    InvalidNip44(&'static str),
    #[cfg(feature = "nostr")]
    Json(crate::EventJsonError),
    Field(neco_galois::FieldError),
    Nonce(neco_sha2::rfc6979::Rfc6979Error),
    Hash(neco_sha2::Sha256Error),
    #[cfg(any(feature = "nip04", feature = "nip44"))]
    Base64(neco_base64::Base64Error),
    #[cfg(any(feature = "nip04", feature = "nip44"))]
    Hkdf(neco_sha2::HkdfError),
    RandomUnavailable,
    EntropyRequired,
    CapacityOverflow {
        input_len: usize,
    },
    AllocationFailed {
        required: usize,
    },
}

impl fmt::Display for SecpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretKey => f.write_str("invalid secret key"),
            Self::InvalidPublicKey => f.write_str("invalid public key"),
            Self::InvalidSignature => f.write_str("invalid signature"),
            Self::ExhaustedAttempts => f.write_str("exhausted attempts"),
            Self::InvalidHex(message) => f.write_str(message),
            Self::InvalidEvent(message) => f.write_str(message),
            #[cfg(feature = "nostr")]
            Self::InvalidEventKind { kind } => write!(f, "event kind {kind} exceeds 65535"),
            #[cfg(feature = "nostr")]
            Self::EmptyEventTag { index } => write!(f, "event tag at index {index} is empty"),
            Self::InvalidNip19(message) => f.write_str(message),
            Self::InvalidNip04(message) => f.write_str(message),
            Self::InvalidNip44(message) => f.write_str(message),
            #[cfg(feature = "nostr")]
            Self::Json(error) => write!(f, "json error: {error}"),
            Self::Field(error) => write!(f, "field error: {error}"),
            Self::Nonce(error) => write!(f, "nonce error: {error}"),
            Self::Hash(error) => write!(f, "hash error: {error}"),
            #[cfg(any(feature = "nip04", feature = "nip44"))]
            Self::Base64(error) => write!(f, "base64 error: {error}"),
            #[cfg(any(feature = "nip04", feature = "nip44"))]
            Self::Hkdf(error) => write!(f, "HKDF error: {error}"),
            Self::RandomUnavailable => f.write_str("operating system randomness is unavailable"),
            Self::EntropyRequired => f.write_str("external entropy is required"),
            Self::CapacityOverflow { input_len } => {
                write!(f, "capacity overflow for input length {input_len}")
            }
            Self::AllocationFailed { required } => {
                write!(f, "allocation failed for {required} requested elements")
            }
        }
    }
}

impl core::error::Error for SecpError {}

impl From<neco_galois::FieldError> for SecpError {
    fn from(value: neco_galois::FieldError) -> Self {
        Self::Field(value)
    }
}

impl From<neco_sha2::Sha256Error> for SecpError {
    fn from(value: neco_sha2::Sha256Error) -> Self {
        Self::Hash(value)
    }
}

impl From<neco_sha2::rfc6979::Rfc6979Error> for SecpError {
    fn from(value: neco_sha2::rfc6979::Rfc6979Error) -> Self {
        Self::Nonce(value)
    }
}

#[cfg(any(feature = "nip04", feature = "nip44"))]
impl From<neco_base64::Base64Error> for SecpError {
    fn from(value: neco_base64::Base64Error) -> Self {
        Self::Base64(value)
    }
}

#[cfg(any(feature = "nip04", feature = "nip44"))]
impl From<neco_sha2::HkdfError> for SecpError {
    fn from(value: neco_sha2::HkdfError) -> Self {
        Self::Hkdf(value)
    }
}

#[cfg(feature = "nostr")]
impl From<crate::EventJsonError> for SecpError {
    fn from(value: crate::EventJsonError) -> Self {
        Self::Json(value)
    }
}
