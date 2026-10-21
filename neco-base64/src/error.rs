#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base64Error {
    InvalidCharacter,
    InvalidLength,
    NonZeroPaddingBits,
    CapacityOverflow { input_len: usize },
    AllocationFailed { required: usize },
}

impl core::fmt::Display for Base64Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidCharacter => f.write_str("invalid base64 character"),
            Self::InvalidLength => f.write_str("invalid base64 input length"),
            Self::NonZeroPaddingBits => f.write_str("non-zero padding bits"),
            Self::CapacityOverflow { input_len } => write!(
                f,
                "base64 output capacity exceeds the addressable range for input length {input_len}"
            ),
            Self::AllocationFailed { required } => {
                write!(f, "base64 allocation failed for {required} bytes")
            }
        }
    }
}

impl core::error::Error for Base64Error {}
