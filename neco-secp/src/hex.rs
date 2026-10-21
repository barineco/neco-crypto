#[cfg(feature = "alloc")]
use crate::SecpError;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
pub fn hex_encode(bytes: &[u8]) -> Result<String, SecpError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let required = bytes
        .len()
        .checked_mul(2)
        .filter(|required| *required <= isize::MAX as usize)
        .ok_or(SecpError::CapacityOverflow {
            input_len: bytes.len(),
        })?;
    let mut encoded = String::new();
    encoded
        .try_reserve_exact(required)
        .map_err(|_| SecpError::AllocationFailed { required })?;
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(encoded)
}

#[cfg(feature = "alloc")]
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, SecpError> {
    let hex = hex.as_bytes();
    if hex.len() % 2 != 0 {
        return Err(SecpError::InvalidHex("odd length"));
    }

    let required = hex.len() / 2;
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(required)
        .map_err(|_| SecpError::AllocationFailed { required })?;
    for chunk in hex.chunks_exact(2) {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

#[cfg(feature = "alloc")]
fn hex_nibble(byte: u8) -> Result<u8, SecpError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(SecpError::InvalidHex("invalid character")),
    }
}
