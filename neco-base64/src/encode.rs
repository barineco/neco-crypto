use crate::Base64Error;
use alloc::string::String;

const STANDARD_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encoded_length(input_len: usize, pad: bool) -> Result<usize, Base64Error> {
    let full = (input_len / 3)
        .checked_mul(4)
        .ok_or(Base64Error::CapacityOverflow { input_len })?;
    let tail = match input_len % 3 {
        0 => 0,
        rem if pad => {
            let _ = rem;
            4
        }
        rem => rem + 1,
    };
    let required = full
        .checked_add(tail)
        .ok_or(Base64Error::CapacityOverflow { input_len })?;
    if required > isize::MAX as usize {
        return Err(Base64Error::CapacityOverflow { input_len });
    }
    Ok(required)
}

fn encode_with_table(input: &[u8], table: &[u8; 64], pad: bool) -> Result<String, Base64Error> {
    let required = encoded_length(input.len(), pad)?;
    let mut output = String::new();
    output
        .try_reserve_exact(required)
        .map_err(|_| Base64Error::AllocationFailed { required })?;
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let block = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        for shift in [18, 12, 6, 0] {
            output.push(char::from(table[((block >> shift) & 0x3f) as usize]));
        }
    }
    match chunks.remainder() {
        [a] => {
            let block = u32::from(*a) << 16;
            output.push(char::from(table[((block >> 18) & 0x3f) as usize]));
            output.push(char::from(table[((block >> 12) & 0x3f) as usize]));
            if pad {
                output.push_str("==");
            }
        }
        [a, b] => {
            let block = (u32::from(*a) << 16) | (u32::from(*b) << 8);
            output.push(char::from(table[((block >> 18) & 0x3f) as usize]));
            output.push(char::from(table[((block >> 12) & 0x3f) as usize]));
            output.push(char::from(table[((block >> 6) & 0x3f) as usize]));
            if pad {
                output.push('=');
            }
        }
        _ => {}
    }
    Ok(output)
}

pub fn encode(input: &[u8]) -> Result<String, Base64Error> {
    encode_with_table(input, STANDARD_TABLE, true)
}

pub fn encode_url(input: &[u8]) -> Result<String, Base64Error> {
    encode_with_table(input, URL_TABLE, false)
}

pub fn encode_url_padded(input: &[u8]) -> Result<String, Base64Error> {
    encode_with_table(input, URL_TABLE, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacity_overflow_is_reported_before_allocation() {
        for pad in [false, true] {
            assert_eq!(
                encoded_length(usize::MAX, pad),
                Err(Base64Error::CapacityOverflow {
                    input_len: usize::MAX
                })
            );
            assert_eq!(
                encoded_length(isize::MAX as usize, pad),
                Err(Base64Error::CapacityOverflow {
                    input_len: isize::MAX as usize
                })
            );
        }
    }
    #[test]
    fn exact_output_lengths_cover_partial_blocks() {
        for (input_len, padded, unpadded) in [
            (0, 0, 0),
            (1, 4, 2),
            (2, 4, 3),
            (3, 4, 4),
            (4, 8, 6),
            (5, 8, 7),
        ] {
            assert_eq!(encoded_length(input_len, true).unwrap(), padded);
            assert_eq!(encoded_length(input_len, false).unwrap(), unpadded);
        }
    }
}
