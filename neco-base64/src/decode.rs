use crate::Base64Error;
use alloc::vec::Vec;

fn standard_value(byte: u8) -> Result<u8, Base64Error> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(Base64Error::InvalidCharacter),
    }
}

fn url_value(byte: u8) -> Result<u8, Base64Error> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(Base64Error::InvalidCharacter),
    }
}

fn decoded_length(input_len: usize) -> Result<usize, Base64Error> {
    let tail = match input_len % 4 {
        0 => 0,
        2 => 1,
        3 => 2,
        _ => return Err(Base64Error::InvalidLength),
    };
    let required = (input_len / 4)
        .checked_mul(3)
        .and_then(|n| n.checked_add(tail))
        .ok_or(Base64Error::CapacityOverflow { input_len })?;
    if required > isize::MAX as usize {
        return Err(Base64Error::CapacityOverflow { input_len });
    }
    Ok(required)
}

fn decode_with_alphabet(
    input: &str,
    value_fn: fn(u8) -> Result<u8, Base64Error>,
) -> Result<Vec<u8>, Base64Error> {
    let unpadded = input.trim_end_matches('=');
    if unpadded.bytes().any(|b| b == b'=') {
        return Err(Base64Error::InvalidCharacter);
    }
    let required = decoded_length(unpadded.len())?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(required)
        .map_err(|_| Base64Error::AllocationFailed { required })?;
    let mut chunks = unpadded.as_bytes().chunks_exact(4);
    for chunk in &mut chunks {
        let a = value_fn(chunk[0])?;
        let b = value_fn(chunk[1])?;
        let c = value_fn(chunk[2])?;
        let d = value_fn(chunk[3])?;
        output.push((a << 2) | (b >> 4));
        output.push(((b & 0x0f) << 4) | (c >> 2));
        output.push(((c & 0x03) << 6) | d);
    }
    match chunks.remainder() {
        [] => {}
        [a, b] => {
            let a = value_fn(*a)?;
            let b = value_fn(*b)?;
            output.push((a << 2) | (b >> 4));
        }
        [a, b, c] => {
            let a = value_fn(*a)?;
            let b = value_fn(*b)?;
            let c = value_fn(*c)?;
            output.push((a << 2) | (b >> 4));
            output.push(((b & 0x0f) << 4) | (c >> 2));
        }
        _ => return Err(Base64Error::InvalidLength),
    }
    Ok(output)
}

pub fn decode(input: &str) -> Result<Vec<u8>, Base64Error> {
    decode_with_alphabet(input, standard_value)
}

pub fn decode_url(input: &str) -> Result<Vec<u8>, Base64Error> {
    decode_with_alphabet(input, url_value)
}

pub fn decode_url_strict(input: &str) -> Result<Vec<u8>, Base64Error> {
    if input.contains('=') {
        return Err(Base64Error::InvalidCharacter);
    }
    let remainder = input.len() % 4;
    if remainder == 1 {
        return Err(Base64Error::InvalidLength);
    }
    if remainder > 0 {
        let last = *input.as_bytes().last().ok_or(Base64Error::InvalidLength)?;
        let val = url_value(last)?;
        let padding_bits = match remainder {
            2 => 4,
            3 => 2,
            _ => 0,
        };
        let mask = (1u8 << padding_bits) - 1;
        if val & mask != 0 {
            return Err(Base64Error::NonZeroPaddingBits);
        }
    }
    decode_with_alphabet(input, url_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decoded_capacity_is_checked_without_input_storage() {
        assert_eq!(
            decoded_length(usize::MAX),
            Err(Base64Error::CapacityOverflow {
                input_len: usize::MAX
            })
        );
        for (input, output) in [(0, 0), (2, 1), (3, 2), (4, 3), (6, 4), (7, 5), (8, 6)] {
            assert_eq!(decoded_length(input).unwrap(), output);
        }
    }
}
