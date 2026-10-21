use crate::SecpError;
#[cfg(any(feature = "nostr", feature = "nip04"))]
use alloc::string::String;
use alloc::vec::Vec;

pub(crate) fn vector<T>(required: usize) -> Result<Vec<T>, SecpError> {
    let bytes =
        required
            .checked_mul(core::mem::size_of::<T>())
            .ok_or(SecpError::CapacityOverflow {
                input_len: required,
            })?;
    if bytes > isize::MAX as usize {
        return Err(SecpError::CapacityOverflow {
            input_len: required,
        });
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(required)
        .map_err(|_| SecpError::AllocationFailed { required })?;
    Ok(result)
}

#[cfg(any(feature = "nostr", feature = "nip04"))]
pub(crate) fn string(required: usize) -> Result<String, SecpError> {
    if required > isize::MAX as usize {
        return Err(SecpError::CapacityOverflow {
            input_len: required,
        });
    }
    let mut result = String::new();
    result
        .try_reserve_exact(required)
        .map_err(|_| SecpError::AllocationFailed { required })?;
    Ok(result)
}

#[cfg(feature = "nostr")]
pub(crate) fn text(value: &str) -> Result<String, SecpError> {
    let mut result = string(value.len())?;
    result.push_str(value);
    Ok(result)
}
