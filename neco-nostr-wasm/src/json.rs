use core::fmt::{self, Write};
use wasm_bindgen::JsValue;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OutputError {
    CapacityOverflow { written: usize, additional: usize },
    AllocationFailed { required: usize },
    Formatting,
}

impl fmt::Display for OutputError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityOverflow { written, additional } => write!(
                output,
                "JSON output capacity exceeded after {written} bytes with {additional} additional bytes"
            ),
            Self::AllocationFailed { required } => {
                write!(output, "JSON output allocation failed for {required} bytes")
            }
            Self::Formatting => output.write_str("JSON output formatting failed"),
        }
    }
}

impl core::error::Error for OutputError {}

enum ByteCount {
    Length(usize),
    Overflow { written: usize, additional: usize },
}

impl Write for ByteCount {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let Self::Length(written) = *self else {
            return Err(fmt::Error);
        };
        match written
            .checked_add(value.len())
            .filter(|&length| length <= isize::MAX as usize)
        {
            Some(length) => {
                *self = Self::Length(length);
                Ok(())
            }
            None => {
                *self = Self::Overflow {
                    written,
                    additional: value.len(),
                };
                Err(fmt::Error)
            }
        }
    }
}

struct ReservedText {
    text: String,
    limit: usize,
}

impl Write for ReservedText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.text.len().checked_add(value.len()).ok_or(fmt::Error)?;
        if end > self.limit || end > self.text.capacity() {
            return Err(fmt::Error);
        }
        self.text.push_str(value);
        Ok(())
    }
}

pub(crate) fn encode<F>(write_value: F) -> Result<String, OutputError>
where
    F: Fn(&mut dyn Write) -> fmt::Result,
{
    let mut count = ByteCount::Length(0);
    let counted = write_value(&mut count);
    let required = match count {
        ByteCount::Overflow {
            written,
            additional,
        } => {
            return Err(OutputError::CapacityOverflow {
                written,
                additional,
            });
        }
        ByteCount::Length(length) => length,
    };
    counted.map_err(|_| OutputError::Formatting)?;
    let mut text = String::new();
    text.try_reserve_exact(required)
        .map_err(|_| OutputError::AllocationFailed { required })?;
    let mut output = ReservedText {
        text,
        limit: required,
    };
    write_value(&mut output).map_err(|_| OutputError::Formatting)?;
    Ok(output.text)
}

pub(crate) fn write_strings<T: AsRef<str>>(output: &mut dyn Write, values: &[T]) -> fmt::Result {
    output.write_char('[')?;
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.write_char(',')?;
        }
        write!(output, "{}", neco_json::JsonString::new(value.as_ref()))?;
    }
    output.write_char(']')
}

struct ErrorText {
    bytes: [u8; 512],
    length: usize,
}

impl ErrorText {
    fn new() -> Self {
        Self {
            bytes: [0; 512],
            length: 0,
        }
    }

    fn as_str(&self) -> Result<&str, core::str::Utf8Error> {
        core::str::from_utf8(&self.bytes[..self.length])
    }
}

impl Write for ErrorText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.length.checked_add(value.len()).ok_or(fmt::Error)?;
        let destination = self.bytes.get_mut(self.length..end).ok_or(fmt::Error)?;
        destination.copy_from_slice(value.as_bytes());
        self.length = end;
        Ok(())
    }
}

pub(crate) fn js_error<E: fmt::Display>(error: E) -> JsValue {
    let mut output = ErrorText::new();
    if write!(&mut output, "{error}").is_err() {
        return JsValue::from_str("error message could not be formatted in 512 bytes");
    }
    match output.as_str() {
        Ok(text) => JsValue::from_str(text),
        Err(_) => JsValue::from_str("error message contains invalid UTF-8"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn output_uses_the_shared_escaping_and_exact_reserved_length() {
        let value = "\u{001f} é😀\"/";
        let output =
            encode(|sink| write!(sink, "[{}]", neco_json::JsonString::new(value))).expect("encode");
        assert_eq!(output, "[\"\\u001f é😀\\\"/\"]");
    }

    #[test]
    fn output_capacity_overflow_preserves_both_operands() {
        let mut count = ByteCount::Length(isize::MAX as usize);
        assert!(count.write_str("x").is_err());
        assert!(matches!(
            count,
            ByteCount::Overflow { written, additional: 1 } if written == isize::MAX as usize
        ));
    }

    #[test]
    fn output_propagates_formatter_failure() {
        assert_eq!(encode(|_| Err(fmt::Error)), Err(OutputError::Formatting));
    }

    #[test]
    fn output_rejects_growth_beyond_the_counted_limit() {
        let calls = Cell::new(0);
        let output = encode(|sink| {
            let call = calls.get();
            calls.set(call + 1);
            sink.write_str(if call == 0 { "a" } else { "longer" })
        });
        assert_eq!(output, Err(OutputError::Formatting));
    }

    #[test]
    fn error_text_uses_a_bounded_utf8_stack_buffer() {
        let mut text = ErrorText::new();
        write!(&mut text, "allocation failed for {} bytes: é😀", usize::MAX).expect("format");
        assert!(text.as_str().expect("UTF-8").ends_with("é😀"));
        let full = "x".repeat(512);
        let mut text = ErrorText::new();
        text.write_str(&full).expect("exact limit");
        assert!(text.write_str("x").is_err());
        assert_eq!(text.as_str().expect("UTF-8"), full);
    }
}
