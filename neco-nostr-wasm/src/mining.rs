use crate::types::{js_error, public_key_json, PublicKeyFields};
use core::fmt::{self, Write};
use neco_json::JsonString;
use neco_secp::SecpError;
use wasm_bindgen::prelude::*;

fn write_public(output: &mut dyn Write, fields: &PublicKeyFields) -> fmt::Result {
    output.write_char('{')?;
    fields.write_fields(output)?;
    output.write_char('}')
}

fn write_secret_fields(
    output: &mut dyn Write,
    fields: &PublicKeyFields,
    secret: &str,
) -> fmt::Result {
    fields.write_fields(output)?;
    write!(output, ",\"secret_hex\":{}", JsonString::new(secret))
}

fn vector<T>(required: usize) -> Result<Vec<T>, JsValue> {
    let bytes = required
        .checked_mul(core::mem::size_of::<T>())
        .ok_or_else(|| {
            js_error(SecpError::CapacityOverflow {
                input_len: required,
            })
        })?;
    if bytes > isize::MAX as usize {
        return Err(js_error(SecpError::CapacityOverflow {
            input_len: required,
        }));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(required)
        .map_err(|_| js_error(SecpError::AllocationFailed { required }))?;
    Ok(output)
}

#[wasm_bindgen]
pub fn generate_keypair() -> Result<String, JsValue> {
    let bundle = neco_secp::KeyBundle::generate().map_err(js_error)?;
    let fields = public_key_json(bundle.secret())?;
    crate::json::encode(|output| write_public(output, &fields)).map_err(js_error)
}

#[wasm_bindgen]
pub fn generate_keypairs_batch(count: u32) -> Result<String, JsValue> {
    let bundles = neco_secp::KeyBundle::generate_batch(count as usize).map_err(js_error)?;
    let mut items = vector(bundles.len())?;
    for bundle in &bundles {
        items.push(public_key_json(bundle.secret())?);
    }
    crate::json::encode(|output| {
        output.write_char('[')?;
        for (index, fields) in items.iter().enumerate() {
            if index != 0 {
                output.write_char(',')?;
            }
            write_public(output, fields)?;
        }
        output.write_char(']')
    })
    .map_err(js_error)
}

#[wasm_bindgen]
pub fn mine_pow_batch(difficulty: u8, max_attempts: u32) -> Result<String, JsValue> {
    let (bundle, actual_difficulty) =
        neco_secp::mine_pow_best(difficulty, max_attempts.into()).map_err(js_error)?;
    let fields = public_key_json(bundle.secret())?;
    crate::json::encode(|output| {
        write!(output, "{{\"difficulty\":{actual_difficulty},")?;
        fields.write_fields(output)?;
        output.write_char('}')
    })
    .map_err(js_error)
}

#[wasm_bindgen]
pub fn mine_vanity_batch(prefix: &str, max_attempts: u32) -> Result<String, JsValue> {
    let bundle = neco_secp::mine_vanity_npub(prefix, max_attempts.into()).map_err(js_error)?;
    let fields = public_key_json(bundle.secret())?;
    let secret = bundle.secret().to_hex().map_err(js_error)?;
    crate::json::encode(|output| {
        output.write_char('{')?;
        write_secret_fields(output, &fields, &secret)?;
        output.write_char('}')
    })
    .map_err(js_error)
}

#[wasm_bindgen]
pub fn mine_vanity_with_candidates(
    prefix: &str,
    max_attempts: u32,
    top_k: u32,
) -> Result<String, JsValue> {
    let candidates =
        neco_secp::mine_vanity_npub_candidates(prefix, max_attempts.into(), top_k as usize)
            .map_err(js_error)?;
    let mut items = vector(candidates.len())?;
    for candidate in &candidates {
        items.push((
            public_key_json(candidate.bundle().secret())?,
            candidate.bundle().secret().to_hex().map_err(js_error)?,
            candidate.matched_len(),
        ));
    }
    crate::json::encode(|output| {
        output.write_char('[')?;
        for (index, (fields, secret, matched_len)) in items.iter().enumerate() {
            if index != 0 {
                output.write_char(',')?;
            }
            write!(output, "{{\"matched_len\":{matched_len},")?;
            write_secret_fields(output, fields, secret)?;
            output.write_char('}')?;
        }
        output.write_char(']')
    })
    .map_err(js_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neco_json::JsonValue as Value;

    #[test]
    fn generate_keypair_hides_secret() {
        let json = generate_keypair().expect("generate");
        let value: Value = neco_json::parse(json.as_bytes()).expect("json");
        assert!(value.get("secret_hex").is_none());
        assert!(value.get("pubkey_hex").is_some());
    }

    #[test]
    fn vanity_result_exposes_secret_hex() {
        let json = mine_vanity_batch("", 1).expect("mine vanity");
        let value: Value = neco_json::parse(json.as_bytes()).expect("json");
        assert!(value.get("secret_hex").is_some());
    }

    #[test]
    fn pow_result_hides_secret_and_reports_difficulty() {
        let json = mine_pow_batch(0, 1).expect("mine pow");
        let value: Value = neco_json::parse(json.as_bytes()).expect("json");
        assert!(value.get("secret_hex").is_none());
        assert!(value.get("pubkey_hex").is_some());
        assert!(value.get("difficulty").is_some());
    }

    #[test]
    fn vanity_candidates_include_matched_len_and_secret_hex() {
        let json = mine_vanity_with_candidates("q", 10_000, 3).expect("candidates");
        let value: Value = neco_json::parse(json.as_bytes()).expect("json");
        let items = value.as_array().expect("array");
        assert!(!items.is_empty());
        assert!(items[0].get("secret_hex").is_some());
        assert!(items[0].get("matched_len").is_some());
        assert!(items.len() <= 3);
    }
}
