//! Lowercase hex, for secrets and fingerprints.

use std::fmt::Write as _;

/// `bytes` as lowercase hex digits.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            // Writing to a String cannot fail.
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The text is not exactly the expected number of hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("expected {expected} hex digits")]
pub struct InvalidHex {
    pub expected: usize,
}

/// Fills `out` from exactly `2 * out.len()` hex digits (either case).
///
/// # Errors
/// When `text` has another length or a character that is not a hex digit.
pub fn decode_into(text: &str, out: &mut [u8]) -> Result<(), InvalidHex> {
    let invalid = InvalidHex {
        expected: out.len() * 2,
    };
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if pairs.len() != out.len() || !rest.is_empty() {
        return Err(invalid);
    }
    for (byte, [high, low]) in out.iter_mut().zip(pairs) {
        *byte = (digit(*high).ok_or(invalid)? << 4) | digit(*low).ok_or(invalid)?;
    }
    Ok(())
}

fn digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_bad_input() {
        let bytes = [0x00, 0x7f, 0xab, 0xff];
        let text = encode(&bytes);
        assert_eq!(text, "007fabff");
        let mut back = [0u8; 4];
        decode_into("007FabFF", &mut back).unwrap();
        assert_eq!(back, bytes);
        assert!(decode_into("007fab", &mut back).is_err());
        assert!(decode_into("007fabfg", &mut back).is_err());
    }
}
