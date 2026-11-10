//! `zinkhole secret`: a new Sync secret (ADR-0003).

use crate::config::Secret;

/// 256 random bits from the operating system, as 64 hex digits.
///
/// # Errors
/// When the operating system cannot provide random bytes.
pub fn generate() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; Secret::LEN];
    getrandom::fill(&mut bytes)?;
    Ok(crate::hex::encode(&bytes))
}

#[cfg(test)]
mod tests {
    #[test]
    fn secrets_are_64_hex_digits_and_differ() {
        let a = super::generate().unwrap();
        let b = super::generate().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
