//! Domain names as the Policy compares them: lowercase ASCII, without the
//! trailing dot.

/// The longest name DNS allows, without the trailing dot.
pub const MAX_LEN: usize = 253;
/// The longest label DNS allows.
pub const MAX_LABEL_LEN: usize = 63;

/// `text` lowercased and without a trailing dot, if it is a valid name:
/// labels of 1 to [`MAX_LABEL_LEN`] letters, digits, hyphens or underscores
/// (lists contain names like `_dmarc.example.com`), at most [`MAX_LEN`]
/// characters in all.
#[must_use]
pub fn normalize(text: &str) -> Option<String> {
    let name = without_dot(text);
    check(name).is_ok().then(|| name.to_ascii_lowercase())
}

/// `text` lowercased and without a trailing dot, not checked: the form
/// [`check`] and [`check_hostname`] take.
#[must_use]
pub fn lowercase(text: &str) -> String {
    without_dot(text).to_ascii_lowercase()
}

/// Checks that `name` (no trailing dot) is a valid name, by the rules of
/// [`normalize`].
///
/// # Errors
///
/// What is wrong with the name.
pub fn check(name: &str) -> Result<(), String> {
    check_lengths(name)?;
    let valid = |byte| is_hostname_byte(byte) || byte == b'_';
    if !name.split('.').all(|label| label.bytes().all(valid)) {
        return Err("only letters, digits, hyphens, underscores and dots".to_owned());
    }
    Ok(())
}

/// Checks that `name` (no trailing dot) is a hostname. Stricter than
/// [`check`], which takes what lists and zones hold: a hostname has no
/// underscores, and no hyphen at either end of a label.
///
/// # Errors
///
/// What is wrong with the name.
pub fn check_hostname(name: &str) -> Result<(), String> {
    check_lengths(name)?;
    for label in name.split('.') {
        if label.starts_with('-') || label.ends_with('-') {
            return Err("a label may not start or end with a hyphen".to_owned());
        }
        if !label.bytes().all(is_hostname_byte) {
            return Err("only letters, digits, hyphens and dots".to_owned());
        }
    }
    Ok(())
}

/// The lengths every name keeps to: its own, and each label's.
fn check_lengths(name: &str) -> Result<(), String> {
    if name.len() > MAX_LEN {
        return Err(format!("longer than {MAX_LEN} characters"));
    }
    if name
        .split('.')
        .any(|label| !(1..=MAX_LABEL_LEN).contains(&label.len()))
    {
        return Err(format!("each label needs 1 to {MAX_LABEL_LEN} characters"));
    }
    Ok(())
}

fn without_dot(text: &str) -> &str {
    text.strip_suffix('.').unwrap_or(text)
}

/// A letter, a digit or a hyphen: what every label may hold.
fn is_hostname_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

/// True if `name` equals `zone` or is below it (`a.b.lan` is below `lan`).
#[must_use]
pub fn is_at_or_below(name: &str, zone: &str) -> bool {
    match name.strip_suffix(zone) {
        Some("") => true,
        Some(rest) => rest.ends_with('.'),
        None => false,
    }
}

/// The names above `name`, nearest first: `a.b.lan` gives `b.lan`, `lan`.
pub fn parents(name: &str) -> impl Iterator<Item = &str> {
    name.match_indices('.')
        .filter_map(|(dot, _)| name.get(dot + 1..))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_lowercases_and_rejects_invalid_names() {
        assert_eq!(
            normalize("Ads.Example.COM.").as_deref(),
            Some("ads.example.com")
        );
        assert_eq!(
            normalize("_dmarc.example.com").as_deref(),
            Some("_dmarc.example.com")
        );
        for bad in [
            "",
            ".",
            "a..b",
            ".a",
            "a b",
            "ads.example.com##.ad",
            "ex!ample.com",
            "über.de",
        ] {
            assert_eq!(normalize(bad), None, "{bad}");
        }
        assert_eq!(normalize(&"a".repeat(64)), None);
        assert!(normalize(&"a".repeat(63)).is_some());
        let long = vec!["a".repeat(63); 4].join(".");
        assert_eq!(normalize(&long), None);
    }

    #[test]
    fn a_hostname_is_stricter_than_a_name() {
        for good in ["nas.lan", "a-b.example.com", "1.168.192.in-addr.arpa", "x"] {
            assert_eq!(check_hostname(good), Ok(()), "{good}");
            assert!(normalize(good).is_some(), "a hostname is a name: {good}");
        }
        for (bad, why) in [
            ("_dmarc.example.com", "only letters"),
            ("-a.lan", "hyphen"),
            ("a-.lan", "hyphen"),
            ("a..lan", "each label"),
            ("", "each label"),
        ] {
            let error = check_hostname(bad).unwrap_err();
            assert!(error.contains(why), "{bad}: {error}");
        }
        // The limits are the ones every name has.
        let label = "a".repeat(MAX_LABEL_LEN);
        assert_eq!(check_hostname(&label), Ok(()));
        assert!(check_hostname(&format!("{label}a")).is_err());
        let longest = vec!["a".repeat(MAX_LABEL_LEN); 4].join(".");
        assert!(longest.len() > MAX_LEN);
        assert!(check_hostname(&longest).unwrap_err().contains("253"));
        assert_eq!(lowercase("NAS.Lan."), "nas.lan");
    }

    #[test]
    fn a_name_may_have_what_a_hostname_may_not() {
        for name in ["_msdcs.corp.lan", "_dmarc.example.com", "-a.lan", "a-.lan"] {
            assert_eq!(check(name), Ok(()), "{name}");
            assert!(check_hostname(name).is_err(), "{name}");
        }
        for (bad, why) in [
            ("a b.lan", "only letters"),
            ("ex!ample.com", "only letters"),
            ("a..lan", "each label"),
            ("", "each label"),
        ] {
            assert!(check(bad).unwrap_err().contains(why), "{bad}");
        }
    }

    #[test]
    fn at_or_below_matches_whole_labels() {
        assert!(is_at_or_below("lan", "lan"));
        assert!(is_at_or_below("nas.lan", "lan"));
        assert!(!is_at_or_below("plan", "lan"));
        assert!(!is_at_or_below("lan", "nas.lan"));
    }

    #[test]
    fn parents_go_up_one_label_at_a_time() {
        assert_eq!(parents("a.b.lan").collect::<Vec<_>>(), ["b.lan", "lan"]);
        assert_eq!(parents("lan").count(), 0);
    }
}
