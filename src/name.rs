//! Domain names as the Policy compares them: lowercase ASCII, without the
//! trailing dot.

/// The longest name DNS allows, without the trailing dot.
pub const MAX_LEN: usize = 253;

/// `text` lowercased and without a trailing dot, if it is a valid name:
/// labels of 1 to 63 letters, digits, hyphens or underscores (lists contain
/// names like `_dmarc.example.com`), at most [`MAX_LEN`] characters in all.
#[must_use]
pub fn normalize(text: &str) -> Option<String> {
    let name = text.strip_suffix('.').unwrap_or(text);
    if name.is_empty() || name.len() > MAX_LEN {
        return None;
    }
    let valid_labels = name.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    valid_labels.then(|| name.to_ascii_lowercase())
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
