//! Local DNS: hostnames for the network's own devices (`nas.lan`), reverse
//! (PTR) lookups for them, and the Private names that must never be sent to
//! public upstream servers.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use crate::config;
use crate::domain_set::DomainSet;
use crate::name;
use crate::rules::Matching;

/// The local records, ready for lookups.
#[derive(Debug)]
pub struct LocalZone {
    exact: HashMap<Box<str>, Arc<[IpAddr]>>,
    /// Keyed by the name after `*.`.
    wildcards: HashMap<Box<str>, Arc<[IpAddr]>>,
    /// Address → the first name configured for it.
    reverse: HashMap<IpAddr, Arc<str>>,
    private: DomainSet,
}

impl LocalZone {
    /// The zone for `records`, in file order, plus `localhost` (RFC 6761)
    /// unless a record overrides it.
    #[must_use]
    pub fn new(records: &indexmap::IndexMap<config::RecordName, config::Addresses>) -> LocalZone {
        let mut zone = LocalZone {
            exact: HashMap::new(),
            wildcards: HashMap::new(),
            reverse: HashMap::new(),
            private: DomainSet::new(),
        };
        for (name, addresses) in records {
            let addresses: Arc<[IpAddr]> = addresses.0.as_slice().into();
            if let Some(below) = name.as_str().strip_prefix("*.") {
                zone.wildcards.insert(below.into(), addresses);
                continue;
            }
            let host: Arc<str> = name.as_str().into();
            for ip in addresses.iter() {
                zone.reverse.entry(*ip).or_insert_with(|| Arc::clone(&host));
            }
            zone.exact.insert(name.as_str().into(), addresses);
        }

        let loopback: Arc<[IpAddr]> = [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]
        .into();
        zone.exact
            .entry("localhost".into())
            .or_insert_with(|| Arc::clone(&loopback));
        zone.wildcards
            .entry("localhost".into())
            .or_insert_with(|| Arc::clone(&loopback));
        let localhost: Arc<str> = "localhost".into();
        for ip in loopback.iter() {
            zone.reverse
                .entry(*ip)
                .or_insert_with(|| Arc::clone(&localhost));
        }

        for private_zone in private_zones() {
            zone.private
                .insert(&private_zone, Matching::DomainAndSubdomains);
        }
        zone
    }

    /// The addresses for `name` (normalized): an exact record, else the most
    /// specific wildcard above it.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<Arc<[IpAddr]>> {
        if let Some(addresses) = self.exact.get(name) {
            return Some(Arc::clone(addresses));
        }
        name::parents(name).find_map(|parent| self.wildcards.get(parent).map(Arc::clone))
    }

    /// The hostname for a reverse lookup name like `10.1.168.192.in-addr.arpa`.
    #[must_use]
    pub fn reverse_lookup(&self, name: &str) -> Option<Arc<str>> {
        parse_reverse_name(name).and_then(|ip| self.reverse.get(&ip).map(Arc::clone))
    }

    /// True for single-label names and names in private or special-use zones.
    #[must_use]
    pub fn is_private(&self, name: &str) -> bool {
        !name.is_empty() && (!name.contains('.') || self.private.matches(name))
    }
}

/// Zones that never resolve on the public internet. A query for one that no
/// local record answers gets NXDOMAIN instead of leaking upstream.
fn private_zones() -> impl Iterator<Item = String> {
    const ZONES: &[&str] = &[
        // Special-use and private-use names (RFC 6761, RFC 6762 appendix G,
        // RFC 7686, RFC 8375, ICANN's .internal).
        "local",
        "lan",
        "home",
        "internal",
        "intranet",
        "private",
        "corp",
        "localdomain",
        "home.arpa",
        "test",
        "invalid",
        "onion",
        // Reverse zones for private and special-purpose ranges (RFC 6303).
        "0.in-addr.arpa",
        "10.in-addr.arpa",
        "127.in-addr.arpa",
        "254.169.in-addr.arpa",
        "168.192.in-addr.arpa",
        "d.f.ip6.arpa", // fc00::/7
        "c.f.ip6.arpa",
        "8.e.f.ip6.arpa", // fe80::/10
        "9.e.f.ip6.arpa",
        "a.e.f.ip6.arpa",
        "b.e.f.ip6.arpa",
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", // ::
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", // ::1
    ];
    let named = ZONES.iter().copied().map(str::to_owned);
    // 172.16.0.0/12, and 100.64.0.0/10 (carrier-grade NAT, Tailscale).
    let rfc1918 = (16..=31).map(|second| format!("{second}.172.in-addr.arpa"));
    let cgnat = (64..=127).map(|second| format!("{second}.100.in-addr.arpa"));
    named.chain(rfc1918).chain(cgnat)
}

/// The address of `4.3.2.1.in-addr.arpa` or of a complete 32-nibble
/// `ip6.arpa` name.
#[must_use]
pub fn parse_reverse_name(name: &str) -> Option<IpAddr> {
    if let Some(octets) = name.strip_suffix(".in-addr.arpa") {
        let mut bytes = [0u8; 4];
        let mut labels = octets.split('.');
        for byte in bytes.iter_mut().rev() {
            *byte = parse_octet(labels.next()?)?;
        }
        return labels
            .next()
            .is_none()
            .then_some(IpAddr::V4(Ipv4Addr::from(bytes)));
    }
    let nibbles = name.strip_suffix(".ip6.arpa")?;
    let mut value: u128 = 0;
    let mut count = 0;
    // The first label is the lowest nibble.
    for (position, label) in nibbles.split('.').enumerate() {
        if position == 32 {
            return None; // more nibbles than an IPv6 address has
        }
        let [digit] = label.as_bytes() else {
            return None;
        };
        let nibble = char::from(*digit).to_digit(16)?;
        value |= u128::from(nibble) << (4 * position);
        count += 1;
    }
    (count == 32).then_some(IpAddr::V6(Ipv6Addr::from(value)))
}

/// A decimal 0-255 without sign or leading zeros.
fn parse_octet(text: &str) -> Option<u8> {
    let canonical =
        !text.is_empty() && text.len() <= 3 && !(text.len() > 1 && text.starts_with('0'));
    if !canonical || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(toml: &str) -> LocalZone {
        let local: config::Local = toml::from_str(toml).unwrap();
        LocalZone::new(&local.records)
    }

    fn ips(addresses: &[&str]) -> Vec<IpAddr> {
        addresses.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn exact_records_win_over_wildcards_and_the_most_specific_wildcard_wins() {
        let zone = zone(
            r#"[records]
"nas.lan" = ["192.168.1.10", "fd00::10"]
"*.apps.lan" = "192.168.1.20"
"*.lan" = "192.168.1.30"
"special.apps.lan" = "192.168.1.40"
"#,
        );
        assert_eq!(
            zone.lookup("nas.lan").unwrap().to_vec(),
            ips(&["192.168.1.10", "fd00::10"])
        );
        assert_eq!(
            zone.lookup("a.b.apps.lan").unwrap().to_vec(),
            ips(&["192.168.1.20"])
        );
        assert_eq!(
            zone.lookup("special.apps.lan").unwrap().to_vec(),
            ips(&["192.168.1.40"])
        );
        assert_eq!(
            zone.lookup("printer.lan").unwrap().to_vec(),
            ips(&["192.168.1.30"])
        );
        // A wildcard does not match its own name.
        assert_eq!(
            zone.lookup("apps.lan").unwrap().to_vec(),
            ips(&["192.168.1.30"])
        );
        assert!(zone.lookup("lan").is_none());
        assert!(zone.lookup("example.com").is_none());
    }

    #[test]
    fn localhost_is_built_in_but_can_be_overridden() {
        let default = zone("");
        assert_eq!(
            default.lookup("localhost").unwrap().to_vec(),
            ips(&["127.0.0.1", "::1"])
        );
        assert_eq!(
            default.lookup("a.localhost").unwrap().to_vec(),
            ips(&["127.0.0.1", "::1"])
        );
        assert_eq!(
            default.reverse_lookup("1.0.0.127.in-addr.arpa").as_deref(),
            Some("localhost")
        );

        let overridden = zone("[records]\n\"localhost\" = \"10.0.0.1\"\n");
        assert_eq!(
            overridden.lookup("localhost").unwrap().to_vec(),
            ips(&["10.0.0.1"])
        );
    }

    #[test]
    fn reverse_lookups_answer_the_first_name_in_the_file() {
        let zone = zone(
            "[records]\n\"nas.lan\" = [\"192.168.1.10\", \"fd00::10\"]\n\"media.lan\" = \"192.168.1.10\"\n",
        );
        assert_eq!(
            zone.reverse_lookup("10.1.168.192.in-addr.arpa").as_deref(),
            Some("nas.lan")
        );
        let v6 = "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa";
        assert_eq!(zone.reverse_lookup(v6).as_deref(), Some("nas.lan"));
        assert!(zone.reverse_lookup("11.1.168.192.in-addr.arpa").is_none());
    }

    #[test]
    fn reverse_names_parse_strictly() {
        assert_eq!(
            parse_reverse_name("10.1.168.192.in-addr.arpa"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)))
        );
        for bad in [
            "1.168.192.in-addr.arpa",
            "010.1.168.192.in-addr.arpa",
            "256.1.168.192.in-addr.arpa",
            "1.10.1.168.192.in-addr.arpa",
            "+1.1.168.192.in-addr.arpa",
            "8.b.d.0.1.0.0.2.ip6.arpa",
            "example.com",
        ] {
            assert_eq!(parse_reverse_name(bad), None, "{bad}");
        }
        let v6 = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
        assert_eq!(parse_reverse_name(v6), Some("2001:db8::1".parse().unwrap()));
        let too_long = format!("0.{v6}");
        assert_eq!(parse_reverse_name(&too_long), None);
    }

    #[test]
    fn private_names() {
        let zone = zone("");
        for private in [
            "printer",
            "nas.lan",
            "x.home.arpa",
            "a.internal",
            "10.1.168.192.in-addr.arpa",
            "1.20.172.in-addr.arpa",
        ] {
            assert!(zone.is_private(private), "{private}");
        }
        for public in [
            "example.com",
            "1.32.172.in-addr.arpa",
            "8.8.8.8.in-addr.arpa",
            "plan.example",
            "",
        ] {
            assert!(!zone.is_private(public), "{public}");
        }
    }
}
