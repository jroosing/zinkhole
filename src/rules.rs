//! Rules from lists and inline rules. Each line is recognized on its own, so
//! the common list formats (and lists that mix them) need no configuration:
//!
//! ```text
//! hosts file     0.0.0.0 ads.example.com tracker.example.com
//! domain list    ads.example.com
//! wildcards      *.example.com                (subdomains only)
//! Adblock        ||ads.example.com^           (@@||...^ exceptions allow)
//! dnsmasq        address=/ads.example.com/0.0.0.0, local=/x/, server=/x/
//! ```
//!
//! Comments (`#`, `!`), Adblock headers and rules without DNS meaning
//! (cosmetic filters, URL paths, regular expressions, unknown `$` modifiers)
//! are skipped. A listed domain matches itself and all of its subdomains.

use std::net::IpAddr;
use std::str::FromStr;

use crate::name;

/// Longest line considered; longer lines are skipped.
pub const MAX_LINE_LEN: usize = 4096;

/// Which names a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Matching {
    /// `example.com` and everything below it.
    DomainAndSubdomains,
    /// Only names below `example.com` (`*.example.com`).
    SubdomainsOnly,
}

/// One block or allow entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Normalized (see [`name::normalize`]).
    pub name: String,
    pub matching: Matching,
    /// An Adblock exception (`@@||example.com^`): allows instead of blocking.
    pub exception: bool,
}

/// What one line held.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub rules: Vec<Rule>,
    /// Entries on the line that are not rules zinkhole understands.
    pub skipped: u32,
}

impl Parsed {
    fn rule(name: String, matching: Matching, exception: bool) -> Parsed {
        Parsed {
            rules: vec![Rule {
                name,
                matching,
                exception,
            }],
            skipped: 0,
        }
    }

    fn skip() -> Parsed {
        Parsed {
            rules: Vec::new(),
            skipped: 1,
        }
    }
}

/// Parses one line of a list, in any supported format.
#[must_use]
pub fn parse_line(raw: &str) -> Parsed {
    let line = strip_comment(raw).trim_matches([' ', '\t', '\r']);
    if line.is_empty() || line.starts_with(['!', '[']) {
        // Blank, an Adblock comment or a "[Adblock Plus 2.0]" header.
        return Parsed::default();
    }
    if let Some(body) = line.strip_prefix("@@||") {
        return parse_adblock(body, true);
    }
    if let Some(body) = line.strip_prefix("||") {
        return parse_adblock(body, false);
    }
    if ["address=/", "local=/", "server=/"]
        .iter()
        .any(|prefix| line.starts_with(prefix))
    {
        return parse_dnsmasq(line);
    }

    let mut fields = line.split([' ', '\t']).filter(|field| !field.is_empty());
    let Some(first) = fields.next() else {
        return Parsed::default();
    };
    if IpAddr::from_str(first).is_ok() {
        // A hosts file line: "<address> <name> [<name>...]".
        return fields.fold(Parsed::default(), |mut parsed, host| {
            match hosts_entry(host) {
                Some(name) => parsed.rules.push(Rule {
                    name,
                    matching: Matching::DomainAndSubdomains,
                    exception: false,
                }),
                None => parsed.skipped += 1,
            }
            parsed
        });
    }
    if fields.next().is_some() {
        return Parsed::skip(); // not a format we know
    }
    parse_domain(first)
}

/// Removes a `#` comment. Only a `#` at the start or after whitespace starts
/// one, so cosmetic filters like `example.com##.ad` stay whole (and are then
/// rejected as invalid names rather than blocking example.com).
fn strip_comment(line: &str) -> &str {
    let mut previous = ' ';
    for (i, c) in line.char_indices() {
        if c == '#' && (previous == ' ' || previous == '\t') {
            return line.get(..i).unwrap_or(line);
        }
        previous = c;
    }
    line
}

/// An Adblock rule body after `||`: `example.com^`, optionally followed by `|`
/// and `$important`. Other modifiers change the meaning, so those rules are
/// skipped rather than guessed at.
fn parse_adblock(body: &str, exception: bool) -> Parsed {
    let (domain, tail) = body.split_at(body.find(['^', '|', '$', '/']).unwrap_or(body.len()));
    let tail = tail.strip_prefix('^').unwrap_or(tail);
    let tail = tail.strip_prefix('|').unwrap_or(tail);
    if !tail.is_empty() && tail != "$important" {
        return Parsed::skip();
    }
    let (domain, matching) = match domain.strip_prefix("*.") {
        Some(rest) => (rest, Matching::SubdomainsOnly),
        None => (domain, Matching::DomainAndSubdomains),
    };
    name::normalize(domain)
        .map_or_else(Parsed::skip, |name| Parsed::rule(name, matching, exception))
}

/// dnsmasq rules: `address=/a.com/b.com/<target>` blocks when the target is a
/// sinkhole address or empty; `local=/a.com/` and `server=/a.com/` (no
/// upstream server) mean "answer locally", which blocks too. Rules that
/// redirect or forward elsewhere are skipped.
fn parse_dnsmasq(line: &str) -> Parsed {
    let Some((key, spec)) = line.split_once('=') else {
        return Parsed::skip();
    };
    let Some((domains, target)) = spec.rsplit_once('/') else {
        return Parsed::skip();
    };
    let Some(domains) = domains.strip_prefix('/').filter(|d| !d.is_empty()) else {
        return Parsed::skip();
    };
    let blocks = if key == "address" {
        is_sinkhole(target)
    } else {
        target.is_empty()
    };
    if !blocks {
        return Parsed::skip();
    }
    domains
        .split('/')
        .filter(|d| !d.is_empty())
        .fold(Parsed::default(), |mut parsed, domain| {
            match name::normalize(domain) {
                Some(name) => parsed.rules.push(Rule {
                    name,
                    matching: Matching::DomainAndSubdomains,
                    exception: false,
                }),
                None => parsed.skipped += 1,
            }
            parsed
        })
}

fn is_sinkhole(target: &str) -> bool {
    ["", "#", "0.0.0.0", "::", "127.0.0.1", "::1"].contains(&target)
}

/// A name from a hosts file line. Hosts files also map local names
/// (`127.0.0.1 localhost`): single-label names, address-like names and the
/// usual local aliases are never blocked.
fn hosts_entry(host: &str) -> Option<String> {
    let name = name::normalize(host)?;
    let local_alias =
        !name.contains('.') || IpAddr::from_str(&name).is_ok() || name == "localhost.localdomain";
    (!local_alias).then_some(name)
}

/// A plain domain, or `*.domain` for subdomains only.
fn parse_domain(token: &str) -> Parsed {
    let (domain, matching) = match token.strip_prefix("*.") {
        Some(rest) => (rest, Matching::SubdomainsOnly),
        None => (token, Matching::DomainAndSubdomains),
    };
    name::normalize(domain).map_or_else(Parsed::skip, |name| Parsed::rule(name, matching, false))
}

// ---------------------------------------------------------------------------
// Streaming

/// What a list held.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListCounts {
    pub lines: u64,
    pub rules: u64,
    pub skipped: u64,
}

/// More bytes arrived than a list may have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the list is larger than {max_bytes} bytes")]
pub struct ListTooLarge {
    pub max_bytes: u64,
}

/// Parses a list as it arrives, in chunks of any size: lines that straddle
/// chunks are kept until complete, and the list is never held whole.
#[derive(Debug)]
pub struct ListParser {
    max_bytes: u64,
    bytes: u64,
    /// The start of a line whose end has not arrived yet.
    partial: Vec<u8>,
    /// The current line is longer than [`MAX_LINE_LEN`] and is being skipped.
    overflow: bool,
    first_line: bool,
    counts: ListCounts,
}

impl ListParser {
    #[must_use]
    pub fn new(max_bytes: u64) -> ListParser {
        ListParser {
            max_bytes,
            bytes: 0,
            partial: Vec::new(),
            overflow: false,
            first_line: true,
            counts: ListCounts::default(),
        }
    }

    /// Parses the complete lines in `chunk`, passing each rule to `sink`.
    ///
    /// # Errors
    /// When the list grows beyond its limit; what was parsed so far stands.
    pub fn feed(&mut self, chunk: &[u8], sink: &mut impl FnMut(Rule)) -> Result<(), ListTooLarge> {
        self.bytes = self.bytes.saturating_add(chunk.len() as u64);
        if self.bytes > self.max_bytes {
            return Err(ListTooLarge {
                max_bytes: self.max_bytes,
            });
        }
        let mut pieces = chunk.split(|&b| b == b'\n').peekable();
        while let Some(piece) = pieces.next() {
            if pieces.peek().is_none() {
                self.append(piece); // no newline yet: the line continues
                break;
            }
            if self.partial.is_empty() && !self.overflow {
                self.line(piece, sink);
            } else {
                self.append(piece);
                let line = std::mem::take(&mut self.partial);
                self.line(&line, sink);
            }
            self.overflow = false;
        }
        Ok(())
    }

    /// Parses the last line, if it had no newline, and says what the list held.
    pub fn finish(mut self, sink: &mut impl FnMut(Rule)) -> ListCounts {
        if !self.partial.is_empty() || self.overflow {
            let line = std::mem::take(&mut self.partial);
            self.line(&line, sink);
        }
        self.counts
    }

    fn append(&mut self, bytes: &[u8]) {
        if self.overflow {
            return;
        }
        if self.partial.len() + bytes.len() > MAX_LINE_LEN {
            self.overflow = true;
            self.partial.clear();
            return;
        }
        self.partial.extend_from_slice(bytes);
    }

    fn line(&mut self, bytes: &[u8], sink: &mut impl FnMut(Rule)) {
        self.counts.lines += 1;
        let first = std::mem::replace(&mut self.first_line, false);
        let bytes = if first {
            bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)
        } else {
            bytes
        };
        // Lists are ASCII; a line that is not even UTF-8 holds no rule.
        let text = (!self.overflow && bytes.len() <= MAX_LINE_LEN)
            .then(|| std::str::from_utf8(bytes).ok())
            .flatten();
        let Some(text) = text else {
            self.counts.skipped += 1;
            return;
        };
        let parsed = parse_line(text);
        self.counts.skipped += u64::from(parsed.skipped);
        self.counts.rules += parsed.rules.len() as u64;
        parsed.rules.into_iter().for_each(&mut *sink);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rules of `text`, written as "name", "*.name" or "allow name".
    fn rules(text: &str) -> Vec<String> {
        let mut parser = ListParser::new(u64::MAX);
        let mut found = Vec::new();
        let mut sink = |rule: Rule| found.push(describe(&rule));
        parser.feed(text.as_bytes(), &mut sink).unwrap();
        parser.finish(&mut sink);
        found
    }

    fn describe(rule: &Rule) -> String {
        let prefix = match (rule.exception, rule.matching) {
            (true, _) => "allow ",
            (false, Matching::SubdomainsOnly) => "*.",
            (false, Matching::DomainAndSubdomains) => "",
        };
        format!("{prefix}{}", rule.name)
    }

    #[test]
    fn hosts_files() {
        let text = "# comment\n0.0.0.0 ads.example.com tracker.Example.com # trailing\n\
                    127.0.0.1 localhost\n127.0.0.1 localhost.localdomain\n::1 ip6-localhost\n\
                    0.0.0.0 0.0.0.0\n\n   \n";
        assert_eq!(rules(text), ["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn domain_lists_and_wildcards() {
        let text =
            "ads.example.com\n*.tracker.net\nexample.com##.ad\nnot a domain\n_dmarc.example.org.\n";
        assert_eq!(
            rules(text),
            ["ads.example.com", "*.tracker.net", "_dmarc.example.org"]
        );
    }

    #[test]
    fn adblock_syntax() {
        let text = "[Adblock Plus 2.0]\n! comment\n||ads.example.com^\n||t.example.com^|\n\
                    ||imp.example.com^$important\n||*.sub.example.com^\n@@||good.example.com^\n\
                    ||path.example.com/banner\n||third.example.com^$third-party\n/regex/\n";
        assert_eq!(
            rules(text),
            [
                "ads.example.com",
                "t.example.com",
                "imp.example.com",
                "*.sub.example.com",
                "allow good.example.com"
            ]
        );
    }

    #[test]
    fn dnsmasq_syntax() {
        let text = "address=/a.example.com/0.0.0.0\naddress=/b.example.com/c.example.com/\n\
                    address=/redirect.example.com/192.0.2.1\nlocal=/l.example.com/\n\
                    server=/s.example.com/\nserver=/fwd.example.com/9.9.9.9\naddress=//0.0.0.0\n";
        assert_eq!(
            rules(text),
            [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "l.example.com",
                "s.example.com"
            ]
        );
    }

    #[test]
    fn lines_split_across_chunks_and_overlong_lines_are_skipped() {
        let long = "x".repeat(MAX_LINE_LEN + 10);
        let text =
            format!("\u{feff}first.example.com\nsecond.exa{long}\nmple.com\nthird.example.com");
        // The long line is not a rule; the line after it is, even though the
        // chunk boundary falls in the middle of it.
        let mut parser = ListParser::new(u64::MAX);
        let mut found = Vec::new();
        let mut sink = |rule: Rule| found.push(rule.name);
        for chunk in text.as_bytes().chunks(7) {
            parser.feed(chunk, &mut sink).unwrap();
        }
        let counts = parser.finish(&mut sink);
        assert_eq!(
            found,
            ["first.example.com", "mple.com", "third.example.com"]
        );
        assert_eq!(
            counts,
            ListCounts {
                lines: 4,
                rules: 3,
                skipped: 1
            }
        );
    }

    #[test]
    fn a_list_beyond_its_limit_is_refused() {
        let mut parser = ListParser::new(10);
        let mut sink = |_: Rule| {};
        assert_eq!(
            parser.feed(b"a.example.com\n", &mut sink),
            Err(ListTooLarge { max_bytes: 10 })
        );
    }

    proptest::proptest! {
        /// Any line, however malformed, parses without panicking, and every
        /// rule it yields is a normalized name.
        #[test]
        fn any_line_yields_only_normalized_names(line in "\\PC{0,200}") {
            for rule in parse_line(&line).rules {
                let normalized = name::normalize(&rule.name);
                proptest::prop_assert_eq!(normalized.as_deref(), Some(rule.name.as_str()));
            }
        }

        /// A list gives the same rules however the network splits it.
        #[test]
        fn chunking_never_changes_the_rules(
            lines in proptest::collection::vec("(0\\.0\\.0\\.0 |\\|\\||\\*\\.)?[a-z]{1,8}\\.(com|net)\\^?", 0..40),
            chunk in 1usize..64,
        ) {
            let text = lines.join("\n");
            let whole = rules(&text);
            let mut parser = ListParser::new(u64::MAX);
            let mut parts = Vec::new();
            let mut sink = |rule: Rule| parts.push(describe(&rule));
            for piece in text.as_bytes().chunks(chunk) {
                parser.feed(piece, &mut sink).unwrap();
            }
            parser.finish(&mut sink);
            proptest::prop_assert_eq!(whole, parts);
        }
    }

    #[test]
    fn every_rule_is_a_normalized_name_whatever_the_input() {
        let inputs = [
            "||Ü.com^",
            "0.0.0.0 \u{0}evil",
            "address=/x/../0.0.0.0",
            "|| ^",
            "@@||^",
            "*.",
            "||*.^",
        ];
        for input in inputs {
            for rule in parse_line(input).rules {
                assert_eq!(
                    name::normalize(&rule.name).as_deref(),
                    Some(rule.name.as_str()),
                    "{input}"
                );
            }
        }
    }
}
