//! Loading the lists from their sources: http(s) URLs and files.
//!
//! Each source is streamed through the [`ListParser`] into one set of
//! [`Lists`], so a list is never held whole. A source fails when:
//!
//! - it has not finished within 2 minutes (a server that stops sending must
//!   not hold up the sources after it);
//! - it is larger than 64 MiB, decompressed;
//! - a server answers with anything but 200 OK;
//! - a list configured as `https://` is redirected to plain `http://`, where
//!   anyone on the way could rewrite its rules.
//!
//! Rules read before a source failed are kept; the [`Lists`] are then not
//! complete, and the Policy decides whether they replace the current ones.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use reqwest::redirect;
use tokio::io::AsyncReadExt;
use url::Url;

use crate::config::Source;
use crate::policy::{Lists, ListsBuilder, Sources};
use crate::rules::{ListParser, ListStats, ListTooLarge, Rule};

/// The most one source may hold, decompressed.
pub const MAX_LIST_BYTES: u64 = 64 * 1024 * 1024;
/// The most one source may take.
pub const SOURCE_TIMEOUT: Duration = Duration::from_mins(2);
/// The most a whole load may take; sources not done by then count as
/// failed, and what loaded is kept.
pub const LOAD_TIMEOUT: Duration = Duration::from_mins(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_REDIRECTS: usize = 10;
/// Bytes read from a file at a time.
const FILE_CHUNK: usize = 64 * 1024;

/// Why a source did not load completely.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("not loaded within {} s", .0.as_secs())]
    Timeout(Duration),
    #[error("not loaded: the load ran out of time ({} minutes)", LOAD_TIMEOUT.as_secs() / 60)]
    LoadTimeout,
    #[error("HTTP status {0}")]
    Status(StatusCode),
    #[error(transparent)]
    TooLarge(#[from] ListTooLarge),
    #[error("{0}")]
    Http(String),
    #[error(transparent)]
    File(#[from] io::Error),
}

impl From<reqwest::Error> for LoadError {
    fn from(error: reqwest::Error) -> Self {
        // Without reqwest's "for url (...)": its query may hold a token.
        let error = error.without_url();
        // The whole chain: "error sending request" alone says little.
        let mut text = error.to_string();
        let mut source = std::error::Error::source(&error);
        while let Some(cause) = source {
            text.push_str(": ");
            text.push_str(&cause.to_string());
            source = cause.source();
        }
        LoadError::Http(text)
    }
}

/// The client could not be set up.
#[derive(Debug, thiserror::Error)]
#[error("cannot set up the HTTP client: {0}")]
pub struct ClientError(#[from] reqwest::Error);

/// Loads lists; one client, so connections to a list server are reused.
#[derive(Debug, Clone)]
pub struct Loader {
    client: reqwest::Client,
    source_timeout: Duration,
    load_timeout: Duration,
    max_bytes: u64,
}

impl Loader {
    /// A loader that trusts the public roots, with the standard limits.
    ///
    /// # Errors
    ///
    /// The HTTP client cannot be set up.
    pub fn new() -> Result<Loader, ClientError> {
        Loader::with(crate::tls::public_roots(), SOURCE_TIMEOUT, MAX_LIST_BYTES)
    }

    /// A loader that trusts `roots`, with these limits per source.
    ///
    /// # Errors
    ///
    /// The HTTP client cannot be set up.
    pub fn with(
        roots: rustls::RootCertStore,
        source_timeout: Duration,
        max_bytes: u64,
    ) -> Result<Loader, ClientError> {
        let mut tls = crate::tls::client_config(roots);
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .user_agent(concat!("zinkhole/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(redirect::Policy::custom(no_downgrade))
            .no_proxy()
            // A redirect to another host must not learn the list's URL.
            .referer(false)
            .build()?;
        Ok(Loader {
            client,
            source_timeout,
            load_timeout: LOAD_TIMEOUT,
            max_bytes,
        })
    }

    /// The same, with `load_timeout` for a whole load instead of
    /// [`LOAD_TIMEOUT`] (tests).
    #[must_use]
    pub fn load_timeout(self, load_timeout: Duration) -> Loader {
        Loader {
            load_timeout,
            ..self
        }
    }

    /// Every source, one after the other. Failures are logged; the lists say
    /// which sources loaded.
    /// A load ends after its load timeout: sources not done by then count
    /// as failed, and the rules read so far stay.
    pub async fn load(&self, sources: Sources) -> Lists {
        let started = Instant::now();
        let deadline = started + self.load_timeout;
        let mut builder = ListsBuilder::new(sources.clone());
        let mut failed = 0;
        for (source, kind) in sources.iter() {
            let mut sink = |rule: Rule| builder.add(kind, &rule);
            let left = deadline.saturating_duration_since(Instant::now());
            let loaded = if left.is_zero() {
                Err(LoadError::LoadTimeout)
            } else if left < self.source_timeout {
                tokio::time::timeout(left, self.load_source(source, &mut sink))
                    .await
                    .unwrap_or(Err(LoadError::LoadTimeout))
            } else {
                tokio::time::timeout(self.source_timeout, self.load_source(source, &mut sink))
                    .await
                    .unwrap_or(Err(LoadError::Timeout(self.source_timeout)))
            };
            builder.source_done(loaded.is_ok());
            match loaded {
                Ok(stats) => tracing::info!(
                    source = %shown(source),
                    rules = stats.rules,
                    skipped_lines = stats.skipped,
                    "list loaded"
                ),
                Err(error) => {
                    failed += 1;
                    tracing::warn!(source = %shown(source), %error, "list not loaded");
                }
            }
        }
        let lists = builder.finish();
        if sources.is_empty() {
            return lists;
        }
        tracing::info!(
            blocked_domains = lists.blocked_domains(),
            allowed_domains = lists.allowed_domains(),
            sources = sources.len(),
            failed,
            millis = started.elapsed().as_millis(),
            "lists loaded"
        );
        lists
    }

    async fn load_source(
        &self,
        source: &Source,
        sink: &mut impl FnMut(Rule),
    ) -> Result<ListStats, LoadError> {
        let mut parser = ListParser::new(self.max_bytes);
        match source {
            Source::Url(url) => {
                if url.scheme() == "http" {
                    tracing::warn!(%url, "loading a list over plain HTTP: anyone on the way can change its rules");
                }
                let mut response = self.client.get(url.clone()).send().await?;
                if response.status() != StatusCode::OK {
                    return Err(LoadError::Status(response.status()));
                }
                while let Some(chunk) = response.chunk().await? {
                    parser.feed(&chunk, sink)?;
                }
            }
            Source::File(path) => read_file(path, &mut parser, sink).await?,
        }
        Ok(parser.finish(sink))
    }
}

async fn read_file(
    path: &Path,
    parser: &mut ListParser,
    sink: &mut impl FnMut(Rule),
) -> Result<(), LoadError> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut buffer = vec![0u8; FILE_CHUNK];
    loop {
        let len = file.read(&mut buffer).await?;
        let Some(chunk) = buffer.get(..len).filter(|chunk| !chunk.is_empty()) else {
            return Ok(());
        };
        parser.feed(chunk, sink)?;
    }
}

/// Follows redirects, except from a list configured as `https://` to plain
/// `http://`.
fn no_downgrade(attempt: redirect::Attempt<'_>) -> redirect::Action {
    let from_https = attempt
        .previous()
        .first()
        .is_some_and(|first| first.scheme() == "https");
    if from_https && attempt.url().scheme() != "https" {
        let error = format!(
            "refused a redirect from https to {}",
            shown_url(attempt.url())
        );
        return attempt.error(error);
    }
    if attempt.previous().len() > MAX_REDIRECTS {
        return attempt.error("too many redirects");
    }
    attempt.follow()
}

/// A source for the log: a URL without credentials, query or fragment,
/// which may hold tokens.
pub(crate) fn shown(source: &Source) -> String {
    match source {
        Source::Url(url) => shown_url(url),
        Source::File(path) => path.display().to_string(),
    }
}

/// `url` without credentials, query or fragment.
fn shown_url(url: &Url) -> String {
    let mut shown = url.clone();
    let _ = shown.set_username("");
    let _ = shown.set_password(None);
    shown.set_query(None);
    shown.set_fragment(None);
    shown.to_string()
}

#[cfg(test)]
mod tests;
