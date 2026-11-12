//! Sync (ADR-0001): replicas pull the Policy settings from an
//! origin, over the HTTP port, sealed.
//!
//! - A replica sends `GET /sync` with a fresh random nonce, the `ETag` of
//!   the settings it has, and a proof that it has the shared secret: an
//!   HMAC-SHA256 over the two, under a key derived from the secret.
//! - The origin answers only a request with that proof (others are 401), so
//!   only replicas show in its Metrics, and nobody else learns when the
//!   settings change or how large they are.
//! - The origin derives a one-time key from the shared secret and that nonce
//!   (HKDF-SHA256) and seals its answer with XChaCha20-Poly1305: either
//!   "unchanged" or its settings as TOML. The `ETag` is associated data, so it
//!   is authenticated too.
//! - So an answer opens only for the request it was made for: a replayed or
//!   altered answer is rejected, and the settings cannot be read on the way.
//! - A replica keeps the last settings it accepted in a state file, sealed
//!   under a key of its own, to start from when the origin is down.
//!
//! The `ETag` is a fingerprint keyed with the secret, so it says nothing about
//! the settings.

use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use axum::Extension;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::client::{self, ClientError};
use crate::config::{self, PolicySettings, Secret};
use crate::hex;
use crate::http::Client;
use crate::metrics;
use crate::settings::InForce;

pub const PATH: &str = "/sync";
const NONCE_HEADER: &str = "x-zinkhole-nonce";
/// The request's proof of the secret, in hex.
const PROOF_HEADER: &str = "x-zinkhole-proof";
const PROOF_LEN: usize = 32;
const NONCE_LEN: usize = 32;
const XNONCE_LEN: usize = 24;
/// Synced settings are config sections: the config's limit applies.
const MAX_TEXT: usize = config::MAX_FILE_SIZE;
/// The most a sealed answer adds: the nonce, the payload tag and the tag.
const OVERHEAD: usize = XNONCE_LEN + 1 + 16;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Failed syncs in a row before a warning.
const WARN_AFTER: u64 = 3;
const STATE_FILE: &str = "synced-settings";

const INFO_ANSWER: &[u8] = b"zinkhole sync answer v1";
const INFO_REQUEST: &[u8] = b"zinkhole sync request v1";
const INFO_ETAG: &[u8] = b"zinkhole sync etag v1";
const INFO_STATE: &[u8] = b"zinkhole state file v1";
const AD_ANSWER: &[u8] = b"zinkhole-sync-1\n";
const AD_STATE: &[u8] = b"zinkhole-state-1\n";

const UNCHANGED: u8 = 0;
const SETTINGS: u8 = 1;

/// The keys derived from the shared secret.
struct Keys {
    hkdf: Hkdf<Sha256>,
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keys([redacted])")
    }
}

impl Keys {
    fn new(secret: &Secret) -> Keys {
        Keys {
            hkdf: Hkdf::new(None, secret.expose()),
        }
    }

    fn derive(&self, info: &[&[u8]]) -> [u8; 32] {
        let mut key = [0u8; 32];
        // 32 bytes is far below HKDF-SHA256's limit of 8160.
        let _ = self.hkdf.expand_multi_info(info, &mut key);
        key
    }

    /// The one-time key for the answer to the request with `nonce`.
    fn answer(&self, nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
        self.derive(&[INFO_ANSWER, nonce])
    }

    fn state(&self) -> [u8; 32] {
        self.derive(&[INFO_STATE])
    }

    /// The HMAC that proves a request comes from someone with the secret:
    /// over the request's `nonce` and the `ETag` it says the replica has.
    /// None only if no HMAC could be set up (any key fits one).
    fn request_mac(&self, nonce: &[u8; NONCE_LEN], have: Option<&str>) -> Option<Hmac<Sha256>> {
        let key = self.derive(&[INFO_REQUEST]);
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&key).ok()?;
        mac.update(nonce);
        mac.update(have.unwrap_or_default().as_bytes());
        Some(mac)
    }

    /// That proof as a request carries it: in hex.
    fn proof(&self, nonce: &[u8; NONCE_LEN], have: Option<&str>) -> String {
        self.request_mac(nonce, have)
            .map(|mac| hex::encode(&mac.finalize().into_bytes()))
            .unwrap_or_default()
    }

    /// True if `proof` (hex) is the proof for a request with `nonce` and
    /// `have`. Compared in constant time.
    fn proves(&self, nonce: &[u8; NONCE_LEN], have: Option<&str>, proof: &str) -> bool {
        let mut bytes = [0u8; PROOF_LEN];
        hex::decode_into(proof, &mut bytes).is_ok()
            && self
                .request_mac(nonce, have)
                .is_some_and(|mac| mac.verify_slice(&bytes).is_ok())
    }

    /// The `ETag` of `text`: a keyed fingerprint, quoted as HTTP has it.
    fn etag(&self, text: &str) -> String {
        let key = self.derive(&[INFO_ETAG]);
        let fingerprint = match <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&key) {
            Ok(mut mac) => {
                mac.update(text.as_bytes());
                mac.finalize().into_bytes().to_vec()
            }
            Err(_) => Vec::new(),
        };
        format!("\"{}\"", hex::encode(&fingerprint))
    }
}

/// An answer or state file that did not open: not sealed with this secret
/// for this purpose, or altered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("it does not open with the shared secret (another secret, or altered)")]
pub struct Tampered;

/// A fresh random nonce, then `plaintext` sealed under `key` with `ad`.
fn seal(key: &[u8; 32], ad: &[u8], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    let mut nonce = [0u8; XNONCE_LEN];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    let sealed = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .map_err(|_| io::Error::other("cannot seal"))?;
    let mut out = Vec::with_capacity(XNONCE_LEN + sealed.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn open(key: &[u8; 32], ad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, Tampered> {
    let (nonce, ciphertext) = sealed.split_at_checked(XNONCE_LEN).ok_or(Tampered)?;
    let nonce: [u8; XNONCE_LEN] = nonce.try_into().map_err(|_| Tampered)?;
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map_err(|_| Tampered)
}

fn answer_ad(etag: &str) -> Vec<u8> {
    [AD_ANSWER, etag.as_bytes()].concat()
}

// ---------------------------------------------------------------------------
// The origin

/// The settings an origin serves.
#[derive(Debug)]
struct Published {
    text: String,
    etag: String,
}

/// Serves the Policy settings in force to replicas.
#[derive(Debug)]
pub struct Origin {
    keys: Keys,
    published: ArcSwap<Published>,
    metrics: Arc<metrics::State>,
}

impl Origin {
    /// An origin serving `settings`.
    ///
    /// # Errors
    ///
    /// The settings cannot be written as TOML.
    pub fn new(
        secret: &Secret,
        settings: &PolicySettings,
        metrics: Arc<metrics::State>,
    ) -> Result<Origin, PublishError> {
        let keys = Keys::new(secret);
        let published = publication(&keys, settings)?;
        Ok(Origin {
            keys,
            published: ArcSwap::from_pointee(published),
            metrics,
        })
    }

    /// Serves `settings` from now on.
    ///
    /// # Errors
    ///
    /// The settings cannot be written as TOML; the last ones stay served.
    pub fn publish(&self, settings: &PolicySettings) -> Result<(), PublishError> {
        self.published
            .store(Arc::new(publication(&self.keys, settings)?));
        Ok(())
    }

    /// The settings served, as TOML.
    #[cfg(test)]
    pub(crate) fn published_text(&self) -> String {
        self.published.load().text.clone()
    }

    /// `GET /sync`.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().route(PATH, get(get_sync)).with_state(self)
    }

    /// The sealed answer to a request with `nonce` (hex) from a replica
    /// that has `if_none_match`, if `proof` shows it has the secret.
    fn answer(
        &self,
        nonce: &str,
        if_none_match: Option<&str>,
        proof: Option<&str>,
    ) -> Result<(String, Vec<u8>), AnswerError> {
        let mut bytes = [0u8; NONCE_LEN];
        if hex::decode_into(nonce, &mut bytes).is_err() {
            return Err(AnswerError::BadNonce);
        }
        // Sealed as it is, an answer still says when the settings change
        // (its ETag) and how large they are, and whoever gets one counts as
        // a replica in the Metrics: only for those with the secret.
        if !proof.is_some_and(|proof| self.keys.proves(&bytes, if_none_match, proof)) {
            return Err(AnswerError::NoProof);
        }
        let published = self.published.load();
        let mut payload = Vec::with_capacity(1 + published.text.len());
        if if_none_match == Some(published.etag.as_str()) {
            payload.push(UNCHANGED);
        } else {
            payload.push(SETTINGS);
            payload.extend_from_slice(published.text.as_bytes());
        }
        let sealed = seal(
            &self.keys.answer(&bytes),
            &answer_ad(&published.etag),
            &payload,
        )
        .map_err(|_| AnswerError::Seal)?;
        Ok((published.etag.clone(), sealed))
    }
}

/// Why the origin did not answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnswerError {
    BadNonce,
    /// The request does not prove the secret.
    NoProof,
    /// No random nonce could be made.
    Seal,
}

impl IntoResponse for AnswerError {
    fn into_response(self) -> Response {
        match self {
            AnswerError::BadNonce => (StatusCode::BAD_REQUEST, "bad nonce\n").into_response(),
            AnswerError::NoProof => StatusCode::UNAUTHORIZED.into_response(),
            AnswerError::Seal => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

/// Why an origin cannot serve settings.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error(transparent)]
    Toml(#[from] toml::ser::Error),
    /// Replicas would refuse them: the settings are written out anew, which
    /// can be larger than the config file they came from.
    #[error("the settings take {0} bytes as served, more than the {MAX_TEXT} replicas accept")]
    TooLarge(usize),
}

fn publication(keys: &Keys, settings: &PolicySettings) -> Result<Published, PublishError> {
    let text = toml::to_string(settings)?;
    if text.len() > MAX_TEXT {
        return Err(PublishError::TooLarge(text.len()));
    }
    let etag = keys.etag(&text);
    Ok(Published { text, etag })
}

async fn get_sync(
    State(origin): State<Arc<Origin>>,
    Extension(Client(client)): Extension<Client>,
    headers: HeaderMap,
) -> Response {
    let Some(nonce) = headers.get(NONCE_HEADER).and_then(|v| v.to_str().ok()) else {
        return (StatusCode::BAD_REQUEST, "no nonce\n").into_response();
    };
    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    let proof = headers.get(PROOF_HEADER).and_then(|v| v.to_str().ok());
    match origin.answer(nonce, if_none_match, proof) {
        Ok((etag, sealed)) => {
            origin.metrics.fetched_by(client, SystemTime::now());
            let etag = HeaderValue::from_str(&etag).unwrap_or(HeaderValue::from_static("\"\""));
            (
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/octet-stream"),
                    ),
                    (header::ETAG, etag),
                    (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                ],
                sealed,
            )
                .into_response()
        }
        Err(error) => error.into_response(),
    }
}

// ---------------------------------------------------------------------------
// The replica

/// Why a sync failed.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("{0}")]
    Http(String),
    #[error("HTTP status {0}")]
    Status(StatusCode),
    /// The origin wants proof of its secret, and this replica's did not do.
    #[error("the origin refused the request: it has another secret")]
    Refused,
    #[error("the answer is larger than {} bytes", MAX_TEXT + OVERHEAD)]
    TooLarge,
    #[error("the answer has no ETag")]
    NoEtag,
    #[error("the answer {0}")]
    Tampered(#[from] Tampered),
    #[error("the answer is not settings")]
    Malformed,
    /// "Unchanged", but about other settings than the ones this replica
    /// has: its `If-None-Match` was altered on the way.
    #[error("the answer says \"unchanged\" about settings this replica does not have")]
    NotOurs,
}

impl From<reqwest::Error> for SyncError {
    fn from(error: reqwest::Error) -> Self {
        SyncError::Http(client::error_text(error))
    }
}

/// What an origin answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    Unchanged,
    Changed(Synced),
}

/// Settings from the origin, as text, with their `ETag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Synced {
    pub etag: String,
    pub text: String,
}

/// Why the state file was not used.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("the state file {0}")]
    Tampered(#[from] Tampered),
    #[error("the state file is not settings")]
    Malformed,
}

/// Fetches the settings from the origin, and keeps them in the state file.
#[derive(Debug)]
pub struct Replica {
    url: Url,
    keys: Keys,
    client: reqwest::Client,
    state_file: PathBuf,
}

impl Replica {
    /// A replica of the origin at `origin` (its HTTP port).
    ///
    /// # Errors
    ///
    /// The HTTP client cannot be set up.
    pub fn new(origin: &Url, secret: &Secret, state_dir: &Path) -> Result<Replica, ClientError> {
        let mut url = origin.clone();
        url.set_path(PATH);
        let tls = crate::tls::client_config(crate::tls::public_roots());
        let client = client::builder(tls)
            .timeout(FETCH_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Replica {
            url,
            keys: Keys::new(secret),
            client,
            state_file: state_dir.join(STATE_FILE),
        })
    }

    #[must_use]
    pub fn origin(&self) -> &Url {
        &self.url
    }

    /// Asks the origin for its settings, telling it the `ETag` we `have`.
    ///
    /// # Errors
    ///
    /// The origin cannot be reached, or its answer does not open or hold
    /// settings.
    pub async fn fetch(&self, have: Option<&str>) -> Result<Fetched, SyncError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| SyncError::Http(e.to_string()))?;
        let mut request = self
            .client
            .get(self.url.clone())
            .header(NONCE_HEADER, hex::encode(&nonce))
            .header(PROOF_HEADER, self.keys.proof(&nonce, have));
        if let Some(etag) = have {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        let mut response = request.send().await?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED => return Err(SyncError::Refused),
            status => return Err(SyncError::Status(status)),
        }
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .ok_or(SyncError::NoEtag)?
            .to_owned();
        let mut sealed = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if sealed.len() + chunk.len() > MAX_TEXT + OVERHEAD {
                return Err(SyncError::TooLarge);
            }
            sealed.extend_from_slice(&chunk);
        }
        opened(&self.keys, &nonce, have, etag, &sealed)
    }

    /// The settings in the state file; None if there is none.
    ///
    /// # Errors
    ///
    /// The file cannot be read, or does not open.
    pub fn load_state(&self) -> Result<Option<Synced>, StateError> {
        let sealed = match fs::read(&self.state_file) {
            Ok(sealed) => sealed,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let plain = open(&self.keys.state(), AD_STATE, &sealed)?;
        let text = String::from_utf8(plain).map_err(|_| StateError::Malformed)?;
        let (etag, text) = text.split_once('\n').ok_or(StateError::Malformed)?;
        Ok(Some(Synced {
            etag: etag.to_owned(),
            text: text.to_owned(),
        }))
    }

    /// Replaces the state file with `synced`, atomically, readable by the
    /// owner only.
    ///
    /// # Errors
    ///
    /// The file cannot be written.
    pub fn save_state(&self, synced: &Synced) -> io::Result<()> {
        let plain = [synced.etag.as_bytes(), b"\n", synced.text.as_bytes()].concat();
        let sealed = seal(&self.keys.state(), AD_STATE, &plain)?;
        let partial = self.state_file.with_extension("partial");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&partial)?;
        file.write_all(&sealed)?;
        file.sync_all()?;
        fs::rename(&partial, &self.state_file)
    }

    #[must_use]
    pub fn state_file(&self) -> &Path {
        &self.state_file
    }

    /// Creates the state directory if missing, and checks a file can be
    /// written there.
    ///
    /// # Errors
    ///
    /// The directory cannot be created or written to.
    pub fn check_state_dir(&self) -> io::Result<()> {
        let dir = self.state_file.parent().unwrap_or(Path::new("."));
        fs::create_dir_all(dir)?;
        let probe = self.state_file.with_extension("probe");
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&probe)?;
        fs::remove_file(&probe)
    }
}

/// What the sealed answer to the request with `nonce` says, to a replica
/// that has the settings with the `ETag` `have`.
///
/// The request is not sealed, so "unchanged" counts only for the `ETag`
/// the replica really has: an altered `If-None-Match` must not keep it on
/// old settings.
fn opened(
    keys: &Keys,
    nonce: &[u8; NONCE_LEN],
    have: Option<&str>,
    etag: String,
    sealed: &[u8],
) -> Result<Fetched, SyncError> {
    let payload = open(&keys.answer(nonce), &answer_ad(&etag), sealed)?;
    match payload.split_first() {
        Some((&UNCHANGED, [])) if have == Some(etag.as_str()) => Ok(Fetched::Unchanged),
        Some((&UNCHANGED, [])) => Err(SyncError::NotOurs),
        Some((&SETTINGS, text)) => {
            let text = String::from_utf8(text.to_vec()).map_err(|_| SyncError::Malformed)?;
            Ok(Fetched::Changed(Synced { etag, text }))
        }
        _ => Err(SyncError::Malformed),
    }
}

/// A replica's Sync loop: what it syncs with, and where the settings go.
#[derive(Debug)]
pub struct Syncer {
    pub replica: Replica,
    /// This instance's `[server]` section, which synced settings must fit.
    pub server: config::Server,
    pub in_force: Arc<InForce>,
    /// The `ETag` of the settings in force, if they came from the origin.
    pub have: Option<String>,
    pub interval: Duration,
    /// Notified to sync at once (a Reload).
    pub now: Arc<Notify>,
    pub metrics: Arc<metrics::State>,
}

impl Syncer {
    /// Syncs with the origin every `interval`, and at once when `now` is
    /// notified, until `shutdown`. Valid settings are put in force and
    /// saved.
    pub async fn run(mut self, shutdown: CancellationToken) {
        let origin = self.replica.origin().clone();
        let mut failures: u64 = 0;
        // The origin's current settings are refused here.
        let mut rejected = false;
        loop {
            // A fetch can take as long as its timeout: a shutdown does not
            // wait for it, and nothing fetched after it is put in force.
            let fetched = tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                fetched = self.replica.fetch(self.have.as_deref()) => fetched,
            };
            match fetched {
                Ok(fetched) => {
                    if failures >= WARN_AFTER {
                        tracing::info!(%origin, "syncing again");
                    }
                    failures = 0;
                    if let Fetched::Changed(synced) = fetched {
                        rejected = !self.apply(&synced);
                        // Also after invalid settings: they are not fetched
                        // and logged again until the origin's settings
                        // change (the Metrics show them refused meanwhile).
                        self.have = Some(synced.etag);
                    }
                    if rejected {
                        self.metrics.sync_rejected();
                    } else {
                        self.metrics.synced(SystemTime::now());
                    }
                }
                Err(error) => {
                    failures += 1;
                    self.metrics.sync_failed();
                    if failures == WARN_AFTER {
                        tracing::warn!(%origin, %error, "syncing failed {WARN_AFTER} times in a row; keeping the last settings");
                    } else {
                        tracing::debug!(%origin, %error, "sync failed");
                    }
                }
            }
            tokio::select! {
                () = tokio::time::sleep(self.interval) => {}
                () = self.now.notified() => {}
                () = shutdown.cancelled() => return,
            }
        }
    }

    /// Puts `synced` in force and saves it, if it is valid here; false if
    /// not.
    fn apply(&self, synced: &Synced) -> bool {
        let origin = self.replica.origin();
        match self.server.synced_settings(&synced.text) {
            Ok(settings) => {
                self.in_force.apply(&settings);
                tracing::info!(%origin, "applied the settings synced from the origin");
                let saved = self.replica.save_state(synced);
                self.metrics.state_file(saved.is_ok());
                if let Err(error) = saved {
                    tracing::error!(
                        file = %self.replica.state_file().display(),
                        %error,
                        "cannot save the synced settings: a restart while the origin is down would start without them"
                    );
                }
                true
            }
            Err(error) => {
                tracing::error!(
                    %origin,
                    "the settings from the origin are invalid here, keeping the current ones: {error}"
                );
                false
            }
        }
    }
}

#[cfg(test)]
mod tests;
