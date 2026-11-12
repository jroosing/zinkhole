//! Sealing, and an origin and a replica over loopback.

use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt as _;

use hickory_proto::rr::RecordType;
use serde::Deserialize;

use super::*;
use crate::config::Config;
use crate::http::{self, HttpListeners};
use crate::policy::{Decision, Policy};

fn secret(byte: u8) -> Secret {
    #[derive(Deserialize)]
    struct Holder {
        secret: Secret,
    }
    let text = format!("secret = \"{}\"", hex::encode(&[byte; 32]));
    toml::from_str::<Holder>(&text).unwrap().secret
}

fn settings(toml: &str) -> PolicySettings {
    toml::from_str(toml).unwrap()
}

#[test]
fn sealed_data_opens_only_with_its_key_and_associated_data_unaltered() {
    let keys = Keys::new(&secret(1));
    let key = keys.state();
    let sealed = seal(&key, b"ad", b"settings").unwrap();
    assert_eq!(open(&key, b"ad", &sealed).unwrap(), b"settings");
    assert_eq!(open(&key, b"other", &sealed), Err(Tampered));
    assert_eq!(
        open(&Keys::new(&secret(2)).state(), b"ad", &sealed),
        Err(Tampered)
    );
    let mut altered = sealed.clone();
    *altered.last_mut().unwrap() ^= 1;
    assert_eq!(open(&key, b"ad", &altered), Err(Tampered));
    assert_eq!(open(&key, b"ad", &sealed[..10]), Err(Tampered));
    assert_ne!(
        seal(&key, b"ad", b"settings").unwrap(),
        sealed,
        "a fresh nonce each time"
    );
}

#[test]
fn keys_differ_per_purpose_and_per_request() {
    let keys = Keys::new(&secret(1));
    let (a, b) = (keys.answer(&[1; 32]), keys.answer(&[2; 32]));
    assert_ne!(a, b);
    assert_ne!(a, keys.state());
    assert_eq!(keys.etag("x"), keys.etag("x"));
    assert_ne!(keys.etag("x"), keys.etag("y"));
    assert_ne!(
        keys.etag("x"),
        Keys::new(&secret(2)).etag("x"),
        "keyed with the secret"
    );
}

#[test]
fn an_answer_cannot_be_replayed_to_another_request_or_its_etag_altered() {
    let origin = Origin::new(
        &secret(1),
        &settings("[blocking]\nblock = [\"ads.example\"]\n"),
        Arc::default(),
    )
    .unwrap();
    let nonce = [7u8; NONCE_LEN];
    let (etag, sealed) = origin.answer(&hex::encode(&nonce), None).unwrap();
    let keys = Keys::new(&secret(1));
    assert!(open(&keys.answer(&nonce), &answer_ad(&etag), &sealed).is_ok());
    assert_eq!(
        open(&keys.answer(&[8; NONCE_LEN]), &answer_ad(&etag), &sealed),
        Err(Tampered)
    );
    assert_eq!(
        open(&keys.answer(&nonce), &answer_ad("\"other\""), &sealed),
        Err(Tampered)
    );
    assert!(origin.answer("not hex", None).is_err());
}

#[test]
fn unchanged_counts_only_for_the_settings_a_replica_has() {
    let origin = Origin::new(
        &secret(1),
        &settings("[blocking]\nblock = [\"ads.example\"]\n"),
        Arc::default(),
    )
    .unwrap();
    let keys = Keys::new(&secret(1));
    let nonce = [7u8; NONCE_LEN];
    let current = origin.published.load().etag.clone();
    // What the origin answers when `If-None-Match` names its current
    // settings, whoever put that there.
    let (etag, sealed) = origin.answer(&hex::encode(&nonce), Some(&current)).unwrap();
    assert_eq!(etag, current);

    assert_eq!(
        opened(&keys, &nonce, Some(&current), etag.clone(), &sealed).unwrap(),
        Fetched::Unchanged
    );
    for have in [None, Some("\"older\"")] {
        let error = opened(&keys, &nonce, have, etag.clone(), &sealed).unwrap_err();
        assert!(matches!(error, SyncError::NotOurs), "{have:?}: {error}");
    }
}

struct Running {
    url: Url,
    origin: Arc<Origin>,
    metrics: Arc<metrics::State>,
    shutdown: CancellationToken,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

fn start_origin(secret_byte: u8, toml: &str) -> Running {
    let metrics = Arc::new(metrics::State::new(config::Role::Origin));
    let origin =
        Arc::new(Origin::new(&secret(secret_byte), &settings(toml), Arc::clone(&metrics)).unwrap());
    let listeners = HttpListeners::bind(&[SocketAddr::from((Ipv4Addr::LOCALHOST, 0))]).unwrap();
    let url = Url::parse(&format!("http://{}", listeners.addresses()[0])).unwrap();
    let allow = vec![config::Network("127.0.0.0/8".parse().unwrap())];
    let shutdown = CancellationToken::new();
    tokio::spawn(http::serve(
        listeners,
        Arc::clone(&origin).router(),
        allow,
        shutdown.clone(),
    ));
    Running {
        url,
        origin,
        metrics,
        shutdown,
    }
}

fn replica(url: &Url, secret_byte: u8, dir: &Path) -> Replica {
    Replica::new(url, &secret(secret_byte), dir).unwrap()
}

#[tokio::test]
async fn a_replica_fetches_the_settings_then_unchanged_until_they_change() {
    let running = start_origin(1, "[blocking]\nblock = [\"ads.example\"]\n");
    let dir = tempfile::tempdir().unwrap();
    let replica = replica(&running.url, 1, dir.path());

    let Fetched::Changed(first) = replica.fetch(None).await.unwrap() else {
        panic!("settings expected")
    };
    assert_eq!(
        settings(&first.text),
        settings("[blocking]\nblock = [\"ads.example\"]\n")
    );
    assert_eq!(
        replica.fetch(Some(&first.etag)).await.unwrap(),
        Fetched::Unchanged
    );

    running
        .origin
        .publish(&settings("[blocking]\nblock = [\"tracker.example\"]\n"))
        .unwrap();
    let Fetched::Changed(second) = replica.fetch(Some(&first.etag)).await.unwrap() else {
        panic!()
    };
    assert_ne!(second.etag, first.etag);
    assert!(second.text.contains("tracker.example"));

    let replicas = metrics::render(&snapshot(&running.metrics));
    assert!(
        replicas
            .contains("zinkhole_sync_replica_last_fetch_timestamp_seconds{replica=\"127.0.0.1\"}"),
        "{replicas}"
    );
}

fn snapshot(state: &metrics::State) -> metrics::Snapshot<'_> {
    static QUERIES: std::sync::LazyLock<metrics::Queries> =
        std::sync::LazyLock::new(metrics::Queries::default);
    metrics::Snapshot {
        queries: &QUERIES,
        upstream: Vec::new(),
        counts: crate::policy::Counts::default(),
        cache_entries: 0,
        lists: Arc::new(crate::policy::Lists::empty()),
        state,
    }
}

#[tokio::test]
async fn a_replica_with_another_secret_gets_nothing_it_can_open() {
    let running = start_origin(1, "");
    let dir = tempfile::tempdir().unwrap();
    let error = replica(&running.url, 2, dir.path())
        .fetch(None)
        .await
        .unwrap_err();
    assert!(matches!(error, SyncError::Tampered(_)), "{error}");
}

#[tokio::test]
async fn the_origin_wants_a_nonce() {
    let running = start_origin(1, "");
    let dir = tempfile::tempdir().unwrap();
    let replica = replica(&running.url, 1, dir.path());
    let response = replica
        .client
        .get(replica.url.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn the_state_file_is_sealed_owner_only_and_checked() {
    let dir = tempfile::tempdir().unwrap();
    let url = Url::parse("http://127.0.0.1:1").unwrap();
    let replica = replica(&url, 1, dir.path());
    assert!(replica.load_state().unwrap().is_none());

    let synced = Synced {
        etag: "\"abc\"".to_owned(),
        text: "[blocking]\nblock = [\"ads.example\"]\n".to_owned(),
    };
    replica.save_state(&synced).unwrap();
    assert_eq!(replica.load_state().unwrap(), Some(synced.clone()));
    let file = replica.state_file();
    assert_eq!(
        fs::metadata(file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        !fs::read_to_string(file)
            .unwrap_or_default()
            .contains("ads.example"),
        "not readable on disk"
    );

    let other = self::replica(&url, 2, dir.path());
    assert!(matches!(other.load_state(), Err(StateError::Tampered(_))));
    let mut bytes = fs::read(file).unwrap();
    bytes[30] ^= 1;
    fs::write(file, bytes).unwrap();
    assert!(matches!(replica.load_state(), Err(StateError::Tampered(_))));
}

/// A Sync loop for `replica` on an instance with `config`, with nothing
/// synced yet and an interval that never comes round.
fn syncer(replica: Replica, config: &Config, in_force: InForce) -> Syncer {
    Syncer {
        replica,
        server: config.server.clone(),
        in_force: Arc::new(in_force),
        have: None,
        interval: Duration::from_secs(3600),
        now: Arc::new(Notify::new()),
        metrics: Arc::new(metrics::State::new(config::Role::Replica)),
    }
}

#[tokio::test]
async fn the_sync_loop_applies_saves_skips_invalid_settings_and_syncs_on_request() {
    let running = start_origin(1, "[blocking]\nblock = [\"ads.example\"]\n");
    let dir = tempfile::tempdir().unwrap();
    let config = Config::parse(&format!(
        "[server]\nlisten = [\"127.0.0.1:5399\"]\n[upstream]\nservers = [\"9.9.9.9\"]\n[sync]\nrole = \"replica\"\norigin = \"{}\"\nsecret = \"{}\"\n",
        running.url,
        hex::encode(&[1; 32])
    ))
    .unwrap();
    let policy = Arc::new(Policy::new(&PolicySettings::default()));
    let (in_force, _refresh) = InForce::new(Arc::clone(&policy), &PolicySettings::default());
    let metrics = Arc::new(metrics::State::new(config::Role::Replica));
    let now = Arc::new(Notify::new());
    let shutdown = CancellationToken::new();
    let syncer = Syncer {
        now: Arc::clone(&now),
        metrics: Arc::clone(&metrics),
        ..syncer(replica(&running.url, 1, dir.path()), &config, in_force)
    };
    let task = tokio::spawn(syncer.run(shutdown.clone()));
    let blocked = |name: &str| matches!(policy.decide(name, RecordType::A), Decision::Blocked(_));
    let settle = || tokio::time::sleep(Duration::from_millis(300));

    settle().await;
    assert!(blocked("ads.example"), "synced at start");
    assert!(
        replica(&running.url, 1, dir.path())
            .load_state()
            .unwrap()
            .is_some(),
        "saved"
    );

    // A forwarded zone pointing at the replica itself: invalid here.
    running
        .origin
        .publish(&settings("[local.forward]\n\"lan\" = \"127.0.0.1:5399\"\n"))
        .unwrap();
    now.notify_one();
    settle().await;
    assert!(blocked("ads.example"), "the last good settings stay");
    // Polled again, the refused settings are "unchanged": still refused.
    now.notify_one();
    settle().await;
    let text = metrics::render(&snapshot(&metrics));
    assert!(text.contains("zinkhole_sync_rejected 1"), "{text}");

    running
        .origin
        .publish(&settings("[blocking]\nblock = [\"tracker.example\"]\n"))
        .unwrap();
    now.notify_one();
    settle().await;
    assert!(blocked("tracker.example") && !blocked("ads.example"));

    let text = metrics::render(&snapshot(&metrics));
    assert!(text.contains("zinkhole_sync_failures_in_a_row 0"), "{text}");
    assert!(text.contains("zinkhole_sync_rejected 0"), "{text}");
    assert!(
        text.lines()
            .any(|l| l.starts_with("zinkhole_sync_last_success_timestamp_seconds ")),
        "{text}"
    );

    // The origin goes away: failures are counted.
    running.shutdown.cancel();
    settle().await;
    now.notify_one();
    settle().await;
    let text = metrics::render(&snapshot(&metrics));
    assert!(text.contains("zinkhole_sync_failures_in_a_row 1"), "{text}");
    assert!(blocked("tracker.example"));

    shutdown.cancel();
    task.await.unwrap();
}

#[test]
fn a_state_dir_that_cannot_be_written_is_found_at_start_and_on_save() {
    let dir = tempfile::tempdir().unwrap();
    let url = Url::parse("http://127.0.0.1:1").unwrap();
    assert!(
        replica(&url, 1, &dir.path().join("new/state"))
            .check_state_dir()
            .is_ok(),
        "created"
    );

    // A file where the directory should be.
    let blocked = dir.path().join("blocked");
    fs::write(&blocked, "").unwrap();
    let stuck = replica(&url, 1, &blocked.join("state"));
    assert!(stuck.check_state_dir().is_err());

    let config = Config::parse("[upstream]\nservers = [\"9.9.9.9\"]\n").unwrap();
    let policy = Arc::new(Policy::new(&PolicySettings::default()));
    let (in_force, _refresh) = InForce::new(policy, &PolicySettings::default());
    let settings = Synced {
        etag: "\"e\"".to_owned(),
        text: "[blocking]\nblock = [\"ads.example\"]\n".to_owned(),
    };
    let syncer = syncer(stuck, &config, in_force);
    assert!(syncer.apply(&settings), "valid, though not saved");
    let text = metrics::render(&snapshot(&syncer.metrics));
    assert!(text.contains("zinkhole_sync_state_file_ok 0"), "{text}");
}

#[test]
fn an_origin_never_serves_more_than_replicas_accept() {
    let origin = Origin::new(
        &secret(1),
        &settings("[blocking]\nblock = [\"ads.example\"]\n"),
        Arc::default(),
    )
    .unwrap();
    // Long enough to pass as rules, too long once written out.
    let rules: Vec<String> = (0..60_000)
        .map(|i| format!("\"host{i:06}.example\""))
        .collect();
    let huge = settings(&format!("[blocking]\nblock = [{}]\n", rules.join(",")));
    assert!(matches!(
        origin.publish(&huge),
        Err(PublishError::TooLarge(_))
    ));
    assert!(
        origin.published_text().contains("ads.example"),
        "the last settings stay served"
    );
}

#[tokio::test]
async fn a_shutdown_does_not_wait_for_a_fetch_the_origin_never_answers() {
    // Accepts connections and says nothing, like an origin behind a
    // firewall that drops packets.
    let silent = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let url = Url::parse(&format!("http://{}", silent.local_addr().unwrap())).unwrap();
    let held = tokio::spawn(async move {
        let mut connections = Vec::new();
        while let Ok((stream, _)) = silent.accept().await {
            connections.push(stream);
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let config = Config::parse("[upstream]\nservers = [\"9.9.9.9\"]\n").unwrap();
    let policy = Arc::new(Policy::new(&PolicySettings::default()));
    let (in_force, _refresh) = InForce::new(policy, &PolicySettings::default());
    let shutdown = CancellationToken::new();
    let syncer = syncer(replica(&url, 1, dir.path()), &config, in_force);
    let task = tokio::spawn(syncer.run(shutdown.clone()));
    // Long enough for the fetch to be under way.
    tokio::time::sleep(Duration::from_millis(300)).await;
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("well within the fetch timeout")
        .unwrap();
    held.abort();
}
