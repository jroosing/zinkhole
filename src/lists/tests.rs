//! Loading lists from files and from HTTP(S) stubs on loopback.

use hickory_proto::rr::RecordType;

use super::*;
use crate::config::Config;
use crate::policy::{Decision, Policy, Replacement};
use crate::stub::{HttpStub, Reply};

fn loader(roots: Option<&rustls::RootCertStore>) -> Loader {
    let roots = roots.cloned().unwrap_or_else(rustls::RootCertStore::empty);
    Loader::with(roots, Duration::from_millis(500), 1024).unwrap()
}

fn source(text: &str) -> Source {
    Source::try_from(text.to_owned()).unwrap()
}

fn sources(blocklists: &[String], allowlists: &[String]) -> Sources {
    Sources {
        blocklists: blocklists.iter().map(|s| source(s)).collect(),
        allowlists: allowlists.iter().map(|s| source(s)).collect(),
    }
}

/// Which sources loaded, in order.
fn results(lists: &Lists) -> Vec<bool> {
    lists.results().map(|(_, _, loaded)| loaded).collect()
}

/// True if the Policy with `lists` blocks `name`.
fn blocks(lists: Lists, name: &str) -> bool {
    let config = Config::parse("[upstream]\nservers = [\"9.9.9.9\"]\n").unwrap();
    let policy = Policy::new(&config.policy_settings());
    assert_eq!(policy.replace_lists(lists), Replacement::Replaced);
    matches!(policy.decide(name, RecordType::A), Decision::Blocked(_))
}

#[tokio::test]
async fn lists_load_from_files_and_urls_and_allowlists_win() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("hosts.txt");
    std::fs::write(
        &file,
        "# a hosts file\n0.0.0.0 tracker.example\n0.0.0.0 cdn.example",
    )
    .unwrap();
    let http = HttpStub::start(false).await;
    http.route(
        "/adblock.txt",
        Reply::Body("||ads.example^\n@@||good.ads.example^\n".to_owned()),
    );
    http.route("/allow.txt", Reply::Body("cdn.example\n".to_owned()));

    let lists = loader(None)
        .load(sources(
            &[file.display().to_string(), http.url("/adblock.txt")],
            &[http.url("/allow.txt")],
        ))
        .await;
    assert!(lists.is_complete());
    assert_eq!((lists.blocked_domains(), lists.allowed_domains()), (3, 2));
    assert!(blocks(lists, "x.ads.example"));
}

#[tokio::test]
async fn gzip_lists_are_decompressed() {
    let http = HttpStub::start(false).await;
    http.route(
        "/list.gz",
        Reply::Gzip("ads.example\n".repeat(3) + "tracker.example\n"),
    );
    let lists = loader(None)
        .load(sources(&[http.url("/list.gz")], &[]))
        .await;
    assert!(lists.is_complete());
    assert_eq!(lists.blocked_domains(), 2);
}

#[tokio::test]
async fn a_failed_source_makes_the_lists_incomplete_and_the_others_still_load() {
    let http = HttpStub::start(false).await;
    http.route("/good.txt", Reply::Body("ads.example\n".to_owned()));
    http.route("/gone.txt", Reply::Status(404));
    let lists = loader(None)
        .load(sources(
            &[
                http.url("/gone.txt"),
                "/no/such/list.txt".to_owned(),
                http.url("/good.txt"),
            ],
            &[],
        ))
        .await;
    assert!(!lists.is_complete());
    assert_eq!(results(&lists), [false, false, true]);
    assert!(blocks(lists, "ads.example"));
}

#[tokio::test]
async fn a_list_over_its_size_limit_fails() {
    let http = HttpStub::start(false).await;
    // 1024 bytes allowed.
    let big = "host.example\n".repeat(200);
    http.route("/big.txt", Reply::Body(big));
    let lists = loader(None)
        .load(sources(&[http.url("/big.txt")], &[]))
        .await;
    assert_eq!(results(&lists), [false]);
}

#[tokio::test]
async fn a_server_that_stops_sending_is_given_up_on_and_the_next_source_loads() {
    let http = HttpStub::start(false).await;
    http.route("/stall.txt", Reply::Stall);
    http.route("/good.txt", Reply::Body("tracker.example\n".to_owned()));
    let started = Instant::now();
    let lists = loader(None)
        .load(sources(
            &[http.url("/stall.txt"), http.url("/good.txt")],
            &[],
        ))
        .await;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(results(&lists), [false, true]);
}

#[tokio::test]
async fn https_lists_load_and_follow_redirects_but_never_down_to_http() {
    let https = HttpStub::start(true).await;
    let http = HttpStub::start(false).await;
    http.route("/list.txt", Reply::Body("ads.example\n".to_owned()));
    https.route("/list.txt", Reply::Body("ads.example\n".to_owned()));
    https.route("/moved.txt", Reply::Redirect(https.url("/list.txt")));
    https.route("/downgrade.txt", Reply::Redirect(http.url("/list.txt")));

    let lists = loader(https.roots.as_ref())
        .load(sources(
            &[
                https.url("/list.txt"),
                https.url("/moved.txt"),
                https.url("/downgrade.txt"),
            ],
            &[],
        ))
        .await;
    assert_eq!(results(&lists), [true, true, false]);
    assert_eq!(http.requests(), 0, "the http URL was never fetched");

    // From http, a redirect anywhere is followed.
    http.route("/moved.txt", Reply::Redirect(https.url("/list.txt")));
    let lists = loader(https.roots.as_ref())
        .load(sources(&[http.url("/moved.txt")], &[]))
        .await;
    assert_eq!(results(&lists), [true]);
}

#[tokio::test]
async fn a_certificate_nobody_vouches_for_fails() {
    let https = HttpStub::start(true).await;
    https.route("/list.txt", Reply::Body("ads.example\n".to_owned()));
    let lists = loader(None)
        .load(sources(&[https.url("/list.txt")], &[]))
        .await;
    assert_eq!(results(&lists), [false]);
    assert_eq!(https.requests(), 0);
}

#[tokio::test]
async fn no_sources_make_complete_empty_lists() {
    let lists = loader(None).load(Sources::default()).await;
    assert!(lists.is_complete());
    assert_eq!(lists.blocked_domains(), 0);
}

#[test]
fn urls_are_logged_without_credentials_or_query() {
    let shown = shown(&source(
        "https://user:secret@lists.example/ads.txt?token=abc#x",
    ));
    assert_eq!(shown, "https://lists.example/ads.txt");
    assert_eq!(
        super::shown(&source("/etc/zinkhole/ads.txt")),
        "/etc/zinkhole/ads.txt"
    );
}

#[tokio::test]
async fn errors_do_not_show_the_tokens_in_list_urls() {
    // Nothing listens on port 1: the request fails with reqwest's error.
    let failed = loader(None)
        .load_source(
            &source("http://127.0.0.1:1/list.txt?token=SECRET"),
            &mut |_| {},
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        failed.contains("127.0.0.1:1") || failed.contains("connect"),
        "{failed}"
    );
    assert!(!failed.contains("SECRET"), "{failed}");

    // A refused https-to-http redirect names its target without the query.
    let https = HttpStub::start(true).await;
    https.route(
        "/moved.txt",
        Reply::Redirect("http://127.0.0.1:1/list.txt?token=SECRET".to_owned()),
    );
    let refused = loader(https.roots.as_ref())
        .load_source(&source(&https.url("/moved.txt")), &mut |_| {})
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("refused a redirect"), "{refused}");
    assert!(!refused.contains("SECRET"), "{refused}");
}

#[tokio::test]
async fn a_load_that_runs_out_of_time_keeps_what_loaded_and_fails_the_rest() {
    let http = HttpStub::start(false).await;
    http.route("/first.txt", Reply::Body("ads.example\n".to_owned()));
    http.route("/stall.txt", Reply::Stall);
    http.route("/last.txt", Reply::Body("tracker.example\n".to_owned()));
    // Each source may take 500 ms, the whole load 400 ms.
    let loader = loader(None).load_timeout(Duration::from_millis(400));
    let started = Instant::now();
    let lists = loader
        .load(sources(
            &[
                http.url("/first.txt"),
                http.url("/stall.txt"),
                http.url("/last.txt"),
            ],
            &[],
        ))
        .await;
    assert!(
        started.elapsed() < Duration::from_millis(480),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(results(&lists), [true, false, false]);
    assert_eq!(http.requests(), 2, "the last source was not even asked");
    assert!(blocks(lists, "ads.example"), "the first list is kept");
}
