//! Reloads from a config file on disk.

use std::path::Path;

use hickory_proto::rr::RecordType;

use super::*;
use crate::config::Source;
use crate::policy::Decision;

const BASE: &str = "[upstream]\nservers = [\"127.0.0.1:9\"]\n";

struct Setup {
    _dir: tempfile::TempDir,
    path: PathBuf,
    resolver: Resolver<Upstream>,
    reloader: Reloader,
    refresh: tokio::sync::watch::Receiver<crate::refresh::RefreshSettings>,
}

fn write(path: &Path, toml: &str) {
    std::fs::write(path, format!("{BASE}{toml}")).unwrap();
}

fn setup(toml: &str) -> Setup {
    setup_as(toml, |_| RoleHooks::Alone)
}

fn setup_as(toml: &str, role: impl FnOnce(&Config) -> RoleHooks) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    write(&path, toml);
    let config = Config::load(&path).unwrap();
    let resolver = resolver(&config, Upstream::new(&config.upstream));
    let (in_force, refresh) =
        InForce::new(Arc::clone(resolver.policy()), &config.policy_settings());
    let role = role(&config);
    let reloader = Reloader::new(path.clone(), config, Arc::new(in_force), role, None);
    Setup {
        _dir: dir,
        path,
        resolver,
        reloader,
        refresh,
    }
}

fn decide(setup: &Setup, name: &str) -> Decision {
    setup.resolver.policy().decide(name, RecordType::A)
}

#[test]
fn a_reload_applies_local_records_inline_rules_and_list_sources_at_once() {
    let s = setup("[blocking]\nlists = [\"/lists/a.txt\"]\n");
    assert!(matches!(decide(&s, "nas.lan"), Decision::Private { .. }));
    assert!(matches!(decide(&s, "ads.example"), Decision::Upstream));

    write(
        &s.path,
        "[blocking]\nlists = [\"/lists/b.txt\"]\nblock = [\"ads.example\"]\nrefresh_hours = 0\n[local.records]\n\"nas.lan\" = \"192.168.1.10\"\n",
    );
    s.reloader.reload(&s.resolver).unwrap();
    assert!(matches!(decide(&s, "nas.lan"), Decision::Local { .. }));
    assert!(matches!(decide(&s, "ads.example"), Decision::Blocked(_)));
    let refresh = s.refresh.borrow();
    assert_eq!(
        refresh.sources.blocklists,
        [Source::File("/lists/b.txt".into())]
    );
    assert_eq!(refresh.interval, None);
}

#[test]
fn an_invalid_file_changes_nothing() {
    let s = setup("[blocking]\nblock = [\"ads.example\"]\n");
    write(
        &s.path,
        "[blocking]\nblock = [\"other.example\"]\nnonsense = 1\n",
    );
    let error = s.reloader.reload(&s.resolver).unwrap_err();
    assert!(error.to_string().contains("config.toml"), "{error}");
    assert!(matches!(decide(&s, "ads.example"), Decision::Blocked(_)));
    assert!(matches!(decide(&s, "other.example"), Decision::Upstream));
}

#[test]
fn changing_the_sync_role_is_refused() {
    let s = setup("");
    let secret = "ab".repeat(32);
    write(
        &s.path,
        &format!(
            "[http]\nlisten = [\"127.0.0.1:5380\"]\n[sync]\nrole = \"origin\"\nsecret = \"{secret}\"\n"
        ),
    );
    let error = s.reloader.reload(&s.resolver).unwrap_err();
    assert!(
        matches!(
            error,
            ReloadError::RoleChanged {
                from: Role::Alone,
                to: Role::Origin
            }
        ),
        "{error}"
    );
}

#[test]
fn settings_that_need_a_restart_are_named() {
    let s = setup("");
    let new = Config::parse(&format!(
        "{BASE}timeout_ms = 500\n[server]\nlisten = [\"127.0.0.1:5353\"]\n[log]\nformat = \"json\"\nlevel = \"debug\"\n"
    ))
    .unwrap();
    assert_eq!(
        s.reloader.needs_restart(&new),
        ["server", "upstream", "log.format"]
    );
    let same = Config::parse(&format!("{BASE}[log]\nlevel = \"debug\"\nqueries = true\n")).unwrap();
    assert_eq!(s.reloader.needs_restart(&same), Vec::<&str>::new());
}

#[test]
fn a_changed_sync_section_needs_a_restart() {
    let replica = |origin: &str, secret: &str| {
        format!(
            "[sync]\nrole = \"replica\"\norigin = \"{origin}\"\nsecret = \"{}\"\n",
            secret.repeat(32)
        )
    };
    let s = setup(&replica("http://192.168.1.5:5380", "ab"));
    let parse = |toml: &str| Config::parse(&format!("{BASE}{toml}")).unwrap();
    let moved = parse(&replica("http://192.168.1.6:5380", "ab"));
    assert_eq!(s.reloader.needs_restart(&moved), ["sync"]);
    let new_secret = parse(&replica("http://192.168.1.5:5380", "cd"));
    assert_eq!(s.reloader.needs_restart(&new_secret), ["sync"]);
    let same = parse(&replica("http://192.168.1.5:5380", "ab"));
    assert_eq!(s.reloader.needs_restart(&same), Vec::<&str>::new());
}

#[tokio::test]
async fn a_replica_keeps_its_synced_settings_on_a_reload_and_syncs_at_once() {
    let secret = "ab".repeat(32);
    let replica = format!(
        "[sync]\nrole = \"replica\"\norigin = \"http://127.0.0.1:5380\"\nsecret = \"{secret}\"\n"
    );
    let sync_now = Arc::new(Notify::new());
    let hooks = Arc::clone(&sync_now);
    let s = setup_as(&replica, move |_| RoleHooks::Replica(hooks));
    // As if synced from the origin.
    let synced: PolicySettings = toml::from_str("[blocking]\nblock = [\"ads.example\"]\n").unwrap();
    s.resolver.policy().apply(&synced);

    s.reloader.reload(&s.resolver).unwrap();
    assert!(
        matches!(decide(&s, "ads.example"), Decision::Blocked(_)),
        "still in force"
    );
    let notified =
        tokio::time::timeout(std::time::Duration::from_secs(1), sync_now.notified()).await;
    assert!(notified.is_ok(), "a sync was asked for");
}

#[test]
fn an_origin_serves_what_a_reload_puts_in_force() {
    let secret = "ab".repeat(32);
    let origin_config = format!(
        "[http]\nlisten = [\"127.0.0.1:5380\"]\n[sync]\nrole = \"origin\"\nsecret = \"{secret}\"\n"
    );
    let mut origin = None;
    let s = setup_as(&origin_config, |config| {
        let Some(config::Sync::Origin { secret }) = &config.sync else {
            panic!()
        };
        let made =
            Arc::new(Origin::new(secret, &config.policy_settings(), Arc::default()).unwrap());
        origin = Some(Arc::clone(&made));
        RoleHooks::Origin(made)
    });
    let origin = origin.unwrap();
    let before = origin.published_text();
    write(
        &s.path,
        &format!("{origin_config}[blocking]\nblock = [\"ads.example\"]\n"),
    );
    s.reloader.reload(&s.resolver).unwrap();
    assert_ne!(origin.published_text(), before);
    assert!(origin.published_text().contains("ads.example"));
}

#[test]
fn the_summary_names_every_outcome_with_its_count() {
    use crate::resolver::Outcome;

    let queries = metrics::Queries::default();
    queries.record(Outcome::Blocked);
    queries.record(Outcome::Blocked);
    queries.record(Outcome::Local);
    let summary = summary(&queries);
    assert!(summary.starts_with("local=1 blocked=2 "), "{summary}");
    for outcome in Outcome::ALL {
        assert!(
            summary.contains(&format!("{outcome}=")),
            "{outcome}: {summary}"
        );
    }
}
