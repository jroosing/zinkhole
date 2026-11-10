//! The `zinkhole` command, run as a user would.

// Test-only crate: a failed setup step should panic the test.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::Path;
use std::process::{Command, Output};

fn zinkhole(args: &[&str], config: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zinkhole"));
    command.args(args).env_remove("ZINKHOLE_CONFIG");
    if let Some(path) = config {
        command.env("ZINKHOLE_CONFIG", path);
    }
    command.output().expect("run zinkhole")
}

fn write_config(dir: &tempfile::TempDir, text: &str) -> std::path::PathBuf {
    let path = dir.path().join("config.toml");
    std::fs::write(&path, text).expect("write config");
    path
}

#[test]
fn check_accepts_the_example_config() {
    let out = zinkhole(&["check", "-c", "config.example.toml"], None);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "configuration OK\n");
}

#[test]
fn check_rejects_an_invalid_config_and_names_the_file_and_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        &dir,
        "[upstream]\nservers = [\"9.9.9.9\"]\n\n[cache]\nmin_ttl = -1\n",
    );
    let out = zinkhole(&["check"], Some(&path));
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("config.toml") && stderr.contains("line 5"),
        "{stderr}"
    );
    assert_eq!(out.stdout.len(), 0);
}

#[test]
fn a_missing_config_file_is_an_error() {
    let out = zinkhole(&["check", "-c", "/no/such/zinkhole.toml"], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read /no/such/zinkhole.toml"));
}

#[test]
fn the_config_flag_wins_over_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    let broken = write_config(&dir, "not toml");
    let out = zinkhole(&["check", "-c", "config.example.toml"], Some(&broken));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn without_a_subcommand_it_prints_help_and_exits_2() {
    let out = zinkhole(&[], None);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Usage"));
}

#[test]
fn secret_prints_64_hex_digits() {
    let out = zinkhole(&["secret"], None);
    assert_eq!(out.status.code(), Some(0));
    let secret = String::from_utf8(out.stdout).unwrap();
    let secret = secret.trim_end();
    assert_eq!(secret.len(), 64);
    assert!(secret.bytes().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn healthcheck_fails_when_nothing_answers() {
    // A bound but silent socket: the check must give up, not hang.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = silent.local_addr().unwrap().to_string();
    let out = zinkhole(&["healthcheck", &address], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unhealthy"));
}

/// A loopback port free for UDP and TCP a moment ago.
fn free_port() -> u16 {
    loop {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

fn serve_config(dir: &tempfile::TempDir, port: u16) -> std::path::PathBuf {
    write_config(
        dir,
        &format!(
            "[server]\nlisten = [\"127.0.0.1:{port}\"]\n\n[upstream]\nservers = [\"127.0.0.1:9\"]\n"
        ),
    )
}

/// Polls `done` for up to five seconds.
fn within_five_seconds(mut done: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

#[test]
fn serve_answers_until_sigterm_and_then_exits_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = serve_config(&dir, port);
    let mut server = Command::new(env!("CARGO_BIN_EXE_zinkhole"))
        .args(["serve", "-c"])
        .arg(&config)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let address = format!("127.0.0.1:{port}");
    let healthy =
        within_five_seconds(|| zinkhole(&["healthcheck", &address], None).status.success());
    let terminated = Command::new("kill")
        .args(["-TERM", &server.id().to_string()])
        .status()
        .unwrap();
    assert!(terminated.success());
    let mut status = None;
    assert!(within_five_seconds(|| {
        status = server.try_wait().unwrap();
        status.is_some()
    }));
    let out = server.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(healthy, "{stderr}");
    assert_eq!(status.and_then(|s| s.code()), Some(0), "{stderr}");
    assert!(
        stderr.contains(&address) && stderr.contains("SIGTERM"),
        "{stderr}"
    );
}

#[test]
fn serve_fails_when_the_port_is_taken() {
    let dir = tempfile::tempdir().unwrap();
    let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let config = serve_config(&dir, taken.local_addr().unwrap().port());
    let out = zinkhole(&["serve"], Some(&config));
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot listen on 127.0.0.1:"), "{stderr}");
}

#[test]
fn check_lists_loads_every_list_and_fails_when_one_does_not_load() {
    let dir = tempfile::tempdir().unwrap();
    let list = dir.path().join("ads.txt");
    std::fs::write(&list, "0.0.0.0 ads.example\n0.0.0.0 tracker.example\n").unwrap();
    let config = |lists: &str| {
        write_config(
            &dir,
            &format!(
                "[upstream]\nservers = [\"9.9.9.9\"]\n[blocking]\nblock = [\"x.example\"]\nlists = [{lists}]\n"
            ),
        )
    };

    let path = config(&format!("{:?}", list.display().to_string()));
    let out = zinkhole(&["check", "--lists"], Some(&path));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "configuration OK: 0 local records, 1 inline rules, 2 blocked and 0 allowed domains from lists\n"
    );

    let path = config(&format!(
        "{:?}, \"/no/such/list.txt\"",
        list.display().to_string()
    ));
    let out = zinkhole(&["check", "--lists"], Some(&path));
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("/no/such/list.txt") && stderr.contains("some lists failed"),
        "{stderr}"
    );
}

/// The answer of the server on `port` to an A query for `name`, if any
/// within a second.
fn ask(port: u16, name: &str) -> Option<hickory_proto::op::Message> {
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .unwrap();
    socket
        .send_to(&query.to_vec().unwrap(), ("127.0.0.1", port))
        .unwrap();
    let mut buffer = [0u8; 4096];
    let len = socket.recv(&mut buffer).ok()?;
    Message::from_vec(&buffer[..len]).ok()
}

fn signal(child: &std::process::Child, name: &str) {
    let sent = Command::new("kill")
        .args([&format!("-{name}"), &child.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
}

#[test]
fn sighup_reloads_the_config_and_sigusr1_logs_a_summary() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let base = format!(
        "[server]\nlisten = [\"127.0.0.1:{port}\"]\n\n[upstream]\nservers = [\"127.0.0.1:9\"]\n"
    );
    let config = write_config(&dir, &base);
    let server = Command::new(env!("CARGO_BIN_EXE_zinkhole"))
        .args(["serve", "-c"])
        .arg(&config)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let nas_answer = || {
        ask(port, "nas.lan.")
            .and_then(|answer| answer.answers.first().map(|record| record.data.to_string()))
    };

    assert!(
        within_five_seconds(|| ask(port, "nas.lan.").is_some()),
        "the server answers"
    );
    assert_eq!(nas_answer(), None, "a private name, NXDOMAIN");

    std::fs::write(
        &config,
        format!("{base}[log]\nqueries = true\n[local.records]\n\"nas.lan\" = \"192.168.1.10\"\n"),
    )
    .unwrap();
    signal(&server, "HUP");
    assert!(within_five_seconds(
        || nas_answer().as_deref() == Some("192.168.1.10")
    ));
    signal(&server, "USR1");
    std::thread::sleep(std::time::Duration::from_millis(200));
    signal(&server, "TERM");
    let out = server.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("configuration reloaded"), "{stderr}");
    assert!(
        stderr.contains("queries since start") && stderr.contains("local=1"),
        "{stderr}"
    );
    assert!(
        stderr.contains("zinkhole::query") && stderr.contains("name=nas.lan"),
        "{stderr}"
    );
}

/// The body of `GET path` on the HTTP port, if it answers.
fn http_get(port: u16, path: &str) -> Option<String> {
    use std::io::{Read as _, Write as _};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    write!(stream, "GET {path} HTTP/1.1\r\nHost: zinkhole\r\n\r\n").ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    head.starts_with("HTTP/1.1 200 ").then(|| body.to_owned())
}

#[test]
fn serve_shows_the_metrics_on_the_http_port() {
    let dir = tempfile::tempdir().unwrap();
    let (dns, http) = (free_port(), free_port());
    let config = write_config(
        &dir,
        &format!(
            "[server]\nlisten = [\"127.0.0.1:{dns}\"]\n[upstream]\nservers = [\"127.0.0.1:9\"]\n[http]\nlisten = [\"127.0.0.1:{http}\"]\n"
        ),
    );
    let server = Command::new(env!("CARGO_BIN_EXE_zinkhole"))
        .args(["serve", "-c"])
        .arg(&config)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    assert!(within_five_seconds(|| ask(dns, "nas.lan.").is_some()));
    let metrics = http_get(http, "/metrics");
    signal(&server, "TERM");
    let out = server.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let metrics = metrics.unwrap_or_else(|| panic!("no metrics; {stderr}"));
    assert!(
        metrics.contains("zinkhole_queries_total{outcome=\"private\"} 1"),
        "{metrics}"
    );
    assert!(
        stderr.contains(&format!("http://127.0.0.1:{http}/metrics")),
        "{stderr}"
    );
    assert_eq!(out.status.code(), Some(0), "{stderr}");
}

fn spawn_serve(config: &Path) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_zinkhole"))
        .args(["serve", "-c"])
        .arg(config)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
}

/// Stops `server` and returns what it logged.
fn stop(server: std::process::Child) -> String {
    signal(&server, "TERM");
    let out = server.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    stderr
}

#[test]
fn a_replica_follows_its_origin_and_starts_from_its_saved_settings_when_it_is_down() {
    let dir = tempfile::tempdir().unwrap();
    let (origin_dns, origin_http, replica_dns) = (free_port(), free_port(), free_port());
    let secret = String::from_utf8(zinkhole(&["secret"], None).stdout).unwrap();
    let secret = secret.trim();
    let origin_config = dir.path().join("origin.toml");
    let origin_text = |address: &str| {
        format!(
            "[server]\nlisten = [\"127.0.0.1:{origin_dns}\"]\n[upstream]\nservers = [\"127.0.0.1:9\"]\n\
             [http]\nlisten = [\"127.0.0.1:{origin_http}\"]\n[sync]\nrole = \"origin\"\nsecret = \"{secret}\"\n\
             [local.records]\n\"nas.lan\" = \"{address}\"\n"
        )
    };
    std::fs::write(&origin_config, origin_text("192.168.1.10")).unwrap();
    let state_dir = dir.path().join("state");
    std::fs::create_dir(&state_dir).unwrap();
    let replica_config = dir.path().join("replica.toml");
    std::fs::write(
        &replica_config,
        format!(
            "[server]\nlisten = [\"127.0.0.1:{replica_dns}\"]\n[upstream]\nservers = [\"127.0.0.1:9\"]\n\
             [sync]\nrole = \"replica\"\norigin = \"http://127.0.0.1:{origin_http}\"\nsecret = \"{secret}\"\n\
             interval_secs = 1\nstate_dir = {:?}\n",
            state_dir.display().to_string()
        ),
    )
    .unwrap();
    let nas = |port: u16| {
        ask(port, "nas.lan.")
            .and_then(|answer| answer.answers.first().map(|record| record.data.to_string()))
    };

    let origin = spawn_serve(&origin_config);
    let replica = spawn_serve(&replica_config);
    assert!(
        within_five_seconds(|| nas(replica_dns).as_deref() == Some("192.168.1.10")),
        "synced"
    );

    std::fs::write(&origin_config, origin_text("192.168.1.11")).unwrap();
    signal(&origin, "HUP");
    assert!(
        within_five_seconds(|| nas(replica_dns).as_deref() == Some("192.168.1.11")),
        "followed"
    );

    let origin_log = stop(origin);
    let replica_log = stop(replica);
    assert!(origin_log.contains("/sync"), "{origin_log}");
    assert!(
        replica_log.contains("applied the settings synced from the origin"),
        "{replica_log}"
    );

    // The origin is down: the replica starts from what it saved.
    let replica = spawn_serve(&replica_config);
    assert!(
        within_five_seconds(|| nas(replica_dns).as_deref() == Some("192.168.1.11")),
        "from the state file"
    );
    let replica_log = stop(replica);
    assert!(
        replica_log.contains("starting from the settings synced earlier"),
        "{replica_log}"
    );
}

#[test]
fn healthcheck_without_an_address_asks_where_the_config_listens() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = serve_config(&dir, port);
    let server = spawn_serve(&config);
    let healthy =
        within_five_seconds(|| zinkhole(&["healthcheck"], Some(&config)).status.success());
    stop(server);
    assert!(healthy, "port {port} from the config");
    // Nothing listens there any more.
    assert_eq!(
        zinkhole(&["healthcheck"], Some(&config)).status.code(),
        Some(1)
    );
}
