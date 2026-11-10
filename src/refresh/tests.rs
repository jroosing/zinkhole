//! The schedule with time passed in, and the runner on tokio's paused clock.

use hickory_proto::rr::RecordType;

use super::*;
use crate::config::{Config, Source};
use crate::policy::Decision;

const HOUR: Duration = Duration::from_hours(1);
const H: Option<Duration> = Some(HOUR);

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// Instants as seconds after one fixed start.
struct Clock(Instant);

impl Clock {
    fn new() -> Clock {
        Clock(Instant::now())
    }
    fn at(&self, s: u64) -> Instant {
        self.0 + secs(s)
    }
}

#[test]
fn the_first_check_starts_a_load() {
    let t = Clock::new();
    assert_eq!(Schedule::default().next(t.at(0), H), Action::Start);
}

#[test]
fn a_hung_load_is_left_alone_and_canceled_after_eleven_minutes() {
    let t = Clock::new();
    let mut s = Schedule::default();
    s.started(t.at(100));
    assert_eq!(s.next(t.at(101), H), Action::Idle);
    assert_eq!(s.next(t.at(100 + 660), H), Action::Idle);
    assert_eq!(s.next(t.at(100 + 661), H), Action::Cancel);
    // The canceled load counts as incomplete.
    s.finished(t.at(701), false, H);
    assert_eq!(s.next(t.at(701 + 59), H), Action::Idle);
    assert_eq!(s.next(t.at(701 + 60), H), Action::Start);
}

#[test]
fn the_next_load_is_one_interval_after_a_complete_load_or_the_retry_after_a_failed_one() {
    let t = Clock::new();
    let mut s = Schedule::default();
    assert_eq!(s.due(H), None, "the first is about to start");
    s.started(t.at(10));
    assert_eq!(s.due(H), None);
    s.finished(t.at(20), true, H);
    assert_eq!(s.due(H), Some(t.at(20) + HOUR));
    assert_eq!(s.due(None), None);
    s.started(t.at(20) + HOUR);
    s.finished(t.at(30) + HOUR, false, H);
    assert_eq!(s.due(H), Some(t.at(30 + 60) + HOUR));
    s.sources_changed();
    assert_eq!(s.due(H), None);
}

#[test]
fn after_a_complete_load_the_next_starts_one_interval_later_or_never_without_one() {
    let t = Clock::new();
    let mut s = Schedule::default();
    s.started(t.at(0));
    s.finished(t.at(10), true, H);
    assert_eq!(s.next(t.at(11), H), Action::Idle);
    assert_eq!(s.next(t.at(10 + 3599), H), Action::Idle);
    assert_eq!(s.next(t.at(10) + HOUR, H), Action::Start);
    assert_eq!(s.next(t.at(10) + HOUR * 24_000, None), Action::Idle);
}

/// Fails a load at `now` and checks it is retried exactly `delay` later.
fn assert_retry_after(
    s: &mut Schedule,
    t: &Clock,
    now: u64,
    interval: Option<Duration>,
    delay: u64,
) {
    s.started(t.at(now));
    assert_eq!(s.finished(t.at(now), false, interval), Some(secs(delay)));
    assert_eq!(s.next(t.at(now + delay - 1), interval), Action::Idle);
    assert_eq!(s.next(t.at(now + delay), interval), Action::Start);
}

#[test]
fn incomplete_loads_are_retried_with_a_doubling_delay_capped_at_the_interval_or_a_day() {
    let t = Clock::new();
    let mut s = Schedule::default();
    let mut now = 0;
    for delay in [60, 120, 240, 480, 960, 1920, 3600, 3600] {
        assert_retry_after(&mut s, &t, now, H, delay);
        now += delay;
    }

    let mut no_refresh = Schedule::default();
    let mut now = 0;
    let day = 24 * 3600;
    for delay in [
        60, 120, 240, 480, 960, 1920, 3840, 7680, 15360, 30720, 61440, day, day,
    ] {
        assert_retry_after(&mut no_refresh, &t, now, None, delay);
        now += delay;
    }
}

#[test]
fn a_complete_load_resets_the_retry_delay() {
    let t = Clock::new();
    let mut s = Schedule::default();
    assert_retry_after(&mut s, &t, 0, H, 60);
    assert_retry_after(&mut s, &t, 60, H, 120);
    s.started(t.at(180));
    s.finished(t.at(190), true, H);
    assert_retry_after(&mut s, &t, 190 + 3600, H, 60);
}

#[test]
fn a_changed_interval_applies_at_once() {
    let t = Clock::new();
    let mut s = Schedule::default();
    s.started(t.at(0));
    s.finished(t.at(0), true, H);
    // 24 h -> 1 h, three hours after the last load: load now.
    let three_hours = t.at(0) + HOUR * 3;
    assert_eq!(s.next(three_hours, Some(HOUR * 24)), Action::Idle);
    assert_eq!(s.next(three_hours, H), Action::Start);
    // Refresh turned off, then on again.
    assert_eq!(s.next(three_hours, None), Action::Idle);
    assert_eq!(s.next(t.at(0) + HOUR * 24, Some(HOUR * 24)), Action::Start);
}

#[test]
fn changed_sources_start_a_load_at_once_with_a_fresh_retry_delay() {
    let t = Clock::new();
    let mut s = Schedule::default();
    s.started(t.at(0));
    s.finished(t.at(0), true, H);
    s.sources_changed();
    assert_eq!(s.next(t.at(10), H), Action::Start);

    // While retrying the old sources.
    let mut retrying = Schedule::default();
    assert_retry_after(&mut retrying, &t, 0, H, 60);
    assert_retry_after(&mut retrying, &t, 60, H, 120);
    retrying.sources_changed();
    assert_eq!(retrying.next(t.at(181), H), Action::Start);
    assert_retry_after(&mut retrying, &t, 181, H, 60);
}

#[test]
fn changed_sources_cancel_the_running_load_without_counting_a_failure() {
    let t = Clock::new();
    let mut s = Schedule::default();
    s.started(t.at(0));
    s.sources_changed();
    assert_eq!(s.next(t.at(5), H), Action::Cancel);
    assert_eq!(s.finished(t.at(5), false, H), None);
    assert_eq!(s.next(t.at(5), H), Action::Start);
    // The canceled load did not count: the next failure waits 60 s, not 120.
    assert_retry_after(&mut s, &t, 6, H, 60);
}

#[test]
fn a_load_that_could_not_start_waits_for_the_retry_delay() {
    let t = Clock::new();
    let mut s = Schedule::default();
    s.finished(t.at(0), false, H);
    assert_eq!(s.next(t.at(59), H), Action::Idle);
    assert_eq!(s.next(t.at(60), H), Action::Start);

    // Also right after the sources changed: no new attempt at once.
    let mut changed = Schedule::default();
    changed.started(t.at(0));
    changed.finished(t.at(0), true, H);
    changed.sources_changed();
    changed.finished(t.at(10), false, H);
    assert_eq!(changed.next(t.at(11), H), Action::Idle);
    assert_eq!(changed.next(t.at(70), H), Action::Start);
}

// ---------------------------------------------------------------------------
// The runner

struct Running {
    policy: Arc<Policy>,
    settings: watch::Sender<RefreshSettings>,
    shutdown: CancellationToken,
    task: JoinHandle<()>,
}

fn start(lists: &[&std::path::Path], refresh_hours: u32) -> Running {
    let config = Config::parse(&format!(
        "[upstream]\nservers = [\"9.9.9.9\"]\n[blocking]\nrefresh_hours = {refresh_hours}\nlists = [{}]\n",
        lists.iter().map(|path| format!("{:?}", path.display().to_string())).collect::<Vec<_>>().join(", ")
    ))
    .unwrap_or_else(|e| panic!("{e}"));
    let settings = config.policy_settings();
    let policy = Arc::new(Policy::new(&settings));
    let (sender, receiver) = watch::channel(RefreshSettings::of(&settings));
    let shutdown = CancellationToken::new();
    let loader = Loader::with(rustls::RootCertStore::empty(), secs(5), 1 << 20).unwrap();
    let task = tokio::spawn(run(
        Arc::clone(&policy),
        loader,
        receiver,
        Arc::new(metrics::State::default()),
        shutdown.clone(),
    ));
    Running {
        policy,
        settings: sender,
        shutdown,
        task,
    }
}

fn blocks(policy: &Policy, name: &str) -> bool {
    matches!(policy.decide(name, RecordType::A), Decision::Blocked(_))
}

/// Lets the runner work: real file reads, on paused time.
async fn settle() {
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn lists_load_at_start_and_again_every_interval() {
    let dir = tempfile::tempdir().unwrap();
    let list = dir.path().join("ads.txt");
    std::fs::write(&list, "ads.example\n").unwrap();
    let running = start(&[&list], 1);
    settle().await;
    assert!(blocks(&running.policy, "ads.example"));

    std::fs::write(&list, "tracker.example\n").unwrap();
    tokio::time::sleep(secs(3595)).await;
    settle().await;
    assert!(blocks(&running.policy, "ads.example"), "not an hour yet");
    tokio::time::sleep(secs(10)).await;
    settle().await;
    assert!(blocks(&running.policy, "tracker.example"));
    assert!(!blocks(&running.policy, "ads.example"));

    running.shutdown.cancel();
    running.task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_missing_list_is_retried_and_changed_sources_load_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let late = dir.path().join("late.txt");
    let running = start(&[&late], 24);
    settle().await;
    assert!(!running.policy.lists().is_complete());

    std::fs::write(&late, "ads.example\n").unwrap();
    tokio::time::sleep(secs(61)).await;
    settle().await;
    assert!(
        blocks(&running.policy, "ads.example"),
        "retried after a minute"
    );

    let other = dir.path().join("other.txt");
    std::fs::write(&other, "tracker.example\n").unwrap();
    let mut changed = running.settings.borrow().clone();
    changed.sources.blocklists = vec![Source::File(other)];
    running.settings.send(changed).unwrap();
    settle().await;
    assert!(blocks(&running.policy, "tracker.example"));
    assert!(!blocks(&running.policy, "ads.example"));

    running.shutdown.cancel();
    running.task.await.unwrap();
}
