//! The Metrics: counters kept while running, and their Prometheus text
//! exposition at `GET /metrics` (ADR-0001). Kept in memory only; a restart
//! starts them from zero.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::Role;
use crate::policy::{Counts, ListKind, Lists};
use crate::resolver::Outcome;

/// Queries answered since start, per Outcome.
#[derive(Debug, Default)]
pub struct Queries {
    counts: [AtomicU64; Outcome::ALL.len()],
}

impl Queries {
    pub fn record(&self, outcome: Outcome) {
        if let Some(count) = self.counts.get(outcome as usize) {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn count(&self, outcome: Outcome) -> u64 {
        self.counts
            .get(outcome as usize)
            .map_or(0, |count| count.load(Ordering::Relaxed))
    }

    /// Every Outcome with its count, in [`Outcome::ALL`] order.
    pub fn counts(&self) -> impl Iterator<Item = (Outcome, u64)> + '_ {
        Outcome::ALL
            .into_iter()
            .map(|outcome| (outcome, self.count(outcome)))
    }

    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts().map(|(_, count)| count).sum()
    }
}

/// The upper bounds of the answer-time buckets; slower answers go in the
/// last, unbounded one.
pub const ANSWER_TIME_BUCKETS: [Duration; 10] = [
    Duration::from_millis(5),
    Duration::from_millis(10),
    Duration::from_millis(25),
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_millis(2500),
    Duration::from_secs(5),
];

/// Durations counted in [`ANSWER_TIME_BUCKETS`].
#[derive(Debug, Default)]
pub struct Histogram {
    /// Per bucket, not cumulative; the last is beyond every bound.
    counts: [AtomicU64; ANSWER_TIME_BUCKETS.len() + 1],
    sum_micros: AtomicU64,
}

impl Histogram {
    pub fn record(&self, duration: Duration) {
        let bucket = ANSWER_TIME_BUCKETS
            .iter()
            .position(|&bound| duration <= bound)
            .unwrap_or(ANSWER_TIME_BUCKETS.len());
        if let Some(count) = self.counts.get(bucket) {
            count.fetch_add(1, Ordering::Relaxed);
        }
        let micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> HistogramSnapshot {
        HistogramSnapshot {
            counts: self
                .counts
                .iter()
                .map(|count| count.load(Ordering::Relaxed))
                .collect(),
            sum: Duration::from_micros(self.sum_micros.load(Ordering::Relaxed)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistogramSnapshot {
    /// Per bucket of [`ANSWER_TIME_BUCKETS`], then beyond them.
    pub counts: Vec<u64>,
    pub sum: Duration,
}

impl HistogramSnapshot {
    #[must_use]
    pub fn count(&self) -> u64 {
        self.counts.iter().sum()
    }
}

/// What the instance did that is neither a query nor part of the Policy,
/// as times since the Unix epoch in seconds (0: not yet).
#[derive(Debug)]
pub struct State {
    started: u64,
    last_complete_load: AtomicU64,
    next_load: AtomicU64,
    role: Role,
    /// On a replica.
    last_sync: AtomicU64,
    sync_failures_in_a_row: AtomicU64,
    /// On a replica: whether the synced settings can be saved.
    saves_work: AtomicBool,
    /// On a replica: whether it refuses the settings its origin serves.
    sync_rejected: AtomicBool,
    /// On an origin: when each replica last fetched the settings.
    replicas: Mutex<BTreeMap<IpAddr, u64>>,
}

/// Replicas an origin keeps track of; the one heard from longest ago makes
/// room for a new one.
const MAX_REPLICAS: usize = 64;

impl Default for State {
    fn default() -> Self {
        State::new(Role::Alone)
    }
}

impl State {
    #[must_use]
    pub fn new(role: Role) -> State {
        State {
            started: unix_seconds(SystemTime::now()),
            last_complete_load: AtomicU64::new(0),
            next_load: AtomicU64::new(0),
            role,
            last_sync: AtomicU64::new(0),
            sync_failures_in_a_row: AtomicU64::new(0),
            saves_work: AtomicBool::new(true),
            sync_rejected: AtomicBool::new(false),
            replicas: Mutex::new(BTreeMap::new()),
        }
    }

    /// A replica synced at `at`.
    pub fn synced(&self, at: SystemTime) {
        self.last_sync.store(unix_seconds(at), Ordering::Relaxed);
        self.sync_failures_in_a_row.store(0, Ordering::Relaxed);
        self.sync_rejected.store(false, Ordering::Relaxed);
    }

    /// A replica reached its origin, but refuses the settings it serves:
    /// not a failed sync, and not a successful one either.
    pub fn sync_rejected(&self) {
        self.sync_failures_in_a_row.store(0, Ordering::Relaxed);
        self.sync_rejected.store(true, Ordering::Relaxed);
    }

    /// Whether a replica could save its synced settings (or, at start,
    /// write where it saves them).
    pub fn state_file(&self, ok: bool) {
        self.saves_work.store(ok, Ordering::Relaxed);
    }

    /// A replica's sync failed.
    pub fn sync_failed(&self) {
        self.sync_failures_in_a_row.fetch_add(1, Ordering::Relaxed);
    }

    /// The origin served its settings to `replica` at `at`.
    pub fn fetched_by(&self, replica: IpAddr, at: SystemTime) {
        let mut replicas = self.replicas.lock().unwrap_or_else(PoisonError::into_inner);
        if replicas.len() >= MAX_REPLICAS && !replicas.contains_key(&replica) {
            let oldest = replicas
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(ip, _)| *ip);
            if let Some(oldest) = oldest {
                replicas.remove(&oldest);
            }
        }
        replicas.insert(replica, unix_seconds(at));
    }

    /// Complete lists were put in force at `at`.
    pub fn complete_load(&self, at: SystemTime) {
        self.last_complete_load
            .store(unix_seconds(at), Ordering::Relaxed);
    }

    /// When the next list load is due; None while one runs, or with none
    /// scheduled.
    pub fn next_load(&self, at: Option<SystemTime>) {
        self.next_load
            .store(at.map_or(0, unix_seconds), Ordering::Relaxed);
    }
}

fn unix_seconds(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// One upstream server, as the Metrics show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerMetrics {
    /// As configured, such as `https://dns.quad9.net/dns-query (9.9.9.9)`.
    pub name: String,
    pub preferred: bool,
    pub failures: u64,
    /// Its count is the number of answers.
    pub answer_times: HistogramSnapshot,
}

/// Everything shown at one scrape.
#[derive(Debug)]
pub struct Snapshot<'a> {
    pub queries: &'a Queries,
    pub upstream: Vec<ServerMetrics>,
    pub counts: Counts,
    pub cache_entries: u64,
    pub lists: Arc<Lists>,
    pub state: &'a State,
}

/// `snapshot` in the Prometheus text format (version 0.0.4).
#[must_use]
pub fn render(snapshot: &Snapshot<'_>) -> String {
    let mut out = Exposition::default();
    out.family("zinkhole_build_info", "gauge", "The running version.");
    out.sample(
        "zinkhole_build_info",
        &[("version", env!("CARGO_PKG_VERSION"))],
        1,
    );
    out.family(
        "zinkhole_start_time_seconds",
        "gauge",
        "When the instance started, in seconds since the Unix epoch.",
    );
    out.sample("zinkhole_start_time_seconds", &[], snapshot.state.started);

    out.family(
        "zinkhole_queries_total",
        "counter",
        "Queries answered since start, per Outcome.",
    );
    for (outcome, count) in snapshot.queries.counts() {
        out.sample(
            "zinkhole_queries_total",
            &[("outcome", outcome.as_str())],
            count,
        );
    }

    render_upstream(&mut out, &snapshot.upstream);

    let gauges = [
        (
            "zinkhole_blocked_domains",
            "Domains blocked by the lists in force (not the inline rules).",
            snapshot.counts.blocked_domains as u64,
        ),
        (
            "zinkhole_allowed_domains",
            "Domains allowed by the lists in force (not the inline rules).",
            snapshot.counts.allowed_domains as u64,
        ),
        (
            "zinkhole_local_records",
            "Configured local records, wildcards included.",
            snapshot.counts.local_records as u64,
        ),
        (
            "zinkhole_cache_entries",
            "Answers in the cache.",
            snapshot.cache_entries,
        ),
    ];
    for (name, help, value) in gauges {
        out.family(name, "gauge", help);
        out.sample(name, &[], value);
    }

    render_lists(&mut out, &snapshot.lists, snapshot.state);
    render_sync(&mut out, snapshot.state);
    out.text
}

fn render_upstream(out: &mut Exposition, servers: &[ServerMetrics]) {
    const ANSWER: &str = "zinkhole_upstream_answer_duration_seconds";
    out.family(
        ANSWER,
        "histogram",
        "How long upstream servers took to answer; the count is the answers.",
    );
    for server in servers {
        let labels = [("server", server.name.as_str())];
        let mut cumulative = 0;
        let bounds = ANSWER_TIME_BUCKETS
            .iter()
            .map(|bound| Seconds(*bound).to_string());
        let bounds = bounds.chain(std::iter::once("+Inf".to_owned()));
        for (bound, count) in bounds.zip(&server.answer_times.counts) {
            cumulative += count;
            out.sample(
                &format!("{ANSWER}_bucket"),
                &[("server", server.name.as_str()), ("le", &bound)],
                cumulative,
            );
        }
        out.sample(
            &format!("{ANSWER}_sum"),
            &labels,
            Seconds(server.answer_times.sum),
        );
        out.sample(
            &format!("{ANSWER}_count"),
            &labels,
            server.answer_times.count(),
        );
    }
    out.family(
        "zinkhole_upstream_failures_total",
        "counter",
        "Upstream exchanges that failed: a timeout, a connection error, a malformed answer or REFUSED.",
    );
    for server in servers {
        out.sample(
            "zinkhole_upstream_failures_total",
            &[("server", server.name.as_str())],
            server.failures,
        );
    }
    out.family(
        "zinkhole_upstream_preferred",
        "gauge",
        "1 for the server asked first: the one that answered last.",
    );
    for server in servers {
        out.sample(
            "zinkhole_upstream_preferred",
            &[("server", server.name.as_str())],
            u8::from(server.preferred),
        );
    }
}

fn render_lists(out: &mut Exposition, lists: &Lists, state: &State) {
    out.family(
        "zinkhole_list_loaded",
        "gauge",
        "1 if the source loaded completely for the lists in force; index is its place among the blocklists or allowlists.",
    );
    let (mut blocklists, mut allowlists) = (0_usize, 0_usize);
    for (source, kind, loaded) in lists.results() {
        // Sources can look alike once their query is hidden: the place
        // keeps the series apart.
        let place = match kind {
            ListKind::Block => &mut blocklists,
            ListKind::Allow => &mut allowlists,
        };
        let index = place.to_string();
        *place += 1;
        out.sample(
            "zinkhole_list_loaded",
            &[
                ("kind", kind.as_str()),
                ("index", &index),
                ("source", &crate::lists::shown(source)),
            ],
            u8::from(loaded),
        );
    }
    let times = [
        (
            "zinkhole_lists_last_complete_load_timestamp_seconds",
            "When complete lists were last put in force, in seconds since the Unix epoch.",
            state.last_complete_load.load(Ordering::Relaxed),
        ),
        (
            "zinkhole_lists_next_load_timestamp_seconds",
            "When the lists load next, in seconds since the Unix epoch.",
            state.next_load.load(Ordering::Relaxed),
        ),
    ];
    for (name, help, at) in times {
        out.family(name, "gauge", help);
        // Not yet, or not scheduled: no sample rather than a fake time.
        if at > 0 {
            out.sample(name, &[], at);
        }
    }
}

fn render_sync(out: &mut Exposition, state: &State) {
    match state.role {
        Role::Alone => {}
        Role::Replica => {
            const LAST: &str = "zinkhole_sync_last_success_timestamp_seconds";
            out.family(
                LAST,
                "gauge",
                "When this replica last synced with its origin, in seconds since the Unix epoch.",
            );
            let last = state.last_sync.load(Ordering::Relaxed);
            if last > 0 {
                out.sample(LAST, &[], last);
            }
            out.family(
                "zinkhole_sync_failures_in_a_row",
                "gauge",
                "Syncs that failed since the last one that worked.",
            );
            out.sample(
                "zinkhole_sync_failures_in_a_row",
                &[],
                state.sync_failures_in_a_row.load(Ordering::Relaxed),
            );
            out.family(
                "zinkhole_sync_rejected",
                "gauge",
                "1 while this replica refuses the settings its origin serves (see the log), keeping its last ones.",
            );
            out.sample(
                "zinkhole_sync_rejected",
                &[],
                u8::from(state.sync_rejected.load(Ordering::Relaxed)),
            );
            out.family(
                "zinkhole_sync_state_file_ok",
                "gauge",
                "1 if the synced settings can be saved, to start from when the origin is down.",
            );
            out.sample(
                "zinkhole_sync_state_file_ok",
                &[],
                u8::from(state.saves_work.load(Ordering::Relaxed)),
            );
        }
        Role::Origin => {
            const FETCH: &str = "zinkhole_sync_replica_last_fetch_timestamp_seconds";
            out.family(
                FETCH,
                "gauge",
                "When each replica last fetched the settings, in seconds since the Unix epoch.",
            );
            let replicas = state
                .replicas
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for (replica, at) in replicas.iter() {
                out.sample(FETCH, &[("replica", &replica.to_string())], at);
            }
        }
    }
}

/// A duration in seconds, as Prometheus writes them.
struct Seconds(Duration);

impl fmt::Display for Seconds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.as_secs_f64())
    }
}

#[derive(Default)]
struct Exposition {
    text: String,
}

impl Exposition {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.text, "# HELP {name} {help}");
        let _ = writeln!(self.text, "# TYPE {name} {kind}");
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: impl fmt::Display) {
        self.text.push_str(name);
        if !labels.is_empty() {
            self.text.push('{');
            for (i, (label, text)) in labels.iter().enumerate() {
                if i > 0 {
                    self.text.push(',');
                }
                let _ = write!(self.text, "{label}=\"");
                escape_into(&mut self.text, text);
                self.text.push('"');
            }
            self.text.push('}');
        }
        let _ = writeln!(self.text, " {value}");
    }
}

/// A label value: backslash, double quote and line feed escaped.
fn escape_into(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests;
