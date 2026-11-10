//! The Refresh: when the lists are loaded.
//!
//! - The first load starts at once, then one Refresh interval after each
//!   complete load (`blocking.refresh_hours`; 0 is none).
//! - An incomplete load is retried after 60 seconds, doubling after each
//!   further one, capped at the interval (or a day without one).
//! - A load ends after 10 minutes, keeping the lists that loaded by then
//!   (the Loader's own deadline). Should it hang anyway, it is canceled a
//!   minute later and counts as incomplete.
//! - When a Reload changes the sources, the running load is canceled and a
//!   new one starts at once, with a fresh retry delay.
//!
//! [`Schedule`] decides, given the time; [`run`] carries out its decisions.

use std::future::pending;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::config::PolicySettings;
use crate::lists::{self, Loader};
use crate::metrics;
use crate::policy::{Lists, Policy, Replacement, Sources};

/// A load still running after this is canceled: a backstop, as the Loader
/// ends a load at [`lists::LOAD_TIMEOUT`] on its own.
const LOAD_TIMEOUT: Duration = lists::LOAD_TIMEOUT.saturating_add(Duration::from_mins(1));
/// The first retry after an incomplete load; doubles with each further one.
const MIN_RETRY_DELAY: Duration = Duration::from_mins(1);
/// The retry delay without a Refresh interval to cap it.
const MAX_RETRY_DELAY: Duration = Duration::from_hours(24);

/// What the Refresh needs from the settings in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshSettings {
    pub sources: Sources,
    /// None: no Refresh, the lists load at start and when the sources change.
    pub interval: Option<Duration>,
}

impl RefreshSettings {
    #[must_use]
    pub fn of(settings: &PolicySettings) -> RefreshSettings {
        let hours = settings.blocking.refresh_hours;
        RefreshSettings {
            sources: Sources::of(settings),
            interval: (hours > 0).then(|| Duration::from_hours(u64::from(hours))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Idle,
    Start,
    Cancel,
}

#[derive(Debug, Default)]
pub struct Schedule {
    /// When the running load started.
    running_since: Option<Instant>,
    /// When the last complete load finished.
    last_complete: Option<Instant>,
    /// Incomplete loads since the last complete one, and when the latest ended.
    failures: u32,
    last_failure: Option<Instant>,
    /// A Reload changed the sources since the last load started.
    sources_changed: bool,
}

impl Schedule {
    /// What to do at `now`, with the Refresh `interval` in force.
    #[must_use]
    pub fn next(&self, now: Instant, interval: Option<Duration>) -> Action {
        if let Some(since) = self.running_since {
            // A load of outdated sources is not worth finishing.
            if self.sources_changed || now.duration_since(since) > LOAD_TIMEOUT {
                return Action::Cancel;
            }
            return Action::Idle;
        }
        if self.sources_changed {
            return Action::Start;
        }
        let start = match self.due(interval) {
            Some(due) => now >= due,
            // The first load, unless one already failed to start.
            None => self.last_complete.is_none() && self.failures == 0,
        };
        if start { Action::Start } else { Action::Idle }
    }

    /// When the next load starts, if one is due later; None while one runs
    /// or is about to start, and when no Refresh is configured.
    #[must_use]
    pub fn due(&self, interval: Option<Duration>) -> Option<Instant> {
        if self.running_since.is_some() || self.sources_changed {
            return None;
        }
        if self.failures > 0 {
            return self
                .last_failure
                .map(|at| at + retry_delay(self.failures, interval));
        }
        Some(self.last_complete? + interval?)
    }

    /// When [`Schedule::next`] may decide differently without any event:
    /// the running load's deadline, or the next due load.
    fn wake_at(&self, interval: Option<Duration>) -> Option<Instant> {
        match self.running_since {
            Some(since) => Some(since + LOAD_TIMEOUT),
            None => self.due(interval),
        }
    }

    pub fn started(&mut self, now: Instant) {
        self.running_since = Some(now);
        self.sources_changed = false;
    }

    /// The load ended (after a [`Action::Cancel`]: incomplete). Returns the
    /// retry delay if the load counts as failed.
    pub fn finished(
        &mut self,
        now: Instant,
        complete: bool,
        interval: Option<Duration>,
    ) -> Option<Duration> {
        // Canceled because the sources changed: not a failure of the sources.
        let superseded = self.running_since.is_some() && self.sources_changed;
        self.running_since = None;
        if complete {
            self.last_complete = Some(now);
            self.failures = 0;
            return None;
        }
        if superseded {
            return None;
        }
        // A load that could not start counts as a failed load of the current
        // sources: trying again at once would not help.
        self.sources_changed = false;
        self.failures = self.failures.saturating_add(1);
        self.last_failure = Some(now);
        Some(retry_delay(self.failures, interval))
    }

    /// A Reload changed the sources: load them at once, with a fresh retry
    /// delay.
    pub fn sources_changed(&mut self) {
        self.sources_changed = true;
        self.failures = 0;
    }
}

/// 60 s after the first incomplete load, doubling after each further one,
/// capped at the interval.
fn retry_delay(failures: u32, interval: Option<Duration>) -> Duration {
    let doublings = failures.saturating_sub(1).min(30);
    let delay = MIN_RETRY_DELAY.saturating_mul(1 << doublings);
    delay.min(interval.unwrap_or(MAX_RETRY_DELAY))
}

/// Loads the lists into `policy` as the schedule says, until `shutdown`.
/// `settings` carries the settings in force, changed by Reloads.
pub async fn run(
    policy: Arc<Policy>,
    loader: Loader,
    mut settings: watch::Receiver<RefreshSettings>,
    metrics: Arc<metrics::State>,
    shutdown: CancellationToken,
) {
    let mut schedule = Schedule::default();
    let mut current = settings.borrow_and_update().clone();
    let mut load: Option<JoinHandle<Lists>> = None;
    // False once nobody can send changes any more.
    let mut may_change = true;
    loop {
        let now = Instant::now();
        match schedule.next(now, current.interval) {
            Action::Start => {
                let (loader, sources) = (loader.clone(), current.sources.clone());
                load = Some(tokio::spawn(async move { loader.load(sources).await }));
                schedule.started(now);
            }
            Action::Cancel => {
                if let Some(task) = load.take() {
                    task.abort();
                }
                if !schedule.sources_changed {
                    tracing::warn!(
                        "loading the lists took longer than {} minutes, canceled",
                        LOAD_TIMEOUT.as_secs() / 60
                    );
                }
                report_retry(schedule.finished(now, false, current.interval));
                continue;
            }
            Action::Idle => {}
        }
        let wake = schedule.wake_at(current.interval);
        metrics.next_load(
            schedule
                .due(current.interval)
                .map(|due| SystemTime::now() + due.saturating_duration_since(Instant::now())),
        );
        tokio::select! {
            finished = until_finished(&mut load) => {
                load = None;
                let complete = match finished {
                    Ok(lists) => {
                        let complete = put_in_force(&policy, lists);
                        if complete {
                            metrics.complete_load(SystemTime::now());
                        }
                        complete
                    }
                    Err(error) => {
                        tracing::error!(%error, "loading the lists failed");
                        false
                    }
                };
                report_retry(schedule.finished(Instant::now(), complete, current.interval));
            }
            () = until(wake) => {}
            changed = settings.changed(), if may_change => match changed {
                Ok(()) => {
                    let new = settings.borrow_and_update().clone();
                    if new.sources != current.sources {
                        tracing::info!("the list sources changed, loading them");
                        schedule.sources_changed();
                    }
                    current = new;
                }
                Err(_) => may_change = false,
            },
            () = shutdown.cancelled() => {
                if let Some(task) = load.take() {
                    task.abort();
                }
                return;
            }
        }
    }
}

/// Puts `lists` in force unless the Policy keeps the current ones; true if
/// they were complete.
fn put_in_force(policy: &Policy, lists: Lists) -> bool {
    let complete = lists.is_complete();
    if policy.replace_lists(lists) == Replacement::Kept {
        tracing::warn!("some lists failed to load, keeping the previous lists");
    }
    complete
}

fn report_retry(delay: Option<Duration>) {
    if let Some(delay) = delay {
        tracing::info!(
            "retrying the lists in {} minutes",
            delay.as_secs().div_ceil(60)
        );
    }
}

async fn until_finished(
    load: &mut Option<JoinHandle<Lists>>,
) -> Result<Lists, tokio::task::JoinError> {
    match load {
        Some(task) => task.await,
        None => pending().await,
    }
}

async fn until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => pending().await,
    }
}

#[cfg(test)]
mod tests;
