//! `zinkhole serve`: the parts wired together, running until SIGTERM or
//! SIGINT.
//!
//! - SIGHUP reloads the config file: local records, inline rules and the
//!   other Policy settings apply at once; the lists load again only when
//!   their sources changed; the log level and the query log change too.
//!   Server, upstream, cache, HTTP and sync settings apply after a restart,
//!   and a changed sync role is refused.
//! - SIGUSR1 logs the queries per Outcome since start and the cache entries.
//! - The list Refresh, the Sync loop and the HTTP port run beside the DNS
//!   listeners. Should one of them end on its own, the server stops with an
//!   error, so that whatever runs zinkhole starts all of it again; only an
//!   HTTP port that cannot be served at all is done without.

use std::future::pending;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::Notify;
use tokio::task::{JoinError, JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::cache::Cache;
use crate::client::ClientError;
use crate::config::{self, Config, PolicySettings, Role};
use crate::http::{self, HttpListeners, MetricsSource};
use crate::listen::BindError;
use crate::lists::Loader;
use crate::logging::Logging;
use crate::metrics;
use crate::policy::Policy;
use crate::refresh;
use crate::resolver::{Forwarder, Resolver};
use crate::server::{self, Listeners};
use crate::settings::InForce;
use crate::sync::{self, Origin, Replica, Syncer};
use crate::upstream::Upstream;

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("cannot serve the Policy settings: {0}")]
    Publish(#[from] sync::PublishError),
    #[error(transparent)]
    Bind(#[from] BindError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A background task ended while the server ran.
    #[error("{what} failed ({why}); stopped, to be started again")]
    Task { what: &'static str, why: String },
}

/// Runs the server for `config`, read from `path`, until `shutdown`.
/// Queries are answered at once, with local records and inline rules; the
/// lists load in the background (which also lets this host resolve the list
/// servers through itself).
///
/// # Errors
///
/// The signal handlers cannot be set up, a listen address cannot be bound,
/// a socket not served, the HTTP client for lists not set up, or the list
/// Refresh, the Sync loop or the HTTP port ended on its own.
pub async fn run(
    path: PathBuf,
    config: Config,
    logging: Option<Logging>,
    controls: Controls,
    shutdown: CancellationToken,
) -> Result<(), ServeError> {
    let resolver = Arc::new(resolver(&config, Upstream::new(&config.upstream)));
    resolver.log_queries(config.log.queries);
    let loader = Loader::new()?;
    let addresses: Vec<SocketAddr> = config
        .server
        .listen
        .iter()
        .map(|address| address.0)
        .collect();
    let listeners = Listeners::bind(&addresses)?;
    for address in listeners.addresses() {
        tracing::info!(%address, "answering DNS over UDP and TCP");
    }
    let http_listeners = bind_http(&config)?;
    let state = Arc::new(metrics::State::new(config.role()));
    let Roles {
        settings,
        origin,
        replica,
    } = Roles::of(&config, &state)?;
    let (in_force, refresh_changes) = InForce::new(Arc::clone(resolver.policy()), &settings);
    let in_force = Arc::new(in_force);

    let refresh = tokio::spawn(refresh::run(
        Arc::clone(resolver.policy()),
        loader,
        refresh_changes,
        Arc::clone(&state),
        shutdown.clone(),
    ));
    let http = http_listeners.map(|listeners| {
        let router = http_router(&resolver, &state, origin.as_ref(), &listeners);
        tokio::spawn(http::serve(
            listeners,
            router,
            config.server.allow_clients.clone(),
            shutdown.clone(),
        ))
    });
    let sync_now = Arc::new(Notify::new());
    let syncing = replica.map(|starting| {
        let Starting {
            replica,
            have,
            interval,
        } = starting;
        tracing::info!(
            origin = %replica.origin(),
            "syncing the Policy settings every {} s",
            interval.as_secs()
        );
        let syncer = Syncer {
            replica,
            server: config.server.clone(),
            in_force: Arc::clone(&in_force),
            have,
            interval,
            now: Arc::clone(&sync_now),
            metrics: Arc::clone(&state),
        };
        tokio::spawn(syncer.run(shutdown.clone()))
    });
    let mut serving = tokio::spawn(server::serve(
        listeners,
        Arc::clone(&resolver),
        shutdown.clone(),
    ));
    let role = match (origin, config.role()) {
        (Some(origin), _) => RoleHooks::Origin(origin),
        (None, Role::Replica) => RoleHooks::Replica(sync_now),
        (None, _) => RoleHooks::Alone,
    };
    let reloader = Reloader::new(path, config, in_force, role, logging);

    let mut beside = Beside {
        refresh: Background::new("the list refresh", Some(refresh)),
        syncing: Background::new("syncing", syncing),
        http: Background::new("the HTTP port", http),
    };
    let (served, failure) = beside
        .watch(controls, &reloader, &resolver, &mut serving, &shutdown)
        .await;
    shutdown.cancel();
    beside.stopped().await;
    served.map_err(io::Error::other)??;
    tracing::info!("stopped");
    failure.map_or(Ok(()), Err)
}

/// What runs beside the DNS listeners.
#[derive(Debug)]
struct Beside {
    refresh: Background<()>,
    syncing: Background<()>,
    http: Background<io::Result<()>>,
}

impl Beside {
    /// Reloads and logs the summary when asked, until the DNS listeners
    /// (`serving`) end. Returns how they ended, and why the server stops if
    /// that is because one of these tasks ended on its own.
    async fn watch(
        &mut self,
        controls: Controls,
        reloader: &Reloader,
        resolver: &Resolver<Upstream>,
        serving: &mut JoinHandle<io::Result<()>>,
        shutdown: &CancellationToken,
    ) -> (Result<io::Result<()>, JoinError>, Option<ServeError>) {
        let Controls {
            mut hangup,
            mut user1,
        } = controls;
        let Beside {
            refresh,
            syncing,
            http,
        } = self;
        let mut failure = None;
        let served = loop {
            tokio::select! {
                _ = hangup.recv() => {
                    if let Err(error) = reloader.reload(resolver) {
                        tracing::error!("reload failed, keeping the current configuration: {error}");
                    }
                }
                _ = user1.recv() => log_summary(resolver),
                served = &mut *serving => break served,
                ended = refresh.ended() => failure = failure.or(refresh.failed(ended, shutdown)),
                ended = syncing.ended() => failure = failure.or(syncing.failed(ended, shutdown)),
                ended = http.ended() => match ended {
                    // Its listeners could not be served: DNS without the
                    // HTTP port is worth more than no DNS.
                    Ok(Err(error)) => {
                        tracing::error!(%error, "the HTTP port failed; answering DNS without it");
                    }
                    Ok(Ok(())) => failure = failure.or(http.failed(Ok(()), shutdown)),
                    Err(error) => failure = failure.or(http.failed(Err(error), shutdown)),
                },
            }
        };
        (served, failure)
    }

    /// Waits for the tasks, which were told to stop.
    async fn stopped(self) {
        self.refresh.stopped().await;
        self.syncing.stopped().await;
        if let Some(Err(error)) = self.http.stopped().await {
            tracing::error!(%error, "the HTTP port failed");
        }
    }
}

/// A task that runs beside the DNS listeners for as long as they do: the
/// list Refresh, the Sync loop or the HTTP port.
#[derive(Debug)]
struct Background<T> {
    what: &'static str,
    /// None without one (no HTTP port, not a replica), and once it ended.
    task: Option<JoinHandle<T>>,
}

impl<T> Background<T> {
    fn new(what: &'static str, task: Option<JoinHandle<T>>) -> Background<T> {
        Background { what, task }
    }

    /// How the task ended, once it does; never, without a task.
    async fn ended(&mut self) -> Result<T, JoinError> {
        let Some(task) = self.task.as_mut() else {
            return pending().await;
        };
        let ended = task.await;
        self.task = None;
        ended
    }

    /// What follows from the task having ended.
    ///
    /// - Told to stop (`shutdown`): nothing, but a panic is logged.
    /// - On its own: its work would be missing from now on (no lists
    ///   refreshed, no syncing) with nothing to show for it. The server is
    ///   told to stop, and the error returned is why.
    fn failed(
        &self,
        ended: Result<(), JoinError>,
        shutdown: &CancellationToken,
    ) -> Option<ServeError> {
        let what = self.what;
        if shutdown.is_cancelled() {
            if let Err(error) = ended {
                tracing::error!(%error, "{what} failed");
            }
            return None;
        }
        let why = ended
            .err()
            .map_or_else(|| "it ended".to_owned(), |error| error.to_string());
        tracing::error!("{what} failed ({why}): stopping, to be started again with all of it");
        shutdown.cancel();
        Some(ServeError::Task { what, why })
    }

    /// Waits for the task, which was told to stop; what it returned, unless
    /// it panicked, which is logged.
    async fn stopped(mut self) -> Option<T> {
        match self.task.take()?.await {
            Ok(returned) => Some(returned),
            Err(error) => {
                tracing::error!(%error, "{} failed", self.what);
                None
            }
        }
    }
}

/// `GET /metrics`, and `GET /sync` on an origin.
fn http_router(
    resolver: &Arc<Resolver<Upstream>>,
    state: &Arc<metrics::State>,
    origin: Option<&Arc<Origin>>,
    listeners: &HttpListeners,
) -> axum::Router {
    let router = http::metrics_router(MetricsSource {
        resolver: Arc::clone(resolver),
        state: Arc::clone(state),
    });
    let Some(origin) = origin else {
        return router;
    };
    for address in listeners.addresses() {
        tracing::info!("serving the Policy settings to replicas on http://{address}/sync");
    }
    router.merge(Arc::clone(origin).router())
}

/// The HTTP port's listeners, if there is one.
fn bind_http(config: &Config) -> Result<Option<HttpListeners>, BindError> {
    let Some(settings) = &config.http else {
        return Ok(None);
    };
    let addresses: Vec<SocketAddr> = settings.listen.iter().map(|address| address.0).collect();
    let bound = HttpListeners::bind(&addresses)?;
    for address in bound.addresses() {
        tracing::info!("serving the Metrics on http://{address}/metrics");
    }
    Ok(Some(bound))
}

/// What the sync role brings: the Policy settings to start with, and the
/// origin or the replica.
struct Roles {
    settings: PolicySettings,
    origin: Option<Arc<Origin>>,
    replica: Option<Starting>,
}

/// A replica as it starts.
struct Starting {
    replica: Replica,
    /// The `ETag` of the saved settings it starts with, if it has any.
    have: Option<String>,
    interval: Duration,
}

impl Roles {
    fn of(config: &Config, state: &Arc<metrics::State>) -> Result<Roles, ServeError> {
        Ok(match &config.sync {
            None => Roles {
                settings: config.policy_settings(),
                origin: None,
                replica: None,
            },
            Some(config::Sync::Origin { secret }) => {
                let settings = config.policy_settings();
                let origin = Origin::new(secret, &settings, Arc::clone(state))?;
                Roles {
                    settings,
                    origin: Some(Arc::new(origin)),
                    replica: None,
                }
            }
            // A replica starts from the settings it saved, if any, until it
            // syncs.
            Some(config::Sync::Replica {
                secret,
                origin,
                interval_secs,
                state_dir,
            }) => {
                let replica = Replica::new(&origin.0, secret, state_dir)?;
                if let Err(error) = replica.check_state_dir() {
                    tracing::error!(
                        dir = %state_dir.display(),
                        %error,
                        "cannot save synced settings here: a restart while the origin is down would start without them"
                    );
                    state.state_file(false);
                }
                let (settings, have) = saved_settings(&replica, &config.server);
                Roles {
                    settings,
                    origin: None,
                    replica: Some(Starting {
                        replica,
                        have,
                        interval: Duration::from_secs(u64::from(*interval_secs)),
                    }),
                }
            }
        })
    }
}

/// The settings a replica saved, if they are valid here, with their `ETag`;
/// else empty settings until the first sync.
fn saved_settings(replica: &Replica, server: &config::Server) -> (PolicySettings, Option<String>) {
    let file = replica.state_file().display();
    match replica.load_state() {
        Ok(Some(saved)) => match server.synced_settings(&saved.text) {
            Ok(settings) => {
                tracing::info!(%file, "starting from the settings synced earlier");
                return (settings, Some(saved.etag));
            }
            Err(error) => {
                tracing::warn!(%file, "the settings synced earlier are invalid here: {error}");
            }
        },
        Ok(None) => tracing::info!("no settings synced yet; blocking starts with the first sync"),
        Err(error) => tracing::warn!(%file, %error, "cannot use the settings synced earlier"),
    }
    (PolicySettings::default(), None)
}

/// The Resolver for `config`, asking `forwarder` what it cannot answer.
pub fn resolver<F: Forwarder>(config: &Config, forwarder: F) -> Resolver<F> {
    Resolver::new(
        Arc::new(Policy::new(&config.policy_settings())),
        Cache::new(&config.cache),
        forwarder,
        config.server.allow_clients.clone(),
        usize::try_from(config.upstream.max_in_flight).unwrap_or(usize::MAX),
    )
}

/// Why a Reload changed nothing.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error(transparent)]
    Config(#[from] config::Error),
    #[error("changing the sync role (from {from} to {to}) needs a restart")]
    RoleChanged { from: Role, to: Role },
}

/// What a Reload does for this instance's role.
#[derive(Debug)]
pub enum RoleHooks {
    /// Puts the file's Policy settings in force.
    Alone,
    /// Also serves them to the replicas.
    Origin(Arc<Origin>),
    /// Keeps the synced settings, and syncs at once.
    Replica(Arc<Notify>),
}

/// Applies the config file again, as far as it can while running.
#[derive(Debug)]
pub struct Reloader {
    path: PathBuf,
    /// The config the server started with: what needs a restart stays as
    /// it says.
    started: Config,
    in_force: Arc<InForce>,
    role: RoleHooks,
    logging: Option<Logging>,
}

impl Reloader {
    #[must_use]
    pub fn new(
        path: PathBuf,
        started: Config,
        in_force: Arc<InForce>,
        role: RoleHooks,
        logging: Option<Logging>,
    ) -> Reloader {
        Reloader {
            path,
            started,
            in_force,
            role,
            logging,
        }
    }

    /// Reads the config file and applies what can change while running.
    ///
    /// # Errors
    ///
    /// The file is invalid or changes the sync role; nothing changed then.
    pub fn reload<F: Forwarder>(&self, resolver: &Resolver<F>) -> Result<(), ReloadError> {
        let new = Config::load(&self.path)?;
        let (from, to) = (self.started.role(), new.role());
        if from != to {
            return Err(ReloadError::RoleChanged { from, to });
        }
        match &self.role {
            RoleHooks::Alone => self.in_force.apply(&new.policy_settings()),
            RoleHooks::Origin(origin) => {
                let settings = new.policy_settings();
                self.in_force.apply(&settings);
                if let Err(error) = origin.publish(&settings) {
                    tracing::error!(%error, "cannot serve the new settings to the replicas");
                }
            }
            RoleHooks::Replica(sync_now) => sync_now.notify_one(),
        }
        if let Some(logging) = &self.logging {
            logging.set_level(new.log.level);
        }
        resolver.log_queries(new.log.queries);
        tracing::info!("configuration reloaded");

        let restart = self.needs_restart(&new);
        if !restart.is_empty() {
            tracing::warn!("changes to {} apply after a restart", restart.join(", "));
        }
        Ok(())
    }

    /// The settings in `new` that differ from those running and only apply
    /// after a restart.
    fn needs_restart(&self, new: &Config) -> Vec<&'static str> {
        let old = &self.started;
        [
            ("server", old.server != new.server),
            ("upstream", old.upstream != new.upstream),
            ("cache", old.cache != new.cache),
            ("http", old.http != new.http),
            ("log.format", old.log.format != new.log.format),
            ("sync", sync_changed(old.sync.as_ref(), new.sync.as_ref())),
        ]
        .into_iter()
        .filter_map(|(section, changed)| changed.then_some(section))
        .collect()
    }
}

/// True if the sync settings differ (the role is checked before). The secret
/// is compared in constant time.
fn sync_changed(old: Option<&config::Sync>, new: Option<&config::Sync>) -> bool {
    use config::Sync::{Origin, Replica};
    match (old, new) {
        (None, None) => false,
        (Some(Origin { secret: a }), Some(Origin { secret: b })) => !a.same_as(b),
        (
            Some(Replica {
                secret: a,
                origin: origin_a,
                interval_secs: interval_a,
                state_dir: dir_a,
            }),
            Some(Replica {
                secret: b,
                origin: origin_b,
                interval_secs: interval_b,
                state_dir: dir_b,
            }),
        ) => origin_a != origin_b || interval_a != interval_b || dir_a != dir_b || !a.same_as(b),
        _ => true,
    }
}

/// The SIGUSR1 summary: the queries per Outcome, every one of them, and
/// the cache entries.
fn log_summary<F: Forwarder>(resolver: &Resolver<F>) {
    tracing::info!(
        cache_entries = resolver.cache().entry_count(),
        "queries since start: {}",
        summary(resolver.queries())
    );
}

/// `local=3 blocked=1 ...`: every Outcome with its count.
fn summary(queries: &metrics::Queries) -> String {
    queries
        .counts()
        .map(|(outcome, count)| format!("{outcome}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The signals zinkhole handles, set up first thing: until a handler is in
/// place a signal's default action applies, which for SIGHUP and SIGUSR1 is
/// to end the process (and systemd counts SIGHUP as a clean exit, so it
/// would not restart it).
#[derive(Debug)]
pub struct Signals {
    terminate: Signal,
    interrupt: Signal,
    controls: Controls,
}

/// SIGHUP (reload) and SIGUSR1 (summary), for [`run`].
#[derive(Debug)]
pub struct Controls {
    hangup: Signal,
    user1: Signal,
}

impl Signals {
    /// # Errors
    ///
    /// A handler cannot be set up; a server that cannot be stopped or
    /// reloaded gracefully should not start.
    pub fn new() -> io::Result<Signals> {
        Ok(Signals {
            terminate: signal(SignalKind::terminate())?,
            interrupt: signal(SignalKind::interrupt())?,
            controls: Controls {
                hangup: signal(SignalKind::hangup())?,
                user1: signal(SignalKind::user_defined1())?,
            },
        })
    }

    /// A future that cancels `shutdown` at the first SIGTERM or SIGINT, and
    /// the controls for [`run`].
    pub fn split(self, shutdown: CancellationToken) -> (impl Future<Output = ()>, Controls) {
        let Signals {
            mut terminate,
            mut interrupt,
            controls,
        } = self;
        let stop = async move {
            tokio::select! {
                _ = terminate.recv() => tracing::info!("SIGTERM, shutting down"),
                _ = interrupt.recv() => tracing::info!("SIGINT, shutting down"),
                () = shutdown.cancelled() => {}
            }
            shutdown.cancel();
        };
        (stop, controls)
    }
}

#[cfg(test)]
mod tests;
