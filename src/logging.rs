//! Log lines on standard error, as text or JSON. The level can change while
//! running (a Reload); the format needs a restart.
//!
//! zinkhole's own events go out from the configured level up; the libraries
//! it uses only from warnings up, unless the level is `debug`.

use std::io::{self, IsTerminal as _};

use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{Registry, fmt, reload};

use crate::config::{self, LogFormat, LogLevel};

/// Changes the level of the logging set up by [`init`].
#[derive(Debug, Clone)]
pub struct Logging {
    filter: reload::Handle<Targets, Registry>,
}

impl Logging {
    pub fn set_level(&self, level: LogLevel) {
        if let Err(error) = self.filter.reload(targets(level)) {
            tracing::warn!(%error, "cannot change the log level");
        }
    }
}

/// Sets up logging as `settings` say; None if logging was already set up
/// (as in tests), which then stays as it was.
#[must_use]
pub fn init(settings: &config::Log) -> Option<Logging> {
    let (filter, handle) = reload::Layer::new(targets(settings.level));
    let ansi = io::stderr().is_terminal();
    let (text, json) = match settings.format {
        LogFormat::Text => (
            Some(fmt::layer().with_writer(io::stderr).with_ansi(ansi)),
            None,
        ),
        LogFormat::Json => (None, Some(fmt::layer().json().with_writer(io::stderr))),
    };
    tracing_subscriber::registry()
        .with(filter)
        .with(text)
        .with(json)
        .try_init()
        .ok()
        .map(|()| Logging { filter: handle })
}

fn targets(level: LogLevel) -> Targets {
    let level = match level {
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
    };
    // Libraries: warnings and errors (fewer if the level says so), and
    // everything at debug.
    let libraries = if level == LevelFilter::DEBUG {
        LevelFilter::DEBUG
    } else {
        level.min(LevelFilter::WARN)
    };
    Targets::new()
        .with_target("zinkhole", level)
        .with_default(libraries)
}
