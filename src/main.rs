//! The `zinkhole` command (docs/adr/0001).

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use zinkhole::config::{self, Config};
use zinkhole::lists::Loader;
use zinkhole::policy::{Policy, Sources};
use zinkhole::{healthcheck, secret};

/// A DNS blocker and local DNS server for home networks.
#[derive(Debug, Parser)]
#[command(version, arg_required_else_help = true)]
struct Cli {
    /// The configuration file.
    #[arg(short, long, global = true, env = "ZINKHOLE_CONFIG", default_value = config::DEFAULT_PATH)]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the server.
    Serve,
    /// Check the configuration; with --lists, also load every list once.
    Check {
        /// Load the lists too (needs the network for URLs).
        #[arg(long)]
        lists: bool,
    },
    /// Ask a running server for "localhost"; exit 0 if it answers.
    Healthcheck {
        /// The server's address [default: the first address in the config's
        /// server.listen (loopback for a wildcard), else 127.0.0.1:53].
        server: Option<SocketAddr>,
    },
    /// Print a new 256-bit secret for sync.
    Secret,
}

/// Exit codes: 0 OK, 1 invalid configuration or unhealthy, 2 usage (clap).
fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve => serve(cli.config),
        Command::Check { lists } => match load(&cli.config) {
            Ok(config) if lists => check_lists(&config),
            Ok(_) => say("configuration OK"),
            Err(message) => fail(&message),
        },
        Command::Healthcheck { server } => {
            // Without an address: where the config says it listens; with no
            // readable config, the default port on loopback.
            let server = server.unwrap_or_else(|| {
                Config::load(&cli.config).map_or_else(
                    |_| SocketAddr::from(([127, 0, 0, 1], config::DNS_PORT)),
                    |config| healthcheck::target(&config),
                )
            });
            match healthcheck::check(server) {
                Ok(()) => ExitCode::SUCCESS,
                Err(unhealthy) => fail(&format!("unhealthy: {unhealthy}")),
            }
        }
        Command::Secret => match secret::generate() {
            Ok(secret) => say(&secret),
            Err(error) => fail(&format!("cannot generate a secret: {error}")),
        },
    }
}

fn serve(path: PathBuf) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return fail(&format!("cannot start: {error}")),
    };
    let shutdown = CancellationToken::new();
    let served = runtime.block_on(async {
        // Before anything else: a reload asked for while starting must not
        // end the process.
        let signals = zinkhole::serve::Signals::new()
            .map_err(|error| format!("cannot handle signals: {error}"))?;
        let config = load(&path)?;
        let logging = zinkhole::logging::init(&config.log);
        let (stop, controls) = signals.split(shutdown.clone());
        tokio::spawn(stop);
        zinkhole::serve::run(path, config, logging, controls, shutdown)
            .await
            .map_err(|error| error.to_string())
    });
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => fail(&message),
    }
}

/// Loads every list once and says what the configuration holds; failures
/// are logged as they happen.
fn check_lists(config: &Config) -> ExitCode {
    let _ = zinkhole::logging::init(&config.log);
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return fail(&format!("cannot start: {error}")),
    };
    let settings = config.policy_settings();
    let loader = match Loader::new() {
        Ok(loader) => loader,
        Err(error) => return fail(&error.to_string()),
    };
    let lists = runtime.block_on(loader.load(Sources::of(&settings)));
    let complete = lists.is_complete();
    let policy = Policy::new(&settings);
    policy.replace_lists(lists);
    let counts = policy.counts();
    let inline = settings.blocking.block.len() + settings.blocking.allow.len();
    let summary = format!(
        "configuration OK: {} local records, {inline} inline rules, {} blocked and {} allowed domains from lists",
        counts.local_records, counts.blocked_domains, counts.allowed_domains
    );
    if !complete {
        let _ = writeln!(std::io::stdout(), "{summary}");
        return fail("some lists failed to load (see above)");
    }
    say(&summary)
}

fn load(path: &std::path::Path) -> Result<Config, String> {
    Config::load(path).map_err(|error| error.to_string())
}

fn say(message: &str) -> ExitCode {
    let _ = writeln!(std::io::stdout(), "{message}");
    ExitCode::SUCCESS
}

fn fail(message: &str) -> ExitCode {
    let _ = writeln!(std::io::stderr(), "error: {message}");
    ExitCode::FAILURE
}
