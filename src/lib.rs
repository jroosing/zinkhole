//! zinkhole: a DNS blocker and local DNS server for home networks
//! (`CONTEXT.md` has the vocabulary, `docs/adr/` the decisions).

pub mod answer;
pub mod cache;
pub mod client;
pub mod config;
pub mod domain_set;
pub mod healthcheck;
pub mod hex;
pub mod http;
pub mod listen;
pub mod lists;
pub mod local;
pub mod logging;
pub mod metrics;
pub mod name;
pub mod policy;
pub mod refresh;
pub mod resolver;
pub mod rules;
pub mod secret;
pub mod serve;
pub mod server;
pub mod settings;
#[cfg(test)]
mod stub;
pub mod sync;
pub mod tls;
pub mod upstream;
