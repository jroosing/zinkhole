//! The Policy settings in force, from the config file (a Reload) or from
//! the origin (a Sync), and what follows from them.

use std::sync::Arc;

use tokio::sync::watch;

use crate::config::PolicySettings;
use crate::policy::Policy;
use crate::refresh::RefreshSettings;

/// Puts Policy settings in force: in the Policy at once, and their list
/// sources and Refresh interval for the Refresh.
#[derive(Debug)]
pub struct InForce {
    policy: Arc<Policy>,
    refresh: watch::Sender<RefreshSettings>,
}

impl InForce {
    /// `settings` in force for `policy`; the receiver feeds the Refresh.
    #[must_use]
    pub fn new(
        policy: Arc<Policy>,
        settings: &PolicySettings,
    ) -> (InForce, watch::Receiver<RefreshSettings>) {
        policy.apply(settings);
        let (refresh, changes) = watch::channel(RefreshSettings::of(settings));
        (InForce { policy, refresh }, changes)
    }

    pub fn apply(&self, settings: &PolicySettings) {
        self.policy.apply(settings);
        self.refresh.send_replace(RefreshSettings::of(settings));
    }

    #[must_use]
    pub fn policy(&self) -> &Arc<Policy> {
        &self.policy
    }
}
