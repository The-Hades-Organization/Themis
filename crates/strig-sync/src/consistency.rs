//! Read your own writes: what a decision that requires a revision answers when the instance is behind.

use std::time::Duration;

use strig::Revision;

use crate::provider::BoxError;

/// Why a decision that requires `at_least(revision)` could not be made. All of them mean "no
/// decision": the caller denies. The instance never decides from state older than the revision.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConsistencyError {
    /// The instance is in the same data scope but behind, and did not catch up before the timeout.
    #[error("the instance is at {have}, behind the required {required}")]
    NotReached { required: Revision, have: Revision },
    /// The required revision belongs to another data scope: the two cannot be compared.
    #[error("the required revision {required} is of another data scope than {have}")]
    OtherScope { required: Revision, have: Revision },
    /// The instance cannot say which revision it holds (a loader or provider that does not track one).
    #[error("the instance does not track revisions, so {required} cannot be proven")]
    Untracked { required: Revision },
    /// The source could not be read.
    #[error("the source failed: {0}")]
    Source(#[source] BoxError),
}

impl ConsistencyError {
    /// Stable machine-readable reason, the one a client or the `/v1` error body carries.
    pub fn code(&self) -> &'static str {
        match self {
            ConsistencyError::NotReached { .. } => "revision_not_reached",
            ConsistencyError::OtherScope { .. } => "revision_scope_mismatch",
            ConsistencyError::Untracked { .. } => "revision_untracked",
            ConsistencyError::Source(_) => "source_unavailable",
        }
    }
}

/// How long and how often an instance that is behind tries to catch up before it denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConsistencyOptions {
    /// Longest wait for the instance to reach the required revision. `ZERO` denies at once.
    pub timeout: Duration,
    /// Pause between two reloads while waiting.
    pub poll: Duration,
}

impl Default for ConsistencyOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(1),
            poll: Duration::from_millis(25),
        }
    }
}

impl ConsistencyOptions {
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub fn poll(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }
}
