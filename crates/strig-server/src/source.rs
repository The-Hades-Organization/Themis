//! Where the policy and the grants come from.

use std::error::Error;
use std::sync::{Arc, PoisonError, RwLock};

use async_trait::async_trait;
use strig::{Engine, Grant, InMemoryTuples, Revision};

/// Why a source could not load. Any variant makes the server answer 503: no source, no allow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SourceError {
    /// The store behind the source did not answer, or answered something unusable.
    #[error("the grant source is unavailable")]
    Unavailable(#[source] Box<dyn Error + Send + Sync>),
}

impl SourceError {
    pub fn unavailable(cause: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self::Unavailable(cause.into())
    }
}

/// Everything one answer reads: the engine (catalog, roles, strategy, overrides), the grants and
/// the ReBAC tuples. The server does not cache it: it asks the source for each request, so a
/// source that wants a cache keeps its own.
#[derive(Clone)]
pub struct Snapshot {
    pub engine: Arc<Engine>,
    pub grants: Vec<Grant>,
    pub tuples: Option<InMemoryTuples>,
    /// The revision of the data this snapshot was read at, when the store numbers its writes. A
    /// request that requires a `min_revision` is answered only from a snapshot that has reached it.
    pub revision: Option<Revision>,
}

impl Snapshot {
    pub fn new(engine: Arc<Engine>, grants: Vec<Grant>) -> Self {
        Self {
            engine,
            grants,
            tuples: None,
            revision: None,
        }
    }

    /// Records the revision of the data of this snapshot. Read it **before** the grants: a revision
    /// older than the data is a safe claim, a newer one lets stale data pass for fresh.
    #[must_use]
    pub fn with_revision(mut self, revision: Revision) -> Self {
        self.revision = Some(revision);
        self
    }

    #[must_use]
    pub fn with_tuples(mut self, tuples: InMemoryTuples) -> Self {
        self.tuples = Some(tuples);
        self
    }
}

/// The loader the embedder provides.
#[async_trait]
pub trait DecisionSource: Send + Sync + 'static {
    /// Loads the data of one answer.
    ///
    /// # Errors
    ///
    /// [`SourceError::Unavailable`] when it cannot; the server answers 503 and denies.
    async fn snapshot(&self) -> Result<Arc<Snapshot>, SourceError>;
}

/// A source that keeps one snapshot in memory. For tests and examples; [`MemorySource::replace`]
/// swaps the data without restarting the server.
pub struct MemorySource {
    current: RwLock<Arc<Snapshot>>,
}

impl MemorySource {
    pub fn new(snapshot: Snapshot) -> Self {
        Self {
            current: RwLock::new(Arc::new(snapshot)),
        }
    }

    pub fn replace(&self, snapshot: Snapshot) {
        // A poisoned lock still holds a whole `Arc`: nothing half-written can be behind it.
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(snapshot);
    }
}

#[async_trait]
impl DecisionSource for MemorySource {
    async fn snapshot(&self) -> Result<Arc<Snapshot>, SourceError> {
        Ok(Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner)))
    }
}
