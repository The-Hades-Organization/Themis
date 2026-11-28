//! Limits of the server: body size, batch size, deadlines and query cost.

use std::time::Duration;

use axum::http::HeaderMap;
use strig::QueryLimits;

use crate::error::{ApiError, ErrorCode};

/// Request header that carries the caller's deadline, in milliseconds. The server never waits
/// longer than [`ServerConfig::max_timeout`], whatever the header says.
pub const TIMEOUT_HEADER: &str = "x-strig-timeout-ms";

/// Request header that carries the revision the answer must be computed from, as the opaque token a
/// write returned. The server answers 503 (`revision_not_reached`, `revision_mismatch`) instead of
/// deciding from older data. It works on every decision route, AuthZEN included.
pub const MIN_REVISION_HEADER: &str = "x-strig-min-revision";

/// Limits applied to every request.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ServerConfig {
    /// Largest request body in bytes. Past it the answer is 413.
    pub max_body_bytes: usize,
    /// Most checks in one `POST /v1/check/batch`.
    pub max_batch: usize,
    /// Most candidate resources in one `POST /v1/list`.
    pub max_resources: usize,
    /// Deadline of a request that sends none.
    pub default_timeout: Duration,
    /// Ceiling of every deadline.
    pub max_timeout: Duration,
    /// Ceilings of the reverse queries (`who`, `access`). Past one the answer is 503
    /// `query_limit_exceeded`.
    pub query_limits: QueryLimits,
    /// Most grant evaluations (items times grants) one batch, or the candidate resolution of one
    /// listing, may cost. Past it the answer is 503 `query_limit_exceeded`.
    pub max_work: usize,
    /// Most requests whose engine work runs at once. A request that finds no free slot before its
    /// deadline is answered 503 `overloaded`. The slot is held until the work really ends, so a
    /// request that timed out cannot pile up work behind it.
    pub max_concurrent_work: usize,
}

impl ServerConfig {
    pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
    pub const DEFAULT_MAX_BATCH: usize = 256;
    pub const DEFAULT_MAX_RESOURCES: usize = 1_000;
    /// Default of [`ServerConfig::max_work`].
    pub const DEFAULT_MAX_WORK: usize = 1_000_000;
    /// Default of the `max_parties` ceiling of [`ServerConfig::query_limits`]: tighter than the
    /// engine's, because the server answers untrusted callers.
    pub const DEFAULT_MAX_PARTIES: usize = 1_000;
    /// Default of the `max_decisions` ceiling of [`ServerConfig::query_limits`].
    pub const DEFAULT_MAX_DECISIONS: usize = 100_000;

    #[must_use]
    pub fn with_max_body_bytes(mut self, bytes: usize) -> Self {
        self.max_body_bytes = bytes;
        self
    }

    #[must_use]
    pub fn with_max_batch(mut self, items: usize) -> Self {
        self.max_batch = items;
        self
    }

    #[must_use]
    pub fn with_max_resources(mut self, items: usize) -> Self {
        self.max_resources = items;
        self
    }

    #[must_use]
    pub fn with_default_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_max_timeout(mut self, timeout: Duration) -> Self {
        self.max_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_query_limits(mut self, limits: QueryLimits) -> Self {
        self.query_limits = limits;
        self
    }

    #[must_use]
    pub fn with_max_work(mut self, work: usize) -> Self {
        self.max_work = work;
        self
    }

    /// At least one slot: zero would refuse every request.
    #[must_use]
    pub fn with_max_concurrent_work(mut self, slots: usize) -> Self {
        self.max_concurrent_work = slots.max(1);
        self
    }

    /// The deadline of a request: the header when it has one, the default otherwise, never more
    /// than the ceiling.
    pub(crate) fn timeout_for(&self, headers: &HeaderMap) -> Result<Duration, ApiError> {
        let Some(raw) = headers.get(TIMEOUT_HEADER) else {
            return Ok(self.default_timeout.min(self.max_timeout));
        };
        let ms = raw
            .to_str()
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
            .filter(|ms| *ms > 0)
            .ok_or(ApiError::new(ErrorCode::InvalidRequest))?;
        Ok(Duration::from_millis(ms).min(self.max_timeout))
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: Self::DEFAULT_MAX_BODY_BYTES,
            max_batch: Self::DEFAULT_MAX_BATCH,
            max_resources: Self::DEFAULT_MAX_RESOURCES,
            default_timeout: Duration::from_secs(2),
            max_timeout: Duration::from_secs(10),
            query_limits: QueryLimits::default()
                .with_max_parties(Self::DEFAULT_MAX_PARTIES)
                .with_max_decisions(Self::DEFAULT_MAX_DECISIONS),
            max_work: Self::DEFAULT_MAX_WORK,
            // One slot per core: the work is CPU-bound, more only adds queueing.
            max_concurrent_work: std::thread::available_parallelism().map_or(2, std::num::NonZero::get),
        }
    }
}
