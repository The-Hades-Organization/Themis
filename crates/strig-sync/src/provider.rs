use std::sync::Arc;

use async_trait::async_trait;
use strig::{CapabilitySet, Context, Engine, Grant, Reached, Resource, Revised, Revision, Subject};

use crate::cache::CapabilityCache;
use crate::consistency::{ConsistencyError, ConsistencyOptions};
use crate::hub::now_ms;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Computes the capabilities a session sends to the client.
#[async_trait]
pub trait CapabilityProvider: Send + Sync + 'static {
    async fn capabilities(&self, subject: &Subject, scope: &Resource) -> Result<CapabilitySet, BoxError>;

    /// Like [`CapabilityProvider::capabilities`], plus the instant the set was evaluated at and the
    /// next moment a grant or role assignment starts or stops being in force. Sessions schedule the
    /// expiry notice from it. The default derives the boundary from the returned set, which misses
    /// grants that start later; a provider that knows its candidate grants should override it.
    async fn evaluate(&self, subject: &Subject, scope: &Resource) -> Result<Evaluation, BoxError> {
        let evaluated_at = self.now_ms();
        let set = self.capabilities(subject, scope).await?;
        let next_boundary = set.next_boundary(evaluated_at);
        Ok(Evaluation {
            set,
            evaluated_at,
            next_boundary,
        })
    }

    /// Like [`CapabilityProvider::evaluate`], with the revision of the data the set was computed from
    /// and, when `required` is given, the guarantee that the data is at that revision or later: an
    /// instance that is behind catches up or answers [`ConsistencyError`], and never decides from older
    /// state. The default cannot prove a revision, so it refuses a `required` (fail closed) and answers
    /// without one otherwise; a provider that knows its data's revision overrides it.
    async fn evaluate_revised(
        &self,
        subject: &Subject,
        scope: &Resource,
        required: Option<&Revision>,
    ) -> Result<Revised<Evaluation>, ConsistencyError> {
        if let Some(required) = required {
            return Err(ConsistencyError::Untracked {
                required: required.clone(),
            });
        }
        let evaluation = self.evaluate(subject, scope).await.map_err(ConsistencyError::Source)?;
        Ok(Revised::new(evaluation, None))
    }

    /// The instant, in milliseconds since the Unix epoch, that `capabilities` evaluates validity
    /// windows at. Sessions use it to schedule the expiry notice. Defaults to the system clock.
    fn now_ms(&self) -> u64 {
        now_ms()
    }
}

/// Capabilities with the validity information a session needs to schedule its next recompute.
#[derive(Debug, Clone, PartialEq)]
pub struct Evaluation {
    pub set: CapabilitySet,
    /// Instant the set was evaluated at, milliseconds since the Unix epoch.
    pub evaluated_at: u64,
    /// Next instant after `evaluated_at` at which the set goes stale; `None` when it never does.
    pub next_boundary: Option<u64>,
}

/// Source of the current instant, in milliseconds since the Unix epoch.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Fetches the candidate grants of a subject in a scope (database, service, file).
///
/// Return the grants that start later too, and drop at most the ones that already expired: the
/// provider schedules the recompute at each start, and a start the loader filtered out never
/// triggers one. The engine applies the validity window itself, so a grant that has not started
/// is not granted. With the `strig-postgres` crate, filter with `candidate_predicate`, not
/// `window_predicate`.
#[async_trait]
pub trait GrantLoader: Send + Sync + 'static {
    async fn load(&self, subject: &Subject, scope: &Resource) -> Result<Vec<Grant>, BoxError>;

    /// The revision of the data `load` reads, or `None` when the store does not number its writes.
    ///
    /// The provider reads it **before** `load`: a revision older than the grants is a safe claim, a
    /// newer one would let stale grants pass for fresh. A database loader returns the latest value of
    /// the sequence or version column its writes bump in the same transaction as the change.
    async fn revision(&self) -> Result<Option<Revision>, BoxError> {
        Ok(None)
    }
}

#[async_trait]
impl GrantLoader for Vec<Grant> {
    async fn load(&self, _: &Subject, _: &Resource) -> Result<Vec<Grant>, BoxError> {
        Ok(self.clone())
    }
}

/// Default [`CapabilityProvider`]: loads the grants through the [`GrantLoader`], filters them with
/// [`Engine::capabilities`] and stores the result in the [`CapabilityCache`], if there is one.
pub struct EngineProvider<L> {
    engine: Arc<Engine>,
    loader: L,
    cache: Option<Arc<CapabilityCache>>,
    clock: Clock,
    consistency: ConsistencyOptions,
    known: std::sync::Mutex<Option<Revision>>,
}

impl<L: GrantLoader> EngineProvider<L> {
    pub fn new(engine: Arc<Engine>, loader: L) -> Self {
        Self {
            engine,
            loader,
            cache: None,
            clock: Arc::new(now_ms),
            consistency: ConsistencyOptions::default(),
            known: std::sync::Mutex::new(None),
        }
    }

    /// How long a decision that requires a revision waits for this instance to reach it before it
    /// denies. Default: one second, polling every 25 ms.
    #[must_use]
    pub fn with_consistency(mut self, options: ConsistencyOptions) -> Self {
        self.consistency = options;
        self
    }

    /// The latest revision this instance has read from the loader, if the loader tracks one.
    pub fn known_revision(&self) -> Option<Revision> {
        self.known
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn remember(&self, revision: &Revision) {
        let mut known = self.known.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if known
            .as_ref()
            .is_none_or(|have| have.reaches(revision) == Reached::Behind || have.scope() != revision.scope())
        {
            *known = Some(revision.clone());
        }
    }

    /// Reads the loader's revision until it reaches `required` or the wait runs out.
    async fn settle(&self, required: Option<&Revision>) -> Result<Option<Revision>, ConsistencyError> {
        let started = tokio::time::Instant::now();
        loop {
            let revision = self.loader.revision().await.map_err(ConsistencyError::Source)?;
            if let Some(revision) = &revision {
                self.remember(revision);
            }
            let Some(required) = required else {
                return Ok(revision);
            };
            let Some(have) = revision else {
                return Err(ConsistencyError::Untracked {
                    required: required.clone(),
                });
            };
            match have.reaches(required) {
                Reached::Yes => return Ok(Some(have)),
                Reached::OtherScope => {
                    return Err(ConsistencyError::OtherScope {
                        required: required.clone(),
                        have,
                    });
                }
                _ => {
                    let left = self.consistency.timeout.saturating_sub(started.elapsed());
                    if left.is_zero() {
                        return Err(ConsistencyError::NotReached {
                            required: required.clone(),
                            have,
                        });
                    }
                    tokio::time::sleep(self.consistency.poll.min(left)).await;
                }
            }
        }
    }

    async fn evaluate_inner(
        &self,
        subject: &Subject,
        scope: &Resource,
        required: Option<&Revision>,
    ) -> Result<Revised<Evaluation>, ConsistencyError> {
        let now = (self.clock)();
        if let Some(cache) = &self.cache
            && let Some((set, next_boundary, revision)) = cache.get_revised(subject, scope, required)
        {
            return Ok(Revised::new(
                Evaluation {
                    set,
                    evaluated_at: now,
                    next_boundary,
                },
                revision,
            ));
        }
        let revision = self.settle(required).await?;
        let grants = self
            .loader
            .load(subject, scope)
            .await
            .map_err(ConsistencyError::Source)?;
        let set = self.engine.capabilities(&Context::new(&grants).at(now), subject, scope);
        // From the candidates, not from the set: a grant that starts later is not in the set yet.
        let next_boundary = strig::next_boundary(now, &grants, &subject.roles);
        if let Some(cache) = &self.cache {
            // Measured when the entry is stored, not when it was evaluated: the TTL counts from the
            // insert, so time spent loading must come off the lifetime.
            cache.insert_revised(
                subject,
                scope,
                set.clone(),
                next_boundary,
                (self.clock)(),
                revision.clone(),
            );
        }
        Ok(Revised::new(
            Evaluation {
                set,
                evaluated_at: now,
                next_boundary,
            },
            revision,
        ))
    }

    /// Replaces the system clock that decides which validity windows are open, for tests and for
    /// deployments that keep their own time source.
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Remember to register the same cache on the hub (`hub.on_change(cache.clone())`).
    ///
    /// The cache checks each entry's boundary against the system wall clock when it serves it, so
    /// a clock set with [`EngineProvider::with_clock`] must count milliseconds since the Unix epoch.
    pub fn with_cache(mut self, cache: Arc<CapabilityCache>) -> Self {
        self.cache = Some(cache);
        self
    }
}

#[async_trait]
impl<L: GrantLoader> CapabilityProvider for EngineProvider<L> {
    async fn capabilities(&self, subject: &Subject, scope: &Resource) -> Result<CapabilitySet, BoxError> {
        Ok(self.evaluate(subject, scope).await?.set)
    }

    async fn evaluate(&self, subject: &Subject, scope: &Resource) -> Result<Evaluation, BoxError> {
        let revised = self
            .evaluate_inner(subject, scope, None)
            .await
            .map_err(|error| match error {
                ConsistencyError::Source(source) => source,
                other => Box::new(other) as BoxError,
            })?;
        Ok(revised.value)
    }

    async fn evaluate_revised(
        &self,
        subject: &Subject,
        scope: &Resource,
        required: Option<&Revision>,
    ) -> Result<Revised<Evaluation>, ConsistencyError> {
        self.evaluate_inner(subject, scope, required).await
    }

    fn now_ms(&self) -> u64 {
        (self.clock)()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use strig::{Catalog, PermissionDef, SubjectMatcher, TargetSelector};

    fn engine() -> Arc<Engine> {
        let catalog = Catalog::builder()
            .target_kinds(["project"])
            .broad_target("org")
            .permission(PermissionDef::new("project.view").targets(["project"]))
            .build()
            .unwrap();
        Arc::new(Engine::builder(catalog).build().unwrap())
    }

    fn view() -> Grant {
        Grant::allow(
            "g",
            SubjectMatcher::Any,
            "project.view",
            TargetSelector::kind("project"),
        )
    }

    #[tokio::test]
    async fn the_next_boundary_comes_from_candidates_that_start_later() {
        let grants = vec![view().valid_from(5_000)];
        let provider = EngineProvider::new(engine(), grants).with_clock(|| 1_000);
        let evaluation = provider
            .evaluate(&Subject::user("alice"), &Resource::new("project", "p1"))
            .await
            .unwrap();
        assert!(evaluation.set.grants.is_empty());
        assert_eq!(evaluation.next_boundary, Some(5_000));
    }

    #[tokio::test]
    async fn a_cache_that_is_not_registered_on_the_hub_still_drops_an_expired_set() {
        let now = now_ms();
        let grants = vec![view().valid_until(now + 60)];
        let cache = Arc::new(CapabilityCache::new(Duration::from_secs(60), 10));
        let provider = EngineProvider::new(engine(), grants).with_cache(cache);
        let (alice, scope) = (Subject::user("alice"), Resource::new("project", "p1"));

        assert_eq!(provider.evaluate(&alice, &scope).await.unwrap().set.grants.len(), 1);
        tokio::time::sleep(Duration::from_millis(120)).await;
        // Past the `valid_until`: the entry is a miss and the set is recomputed without the grant.
        assert!(provider.evaluate(&alice, &scope).await.unwrap().set.grants.is_empty());
    }
}
