//! Cache with a TTL and the capability cache that is invalidated through the [`crate::Hub`].
//!
//! The cache is an optimization: the application still revalidates on the server on every
//! privileged operation.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use strig::{CapabilitySet, Resource, Revision, Subject};

use crate::change::{Change, ChangeKind};
use crate::hub::{ChangeSink, now_ms};

struct Entry<V> {
    value: V,
    stored_at: Instant,
    /// `None` when the lifetime does not fit an `Instant`: the entry never expires by age.
    expires_at: Option<Instant>,
}

impl<V> Entry<V> {
    fn is_live(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|at| now < at)
    }
}

pub struct TtlCache<K, V> {
    ttl: Duration,
    capacity: usize,
    entries: Mutex<HashMap<K, Entry<V>>>,
}

impl<K: Eq + Hash + Clone, V: Clone> TtlCache<K, V> {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity: capacity.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<K, Entry<V>>> {
        self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn get(&self, key: &K) -> Option<V> {
        let entries = self.lock();
        let now = Instant::now();
        entries
            .get(key)
            .filter(|entry| entry.is_live(now))
            .map(|entry| entry.value.clone())
    }

    pub fn insert(&self, key: K, value: V) {
        self.insert_for(key, value, self.ttl);
    }

    /// Like [`TtlCache::insert`], but the entry lives for the shorter of the cache TTL and
    /// `max_age`. For a value that stops being valid at a known instant.
    pub fn insert_for(&self, key: K, value: V, max_age: Duration) {
        let mut entries = self.lock();
        let now = Instant::now();
        if entries.len() >= self.capacity && !entries.contains_key(&key) {
            entries.retain(|_, entry| entry.is_live(now));
            if entries.len() >= self.capacity
                && let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.stored_at)
                    .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            key,
            Entry {
                value,
                stored_at: now,
                expires_at: now.checked_add(self.ttl.min(max_age)),
            },
        );
    }

    pub fn invalidate(&self, key: &K) {
        self.lock().remove(key);
    }

    /// Keeps only the entries for which `keep` returns `true`.
    pub fn retain(&self, keep: impl Fn(&K, &V) -> bool) {
        self.lock().retain(|key, entry| keep(key, &entry.value));
    }

    pub fn clear(&self) {
        self.lock().clear();
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What the cache keeps per subject and scope: whose entry it is, the set, when the set stops being
/// valid and the revision of the data it was computed from.
#[derive(Clone)]
struct CachedSet {
    subject: Option<String>,
    scope: Resource,
    set: CapabilitySet,
    boundary: Option<u64>,
    revision: Option<Revision>,
}

/// [`CapabilitySet`] per subject and scope. Registered on the hub with [`crate::Hub::on_change`],
/// it drops the entries a change affects.
///
/// An entry never outlives the next validity boundary of its set (a grant or role assignment that
/// starts or stops being in force), so a capability is not served after its `valid_until`. The
/// monotonic lifetime does not count time the machine spent suspended; the wall-clock check on every
/// read covers that and a clock step.
pub struct CapabilityCache {
    inner: TtlCache<String, CachedSet>,
}

impl CapabilityCache {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            inner: TtlCache::new(ttl, capacity),
        }
    }

    fn key(subject: &Subject, scope: &Resource) -> String {
        let path: Vec<String> = scope.path.iter().map(ToString::to_string).collect();
        format!(
            "{}:{}|{}",
            subject.kind,
            subject.id.as_deref().unwrap_or("-"),
            path.join("/")
        )
    }

    pub fn get(&self, subject: &Subject, scope: &Resource) -> Option<CapabilitySet> {
        self.get_with_boundary(subject, scope).map(|(set, _)| set)
    }

    /// The cached set and the instant at which it stops being valid (see
    /// [`CapabilityCache::insert_with_boundary`]).
    ///
    /// The entry lifetime runs on the monotonic clock, which a wall-clock step or a suspend of the
    /// machine moves apart from the validity boundary, so the boundary is also compared with the wall
    /// clock here: an entry whose boundary has been reached is a miss (fail closed).
    pub fn get_with_boundary(&self, subject: &Subject, scope: &Resource) -> Option<(CapabilitySet, Option<u64>)> {
        self.get_with_boundary_at(subject, scope, now_ms())
    }

    fn get_with_boundary_at(
        &self,
        subject: &Subject,
        scope: &Resource,
        wall_ms: u64,
    ) -> Option<(CapabilitySet, Option<u64>)> {
        self.inner
            .get(&Self::key(subject, scope))
            // `wall_ms` is truncated to the millisecond: one more keeps the cut strict.
            .filter(|entry| entry.boundary.is_none_or(|b| b > wall_ms.saturating_add(1)))
            .map(|entry| (entry.set, entry.boundary))
    }

    /// Like [`CapabilityCache::get_with_boundary`], but the entry is served only if it was computed
    /// from data at `required` or later. An entry with no revision, or from another data scope, does
    /// not count: it is a miss, and the caller reloads (fail closed).
    pub fn get_at_least(
        &self,
        subject: &Subject,
        scope: &Resource,
        required: &Revision,
    ) -> Option<(CapabilitySet, Option<u64>)> {
        self.get_revised(subject, scope, Some(required))
            .map(|(set, boundary, _)| (set, boundary))
    }

    /// The entry with the revision of the data it was computed from, read in one lookup so the two
    /// always belong together. With `required`, see [`CapabilityCache::get_at_least`].
    pub fn get_revised(
        &self,
        subject: &Subject,
        scope: &Resource,
        required: Option<&Revision>,
    ) -> Option<(CapabilitySet, Option<u64>, Option<Revision>)> {
        let wall_ms = now_ms();
        self.inner
            .get(&Self::key(subject, scope))
            .filter(|entry| entry.boundary.is_none_or(|b| b > wall_ms.saturating_add(1)))
            .filter(|entry| {
                required.is_none_or(|required| {
                    entry
                        .revision
                        .as_ref()
                        .is_some_and(|have| have.reaches(required).is_reached())
                })
            })
            .map(|entry| (entry.set, entry.boundary, entry.revision))
    }

    /// Stores a set that was computed just now, by the system clock. See [`CapabilityCache::insert_at`].
    ///
    /// Only for a set evaluated at this moment. If a grant in the set is already out of its window
    /// (it expired between the evaluation and this call) the set is not stored. A caller that
    /// evaluated earlier, or that knows grants the set does not hold, uses
    /// [`CapabilityCache::insert_with_boundary`].
    pub fn insert(&self, subject: &Subject, scope: &Resource, set: CapabilitySet) {
        self.insert_at(subject, scope, set, now_ms());
    }

    /// Stores a set evaluated at `evaluated_at` (milliseconds since the Unix epoch), cutting the TTL at
    /// the set's next validity boundary after that instant. A grant that starts later is not in the
    /// set and is not seen: use [`CapabilityCache::insert_with_boundary`] when the caller knows it.
    pub fn insert_at(&self, subject: &Subject, scope: &Resource, set: CapabilitySet, evaluated_at: u64) {
        // A grant that is not open at the evaluation instant means the set is already stale.
        if set.grants.iter().any(|g| !g.validity().contains(evaluated_at)) {
            return;
        }
        let boundary = set.next_boundary(evaluated_at);
        self.insert_with_boundary(subject, scope, set, boundary, evaluated_at);
    }

    /// Stores a set evaluated at `now_ms` that stays valid until `next_boundary`. Use it when the
    /// boundary is known from more than the set holds: grants that start later are not in the set,
    /// but their start is still a boundary.
    pub fn insert_with_boundary(
        &self,
        subject: &Subject,
        scope: &Resource,
        set: CapabilitySet,
        next_boundary: Option<u64>,
        now_ms: u64,
    ) {
        self.insert_revised(subject, scope, set, next_boundary, now_ms, None);
    }

    /// Like [`CapabilityCache::insert_with_boundary`], also recording the revision of the data the
    /// set was computed from, so a later [`CapabilityCache::get_at_least`] can tell whether the entry
    /// is fresh enough. Read the revision before loading the grants: a claim older than the data is
    /// safe, a newer one is not.
    pub fn insert_revised(
        &self,
        subject: &Subject,
        scope: &Resource,
        set: CapabilitySet,
        next_boundary: Option<u64>,
        now_ms: u64,
        revision: Option<Revision>,
    ) {
        self.inner.insert_for(
            Self::key(subject, scope),
            CachedSet {
                subject: subject.id.clone(),
                scope: scope.clone(),
                set,
                boundary: next_boundary,
                revision,
            },
            max_age(next_boundary, now_ms),
        );
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&self) {
        self.inner.clear();
    }
}

/// Time left until the set's next validity boundary; unlimited when nothing changes any more.
///
/// `now_ms` is truncated, so the real instant is up to 1 ms later: that millisecond comes off the
/// lifetime and the entry is never alive past the boundary.
fn max_age(next_boundary: Option<u64>, now_ms: u64) -> Duration {
    next_boundary.map_or(Duration::MAX, |boundary| {
        Duration::from_millis(boundary.saturating_sub(now_ms.saturating_add(1)))
    })
}

impl ChangeSink for CapabilityCache {
    fn on_change(&self, change: &Change) {
        if change.kind == ChangeKind::Resync {
            self.inner.clear();
            return;
        }
        self.inner
            .retain(|_, entry| !change.affects(entry.subject.as_deref(), &entry.scope));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strig::{Anchor, Grant, SubjectMatcher, TargetSelector};

    #[test]
    fn expires_and_evicts() {
        let cache = TtlCache::new(Duration::from_millis(0), 2);
        cache.insert(1, "a");
        assert_eq!(cache.get(&1), None);

        let cache = TtlCache::new(Duration::from_secs(60), 2);
        cache.insert(1, "a");
        cache.insert(2, "b");
        cache.insert(3, "c");
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&3), Some("c"));
    }

    fn windowed_set(subject: &Subject, valid_until: u64) -> CapabilitySet {
        CapabilitySet {
            subject: subject.clone(),
            grants: vec![
                Grant::allow("g", SubjectMatcher::Any, "project.view", TargetSelector::global())
                    .valid_until(valid_until),
            ],
        }
    }

    #[test]
    fn ttl_is_cut_at_the_next_boundary() {
        let alice = Subject::user("alice");
        let set = windowed_set(&alice, 1_050);
        assert_eq!(max_age(set.next_boundary(1_000), 1_000), Duration::from_millis(49));
        assert_eq!(max_age(None, 1_000), Duration::MAX);
        assert_eq!(max_age(Some(900), 1_000), Duration::ZERO);
    }

    #[test]
    fn entry_does_not_outlive_its_max_age() {
        let cache = TtlCache::new(Duration::from_secs(60), 4);
        cache.insert_for(1, "a", Duration::ZERO);
        cache.insert_for(2, "b", Duration::from_secs(120));
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), Some("b"));
    }

    #[test]
    fn capability_cache_drops_the_set_once_the_boundary_passes() {
        let cache = CapabilityCache::new(Duration::from_secs(60), 10);
        let alice = Subject::user("alice");
        let scope = Resource::new("project", "p1");
        cache.insert_at(&alice, &scope, windowed_set(&alice, 1_001), 1_000);
        std::thread::sleep(Duration::from_millis(30));
        assert!(cache.get(&alice, &scope).is_none(), "served a set past its valid_until");

        let now = now_ms();
        cache.insert_at(&alice, &scope, windowed_set(&alice, now + 1_000_000), now);
        assert!(cache.get(&alice, &scope).is_some());
    }

    #[test]
    fn a_later_start_known_to_the_caller_cuts_the_ttl_and_is_returned() {
        let cache = CapabilityCache::new(Duration::from_secs(60), 10);
        let alice = Subject::user("alice");
        let scope = Resource::new("project", "p1");
        let empty = CapabilitySet {
            subject: alice.clone(),
            grants: Vec::new(),
        };
        cache.insert_with_boundary(&alice, &scope, empty.clone(), Some(1_000), 1_000);
        assert!(cache.get(&alice, &scope).is_none(), "served a set at its boundary");

        let now = now_ms();
        let later = now + 5_000_000;
        cache.insert_with_boundary(&alice, &scope, empty.clone(), Some(later), now);
        assert_eq!(cache.get_with_boundary(&alice, &scope), Some((empty, Some(later))));
    }

    #[test]
    fn the_entry_lifetime_never_exceeds_the_time_left_to_the_boundary() {
        // `now_ms` truncates: at 1_000.9 ms the boundary at 1_001 is 0.1 ms away, not 1 ms.
        assert_eq!(max_age(Some(1_001), 1_000), Duration::ZERO);
        assert_eq!(max_age(Some(1_002), 1_000), Duration::from_millis(1));
    }

    #[test]
    fn a_wall_clock_jump_past_the_boundary_is_a_miss() {
        let cache = CapabilityCache::new(Duration::from_secs(60), 10);
        let alice = Subject::user("alice");
        let scope = Resource::new("project", "p1");
        let now = now_ms();
        let boundary = now + 30_000;
        cache.insert_with_boundary(&alice, &scope, windowed_set(&alice, boundary), Some(boundary), now);

        // The monotonic lifetime still has 30 s, but the wall clock jumped 40 s ahead.
        assert!(cache.get_with_boundary_at(&alice, &scope, now).is_some());
        assert!(cache.get_with_boundary_at(&alice, &scope, boundary - 2).is_some());
        assert!(cache.get_with_boundary_at(&alice, &scope, boundary - 1).is_none());
        assert!(cache.get_with_boundary_at(&alice, &scope, now + 40_000).is_none());
    }

    #[test]
    fn insert_does_not_keep_a_set_whose_grant_expired_before_the_insert() {
        let cache = CapabilityCache::new(Duration::from_secs(60), 10);
        let alice = Subject::user("alice");
        let scope = Resource::new("project", "p1");
        // The set was computed while the grant was open; its `valid_until` passed since.
        cache.insert(&alice, &scope, windowed_set(&alice, 1_000));
        assert!(cache.is_empty(), "a stale set stayed for the whole TTL");

        cache.insert_at(&alice, &scope, windowed_set(&alice, 1_000), 1_000);
        assert!(cache.is_empty());
    }

    #[test]
    fn insert_at_cuts_at_the_boundary_after_the_evaluation_instant() {
        let cache = CapabilityCache::new(Duration::from_secs(60), 10);
        let alice = Subject::user("alice");
        let scope = Resource::new("project", "p1");
        let now = now_ms();
        cache.insert_at(&alice, &scope, windowed_set(&alice, now + 5_000), now - 1_000);
        let (_, boundary) = cache.get_with_boundary(&alice, &scope).expect("still in force");
        assert_eq!(boundary, Some(now + 5_000));
    }

    #[test]
    fn change_drops_only_affected_entries() {
        let cache = CapabilityCache::new(Duration::from_secs(60), 100);
        let alice = Subject::user("alice");
        let p1 = Resource::new("project", "p1").within("org", "o1");
        let p2 = Resource::new("project", "p2").within("org", "o2");
        let empty = |s: &Subject| CapabilitySet {
            subject: s.clone(),
            grants: Vec::new(),
        };
        cache.insert(&alice, &p1, empty(&alice));
        cache.insert(&alice, &p2, empty(&alice));

        cache.on_change(&Change::grants(Anchor::new("org", "o1")));
        assert!(cache.get(&alice, &p1).is_none());
        assert!(cache.get(&alice, &p2).is_some());

        cache.on_change(&Change::roles("bob", Anchor::new("org", "o2")));
        assert!(cache.get(&alice, &p2).is_some());
        cache.on_change(&Change::roles("alice", Anchor::new("org", "o2")));
        assert!(cache.is_empty());
    }
}
