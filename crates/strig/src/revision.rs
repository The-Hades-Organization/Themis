//! Revision tokens: read your own writes, end to end.
//!
//! A [`Revision`] orders the changes applied to one data scope (a tenant, a database, a store). The
//! store that persists a change assigns it, through a [`RevisionSource`]; the token then travels with
//! the result of the write, the change notice, the capabilities sent to a client and the decision
//! request, so whoever decides after a write can ask for "at least this revision" and refuse to
//! answer from older state.
//!
//! The token is opaque text (`scope@value` today, never to be parsed by callers) and is only
//! comparable inside one scope: two tokens of different scopes say nothing about each other, and
//! [`Revision::reached_by`] reports that as [`Reached::OtherScope`] so the caller denies instead of
//! guessing.

use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A position in the history of one data scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Revision {
    scope: String,
    value: u64,
}

/// How a revision a holder has compares with the one a decision requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Reached {
    /// The holder is at the required revision or past it.
    Yes,
    /// Same scope, older state.
    Behind,
    /// The two tokens belong to different data scopes and cannot be compared.
    OtherScope,
}

impl Reached {
    pub fn is_reached(self) -> bool {
        self == Reached::Yes
    }
}

impl Revision {
    /// The `value`-th revision of `scope`. `scope` names the data the sequence orders; it must not
    /// be empty (an empty scope is read as the scope `default`).
    pub fn new(scope: impl Into<String>, value: u64) -> Self {
        let scope = scope.into();
        Self {
            scope: if scope.is_empty() {
                DEFAULT_SCOPE.to_owned()
            } else {
                scope
            },
            value,
        }
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    /// Whether the state a holder has (`None` when it has no revision at all) has reached `required`.
    pub fn reached_by(required: &Revision, have: Option<&Revision>) -> Reached {
        match have {
            Some(have) => have.reaches(required),
            None => Reached::OtherScope,
        }
    }

    /// Whether `self`, the state a holder has, has reached `required`.
    pub fn reaches(&self, required: &Revision) -> Reached {
        if self.scope != required.scope {
            Reached::OtherScope
        } else if self.value >= required.value {
            Reached::Yes
        } else {
            Reached::Behind
        }
    }

    /// The same scope, `value` revisions later. Saturates.
    #[must_use]
    pub fn advanced(&self, by: u64) -> Self {
        Self {
            scope: self.scope.clone(),
            value: self.value.saturating_add(by),
        }
    }
}

/// The scope an empty one is read as.
pub const DEFAULT_SCOPE: &str = "default";

/// The text did not read as a revision token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionParseError;

impl std::error::Error for RevisionParseError {}

impl fmt::Display for RevisionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a revision token")
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.scope, self.value)
    }
}

impl FromStr for Revision {
    type Err = RevisionParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (scope, value) = text.rsplit_once('@').ok_or(RevisionParseError)?;
        if scope.is_empty() {
            return Err(RevisionParseError);
        }
        let value = value.parse::<u64>().map_err(|_| RevisionParseError)?;
        Ok(Revision::new(scope, value))
    }
}

impl Serialize for Revision {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Revision {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Where revisions come from: the store that persists the changes of one data scope.
///
/// [`RevisionSource::next`] is called once per applied change, after the change is durable, and
/// must return strictly increasing revisions of the same scope. A database store backs it with a
/// sequence or a version column written in the same transaction as the change; the memory and
/// file stores use [`MemoryRevisions`].
pub trait RevisionSource: Send + Sync {
    /// The revision of the change that was just applied.
    fn next(&self) -> Revision;

    /// The revision of the latest change applied so far.
    fn current(&self) -> Revision;
}

/// A [`RevisionSource`] that counts in memory, for the memory and file stores and for tests.
#[derive(Debug)]
pub struct MemoryRevisions {
    scope: String,
    counter: AtomicU64,
}

impl MemoryRevisions {
    /// Starts at revision 0 of `scope`: nothing has been applied yet.
    pub fn new(scope: impl Into<String>) -> Self {
        Self::starting_at(scope, 0)
    }

    /// Resumes a counter whose latest revision is `value` (a store that reloads from disk).
    pub fn starting_at(scope: impl Into<String>, value: u64) -> Self {
        Self {
            scope: Revision::new(scope, 0).scope,
            counter: AtomicU64::new(value),
        }
    }
}

impl RevisionSource for MemoryRevisions {
    fn next(&self) -> Revision {
        let value = self.counter.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        Revision::new(self.scope.clone(), value)
    }

    fn current(&self) -> Revision {
        Revision::new(self.scope.clone(), self.counter.load(Ordering::SeqCst))
    }
}

/// A value together with the revision its write was given.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Revised<T> {
    pub value: T,
    /// Absent when the [`crate::Governance`] has no [`RevisionSource`].
    pub revision: Option<Revision>,
}

impl<T> Revised<T> {
    pub fn new(value: T, revision: Option<Revision>) -> Self {
        Self { value, revision }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trip_keeps_an_at_sign_in_the_scope() {
        let revision = Revision::new("tenant@eu", 7);
        assert_eq!(revision.to_string(), "tenant@eu@7");
        assert_eq!("tenant@eu@7".parse::<Revision>().unwrap(), revision);
        let json = serde_json::to_string(&revision).unwrap();
        assert_eq!(json, "\"tenant@eu@7\"");
        assert_eq!(serde_json::from_str::<Revision>(&json).unwrap(), revision);
    }

    #[test]
    fn garbage_does_not_parse() {
        for text in ["", "7", "@7", "a@", "a@-1", "a@x"] {
            assert!(text.parse::<Revision>().is_err(), "{text}");
        }
        assert!(serde_json::from_str::<Revision>("3").is_err());
    }

    #[test]
    fn comparison_is_per_scope() {
        let have = Revision::new("a", 5);
        assert_eq!(have.reaches(&Revision::new("a", 5)), Reached::Yes);
        assert_eq!(have.reaches(&Revision::new("a", 4)), Reached::Yes);
        assert_eq!(have.reaches(&Revision::new("a", 6)), Reached::Behind);
        assert_eq!(have.reaches(&Revision::new("b", 1)), Reached::OtherScope);
        assert_eq!(Revision::reached_by(&Revision::new("a", 1), None), Reached::OtherScope);
    }

    #[test]
    fn memory_source_is_monotonic() {
        let source = MemoryRevisions::new("t");
        assert_eq!(source.current().value(), 0);
        let (a, b) = (source.next(), source.next());
        assert!(b.value() > a.value());
        assert_eq!(source.current(), b);
    }
}
