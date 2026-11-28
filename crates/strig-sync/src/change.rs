use serde::{Deserialize, Serialize};
use strig::{Anchor, Resource, Revision};

/// What changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Grants,
    Tuples,
    Roles,
    Catalog,
    /// Application change that also invalidates permissions (customer plan, flag).
    Custom,
    /// The node lost changes (transport reconnection, lagging subscriber): everything that is
    /// cached must be reloaded.
    Resync,
}

/// Notice that the permissions under `scope` changed. It does not carry the grants: whoever receives it
/// reloads from the source, so the notice is small and fits any transport (`pg_notify`
/// accepts up to 8000 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub kind: ChangeKind,
    /// Affected step. `global` affects every resource.
    pub scope: Anchor,
    /// Restricts the notice to one subject (a role change for one person).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Id of the changed object (grant, tuple), informational.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Node that published. Filled in by the hub.
    #[serde(default)]
    pub origin: String,
    /// Per-origin sequence. Filled in by the hub.
    #[serde(default)]
    pub seq: u64,
    /// Milliseconds since the Unix epoch. Filled in by the hub.
    #[serde(default)]
    pub at: u64,
    /// The revision the store gave the write this notice announces. A receiver that decides after
    /// a write asks for it with `at_least`. Absent for changes that are not writes (expiry, resync).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<Revision>,
}

impl Change {
    pub fn new(kind: ChangeKind, scope: Anchor) -> Self {
        Self {
            kind,
            scope,
            subject: None,
            id: None,
            origin: String::new(),
            seq: 0,
            at: 0,
            revision: None,
        }
    }

    pub fn grants(scope: Anchor) -> Self {
        Self::new(ChangeKind::Grants, scope)
    }

    pub fn tuples(scope: Anchor) -> Self {
        Self::new(ChangeKind::Tuples, scope)
    }

    pub fn roles(subject: impl Into<String>, scope: Anchor) -> Self {
        Self::new(ChangeKind::Roles, scope).for_subject(subject)
    }

    pub fn catalog() -> Self {
        Self::new(ChangeKind::Catalog, Anchor::global())
    }

    pub fn resync() -> Self {
        Self::new(ChangeKind::Resync, Anchor::global())
    }

    /// A grant or role assignment of `subject` started or stopped being in force. Emitted by the
    /// hub's expiry scheduler, not by a write; only that subject's sessions and cache entries react.
    pub fn expiry(subject: impl Into<String>) -> Self {
        Self::new(ChangeKind::Grants, Anchor::global()).for_subject(subject)
    }

    /// A grant or role assignment that applies to everyone started or stopped being in force.
    /// Every session and cache entry on the node reacts, so use it only when that is the point;
    /// a subject without an id never gets this (see [`Change::expiry`]).
    pub fn expiry_for_everyone() -> Self {
        Self::new(ChangeKind::Grants, Anchor::global())
    }

    pub fn for_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Carries the revision the store gave the write (see [`strig::RevisionSource`]).
    pub fn with_revision(mut self, revision: Revision) -> Self {
        self.revision = Some(revision);
        self
    }

    /// Does the change affect `subject`'s permissions on `scope`?
    pub fn affects(&self, subject: Option<&str>, scope: &Resource) -> bool {
        if self.kind == ChangeKind::Resync {
            return true;
        }
        if let Some(target) = &self.subject
            && subject != Some(target.as_str())
        {
            return false;
        }
        scope.contains(&self.scope)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Change sempre serializa")
    }

    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_and_subject_filter() {
        let doc = Resource::new("document", "d1").within("project", "p1");
        assert!(Change::grants(Anchor::new("project", "p1")).affects(Some("u"), &doc));
        assert!(!Change::grants(Anchor::new("project", "p2")).affects(Some("u"), &doc));
        assert!(Change::catalog().affects(None, &doc));
        let roles = Change::roles("alice", Anchor::new("project", "p1"));
        assert!(roles.affects(Some("alice"), &doc));
        assert!(!roles.affects(Some("bob"), &doc));
    }

    #[test]
    fn the_revision_rides_the_json_and_is_absent_without_one() {
        let change = Change::grants(Anchor::new("org", "o1")).with_revision(Revision::new("tenant", 9));
        let json = change.to_json();
        assert!(json.contains(r#""revision":"tenant@9""#), "{json}");
        assert_eq!(Change::from_json(&json).unwrap(), change);
        // A notice from an older node has no revision and still reads.
        let old = Change::from_json(r#"{"kind":"grants","scope":{"kind":"org","id":"o1"}}"#).unwrap();
        assert_eq!(old.revision, None);
    }

    #[test]
    fn json_round_trip() {
        let change = Change::grants(Anchor::new("org", "o1")).with_id("g1");
        assert_eq!(Change::from_json(&change.to_json()).unwrap(), change);
        assert_eq!(
            change.to_json(),
            r#"{"kind":"grants","scope":{"kind":"org","id":"o1"},"id":"g1","origin":"","seq":0,"at":0}"#
        );
    }
}
