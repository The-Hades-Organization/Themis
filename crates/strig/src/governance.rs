use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::attr::Attributes;
#[cfg(feature = "audit")]
use crate::audit::{AuditStatus, Auditor, FailMode};
use crate::condition::Condition;
use crate::decision::Request;
use crate::engine::{Context, Engine};
use crate::explain::Explanation;
use crate::grant::{Effect, Grant, SubjectMatcher};
use crate::impact::{Impact, ImpactOptions};
use crate::rebac::TupleStore;
use crate::resource::{Anchor, Resource};
use crate::revision::{Revised, Revision, RevisionSource};
use crate::subject::{RoleAssignment, Subject};

/// Proposed change to the grant set or to a subject's roles.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum Mutation {
    Add(Grant),
    Remove {
        id: String,
    },
    /// Gives `role` to `subject`. The grant set does not change; whoever stores the subject's roles
    /// writes [`Mutation::subject_after`].
    AssignRole {
        subject: Subject,
        role: RoleAssignment,
    },
    /// Takes `role` from `subject`, comparing role and scope.
    RevokeRole {
        subject: Subject,
        role: RoleAssignment,
    },
}

impl Mutation {
    /// Subject, assignment and `true` to assign (`false` to revoke), if the change is a
    /// role change.
    pub fn role_change(&self) -> Option<(&Subject, &RoleAssignment, bool)> {
        match self {
            Mutation::AssignRole { subject, role } => Some((subject, role, true)),
            Mutation::RevokeRole { subject, role } => Some((subject, role, false)),
            Mutation::Add(_) | Mutation::Remove { .. } => None,
        }
    }

    /// Which of the four changes this is.
    pub fn kind(&self) -> MutationKind {
        match self {
            Mutation::Add(_) => MutationKind::Add,
            Mutation::Remove { .. } => MutationKind::Remove,
            Mutation::AssignRole { .. } => MutationKind::AssignRole,
            Mutation::RevokeRole { .. } => MutationKind::RevokeRole,
        }
    }

    /// The subject of the role change with the role added or removed. `None` for a grant
    /// change.
    pub fn subject_after(&self) -> Option<Subject> {
        let (subject, role, assigned) = self.role_change()?;
        Some(with_role_change(subject, role, assigned))
    }
}

/// The kind of a [`Mutation`], without its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    Add,
    Remove,
    AssignRole,
    RevokeRole,
}

impl MutationKind {
    pub const ALL: [MutationKind; 4] = [
        MutationKind::Add,
        MutationKind::Remove,
        MutationKind::AssignRole,
        MutationKind::RevokeRole,
    ];

    /// The name the kind has in JSON and in the audit trail.
    pub fn as_str(self) -> &'static str {
        match self {
            MutationKind::Add => "add",
            MutationKind::Remove => "remove",
            MutationKind::AssignRole => "assign_role",
            MutationKind::RevokeRole => "revoke_role",
        }
    }
}

pub(crate) fn with_role_change(subject: &Subject, role: &RoleAssignment, assigned: bool) -> Subject {
    let mut next = subject.clone();
    if !assigned {
        next.roles.retain(|r| r != role);
    } else if !next.roles.contains(role) {
        next.roles.push(role.clone());
    }
    next
}

/// Same subject: subjects are identified by id, ignoring the kind, and only when the id exists.
/// The same id with another kind counts as the same subject, the safe side for self-management and lockout.
pub(crate) fn same_subject(a: &Subject, b: &Subject) -> bool {
    a.id.is_some() && a.id == b.id
}

/// The role assignments of `subject` that a rule guarding a change must count at `now`: the ones that
/// have not ended and have a well-formed window. An assignment that starts later still counts, because
/// the rule protects against what the holder will have, not only what they have at this instant;
/// without an instant nothing is known to have ended. Compare with the engine, where only what is in
/// force decides.
pub(crate) fn standing_roles(subject: &Subject, now: Option<u64>) -> impl Iterator<Item = &RoleAssignment> {
    subject
        .roles
        .iter()
        .filter(move |r| r.check_window().is_ok() && !r.validity().has_ended(now))
}

fn role_label(role: &RoleAssignment) -> String {
    match &role.scope {
        Some(scope) => format!("{} em {scope}", role.role),
        None => role.role.clone(),
    }
}

/// What an invariant sees: who changes, what, and the set before and after. In a role
/// change, `before` and `after` are the same set; the effect shows up in
/// [`Proposal::subject_after`].
pub struct Proposal<'a> {
    pub actor: &'a Subject,
    pub mutation: &'a Mutation,
    pub before: &'a [Grant],
    pub after: &'a [Grant],
    pub tuples: Option<&'a dyn TupleStore>,
    /// The instant the change is judged at, in milliseconds since the Unix epoch; see
    /// [`Governance::at`]. Without it, grants and roles with a validity window fail closed, as in
    /// [`Engine::decide`].
    pub now: Option<u64>,
}

impl<'a> Proposal<'a> {
    /// The grant added, or the one removed. `None` for a role change.
    pub fn grant(&self) -> Option<&'a Grant> {
        match self.mutation {
            Mutation::Add(grant) => Some(grant),
            Mutation::Remove { id } => self.before.iter().find(|g| &g.id == id),
            Mutation::AssignRole { .. } | Mutation::RevokeRole { .. } => None,
        }
    }

    /// `subject` as it would be after the change: with the role applied, if it is the subject of
    /// the role change (same id); unchanged in the other cases.
    pub fn subject_after<'s>(&self, subject: &'s Subject) -> Cow<'s, Subject> {
        match self.mutation.role_change() {
            Some((target, role, assigned)) if same_subject(target, subject) => {
                Cow::Owned(with_role_change(subject, role, assigned))
            }
            _ => Cow::Borrowed(subject),
        }
    }

    pub fn before_context(&self) -> Context<'_> {
        self.context(&self.before)
    }

    pub fn after_context(&self) -> Context<'_> {
        self.context(&self.after)
    }

    fn context<'s>(&'s self, grants: &'s &'a [Grant]) -> Context<'s> {
        let ctx = Context::new(grants);
        let ctx = match self.tuples {
            Some(tuples) => ctx.with_tuples(tuples),
            None => ctx,
        };
        match self.now {
            Some(now) => ctx.at(now),
            None => ctx,
        }
    }
}

/// Compensating change proposed with a [`Violation`]. It names the subject by id and carries only
/// the role: nothing else about the subject is exposed to whoever causes the refusal or reads the
/// audit. Nothing is applied; the caller turns it into an ordinary change with
/// [`Suggestion::into_mutation`] and sends it through the governance like any other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Suggestion {
    AssignRole { subject_id: String, role: RoleAssignment },
    RevokeRole { subject_id: String, role: RoleAssignment },
}

impl Suggestion {
    /// The suggestion for a role change; `None` for a grant change or a subject without id.
    fn of(mutation: &Mutation) -> Option<Self> {
        let (subject, role, assigned) = mutation.role_change()?;
        let subject_id = subject.id.clone()?;
        let role = role.clone();
        Some(if assigned {
            Suggestion::AssignRole { subject_id, role }
        } else {
            Suggestion::RevokeRole { subject_id, role }
        })
    }

    /// The change to send, for the stored `subject` the suggestion names (same id).
    pub fn into_mutation(self, subject: Subject) -> Mutation {
        match self {
            Suggestion::AssignRole { role, .. } => Mutation::AssignRole { subject, role },
            Suggestion::RevokeRole { role, .. } => Mutation::RevokeRole { subject, role },
        }
    }

    pub fn subject_id(&self) -> &str {
        match self {
            Suggestion::AssignRole { subject_id, .. } | Suggestion::RevokeRole { subject_id, .. } => subject_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    pub invariant: String,
    pub message: String,
    /// Change that would let the refused one through, set by [`Governance`] only when it was
    /// checked: the invariant's [`Invariant::remedy`] passes every invariant, with the same actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<Box<Suggestion>>,
}

impl Violation {
    pub fn new(invariant: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            invariant: invariant.into(),
            message: message.into(),
            suggestion: None,
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.invariant, self.message)
    }
}

/// Rule that every grant or role change must respect.
pub trait Invariant: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation>;

    /// The change that would let a refused proposal through, called only after `check` refused it.
    /// [`Governance`] sends it through every invariant, with the same actor and the same grant set,
    /// and only a change they all accept becomes the [`Violation::suggestion`]. Only role changes
    /// are suggested. The default proposes nothing.
    fn remedy(&self, _engine: &Engine, _proposal: &Proposal<'_>) -> Option<Mutation> {
        None
    }
}

#[cfg(feature = "audit")]
type CallMode = Option<FailMode>;
#[cfg(not(feature = "audit"))]
type CallMode = Option<std::convert::Infallible>;

#[cfg(feature = "audit")]
type Delivery = Option<AuditStatus>;
#[cfg(not(feature = "audit"))]
type Delivery = Option<std::convert::Infallible>;

/// What a governed change came to: the grants after it and its impact, or the violations.
type Applied = Result<(Vec<Grant>, Option<Impact>), Vec<Violation>>;

/// A change applied together with what it does to access, from [`Governance::apply_with_impact`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct AppliedWithImpact {
    /// The grants after the change, as [`Governance::apply`] returns them.
    pub grants: Vec<Grant>,
    pub impact: Impact,
    /// The revision the change was given, when the governance has a [`RevisionSource`].
    pub revision: Option<Revision>,
}

/// Applies grant and role changes only after they pass every invariant and, with the
/// `audit` feature, after recording the decision.
#[derive(Default)]
pub struct Governance {
    invariants: Vec<Box<dyn Invariant>>,
    #[cfg(feature = "audit")]
    auditor: Option<Arc<Auditor>>,
    revisions: Option<Arc<dyn RevisionSource>>,
}

impl Governance {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, invariant: impl Invariant + 'static) -> Self {
        self.invariants.push(Box::new(invariant));
        self
    }

    /// Records every change, applied or refused. If the record fails, the change is refused
    /// with the `audit` violation.
    #[cfg(feature = "audit")]
    pub fn audited(mut self, auditor: Arc<Auditor>) -> Self {
        self.auditor = Some(auditor);
        self
    }

    /// Gives every accepted change the next revision of `source`, which the revised and impact results
    /// carry (see [`Governance::apply_revised`]). The source belongs to the store that persists the
    /// change: it hands out the revision after the change is applied, so a refused change takes none.
    #[must_use]
    pub fn with_revisions(mut self, source: Arc<dyn RevisionSource>) -> Self {
        self.revisions = Some(source);
        self
    }

    fn next_revision(&self) -> Option<Revision> {
        self.revisions.as_ref().map(|source| source.next())
    }

    /// [`Governance::apply`] with the revision the accepted change was given. `None` without a
    /// [`Governance::with_revisions`] source.
    pub fn apply_revised(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        tuples: Option<&dyn TupleStore>,
        meta: &Attributes,
    ) -> Result<Revised<Vec<Grant>>, Vec<Violation>> {
        let grants = self.apply_with(engine, actor, current, mutation, tuples, meta)?;
        Ok(Revised::new(grants, self.next_revision()))
    }

    /// The auditor `audited` set, for the records of the approval flow (see [`crate::pending`]).
    #[cfg(feature = "audit")]
    pub(crate) fn auditor(&self) -> Option<&Arc<Auditor>> {
        self.auditor.as_ref()
    }

    pub fn len(&self) -> usize {
        self.invariants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.invariants.is_empty()
    }

    /// Returns the grant set after the change, or all the violations. Persistence
    /// is up to the application, which writes only on `Ok`. For a role change the set comes back unchanged
    /// and the subject to write comes from [`Mutation::subject_after`].
    pub fn apply(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        tuples: Option<&dyn TupleStore>,
    ) -> Result<Vec<Grant>, Vec<Violation>> {
        self.apply_with(engine, actor, current, mutation, tuples, &Attributes::new())
    }

    /// The governance judging every change at `now` (milliseconds since the Unix epoch): the actor's
    /// grants and roles, and the grants and roles the change reads, count only inside their validity
    /// window, as with [`Context::at`]. The crate never reads a clock; the caller passes the instant.
    /// [`Governance::apply`] and [`Governance::apply_with`] pass none, and what has a window then fails
    /// closed.
    pub fn at(&self, now: u64) -> GovernanceAt<'_> {
        GovernanceAt {
            governance: self,
            now,
            call_mode: None,
        }
    }

    /// Like [`Governance::apply`], with request metadata (ip, request id, reason) that goes
    /// to the audit from the `detailed` level upward.
    pub fn apply_with(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        tuples: Option<&dyn TupleStore>,
        meta: &Attributes,
    ) -> Result<Vec<Grant>, Vec<Violation>> {
        self.run(engine, actor, current, mutation, Scene { tuples, now: None }, meta)
    }

    /// What `mutation` would do to access: who gains, who loses and what cannot be settled. The
    /// invariants judge the change first, as in [`Governance::apply`], and refuse it with their
    /// violations; nothing is recorded and nothing changes. See [`crate::impact`] for where the
    /// subjects and resources come from and what the answer promises.
    pub fn impact(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        options: &ImpactOptions<'_>,
    ) -> Result<Impact, Vec<Violation>> {
        let scene = Scene {
            tuples: options.tuples.map(upcast),
            now: options.now,
        };
        let after = self.evaluate_inner(engine, actor, current, mutation, scene, true)?;
        Ok(crate::impact::compute(engine, current, &after, mutation, options))
    }

    /// [`Governance::apply_with`] that also computes the impact before applying and returns it. With an
    /// auditor at `detailed` or `forensic`, the record of the change carries a summary of it (counts and
    /// a few examples). A refused change records no impact.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_with_impact(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        tuples: Option<&dyn TupleStore>,
        meta: &Attributes,
        options: &ImpactOptions<'_>,
    ) -> Result<AppliedWithImpact, Vec<Violation>> {
        let scene = Scene {
            tuples,
            now: options.now,
        };
        let (result, _) = self.run_impact(engine, actor, current, mutation, scene, meta, None, Some(options));
        result.map(|(grants, impact)| AppliedWithImpact {
            grants,
            impact: impact.unwrap_or_default(),
            revision: self.next_revision(),
        })
    }

    fn run(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        scene: Scene<'_>,
        meta: &Attributes,
    ) -> Result<Vec<Grant>, Vec<Violation>> {
        self.run_reporting(engine, actor, current, mutation, scene, meta, None)
            .0
    }

    /// `run` plus where the audit record ended up (`None` with no auditor). `call` is the
    /// [`FailMode`] for this change.
    #[allow(clippy::too_many_arguments)]
    fn run_reporting(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        scene: Scene<'_>,
        meta: &Attributes,
        call: CallMode,
    ) -> (Result<Vec<Grant>, Vec<Violation>>, Delivery) {
        let (result, delivery) = self.run_impact(engine, actor, current, mutation, scene, meta, call, None);
        (result.map(|(grants, _)| grants), delivery)
    }

    /// `run_reporting` that also computes the impact of an accepted change when `options` is given and
    /// hands it to the audit record.
    #[allow(clippy::too_many_arguments)]
    fn run_impact(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        scene: Scene<'_>,
        meta: &Attributes,
        call: CallMode,
        options: Option<&ImpactOptions<'_>>,
    ) -> (Applied, Delivery) {
        crate::obs::mutation(
            || {
                let evaluated = self.evaluate_inner(engine, actor, current, mutation, scene, true);
                let impact = match (&evaluated, options) {
                    (Ok(after), Some(options)) => {
                        let options = ImpactOptions {
                            now: scene.now.or(options.now),
                            ..options.clone()
                        };
                        Some(crate::impact::compute(engine, current, after, mutation, &options))
                    }
                    _ => None,
                };
                #[cfg(feature = "audit")]
                if let Some(auditor) = &self.auditor {
                    return match auditor.grant_mutation_impact(
                        actor,
                        mutation,
                        current,
                        &evaluated,
                        meta,
                        call,
                        impact.as_ref(),
                    ) {
                        Ok(emitted) => (evaluated.map(|g| (g, impact)), Some(emitted.status)),
                        Err(error) => (Err(vec![Violation::new("audit", error.to_string())]), None),
                    };
                }
                #[cfg(not(feature = "audit"))]
                let _ = (meta, call);
                (evaluated.map(|g| (g, impact)), None)
            },
            |(result, _)| result.as_ref().err().map(Vec::as_slice),
        )
    }

    /// The mutation checked against the invariants, with no audit and no side effect. Also used by
    /// [`Materialized::apply`](crate::Materialized::apply) to check a whole batch before recording any of it.
    pub(crate) fn evaluate(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        tuples: Option<&dyn TupleStore>,
    ) -> Result<Vec<Grant>, Vec<Violation>> {
        self.evaluate_inner(engine, actor, current, mutation, Scene { tuples, now: None }, true)
    }

    /// [`Governance::evaluate`] at `now`, for the approval flow to judge a change without recording it.
    pub(crate) fn evaluate_at(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        tuples: Option<&dyn TupleStore>,
        now: u64,
    ) -> Result<Vec<Grant>, Vec<Violation>> {
        let scene = Scene { tuples, now: Some(now) };
        self.evaluate_inner(engine, actor, current, mutation, scene, true)
    }

    fn evaluate_inner(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        scene: Scene<'_>,
        with_remedies: bool,
    ) -> Result<Vec<Grant>, Vec<Violation>> {
        let after: Cow<'_, [Grant]> = match mutation {
            Mutation::Add(grant) => {
                if current.iter().any(|g| g.id == grant.id) {
                    return Err(vec![Violation::new(
                        "mutation",
                        format!("grant {} já existe", grant.id),
                    )]);
                }
                let mut next = current.to_vec();
                next.push(grant.clone());
                Cow::Owned(next)
            }
            Mutation::Remove { id } => {
                if !current.iter().any(|g| &g.id == id) {
                    return Err(vec![Violation::new("mutation", format!("grant {id} não existe"))]);
                }
                Cow::Owned(current.iter().filter(|g| &g.id != id).cloned().collect())
            }
            Mutation::AssignRole { subject, role } => {
                check_role_mutation(subject, role, true)?;
                Cow::Borrowed(current)
            }
            Mutation::RevokeRole { subject, role } => {
                check_role_mutation(subject, role, false)?;
                Cow::Borrowed(current)
            }
        };
        let proposal = Proposal {
            actor,
            mutation,
            before: current,
            after: &after,
            tuples: scene.tuples,
            now: scene.now,
        };
        let mut violations = Vec::new();
        for invariant in &self.invariants {
            let Err(mut violation) = invariant.check(engine, &proposal) else {
                continue;
            };
            if with_remedies
                && let Some(fix) = invariant.remedy(engine, &proposal)
                && self.evaluate_inner(engine, actor, current, &fix, scene, false).is_ok()
            {
                violation.suggestion = Suggestion::of(&fix).map(Box::new);
            }
            violations.push(violation);
        }
        if violations.is_empty() {
            Ok(after.into_owned())
        } else {
            Err(violations)
        }
    }
}

/// What a change is judged against besides the grants: the tuples and the instant.
#[derive(Clone, Copy)]
struct Scene<'a> {
    tuples: Option<&'a dyn TupleStore>,
    now: Option<u64>,
}

fn upcast(index: &dyn crate::rebac::TupleIndex) -> &dyn TupleStore {
    index
}

/// [`Governance`] judging every change at one instant; see [`Governance::at`].
pub struct GovernanceAt<'g> {
    governance: &'g Governance,
    now: u64,
    call_mode: CallMode,
}

impl GovernanceAt<'_> {
    /// The [`FailMode`] of the audit of every change made through this value, over the mode of the
    /// permission and the auditor's default.
    #[cfg(feature = "audit")]
    pub fn fail_mode(mut self, mode: FailMode) -> Self {
        self.call_mode = Some(mode);
        self
    }

    /// Like [`GovernanceAt::apply_with`], and also says where the audit record ended up: `None`
    /// with no auditor or a refused record, `Some(Pending)` when the sink failed in `open` mode and
    /// the change went ahead anyway.
    #[cfg(feature = "audit")]
    pub fn apply_reporting(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        tuples: Option<&dyn TupleStore>,
        meta: &Attributes,
    ) -> (Result<Vec<Grant>, Vec<Violation>>, Option<AuditStatus>) {
        let scene = Scene {
            tuples,
            now: Some(self.now),
        };
        self.governance
            .run_reporting(engine, actor, current, mutation, scene, meta, self.call_mode)
    }

    /// Like [`Governance::apply`], at the instant.
    pub fn apply(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        tuples: Option<&dyn TupleStore>,
    ) -> Result<Vec<Grant>, Vec<Violation>> {
        self.apply_with(engine, actor, current, mutation, tuples, &Attributes::new())
    }

    /// Like [`Governance::impact`], at the instant.
    pub fn impact(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        options: &ImpactOptions<'_>,
    ) -> Result<Impact, Vec<Violation>> {
        let options = ImpactOptions {
            now: Some(self.now),
            ..options.clone()
        };
        self.governance.impact(engine, actor, current, mutation, &options)
    }

    /// Like [`Governance::apply_with_impact`], at the instant.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_with_impact(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        tuples: Option<&dyn TupleStore>,
        meta: &Attributes,
        options: &ImpactOptions<'_>,
    ) -> Result<AppliedWithImpact, Vec<Violation>> {
        let scene = Scene {
            tuples,
            now: Some(self.now),
        };
        let (result, _) = self.governance.run_impact(
            engine,
            actor,
            current,
            mutation,
            scene,
            meta,
            self.call_mode,
            Some(options),
        );
        result.map(|(grants, impact)| AppliedWithImpact {
            grants,
            impact: impact.unwrap_or_default(),
            revision: self.governance.next_revision(),
        })
    }

    /// Like [`Governance::apply_revised`], at the instant.
    pub fn apply_revised(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        tuples: Option<&dyn TupleStore>,
        meta: &Attributes,
    ) -> Result<Revised<Vec<Grant>>, Vec<Violation>> {
        let grants = self.apply_with(engine, actor, current, mutation, tuples, meta)?;
        Ok(Revised::new(grants, self.governance.next_revision()))
    }

    /// Like [`Governance::apply_with`], at the instant.
    pub fn apply_with(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        tuples: Option<&dyn TupleStore>,
        meta: &Attributes,
    ) -> Result<Vec<Grant>, Vec<Violation>> {
        let scene = Scene {
            tuples,
            now: Some(self.now),
        };
        self.governance
            .run_reporting(engine, actor, current, mutation, scene, meta, self.call_mode)
            .0
    }
}

fn check_role_mutation(subject: &Subject, role: &RoleAssignment, assigned: bool) -> Result<(), Vec<Violation>> {
    let Some(id) = subject.id.as_deref() else {
        return Err(vec![Violation::new(
            "mutation",
            "papel só se atribui a sujeito identificado",
        )]);
    };
    if assigned && let Err(error) = role.check_window() {
        return Err(vec![Violation::new("mutation", error.to_string())]);
    }
    let has = subject.roles.contains(role);
    let message = match (assigned, has) {
        (true, true) => format!("{id} já tem o papel {}", role_label(role)),
        (false, false) => format!("{id} não tem o papel {}", role_label(role)),
        _ => return Ok(()),
    };
    Err(vec![Violation::new("mutation", message)])
}

/// The added grant exists in the catalog and targets a kind the permission accepts. The assigned
/// role is known (it is in the engine's [`RoleGraph`](crate::RoleGraph) or in some current grant) and
/// its scope, if any, uses a kind from the catalog. Revoking always passes: removing an
/// unknown role is cleanup.
pub struct CatalogConformance;

impl CatalogConformance {
    fn check_role(&self, engine: &Engine, current: &[Grant], role: &RoleAssignment) -> Result<(), Violation> {
        let known = engine.roles().contains(&role.role)
            || current
                .iter()
                .any(|g| matches!(&g.subject, SubjectMatcher::Role { id } if *id == role.role));
        if !known {
            return Err(Violation::new(
                self.name(),
                format!("papel desconhecido: {}", role.role),
            ));
        }
        match &role.scope {
            Some(scope) if !engine.catalog().is_target_kind(&scope.kind) => Err(Violation::new(
                self.name(),
                format!("escopo {scope} usa tipo fora do catálogo"),
            )),
            _ => Ok(()),
        }
    }
}

impl Invariant for CatalogConformance {
    fn name(&self) -> &str {
        "catalog_conformance"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        match proposal.mutation {
            Mutation::Add(grant) => engine
                .validate_grant(grant)
                .map_err(|e| Violation::new(self.name(), e.to_string())),
            Mutation::AssignRole { role, .. } => self.check_role(engine, proposal.before, role),
            Mutation::Remove { .. } | Mutation::RevokeRole { .. } => Ok(()),
        }
    }
}

/// Nobody changes a grant that applies to themselves: neither the user directly, nor a role they
/// hold (direct or inherited). Grants by principal and by relation are left out. Nobody assigns
/// or revokes a role of their own, either.
pub struct NoSelfManagement;

impl Invariant for NoSelfManagement {
    fn name(&self) -> &str {
        "no_self_management"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        let actor = proposal.actor;
        if let Some((subject, _, _)) = proposal.mutation.role_change() {
            return if same_subject(subject, actor) {
                Err(Violation::new(
                    self.name(),
                    "não é permitido gerenciar os próprios papéis",
                ))
            } else {
                Ok(())
            };
        }
        let Some(grant) = proposal.grant() else {
            return Ok(());
        };
        let affects_actor = match &grant.subject {
            SubjectMatcher::User { id } => actor.id.as_deref() == Some(id.as_str()),
            SubjectMatcher::Role { id } => engine
                .roles()
                .expand(standing_roles(actor, proposal.now).map(|r| r.role.as_str()))
                .contains(id),
            _ => false,
        };
        if affects_actor {
            Err(Violation::new(
                self.name(),
                "não é permitido gerenciar as próprias permissões",
            ))
        } else {
            Ok(())
        }
    }
}

/// The actor must hold `key` on `resource` before the change.
pub struct RequirePermission {
    key: String,
    resource: Resource,
}

impl RequirePermission {
    pub fn new(key: impl Into<String>, resource: Resource) -> Self {
        Self {
            key: key.into(),
            resource,
        }
    }
}

impl Invariant for RequirePermission {
    fn name(&self) -> &str {
        "require_permission"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        let request = Request::new(proposal.actor, &self.key, &self.resource);
        if engine.check(&proposal.before_context(), &request) {
            Ok(())
        } else {
            Err(Violation::new(self.name(), format!("falta a permissão {}", self.key)))
        }
    }
}

/// After the change, each critical permission still has at least one member able to
/// exercise it on `resource`. Prevents locking a scope out of its own management. Each member
/// is evaluated as they would be after the change ([`Proposal::subject_after`]), so revoking the
/// role of the last one who exercises the permission is also refused.
///
/// With [`NoLockout::with_reserve`], the refusal may carry a [`Suggestion`]: assigning the
/// administrator role to a reserve subject. It is only offered when it really fixes the lockout and
/// the governance accepts it (see [`Invariant::remedy`]); otherwise the violation has no suggestion.
pub struct NoLockout {
    critical: Vec<String>,
    members: Vec<Subject>,
    resource: Resource,
    reserve: Option<Reserve>,
}

struct Reserve {
    admin_role: RoleAssignment,
    subjects: Vec<Subject>,
}

impl NoLockout {
    pub fn new<I, S>(critical: I, members: Vec<Subject>, resource: Resource) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            critical: critical.into_iter().map(Into::into).collect(),
            members,
            resource,
            reserve: None,
        }
    }

    /// Subjects held in reserve and the administrator role that the suggestion assigns to one of
    /// them. A reserve subject is only suggested when it is one of the `members` (same id), has an
    /// id, does not have the role yet, is not the actor of the refused change, and the role makes
    /// every critical permission covered again. Only its id and the role leave the invariant.
    #[must_use]
    pub fn with_reserve<I>(mut self, admin_role: RoleAssignment, subjects: I) -> Self
    where
        I: IntoIterator<Item = Subject>,
    {
        self.reserve = Some(Reserve {
            admin_role,
            subjects: subjects.into_iter().collect(),
        });
        self
    }

    /// Critical permissions with no member able to exercise them after the change. With `promoted`,
    /// that subject stands in for the member with the same id.
    fn uncovered(&self, engine: &Engine, proposal: &Proposal<'_>, promoted: Option<&Subject>) -> Vec<&String> {
        let ctx = proposal.after_context();
        self.critical
            .iter()
            .filter(|key| {
                !self.members.iter().any(|m| {
                    let member = match promoted {
                        Some(p) if same_subject(p, m) => Cow::Borrowed(p),
                        _ => proposal.subject_after(m),
                    };
                    engine.check(&ctx, &Request::new(&member, key, &self.resource))
                })
            })
            .collect()
    }
}

impl Invariant for NoLockout {
    fn name(&self) -> &str {
        "no_lockout"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        match self.uncovered(engine, proposal, None).first() {
            Some(first) => Err(Violation::new(
                self.name(),
                format!("a mudança deixaria ninguém com a permissão {first}"),
            )),
            None => Ok(()),
        }
    }

    fn remedy(&self, engine: &Engine, proposal: &Proposal<'_>) -> Option<Mutation> {
        let reserve = self.reserve.as_ref()?;
        reserve.subjects.iter().find_map(|candidate| {
            candidate.id.as_ref()?;
            if same_subject(candidate, proposal.actor) {
                return None;
            }
            let member = self.members.iter().find(|m| same_subject(m, candidate))?;
            let base = proposal.subject_after(member);
            if member.roles.contains(&reserve.admin_role) || base.roles.contains(&reserve.admin_role) {
                return None;
            }
            let promoted = with_role_change(&base, &reserve.admin_role, true);
            self.uncovered(engine, proposal, Some(&promoted))
                .is_empty()
                .then(|| Mutation::AssignRole {
                    subject: member.clone(),
                    role: reserve.admin_role.clone(),
                })
        })
    }
}

/// `subject` never receives `allow` on `permissions` or on any permission that grants them.
///
/// On a role assignment, it only applies when `subject` is [`SubjectMatcher::User`] with the
/// subject's id: it refuses the role if any current `allow` grant for them, or for a role they inherit,
/// grants a forbidden permission, regardless of scope. The other matchers (principal, `any`,
/// role, relation) do not apply to role assignment.
pub struct Forbid {
    subject: SubjectMatcher,
    permissions: Vec<String>,
}

impl Forbid {
    pub fn new<I, S>(subject: SubjectMatcher, permissions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            subject,
            permissions: permissions.into_iter().map(Into::into).collect(),
        }
    }
}

impl Invariant for Forbid {
    fn name(&self) -> &str {
        "forbid"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        match proposal.mutation {
            Mutation::Add(grant) => self.check_grant(engine, grant),
            Mutation::AssignRole { subject, role } => self.check_role(engine, proposal, subject, role),
            Mutation::Remove { .. } | Mutation::RevokeRole { .. } => Ok(()),
        }
    }
}

impl Forbid {
    fn forbidden_by<'s>(&'s self, engine: &Engine, permission: &str) -> Option<&'s String> {
        self.permissions
            .iter()
            .find(|p| engine.catalog().implies(permission, p))
    }

    fn check_grant(&self, engine: &Engine, grant: &Grant) -> Result<(), Violation> {
        if grant.effect != Effect::Allow || grant.subject != self.subject {
            return Ok(());
        }
        match self.forbidden_by(engine, &grant.permission) {
            Some(forbidden) => Err(Violation::new(
                self.name(),
                format!(
                    "{} concederia {forbidden}, proibido para este sujeito",
                    grant.permission
                ),
            )),
            None => Ok(()),
        }
    }

    fn check_role(
        &self,
        engine: &Engine,
        proposal: &Proposal<'_>,
        subject: &Subject,
        role: &RoleAssignment,
    ) -> Result<(), Violation> {
        let SubjectMatcher::User { id } = &self.subject else {
            return Ok(());
        };
        if subject.id.as_deref() != Some(id.as_str()) {
            return Ok(());
        }
        let roles = engine.roles().expand([role.role.as_str()]);
        for grant in proposal
            .before
            .iter()
            .filter(|g| g.effect == Effect::Allow && !g.validity().has_ended(proposal.now))
        {
            let SubjectMatcher::Role { id: granted } = &grant.subject else {
                continue;
            };
            if !roles.contains(granted) {
                continue;
            }
            if let Some(forbidden) = self.forbidden_by(engine, &grant.permission) {
                return Err(Violation::new(
                    self.name(),
                    format!(
                        "o papel {} concederia {forbidden} pelo grant {} ({}), proibido para este sujeito",
                        role.role, grant.id, grant.permission
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Resource on which `grant` takes effect, as far as governance can tell without a concrete
/// resource: the target step (a kind-only target becomes `kind:*`), the grant's scope and the scope
/// of the role assignment that carries it. The implicit `global` is not repeated.
fn grant_resource(grant: &Grant, role_scope: Option<&Anchor>) -> Resource {
    let mut path: Vec<Anchor> = Vec::new();
    let target = Anchor {
        kind: grant.target.kind.clone(),
        id: grant.target.id.clone().or_else(|| Some(KIND_WILDCARD.to_string())),
    };
    for anchor in [Some(target), grant.scope.clone(), role_scope.cloned()]
        .into_iter()
        .flatten()
    {
        if !anchor.is_global() && !path.contains(&anchor) {
            path.push(anchor);
        }
    }
    Resource {
        path,
        ..Resource::default()
    }
}

/// Id of the synthetic step that stands for "any instance" of a kind-only target.
const KIND_WILDCARD: &str = "*";

/// Id of the probe subject built from a grant's matcher.
pub(crate) const PROBE_ID: &str = "strig:probe";

/// A subject that the grant's matcher selects. `None` for a relation, which depends on tuples.
pub(crate) fn matcher_subject(matcher: &SubjectMatcher) -> Option<Subject> {
    Some(match matcher {
        SubjectMatcher::User { id } => Subject::user(id.clone()),
        SubjectMatcher::Role { id } => Subject::user(PROBE_ID).with_role(id.clone()),
        SubjectMatcher::Principal { name } => Subject::user(PROBE_ID).with_principal(name.clone()),
        SubjectMatcher::Any => Subject::user(PROBE_ID),
        SubjectMatcher::Relation { .. } => return None,
    })
}

/// What a change hands out: one allow grant, on one resource, with every permission it confers.
struct Conferred<'a> {
    grant: &'a Grant,
    resource: Resource,
    /// The grant's permission and every permission it grants by implication.
    keys: Vec<String>,
}

fn conferred_keys(engine: &Engine, permission: &str) -> Vec<String> {
    let mut keys = vec![permission.to_string()];
    keys.extend(engine.catalog().descendants(permission));
    keys
}

/// The allow grants that the change gives to someone: the added grant, or, in a role assignment,
/// the allow grants of the role (and of the roles it inherits) in the scope of the assignment.
fn conferred<'a>(engine: &Engine, proposal: &Proposal<'a>) -> Vec<Conferred<'a>> {
    let ended = |grant: &Grant| grant.validity().has_ended(proposal.now);
    match proposal.mutation {
        Mutation::Add(grant) if grant.effect == Effect::Allow && !ended(grant) => vec![Conferred {
            grant,
            resource: grant_resource(grant, None),
            keys: conferred_keys(engine, &grant.permission),
        }],
        Mutation::AssignRole { role, .. } if !role.validity().has_ended(proposal.now) => {
            let roles = engine.roles().expand([role.role.as_str()]);
            proposal
                .before
                .iter()
                .filter(|g| g.effect == Effect::Allow && !ended(g))
                .filter(|g| matches!(&g.subject, SubjectMatcher::Role { id } if roles.contains(id)))
                .map(|grant| Conferred {
                    grant,
                    resource: grant_resource(grant, role.scope.as_ref()),
                    keys: conferred_keys(engine, &grant.permission),
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

/// The `deny` grants that the change lifts: the removed one, or, in a role revocation, the `deny`
/// grants of the role (and of the roles it inherits) in the scope of the assignment. What each one was
/// blocking, the permission and the ones it implies, is now open to its subject.
fn unlocked<'a>(engine: &Engine, proposal: &Proposal<'a>) -> Vec<Conferred<'a>> {
    let ended = |grant: &Grant| grant.validity().has_ended(proposal.now);
    match proposal.mutation {
        Mutation::Remove { .. } => proposal
            .grant()
            .filter(|g| g.effect == Effect::Deny && !ended(g))
            .map(|grant| Conferred {
                grant,
                resource: grant_resource(grant, None),
                keys: conferred_keys(engine, &grant.permission),
            })
            .into_iter()
            .collect(),
        Mutation::RevokeRole { role, .. } if !role.validity().has_ended(proposal.now) => {
            let roles = engine.roles().expand([role.role.as_str()]);
            proposal
                .before
                .iter()
                .filter(|g| g.effect == Effect::Deny && !ended(g))
                .filter(|g| matches!(&g.subject, SubjectMatcher::Role { id } if roles.contains(id)))
                .map(|grant| Conferred {
                    grant,
                    resource: grant_resource(grant, role.scope.as_ref()),
                    keys: conferred_keys(engine, &grant.permission),
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

/// Holding a permission requires holding its `depends_on` prerequisites on the same resource.
/// The change is refused when it would leave someone with a permission and without one of its
/// prerequisites: adding the permission alone, adding a `deny` on the prerequisite, removing the
/// prerequisite, or assigning or revoking a role that carries them.
///
/// The check is conservative and approximate, not a second decision engine:
///
/// - A grant is probed with a synthetic subject that only has what the grant's matcher selects (a
///   user id, a role, a principal, or nothing for `any`). A role that confers `edit` without `view` is
///   refused even if everyone who holds it also holds another role with `view`; to model that, give the
///   prerequisite to the role itself. A relation matcher depends on tuples and is not probed.
/// - A grant with a condition is probed as it evaluates for the synthetic subject. If the condition is
///   false for it, the grant is not seen. The engine still denies the permission at decision time when the
///   prerequisite is missing, so this never lets anything through.
/// - On a role change, the grants of the subject come from its user id, its roles (each one, with its
///   own scope), its principals and `any`; relation grants are not considered.
/// - The cost grows with grants × permissions they confer × decisions: removing a grant or adding a
///   `deny` walks every `allow` of the set, which is quadratic in large sets.
pub struct Prerequisites;

impl Prerequisites {
    /// The first prerequisite of `key` that `subject` lacks on `resource`, if the subject holds
    /// `key` itself.
    fn missing(
        engine: &Engine,
        ctx: &Context<'_>,
        subject: &Subject,
        key: &str,
        resource: &Resource,
    ) -> Option<String> {
        if !engine.catalog().has_prerequisites(key)
            || !engine
                .decide_ignoring_prerequisites(ctx, &Request::new(subject, key, resource))
                .is_allowed()
        {
            return None;
        }
        engine
            .catalog()
            .prerequisites(key)
            .find(|p| !engine.check(ctx, &Request::new(subject, p, resource)))
            .map(str::to_string)
    }

    fn violation(&self, key: &str, prerequisite: &str) -> Violation {
        Violation::new(self.name(), format!("{key} exige {prerequisite} no mesmo recurso"))
    }

    /// Allow grants that `subject` (after the change) picks up through its user id, each of its roles
    /// (with the scope of the assignment that carries it), its principals, or `any`.
    fn grants_of<'g>(engine: &Engine, subject: &Subject, grants: &'g [Grant]) -> Vec<(&'g Grant, Option<Anchor>)> {
        let mut found = Vec::new();
        for grant in grants.iter().filter(|g| g.effect == Effect::Allow) {
            match &grant.subject {
                SubjectMatcher::User { id } if subject.id.as_deref() == Some(id.as_str()) => {
                    found.push((grant, None));
                }
                SubjectMatcher::Role { id } => {
                    for assignment in &subject.roles {
                        if engine.roles().expand([assignment.role.as_str()]).contains(id) {
                            found.push((grant, assignment.scope.clone()));
                        }
                    }
                }
                SubjectMatcher::Principal { name } if subject.principals.contains(name) => {
                    found.push((grant, None));
                }
                SubjectMatcher::Any => found.push((grant, None)),
                _ => {}
            }
        }
        found
    }

    /// The first `allow` of `after` that stands on a prerequisite the `changed` permission covers and
    /// that is no longer fully held: the grant's holder has it without the prerequisite.
    fn broken_by(
        &self,
        engine: &Engine,
        proposal: &Proposal<'_>,
        ctx: &Context<'_>,
        changed: &str,
    ) -> Result<(), Violation> {
        for grant in proposal.after.iter().filter(|g| g.effect == Effect::Allow) {
            let Some(subject) = matcher_subject(&grant.subject) else {
                continue;
            };
            let resource = grant_resource(grant, None);
            for key in conferred_keys(engine, &grant.permission) {
                let relies = engine
                    .catalog()
                    .prerequisites(&key)
                    .any(|p| engine.catalog().implies(changed, p));
                if !relies {
                    continue;
                }
                if let Some(p) = Self::missing(engine, ctx, &subject, &key, &resource) {
                    return Err(self.violation(&key, &p));
                }
            }
        }
        Ok(())
    }
}

impl Invariant for Prerequisites {
    fn name(&self) -> &str {
        "prerequisites"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        let ctx = proposal.after_context();
        match proposal.mutation {
            Mutation::Add(grant) if grant.effect == Effect::Deny => {
                if grant.validity().has_ended(proposal.now) {
                    return Ok(());
                }
                self.broken_by(engine, proposal, &ctx, &grant.permission)
            }
            Mutation::Add(grant) => {
                let Some(subject) = matcher_subject(&grant.subject) else {
                    return Ok(());
                };
                for c in conferred(engine, proposal) {
                    for key in &c.keys {
                        if let Some(p) = Self::missing(engine, &ctx, &subject, key, &c.resource) {
                            return Err(self.violation(key, &p));
                        }
                    }
                }
                Ok(())
            }
            Mutation::Remove { .. } => match proposal.grant().filter(|g| !g.validity().has_ended(proposal.now)) {
                Some(removed) => self.broken_by(engine, proposal, &ctx, &removed.permission),
                None => Ok(()),
            },
            Mutation::AssignRole { role, .. } | Mutation::RevokeRole { role, .. }
                if role.validity().has_ended(proposal.now) =>
            {
                Ok(())
            }
            Mutation::AssignRole { subject, .. } | Mutation::RevokeRole { subject, .. } => {
                let after = proposal.subject_after(subject);
                for (grant, scope) in Self::grants_of(engine, &after, proposal.after) {
                    let resource = grant_resource(grant, scope.as_ref());
                    for key in conferred_keys(engine, &grant.permission) {
                        if let Some(p) = Self::missing(engine, &ctx, &after, &key, &resource) {
                            return Err(self.violation(&key, &p));
                        }
                    }
                }
                Ok(())
            }
        }
    }
}

/// A permission marked [`PermissionDef::non_delegable`](crate::PermissionDef::non_delegable) is only
/// granted by an actor who holds `manager` on the resource: having the permission is not enough to
/// pass it on. Applies to adding a grant and to assigning a role that carries the permission.
pub struct NonDelegable {
    manager: String,
}

impl NonDelegable {
    pub fn new(manager: impl Into<String>) -> Self {
        Self {
            manager: manager.into(),
        }
    }
}

impl Invariant for NonDelegable {
    fn name(&self) -> &str {
        "non_delegable"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        let ctx = proposal.before_context();
        for c in conferred(engine, proposal) {
            let Some(key) = c
                .keys
                .iter()
                .find(|k| engine.catalog().get(k).is_some_and(|d| d.non_delegable))
            else {
                continue;
            };
            let request = Request::new(proposal.actor, &self.manager, &c.resource);
            if !engine.check(&ctx, &request) {
                return Err(Violation::new(
                    self.name(),
                    format!("{key} não é delegável: só quem tem {} concede", self.manager),
                ));
            }
        }
        Ok(())
    }
}

/// A permission marked [`PermissionDef::management_only`](crate::PermissionDef::management_only) is
/// only granted to the management `roles`: never straight to a user, a principal or an ordinary
/// role. Assigning a role outside `roles` that carries the permission is refused as well.
pub struct ManagementOnly {
    roles: Vec<String>,
}

impl ManagementOnly {
    pub fn new<I, S>(roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            roles: roles.into_iter().map(Into::into).collect(),
        }
    }

    fn is_management(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

impl Invariant for ManagementOnly {
    fn name(&self) -> &str {
        "management_only"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        for c in conferred(engine, proposal) {
            let Some(key) = c
                .keys
                .iter()
                .find(|k| engine.catalog().get(k).is_some_and(|d| d.management_only))
            else {
                continue;
            };
            let allowed = match proposal.mutation {
                Mutation::AssignRole { role, .. } => self.is_management(&role.role),
                _ => matches!(&c.grant.subject, SubjectMatcher::Role { id } if self.is_management(id)),
            };
            if !allowed {
                return Err(Violation::new(
                    self.name(),
                    format!("{key} só pode ser concedida a papéis de gestão"),
                ));
            }
        }
        Ok(())
    }
}

/// Permission that exempts its holder from [`NoEscalation`] on `resource`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bypass {
    pub permission: String,
    pub resource: Resource,
}

impl Bypass {
    pub fn new(permission: impl Into<String>, resource: Resource) -> Self {
        Self {
            permission: permission.into(),
            resource,
        }
    }
}

/// The actor only hands out what they hold. Three things count as handing out:
///
/// - adding an `allow` grant, or assigning a role: every permission it confers, the permission itself
///   and each one it implies, must be held by the actor on the resource where it would apply (for a
///   role: in the scope of the assignment);
/// - removing a `deny` grant, or revoking a role that carries one: the permissions the `deny` was
///   blocking are unlocked for its subject, so the actor must hold each of them where they become
///   valid. It is the same rule as for an `allow`, applied to what the change lets through;
/// - a condition does not widen: when the actor holds a permission only through grants with a
///   condition, the new grant must carry that condition, the same or inside an `all`. Anything else is
///   refused (fail closed), since the check cannot compare conditions by meaning.
///
/// The actor is evaluated against a synthetic resource built from the grant (target, scope and the
/// scope of the assignment), with no attributes: a condition on resource attributes does not hold
/// there, so it also fails closed. With [`NoEscalation::bypass`], whoever holds the bypass permission
/// is exempt.
#[derive(Default)]
pub struct NoEscalation {
    bypass: Option<Bypass>,
}

impl NoEscalation {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn bypass(mut self, bypass: Bypass) -> Self {
        self.bypass = Some(bypass);
        self
    }

    fn name_of(&self) -> &'static str {
        "no_escalation"
    }

    /// The actor holds every key of `c` on its resource. With `carried`, the grant that hands the
    /// permission out, it must also be at least as restrictive as the actor's own derivation.
    fn require_held(
        &self,
        engine: &Engine,
        ctx: &Context<'_>,
        actor: &Subject,
        c: &Conferred<'_>,
        carried: Option<&Grant>,
    ) -> Result<(), Violation> {
        for key in &c.keys {
            for question in held_questions(engine, key, &c.grant.fields) {
                let explanation = engine.explain(ctx, &question.request(actor, key, &c.resource));
                if !explanation.decision.is_allowed() {
                    return Err(Violation::new(
                        self.name_of(),
                        match question {
                            HeldQuestion::Field(field) => {
                                format!("o ator não tem {key} no campo {field} onde a mudança passaria a valer")
                            }
                            HeldQuestion::Whole => format!("o ator não tem {key} onde a mudança passaria a valer"),
                        },
                    ));
                }
                let Some(grant) = carried else { continue };
                let Some(required) = conditions_behind(&explanation) else {
                    continue;
                };
                if !required.iter().any(|r| covers(grant.condition.as_ref(), r)) {
                    return Err(Violation::new(
                        self.name_of(),
                        format!("o ator só tem {key} sob condição: a concessão precisa carregar a mesma condição"),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// What the actor has to hold for one permission a change hands out: the whole resource, or each
/// field the grant names.
enum HeldQuestion<'f> {
    Whole,
    Field(&'f str),
}

impl<'f> HeldQuestion<'f> {
    fn request<'a>(&self, actor: &'a Subject, key: &'a str, resource: &'a Resource) -> Request<'a>
    where
        'f: 'a,
    {
        let request = Request::new(actor, key, resource);
        match self {
            HeldQuestion::Whole => request,
            HeldQuestion::Field(field) => request.field(field),
        }
    }
}

/// The questions that stand for handing out `key` restricted to `fields`. A field the catalog
/// declares for `key` without including it is skipped: the engine denies it there, so the grant
/// confers nothing on it.
fn held_questions<'f>(engine: &Engine, key: &str, fields: &'f [String]) -> Vec<HeldQuestion<'f>> {
    if fields.is_empty() {
        return vec![HeldQuestion::Whole];
    }
    let declared = engine.catalog().fields(key);
    fields
        .iter()
        .filter(|f| declared.is_empty() || declared.contains(f))
        .map(|f| HeldQuestion::Field(f))
        .collect()
}

/// Conditions of the `allow` grants the decision stands on. `None` when some of them is
/// unconditional, or no grant decided (an override), so nothing limits the actor.
fn conditions_behind(explanation: &Explanation) -> Option<Vec<&Condition>> {
    let mut conditions = Vec::new();
    for trace in explanation.candidates().filter(|t| t.grant.effect == Effect::Allow) {
        conditions.push(trace.grant.condition.as_ref()?);
    }
    (!conditions.is_empty()).then_some(conditions)
}

/// `candidate` is `required` itself, or an `all` that has it among its terms (at any depth).
fn covers(candidate: Option<&Condition>, required: &Condition) -> bool {
    match candidate {
        None => false,
        Some(c) if c == required => true,
        Some(Condition::All { of }) => of.iter().any(|term| covers(Some(term), required)),
        Some(_) => false,
    }
}

impl Invariant for NoEscalation {
    fn name(&self) -> &str {
        self.name_of()
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        let ctx = proposal.before_context();
        if let Some(bypass) = &self.bypass
            && engine.check(
                &ctx,
                &Request::new(proposal.actor, &bypass.permission, &bypass.resource),
            )
        {
            return Ok(());
        }
        for c in conferred(engine, proposal) {
            self.require_held(engine, &ctx, proposal.actor, &c, Some(c.grant))?;
        }
        for c in unlocked(engine, proposal) {
            self.require_held(engine, &ctx, proposal.actor, &c, None)?;
        }
        Ok(())
    }
}
