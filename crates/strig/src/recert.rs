//! Access recertification: a periodic review of the grants and role assignments in force by someone
//! accountable for them, with what nobody renews taken away when the time is up (ISO 27001 A.5.18,
//! SOX access reviews).
//!
//! A [`Campaign`] has a scope ([`RecertScope`]: an anchor, permissions, roles, kinds of subject), a
//! reviewer rule per item, a deadline, how long a kept item stays certified and the action that runs
//! on what was not reviewed ([`DefaultAction`]). It is one document: the items are generated at the
//! opening from the grants and the subjects you pass, each with the [`Impact`] of revoking it when the
//! flow has [`Recertifications::with_impact`].
//!
//! - **Open.** [`Recertifications::open`] refuses a scope with nothing in it, a deadline that is not in
//!   the future and an escalation default without an escalation reviewer. Only `allow` grants and
//!   assignments that have not ended become items.
//! - **Decide.** [`Recertifications::decide`] takes a [`RecertDecision`] per item: `keep` certifies the access
//!   for the campaign's period (the grant is not touched: the certification is what is recorded),
//!   `revoke` becomes a [`Mutation`] ([`Mutation::Remove`] or [`Mutation::RevokeRole`]) through the
//!   [`Governance`] with the reviewer as the actor, so every invariant, separation of duties included,
//!   judges it, and `delegate` hands the item to another reviewer. The reviewer must be identified,
//!   hold the permission the campaign declares, match the item's reviewer rule (or be its delegate), not
//!   review access they hold themselves, and not accumulate conflicting duties of the catalog's
//!   separation sets. A decision after the deadline is refused.
//! - **Close.** [`Recertifications::close`] runs from the deadline on and applies the default action to
//!   every item still open: `expire` revokes it through the governance (an item the invariants refuse to
//!   revoke is flagged, never silently kept), `flag` keeps it marked for follow-up, `escalate` hands it
//!   to the escalation reviewer. Nothing is decided after the closing; a follow-up is a new campaign.
//! - **Audit.** With the `audit` feature and an auditor on the governance: `recert_open`, one
//!   `recert_decide` per decision (refused ones included, `rejected`) and per default action, and
//!   `recert_close`. A revocation also leaves the usual `grant_remove` / `role_revoke` record. The
//!   record of a decision is written before the revocation is applied.
//! - **Report.** [`Campaign::report`] counts the items by outcome and by reviewer.
//!
//! The crate reads no clock and persists nothing: the caller passes the instant, stores the grants and
//! subjects that a revocation returns, and keeps the campaigns in a [`RecertStore`]. Two reviewers of the
//! same campaign must not run at once; the store's [`RecertStore::update`] refuses a stale revision, and
//! a host with several processes serialises per campaign before it applies the grants.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

#[cfg(feature = "audit")]
use crate::audit::{AuditAction, AuditOutcome, FailMode, RecertRef};
use crate::decision::Request;
use crate::engine::{Context, Engine};
use crate::governance::{Governance, Mutation, Violation, same_subject};
use crate::grant::{Effect, Grant, SubjectMatcher};
use crate::impact::{Impact, ImpactOptions};
use crate::pending::Review;
use crate::resource::{Anchor, Resource};
use crate::separation::clashes_of;
use crate::subject::{RoleAssignment, Subject};

#[derive(Clone, Copy)]
enum Step {
    Open,
    Decide,
    Close,
}

/// What a record says, before it becomes an audit record.
#[cfg_attr(not(feature = "audit"), allow(dead_code))]
struct Trace {
    campaign: String,
    item: Option<String>,
    decision: Option<String>,
    target: Option<String>,
    reason: Option<String>,
}

impl Trace {
    fn campaign(id: &str) -> Self {
        Self {
            campaign: id.to_string(),
            item: None,
            decision: None,
            target: None,
            reason: None,
        }
    }
}

const REVIEWER: &str = "recert_reviewer";
const SELF_REVIEW: &str = "recert_self_review";
const SEPARATION: &str = "recert_reviewer_separation";
const STATE: &str = "recert_state";
const OVERDUE: &str = "recert_overdue";
const NOT_DUE: &str = "recert_not_due";
const SPEC: &str = "recert_campaign";
const DELEGATE: &str = "recert_delegate";

/// Why a recertification step failed.
#[derive(Debug, thiserror::Error, PartialEq)]
#[non_exhaustive]
pub enum RecertError {
    /// The rules, the invariants or the audit refused. The campaign stays as it was.
    #[error("recusado: {}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
    Refused(Vec<Violation>),
    #[error("a campanha {0} já existe")]
    Duplicate(String),
    #[error("a campanha {0} não existe")]
    Unknown(String),
    #[error("o item {item} não existe na campanha {campaign}")]
    UnknownItem { campaign: String, item: String },
    #[error("a campanha {0} já foi encerrada")]
    Closed(String),
    /// Another writer changed the campaign since it was read.
    #[error("a campanha {0} mudou desde a leitura")]
    Stale(String),
    #[error("falha no armazenamento de campanhas: {0}")]
    Store(String),
}

impl RecertError {
    #[cfg_attr(not(feature = "audit"), allow(dead_code))]
    fn refused(invariant: &str, message: impl Into<String>) -> Self {
        Self::Refused(vec![Violation::new(invariant, message)])
    }
}

/// Who may review an item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReviewerRule {
    /// Whoever holds `permission` on `resource`: the owner of the scope.
    Permission { permission: String, resource: Resource },
    /// Whoever holds `role`, directly or inherited.
    Role { role: String },
    /// One declared subject.
    Subject { id: String },
}

impl ReviewerRule {
    pub fn permission(permission: impl Into<String>, resource: Resource) -> Self {
        Self::Permission {
            permission: permission.into(),
            resource,
        }
    }

    pub fn role(role: impl Into<String>) -> Self {
        Self::Role { role: role.into() }
    }

    pub fn subject(id: impl Into<String>) -> Self {
        Self::Subject { id: id.into() }
    }
}

/// Sends the items about one permission or role to a reviewer rule other than the campaign's default.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ReviewerRoute {
    /// Matches the grants of this permission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    /// Matches the assignments of this role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub reviewer: ReviewerRule,
}

impl ReviewerRoute {
    /// The grants of `permission` go to `reviewer`.
    pub fn for_permission(permission: impl Into<String>, reviewer: ReviewerRule) -> Self {
        Self {
            permission: Some(permission.into()),
            role: None,
            reviewer,
        }
    }

    /// The assignments of `role` go to `reviewer`.
    pub fn for_role(role: impl Into<String>, reviewer: ReviewerRule) -> Self {
        Self {
            permission: None,
            role: Some(role.into()),
            reviewer,
        }
    }

    fn matches(&self, target: &RecertTarget) -> bool {
        match (target, &self.permission, &self.role) {
            (_, None, None) => true,
            (RecertTarget::Grant { grant }, Some(permission), _) => &grant.permission == permission,
            (RecertTarget::Role { role, .. }, _, Some(wanted)) => &role.role == wanted,
            _ => false,
        }
    }
}

/// What a campaign reviews. Empty lists mean everything on that axis; only `permissions` selects only
/// grants, only `roles` only role assignments, and both select both.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RecertScope {
    /// Only grants and assignments restricted to exactly this anchor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<Anchor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    /// The kind of the subject (`user`, `service`, ...) of an assignment; for a grant, the kind of its
    /// matcher (`user`, `role`, `principal`, `relation`, `any`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_kinds: Vec<String>,
}

impl RecertScope {
    /// Everything in force.
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn anchored(mut self, anchor: Anchor) -> Self {
        self.anchor = Some(anchor);
        self
    }

    #[must_use]
    pub fn permissions<I, S>(mut self, permissions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.permissions = permissions.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.roles = roles.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn subject_kinds<I, S>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.subject_kinds = kinds.into_iter().map(Into::into).collect();
        self
    }

    fn wants_grants(&self) -> bool {
        !self.permissions.is_empty() || self.roles.is_empty()
    }

    fn wants_roles(&self) -> bool {
        !self.roles.is_empty() || self.permissions.is_empty()
    }

    fn kind_ok(&self, kind: &str) -> bool {
        self.subject_kinds.is_empty() || self.subject_kinds.iter().any(|k| k == kind)
    }

    fn anchor_ok(&self, scope: Option<&Anchor>) -> bool {
        self.anchor.is_none() || self.anchor.as_ref() == scope
    }
}

/// What runs on an item nobody reviewed when the campaign closes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DefaultAction {
    /// Revoke it through the governance. The default: access nobody vouches for does not stay.
    #[default]
    Expire,
    /// Keep it, marked for follow-up.
    Flag,
    /// Hand it to the campaign's escalation reviewer.
    Escalate,
}

impl DefaultAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Expire => "expire",
            Self::Flag => "flag",
            Self::Escalate => "escalate",
        }
    }
}

/// What a campaign is made of, before it opens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CampaignSpec {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub scope: RecertScope,
    /// Who reviews an item no route claims.
    pub reviewer: ReviewerRule,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<ReviewerRoute>,
    /// The permission every reviewer (and the delegate) must hold, and on which resource.
    pub reviewer_permission: String,
    pub reviewer_resource: Resource,
    /// The deadline, in milliseconds since the Unix epoch. Nobody decides from this instant on.
    pub due_at: u64,
    /// How long a kept item stays certified, in milliseconds.
    pub keep_period_ms: u64,
    #[serde(default)]
    pub default_action: DefaultAction,
    /// Who an `escalate` default hands the items to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalate_to: Option<ReviewerRule>,
}

impl CampaignSpec {
    pub fn new(
        id: impl Into<String>,
        reviewer: ReviewerRule,
        reviewer_permission: impl Into<String>,
        reviewer_resource: Resource,
        due_at: u64,
        keep_period_ms: u64,
    ) -> Self {
        Self {
            id: id.into(),
            name: None,
            scope: RecertScope::new(),
            reviewer,
            routes: Vec::new(),
            reviewer_permission: reviewer_permission.into(),
            reviewer_resource,
            due_at,
            keep_period_ms,
            default_action: DefaultAction::Expire,
            escalate_to: None,
        }
    }

    #[must_use]
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub fn scoped(mut self, scope: RecertScope) -> Self {
        self.scope = scope;
        self
    }

    #[must_use]
    pub fn routed(mut self, route: ReviewerRoute) -> Self {
        self.routes.push(route);
        self
    }

    #[must_use]
    pub fn defaulting_to(mut self, action: DefaultAction) -> Self {
        self.default_action = action;
        self
    }

    #[must_use]
    pub fn escalating_to(mut self, reviewer: ReviewerRule) -> Self {
        self.escalate_to = Some(reviewer);
        self
    }
}

/// The access an item is about.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecertTarget {
    /// An `allow` grant.
    Grant { grant: Grant },
    /// `role` held by `subject`, as the subject stood when the campaign opened.
    Role { subject: Subject, role: RoleAssignment },
}

impl RecertTarget {
    /// Grant id, or `role@subject` (`role#scope@subject` with a scope).
    pub fn label(&self) -> String {
        match self {
            Self::Grant { grant } => grant.id.clone(),
            Self::Role { subject, role } => {
                let who = subject.id.clone().unwrap_or_else(|| subject.kind.clone());
                match &role.scope {
                    Some(scope) => format!("{}#{scope}@{who}", role.role),
                    None => format!("{}@{who}", role.role),
                }
            }
        }
    }

    fn revocation(&self) -> Mutation {
        match self {
            Self::Grant { grant } => Mutation::Remove { id: grant.id.clone() },
            Self::Role { subject, role } => Mutation::RevokeRole {
                subject: subject.clone(),
                role: role.clone(),
            },
        }
    }
}

/// A reviewer handing an item over.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Delegation {
    pub from: String,
    pub to: String,
    pub at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Where an item stands. Only `Open` can still change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", rename_all_fields = "camelCase")]
#[non_exhaustive]
pub enum ItemState {
    Open,
    /// Certified until `until`.
    Kept {
        by: String,
        at: u64,
        until: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Revoked by a reviewer.
    Revoked {
        by: String,
        at: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Revoked at the closing because nobody reviewed it.
    Expired {
        by: String,
        at: u64,
    },
    /// Left in place and marked for follow-up: the default action, or an expiry the invariants refused.
    Flagged {
        at: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Handed to the escalation reviewer at the closing.
    Escalated {
        at: u64,
        to: ReviewerRule,
    },
}

/// One access to certify.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RecertItem {
    pub id: String,
    pub target: RecertTarget,
    /// The user whose access it is, when the item names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    /// The role whose holders have the access, for a grant by role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_role: Option<String>,
    pub reviewer: ReviewerRule,
    /// Set by a delegation: only this subject decides the item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegations: Vec<Delegation>,
    /// What revoking it does to access, from [`Recertifications::with_impact`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact: Option<Impact>,
    pub state: ItemState,
}

impl RecertItem {
    pub fn is_open(&self) -> bool {
        self.state == ItemState::Open
    }
}

/// Where a campaign stands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", rename_all_fields = "camelCase")]
#[non_exhaustive]
pub enum CampaignStatus {
    Open,
    Closed { by: String, at: u64 },
}

/// A recertification campaign and its items.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Campaign {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub scope: RecertScope,
    pub reviewer: ReviewerRule,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<ReviewerRoute>,
    pub reviewer_permission: String,
    pub reviewer_resource: Resource,
    pub opened_by: String,
    pub opened_at: u64,
    pub due_at: u64,
    pub keep_period_ms: u64,
    pub default_action: DefaultAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalate_to: Option<ReviewerRule>,
    pub status: CampaignStatus,
    pub items: Vec<RecertItem>,
    /// Counts the writes, so a store can refuse a stale one.
    pub revision: u64,
}

impl Campaign {
    pub fn is_open(&self) -> bool {
        self.status == CampaignStatus::Open
    }

    pub fn item(&self, id: &str) -> Option<&RecertItem> {
        self.items.iter().find(|item| item.id == id)
    }

    /// The items still waiting for a decision.
    pub fn open_items(&self) -> impl Iterator<Item = &RecertItem> {
        self.items.iter().filter(|item| item.is_open())
    }

    /// The items certified and not yet past their date at `now`.
    pub fn certified(&self, now: u64) -> impl Iterator<Item = &RecertItem> {
        self.items
            .iter()
            .filter(move |item| matches!(item.state, ItemState::Kept { until, .. } if now < until))
    }

    /// The campaign counted by outcome and by reviewer.
    pub fn report(&self) -> CampaignReport {
        let mut report = CampaignReport {
            campaign: self.id.clone(),
            name: self.name.clone(),
            status: self.status.clone(),
            opened_by: self.opened_by.clone(),
            opened_at: self.opened_at,
            due_at: self.due_at,
            default_action: self.default_action,
            total: self.items.len(),
            open: 0,
            kept: 0,
            revoked: 0,
            expired: 0,
            flagged: 0,
            escalated: 0,
            delegated: 0,
            by_reviewer: BTreeMap::new(),
            unresolved: Vec::new(),
        };
        for item in &self.items {
            if !item.delegations.is_empty() {
                report.delegated += 1;
            }
            for delegation in &item.delegations {
                report.by_reviewer.entry(delegation.from.clone()).or_default().delegated += 1;
            }
            match &item.state {
                ItemState::Open => report.open += 1,
                ItemState::Kept { by, .. } => {
                    report.kept += 1;
                    report.by_reviewer.entry(by.clone()).or_default().kept += 1;
                }
                ItemState::Revoked { by, .. } => {
                    report.revoked += 1;
                    report.by_reviewer.entry(by.clone()).or_default().revoked += 1;
                }
                ItemState::Expired { .. } => report.expired += 1,
                ItemState::Flagged { .. } => {
                    report.flagged += 1;
                    report.unresolved.push(item.id.clone());
                }
                ItemState::Escalated { .. } => {
                    report.escalated += 1;
                    report.unresolved.push(item.id.clone());
                }
            }
        }
        report
    }
}

/// What each reviewer did.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ReviewerTally {
    pub kept: usize,
    pub revoked: usize,
    pub delegated: usize,
}

/// A campaign counted by outcome and by reviewer, from [`Campaign::report`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CampaignReport {
    pub campaign: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub status: CampaignStatus,
    pub opened_by: String,
    pub opened_at: u64,
    pub due_at: u64,
    pub default_action: DefaultAction,
    pub total: usize,
    /// Still waiting for a decision.
    pub open: usize,
    pub kept: usize,
    /// Revoked by a reviewer.
    pub revoked: usize,
    /// Revoked at the closing, unreviewed.
    pub expired: usize,
    pub flagged: usize,
    pub escalated: usize,
    /// Items that changed hands at least once.
    pub delegated: usize,
    pub by_reviewer: BTreeMap<String, ReviewerTally>,
    /// The flagged and escalated items: what the closing left for someone to follow up.
    pub unresolved: Vec<String>,
}

/// What a reviewer decides about an item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecertDecision {
    /// Certify the access for the campaign's period.
    Keep,
    /// Take the access away, through the governance.
    Revoke,
    /// Hand the item to `to`, who must hold the campaign's reviewer permission.
    Delegate { to: Subject },
}

impl RecertDecision {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Revoke => "revoke",
            Self::Delegate { .. } => "delegate",
        }
    }
}

/// A decision taken and the grants to persist.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Decided {
    /// The grants after the decision: unchanged unless a grant was revoked. A revoked role comes back
    /// in `revoked`.
    pub grants: Vec<Grant>,
    /// The role change to write, when a role assignment was revoked.
    pub revoked_role: Option<Subject>,
    pub campaign: Campaign,
    pub item: RecertItem,
}

/// A campaign closed: the grants to persist, the subjects whose roles changed and the report.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Closed {
    pub grants: Vec<Grant>,
    /// The subjects to write, with the role the closing took from each.
    pub revoked_roles: Vec<Subject>,
    pub campaign: Campaign,
    pub report: CampaignReport,
}

/// Where the campaigns are kept. Implementations are shared between threads.
pub trait RecertStore: Send + Sync {
    /// Stores a new campaign; [`RecertError::Duplicate`] if the id is taken.
    fn insert(&self, campaign: Campaign) -> Result<(), RecertError>;
    fn get(&self, id: &str) -> Result<Option<Campaign>, RecertError>;
    /// Replaces the campaign with the same id. It fails with [`RecertError::Closed`] when the stored one is
    /// closed, and with [`RecertError::Stale`] unless the stored revision is one behind the new one.
    fn update(&self, campaign: Campaign) -> Result<(), RecertError>;
    /// Every campaign, oldest first.
    fn list(&self) -> Result<Vec<Campaign>, RecertError>;
}

/// [`RecertStore`] in memory.
#[derive(Debug, Default)]
pub struct MemoryRecertStore {
    campaigns: Mutex<BTreeMap<String, Campaign>>,
}

impl MemoryRecertStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Campaign>> {
        self.campaigns.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl RecertStore for MemoryRecertStore {
    fn insert(&self, campaign: Campaign) -> Result<(), RecertError> {
        let mut campaigns = self.lock();
        if campaigns.contains_key(&campaign.id) {
            return Err(RecertError::Duplicate(campaign.id));
        }
        campaigns.insert(campaign.id.clone(), campaign);
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Option<Campaign>, RecertError> {
        Ok(self.lock().get(id).cloned())
    }

    fn update(&self, campaign: Campaign) -> Result<(), RecertError> {
        let mut campaigns = self.lock();
        match campaigns.get_mut(&campaign.id) {
            None => Err(RecertError::Unknown(campaign.id)),
            Some(stored) if !stored.is_open() => Err(RecertError::Closed(campaign.id)),
            Some(stored) if stored.revision + 1 != campaign.revision => Err(RecertError::Stale(campaign.id)),
            Some(stored) => {
                *stored = campaign;
                Ok(())
            }
        }
    }

    fn list(&self) -> Result<Vec<Campaign>, RecertError> {
        let mut all: Vec<Campaign> = self.lock().values().cloned().collect();
        all.sort_by(|a, b| a.opened_at.cmp(&b.opened_at).then_with(|| a.id.cmp(&b.id)));
        Ok(all)
    }
}

/// The state an item moves to, the grants after it and the subject whose role changed.
type Outcome = (ItemState, Option<Vec<Grant>>, Option<Subject>);

/// The recertification flow over a [`Governance`] and a [`RecertStore`].
pub struct Recertifications<'a> {
    governance: &'a Governance,
    store: &'a dyn RecertStore,
    impact: Option<&'a ImpactOptions<'a>>,
    #[cfg(feature = "audit")]
    call_mode: Option<FailMode>,
}

impl<'a> Recertifications<'a> {
    pub fn new(governance: &'a Governance, store: &'a dyn RecertStore) -> Self {
        Self {
            governance,
            store,
            impact: None,
            #[cfg(feature = "audit")]
            call_mode: None,
        }
    }

    /// Computes the [`Impact`] of revoking every item, over `options`, as the opener of the campaign.
    /// An impact that cannot be computed is simply absent.
    #[must_use]
    pub fn with_impact(mut self, options: &'a ImpactOptions<'a>) -> Self {
        self.impact = Some(options);
        self
    }

    /// The [`FailMode`] of every audit record of this flow.
    #[cfg(feature = "audit")]
    #[must_use]
    pub fn fail_mode(mut self, mode: FailMode) -> Self {
        self.call_mode = Some(mode);
        self
    }

    /// The campaigns still open.
    pub fn open_campaigns(&self) -> Result<Vec<Campaign>, RecertError> {
        Ok(self.store.list()?.into_iter().filter(Campaign::is_open).collect())
    }

    /// The report of campaign `id`.
    pub fn report(&self, id: &str) -> Result<CampaignReport, RecertError> {
        Ok(self.load(id)?.report())
    }

    /// `opener` opens the campaign `spec`, with an item per `allow` grant of `review.current` and per role
    /// assignment of `subjects` that is inside the scope and has not ended. Refused, and audited, when
    /// the opener is not identified, the deadline is not after `review.now`, the period is zero, the
    /// escalation default has no reviewer or nothing falls inside the scope.
    pub fn open(
        &self,
        review: &Review<'_>,
        opener: &Subject,
        spec: CampaignSpec,
        subjects: &[Subject],
    ) -> Result<Campaign, RecertError> {
        let mut campaign = Campaign {
            id: spec.id.clone(),
            name: spec.name.clone(),
            scope: spec.scope.clone(),
            reviewer: spec.reviewer.clone(),
            routes: spec.routes.clone(),
            reviewer_permission: spec.reviewer_permission.clone(),
            reviewer_resource: spec.reviewer_resource.clone(),
            opened_by: label(opener),
            opened_at: review.now,
            due_at: spec.due_at,
            keep_period_ms: spec.keep_period_ms,
            default_action: spec.default_action,
            escalate_to: spec.escalate_to.clone(),
            status: CampaignStatus::Open,
            items: Vec::new(),
            revision: 0,
        };
        let mut violations = spec_violations(review, opener, &spec);
        if violations.is_empty() {
            campaign.items = self.generate(review, opener, &campaign, subjects);
            if campaign.items.is_empty() {
                violations.push(Violation::new(SPEC, "o escopo não tem nenhum acesso a recertificar"));
            }
        }
        if !violations.is_empty() {
            return Err(self.refusal(review, opener, Step::Open, &campaign, None, violations));
        }
        if self.store.get(&campaign.id)?.is_some() {
            return Err(RecertError::Duplicate(campaign.id));
        }
        self.record(
            review,
            opener,
            Step::Open,
            &campaign,
            Trace::campaign(&campaign.id),
            None,
        )?;
        self.store.insert(campaign.clone())?;
        Ok(campaign)
    }

    fn generate(
        &self,
        review: &Review<'_>,
        opener: &Subject,
        campaign: &Campaign,
        subjects: &[Subject],
    ) -> Vec<RecertItem> {
        let scope = &campaign.scope;
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        let mut items = Vec::new();
        let mut push = |target: RecertTarget, holder: Option<String>, holder_role: Option<String>| {
            let mut id = match &target {
                RecertTarget::Grant { .. } => format!("grant:{}", target.label()),
                RecertTarget::Role { .. } => format!("role:{}", target.label()),
            };
            let count = seen.entry(id.clone()).or_insert(0);
            *count += 1;
            if *count > 1 {
                id = format!("{id}#{count}");
            }
            let reviewer = campaign
                .routes
                .iter()
                .find(|route| route.matches(&target))
                .map_or_else(|| campaign.reviewer.clone(), |route| route.reviewer.clone());
            let impact = self.impact.and_then(|options| {
                self.governance
                    .at(review.now)
                    .impact(review.engine, opener, review.current, &target.revocation(), options)
                    .ok()
            });
            items.push(RecertItem {
                id,
                target,
                holder,
                holder_role,
                reviewer,
                assignee: None,
                delegations: Vec::new(),
                impact,
                state: ItemState::Open,
            });
        };
        if scope.wants_grants() {
            for grant in review.current {
                if grant.effect != Effect::Allow
                    || grant.validity().has_ended(Some(review.now))
                    || !scope.anchor_ok(grant.scope.as_ref())
                    || (!scope.permissions.is_empty() && !scope.permissions.contains(&grant.permission))
                    || !scope.kind_ok(matcher_kind(&grant.subject))
                {
                    continue;
                }
                let (holder, holder_role) = match &grant.subject {
                    SubjectMatcher::User { id } => (Some(id.clone()), None),
                    SubjectMatcher::Role { id } => (None, Some(id.clone())),
                    _ => (None, None),
                };
                push(RecertTarget::Grant { grant: grant.clone() }, holder, holder_role);
            }
        }
        if scope.wants_roles() {
            for subject in subjects {
                let Some(id) = subject.id.clone() else { continue };
                if !scope.kind_ok(&subject.kind) {
                    continue;
                }
                for role in &subject.roles {
                    if role.validity().has_ended(Some(review.now))
                        || !scope.anchor_ok(role.scope.as_ref())
                        || (!scope.roles.is_empty() && !scope.roles.contains(&role.role))
                    {
                        continue;
                    }
                    push(
                        RecertTarget::Role {
                            subject: subject.clone(),
                            role: role.clone(),
                        },
                        Some(id.clone()),
                        None,
                    );
                }
            }
        }
        items
    }

    /// `reviewer` decides `item` of campaign `id`. `reason` is kept on the item and in the record; a
    /// revocation and a delegation need one. Refused, and audited, when the campaign is closed or past
    /// its deadline, the item is not open, or the reviewer fails the checks in the [module](self); a
    /// revocation also refused when the invariants refuse it.
    pub fn decide(
        &self,
        review: &Review<'_>,
        reviewer: &Subject,
        id: &str,
        item: &str,
        decision: RecertDecision,
        reason: Option<&str>,
    ) -> Result<Decided, RecertError> {
        let mut campaign = self.load(id)?;
        if !campaign.is_open() {
            return Err(RecertError::Closed(id.to_string()));
        }
        let position = campaign
            .items
            .iter()
            .position(|i| i.id == item)
            .ok_or_else(|| RecertError::UnknownItem {
                campaign: id.to_string(),
                item: item.to_string(),
            })?;
        let current = campaign.items[position].clone();
        let mut violations = self.reviewer_violations(review, reviewer, &campaign, &current);
        let reason = reason.map(str::trim).filter(|r| !r.is_empty());
        if matches!(decision, RecertDecision::Revoke | RecertDecision::Delegate { .. }) && reason.is_none() {
            violations.push(Violation::new(REVIEWER, "revogar ou delegar exige um motivo"));
        }
        if let RecertDecision::Delegate { to } = &decision {
            violations.extend(self.delegate_violations(review, reviewer, to, &campaign, &current));
        }
        let mutation = matches!(decision, RecertDecision::Revoke).then(|| current.target.revocation());
        let mut grants = review.current.to_vec();
        if violations.is_empty()
            && let Some(mutation) = &mutation
        {
            match self.governance.evaluate_at(
                review.engine,
                reviewer,
                review.current,
                mutation,
                review.tuples,
                review.now,
            ) {
                Ok(after) => grants = after,
                Err(refused) => violations = refused,
            }
        }
        let recert = Trace {
            item: Some(current.id.clone()),
            decision: Some(decision.as_str().to_string()),
            target: Some(current.target.label()),
            reason: reason.map(str::to_string),
            ..Trace::campaign(&campaign.id)
        };
        if !violations.is_empty() {
            return Err(self.refusal_with(review, reviewer, &campaign, recert, violations));
        }
        self.record(review, reviewer, Step::Decide, &campaign, recert, None)?;
        let who = label(reviewer);
        let mut revoked_role = None;
        let state = match &decision {
            RecertDecision::Keep => ItemState::Kept {
                by: who.clone(),
                at: review.now,
                until: review.now.saturating_add(campaign.keep_period_ms),
                reason: reason.map(str::to_string),
            },
            RecertDecision::Revoke => {
                if let Some(mutation) = &mutation {
                    let applied = self.apply(review, reviewer, mutation)?;
                    grants = applied;
                    revoked_role = mutation.subject_after();
                }
                ItemState::Revoked {
                    by: who.clone(),
                    at: review.now,
                    reason: reason.map(str::to_string),
                }
            }
            RecertDecision::Delegate { .. } => ItemState::Open,
        };
        let target = &mut campaign.items[position];
        if let RecertDecision::Delegate { to } = &decision {
            target.assignee = to.id.clone();
            target.delegations.push(Delegation {
                from: who,
                to: label(to),
                at: review.now,
                reason: reason.map(str::to_string),
            });
        }
        target.state = state;
        let item = target.clone();
        campaign.revision += 1;
        self.store.update(campaign.clone())?;
        Ok(Decided {
            grants,
            revoked_role,
            campaign,
            item,
        })
    }

    /// Closes campaign `id` at `review.now`, which must not be before the deadline, and applies the
    /// default action to every item still open, as `closer`: the opener, or whoever holds the campaign's
    /// reviewer permission. The expiry revokes through the governance with `closer` as the actor; an item the
    /// invariants refuse to revoke is flagged with their reasons.
    pub fn close(&self, review: &Review<'_>, closer: &Subject, id: &str) -> Result<Closed, RecertError> {
        let mut campaign = self.load(id)?;
        if !campaign.is_open() {
            return Err(RecertError::Closed(id.to_string()));
        }
        let mut violations = Vec::new();
        if closer.id.is_none() {
            violations.push(Violation::new(
                REVIEWER,
                "quem encerra a campanha precisa ser identificado",
            ));
        } else if label(closer) != campaign.opened_by
            && !holds(
                review,
                closer,
                &campaign.reviewer_permission,
                &campaign.reviewer_resource,
            )
        {
            violations.push(Violation::new(
                REVIEWER,
                format!("falta a permissão {}", campaign.reviewer_permission),
            ));
        }
        if review.now < campaign.due_at {
            violations.push(Violation::new(
                NOT_DUE,
                format!("a campanha só encerra a partir do prazo ({} ms)", campaign.due_at),
            ));
        }
        if !violations.is_empty() {
            return Err(self.refusal(review, closer, Step::Close, &campaign, None, violations));
        }
        let mut grants = review.current.to_vec();
        let mut revoked_roles = Vec::new();
        let who = label(closer);
        for position in 0..campaign.items.len() {
            if !campaign.items[position].is_open() {
                continue;
            }
            let item = campaign.items[position].clone();
            let (state, applied, role) = self.default_state(review, closer, &campaign, &item, &grants)?;
            if let Some(after) = applied {
                grants = after;
            }
            revoked_roles.extend(role);
            campaign.items[position].state = state;
        }
        campaign.status = CampaignStatus::Closed {
            by: who,
            at: review.now,
        };
        campaign.revision += 1;
        let report = campaign.report();
        self.record(
            review,
            closer,
            Step::Close,
            &campaign,
            Trace::campaign(&campaign.id),
            None,
        )?;
        self.store.update(campaign.clone())?;
        Ok(Closed {
            grants,
            revoked_roles,
            campaign,
            report,
        })
    }

    fn default_state(
        &self,
        review: &Review<'_>,
        closer: &Subject,
        campaign: &Campaign,
        item: &RecertItem,
        grants: &[Grant],
    ) -> Result<Outcome, RecertError> {
        let at = review.now;
        let action = campaign.default_action;
        let recert = |reason: Option<String>| Trace {
            item: Some(item.id.clone()),
            decision: Some(action.as_str().to_string()),
            target: Some(item.target.label()),
            reason,
            ..Trace::campaign(&campaign.id)
        };
        let step = Review {
            current: grants,
            ..*review
        };
        match action {
            DefaultAction::Flag => {
                self.record(&step, closer, Step::Decide, campaign, recert(None), None)?;
                Ok((ItemState::Flagged { at, reason: None }, None, None))
            }
            DefaultAction::Escalate => {
                let to = campaign
                    .escalate_to
                    .clone()
                    .unwrap_or_else(|| campaign.reviewer.clone());
                self.record(&step, closer, Step::Decide, campaign, recert(None), None)?;
                Ok((ItemState::Escalated { at, to }, None, None))
            }
            DefaultAction::Expire => {
                let mutation = item.target.revocation();
                match self
                    .governance
                    .evaluate_at(step.engine, closer, step.current, &mutation, step.tuples, step.now)
                {
                    Ok(_) => {
                        self.record(&step, closer, Step::Decide, campaign, recert(None), None)?;
                        let after = self.apply(&step, closer, &mutation)?;
                        Ok((
                            ItemState::Expired { by: label(closer), at },
                            Some(after),
                            mutation.subject_after(),
                        ))
                    }
                    Err(refused) => {
                        let reason = refused.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ");
                        self.record(
                            &step,
                            closer,
                            Step::Decide,
                            campaign,
                            recert(Some(reason.clone())),
                            Some(refused.as_slice()),
                        )?;
                        Ok((
                            ItemState::Flagged {
                                at,
                                reason: Some(reason),
                            },
                            None,
                            None,
                        ))
                    }
                }
            }
        }
    }

    fn apply(&self, review: &Review<'_>, actor: &Subject, mutation: &Mutation) -> Result<Vec<Grant>, RecertError> {
        let at = self.governance.at(review.now);
        #[cfg(feature = "audit")]
        let at = match self.call_mode {
            Some(mode) => at.fail_mode(mode),
            None => at,
        };
        at.apply_with(
            review.engine,
            actor,
            review.current,
            mutation,
            review.tuples,
            review.meta,
        )
        .map_err(RecertError::Refused)
    }

    fn reviewer_violations(
        &self,
        review: &Review<'_>,
        who: &Subject,
        campaign: &Campaign,
        item: &RecertItem,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();
        if !item.is_open() {
            violations.push(Violation::new(STATE, "o item já foi decidido"));
        }
        if review.now >= campaign.due_at {
            violations.push(Violation::new(OVERDUE, "o prazo da campanha já passou"));
        }
        violations.extend(common_violations(review, who, campaign, item));
        let allowed = match &item.assignee {
            Some(assignee) => who.id.as_deref() == Some(assignee.as_str()),
            None => matches_rule(review, who, &item.reviewer),
        };
        if !allowed && who.id.is_some() {
            violations.push(Violation::new(
                REVIEWER,
                match &item.assignee {
                    Some(assignee) => format!("o item foi delegado a {assignee}"),
                    None => "quem decide não é o revisor deste item".to_string(),
                },
            ));
        }
        violations
    }

    fn delegate_violations(
        &self,
        review: &Review<'_>,
        from: &Subject,
        to: &Subject,
        campaign: &Campaign,
        item: &RecertItem,
    ) -> Vec<Violation> {
        if to.id.is_none() {
            return vec![Violation::new(DELEGATE, "quem recebe o item precisa ser identificado")];
        }
        if same_subject(from, to) {
            return vec![Violation::new(DELEGATE, "o item não se delega a quem o delega")];
        }
        common_violations(review, to, campaign, item)
            .into_iter()
            .map(|v| Violation::new(DELEGATE, format!("o delegado não pode revisar o item: {}", v.message)))
            .collect()
    }

    fn load(&self, id: &str) -> Result<Campaign, RecertError> {
        self.store.get(id)?.ok_or_else(|| RecertError::Unknown(id.to_string()))
    }

    #[allow(clippy::unused_self)]
    fn refusal(
        &self,
        review: &Review<'_>,
        actor: &Subject,
        step: Step,
        campaign: &Campaign,
        item: Option<&RecertItem>,
        violations: Vec<Violation>,
    ) -> RecertError {
        let recert = Trace {
            item: item.map(|i| i.id.clone()),
            ..Trace::campaign(&campaign.id)
        };
        match self.record(review, actor, step, campaign, recert, Some(violations.as_slice())) {
            Ok(()) => RecertError::Refused(violations),
            Err(audit) => audit,
        }
    }

    fn refusal_with(
        &self,
        review: &Review<'_>,
        actor: &Subject,
        campaign: &Campaign,
        recert: Trace,
        violations: Vec<Violation>,
    ) -> RecertError {
        match self.record(
            review,
            actor,
            Step::Decide,
            campaign,
            recert,
            Some(violations.as_slice()),
        ) {
            Ok(()) => RecertError::Refused(violations),
            Err(audit) => audit,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        review: &Review<'_>,
        actor: &Subject,
        step: Step,
        campaign: &Campaign,
        recert: Trace,
        violations: Option<&[Violation]>,
    ) -> Result<(), RecertError> {
        #[cfg(feature = "audit")]
        if let Some(auditor) = self.governance.auditor() {
            let action = match step {
                Step::Open => AuditAction::RecertOpen,
                Step::Decide => AuditAction::RecertDecide,
                Step::Close => AuditAction::RecertClose,
            };
            let recert = RecertRef {
                campaign: recert.campaign,
                item: recert.item,
                decision: recert.decision,
                target: recert.target,
                reason: recert.reason,
            };
            let outcome = if violations.is_some() {
                AuditOutcome::Rejected
            } else {
                AuditOutcome::Applied
            };
            auditor
                .recert_event(
                    actor,
                    action,
                    recert,
                    outcome,
                    violations.unwrap_or(&[]),
                    review.meta,
                    Some(&campaign.reviewer_permission),
                    self.call_mode,
                    review.now,
                )
                .map_err(|e| RecertError::refused("audit", e.to_string()))?;
        }
        #[cfg(not(feature = "audit"))]
        let _ = (review, actor, step, campaign, recert, violations);
        Ok(())
    }
}

fn label(subject: &Subject) -> String {
    subject.id.clone().unwrap_or_else(|| subject.kind.clone())
}

fn matcher_kind(matcher: &SubjectMatcher) -> &'static str {
    match matcher {
        SubjectMatcher::User { .. } => "user",
        SubjectMatcher::Role { .. } => "role",
        SubjectMatcher::Principal { .. } => "principal",
        SubjectMatcher::Relation { .. } => "relation",
        SubjectMatcher::Any => "any",
    }
}

fn spec_violations(review: &Review<'_>, opener: &Subject, spec: &CampaignSpec) -> Vec<Violation> {
    let mut violations = Vec::new();
    if spec.id.trim().is_empty() {
        violations.push(Violation::new(SPEC, "a campanha precisa de um id"));
    }
    if opener.id.is_none() {
        violations.push(Violation::new(SPEC, "quem abre a campanha precisa ser identificado"));
    }
    if spec.due_at <= review.now {
        violations.push(Violation::new(SPEC, "o prazo precisa ser depois da abertura"));
    }
    if spec.keep_period_ms == 0 || review.now.checked_add(spec.keep_period_ms).is_none() {
        violations.push(Violation::new(
            SPEC,
            "o período de renovação precisa ser maior que zero e caber na linha do tempo",
        ));
    }
    if spec.reviewer_permission.trim().is_empty() {
        violations.push(Violation::new(
            SPEC,
            "a campanha precisa declarar a permissão do revisor",
        ));
    }
    if spec.default_action == DefaultAction::Escalate && spec.escalate_to.is_none() {
        violations.push(Violation::new(
            SPEC,
            "a ação padrão escalar exige um revisor de escalonamento",
        ));
    }
    violations
}

fn context<'a>(review: &'a Review<'a>) -> Context<'a> {
    let ctx = Context::new(&review.current).at(review.now);
    match review.tuples {
        Some(tuples) => ctx.with_tuples(tuples),
        None => ctx,
    }
}

fn holds(review: &Review<'_>, who: &Subject, permission: &str, resource: &Resource) -> bool {
    review
        .engine
        .check(&context(review), &Request::new(who, permission, resource))
}

fn held_roles(engine: &Engine, who: &Subject, now: u64) -> BTreeSet<String> {
    engine.roles().expand(
        who.roles
            .iter()
            .filter(|r| r.validity().contains(now))
            .map(|r| r.role.as_str()),
    )
}

fn matches_rule(review: &Review<'_>, who: &Subject, rule: &ReviewerRule) -> bool {
    match rule {
        ReviewerRule::Permission { permission, resource } => holds(review, who, permission, resource),
        ReviewerRule::Role { role } => held_roles(review.engine, who, review.now).contains(role),
        ReviewerRule::Subject { id } => who.id.as_deref() == Some(id.as_str()),
    }
}

/// The checks that hold for a reviewer and for whoever an item is delegated to.
fn common_violations(review: &Review<'_>, who: &Subject, campaign: &Campaign, item: &RecertItem) -> Vec<Violation> {
    let mut violations = Vec::new();
    let Some(id) = who.id.as_deref() else {
        violations.push(Violation::new(REVIEWER, "quem decide o item precisa ser identificado"));
        return violations;
    };
    if !holds(review, who, &campaign.reviewer_permission, &campaign.reviewer_resource) {
        violations.push(Violation::new(
            REVIEWER,
            format!("falta a permissão {}", campaign.reviewer_permission),
        ));
    }
    let own_role = item
        .holder_role
        .as_ref()
        .is_some_and(|role| held_roles(review.engine, who, review.now).contains(role));
    if item.holder.as_deref() == Some(id) || own_role {
        violations.push(Violation::new(SELF_REVIEW, "ninguém revisa o próprio acesso"));
    }
    if let Some(clash) = clashes_of(review.engine, who, review.current, Some(review.now)).first() {
        violations.push(Violation::new(SEPARATION, clash.describe(id)));
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_matches_by_permission_and_role() {
        let grant = Grant::allow(
            "g",
            SubjectMatcher::user("u"),
            "doc:read",
            crate::grant::TargetSelector::kind("doc"),
        );
        let target = RecertTarget::Grant { grant };
        assert!(ReviewerRoute::for_permission("doc:read", ReviewerRule::role("x")).matches(&target));
        assert!(!ReviewerRoute::for_permission("doc:write", ReviewerRule::role("x")).matches(&target));
        assert!(!ReviewerRoute::for_role("admin", ReviewerRule::role("x")).matches(&target));
    }

    #[test]
    fn scope_axes_follow_what_was_named() {
        assert!(RecertScope::new().wants_grants() && RecertScope::new().wants_roles());
        let only_permissions = RecertScope::new().permissions(["a"]);
        assert!(only_permissions.wants_grants() && !only_permissions.wants_roles());
        let only_roles = RecertScope::new().roles(["r"]);
        assert!(!only_roles.wants_grants() && only_roles.wants_roles());
    }

    #[test]
    fn an_anchored_scope_wants_exactly_that_anchor() {
        assert!(RecertScope::new().anchor_ok(None));
        let scope = RecertScope::new().anchored(Anchor::new("org", "1"));
        assert!(!scope.anchor_ok(None));
        assert!(scope.anchor_ok(Some(&Anchor::new("org", "1"))));
    }
}
