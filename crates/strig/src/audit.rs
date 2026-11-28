//! Audit trail of permission changes (feature `audit`).
//!
//! Every grant change, ReBAC tuple change or role assignment becomes an [`AuditRecord`], accepted
//! or refused. The [`AuditLevel`] decides how much of each record is kept, and therefore the
//! storage cost ([`AuditLevel::estimate_bytes`]). The destination is an [`AuditSink`]:
//! memory, a JSON Lines file or your own implementation (table, queue, SIEM).
//!
//! At the [`AuditLevel::Forensic`] level the records form a SHA-256 hash chain: each one carries
//! the hash of the previous one, so deleting or editing a record breaks verification
//! ([`verify_chain`]).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attr::Attributes;
use crate::decision::{Decision, Reason, Request};
use crate::engine::{Context, Engine};
use crate::explain::Explanation;
use crate::governance::{Mutation, Suggestion, Violation};
use crate::grant::{Effect, Grant, SubjectMatcher, TargetSelector};
use crate::impact::{Impact, ImpactSummary};
use crate::rebac::Tuple;
use crate::resource::{Anchor, ObjectRef, Resource};
use crate::subject::{RoleAssignment, Subject};

/// How much of each change is recorded. Each level includes everything from the previous one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLevel {
    /// Who, when, what (object id) and whether it was applied.
    Minimal,
    /// Plus a summary of the change (permission, subject, target, effect, scope) and the names of the
    /// invariants that refused it.
    Standard,
    /// Plus the whole object (grant with condition, tuple), the full actor, the violation messages
    /// and the application metadata (ip, request id, reason).
    Detailed,
    /// Plus the digest of the grant set before and after, and the hash chain.
    Forensic,
}

impl AuditLevel {
    pub const ALL: [AuditLevel; 4] = [
        AuditLevel::Minimal,
        AuditLevel::Standard,
        AuditLevel::Detailed,
        AuditLevel::Forensic,
    ];

    /// Typical size of a record in compact JSON, in bytes, measured on the reference record of
    /// [`reference_record`] (grant with a scope and a two-clause condition, actor with two roles and
    /// three metadata entries). The test `estimates_match_reference_records` keeps these numbers
    /// honest.
    pub const fn typical_record_bytes(self) -> u64 {
        match self {
            AuditLevel::Minimal => 174,
            AuditLevel::Standard => 387,
            AuditLevel::Detailed => 1_096,
            AuditLevel::Forensic => 1_414,
        }
    }

    /// Like [`AuditLevel::typical_record_bytes`], for decision records, measured on
    /// [`reference_decision_record`] (three grants in the source, one with a condition).
    pub const fn typical_decision_bytes(self) -> u64 {
        match self {
            AuditLevel::Minimal => 284,
            AuditLevel::Standard => 668,
            AuditLevel::Detailed => 1_238,
            AuditLevel::Forensic => 3_581,
        }
    }

    pub const fn estimate_decision_bytes(self, records: u64) -> u64 {
        (self.typical_decision_bytes() + 1) * records
    }

    /// Storage estimate for `records` records in JSON Lines, with no compression and no index. In a
    /// database, add the per-row overhead (in Postgres, about 28 bytes between the tuple header and the
    /// item pointer, plus whatever indexes you create).
    pub const fn estimate_bytes(self, records: u64) -> u64 {
        (self.typical_record_bytes() + 1) * records
    }
}

impl fmt::Display for AuditLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AuditLevel::Minimal => "minimal",
            AuditLevel::Standard => "standard",
            AuditLevel::Detailed => "detailed",
            AuditLevel::Forensic => "forensic",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditAction {
    GrantAdd,
    GrantRemove,
    TupleAdd,
    TupleRemove,
    RoleAssign,
    RoleRevoke,
    /// An access decision (`Engine::decide`), not a change.
    Decision,
    /// An exclusive resource was acquired (`exclusive` feature).
    ExclusiveAcquire,
    /// An exclusive resource was taken from a lower-priority holder.
    ExclusivePreempt,
    /// The holder released an exclusive resource.
    ExclusiveRelease,
    /// An exclusive lease ran out of time.
    ExclusiveExpire,
    /// A change was proposed and, by policy, left as a pending request (`pending` module).
    MutationPropose,
    /// Another actor approved a pending request; the change then went through the governance.
    MutationApprove,
    /// Another actor refused a pending request.
    MutationReject,
    /// A pending request ran out of time before anyone decided it.
    MutationExpire,
    /// Another actor closed the review of a break-glass elevation (`pending::elevation`).
    ElevationReview,
    /// A recertification campaign was opened (`recert` module).
    RecertOpen,
    /// A reviewer decided an item of a campaign, or the closing applied the default action to it.
    RecertDecide,
    /// A recertification campaign was closed.
    RecertClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Applied,
    Rejected,
    Allowed,
    Denied,
    /// A proposal waits for an approver (`mutation_propose` only).
    Pending,
}

/// Summary of a decision, kept from [`AuditLevel::Standard`] upward.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionSummary {
    pub permission: String,
    /// Resource path as text (`document:d1/project:p1`).
    pub resource: String,
    pub reason: Reason,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched: Vec<String>,
    /// From `detailed` upward.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

fn path_text(resource: &Resource) -> String {
    resource
        .path
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("/")
}

/// Summary of a grant, kept from [`AuditLevel::Standard`] upward.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantSummary {
    pub permission: String,
    pub subject: SubjectMatcher,
    pub target: TargetSelector,
    pub effect: Effect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Anchor>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub conditional: bool,
}

impl From<&Grant> for GrantSummary {
    fn from(grant: &Grant) -> Self {
        Self {
            permission: grant.permission.clone(),
            subject: grant.subject.clone(),
            target: grant.target.clone(),
            effect: grant.effect,
            scope: grant.scope.clone(),
            conditional: grant.condition.is_some(),
        }
    }
}

/// Recorded role assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleChange {
    /// Subject id, or `<kind>:<anonymous>` when it has no id.
    pub subject: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Anchor>,
}

impl RoleChange {
    fn of(subject: &Subject, role: &RoleAssignment) -> Self {
        Self {
            subject: subject
                .id
                .clone()
                .unwrap_or_else(|| format!("{}:<anonymous>", subject.kind)),
            role: role.role.clone(),
            scope: role.scope.clone(),
        }
    }
}

/// The pending request an approval-flow record is about, kept from [`AuditLevel::Standard`] upward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRef {
    pub id: String,
    /// Actor id of whoever proposed the change, or its kind when anonymous.
    pub author: String,
    pub kind: crate::governance::MutationKind,
    /// Grant id, or `role@subject` (`role#scope@subject` with a scope) for a role change.
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Why an approver refused the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The campaign and item a recertification record is about, kept from [`AuditLevel::Standard`] upward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RecertRef {
    pub campaign: String,
    /// The item a decision is about; absent on the opening and closing of a campaign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    /// `keep`, `revoke`, `delegate`, or the default action applied at the closing (`expire`, `flag`, `escalate`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    /// Grant id, or `role@subject`, of the access the item is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Why the reviewer decided so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One record of the trail. The optional fields appear depending on the level.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuditRecord {
    /// Milliseconds since the Unix epoch.
    pub at: u64,
    pub level: AuditLevel,
    /// Actor id, or its kind when anonymous.
    pub actor: String,
    pub action: AuditAction,
    /// Grant id, the tuple's `object#relation@subject`, or `role@subject` for a role change,
    /// with the scope after the role when there is one (`role#scope@subject`).
    pub object: String,
    pub outcome: AuditOutcome,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<GrantSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<RoleChange>,
    /// Names of the invariants (standard) or `name: message` (detailed and above).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<String>,
    /// Compensating changes the refusing invariants proposed (see [`Violation::suggestion`]), from
    /// `standard` upward: the subject id and the role, nothing else. Nothing was applied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suggestions: Vec<Suggestion>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<DecisionSummary>,
    /// The request of an approval-flow record, from `standard` upward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<PendingRef>,
    /// The campaign of a recertification record, from `standard` upward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recert: Option<RecertRef>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_grant: Option<Grant>,
    /// Full resource of a decision, from `detailed` upward. With `actor_detail`, it is enough to
    /// re-evaluate the decision against another policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
    /// Full trace of the decision, at `forensic`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<Box<Explanation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tuple: Option<Tuple>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_detail: Option<Subject>,
    #[serde(default, skip_serializing_if = "Attributes::is_empty")]
    pub meta: Attributes,
    /// What the change does to access (counts and a few examples), from `detailed` upward, on a change
    /// recorded with [`Governance::apply_with_impact`](crate::Governance::apply_with_impact).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact: Option<ImpactSummary>,

    /// Digest of the grant set before the change. For a role change, the digest of the subject's
    /// roles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_digest: Option<String>,
    /// Digest of the grant set after the change (equal to the previous one on a refusal). For a role
    /// change, the digest of the subject's roles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("falha ao gravar auditoria: {0}")]
    Sink(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Destination of the records. An implementation that cannot write returns an error, and
/// governance refuses the change: no record, no change.
pub trait AuditSink: Send + Sync {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError>;
}

impl<F: Fn(&AuditRecord) -> Result<(), AuditError> + Send + Sync> AuditSink for F {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self(record)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// What happens to a change when its audit record cannot be written.
///
/// The mode of a record is resolved in this order: the mode given for the call
/// ([`Auditor::grant_mutation_with`], [`GovernanceAt::fail_mode`](crate::governance::GovernanceAt::fail_mode)),
/// then the mode set for the record's permission ([`Auditor::with_permission_fail_mode`]), then
/// the auditor's default ([`Auditor::with_fail_mode`]), then [`FailMode::Closed`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// No record, no change: the change is refused with the `audit` violation.
    #[default]
    Closed,
    /// The change goes ahead and the record waits in the retry queue ([`RetryPolicy`]).
    Open,
}

/// Where a record ended up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    /// The sink took it.
    Written,
    /// The sink failed in `open` mode; the record waits in the retry queue, in order.
    Pending,
    /// The sink failed in `open` mode and the queue was full: the record was not kept. Its
    /// hash is not part of the chain, so the chain of the written records still verifies.
    Dropped,
}

/// A record the retry queue could not keep.
#[derive(Debug, Clone, PartialEq)]
pub struct DroppedRecord {
    pub record: AuditRecord,
}

/// Called, outside any lock, for each record dropped because the queue was full.
pub type DropHook = Arc<dyn Fn(&DroppedRecord) + Send + Sync>;

/// Limits of the retry queue that `open` mode feeds.
#[derive(Clone)]
pub struct RetryPolicy {
    /// Records kept waiting; past it a new record is dropped (the older ones keep their place).
    pub capacity: usize,
    /// Wait after the first failure, doubled on each consecutive failure up to `max_delay_ms`.
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub on_drop: Option<DropHook>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            capacity: 1024,
            base_delay_ms: 100,
            max_delay_ms: 30_000,
            on_drop: None,
        }
    }
}

impl fmt::Debug for RetryPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetryPolicy")
            .field("capacity", &self.capacity)
            .field("base_delay_ms", &self.base_delay_ms)
            .field("max_delay_ms", &self.max_delay_ms)
            .finish_non_exhaustive()
    }
}

/// Counters of the retry queue, for a metric or a health check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditStats {
    /// Records waiting for the sink.
    pub pending: usize,
    /// Records the sink took after waiting in the queue.
    pub written_late: u64,
    /// Records dropped because the queue was full.
    pub dropped: u64,
    /// Failed writes (each retry that fails counts).
    pub failures: u64,
    /// Earliest instant (the auditor's clock) at which a write is retried by itself.
    pub next_retry_at: Option<u64>,
}

#[derive(Default)]
struct QueueState {
    items: VecDeque<AuditRecord>,
    attempts: u32,
    next_at: u64,
    last_error: String,
    stats: AuditStats,
}

/// The retry queue of `open` mode. Records leave it in the order they entered, and nothing is
/// written ahead of the record at the head, so the sink always sees the hash chain in order. Share
/// one queue between short-lived [`Auditor`]s with [`Auditor::with_queue`].
#[derive(Default)]
pub struct PendingQueue {
    policy: RetryPolicy,
    state: Mutex<QueueState>,
}

impl fmt::Debug for PendingQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingQueue")
            .field("policy", &self.policy)
            .field("stats", &self.stats())
            .finish()
    }
}

impl PendingQueue {
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            policy,
            state: Mutex::default(),
        }
    }

    pub fn stats(&self) -> AuditStats {
        let state = lock(&self.state);
        let mut stats = state.stats;
        stats.pending = state.items.len();
        stats.next_retry_at = (!state.items.is_empty()).then_some(state.next_at);
        stats
    }

    /// The records still waiting, oldest first.
    pub fn pending(&self) -> Vec<AuditRecord> {
        lock(&self.state).items.iter().cloned().collect()
    }

    /// Tries to write the waiting records now (or only if the backoff has passed, when `force` is
    /// false) and returns how many are still waiting.
    pub fn flush(&self, sink: &dyn AuditSink, now: u64, force: bool) -> usize {
        let mut state = lock(&self.state);
        if force || now >= state.next_at {
            self.drain(&mut state, sink, now);
        }
        state.items.len()
    }

    fn drain(&self, state: &mut QueueState, sink: &dyn AuditSink, now: u64) {
        while let Some(head) = state.items.front() {
            match sink.write(head) {
                Ok(()) => {
                    state.items.pop_front();
                    state.stats.written_late += 1;
                    state.attempts = 0;
                    state.next_at = 0;
                    #[cfg(feature = "tracing")]
                    crate::obs::audit::retried(1);
                }
                Err(error) => {
                    self.failed(state, now, &error);
                    #[cfg(feature = "tracing")]
                    crate::obs::audit::depth(state.items.len());
                    return;
                }
            }
        }
        #[cfg(feature = "tracing")]
        crate::obs::audit::depth(state.items.len());
    }

    fn failed(&self, state: &mut QueueState, now: u64, error: &AuditError) {
        state.attempts = state.attempts.saturating_add(1);
        state.stats.failures += 1;
        state.last_error = error.to_string();
        let shift = (state.attempts - 1).min(32);
        let delay = self
            .policy
            .base_delay_ms
            .saturating_mul(1u64 << shift)
            .min(self.policy.max_delay_ms);
        state.next_at = now.saturating_add(delay);
        #[cfg(feature = "tracing")]
        crate::obs::audit::write_failed();
    }

    /// Writes `record` after everything already waiting, or queues it (`open`) or refuses it
    /// (`closed`) if the sink fails.
    fn submit(
        &self,
        sink: &dyn AuditSink,
        record: &AuditRecord,
        mode: FailMode,
        now: u64,
    ) -> Result<AuditStatus, AuditError> {
        #[cfg(feature = "tracing")]
        {
            let span = tracing::info_span!("strig.audit.write", mode = ?mode);
            let result = span.in_scope(|| self.submit_inner(sink, record, mode, now));
            match &result {
                Ok(status) => crate::obs::audit::status(*status),
                Err(_) => crate::obs::audit::refused(),
            }
            crate::obs::audit::depth(lock(&self.state).items.len());
            result
        }
        #[cfg(not(feature = "tracing"))]
        self.submit_inner(sink, record, mode, now)
    }

    fn submit_inner(
        &self,
        sink: &dyn AuditSink,
        record: &AuditRecord,
        mode: FailMode,
        now: u64,
    ) -> Result<AuditStatus, AuditError> {
        let status = {
            let mut state = lock(&self.state);
            if !state.items.is_empty() && (mode == FailMode::Closed || now >= state.next_at) {
                self.drain(&mut state, sink, now);
            }
            if !state.items.is_empty() {
                if mode == FailMode::Closed {
                    let waiting = state.items.len();
                    return Err(AuditError::Sink(format!(
                        "{waiting} earlier records still pending: {}",
                        state.last_error
                    )));
                }
                self.enqueue(&mut state, record)
            } else {
                match sink.write(record) {
                    Ok(()) => AuditStatus::Written,
                    Err(error) if mode == FailMode::Closed => return Err(error),
                    Err(error) => {
                        self.failed(&mut state, now, &error);
                        self.enqueue(&mut state, record)
                    }
                }
            }
        };
        if status == AuditStatus::Dropped
            && let Some(hook) = &self.policy.on_drop
        {
            hook(&DroppedRecord { record: record.clone() });
        }
        Ok(status)
    }

    fn enqueue(&self, state: &mut QueueState, record: &AuditRecord) -> AuditStatus {
        if state.items.len() >= self.policy.capacity {
            state.stats.dropped += 1;
            return AuditStatus::Dropped;
        }
        state.items.push_back(record.clone());
        AuditStatus::Pending
    }
}

/// A record and where it ended up.
#[derive(Debug, Clone, PartialEq)]
pub struct Emitted {
    pub record: AuditRecord,
    pub status: AuditStatus,
}

/// Masks the sensitive parts of a record before it is hashed and written. It may fail (a host
/// function that throws): the record is then refused whatever the [`FailMode`], never written
/// unmasked.
pub type Redactor = Arc<dyn Fn(&mut AuditRecord) -> Result<(), String> + Send + Sync>;

/// Called with every record the auditor accepted, written or queued, and where it ended up.
pub type Observer = Arc<dyn Fn(&AuditRecord, AuditStatus) + Send + Sync>;

/// A [`Redactor`] that replaces the value of the attributes named in `keys` by `mask`, in the
/// request metadata, in the actor's and the resource's attributes, and in the same copies inside a
/// decision trace. Keys are matched exactly. Digests (`before_digest`, `after_digest`) are not
/// touched: they carry no attribute.
pub fn mask_attributes<I, S>(keys: I, mask: impl Into<crate::attr::Value>) -> Redactor
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let keys: Vec<String> = keys.into_iter().map(Into::into).collect();
    let mask = mask.into();
    let apply = move |attrs: &mut Attributes| {
        for key in &keys {
            if let Some(value) = attrs.get_mut(key) {
                *value = mask.clone();
            }
        }
    };
    Arc::new(move |record: &mut AuditRecord| {
        apply(&mut record.meta);
        if let Some(actor) = &mut record.actor_detail {
            apply(&mut actor.attrs);
        }
        if let Some(resource) = &mut record.resource {
            apply(&mut resource.attrs);
        }
        if let Some(explanation) = &mut record.explanation {
            apply(&mut explanation.subject.attrs);
            apply(&mut explanation.resource.attrs);
        }
        Ok(())
    })
}

/// In-memory records, for tests and for callers who drain the trail themselves.
#[derive(Debug, Default)]
pub struct MemoryAuditLog {
    records: Mutex<Vec<AuditRecord>>,
}

impl MemoryAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn records(&self) -> Vec<AuditRecord> {
        lock(&self.records).clone()
    }

    pub fn drain(&self) -> Vec<AuditRecord> {
        std::mem::take(&mut *lock(&self.records))
    }
}

impl AuditSink for MemoryAuditLog {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
        lock(&self.records).push(record.clone());
        Ok(())
    }
}

/// One JSON record per line on a `Write` (file, socket, stdout).
pub struct JsonLinesAudit<W> {
    out: Mutex<W>,
}

impl<W: Write + Send> JsonLinesAudit<W> {
    pub fn new(out: W) -> Self {
        Self { out: Mutex::new(out) }
    }

    pub fn into_inner(self) -> W {
        self.out.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl<W: Write + Send> AuditSink for JsonLinesAudit<W> {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        let mut out = lock(&self.out);
        out.write_all(&line)?;
        out.flush()?;
        Ok(())
    }
}

pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn system_clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `wasm32-unknown-unknown` has no system clock; use [`Auditor::with_clock`].
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn system_clock() -> u64 {
    0
}

/// Builds the records at the configured level and hands them to the sink.
pub struct Auditor {
    level: AuditLevel,
    sink: Arc<dyn AuditSink>,
    clock: Clock,
    last_hash: Mutex<Option<String>>,
    fail_mode: FailMode,
    permission_modes: HashMap<String, FailMode>,
    queue: Arc<PendingQueue>,
    redactor: Option<Redactor>,
    observer: Option<Observer>,
}

impl fmt::Debug for Auditor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Auditor")
            .field("level", &self.level)
            .finish_non_exhaustive()
    }
}

impl Auditor {
    pub fn new(level: AuditLevel, sink: Arc<dyn AuditSink>) -> Self {
        Self {
            level,
            sink,
            clock: Arc::new(system_clock),
            last_hash: Mutex::new(None),
            fail_mode: FailMode::Closed,
            permission_modes: HashMap::new(),
            queue: Arc::new(PendingQueue::default()),
            redactor: None,
            observer: None,
        }
    }

    /// The mode for records with no mode of their own (default [`FailMode::Closed`]).
    pub fn with_fail_mode(mut self, mode: FailMode) -> Self {
        self.fail_mode = mode;
        self
    }

    /// The mode for records about `permission` (a grant change or a decision on it), over the
    /// auditor's default and under a mode given for the call. Role, tuple and exclusive-resource
    /// records carry no permission and follow the default.
    pub fn with_permission_fail_mode(mut self, permission: impl Into<String>, mode: FailMode) -> Self {
        self.permission_modes.insert(permission.into(), mode);
        self
    }

    /// Limits of the retry queue of `open` mode, in a queue of its own.
    pub fn with_retry(mut self, policy: RetryPolicy) -> Self {
        self.queue = Arc::new(PendingQueue::new(policy));
        self
    }

    /// Uses a queue that outlives this auditor, so records that are still waiting keep their place
    /// when the next auditor (one per request, say) is built.
    pub fn with_queue(mut self, queue: Arc<PendingQueue>) -> Self {
        self.queue = queue;
        self
    }

    /// Masks each record before it is hashed and written; the hash covers the masked record.
    pub fn with_redactor(mut self, redactor: Redactor) -> Self {
        self.redactor = Some(redactor);
        self
    }

    pub fn observe(mut self, observer: impl Fn(&AuditRecord, AuditStatus) + Send + Sync + 'static) -> Self {
        self.observer = Some(Arc::new(observer));
        self
    }

    pub fn queue(&self) -> &Arc<PendingQueue> {
        &self.queue
    }

    pub fn stats(&self) -> AuditStats {
        self.queue.stats()
    }

    /// Tries to write the waiting records now and returns how many are still waiting.
    pub fn flush(&self) -> usize {
        self.queue.flush(self.sink.as_ref(), (self.clock)(), true)
    }

    /// Hash of the last record accepted (written or queued): the head of the chain, to publish as
    /// an anchor or to resume with [`Auditor::resume_chain`]. `None` before the first record.
    pub fn chain_head(&self) -> Option<String> {
        lock(&self.last_hash).clone()
    }

    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Resumes a forensic chain from the hash of the last record already written.
    pub fn resume_chain(self, last_hash: impl Into<String>) -> Self {
        *lock(&self.last_hash) = Some(last_hash.into());
        self
    }

    pub fn level(&self) -> AuditLevel {
        self.level
    }

    fn base(&self, actor: &Subject, action: AuditAction, object: String, outcome: AuditOutcome) -> AuditRecord {
        AuditRecord {
            at: (self.clock)(),
            level: self.level,
            actor: actor.id.clone().unwrap_or_else(|| actor.kind.clone()),
            action,
            object,
            outcome,
            grant: None,
            role: None,
            violations: Vec::new(),
            suggestions: Vec::new(),
            decision: None,
            pending: None,
            recert: None,
            full_grant: None,
            resource: None,
            explanation: None,
            tuple: None,
            actor_detail: None,
            meta: Attributes::new(),
            impact: None,
            before_digest: None,
            after_digest: None,
            prev_hash: None,
            hash: None,
        }
    }

    /// Decides and records. At the `forensic` level it uses [`Engine::explain`] and keeps the trace; at
    /// the other levels, [`Engine::decide`]. The decision is returned even if the record fails: the
    /// caller chooses whether to deny access in that case.
    pub fn decide(
        &self,
        engine: &Engine,
        ctx: &Context<'_>,
        request: &Request<'_>,
        meta: &Attributes,
    ) -> (Decision, Result<AuditRecord, AuditError>) {
        if self.level >= AuditLevel::Forensic {
            let explanation = engine.explain(ctx, request);
            let record = self.explained(&explanation, meta);
            (explanation.decision, record)
        } else {
            let decision = engine.decide(ctx, request);
            let record = self.decision(request, &decision, meta);
            (decision, record)
        }
    }

    /// Records a decision that was already made. At `forensic`, prefer [`Auditor::explained`].
    pub fn decision(
        &self,
        request: &Request<'_>,
        decision: &Decision,
        meta: &Attributes,
    ) -> Result<AuditRecord, AuditError> {
        let record = self.decision_record(request.subject, request.permission, request.resource, decision, meta);
        self.emit_with(record, Some(request.permission), None)
            .map(|emitted| emitted.record)
    }

    /// Records a decision with the full trace.
    pub fn explained(&self, explanation: &Explanation, meta: &Attributes) -> Result<AuditRecord, AuditError> {
        let mut record = self.decision_record(
            &explanation.subject,
            &explanation.permission,
            &explanation.resource,
            &explanation.decision,
            meta,
        );
        if self.level >= AuditLevel::Forensic {
            record.explanation = Some(Box::new(explanation.clone()));
        }
        self.emit_with(record, Some(&explanation.permission), None)
            .map(|emitted| emitted.record)
    }

    fn decision_record(
        &self,
        subject: &Subject,
        permission: &str,
        resource: &Resource,
        decision: &Decision,
        meta: &Attributes,
    ) -> AuditRecord {
        let outcome = if decision.is_allowed() {
            AuditOutcome::Allowed
        } else {
            AuditOutcome::Denied
        };
        let path = path_text(resource);
        let object = format!("{permission}@{path}");
        let mut record = self.base(subject, AuditAction::Decision, object, outcome);
        if self.level >= AuditLevel::Standard {
            record.decision = Some(DecisionSummary {
                permission: permission.to_string(),
                resource: path,
                reason: decision.reason.clone(),
                matched: decision.matched.clone(),
                warnings: if self.level >= AuditLevel::Detailed {
                    decision.warnings.clone()
                } else {
                    Vec::new()
                },
            });
        }
        if self.level >= AuditLevel::Detailed {
            record.resource = Some(resource.clone());
        }
        self.detail(&mut record, subject, meta);
        record
    }

    fn detail(&self, record: &mut AuditRecord, actor: &Subject, meta: &Attributes) {
        if self.level >= AuditLevel::Detailed {
            record.actor_detail = Some(actor.clone());
            record.meta = meta.clone();
        }
    }

    /// Records a change decided by governance. A role change is emitted as
    /// `role_assign`/`role_revoke`, like [`Auditor::role_change`], with the violations.
    pub fn grant_mutation(
        &self,
        actor: &Subject,
        mutation: &Mutation,
        before: &[Grant],
        result: &Result<Vec<Grant>, Vec<Violation>>,
        meta: &Attributes,
    ) -> Result<AuditRecord, AuditError> {
        self.grant_mutation_with(actor, mutation, before, result, meta, None)
            .map(|emitted| emitted.record)
    }

    /// Like [`Auditor::grant_mutation`], with the [`FailMode`] for this call (over the one of the
    /// permission and the auditor's default) and where the record ended up.
    pub fn grant_mutation_with(
        &self,
        actor: &Subject,
        mutation: &Mutation,
        before: &[Grant],
        result: &Result<Vec<Grant>, Vec<Violation>>,
        meta: &Attributes,
        call: Option<FailMode>,
    ) -> Result<Emitted, AuditError> {
        self.grant_mutation_impact(actor, mutation, before, result, meta, call, None)
    }

    /// Like [`Auditor::grant_mutation_with`], with the [`Impact`] of the change: from `detailed` upward the
    /// record keeps its summary.
    #[allow(clippy::too_many_arguments)]
    pub fn grant_mutation_impact(
        &self,
        actor: &Subject,
        mutation: &Mutation,
        before: &[Grant],
        result: &Result<Vec<Grant>, Vec<Violation>>,
        meta: &Attributes,
        call: Option<FailMode>,
        impact: Option<&Impact>,
    ) -> Result<Emitted, AuditError> {
        let impact = impact
            .filter(|_| self.level >= AuditLevel::Detailed)
            .map(Impact::summary);
        let (outcome, violations) = match result {
            Ok(_) => (AuditOutcome::Applied, &[][..]),
            Err(violations) => (AuditOutcome::Rejected, violations.as_slice()),
        };
        let (action, object, grant) = match mutation {
            Mutation::Add(grant) => (AuditAction::GrantAdd, grant.id.clone(), Some(grant)),
            Mutation::Remove { id } => (
                AuditAction::GrantRemove,
                id.clone(),
                before.iter().find(|g| &g.id == id),
            ),
            Mutation::AssignRole { subject, role } | Mutation::RevokeRole { subject, role } => {
                let assigned = matches!(mutation, Mutation::AssignRole { .. });
                let change = RoleChange::of(subject, role);
                let before = role_set_digest(&subject.roles);
                let after = match result {
                    Ok(_) => {
                        let roles = mutation.subject_after().map(|s| s.roles);
                        role_set_digest(&roles.unwrap_or_default())
                    }
                    Err(_) => before.clone(),
                };
                let digests = Some((before, after));
                return self.role_record(
                    actor, assigned, &change, outcome, violations, digests, meta, call, impact,
                );
            }
        };
        let mut record = self.base(actor, action, object, outcome);
        if self.level >= AuditLevel::Standard {
            record.grant = grant.map(GrantSummary::from);
            record.violations = self.violation_texts(violations);
            record.suggestions = suggestions_of(violations);
        }
        if self.level >= AuditLevel::Detailed {
            record.full_grant = grant.cloned();
        }
        self.detail(&mut record, actor, meta);
        record.impact = impact;
        if self.level >= AuditLevel::Forensic {
            record.before_digest = Some(grant_set_digest(before));
            record.after_digest = Some(match result {
                Ok(after) => grant_set_digest(after),
                Err(_) => grant_set_digest(before),
            });
        }
        let permission = grant.map(|g| g.permission.as_str());
        self.emit_with(record, permission, call)
    }

    /// Records a step of the approval flow (`pending` module): `action` is one of the `Mutation*` actions
    /// and `object` is the request id. `permission` is the approval permission, so that its [`FailMode`] applies.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn pending_event(
        &self,
        actor: &Subject,
        action: AuditAction,
        pending: PendingRef,
        outcome: AuditOutcome,
        violations: &[Violation],
        meta: &Attributes,
        permission: Option<&str>,
        call: Option<FailMode>,
        at: u64,
    ) -> Result<Emitted, AuditError> {
        let mut record = self.base(actor, action, pending.id.clone(), outcome);
        record.at = at;
        if self.level >= AuditLevel::Standard {
            record.pending = Some(pending);
            record.violations = self.violation_texts(violations);
        }
        self.detail(&mut record, actor, meta);
        self.emit_with(record, permission, call)
    }

    /// Records a step of a recertification campaign (`recert` module). `permission` is the permission
    /// the reviewer needs, so that its [`FailMode`] applies.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn recert_event(
        &self,
        actor: &Subject,
        action: AuditAction,
        recert: RecertRef,
        outcome: AuditOutcome,
        violations: &[Violation],
        meta: &Attributes,
        permission: Option<&str>,
        call: Option<FailMode>,
        at: u64,
    ) -> Result<Emitted, AuditError> {
        let object = recert.item.clone().unwrap_or_else(|| recert.campaign.clone());
        let mut record = self.base(actor, action, object, outcome);
        record.at = at;
        if self.level >= AuditLevel::Standard {
            record.recert = Some(recert);
            record.violations = self.violation_texts(violations);
        }
        self.detail(&mut record, actor, meta);
        self.emit_with(record, permission, call)
    }

    /// Records the writing or removal of a ReBAC tuple.
    pub fn tuple_change(
        &self,
        actor: &Subject,
        added: bool,
        tuple: &Tuple,
        outcome: AuditOutcome,
        meta: &Attributes,
    ) -> Result<AuditRecord, AuditError> {
        let action = if added {
            AuditAction::TupleAdd
        } else {
            AuditAction::TupleRemove
        };
        let mut record = self.base(actor, action, tuple.to_string(), outcome);
        if self.level >= AuditLevel::Detailed {
            record.tuple = Some(tuple.clone());
        }
        self.detail(&mut record, actor, meta);
        self.emit(record)
    }

    /// Records a change of exclusive ownership of `resource` at `at` (milliseconds since the Unix
    /// epoch, supplied by the caller instead of the auditor's clock). `meta` is kept from
    /// `detailed` upward, like the other records.
    pub fn exclusive(
        &self,
        actor: &Subject,
        action: AuditAction,
        resource: &ObjectRef,
        outcome: AuditOutcome,
        at: u64,
        meta: &Attributes,
    ) -> Result<AuditRecord, AuditError> {
        let mut record = self.base(actor, action, resource.to_string(), outcome);
        record.at = at;
        self.detail(&mut record, actor, meta);
        self.emit(record)
    }

    /// Records the assignment or revocation of a role.
    pub fn role_change(
        &self,
        actor: &Subject,
        assigned: bool,
        change: &RoleChange,
        outcome: AuditOutcome,
        meta: &Attributes,
    ) -> Result<AuditRecord, AuditError> {
        self.role_record(actor, assigned, change, outcome, &[], None, meta, None, None)
            .map(|emitted| emitted.record)
    }

    #[allow(clippy::too_many_arguments)]
    fn role_record(
        &self,
        actor: &Subject,
        assigned: bool,
        change: &RoleChange,
        outcome: AuditOutcome,
        violations: &[Violation],
        digests: Option<(String, String)>,
        meta: &Attributes,
        call: Option<FailMode>,
        impact: Option<ImpactSummary>,
    ) -> Result<Emitted, AuditError> {
        let action = if assigned {
            AuditAction::RoleAssign
        } else {
            AuditAction::RoleRevoke
        };
        let object = match &change.scope {
            Some(scope) => format!("{}#{scope}@{}", change.role, change.subject),
            None => format!("{}@{}", change.role, change.subject),
        };
        let mut record = self.base(actor, action, object, outcome);
        if self.level >= AuditLevel::Standard {
            record.role = Some(change.clone());
            record.violations = self.violation_texts(violations);
            record.suggestions = suggestions_of(violations);
        }
        self.detail(&mut record, actor, meta);
        record.impact = impact;
        if self.level >= AuditLevel::Forensic
            && let Some((before, after)) = digests
        {
            record.before_digest = Some(before);
            record.after_digest = Some(after);
        }
        self.emit_with(record, None, call)
    }

    /// Names of the invariants at `standard`; name and message from `detailed` upward.
    fn violation_texts(&self, violations: &[Violation]) -> Vec<String> {
        violations
            .iter()
            .map(|v| {
                if self.level >= AuditLevel::Detailed {
                    v.to_string()
                } else {
                    v.invariant.clone()
                }
            })
            .collect()
    }

    fn emit(&self, record: AuditRecord) -> Result<AuditRecord, AuditError> {
        self.emit_with(record, None, None).map(|emitted| emitted.record)
    }

    fn mode_for(&self, permission: Option<&str>, call: Option<FailMode>) -> FailMode {
        call.or_else(|| permission.and_then(|p| self.permission_modes.get(p).copied()))
            .unwrap_or(self.fail_mode)
    }

    fn emit_with(
        &self,
        mut record: AuditRecord,
        permission: Option<&str>,
        call: Option<FailMode>,
    ) -> Result<Emitted, AuditError> {
        if let Some(redactor) = &self.redactor {
            redactor(&mut record).map_err(|m| AuditError::Sink(format!("redaction failed: {m}")))?;
        }
        let mode = self.mode_for(permission, call);
        let now = (self.clock)();
        let forensic = self.level >= AuditLevel::Forensic;
        let mut last = lock(&self.last_hash);
        if forensic {
            record.prev_hash = last.clone();
            record.hash = Some(record_hash(&record)?);
        }
        let status = self.queue.submit(self.sink.as_ref(), &record, mode, now)?;
        if forensic && status != AuditStatus::Dropped {
            *last = record.hash.clone();
        }
        drop(last);
        if let Some(observer) = &self.observer {
            observer(&record, status);
        }
        Ok(Emitted { record, status })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 digest of a grant set, independent of order.
pub fn grant_set_digest(grants: &[Grant]) -> String {
    let mut lines: Vec<String> = grants
        .iter()
        .map(|g| serde_json::to_string(g).unwrap_or_default())
        .collect();
    lines.sort();
    let mut hasher = Sha256::new();
    for line in lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    hex(&hasher.finalize())
}

/// SHA-256 digest of a subject's roles, independent of order.
fn role_set_digest(roles: &[RoleAssignment]) -> String {
    let mut lines: Vec<String> = roles
        .iter()
        .map(|r| serde_json::to_string(r).unwrap_or_default())
        .collect();
    lines.sort();
    let mut hasher = Sha256::new();
    for line in lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    hex(&hasher.finalize())
}

/// Hash of a record: SHA-256 of the JSON with `hash` empty and `prev_hash` filled in.
pub fn record_hash(record: &AuditRecord) -> Result<String, AuditError> {
    let mut unsigned = record.clone();
    unsigned.hash = None;
    Ok(hex(&Sha256::digest(serde_json::to_vec(&unsigned)?)))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("registro {index}: hash não confere")]
    Tampered { index: usize },
    #[error("registro {index}: elo quebrado com o anterior")]
    Broken { index: usize },
    #[error("registro {index}: sem hash, não é nível forensic")]
    Unchained { index: usize },
    #[error("a cadeia não parte da âncora conhecida")]
    AnchorMismatch,
    #[error("a cadeia não termina na âncora publicada")]
    HeadMismatch,
}

/// Checks a sequence of forensic records, in the order they were written.
pub fn verify_chain(records: &[AuditRecord]) -> Result<(), ChainError> {
    let mut previous: Option<&str> = None;
    for (index, record) in records.iter().enumerate() {
        let Some(hash) = record.hash.as_deref() else {
            return Err(ChainError::Unchained { index });
        };
        if index > 0 && record.prev_hash.as_deref() != previous {
            return Err(ChainError::Broken { index });
        }
        if record_hash(record).ok().as_deref() != Some(hash) {
            return Err(ChainError::Tampered { index });
        }
        previous = Some(hash);
    }
    Ok(())
}

/// Hash of the last record: the head of the chain, to publish outside (an external log, a
/// timestamping service) as an anchor. `None` for an empty sequence or an unchained last record.
pub fn chain_head(records: &[AuditRecord]) -> Option<&str> {
    records.last()?.hash.as_deref()
}

/// Like [`verify_chain`], against anchors known from outside. `start` is the hash the first record
/// must continue (the head of the part of the chain before `records`; `None` if `records` begins
/// the chain), and `head` is the published head the last record must carry. The second anchor is
/// what catches records cut off the end, which no internal check can see.
pub fn verify_chain_anchored(
    records: &[AuditRecord],
    start: Option<&str>,
    head: Option<&str>,
) -> Result<(), ChainError> {
    verify_chain(records)?;
    if let Some(first) = records.first()
        && first.prev_hash.as_deref() != start
    {
        return Err(ChainError::AnchorMismatch);
    }
    if let Some(head) = head
        && chain_head(records) != Some(head)
    {
        return Err(ChainError::HeadMismatch);
    }
    Ok(())
}

/// The reference record used in the storage estimates: the most common grant change (role with a
/// scope and a short condition), made by an actor with two roles and three request metadata
/// entries.
pub fn reference_record(level: AuditLevel) -> AuditRecord {
    use crate::condition::{Condition, Operand};

    let actor = Subject::user("8f14e45f-ceea-467a-9575-0cbd1e4e7c21")
        .with_role_in("admin", Anchor::new("org", "c9f0f895-fb98-4b91-8f1c-3b0b1e6f2a10"))
        .with_role("auditor");
    let grant = Grant::allow(
        "0b8a1e2c-5f6d-4a3b-9c8d-7e6f5a4b3c2d",
        SubjectMatcher::role("editor"),
        "document.export",
        TargetSelector::kind("project"),
    )
    .scoped(Anchor::new("org", "c9f0f895-fb98-4b91-8f1c-3b0b1e6f2a10"))
    .when(Condition::all([
        Condition::eq(Operand::attr("subject.plan"), Operand::lit("enterprise")),
        Condition::lt(Operand::attr("env.hour"), Operand::lit(18)),
    ]));
    let before: Vec<Grant> = Vec::new();
    let mut meta = Attributes::new();
    meta.insert("ip".into(), "203.0.113.42".into());
    meta.insert("request_id".into(), "req-01HZX3K9QW8E7R6T5Y4U3I2O1P".into());
    meta.insert("reason".into(), "ticket SUP-1234".into());

    let auditor = Auditor::new(level, Arc::new(MemoryAuditLog::new()))
        .with_clock(|| 1_763_700_000_000)
        .resume_chain("a".repeat(64));
    let result = Ok(vec![grant.clone()]);
    auditor
        .grant_mutation(&actor, &Mutation::Add(grant), &before, &result, &meta)
        .expect("registro de referência")
}

/// The reference decision record: a subject with two roles, a resource with three steps, three
/// grants in the source (one with a two-clause condition, one for another permission, one out of
/// scope) and three metadata entries.
pub fn reference_decision_record(level: AuditLevel) -> AuditRecord {
    use crate::catalog::{Catalog, PermissionDef};
    use crate::condition::{Condition, Operand};

    let org = "c9f0f895-fb98-4b91-8f1c-3b0b1e6f2a10";
    let catalog = Catalog::builder()
        .target_kinds(["project", "document"])
        .broad_target("org")
        .permission(PermissionDef::new("document.export").targets(["project", "document"]))
        .permission(PermissionDef::new("document.edit").targets(["project", "document"]))
        .build()
        .expect("catálogo de referência");
    let engine = Engine::builder(catalog).build().expect("motor de referência");
    let grants = vec![
        Grant::allow(
            "0b8a1e2c-5f6d-4a3b-9c8d-7e6f5a4b3c2d",
            SubjectMatcher::role("editor"),
            "document.export",
            TargetSelector::kind("project"),
        )
        .scoped(Anchor::new("org", org))
        .when(Condition::all([
            Condition::eq(Operand::attr("subject.plan"), Operand::lit("enterprise")),
            Condition::lt(Operand::attr("env.hour"), Operand::lit(18)),
        ])),
        Grant::allow(
            "1c9b2f3d-6a7e-4b4c-8d9e-8f7a6b5c4d3e",
            SubjectMatcher::role("editor"),
            "document.edit",
            TargetSelector::kind("project"),
        ),
        Grant::deny(
            "2d0c3a4e-7b8f-4c5d-9eaf-9a8b7c6d5e4f",
            SubjectMatcher::Any,
            "document.export",
            TargetSelector::kind("org"),
        )
        .scoped(Anchor::new("org", "other")),
    ];
    let subject = Subject::user("8f14e45f-ceea-467a-9575-0cbd1e4e7c21")
        .with_role_in("editor", Anchor::new("org", org))
        .with_role("auditor")
        .with_attr("plan", "enterprise");
    let resource = Resource::new("document", "5e6f7a8b-9c0d-4e1f-a2b3-c4d5e6f7a8b9")
        .within("project", "3a4b5c6d-7e8f-4a9b-8c0d-1e2f3a4b5c6d")
        .within("org", org);
    let mut env = Attributes::new();
    env.insert("hour".into(), 10.into());
    let mut meta = Attributes::new();
    meta.insert("ip".into(), "203.0.113.42".into());
    meta.insert("request_id".into(), "req-01HZX3K9QW8E7R6T5Y4U3I2O1P".into());
    meta.insert("route".into(), "POST /documents/:id/export".into());

    let auditor = Auditor::new(level, Arc::new(MemoryAuditLog::new()))
        .with_clock(|| 1_763_700_000_000)
        .resume_chain("a".repeat(64));
    let ctx = Context::new(&grants).with_env(&env);
    let request = Request::new(&subject, "document.export", &resource);
    let (_, record) = auditor.decide(&engine, &ctx, &request, &meta);
    record.expect("registro de referência")
}

fn suggestions_of(violations: &[Violation]) -> Vec<Suggestion> {
    violations
        .iter()
        .filter_map(|v| v.suggestion.as_deref().cloned())
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::resource::ObjectRef;

    #[test]
    fn decision_records_by_level() {
        let minimal = reference_decision_record(AuditLevel::Minimal);
        assert_eq!(minimal.outcome, AuditOutcome::Allowed);
        assert!(minimal.object.starts_with("document.export@document:"));
        assert!(minimal.decision.is_none());
        let standard = reference_decision_record(AuditLevel::Standard);
        assert_eq!(standard.decision.as_ref().unwrap().matched.len(), 1);
        let detailed = reference_decision_record(AuditLevel::Detailed);
        assert!(detailed.resource.is_some() && detailed.actor_detail.is_some());
        let forensic = reference_decision_record(AuditLevel::Forensic);
        let explanation = forensic.explanation.as_ref().unwrap();
        assert_eq!(explanation.grants.len(), 3);
        assert!(forensic.hash.is_some());
        let back: AuditRecord = serde_json::from_str(&serde_json::to_string(&forensic).unwrap()).unwrap();
        assert_eq!(back, forensic);
    }

    #[test]
    fn decision_estimates_match_reference_records() {
        let report: Vec<(AuditLevel, u64, u64)> = AuditLevel::ALL
            .into_iter()
            .map(|level| {
                let actual = serde_json::to_vec(&reference_decision_record(level)).unwrap().len() as u64;
                (level, actual, level.typical_decision_bytes())
            })
            .collect();
        let drifted = report
            .iter()
            .any(|(_, actual, typical)| actual.abs_diff(*typical) as f64 / *typical as f64 > 0.10);
        assert!(!drifted, "medido x documentado: {report:?}");
    }

    fn actor() -> Subject {
        Subject::user("alice").with_role("admin")
    }

    fn grant(id: &str) -> Grant {
        Grant::allow(
            id,
            SubjectMatcher::role("editor"),
            "doc.edit",
            TargetSelector::kind("doc"),
        )
    }

    #[test]
    fn levels_add_fields_progressively() {
        let minimal = reference_record(AuditLevel::Minimal);
        assert!(minimal.grant.is_none() && minimal.full_grant.is_none() && minimal.hash.is_none());
        let standard = reference_record(AuditLevel::Standard);
        assert!(standard.grant.as_ref().is_some_and(|g| g.conditional));
        assert!(standard.full_grant.is_none() && standard.meta.is_empty());
        let detailed = reference_record(AuditLevel::Detailed);
        assert!(detailed.full_grant.is_some() && detailed.actor_detail.is_some());
        assert_eq!(detailed.meta.len(), 3);
        assert!(detailed.hash.is_none());
        let forensic = reference_record(AuditLevel::Forensic);
        assert!(forensic.hash.is_some() && forensic.before_digest.is_some());
    }

    #[test]
    fn estimates_match_reference_records() {
        for level in AuditLevel::ALL {
            let actual = serde_json::to_vec(&reference_record(level)).unwrap().len() as u64;
            let typical = level.typical_record_bytes();
            let drift = actual.abs_diff(typical) as f64 / typical as f64;
            assert!(drift <= 0.10, "{level}: medido {actual} B, documentado {typical} B");
        }
        assert!(AuditLevel::Minimal.estimate_bytes(1_000_000) < AuditLevel::Forensic.estimate_bytes(1_000_000));
    }

    #[test]
    fn rejected_mutation_keeps_violations() {
        let log = Arc::new(MemoryAuditLog::new());
        let auditor = Auditor::new(AuditLevel::Standard, log.clone());
        let result = Err(vec![Violation::new("forbid", "não pode")]);
        auditor
            .grant_mutation(&actor(), &Mutation::Add(grant("g1")), &[], &result, &Attributes::new())
            .unwrap();
        let records = log.records();
        assert_eq!(records[0].outcome, AuditOutcome::Rejected);
        assert_eq!(records[0].violations, ["forbid"]);
    }

    #[test]
    fn forensic_chain_detects_tampering() {
        let log = Arc::new(MemoryAuditLog::new());
        let auditor = Auditor::new(AuditLevel::Forensic, log.clone()).with_clock(|| 1);
        let mut current = Vec::new();
        for id in ["g1", "g2", "g3"] {
            let next = {
                let mut v = current.clone();
                v.push(grant(id));
                v
            };
            let result = Ok(next.clone());
            auditor
                .grant_mutation(
                    &actor(),
                    &Mutation::Add(grant(id)),
                    &current,
                    &result,
                    &Attributes::new(),
                )
                .unwrap();
            current = next;
        }
        let tuple = Tuple::new(ObjectRef::new("doc", "d1"), "viewer", ObjectRef::new("user", "bob"));
        auditor
            .tuple_change(&actor(), true, &tuple, AuditOutcome::Applied, &Attributes::new())
            .unwrap();
        let records = log.records();
        assert_eq!(verify_chain(&records), Ok(()));
        assert_eq!(records[0].after_digest, records[1].before_digest);

        let mut edited = records.clone();
        edited[1].object = "g9".into();
        assert_eq!(verify_chain(&edited), Err(ChainError::Tampered { index: 1 }));

        let mut removed = records.clone();
        removed.remove(1);
        assert_eq!(verify_chain(&removed), Err(ChainError::Broken { index: 1 }));
    }

    #[test]
    fn json_lines_sink_writes_one_record_per_line() {
        let sink = Arc::new(JsonLinesAudit::new(Vec::new()));
        let auditor = Auditor::new(AuditLevel::Minimal, sink.clone());
        let change = RoleChange {
            subject: "bob".into(),
            role: "editor".into(),
            scope: None,
        };
        auditor
            .role_change(&actor(), true, &change, AuditOutcome::Applied, &Attributes::new())
            .unwrap();
        auditor
            .role_change(&actor(), false, &change, AuditOutcome::Applied, &Attributes::new())
            .unwrap();
        drop(auditor);
        let sink = Arc::try_unwrap(sink).ok().unwrap();
        let text = String::from_utf8(sink.into_inner()).unwrap();
        let lines: Vec<AuditRecord> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].action, AuditAction::RoleRevoke);
        assert_eq!(lines[0].object, "editor@bob");
    }

    fn forensic_tuple(sink: Arc<dyn AuditSink>) -> Auditor {
        Auditor::new(AuditLevel::Forensic, sink).with_clock(|| 1_700_000_000_000)
    }

    fn bob_tuple() -> Tuple {
        Tuple::new(ObjectRef::new("doc", "d1"), "viewer", ObjectRef::new("user", "bob"))
    }

    fn write_tuple(auditor: &Auditor) -> Result<AuditRecord, AuditError> {
        auditor.tuple_change(&actor(), true, &bob_tuple(), AuditOutcome::Applied, &Attributes::new())
    }

    /// A sink that fails while `down` is set and keeps what it takes, in order.
    #[derive(Default)]
    struct Flaky {
        down: std::sync::atomic::AtomicBool,
        taken: Mutex<Vec<AuditRecord>>,
    }

    impl Flaky {
        fn set_down(&self, down: bool) {
            self.down.store(down, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl AuditSink for Flaky {
        fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
            if self.down.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(AuditError::Sink("down".into()));
            }
            lock(&self.taken).push(record.clone());
            Ok(())
        }
    }

    #[test]
    fn closed_mode_refuses_when_the_sink_fails() {
        let sink = Arc::new(Flaky::default());
        sink.set_down(true);
        let auditor = forensic_tuple(sink.clone());
        assert!(write_tuple(&auditor).is_err());
        assert_eq!(auditor.stats().pending, 0);
        assert_eq!(auditor.chain_head(), None, "a refused record does not enter the chain");
    }

    #[test]
    fn open_mode_queues_and_drains_in_chain_order() {
        let sink = Arc::new(Flaky::default());
        let auditor = forensic_tuple(sink.clone())
            .with_fail_mode(FailMode::Open)
            .with_retry(RetryPolicy {
                base_delay_ms: 0,
                ..RetryPolicy::default()
            });
        write_tuple(&auditor).unwrap();
        sink.set_down(true);
        for _ in 0..3 {
            let emitted = auditor
                .grant_mutation_with(
                    &actor(),
                    &Mutation::Add(grant("g1")),
                    &[],
                    &Ok(vec![grant("g1")]),
                    &Attributes::new(),
                    None,
                )
                .unwrap();
            assert_eq!(emitted.status, AuditStatus::Pending);
        }
        assert_eq!(auditor.stats().pending, 3);
        assert_eq!(auditor.stats().failures, 3);
        sink.set_down(false);
        assert_eq!(auditor.flush(), 0);
        write_tuple(&auditor).unwrap();
        let taken = lock(&sink.taken).clone();
        assert_eq!(taken.len(), 5);
        assert_eq!(verify_chain(&taken), Ok(()), "the sink saw the chain in order");
        assert_eq!(auditor.stats().written_late, 3);
        assert_eq!(auditor.chain_head().as_deref(), chain_head(&taken));
    }

    #[test]
    fn nothing_jumps_the_queue() {
        let sink = Arc::new(Flaky::default());
        sink.set_down(true);
        let auditor = forensic_tuple(sink.clone()).with_fail_mode(FailMode::Open);
        write_tuple(&auditor).unwrap();
        sink.set_down(false);
        let closed = auditor.grant_mutation_with(
            &actor(),
            &Mutation::Add(grant("g1")),
            &[],
            &Ok(vec![grant("g1")]),
            &Attributes::new(),
            Some(FailMode::Closed),
        );
        assert!(closed.is_ok(), "closed forces the drain, then writes");
        let taken = lock(&sink.taken).clone();
        assert_eq!(taken.len(), 2);
        assert_eq!(taken[1].prev_hash, taken[0].hash);
        assert_eq!(verify_chain(&taken), Ok(()));
    }

    #[test]
    fn backoff_holds_the_retry_until_it_is_due() {
        let sink = Arc::new(Flaky::default());
        sink.set_down(true);
        let clock = Arc::new(std::sync::atomic::AtomicU64::new(1_000));
        let c = clock.clone();
        let auditor = Auditor::new(AuditLevel::Minimal, sink.clone())
            .with_clock(move || c.load(std::sync::atomic::Ordering::SeqCst))
            .with_fail_mode(FailMode::Open)
            .with_retry(RetryPolicy {
                base_delay_ms: 100,
                max_delay_ms: 250,
                ..RetryPolicy::default()
            });
        let change = RoleChange {
            subject: "bob".into(),
            role: "editor".into(),
            scope: None,
        };
        let record = |a: &Auditor| a.role_change(&actor(), true, &change, AuditOutcome::Applied, &Attributes::new());
        record(&auditor).unwrap();
        assert_eq!(auditor.stats().next_retry_at, Some(1_100));
        sink.set_down(false);
        clock.store(1_050, std::sync::atomic::Ordering::SeqCst);
        record(&auditor).unwrap();
        assert_eq!(auditor.stats().pending, 2, "before the backoff the sink is not tried");
        clock.store(1_100, std::sync::atomic::Ordering::SeqCst);
        record(&auditor).unwrap();
        assert_eq!(auditor.stats().pending, 0);
        assert_eq!(lock(&sink.taken).len(), 3);

        sink.set_down(true);
        let mut now = 1_100;
        for expected in [100, 200, 250, 250] {
            clock.store(now, std::sync::atomic::Ordering::SeqCst);
            record(&auditor).unwrap();
            assert_eq!(auditor.stats().next_retry_at, Some(now + expected));
            now += expected;
        }
    }

    #[test]
    fn full_queue_drops_the_new_record_and_keeps_the_chain_verifiable() {
        let sink = Arc::new(Flaky::default());
        let dropped = Arc::new(Mutex::new(Vec::new()));
        let seen = dropped.clone();
        let auditor = forensic_tuple(sink.clone())
            .with_fail_mode(FailMode::Open)
            .with_retry(RetryPolicy {
                capacity: 1,
                base_delay_ms: 0,
                on_drop: Some(Arc::new(move |d: &DroppedRecord| lock(&seen).push(d.record.clone()))),
                ..RetryPolicy::default()
            });
        write_tuple(&auditor).unwrap();
        sink.set_down(true);
        let status = |a: &Auditor| {
            a.grant_mutation_with(
                &actor(),
                &Mutation::Add(grant("g1")),
                &[],
                &Ok(vec![grant("g1")]),
                &Attributes::new(),
                None,
            )
            .unwrap()
            .status
        };
        assert_eq!(status(&auditor), AuditStatus::Pending);
        assert_eq!(status(&auditor), AuditStatus::Dropped);
        assert_eq!(auditor.stats().dropped, 1);
        assert_eq!(lock(&dropped).len(), 1);
        sink.set_down(false);
        write_tuple(&auditor).unwrap();
        let taken = lock(&sink.taken).clone();
        assert_eq!(taken.len(), 3);
        assert_eq!(verify_chain(&taken), Ok(()));
    }

    #[test]
    fn fail_mode_precedence_is_call_then_permission_then_default() {
        let sink = Arc::new(Flaky::default());
        sink.set_down(true);
        let auditor = Auditor::new(AuditLevel::Minimal, sink)
            .with_permission_fail_mode("doc.edit", FailMode::Open)
            .with_permission_fail_mode("doc.view", FailMode::Closed)
            .with_fail_mode(FailMode::Closed);
        let apply = |permission: &str, call: Option<FailMode>| {
            let grant = Grant::allow(
                "g",
                SubjectMatcher::role("editor"),
                permission,
                TargetSelector::kind("doc"),
            );
            auditor.grant_mutation_with(
                &actor(),
                &Mutation::Add(grant.clone()),
                &[],
                &Ok(vec![grant]),
                &Attributes::new(),
                call,
            )
        };
        assert!(apply("doc.other", None).is_err(), "default");
        assert!(apply("doc.edit", None).is_ok(), "permission");
        assert!(
            apply("doc.edit", Some(FailMode::Closed)).is_err(),
            "call over permission"
        );
        assert!(apply("doc.view", Some(FailMode::Open)).is_ok(), "call over permission");
    }

    #[test]
    fn redaction_is_hashed_and_written_masked() {
        let log = Arc::new(MemoryAuditLog::new());
        let auditor = Auditor::new(AuditLevel::Forensic, log.clone())
            .with_clock(|| 1)
            .with_redactor(mask_attributes(["ip", "email"], "***"));
        let actor = Subject::user("alice").with_attr("email", "alice@example.com");
        let mut meta = Attributes::new();
        meta.insert("ip".into(), "203.0.113.42".into());
        meta.insert("reason".into(), "ticket".into());
        auditor
            .tuple_change(&actor, true, &bob_tuple(), AuditOutcome::Applied, &meta)
            .unwrap();
        let records = log.records();
        assert_eq!(records[0].meta["ip"], "***".into());
        assert_eq!(records[0].meta["reason"], "ticket".into());
        assert_eq!(records[0].actor_detail.as_ref().unwrap().attrs["email"], "***".into());
        assert_eq!(verify_chain(&records), Ok(()));
        assert!(!serde_json::to_string(&records[0]).unwrap().contains("203.0.113.42"));
    }

    #[test]
    fn a_failing_redactor_refuses_even_in_open_mode() {
        let log = Arc::new(MemoryAuditLog::new());
        let auditor = Auditor::new(AuditLevel::Standard, log.clone())
            .with_fail_mode(FailMode::Open)
            .with_redactor(Arc::new(|_| Err("boom".into())));
        assert!(write_tuple(&auditor).is_err());
        assert!(log.records().is_empty());
    }

    #[test]
    fn anchors_catch_truncation_and_a_foreign_start() {
        let log = Arc::new(MemoryAuditLog::new());
        let auditor = forensic_tuple(log.clone());
        for _ in 0..3 {
            write_tuple(&auditor).unwrap();
        }
        let records = log.records();
        let head = chain_head(&records).unwrap().to_string();
        assert_eq!(auditor.chain_head().as_deref(), Some(head.as_str()));
        assert_eq!(verify_chain_anchored(&records, None, Some(&head)), Ok(()));
        assert_eq!(
            verify_chain_anchored(&records[..2], None, Some(&head)),
            Err(ChainError::HeadMismatch),
            "records cut off the end"
        );
        let anchor = records[0].hash.clone().unwrap();
        assert_eq!(verify_chain_anchored(&records[1..], Some(&anchor), Some(&head)), Ok(()));
        assert_eq!(
            verify_chain_anchored(&records[1..], Some("00"), None),
            Err(ChainError::AnchorMismatch)
        );
    }

    /// The vector of `docs/audit-format.md`: another implementation must reproduce these bytes and this hash.
    pub(crate) const VECTOR_RECORD: &str = r#"{"at":1700000000000,"level":"forensic","actor":"alice","action":"tuple_add","object":"doc:d1#viewer@user:bob","outcome":"applied","tuple":{"object":{"kind":"doc","id":"d1"},"relation":"viewer","subject":{"object":{"kind":"user","id":"bob"}}},"actor_detail":{"kind":"user","id":"alice","roles":[{"role":"admin"}],"principals":["authenticated"]},"meta":{"ip":"203.0.113.42","reason":"ticket \"SUP-1\" é"},"prev_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    pub(super) const VECTOR_HASH: &str = "087dbffda54667a64ae971f80c70bf6544b205be90c9ca9cc592ef113f4a4cb5";

    fn vector_record() -> AuditRecord {
        let sink = Arc::new(MemoryAuditLog::new());
        let auditor = Auditor::new(AuditLevel::Forensic, sink)
            .with_clock(|| 1_700_000_000_000)
            .resume_chain("a".repeat(64));
        let mut meta = Attributes::new();
        meta.insert("reason".into(), "ticket \"SUP-1\" é".into());
        meta.insert("ip".into(), "203.0.113.42".into());
        let actor = Subject::user("alice").with_role("admin");
        auditor
            .tuple_change(&actor, true, &bob_tuple(), AuditOutcome::Applied, &meta)
            .unwrap()
    }

    #[test]
    fn canonical_vector_matches_the_document() {
        let record = vector_record();
        let unsigned = {
            let mut unsigned = record.clone();
            unsigned.hash = None;
            serde_json::to_string(&unsigned).unwrap()
        };
        assert_eq!(unsigned, VECTOR_RECORD);
        assert_eq!(record.hash.as_deref(), Some(VECTOR_HASH));
        let digest = hex(&Sha256::digest(VECTOR_RECORD.as_bytes()));
        assert_eq!(digest, VECTOR_HASH, "the hash is SHA-256 of exactly those bytes");
    }
}
