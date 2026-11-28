import type { Resource } from './protocol.js';

export * from './protocol.js';

export type AuditLevel = 'minimal' | 'standard' | 'detailed' | 'forensic';

/**
 * What happens to a change when its audit record cannot be written. `closed` (the default) refuses
 * the change; `open` lets it through and the record waits in a retry queue, in order. The mode of an
 * `apply` is, in this order: `audit.failMode`, then `hooks.auditPolicy.permissions[permission]`,
 * then `hooks.auditPolicy.failMode`, then `closed`.
 */
export type AuditFailMode = 'closed' | 'open';

/** Where the record ended up: written, waiting in the retry queue, or dropped by a full queue. */
export type AuditDelivery = 'written' | 'pending' | 'dropped';

/** Attributes whose value is replaced by `mask` (default `[redacted]`) before the record is hashed and written. */
export interface AuditRedaction {
  keys: string[];
  mask?: string;
}

export interface Subject {
  kind: string;
  id?: string;
  roles?: RoleAssignment[];
  principals?: string[];
  attrs?: Record<string, unknown>;
}

/** Who a grant names. */
export type SubjectMatcher =
  | { kind: 'user' | 'role'; id: string }
  | { kind: 'principal'; name: string }
  | { kind: 'relation'; relation: string }
  | { kind: 'any' };

/** A reference to an object, by kind and id. */
export interface ObjectRef {
  kind: string;
  id: string;
}

/**
 * Stable `code` of every error the binding throws (`error.code`), the same on both backends.
 * `INVALID_ARGUMENT` is a scalar argument that is not accepted (wrong type, `NaN`, `Infinity`, a
 * negative or fractional instant, a text where a number goes): it is never coerced. `INVALID_INPUT`
 * is a payload (an object) that does not have the expected shape. `EXCLUSIVE_ERROR` is what an
 * `Exclusive` failure without a code of its own falls into; today none does. `INTERNAL` is a result
 * that could not be turned into a JavaScript value; only the wasm backend reports it. A `Context`,
 * `Engine` or `Exclusive` argument of the wrong class fails in the native layer, before the binding.
 */
export type ErrorCode =
  | 'INVALID_ARGUMENT'
  | 'INVALID_INPUT'
  | 'INVALID_SPEC'
  | 'INVALID_GRANT'
  | 'UNKNOWN_SUBJECT'
  | 'QUERY_LIMIT_EXCEEDED'
  | 'RELATION_DEPTH_EXCEEDED'
  | 'QUERY_ERROR'
  | 'EXCLUSIVE_ZERO_TTL'
  | 'EXCLUSIVE_NOT_HELD'
  | 'EXCLUSIVE_NOT_HOLDER'
  | 'EXCLUSIVE_ANONYMOUS_SUBJECT'
  | 'EXCLUSIVE_UNIDENTIFIED_RESOURCE'
  | 'EXCLUSIVE_TTL_TOO_LONG'
  | 'EXCLUSIVE_DENIED'
  | 'EXCLUSIVE_UNKNOWN_PERMISSION'
  | 'EXCLUSIVE_STORE'
  | 'EXCLUSIVE_ERROR'
  | 'UNKNOWN_INVARIANT'
  | 'REENTRANT_CALL'
  | DslErrorCode
  | 'INTERNAL';

/** What the binding throws: an `Error` with a stable `code`. */
export interface BindingError extends Error {
  code: ErrorCode;
}

/** One side of a comparison: an attribute read at decision time (`subject.*`, `resource.*`, `env.*`) or a literal. */
export type ConditionOperand = { attr: string } | string | number | boolean | null | unknown[] | { [key: string]: unknown };

export type Weekday = 'mon' | 'tue' | 'wed' | 'thu' | 'fri' | 'sat' | 'sun';

/**
 * A condition stored with a grant. `time_between` and `weekday_in` read the decision instant
 * (`now` of the context) in UTC, or on the wall clock of the IANA zone in `tz`; without an instant
 * they cannot be resolved, so a grant with them never allows.
 */
export type Condition =
  | { op: 'eq' | 'ne' | 'lt' | 'le' | 'gt' | 'ge'; left: ConditionOperand; right: ConditionOperand }
  | { op: 'in'; item: ConditionOperand; set: ConditionOperand }
  /** Text prefix. */
  | { op: 'starts_with'; left: ConditionOperand; right: ConditionOperand }
  /** Text suffix. */
  | { op: 'ends_with'; left: ConditionOperand; right: ConditionOperand }
  /** Substring when `left` is text; membership when `left` is a list. */
  | { op: 'contains'; left: ConditionOperand; right: ConditionOperand }
  /** The list `left` has at least one element of the list `right`. */
  | { op: 'any_in'; left: ConditionOperand; right: ConditionOperand }
  /** Every element of the list `left` is in the list `right` (an empty `left` holds). */
  | { op: 'all_in'; left: ConditionOperand; right: ConditionOperand }
  /** IPv4 or IPv6 address inside a CIDR, or inside any CIDR of a list. */
  | { op: 'ip_in'; item: ConditionOperand; set: ConditionOperand }
  /**
   * Time of day in `[from, until)`, as `HH:MM`; `from` after `until` crosses midnight. UTC, or the
   * wall clock of the IANA zone `tz` (`America/Sao_Paulo`), daylight saving time included.
   */
  | { op: 'time_between'; from: string; until: string; tz?: string }
  /** Weekday of the decision instant, in UTC or in the IANA zone `tz`. */
  | { op: 'weekday_in'; days: Weekday[]; tz?: string }
  | { op: 'exists'; attr: string }
  | { op: 'all' | 'any'; of: Condition[] }
  | { op: 'not'; cond: Condition }
  | { op: 'call'; func: string; args?: ConditionOperand[] };

export interface Grant {
  id: string;
  subject: SubjectMatcher;
  permission: string;
  target: { kind: string; id?: string };
  effect: 'allow' | 'deny';
  scope?: { kind: string; id?: string };
  condition?: Condition;
  /** Milliseconds since the Unix epoch. The grant counts from this instant (inclusive). */
  validFrom?: number;
  /** Milliseconds since the Unix epoch. The grant stops counting at this instant (exclusive). */
  validUntil?: number;
  /**
   * Fields of the resource the grant is restricted to (`title`, `address.street`). Absent or empty:
   * the whole resource. A `deny` with fields takes away only those fields.
   */
  fields?: string[];
}

export type Reason =
  | { kind: 'override'; name: string }
  | { kind: 'grant'; grantId: string; permission: string; rank: number; strategy: string }
  | { kind: 'no_applicable_grant' }
  | { kind: 'unknown_permission' }
  /** The permission would be allowed, but a `depends_on` prerequisite is not allowed on the same resource. */
  | { kind: 'missing_prerequisite'; permission: string; prerequisite: string };

export type Verdict =
  | { kind: 'candidate' }
  | { kind: 'candidate_fail_safe'; problem: string }
  | { kind: 'permission_unrelated' }
  | { kind: 'out_of_scope' }
  | { kind: 'target_not_on_path' }
  | { kind: 'subject_mismatch' }
  | { kind: 'subject_unresolved'; problem: string }
  | { kind: 'condition_false' }
  | { kind: 'condition_unresolved'; problem: string }
  /** The grant is outside its `validFrom`/`validUntil` window at the context's `now`. */
  | { kind: 'outside_window' }
  /** The grant, or the requested permission, is `override_only`: grants are ignored. */
  | { kind: 'override_only' }
  /** A question about one field: the grant names fields and this one is not among them. */
  | { kind: 'field_not_covered' }
  | { kind: 'not_reached' };

export interface Decision {
  effect: 'allow' | 'deny';
  reason: Reason;
  matched?: string[];
  warnings?: string[];
}

export interface Explanation {
  subject: Subject;
  permission: string;
  /** The field the question was about; absent for the resource as a whole. */
  field?: string;
  resource: Resource;
  effective: string[];
  path: Array<{ kind: string; id?: string }>;
  roles: string[];
  overrides: Array<{ name: string; outcome: 'excepted' | 'abstained' | 'allowed' | 'denied' }>;
  grants: Array<{
    grant: Grant;
    verdict: Verdict;
    rank?: number;
    anchor?: { kind: string; id?: string };
    condition?: ConditionTrace;
  }>;
  /** Prerequisites (`depends_on`, transitive) consulted for an allowed permission, each with its outcome. */
  prerequisites?: Array<{ permission: string; allowed: boolean }>;
  strategy: string;
  decision: Decision;
}

export interface ConditionTrace {
  label: string;
  result: { kind: 'true' | 'false' | 'skipped' } | { kind: 'error'; detail: string };
  children?: ConditionTrace[];
}

export interface CapabilitySet {
  subject: Subject;
  grants: Grant[];
  /**
   * Present when some grant is field-restricted: the real grants, while `grants` holds the form an
   * older reader decides safely (a restricted `allow` left out, a restricted `deny` whole). Pass the
   * set back as received.
   */
  withFields?: Grant[];
}

/**
 * The fields a subject may use for a permission on a resource: `all`, `all_except` (only when the
 * catalog does not declare the permission's fields), `only` or `none`.
 */
export type FieldSet =
  | { kind: 'all' }
  | { kind: 'all_except'; fields: string[] }
  | { kind: 'only'; fields: string[] }
  | { kind: 'none' };

/** Why one field came out allowed or denied. */
export interface FieldVerdict {
  /** Absent for the rest: every field no grant and no catalog entry names. */
  field?: string;
  allowed: boolean;
  reason: Reason;
  /** Ids of the `allow` grants that applied to the field. */
  grantedBy?: string[];
  /** Ids of the `deny` grants that applied to the field. */
  deniedBy?: string[];
}

export interface FieldExplanation {
  permission: string;
  allowed: FieldSet;
  /** The override that decided every field alike; `fields` is empty then. */
  overriddenBy?: string;
  fields: FieldVerdict[];
}

/** What denied a request, as `Engine.whyNot` names it. */
export type WhyNotCause =
  /** An override ruled before the grants: no change of grants or roles undoes it. */
  | { kind: 'override'; name: string }
  | { kind: 'deny'; grantId: string; permission: string; target: { kind: string; id?: string } }
  | { kind: 'no_applicable_grant' }
  | { kind: 'unknown_permission' }
  /** The permission is `override_only`: only an override can allow it. */
  | { kind: 'override_only_permission' }
  | { kind: 'missing_prerequisite'; prerequisite: string; cause: WhyNotCause };

/** One change that, applied alone, makes the decision `allow`. */
export type WhyNotChange =
  | { kind: 'assign_role'; role: string; scope?: { kind: string; id?: string } }
  /** The `id` of the grant is a placeholder. */
  | { kind: 'add_grant'; grant: Grant }
  | { kind: 'remove_deny'; grantId: string; permission: string; target: { kind: string; id?: string } }
  | { kind: 'narrow_deny'; grantId: string; field: string }
  /** The leaves that were false (`failed`) or could not be evaluated (`unresolved`); no value is suggested. */
  | { kind: 'satisfy_condition'; grantId: string; failed?: string[]; unresolved?: string[] };

/** A governance rule the remedy runs into, known to the catalog or to the shape of the change. */
export type WhyNotCaveat = 'override_only' | 'management_only' | 'non_delegable' | 'affects_others';

export type Remedy = WhyNotChange & {
  /** Position of the path step the change acts on (0 = most specific). */
  rank?: number;
  caveats?: WhyNotCaveat[];
};

export interface Remedies {
  cause: WhyNotCause;
  /** Verified, smallest and most specific first. Empty when nothing alone would allow. */
  remedies: Remedy[];
  /** The verification budget or `maxRemedies` cut the list: there may be more. */
  partial?: boolean;
}

export interface WhyNotOptions {
  /** Cap on verifications (one decision each); defaults to the `maxDecisions` of the context's limits. */
  maxDecisions?: number;
  /** Most remedies returned (16 by default). */
  maxRemedies?: number;
}

/** Strict when `P` is given (a union of ids), any string at the default. */
export type PermissionArg<P extends string = string> = string extends P ? string : P;

export interface DecisionRequest<P extends string = string> {
  subject: Subject;
  permission: PermissionArg<P>;
  resource: Resource;
  /** Asks about one field of the resource. Absent: the resource as a whole. */
  field?: string;
}

export interface RoleAssignment {
  role: string;
  scope?: { kind: string; id?: string };
  /** Milliseconds since the Unix epoch, inclusive. */
  validFrom?: number;
  /** Milliseconds since the Unix epoch, exclusive. */
  validUntil?: number;
}

export interface Bypass {
  permission: string;
  resource: Resource;
}

/** Invariants `apply` and `applyTemplate` check, by `kind`. */
export type InvariantSpec =
  | { kind: 'catalog_conformance' }
  | { kind: 'no_self_management' }
  | { kind: 'require_permission'; permission: string; resource: Resource }
  | {
      kind: 'no_lockout';
      permissions: string[];
      members: Subject[];
      resource: Resource;
      /** The administrator role and the subjects that may receive it; makes a refusal carry a `suggestion`. */
      reserve?: { adminRole: RoleAssignment; subjects: Subject[] };
    }
  /** A permission is only held together with its `depends_on` ones. */
  | { kind: 'prerequisites' }
  /** Only whoever holds `manager` grants a non-delegable permission. */
  | { kind: 'non_delegable'; manager: string }
  /** Management-only permissions go only to the listed roles. */
  | { kind: 'management_only'; roles: string[] }
  /** The actor only grants what they hold, unless they hold the bypass. */
  | { kind: 'no_escalation'; bypass?: Bypass }
  | { kind: 'forbid'; subject: SubjectMatcher; permissions: string[] }
  /**
   * Nobody accumulates two members of a `mutuallyExclusive` set of the catalog in the same scope, by a direct
   * role, an inherited one, a grant or a temporary elevation. `subjects` are also judged when a grant is added.
   */
  | { kind: 'separation_of_duties'; subjects?: Subject[] }
  /** An invariant registered in the engine's `hooks.invariants`; `name` must be one of them. */
  | { kind: 'custom'; name: string };

/** Where the subjects and the resources of an impact come from. */
export type ImpactSource =
  /** Your own list. Empty `resources`: the ones the change reaches; empty `permissions`: the ones it touches. */
  | { kind: 'sample'; subjects?: Subject[]; resources?: Resource[]; permissions?: string[]; fields?: string[] }
  /** From the reverse queries. Empty `resources`: the ones the change reaches. This is the default. */
  | { kind: 'derived'; resources?: Resource[] };

/** What the impact of a change is computed over; give it to `apply`, `impact`, `propose` or `resolve`. */
export interface ImpactOptions {
  source?: ImpactSource;
  /** Attributes the questions run with. */
  env?: Record<string, unknown>;
  /** Caps on the parties and decisions; hitting one marks the impact `partial`. */
  limits?: { maxParties?: number; maxDecisions?: number };
}

export type Access = 'allowed' | 'denied' | 'indeterminate';

/** One question whose answer the change moves. `subject` reads `user:alice`, `role:editor`, `anyone`. */
export interface AccessChange {
  subject: string;
  permission: string;
  resource: Resource;
  field?: string;
  before: Access;
  after: Access;
}

/**
 * Who gains and who loses access with a change. `indeterminate` holds what the change moves toward or away
 * from a decision that could not be settled (a condition or an override that cannot be evaluated): it never
 * counts as a gain. `partial`: a limit cut the answer, so more may gain or lose than is listed.
 */
export interface Impact {
  gained: AccessChange[];
  lost: AccessChange[];
  indeterminate: AccessChange[];
  permissions: string[];
  checked: number;
  partial: boolean;
  notes?: string[];
  /** Separation clashes the change would create, listed whether or not `separation_of_duties` is on. */
  separation?: PotentialClash[];
}

/** Two members of a `mutuallyExclusive` set that one subject holds in the same scope. */
export interface SeparationClash {
  set: string;
  of: 'roles' | 'permissions';
  first: string;
  second: string;
  /** `null`/absent for a global set; otherwise the anchor (`org:1`, or `org`). */
  scope?: string;
}

export interface PotentialClash {
  /** `user:alice`, `role:editor`, `principal:authenticated`, `anyone`. */
  subject: string;
  clash: SeparationClash;
}

export interface ApplyInput {
  actor: Subject;
  current: Grant[];
  mutation:
    | { add: Grant }
    | { remove: { id: string } }
    | { assign_role: { subject: Subject; role: RoleAssignment } }
    | { revoke_role: { subject: Subject; role: RoleAssignment } };
  invariants?: InvariantSpec[];
  tuples?: unknown[];
  audit?: { level: AuditLevel; prevHash?: string; failMode?: AuditFailMode; redact?: AuditRedaction };
  meta?: Record<string, unknown>;
  /** Instant the governance judges the actor's windows at, in ms UTC. Defaults to the system clock; an invalid one (`NaN`, negative, text) throws `INVALID_ARGUMENT`, and a clock before 1970 is an error, never `0`. Never take it from a client: a past instant revives expired windows. */
  now?: number | bigint;
  /** Computes the impact of the change and returns it in `ApplyResult.impact`; at audit `detailed` or `forensic` the record carries a summary of it. */
  impact?: ImpactOptions;
}

export interface TemplateGrant {
  id: string;
  permission: string;
  target: { kind: string; id?: string };
  effect?: 'allow' | 'deny';
  scope?: { kind: string; id?: string };
  condition?: Condition;
}

/** A versioned set of model grants; materializing it copies them, with no link back to the template. */
export interface RoleTemplate {
  id: string;
  version: number;
  grants: TemplateGrant[];
}

export interface MaterializeInput {
  template: RoleTemplate;
  subject: SubjectMatcher;
  scope?: { kind: string; id?: string };
  /** Materialized grant ids are `<idPrefix>:<template grant id>`. */
  idPrefix: string;
}

export interface Materialized {
  template: string;
  templateVersion: number;
  mutations: ApplyInput['mutation'][];
  meta: Record<string, unknown>;
}

export interface ApplyTemplateInput extends MaterializeInput {
  actor: Subject;
  current: Grant[];
  invariants?: InvariantSpec[];
  tuples?: unknown[];
  audit?: { level: AuditLevel; prevHash?: string; failMode?: AuditFailMode; redact?: AuditRedaction };
  meta?: Record<string, unknown>;
  now?: number | bigint;
}

export interface ApplyTemplateResult {
  ok: boolean;
  grants?: Grant[];
  violations?: Violation[];
  /** One record per change when accepted; only the refusal when not. Nothing is written by the binding. */
  audits: Array<Record<string, unknown>>;
  /** The worst destination among `audits`; `pending` means a record waits in the retry queue. */
  auditStatus?: AuditDelivery | null;
}

export type Violation = { invariant: string; message: string; suggestion?: Suggestion };

/** How a party reaches a permission. */
export type AccessVia =
  | { type: 'override'; name: string }
  | { type: 'grant'; grantId: string }
  | { type: 'role'; grantId: string; role: string }
  | { type: 'inherited_role'; grantId: string; role: string; from: string }
  | { type: 'relation'; grantId: string; relation: string; object: ObjectRef }
  | { type: 'nothing' }
  | { type: 'unknown' };

/** A party a query names. */
export type SubjectRef =
  | { type: 'user'; id: string }
  | { type: 'object'; kind: string; id: string }
  | { type: 'role'; id: string }
  | { type: 'principal'; name: string }
  | { type: 'userset'; object: ObjectRef; relation: string }
  | { type: 'wildcard'; kind: string }
  | { type: 'anyone' }
  | { type: 'unknown' };

/**
 * Filter expression `list` returns, for the caller's own query language. Treat `unknown` as
 * "check each row", never as `true`.
 */
export type FilterExpr =
  | { op: 'true' | 'false' | 'unknown' }
  | { op: 'within'; anchor: { kind: string; id?: string } }
  | { op: 'on_path'; selector: { kind: string; id?: string } }
  | { op: 'anchor_in'; kind: string; ids: string[] }
  | { op: 'attr_eq'; attr: string; value: unknown }
  | { op: 'residual'; index: number }
  | { op: 'not'; expr: FilterExpr }
  | { op: 'and' | 'or'; exprs: FilterExpr[] };

export type FilterShape =
  | { type: 'nothing' | 'unknown' }
  | { type: 'kind'; except: unknown[] }
  | { type: 'ids'; ids: string[] }
  | { type: 'within'; anchors: unknown[] }
  | { type: 'compound'; expr: FilterExpr };

/** What only the resource, not the filter, decides. Never counts as permission. */
export type FilterResidual =
  | { type: 'condition'; grantId: string; condition: Condition }
  | { type: 'override'; name: string }
  | { type: 'strategy'; name: string }
  | { type: 'outside_layout'; grantIds: string[] }
  | { type: 'unknown' };

export interface ListOptions {
  /** Path steps from the listed `kind` to the widest (`['document', 'project', 'org']`). */
  layout?: string[];
  /** Resources to evaluate against the filter, to get back the allowed ids. */
  resources?: Resource[];
}

export interface ListResult {
  kind: string;
  permission: string;
  exact: boolean;
  shape: FilterShape;
  expr: FilterExpr;
  residual: FilterResidual[];
  warnings: string[];
  /** Allowed ids of `options.resources`; `null` without them. */
  ids: string[] | null;
}

export interface WhoCanOnResult {
  permission: string;
  resource: Resource;
  entries: Array<{ subject: SubjectRef; via: AccessVia }>;
  /** Parties allowed, but denied when they act together with `with`. */
  except: Array<{ allowed: SubjectRef; with: SubjectRef }>;
}

export interface CheckForResult {
  subject: SubjectRef;
  allowed: boolean;
  decision: Decision;
  via: AccessVia;
  explanation: Explanation;
}

/** Ceilings of the reverse queries; what is missing keeps the default. Over the ceiling the query throws `QUERY_LIMIT_EXCEEDED`. */
export interface QueryLimits {
  maxParties?: number;
  maxDecisions?: number;
}

export interface Lease {
  resource: ObjectRef;
  holder: ObjectRef;
  priority: number;
  /** Milliseconds since the Unix epoch. */
  acquiredAt: number;
  /** Milliseconds since the Unix epoch; the lease is over at this instant. */
  expiresAt: number;
}

export type Acquisition =
  | { outcome: 'granted'; lease: Lease }
  /** `previous` is the lease taken from its holder, to warn them. */
  | { outcome: 'preempted'; lease: Lease; previous: Lease }
  | { outcome: 'busy'; holder: Lease };

export interface ExclusiveOptions {
  /** Ceiling of a lease's duration, in ms. */
  maxTtlMs?: number;
  /** Names of the hold and preempt permissions in the catalog. */
  permissions?: { hold: string; preempt: string };
}

/**
 * Compensating change a refusal proposes. It names the subject by id and carries only the role;
 * nothing is applied. Send it back as an `assign_role` or `revoke_role` change with the stored subject.
 */
export type Suggestion =
  | { kind: 'assign_role'; subjectId: string; role: RoleAssignment }
  | { kind: 'revoke_role'; subjectId: string; role: RoleAssignment };

export interface ApplyResult {
  ok: boolean;
  grants?: Grant[];
  /** Subject with the role applied, on an accepted role change. */
  subject?: Subject;
  violations?: Violation[];
  audit?: Record<string, unknown> | null;
  /** With `audit`: `pending` means the sink failed in `open` mode and the record waits in the queue. */
  auditStatus?: AuditDelivery | null;
  /** With `ApplyInput.impact`, on an accepted change. */
  impact?: Impact;
}

/** `ok: true` with the `impact` of the change, nothing applied; `ok: false` with the invariants' `violations`. */
export type ImpactResult = { ok: true; impact: Impact } | { ok: false; violations: Violation[] };

/** Who may approve a kind of change: whoever holds `permission` on `resource`. */
export interface ApprovalRule {
  kind: 'add' | 'remove' | 'assign_role' | 'revoke_role';
  permission: string;
  resource: Resource;
}

export type PendingStatus =
  | { state: 'pending' }
  | { state: 'approved'; by: string; at: number }
  | { state: 'rejected'; by: string; at: number; reason: string }
  | { state: 'expired'; at: number };

/** A change waiting for an approver. `mutation` has the shape of `ApplyInput['mutation']`. */
export interface PendingRequest {
  id: string;
  actor: Subject;
  mutation: ApplyInput['mutation'];
  requestedAt: number;
  expiresAt?: number;
  status: PendingStatus;
  /** The impact when the request was proposed, when `ProposeInput.impact` asked for it. */
  impact?: Impact;
  /** Present when the request is a temporary elevation (see `ElevateInput`). */
  elevation?: ElevationInfo;
}

/** What an elevation gives: a role, or a permission on a target. */
export type ElevationTarget =
  | { kind: 'role'; role: string; scope?: { kind: string; id?: string } }
  | { kind: 'permission'; permission: string; target: { kind: string; id?: string }; scope?: { kind: string; id?: string } };

/** How a role or permission may be elevated. */
export interface ElevationRule {
  key: { role: string } | { permission: string };
  /** The longest an approved elevation lasts, in milliseconds. */
  maxDurationMs: number;
  /** What an approver, a reviewer of a break-glass or whoever revokes must hold... */
  approverPermission: string;
  /** ...and on which resource. */
  approverResource: Resource;
  /** A request without a justification is refused. */
  requireJustification?: boolean;
  /** Present when the actor may elevate themselves in an emergency. */
  breakGlass?: { maxDurationMs: number };
}

export interface ElevationRequest {
  id: string;
  /** Who gets the elevation. Must have an `id`. */
  actor: Subject;
  target: ElevationTarget;
  /** How long it lasts once approved, in milliseconds. The window opens at the approval. */
  durationMs: number;
  justification?: string;
  /** The actor approves it themselves, as an emergency. Needs a policy that allows it and a `forensic` auditor. */
  breakGlass?: boolean;
}

export type ReviewState = { state: 'pending' } | { state: 'closed'; by: string; at: number; note: string };

export interface ElevationInfo {
  target: ElevationTarget;
  durationMs: number;
  justification?: string;
  breakGlass: boolean;
  /** The instant (ms, exclusive) the elevation stops applying, once it is approved. */
  validUntil?: number;
  /** The review of a break-glass elevation; closed by someone other than the actor. */
  review?: ReviewState;
  revoked?: { by: string; at: number; reason?: string };
}

/**
 * One step of the elevation flow, as `Engine.elevate` takes it. `op: 'request'` needs `elevationRequest`; the other
 * operations act on the stored `request` as `by`.
 */
export interface ElevateInput extends ApprovalFlowInput {
  op: 'request' | 'approve' | 'reject' | 'revoke' | 'close_review';
  elevation: ElevationRule[];
  elevationRequest?: ElevationRequest;
  request?: PendingRequest;
  by?: Subject;
  /** The reason of `reject` and `revoke`, or the note of `close_review`. */
  reason?: string;
  expiresAt?: number | bigint;
}

/**
 * `request`: `applied: false` waits for an approver; `applied: true` is a break-glass already in force, with its `grants`.
 * `approve` and `revoke` carry the `grants` to persist (and the elevation of a role is in `request.mutation`).
 */
export type ElevateResult = ApprovalAudit &
  (
    | { ok: true; request: PendingRequest; applied?: boolean; grants?: Grant[]; proposedImpact?: Impact }
    | { ok: false; code: 'REFUSED'; violations: Violation[] }
    | { ok: false; code: 'EXPIRED'; request: PendingRequest }
    | { ok: false; code: 'NOT_PENDING' | 'UNKNOWN' | 'DUPLICATE' }
  );

/** Who may review an item of a recertification campaign. */
export type ReviewerRule =
  | { kind: 'permission'; permission: string; resource: Resource }
  | { kind: 'role'; role: string }
  | { kind: 'subject'; id: string };

/** Sends the items about one permission or role to a reviewer other than the campaign's default. */
export interface ReviewerRoute {
  permission?: string;
  role?: string;
  reviewer: ReviewerRule;
}

/** What a campaign reviews: an empty list means everything on that axis; only `permissions` selects only grants. */
export interface RecertScope {
  anchor?: { kind: string; id?: string };
  permissions?: string[];
  roles?: string[];
  subjectKinds?: string[];
}

/** What happens to an item nobody reviewed by the deadline. */
export type RecertDefaultAction = 'expire' | 'flag' | 'escalate';

/** A campaign to open. `dueAt` and `keepPeriodMs` are in milliseconds. */
export interface CampaignSpec {
  id: string;
  name?: string;
  scope?: RecertScope;
  reviewer: ReviewerRule;
  routes?: ReviewerRoute[];
  /** The permission every reviewer (and delegate) must hold, and on which resource. */
  reviewerPermission: string;
  reviewerResource: Resource;
  dueAt: number | bigint;
  keepPeriodMs: number | bigint;
  defaultAction?: RecertDefaultAction;
  escalateTo?: ReviewerRule;
}

export type RecertDecision = { action: 'keep' } | { action: 'revoke' } | { action: 'delegate'; to: Subject };

export type RecertItemState =
  | { state: 'open' }
  | { state: 'kept'; by: string; at: number; until: number; reason?: string }
  | { state: 'revoked'; by: string; at: number; reason?: string }
  | { state: 'expired'; by: string; at: number }
  | { state: 'flagged'; at: number; reason?: string }
  | { state: 'escalated'; at: number; to: ReviewerRule };

export interface RecertItem {
  id: string;
  target: { kind: 'grant'; grant: Grant } | { kind: 'role'; subject: Subject; role: RoleAssignment };
  holder?: string;
  holderRole?: string;
  reviewer: ReviewerRule;
  assignee?: string;
  delegations?: { from: string; to: string; at: number; reason?: string }[];
  /** What revoking this access would take away from others. */
  impact?: Impact;
  state: RecertItemState;
}

/** A recertification campaign as the engine returns it and the store keeps it. `revision` counts the writes. */
export interface Campaign {
  id: string;
  name?: string;
  scope: RecertScope;
  reviewer: ReviewerRule;
  routes?: ReviewerRoute[];
  reviewerPermission: string;
  reviewerResource: Resource;
  openedBy: string;
  openedAt: number;
  dueAt: number;
  keepPeriodMs: number;
  defaultAction: RecertDefaultAction;
  escalateTo?: ReviewerRule;
  status: { state: 'open' } | { state: 'closed'; by: string; at: number };
  items: RecertItem[];
  revision: number;
}

export interface CampaignReport {
  campaign: string;
  name?: string;
  status: Campaign['status'];
  openedBy: string;
  openedAt: number;
  dueAt: number;
  defaultAction: RecertDefaultAction;
  total: number;
  open: number;
  kept: number;
  revoked: number;
  expired: number;
  flagged: number;
  escalated: number;
  delegated: number;
  byReviewer: Record<string, { kept: number; revoked: number; delegated: number }>;
  /** The items a flag or an escalation left without an answer. */
  unresolved: string[];
}

/**
 * One step of the recertification flow, as `Engine.recertify` takes it. `open` needs `campaignSpec` (and `subjects`,
 * the people whose roles are certified); `decide` needs `campaign`, `item`, `decision` and `by`; `close` and `report`
 * act on `campaign`; `list` takes `campaigns`.
 */
export interface RecertifyInput extends ApprovalFlowInput {
  op: 'open' | 'decide' | 'close' | 'report' | 'list';
  campaignSpec?: CampaignSpec;
  campaign?: Campaign;
  campaigns?: Campaign[];
  subjects?: Subject[];
  by?: Subject;
  item?: string;
  decision?: RecertDecision;
  reason?: string;
}

/**
 * `decide` and `close` carry the `grants` to persist and the subjects whose role the revocation took
 * (`revokedRole`, `revokedRoles`). Nothing is stored by the engine.
 */
export type RecertifyResult = ApprovalAudit &
  (
    | {
        ok: true;
        campaign?: Campaign;
        item?: RecertItem;
        grants?: Grant[];
        revokedRole?: Subject | null;
        revokedRoles?: Subject[];
        report?: CampaignReport;
        campaigns?: Campaign[];
      }
    | { ok: false; code: 'REFUSED'; violations: Violation[] }
    | { ok: false; code: 'UNKNOWN' | 'DUPLICATE' | 'CLOSED' | 'STALE' }
  );

/** What `propose`, `resolve` and `expire` share with `apply`: the state they judge against and the audit. */
export interface ApprovalFlowInput {
  /** The grants as they are now. */
  current?: Grant[];
  /** Which kinds of change wait for approval, and who approves them. */
  approval?: ApprovalRule[];
  invariants?: InvariantSpec[];
  tuples?: unknown[];
  audit?: ApplyInput['audit'];
  meta?: Record<string, unknown>;
  now?: number | bigint;
  /** Computes the impact: `propose` keeps it in the request, `resolve` recomputes it against `current`. */
  impact?: ImpactOptions;
}

export interface ProposeInput extends ApprovalFlowInput {
  actor: Subject;
  mutation: ApplyInput['mutation'];
  /** Id of the request; the caller makes it unique. */
  id: string;
  /** From this instant (ms UTC) on nobody can decide the request. */
  expiresAt?: number | bigint;
}

export interface ResolveInput extends ApprovalFlowInput {
  request: PendingRequest;
  approver: Subject;
  decision: 'approve' | 'reject';
  /** Required by `reject`. */
  reason?: string;
}

export interface ReviewImpactInput extends ApprovalFlowInput {
  request: PendingRequest;
}

/** The impact of a pending request as proposed and as it would be over `current` now; `changed` when they differ. */
export interface ReviewImpactResult {
  ok: true;
  proposed?: Impact;
  current?: Impact;
  changed: boolean;
}

export interface ExpireInput extends ApprovalFlowInput {
  requests: PendingRequest[];
}

/** The records of the steps, in order, and where the worst of them ended up (as in `ApplyResult`). */
interface ApprovalAudit {
  audits: Array<Record<string, unknown>>;
  auditStatus?: AuditDelivery | null;
}

/**
 * `ok` with `applied: true` and `grants`: the policy asks no approval and the change went through. `ok`
 * with `applied: false` and `request`: it waits for an approver. Otherwise `code: 'REFUSED'` and `violations`.
 */
export type ProposeResult = ApprovalAudit &
  (
    | { ok: true; applied: true; grants: Grant[]; subject?: Subject }
    | { ok: true; applied: false; request: PendingRequest }
    | { ok: false; code: 'REFUSED'; violations: Violation[] }
  );

/**
 * Approved: `grants` (and `subject` on a role change) to persist, and the request. Refused: `REFUSED` (the
 * request stays pending), `EXPIRED` (`request` is now expired), `NOT_PENDING`.
 */
export type ResolveResult = ApprovalAudit &
  (
    | { ok: true; request: PendingRequest; grants?: Grant[]; subject?: Subject; proposedImpact?: Impact }
    | { ok: false; code: 'REFUSED'; violations: Violation[] }
    | { ok: false; code: 'EXPIRED'; request: PendingRequest }
    | { ok: false; code: 'NOT_PENDING' }
  );

export interface ExpireResult extends ApprovalAudit {
  ok: true;
  expired: PendingRequest[];
}

/** Counters of the retry queue of `open` mode. */
export interface AuditStats {
  pending: number;
  writtenLate: number;
  dropped: number;
  failures: number;
  /** Instant (ms) from which the next write is tried by itself; `null` with nothing waiting. */
  nextRetryAt: number | null;
}

export interface AuditPolicy {
  failMode?: AuditFailMode;
  /** Mode by permission, over `failMode`. */
  permissions?: Record<string, AuditFailMode>;
  /** Records kept waiting; past it a new one is dropped. Default 1024. */
  capacity?: number;
  /** Wait after the first failure, doubled per consecutive failure up to `maxDelayMs`. Default 100. */
  baseDelayMs?: number;
  /** Default 30000. */
  maxDelayMs?: number;
}

/** Anchors known from outside the log, to check a chain against. */
export interface ChainAnchors {
  /** Hash the first record continues; leave it out when the list starts the chain. */
  start?: string;
  /** Published head the last record must carry. */
  head?: string;
}

export type ChainVerification =
  | { ok: true; head: string | null }
  | {
      ok: false;
      code: 'TAMPERED' | 'BROKEN' | 'UNCHAINED' | 'ANCHOR_MISMATCH' | 'HEAD_MISMATCH';
      index: number | null;
      message: string;
    };

/** Why a Merkle proof was refused. */
export type MerkleVerification =
  | { ok: true }
  | {
      ok: false;
      code: 'INDEX_OUT_OF_RANGE' | 'PROOF_LENGTH' | 'ROOT_MISMATCH' | 'SIZES' | 'INVALID_PROOF';
      message: string;
    };

/** Inclusion of one record (or leaf hash) in a tree of `size` leaves with root `root` (RFC 9162 §2.1.3). */
export interface MerkleInclusionInput {
  /** The audit record; its leaf hash is computed as in `docs/audit-format.md`. Give this or `leaf`. */
  record?: Record<string, unknown>;
  /** The leaf hash, hex, for an auditor that holds only the hash. Give this or `record`. */
  leaf?: string;
  /** Position of the leaf, from 0. */
  index: number;
  /** Number of leaves of the tree the root belongs to. */
  size: number;
  /** The audit path, hex hashes from the leaf up. */
  proof: string[];
  /** The published tree head, hex. */
  root: string;
}

/** The tree of `second` leaves extends the tree of `first` leaves (RFC 9162 §2.1.4). */
export interface MerkleConsistencyInput {
  first: number;
  second: number;
  firstRoot: string;
  secondRoot: string;
  /** The consistency proof, hex hashes. */
  proof: string[];
}

/** An RFC 3161 time stamp of an audit chain head, to verify without network. */
export interface TimestampInput {
  /** The `TimeStampResp`, DER, base64. */
  response: string;
  /** The chain head that was stamped, hex (the `hash` of the last record). */
  head: string;
  /** PEM text with the CA certificates you trust. With none, every response is refused. */
  roots: string;
  /** PEM text with more certificates to complete the chain, when the response did not embed them. */
  certificates?: string;
  /** The nonce sent in the request, hex, up to 16 characters; the response must echo it. */
  nonce?: string;
  /** The policy OID the response must state. */
  policy?: string;
}

export type TimestampVerification =
  | {
      ok: true;
      /** Time the TSA states, seconds since the Unix epoch. */
      genTime: number;
      /** `genTime` as `YYYY-MM-DDTHH:MM:SSZ`. */
      time: string;
      serial: string;
      policy: string;
      algorithm: 'sha256' | 'sha384' | 'sha512';
      imprint: string;
      nonce: string | null;
      /** DER subject of the signer certificate, hex. */
      signerSubject: string;
    }
  | {
      ok: false;
      code:
        | 'MALFORMED'
        | 'NOT_GRANTED'
        | 'IMPRINT_MISMATCH'
        | 'NONCE_MISMATCH'
        | 'POLICY_MISMATCH'
        | 'UNSUPPORTED'
        | 'BAD_SIGNATURE'
        | 'MISSING_SIGNER'
        | 'UNTRUSTED_CHAIN'
        | 'CERTIFICATE_NOT_VALID'
        | 'SIGNER_USAGE';
      message: string;
    };

/**
 * What a `hooks.conditions` function gets: the operands of the `call` condition, already resolved
 * (`{ attr: 'subject.dept' }` becomes the attribute's value). It returns a boolean; anything else, or
 * a throw, is a condition error: an allow grant does not apply, a deny grant still does, and the
 * `explain` trace carries the message.
 */
export type HostCondition = (args: unknown[]) => boolean;

/** What a host override is asked: the decision request and the environment it runs in. */
export interface HostOverrideRequest {
  subject: Subject;
  permission: string;
  resource: Resource;
  env: Record<string, unknown>;
  /** Decision instant in ms UTC, or `null` when there is none. */
  now: number | null;
}

/** What a host override answers; `null` or `undefined` abstain. A throw is `'denied'`. */
export type HostOverrideOutcome = 'allowed' | 'denied' | 'abstained' | null | undefined;

/** An override written in JavaScript. It runs after the overrides of the spec, in list order. */
export interface HostOverride {
  /** Shows in the `explain` trace and as the reason of a decision it settles. */
  name: string;
  /** Permissions (and the ones they grant) the override is never consulted for. */
  except?: string[];
  evaluate(request: HostOverrideRequest): HostOverrideOutcome;
}

/** What a host invariant is asked: the change, and the grants before and after it. */
export interface HostProposal {
  actor: Subject;
  mutation: ApplyInput['mutation'];
  before: Grant[];
  after: Grant[];
  now: number | null;
}

/**
 * What a host invariant answers: nothing (or `null`, or `true`) to accept; a text, or
 * `{ message, suggestion? }`, to refuse (a list refuses with its first entry). `suggestion` is a change
 * the governance re-checks against every invariant before it surfaces in the violation. A throw
 * refuses with the message of the error.
 */
export type HostInvariantResult = void | null | true | string | { message: string; suggestion?: ApplyInput['mutation'] } | Array<string | { message: string; suggestion?: ApplyInput['mutation'] }>;

/**
 * Functions the engine calls back while it decides or governs. They are synchronous: a returned
 * promise is not awaited and is refused as a wrong answer. They cannot call the engine nor change a
 * `Context` while they run: both throw `REENTRANT_CALL`, except a change to the very `Context` under
 * decision, which the runtime refuses with an error of its own (no stable `code`).
 */
export interface EngineHooks {
  /** Functions of the `call` condition, by `func` name. */
  conditions?: Record<string, HostCondition>;
  overrides?: HostOverride[];
  /** Run by `apply` and `applyTemplate` when `invariants` lists `{ kind: 'custom', name }`. */
  invariants?: Record<string, (proposal: HostProposal) => HostInvariantResult>;
  /**
   * Where `apply` and `applyTemplate` write each audit record (the JSON of `audit`), synchronously.
   * A throw is a failure of the sink and applies the failure mode. The record is still returned.
   */
  auditSink?: (record: Record<string, unknown>) => void;
  /**
   * Masks a record before it is hashed and written: takes it and returns it changed. A throw, or an
   * answer that is not a record, refuses the change in any failure mode, never writes it unmasked.
   * Runs after `audit.redact`.
   */
  auditRedact?: (record: Record<string, unknown>) => Record<string, unknown>;
  /** Called with a record that a full retry queue dropped. */
  onAuditDrop?: (record: Record<string, unknown>) => void;
  auditPolicy?: AuditPolicy;
}

export declare class Context {
  constructor(init?: { grants?: Grant[]; tuples?: unknown[]; env?: Record<string, unknown>; now?: number | bigint | null; limits?: QueryLimits });
  setGrants(grants: Grant[]): void;
  addGrant(grant: Grant): void;
  removeGrant(id: string): boolean;
  grants(): Grant[];
  readonly size: number;
  addTuple(tuple: unknown): boolean;
  removeTuple(tuple: unknown): boolean;
  setEnv(env: Record<string, unknown>): void;
  loadCapabilities(set: CapabilitySet): Subject;
  /**
   * The instant, in ms UTC, that validity windows and queries judge at. `null` or `undefined` clears
   * it: without it the engine fails closed. Anything that is not a non-negative integer up to 2^53
   * (`NaN`, `Infinity`, a text, a negative) throws `INVALID_ARGUMENT` and leaves the instant as it was.
   * The instant persists: a long-lived `Context` must be given `setNow` on every request, or pass
   * `now` to each call below, which wins over this one.
   */
  setNow(now: number | bigint | null): void;
  /** Ceilings of the reverse queries; `null` restores the defaults. */
  setLimits(limits: QueryLimits | null): void;
}

/**
 * Every method that decides or lists takes an optional trailing `now` (ms UTC) for that call, which
 * wins over the `Context` instant. The system clock is never used by these: without any `now` the
 * engine fails closed on windows.
 */
export declare class Engine<P extends string = string> {
  /** `EngineSpec` da Strig: catálogo, papéis, relações, estratégia, overrides. */
  constructor(spec: unknown, hooks?: EngineHooks);
  decide(context: Context, request: DecisionRequest<P>, now?: number | bigint): Decision;
  check(context: Context, request: DecisionRequest<P>, now?: number | bigint): boolean;
  /** A decisão com o rastro: overrides, destino de cada grant e árvore das condições. */
  explain(context: Context, request: DecisionRequest<P>, now?: number | bigint): Explanation;
  /**
   * The fields of the request's resource the subject may use for its permission. The `field` of the
   * request, if any, is ignored. A condition that cannot be evaluated never opens a field.
   */
  allowedFields(context: Context, request: DecisionRequest<P>, now?: number | bigint): FieldSet;
  /**
   * For a denied request, the changes that would allow it, smallest and most specific first, each one
   * verified by deciding again on a copy. `null` when the request is already allowed. `options` narrow
   * the limits of the context for the call.
   */
  whyNot(context: Context, request: DecisionRequest<P>, now?: number | bigint, options?: WhyNotOptions): Remedies | null;
  /** `allowedFields` with the grants that gave and the ones that took away each field. */
  explainFields(context: Context, request: DecisionRequest<P>, now?: number | bigint): FieldExplanation;
  /**
   * `check` of every request in one crossing of the boundary, against one `Context` and one instant:
   * one boolean per request, in order. A request that cannot be read throws and decides none.
   */
  checkMany(context: Context, requests: readonly DecisionRequest<P>[], now?: number | bigint): boolean[];
  /** `explain` of every request in one crossing, in order. */
  explainMany(context: Context, requests: readonly DecisionRequest<P>[], now?: number | bigint): Explanation[];
  capabilities(context: Context, subject: Subject, scope: Resource, now?: number | bigint): CapabilitySet;
  validateGrant(grant: Grant): void;
  catalog(): unknown;
  apply(input: ApplyInput): ApplyResult;
  /** The template's changes as plain data, with no link to the template; nothing is applied. */
  materialize(input: MaterializeInput): Materialized;
  /** Materializes and applies the batch through the governance, in `depends_on` order. */
  applyTemplate(input: ApplyTemplateInput): ApplyTemplateResult;
  /** Applies the change at once, or leaves it as a pending request when `approval` asks for approval of its kind. Nothing is stored: keep `request` (see `Approvals` in `@the-hades-organization/strig/approvals`). */
  /** What `mutation` would do to access, before applying it: who gains, who loses, what cannot be settled. */
  impact(input: ApplyInput): ImpactResult;
  /** The impact of a pending request as proposed and as it would be now, for the approver. */
  reviewImpact(input: ReviewImpactInput): ReviewImpactResult;
  propose(input: ProposeInput): ProposeResult;
  /** Approves or refuses `request`. The author never decides their own request; an approval judges the change again over `current`. */
  resolve(input: ResolveInput): ResolveResult;
  /** Requests, approves, refuses, revokes or reviews a temporary elevation, break-glass included. Nothing is stored: see `Elevations` in `@the-hades-organization/strig/approvals`. */
  elevate(input: ElevateInput): ElevateResult;
  /** Opens, decides, closes or reports an access recertification campaign. Nothing is stored: see `Recertifications` in `@the-hades-organization/strig/approvals`. */
  recertify(input: RecertifyInput): RecertifyResult;
  /** Closes the requests whose expiry has come and returns them. */
  expire(input: ExpireInput): ExpireResult;
  /** Tries to write the records waiting in the retry queue now and returns its counters. */
  flushAudit(): AuditStats;
  auditStats(): AuditStats;
  /** The filter of what `subject` holds `permission` on, among `kind` resources. */
  list(context: Context, subject: Subject, permission: PermissionArg<P>, kind: string, options?: ListOptions, now?: number | bigint): ListResult;
  /** Parties named by an allow grant of the permission, anywhere. */
  whoCan(context: Context, permission: PermissionArg<P>, now?: number | bigint): SubjectRef[];
  /** Who holds the permission on the resource, and how. */
  whoCanOn(context: Context, permission: PermissionArg<P>, resource: Resource, now?: number | bigint): WhoCanOnResult;
  /** What each party can do on the resource. */
  accessOf(context: Context, resource: Resource, now?: number | bigint): Array<{ subject: SubjectRef; permissions: string[] }>;
  /** The decision for a named party; `subjects` are those the resolver knows. An unknown one throws `UNKNOWN_SUBJECT`. */
  checkFor(context: Context, subject: SubjectRef, permission: PermissionArg<P>, resource: Resource, subjects: Subject[], now?: number | bigint): CheckForResult;
}

/**
 * In-memory exclusive ownership of resources, with priority and preemption. `acquire` checks the
 * permissions at the `now` of the call, and so does `renew`: a holder who lost the permission cannot
 * keep the resource by renewing. `release` checks nothing, because giving the resource up is always
 * safe; the caller vouches for `holder`, so it must come from the server's own identity, never from a
 * client. Revoking a grant does not drop a lease that exists; it stops its renewal. A bad `now`
 * throws `INVALID_ARGUMENT`; the system clock is used only when `now` is omitted.
 */
export declare class Exclusive {
  constructor(options?: ExclusiveOptions);
  /** Checks that the catalog declares both permissions; throws `EXCLUSIVE_UNKNOWN_PERMISSION`. */
  validate(engine: Engine): void;
  acquire(
    engine: Engine,
    context: Context,
    subject: Subject,
    resource: Resource,
    terms: { priority: number; ttlMs: number },
    now?: number | bigint,
  ): Acquisition;
  holder(resource: ObjectRef, now?: number | bigint): Lease | null;
  release(resource: ObjectRef, holder: ObjectRef, now?: number | bigint): Lease;
  /** Extends the lease of `subject` to `now + ttlMs`, keeping its priority. Throws `EXCLUSIVE_DENIED` when the hold permission no longer holds at `now`. */
  renew(
    engine: Engine,
    context: Context,
    subject: Subject,
    resource: Resource,
    ttlMs: number,
    now?: number | bigint,
  ): Lease;
  /** Removes and returns the leases that ran out. */
  expire(now?: number | bigint): Lease[];
}

/** The syntaxes of the policy language. A source declares its own on the first line: `language rules`. */
export type PolicyLanguage = 'blocks' | 'rules' | 'actors';

/** Codes of the policy language, on top of `INVALID_ARGUMENT` (wrong type of argument, unknown language) and `INVALID_INPUT` (a policy object of the wrong shape). */
export type DslErrorCode =
  | 'DSL_PARSE'
  | 'DSL_VALIDATE'
  | 'DSL_CONFLICT'
  | 'DSL_UNREPRESENTABLE'
  | 'DSL_UNSUPPORTED'
  /** A size or count limit: too many sources, a source or the project too large, a directory with too many files. */
  | 'DSL_LIMIT'
  /** `loadProject` got the same `path` twice. */
  | 'DSL_DUPLICATE_SOURCE'
  /** `loadProjectDir` could not read the directory or a file, or found a `.strig` that is a link. The message carries the path and the system's error: do not pass it on to a remote client. */
  | 'DSL_IO';

/** Where the other side of a conflict lives. */
export interface DslPlace {
  file: string;
  line: number;
  column: number;
}

/** One problem, positioned. `file`, `line` and `column` are `null` for a policy that did not come from text. */
export interface DslDiagnostic {
  file: string | null;
  line: number | null;
  column: number | null;
  message: string;
  hint: string | null;
  /** Present on `DSL_CONFLICT`: the declaration this one clashes with. */
  related?: DslPlace;
}

/** What every language function throws: a stable `code` and at most 100 diagnostics, then one more saying "and N more errors not shown" when some were left out. */
export interface DslError extends Error {
  code: ErrorCode;
  diagnostics: DslDiagnostic[];
}

/** A policy in its canonical JSON: the same whatever the syntax it was written in. Comments are in `notes`. */
export interface PolicyPermission {
  key: string;
  targets: string[];
  label?: string;
  description?: string;
  impliedBy?: string[];
  /**
   * Fields a grant of this permission may be restricted to. Empty: the permission is not
   * field-aware. When declared, a grant naming another field is refused and a request for one is
   * denied.
   */
  fields?: string[];
  dependsOn?: string[];
  nonDelegable?: boolean;
  managementOnly?: boolean;
  overrideOnly?: boolean;
  meta?: Record<string, unknown>;
}

/** Static separation of duties: nobody holds two `members` in the same scope. */
export interface MutuallyExclusive {
  name: string;
  of: 'roles' | 'permissions';
  members: string[];
  /** Kind of anchor inside which two members clash; absent is global. */
  anchor?: string;
}

/**
 * Dynamic separation of duties: whoever did a `first` action on a resource does not do a `then` action on it.
 * The history is an attribute of the resource (or of `env`) holding `"<permission>:<actor>"` entries, with
 * `"|role,role"` appended when `distinctRoles` is on.
 */
export interface ConflictingActions {
  name: string;
  first: string[];
  then: string[];
  /** Attribute that carries the history; default `history`. */
  history?: string;
  /** Also refuses someone who holds a role the author of `first` acted with. */
  distinctRoles?: boolean;
}

export interface PolicyCatalog {
  targetKinds: string[];
  broadTargets: string[];
  permissions: PolicyPermission[];
  mutuallyExclusive?: MutuallyExclusive[];
  conflictingActions?: ConflictingActions[];
}

export type PolicyStrategy = 'most_specific' | 'deny_overrides' | 'permit_overrides' | 'first_applicable';

export interface PolicyDocument {
  catalog: PolicyCatalog;
  roles?: unknown[];
  relations?: unknown[];
  strategy: PolicyStrategy;
  overrides?: unknown[];
  maxRelationDepth?: number;
  subjects?: unknown[];
  grants?: unknown[];
  tuples?: unknown[];
  invariants?: unknown[];
  notes?: PolicyNote[];
}

export interface PolicyNote {
  text: string;
  anchor: { element: string; placement: 'before' | 'after' | 'inline' | 'inside' };
  origin: { file: string; language: PolicyLanguage; line: number; column: number; field?: string };
}

export interface PolicySource {
  path: string;
  text: string;
}

/** A fixture of a test file: more subjects, grants and tuples than the policy has, and the base environment. Written inline; a path is only read by `strig test`. */
export interface PolicyTestFixture {
  subjects?: unknown[];
  grants?: unknown[];
  tuples?: unknown[];
  env?: Record<string, unknown>;
}

/** A test file as `strig test` reads it from `*.strig-test.json`. A subject is `"kind:id"` (declared in the policy or the fixture), `"anonymous"` or the subject object; a resource is `"global"`, `"kind:id"` or the resource object. */
export interface PolicyTestFile {
  name?: string;
  fixture?: PolicyTestFixture;
  cases: PolicyTestCase[];
}

export type PolicyTestCase =
  | {
      kind: 'check';
      name?: string;
      subject: string | object;
      permission: string;
      resource: string | object;
      env?: Record<string, unknown>;
      /** Milliseconds since the Unix epoch. */
      now?: number;
      expect: 'allow' | 'deny';
      reason?: 'override' | 'grant' | 'no_applicable_grant' | 'unknown_permission' | 'missing_prerequisite';
      /** The id of the grant that must decide. */
      grant?: string;
    }
  | {
      kind: 'mutation';
      name?: string;
      actor: string | object;
      /** `{ add: grant }`, `{ remove: { id } }`, `{ assign_role: { subject, role } }` or `{ revoke_role: { subject, role } }`. */
      mutation: object;
      now?: number;
      expect: 'accepted' | 'refused';
      /** For a refusal: an invariant that must be among the ones that refuse. */
      invariant?: string;
    };

/** `passed`: the answer is the expected one. `failed`: it differs. `errored`: the case could not be judged (unknown subject, a permission outside the catalog, a bad fixture): the test is wrong, not the policy. */
export type PolicyTestOutcome = 'passed' | 'failed' | 'errored';

export interface PolicyTestResult {
  /** `tests[i]` for the i-th file passed to `runTests`. */
  file: string;
  name: string;
  outcome: PolicyTestOutcome;
  expected: string;
  actual: string;
  /** For a failed `check`: the grants considered and what became of each. */
  trace?: string[];
  /** For a failed `check`: the full explanation of the decision. */
  explanation?: unknown;
}

export interface PolicyTestReport {
  results: PolicyTestResult[];
}

/** What decided a question on one side of a diff. */
export interface PolicyDiffResponsible {
  effect: 'allow' | 'deny';
  reason: 'override' | 'grant' | 'no_applicable_grant' | 'unknown_permission' | 'missing_prerequisite';
  /** The grant that decided, for a `grant` reason. */
  grant?: string;
  /** The override that decided, for an `override` reason. */
  override?: string;
  /** Where the grant is written (`file:line:column`), when known. */
  at?: string;
}

/** A question whose answer differs between the two versions. */
export interface PolicyDecisionChange {
  /** `kind:id`, or `anonymous`. */
  subject: string;
  permission: string;
  /** `global`, `kind:id`, or `kind:id in kind:id` for a path. */
  resource: string;
  /** `widened`: deny became allow. `narrowed`: allow became deny. */
  change: 'widened' | 'narrowed';
  before: PolicyDiffResponsible;
  after: PolicyDiffResponsible;
}

/** The questions a diff asked. */
export interface PolicyDiffUniverse {
  subjects: number;
  permissions: number;
  resources: number;
  questions: number;
  /** True when subjects or resources were derived from the policies, not given. */
  derived: boolean;
  /** True when a limit stopped the diff early: no change found is not proof there is none. */
  partial: boolean;
}

export interface PolicyDiff {
  /** Ordered by subject, permission and resource. */
  changes: PolicyDecisionChange[];
  universe: PolicyDiffUniverse;
}

/** What a diff asks about. Every list is optional: what is left out is derived from the policies. */
export interface PolicyDiffFixture extends PolicyTestFixture {
  /** `global`, `kind:id`, or the resource object. */
  resources?: unknown[];
  /** Permissions to ask about; by default every one of the two catalogs. */
  permissions?: string[];
}

export interface PolicyDiffOptions {
  /** Subjects, resources, permissions, grants, tuples and env every question is asked with, as in a test fixture; an object or its JSON text. Left out, they are derived from the policies. */
  fixture?: PolicyDiffFixture | string;
  /** Most subjects asked about. */
  maxSubjects?: number;
  /** Most questions asked. */
  maxDecisions?: number;
}

export interface PolicyLintFinding {
  /** Stable code, such as `L001`. */
  code: string;
  /** Stable name, such as `shadowed-grant`. */
  name: string;
  severity: 'info' | 'warning' | 'error';
  message: string;
  hint: string;
  /** The id of the grant, role, permission or field the finding is about. */
  element: string;
  file?: string;
  line?: number;
  column?: number;
}

export interface PolicyLintOptions {
  /** Codes (`L004`) or names (`unused-role`) to leave out. */
  ignore?: string[];
}

export interface PolicyLanguageApi {
  /** Reads a source in the syntax it declares and validates it. `file` names it in the positions. Throws `DSL_PARSE` or `DSL_VALIDATE`. */
  compile(text: string, options?: { file?: string }): PolicyDocument;
  /** Writes a policy as text in `language`, comments included. Throws `DSL_UNREPRESENTABLE` when the syntax cannot say it. */
  print(policy: PolicyDocument, language: PolicyLanguage): string;
  /** Reads `text` in whatever syntax it declares and writes it in `language`. */
  convert(text: string, language: PolicyLanguage): string;
  /** Rewrites a source in the canonical layout of the syntax it declares, comments kept. Formatting the result again changes nothing. Throws `DSL_PARSE` or `DSL_VALIDATE` with positions when the source does not compile. */
  format(text: string, options?: { file?: string }): string;
  /** Whether a source is already in the canonical layout. Throws what `format` throws. */
  isFormatted(text: string, options?: { file?: string }): boolean;
  /** Merges sources, each in its own syntax, into one policy. Throws `DSL_CONFLICT` with both positions when two declare the same thing, `DSL_DUPLICATE_SOURCE` for a repeated `path` and `DSL_LIMIT` past the size and count limits. */
  loadProject(sources: PolicySource[]): PolicyDocument;
  /** Runs test files (objects, or the JSON text of each) against a policy, with the runner `strig test` uses. No IO: a `fixture` given as a path makes its cases error. A file that is not a test file throws `INVALID_INPUT`; an invalid policy throws `DSL_VALIDATE`. A case that fails is in the report, never thrown. */
  runTests(policy: PolicyDocument, tests: (PolicyTestFile | string)[]): PolicyTestReport;
  /** The decisions that change between two versions of a policy, each with the grant or override responsible on both sides. No IO: a `fixture` is an object or JSON text. Throws `INVALID_INPUT` for a bad fixture and `DSL_VALIDATE` for an invalid policy. */
  diff(before: PolicyDocument, after: PolicyDocument, options?: PolicyDiffOptions): PolicyDiff;
  /** Static findings about a policy: shadowed grants, unreachable denies, unused roles and more. A document carries no source positions, so a finding names its element by id. */
  lint(policy: PolicyDocument, options?: PolicyLintOptions): PolicyLintFinding[];
}

export interface NativePolicyLanguageApi extends PolicyLanguageApi {
  /** Reads every `.strig` file of a directory as a project. Only the native module has it: the WebAssembly build has no IO. A `.strig` that is a link is refused with `DSL_IO`, never skipped. `dir` itself is resolved following links, so it must come from a trusted source, never from external input. */
  loadProjectDir(dir: string): PolicyDocument;
}

export interface Strig extends PolicyLanguageApi {
  Engine: typeof Engine;
  Context: typeof Context;
  Exclusive: typeof Exclusive;
  auditEstimate(level: AuditLevel, records: number): number;
  /**
   * Checks `forensic` records in the order they were written, against anchors known from outside
   * (`docs/audit-format.md`). Never throws for a bad chain: it answers `{ ok: false, code }`.
   */
  verifyAuditChain(records: Record<string, unknown>[], anchors?: ChainAnchors): ChainVerification;
  /** Checks a Merkle inclusion proof (`docs/audit-format.md`). Never throws for a bad proof: it answers `{ ok: false, code }`. */
  verifyMerkleInclusion(input: MerkleInclusionInput): MerkleVerification;
  /** Checks that a later tree head extends an earlier one. Never throws for a bad proof. */
  verifyMerkleConsistency(input: MerkleConsistencyInput): MerkleVerification;
  /** Verifies an RFC 3161 time stamp of a chain head against the roots you trust, without network. */
  verifyTimestamp(input: TimestampInput): TimestampVerification;
  backend: 'native' | 'wasm';
}

export interface NativeStrig extends Strig, NativePolicyLanguageApi {
  backend: 'native';
}

export function load(options: { backend: 'native' }): Promise<NativeStrig>;
export function load(options?: { backend?: 'auto' | 'native' | 'wasm'; wasm?: unknown }): Promise<Strig>;
