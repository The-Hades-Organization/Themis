//! The JSON bodies of the routes, shared by the server and the client.

use serde::{Deserialize, Serialize};
use strig::{
    AccessFilter, AccessVia, Anchor, Attributes, Condition, Decision, Expr, FilterResidual, FilterShape, ObjectRef,
    Resource, Revision, Subject, SubjectRef, TargetSelector,
};

use crate::error::{ApiError, ErrorCode};

fn is_empty(env: &Attributes) -> bool {
    env.is_empty()
}

/// One question: can `subject` `permission` on `resource`?
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRequest {
    pub subject: Subject,
    pub permission: String,
    pub resource: Resource,
    /// Environment attributes for ABAC conditions. The server overwrites `now` with its own clock.
    #[serde(default, skip_serializing_if = "is_empty")]
    pub env: Attributes,
    /// The instant the caller believes it is, for the audit trail. The decision ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<u64>,
    /// Answer only from data at this revision or later; otherwise 503 `revision_not_reached` (or
    /// `revision_mismatch`). The `x-strig-min-revision` header means the same on every route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_revision: Option<Revision>,
}

impl CheckRequest {
    pub fn new(subject: Subject, permission: impl Into<String>, resource: Resource) -> Self {
        Self {
            subject,
            permission: permission.into(),
            resource,
            env: Attributes::new(),
            at: None,
            min_revision: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckResponse {
    pub decision: Decision,
    /// The instant of the server clock the decision was made at (milliseconds since the epoch).
    pub evaluated_at: u64,
    /// Echo of the request's `at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<u64>,
    /// The revision of the data the decision was made from, when the source tracks one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<Revision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchRequest {
    pub checks: Vec<CheckRequest>,
    /// Answer only from data at this revision or later; otherwise 503 `revision_not_reached` (or
    /// `revision_mismatch`). The `x-strig-min-revision` header means the same on every route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_revision: Option<Revision>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchResponse {
    /// One answer per check, in the order of the request.
    pub results: Vec<CheckResponse>,
    /// The revision of the data the answers were made from, when the source tracks one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<Revision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListRequest {
    pub subject: Subject,
    pub permission: String,
    /// The kind of resource to list (`document`).
    pub kind: String,
    /// Steps of the resource path from the most specific to the broadest, starting with `kind`.
    /// Defaults to `[kind]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<Vec<String>>,
    /// Candidate resources to settle into `ids`. Without them `ids` is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<Resource>>,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub env: Attributes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListResponse {
    pub evaluated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<u64>,
    pub kind: String,
    pub permission: String,
    /// Whether `shape` alone settles the listing, with nothing left in `residual`.
    pub exact: bool,
    pub shape: ShapeDto,
    /// What only the resource can settle. Never read it as an allow.
    pub residual: Vec<ResidualDto>,
    pub warnings: Vec<String>,
    /// Ids among the candidate `resources` that the subject reaches, with the undecided ones
    /// settled by a real check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WhoRequest {
    pub permission: String,
    /// With a resource: who holds the permission on it (`who_can_on`). Without: who is named by
    /// an allow grant anywhere (`who_can`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub env: Attributes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhoResponse {
    pub evaluated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<u64>,
    pub permission: String,
    pub entries: Vec<WhoEntry>,
    /// Pairs of parties that are each allowed but denied when one subject is both.
    pub except: Vec<WhoExcept>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhoEntry {
    pub subject: SubjectDto,
    /// How the party holds it. Absent for `who_can`, which evaluates nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<ViaDto>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhoExcept {
    pub allowed: SubjectDto,
    pub with: SubjectDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRequest {
    pub resource: Resource,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub env: Attributes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessResponse {
    pub evaluated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<u64>,
    pub parties: Vec<PartyDto>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PartyDto {
    pub subject: SubjectDto,
    pub permissions: Vec<String>,
}

/// A party named by a grant or a tuple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SubjectDto {
    User { id: String },
    Object { kind: String, id: String },
    Role { id: String },
    Principal { name: String },
    Userset { object: ObjectRef, relation: String },
    Wildcard { kind: String },
    Anyone,
}

/// How a party holds a permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ViaDto {
    Override {
        name: String,
    },
    Grant {
        grant_id: String,
    },
    Role {
        grant_id: String,
        role: String,
    },
    InheritedRole {
        grant_id: String,
        role: String,
        from: String,
    },
    Relation {
        grant_id: String,
        relation: String,
        object: ObjectRef,
    },
    Nothing,
}

/// The reach of a listing in its simplest form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ShapeDto {
    Nothing,
    /// Every resource of the kind except `except`.
    Kind {
        except: Vec<String>,
    },
    Ids {
        ids: Vec<String>,
    },
    /// Everything inside any of these steps of the path.
    Within {
        anchors: Vec<Anchor>,
    },
    Compound {
        expr: ExprDto,
    },
}

/// A structural condition over a resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ExprDto {
    True,
    False,
    Within {
        anchor: Anchor,
    },
    OnPath {
        selector: TargetSelector,
    },
    AnchorIn {
        kind: String,
        ids: Vec<String>,
    },
    AttrEq {
        attr: String,
        value: String,
    },
    /// Index into the response's `residual`.
    Residual {
        index: usize,
    },
    Not {
        expr: Box<ExprDto>,
    },
    And {
        items: Vec<ExprDto>,
    },
    Or {
        items: Vec<ExprDto>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResidualDto {
    Condition { grant_id: String, condition: Condition },
    Override { name: String },
    Strategy { name: String },
    OutsideLayout { grant_ids: Vec<String> },
}

/// The shapes below come from `#[non_exhaustive]` enums of the engine. A variant this crate does
/// not know yet becomes an internal error, never a guess that could read as an allow.
fn unsupported() -> ApiError {
    tracing::error!("the engine returned a variant this server does not know how to serialize");
    ApiError::new(ErrorCode::Internal)
}

pub(crate) fn subject_dto(subject: &SubjectRef) -> Result<SubjectDto, ApiError> {
    Ok(match subject {
        SubjectRef::User { id } => SubjectDto::User { id: id.clone() },
        SubjectRef::Object { kind, id } => SubjectDto::Object {
            kind: kind.clone(),
            id: id.clone(),
        },
        SubjectRef::Role { id } => SubjectDto::Role { id: id.clone() },
        SubjectRef::Principal { name } => SubjectDto::Principal { name: name.clone() },
        SubjectRef::Userset { object, relation } => SubjectDto::Userset {
            object: object.clone(),
            relation: relation.clone(),
        },
        SubjectRef::Wildcard { kind } => SubjectDto::Wildcard { kind: kind.clone() },
        SubjectRef::Anyone => SubjectDto::Anyone,
        _ => return Err(unsupported()),
    })
}

pub(crate) fn via_dto(via: &AccessVia) -> Result<ViaDto, ApiError> {
    Ok(match via {
        AccessVia::Override { name } => ViaDto::Override { name: name.clone() },
        AccessVia::Grant { grant_id } => ViaDto::Grant {
            grant_id: grant_id.clone(),
        },
        AccessVia::Role { grant_id, role } => ViaDto::Role {
            grant_id: grant_id.clone(),
            role: role.clone(),
        },
        AccessVia::InheritedRole { grant_id, role, from } => ViaDto::InheritedRole {
            grant_id: grant_id.clone(),
            role: role.clone(),
            from: from.clone(),
        },
        AccessVia::Relation {
            grant_id,
            relation,
            object,
        } => ViaDto::Relation {
            grant_id: grant_id.clone(),
            relation: relation.clone(),
            object: object.clone(),
        },
        AccessVia::Nothing => ViaDto::Nothing,
        _ => return Err(unsupported()),
    })
}

pub(crate) fn expr_dto(expr: &Expr) -> Result<ExprDto, ApiError> {
    let many = |items: &[Expr]| items.iter().map(expr_dto).collect::<Result<Vec<_>, _>>();
    Ok(match expr {
        Expr::True => ExprDto::True,
        Expr::False => ExprDto::False,
        Expr::Within(anchor) => ExprDto::Within { anchor: anchor.clone() },
        Expr::OnPath(selector) => ExprDto::OnPath {
            selector: selector.clone(),
        },
        Expr::AnchorIn { kind, ids } => ExprDto::AnchorIn {
            kind: kind.clone(),
            ids: ids.iter().cloned().collect(),
        },
        Expr::AttrEq { attr, value } => ExprDto::AttrEq {
            attr: attr.clone(),
            value: value.clone(),
        },
        Expr::Residual(index) => ExprDto::Residual { index: *index },
        Expr::Not(inner) => ExprDto::Not {
            expr: Box::new(expr_dto(inner)?),
        },
        Expr::And(items) => ExprDto::And { items: many(items)? },
        Expr::Or(items) => ExprDto::Or { items: many(items)? },
        _ => return Err(unsupported()),
    })
}

pub(crate) fn shape_dto(shape: &FilterShape) -> Result<ShapeDto, ApiError> {
    Ok(match shape {
        FilterShape::Nothing => ShapeDto::Nothing,
        FilterShape::Kind { except } => ShapeDto::Kind {
            except: except.iter().cloned().collect(),
        },
        FilterShape::Ids(ids) => ShapeDto::Ids {
            ids: ids.iter().cloned().collect(),
        },
        FilterShape::Within(anchors) => ShapeDto::Within {
            anchors: anchors.clone(),
        },
        FilterShape::Compound(expr) => ShapeDto::Compound { expr: expr_dto(expr)? },
        _ => return Err(unsupported()),
    })
}

pub(crate) fn residual_dto(residual: &FilterResidual) -> Result<ResidualDto, ApiError> {
    Ok(match residual {
        FilterResidual::Condition { grant_id, condition } => ResidualDto::Condition {
            grant_id: grant_id.clone(),
            condition: condition.clone(),
        },
        FilterResidual::Override { name } => ResidualDto::Override { name: name.clone() },
        FilterResidual::Strategy { name } => ResidualDto::Strategy { name: name.clone() },
        FilterResidual::OutsideLayout { grant_ids } => ResidualDto::OutsideLayout {
            grant_ids: grant_ids.clone(),
        },
        _ => return Err(unsupported()),
    })
}

/// The serializable form of a listing: `(exact, shape, residual, warnings)`.
pub(crate) fn filter_parts(
    filter: &AccessFilter,
    layout: &strig::PathLayout,
) -> Result<(bool, ShapeDto, Vec<ResidualDto>, Vec<String>), ApiError> {
    let residual = filter
        .residual_for(layout)
        .iter()
        .map(residual_dto)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        filter.is_exact(layout),
        shape_dto(&filter.shape(layout))?,
        residual,
        filter.warnings().to_vec(),
    ))
}
