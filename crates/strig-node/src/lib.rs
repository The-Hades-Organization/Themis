//! Bindings JavaScript da Strig.
//!
//! O núcleo ([`EngineHandle`], [`ContextData`]) recebe e devolve `serde_json::Value` e é o
//! mesmo nos dois alvos. `napi` gera o módulo nativo para Node e Bun; `wasm` gera o
//! WebAssembly para o navegador. O pacote npm em `js/` escolhe o alvo em tempo de execução.

/// `json!` com os nomes dos campos em camelCase: toda resposta ao JavaScript passa por aqui.
macro_rules! out {
    ($($json:tt)+) => {
        $crate::camel_keys(::serde_json::json!($($json)+))
    };
}

mod audit_proof;
#[cfg(any(feature = "napi", feature = "wasm", feature = "dsl", test))]
pub mod dsl;
mod error;
pub mod exclusive;
mod host;
mod query_json;

use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;
use strig::ChainError;
use strig::audit::{AuditLevel, AuditRecord, AuditStatus, FailMode, MemoryAuditLog, chain_head, verify_chain_anchored};
use strig::{
    ApprovalError, ApprovalPolicy, ApprovalRule, Approvals, Attributes, Campaign, CampaignSpec, CapabilitySet, Context,
    Elevated, ElevationPolicy, ElevationRequest, ElevationRule, Elevations, Engine, EngineSpec, Governance, Grant,
    ImpactOptions, ImpactSource, InMemorySubjects, InMemoryTuples, InvariantSpec, MemoryPendingStore,
    MemoryRecertStore, Mutation, PathLayout, PendingError, PendingRequest, PendingStore, Proposed, QueryContext,
    QueryLimits, RecertDecision, RecertError, RecertStore, Recertifications, Request, Resource, Review, RoleTemplate,
    Subject, Tuple,
};

#[cfg(feature = "timestamp")]
pub use audit_proof::verify_timestamp;
pub use audit_proof::{verify_merkle_consistency, verify_merkle_inclusion};
pub use error::{BindingError, BindingResult};
pub use exclusive::ExclusiveHandle;
pub use host::{AuditPolicy, HostCallbacks, HostFn, Redaction};
use query_json::{expr_json, parse_subject_ref, residual_json, shape_json, subject_ref_json, via_json};

#[cfg(feature = "napi")]
mod napi_binding;
#[cfg(feature = "wasm")]
mod wasm_binding;

/// N-API entrega todo número JavaScript como float; os campos inteiros (instantes em ms, limites)
/// só aceitam inteiro. Um float integral e seguro vira inteiro; o resto segue como veio e o serde recusa.
fn integral(value: Value) -> Value {
    match value {
        Value::Number(n) if !n.is_u64() && !n.is_i64() => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() <= MAX_SAFE_INT => {
                if f >= 0.0 {
                    Value::from(f as u64)
                } else {
                    Value::from(f as i64)
                }
            }
            _ => Value::Number(n),
        },
        Value::Array(items) => Value::Array(items.into_iter().map(integral).collect()),
        Value::Object(map) => Value::Object(map.into_iter().map(|(k, v)| (k, integral(v))).collect()),
        other => other,
    }
}

pub(crate) fn parse<T: for<'de> Deserialize<'de>>(what: &str, value: Value) -> BindingResult<T> {
    serde_json::from_value(integral(value)).map_err(|e| BindingError::invalid_input(what, e))
}

/// Chaves que guardam dados de quem chama: o que está abaixo delas sai como entrou.
const OPAQUE_KEYS: [&str; 5] = ["attrs", "meta", "env", "condition", "value"];

fn camel_case(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut upper = false;
    for c in key.chars() {
        if c == '_' && !out.is_empty() {
            upper = true;
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// A API JavaScript é toda em camelCase; o JSON do núcleo usa snake_case em alguns campos
/// (`grant_id`, `expires_at`). A conversão é só dos nomes dos campos: valores, rótulos (`kind`,
/// `type`) e o conteúdo de `OPAQUE_KEYS` ficam como estão.
fn camel_keys(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(camel_keys).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    if OPAQUE_KEYS.contains(&key.as_str()) {
                        (key, value)
                    } else {
                        (camel_case(&key), camel_keys(value))
                    }
                })
                .collect(),
        ),
        other => other,
    }
}

fn to_value<T: serde::Serialize>(value: &T) -> Value {
    // Os tipos da Strig só têm chaves de texto e números finitos: a serialização não falha.
    camel_keys(serde_json::to_value(value).expect("tipos da Strig sempre serializam"))
}

/// Largest integer a JavaScript number holds exactly.
const MAX_SAFE_INT: f64 = 9_007_199_254_740_991.0;

/// Milissegundos desde a época Unix, vindos de um número JavaScript: inteiro, finito e não negativo.
pub fn millis(what: &str, value: f64) -> BindingResult<u64> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > MAX_SAFE_INT {
        return Err(BindingError::invalid_argument(
            what,
            "esperado um inteiro não negativo em milissegundos",
        ));
    }
    // Inteiro, finito e dentro de 2^53: a conversão não perde valor.
    Ok(value as u64)
}

fn millis_value(what: &str, value: &Value) -> BindingResult<u64> {
    let number = value
        .as_f64()
        .ok_or_else(|| BindingError::invalid_argument(what, "esperado um número"))?;
    millis(what, number)
}

/// O instante de um argumento `now`: `None` quando falta (`undefined` ou `null`), e um erro
/// `INVALID_ARGUMENT` para qualquer valor que não seja um inteiro não negativo em milissegundos.
/// Nunca coage: texto, booleano, lista e vazio não viram 0.
pub fn now_arg(value: Option<Value>) -> BindingResult<Option<u64>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => millis_value("now", &value).map(Some),
    }
}

/// O relógio do sistema em milissegundos. Um relógio anterior a 1970 (ou fora do intervalo) é um
/// erro: nunca vira `0`, que reabriria as janelas vencidas.
pub fn clock_ms(time: std::time::SystemTime) -> BindingResult<u64> {
    let elapsed = time
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| BindingError::invalid_argument("now", "o relógio do sistema está antes de 1970"))?;
    let ms = u64::try_from(elapsed.as_millis())
        .map_err(|_| BindingError::invalid_argument("now", "o relógio do sistema está fora do intervalo"))?;
    millis("now", ms as f64)
}

fn count_value(what: &str, value: &Value) -> BindingResult<usize> {
    usize::try_from(millis_value(what, value)?).map_err(|e| BindingError::invalid_input(what, e))
}

/// Grants, tuplas, ambiente e instante de uma decisão, mantidos do lado Rust para não converter
/// a cada chamada. Sem `now`, o motor falha fechado: um allow com janela é ignorado e um deny com
/// janela vale.
#[derive(Default)]
pub struct ContextData {
    grants: Vec<Grant>,
    tuples: InMemoryTuples,
    env: Attributes,
    with_tuples: bool,
    now: Option<u64>,
    limits: Option<QueryLimits>,
}

impl ContextData {
    pub fn new(init: Option<Value>) -> BindingResult<Self> {
        let mut data = Self::default();
        let Some(init) = init else {
            return Ok(data);
        };
        let Value::Object(init) = init else {
            if init.is_null() {
                return Ok(data);
            }
            return Err(BindingError::invalid_input("context", "esperado um objeto"));
        };
        if let Some(grants) = init.get("grants") {
            data.set_grants(grants.clone())?;
        }
        if let Some(tuples) = init.get("tuples") {
            for tuple in parse::<Vec<Tuple>>("tuples", tuples.clone())? {
                data.tuples.insert(tuple);
            }
            data.with_tuples = true;
        }
        if let Some(env) = init.get("env") {
            data.set_env(env.clone())?;
        }
        if let Some(now) = init.get("now") {
            data.set_now(now.clone())?;
        }
        if let Some(limits) = init.get("limits") {
            data.set_limits(limits.clone())?;
        }
        Ok(data)
    }

    pub fn set_grants(&mut self, grants: Value) -> BindingResult<()> {
        host::forbid_reentry()?;
        self.grants = parse("grants", grants)?;
        Ok(())
    }

    pub fn add_grant(&mut self, grant: Value) -> BindingResult<()> {
        host::forbid_reentry()?;
        let grant: Grant = parse("grant", grant)?;
        self.grants.retain(|g| g.id != grant.id);
        self.grants.push(grant);
        Ok(())
    }

    pub fn remove_grant(&mut self, id: &str) -> BindingResult<bool> {
        host::forbid_reentry()?;
        let before = self.grants.len();
        self.grants.retain(|g| g.id != id);
        Ok(before != self.grants.len())
    }

    pub fn grants(&self) -> Value {
        to_value(&self.grants)
    }

    pub fn grant_count(&self) -> usize {
        self.grants.len()
    }

    pub fn add_tuple(&mut self, tuple: Value) -> BindingResult<bool> {
        host::forbid_reentry()?;
        self.with_tuples = true;
        Ok(self.tuples.insert(parse("tuple", tuple)?))
    }

    pub fn remove_tuple(&mut self, tuple: Value) -> BindingResult<bool> {
        host::forbid_reentry()?;
        Ok(self.tuples.remove(&parse("tuple", tuple)?))
    }

    pub fn set_env(&mut self, env: Value) -> BindingResult<()> {
        host::forbid_reentry()?;
        self.env = parse("env", env)?;
        Ok(())
    }

    /// Instante das decisões e das consultas, em milissegundos UTC. `null` o remove.
    pub fn set_now(&mut self, now: Value) -> BindingResult<()> {
        host::forbid_reentry()?;
        self.now = if now.is_null() {
            None
        } else {
            Some(millis_value("now", &now)?)
        };
        Ok(())
    }

    pub(crate) fn context(&self) -> Context<'_> {
        self.context_at(None)
    }

    pub fn now(&self) -> Option<u64> {
        self.now
    }

    /// Tetos das consultas reversas: `{ maxParties?, maxDecisions? }`. O que falta fica no padrão;
    /// `null` volta tudo ao padrão.
    pub fn set_limits(&mut self, limits: Value) -> BindingResult<()> {
        host::forbid_reentry()?;
        if limits.is_null() {
            self.limits = None;
            return Ok(());
        }
        let Value::Object(map) = limits else {
            return Err(BindingError::invalid_input("limits", "esperado um objeto"));
        };
        if let Some(unknown) = map
            .keys()
            .find(|k| !matches!(k.as_str(), "maxParties" | "maxDecisions"))
        {
            return Err(BindingError::invalid_input(
                "limits",
                format!("campo desconhecido: {unknown}"),
            ));
        }
        let mut out = QueryLimits::default();
        if let Some(parties) = map.get("maxParties") {
            out = out.with_max_parties(count_value("limits.maxParties", parties)?);
        }
        if let Some(decisions) = map.get("maxDecisions") {
            out = out.with_max_decisions(count_value("limits.maxDecisions", decisions)?);
        }
        self.limits = Some(out);
        Ok(())
    }

    /// Troca os grants pelos de um `CapabilitySet` recebido do servidor.
    pub fn load_capabilities(&mut self, set: Value) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let set: CapabilitySet = parse("capabilities", set)?;
        self.grants = set.grants;
        Ok(to_value(&set.subject))
    }

    /// O contexto de uma decisão no instante `now` da chamada; sem ele vale o do `Context`.
    pub(crate) fn context_at(&self, now: Option<u64>) -> Context<'_> {
        let mut ctx = Context::new(&self.grants).with_env(&self.env);
        if let Some(now) = now.or(self.now) {
            ctx = ctx.at(now);
        }
        if self.with_tuples {
            ctx = ctx.with_tuples(&self.tuples);
        }
        ctx
    }

    fn query_context(&self, now: Option<u64>) -> QueryContext<'_> {
        let mut ctx = QueryContext::new(&self.grants).with_env(&self.env);
        if let Some(now) = now.or(self.now) {
            ctx = ctx.at(now);
        }
        if let Some(limits) = self.limits {
            ctx = ctx.with_limits(limits);
        }
        if self.with_tuples {
            ctx = ctx.with_tuples(&self.tuples);
        }
        ctx
    }
}

#[derive(Deserialize)]
pub(crate) struct RequestInput {
    pub(crate) subject: Subject,
    pub(crate) permission: String,
    pub(crate) resource: Resource,
    /// The field the question is about; absent asks about the resource as a whole.
    #[serde(default)]
    pub(crate) field: Option<String>,
}

impl RequestInput {
    pub(crate) fn request(&self) -> Request<'_> {
        let request = Request::new(&self.subject, &self.permission, &self.resource);
        match &self.field {
            Some(field) => request.field(field),
            None => request,
        }
    }
}

#[cfg_attr(
    not(any(feature = "napi", feature = "wasm")),
    allow(dead_code, reason = "only the JavaScript bindings read requests from text")
)]
impl RequestInput {
    /// A request from the text the JavaScript wrapper made with `JSON.stringify`: every number is
    /// already a JSON integer or float, so no `integral` pass is needed.
    pub(crate) fn from_json(text: &str) -> BindingResult<Self> {
        serde_json::from_str(text).map_err(|e| BindingError::invalid_input("request", e))
    }

    pub(crate) fn many_from_json(text: &str) -> BindingResult<Vec<Self>> {
        serde_json::from_str(text).map_err(|e| BindingError::invalid_input("requests", e))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditInput {
    level: AuditLevel,
    #[serde(default)]
    prev_hash: Option<String>,
    /// Modo de falha desta chamada; vence o da permissão e o padrão do motor.
    #[serde(default)]
    fail_mode: Option<FailMode>,
    #[serde(default)]
    redact: Option<Redaction>,
}

/// Os registros que o auditor aceitou numa chamada, com o destino de cada um.
#[derive(Default)]
struct Capture {
    items: std::sync::Mutex<Vec<(AuditRecord, AuditStatus)>>,
}

impl Capture {
    fn push(&self, record: &AuditRecord, status: AuditStatus) {
        self.items
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((record.clone(), status));
    }

    fn take(&self) -> Vec<(AuditRecord, AuditStatus)> {
        std::mem::take(&mut *self.items.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

/// O pior destino entre os registros: `dropped` sobre `pending` sobre `written`; `None` sem registro.
fn worst_status(items: &[(AuditRecord, AuditStatus)]) -> Option<AuditStatus> {
    let rank = |s: &AuditStatus| match s {
        AuditStatus::Written => 0,
        AuditStatus::Pending => 1,
        AuditStatus::Dropped => 2,
    };
    items.iter().map(|(_, s)| *s).max_by_key(rank)
}

/// Tetos de uma consulta de impacto: `{ maxParties?, maxDecisions? }`; o que falta fica no padrão.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImpactLimits {
    max_parties: Option<usize>,
    max_decisions: Option<usize>,
}

/// O que o impacto de uma mudança se calcula sobre: de onde vêm sujeitos e recursos, o ambiente e os tetos.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImpactInput {
    #[serde(default = "ImpactSource::derived")]
    source: ImpactSource,
    #[serde(default)]
    env: Attributes,
    #[serde(default)]
    limits: ImpactLimits,
}

impl ImpactInput {
    fn options<'a>(&'a self, tuples: Option<&'a InMemoryTuples>, now: u64) -> ImpactOptions<'a> {
        let mut limits = QueryLimits::default();
        if let Some(parties) = self.limits.max_parties {
            limits = limits.with_max_parties(parties);
        }
        if let Some(decisions) = self.limits.max_decisions {
            limits = limits.with_max_decisions(decisions);
        }
        let options = ImpactOptions::new(self.source.clone())
            .with_env(&self.env)
            .with_limits(limits)
            .at(now);
        match tuples {
            Some(tuples) => options.with_tuples(tuples),
            None => options,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplyInput {
    actor: Subject,
    current: Vec<Grant>,
    mutation: Mutation,
    #[serde(default)]
    invariants: Vec<InvariantSpec>,
    #[serde(default)]
    tuples: Option<Vec<Tuple>>,
    #[serde(default)]
    audit: Option<AuditInput>,
    #[serde(default)]
    meta: Attributes,
    #[serde(default)]
    now: Option<Value>,
    #[serde(default)]
    impact: Option<ImpactInput>,
}

/// Entrada comum do fluxo de pedido pendente: o estado contra o qual se julga, as invariantes, a
/// política de aprovação e a auditoria, como em `apply`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FlowInput {
    #[serde(default)]
    current: Vec<Grant>,
    #[serde(default)]
    invariants: Vec<InvariantSpec>,
    #[serde(default)]
    tuples: Option<Vec<Tuple>>,
    #[serde(default)]
    audit: Option<AuditInput>,
    #[serde(default)]
    meta: Attributes,
    #[serde(default)]
    now: Option<Value>,
    #[serde(default)]
    approval: Vec<ApprovalRule>,
    #[serde(default)]
    impact: Option<ImpactInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProposeInput {
    actor: Subject,
    mutation: Mutation,
    id: String,
    #[serde(default)]
    expires_at: Option<Value>,
    #[serde(flatten)]
    flow: FlowInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolveInput {
    request: PendingRequest,
    approver: Subject,
    /// `approve` ou `reject`.
    decision: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(flatten)]
    flow: FlowInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ElevateInput {
    /// `request`, `approve`, `reject`, `revoke` ou `close_review`.
    op: String,
    /// A política: o que se eleva e como.
    #[serde(default)]
    elevation: Vec<ElevationRule>,
    /// O pedido de elevação (`op: 'request'`).
    #[serde(default)]
    elevation_request: Option<ElevationRequest>,
    /// O pedido guardado (as demais operações).
    #[serde(default)]
    request: Option<PendingRequest>,
    /// Quem aprova, recusa, revoga ou revisa.
    #[serde(default)]
    by: Option<Subject>,
    /// O motivo de uma recusa ou de uma revogação, ou a nota do fechamento da revisão.
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    expires_at: Option<Value>,
    #[serde(flatten)]
    flow: FlowInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecertInput {
    /// `open`, `decide`, `close`, `report` ou `list`.
    op: String,
    /// A campanha a abrir (`op: 'open'`).
    #[serde(default)]
    campaign_spec: Option<CampaignSpec>,
    /// A campanha guardada (`decide`, `close`, `report`).
    #[serde(default)]
    campaign: Option<Campaign>,
    /// As campanhas guardadas (`list`).
    #[serde(default)]
    campaigns: Vec<Campaign>,
    /// Quem tem papéis a certificar (`op: 'open'`).
    #[serde(default)]
    subjects: Vec<Subject>,
    /// Quem abre, decide ou fecha.
    #[serde(default)]
    by: Option<Subject>,
    #[serde(default)]
    item: Option<String>,
    #[serde(default)]
    decision: Option<RecertDecision>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(flatten)]
    flow: FlowInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReviewImpactInput {
    request: PendingRequest,
    #[serde(flatten)]
    flow: FlowInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpireInput {
    requests: Vec<PendingRequest>,
    #[serde(flatten)]
    flow: FlowInput,
}

/// O instante, a governança, a captura de auditoria, a política e as tuplas de um passo do fluxo.
type FlowParts = (u64, Governance, Arc<Capture>, ApprovalPolicy, Option<InMemoryTuples>);

/// O pedido como JSON da API: chaves em camelCase, e a mudança como entrou em `apply`
/// (`{ add: grant }`, `{ assign_role: ... }`), para voltar inteira numa chamada seguinte.
fn request_json(request: &PendingRequest) -> Value {
    let mut out = to_value(request);
    let mut mutation = serde_json::to_value(&request.mutation).expect("tipos da Strig sempre serializam");
    if let Value::Object(variant) = &mut mutation {
        for inner in variant.values_mut() {
            *inner = camel_keys(inner.take());
        }
    }
    out["mutation"] = mutation;
    out
}

/// O resultado de um passo do fluxo: `ok`, o que o passo trouxe e os registros de auditoria na
/// ordem em que foram aceitos.
fn flow_reply(capture: &Capture, ok: bool, extra: Value) -> Value {
    let items = capture.take();
    let audits: Vec<Value> = items.iter().map(|(r, _)| to_value(r)).collect();
    let status = worst_status(&items);
    let mut out = serde_json::json!({"ok": ok, "audits": audits, "auditStatus": status});
    if let (Value::Object(base), Value::Object(more)) = (&mut out, extra) {
        base.extend(more);
    }
    out
}

fn recert_refused(capture: &Capture, error: RecertError) -> BindingResult<Value> {
    Ok(match error {
        RecertError::Refused(violations) => flow_reply(
            capture,
            false,
            serde_json::json!({"code": "REFUSED", "violations": to_value(&violations)}),
        ),
        RecertError::Duplicate(_) => flow_reply(capture, false, serde_json::json!({"code": "DUPLICATE"})),
        RecertError::Unknown(_) | RecertError::UnknownItem { .. } => {
            flow_reply(capture, false, serde_json::json!({"code": "UNKNOWN"}))
        }
        RecertError::Closed(_) => flow_reply(capture, false, serde_json::json!({"code": "CLOSED"})),
        RecertError::Stale(_) => flow_reply(capture, false, serde_json::json!({"code": "STALE"})),
        RecertError::Store(message) => return Err(BindingError::invalid_input("recert", message)),
        _ => {
            return Err(BindingError::invalid_input(
                "recert",
                "erro de recertificação desconhecido",
            ));
        }
    })
}

fn refused_reply(capture: &Capture, error: ApprovalError, request: Option<&PendingRequest>) -> BindingResult<Value> {
    Ok(match error {
        ApprovalError::Refused(violations) => flow_reply(
            capture,
            false,
            serde_json::json!({"code": "REFUSED", "violations": to_value(&violations)}),
        ),
        ApprovalError::Expired(_) => flow_reply(
            capture,
            false,
            serde_json::json!({"code": "EXPIRED", "request": request.map(request_json)}),
        ),
        ApprovalError::Store(PendingError::NotPending(_)) => {
            flow_reply(capture, false, serde_json::json!({"code": "NOT_PENDING"}))
        }
        ApprovalError::Store(PendingError::Unknown(_)) => {
            flow_reply(capture, false, serde_json::json!({"code": "UNKNOWN"}))
        }
        ApprovalError::Store(PendingError::Duplicate(_)) => {
            flow_reply(capture, false, serde_json::json!({"code": "DUPLICATE"}))
        }
        ApprovalError::Store(PendingError::Store(message)) => {
            return Err(BindingError::invalid_input("pending", message));
        }
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TemplateInput {
    template: RoleTemplate,
    subject: strig::SubjectMatcher,
    #[serde(default)]
    scope: Option<strig::Anchor>,
    id_prefix: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplyTemplateInput {
    actor: Subject,
    current: Vec<Grant>,
    #[serde(flatten)]
    template: TemplateInput,
    #[serde(default)]
    invariants: Vec<InvariantSpec>,
    #[serde(default)]
    tuples: Option<Vec<Tuple>>,
    #[serde(default)]
    audit: Option<AuditInput>,
    #[serde(default)]
    meta: Attributes,
    #[serde(default)]
    now: Option<Value>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ListOptions {
    /// Passos do caminho, do `kind` listado ao mais amplo (`["document", "project", "org"]`).
    #[serde(default)]
    layout: Vec<String>,
    /// Recursos a avaliar contra o filtro, para devolver os ids permitidos.
    #[serde(default)]
    resources: Option<Vec<Resource>>,
}

pub struct EngineHandle {
    engine: Engine,
    host: HostCallbacks,
}

/// Como uma mudança é aplicada: com as invariantes, a auditoria e o instante.
struct Governed<'a> {
    invariants: &'a [InvariantSpec],
    host: &'a HostCallbacks,
    custom: &'a [String],
    audit: Option<&'a AuditInput>,
    tuples: Option<InMemoryTuples>,
    meta: &'a Attributes,
    now: u64,
}

impl Governed<'_> {
    fn governance(&self, capture: Option<&Arc<Capture>>) -> BindingResult<Governance> {
        let mut governance: Governance = self.invariants.iter().collect();
        for name in self.custom {
            governance = governance.with(self.host.invariant_named(name)?);
        }
        let (Some(audit), Some(capture)) = (self.audit, capture) else {
            return Ok(governance);
        };
        let mut auditor = self.host.auditor(
            audit.level,
            self.now,
            audit.redact.as_ref(),
            Arc::new(MemoryAuditLog::new()),
        );
        if let Some(prev) = &audit.prev_hash {
            auditor = auditor.resume_chain(prev.clone());
        }
        let capture = capture.clone();
        auditor = auditor.observe(move |record, status| capture.push(record, status));
        Ok(governance.audited(Arc::new(auditor)))
    }

    /// O modo de falha da chamada, quando a entrada o traz.
    fn call_mode(&self) -> Option<FailMode> {
        self.audit.and_then(|a| a.fail_mode)
    }

    fn store(&self) -> Option<&dyn strig::TupleStore> {
        self.tuples.as_ref().map(|s| s as &dyn strig::TupleStore)
    }
}

impl EngineHandle {
    pub fn new(spec: Value) -> BindingResult<Self> {
        Self::with_host(spec, HostCallbacks::default())
    }

    /// The engine of `spec` plus the functions the host registered: condition functions and
    /// overrides enter the engine; invariants wait for an `apply` that names them.
    pub fn with_host(spec: Value, host: HostCallbacks) -> BindingResult<Self> {
        let spec: EngineSpec = parse("spec", spec)?;
        let builder = spec
            .builder()
            .map_err(|e| BindingError::new("INVALID_SPEC", e.to_string()))?;
        let engine = host
            .extend(builder)
            .build()
            .map_err(|e| BindingError::new("INVALID_SPEC", e.to_string()))?;
        Ok(Self { engine, host })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn decide(&self, ctx: &ContextData, request: Value, now: Option<u64>) -> BindingResult<Value> {
        let input: RequestInput = parse("request", request)?;
        self.decide_input(ctx, &input, now)
    }

    pub(crate) fn decide_input(
        &self,
        ctx: &ContextData,
        input: &RequestInput,
        now: Option<u64>,
    ) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let request = input.request();
        Ok(to_value(&self.engine.decide(&ctx.context_at(now), &request)))
    }

    pub fn check(&self, ctx: &ContextData, request: Value, now: Option<u64>) -> BindingResult<bool> {
        let input: RequestInput = parse("request", request)?;
        self.check_input(ctx, &input, now)
    }

    /// `check` of a request already read from the host, with no JSON tree in between.
    pub(crate) fn check_input(&self, ctx: &ContextData, input: &RequestInput, now: Option<u64>) -> BindingResult<bool> {
        host::forbid_reentry()?;
        let request = input.request();
        Ok(self.engine.check(&ctx.context_at(now), &request))
    }

    /// `check` of every request, in order, against one `Context` and one instant: one crossing of
    /// the boundary for the whole batch. A request that cannot be read fails the whole call
    /// (`INVALID_INPUT`), never turning into a silent `false` for one slot.
    pub fn check_many(&self, ctx: &ContextData, requests: Value, now: Option<u64>) -> BindingResult<Vec<bool>> {
        let inputs: Vec<RequestInput> = parse("requests", requests)?;
        self.check_inputs(ctx, &inputs, now)
    }

    pub(crate) fn check_inputs(
        &self,
        ctx: &ContextData,
        inputs: &[RequestInput],
        now: Option<u64>,
    ) -> BindingResult<Vec<bool>> {
        host::forbid_reentry()?;
        let ctx = ctx.context_at(now);
        Ok(inputs
            .iter()
            .map(|input| self.engine.check(&ctx, &input.request()))
            .collect())
    }

    /// A decisão com o rastro completo (`strig::Explanation`).
    pub fn explain(&self, ctx: &ContextData, request: Value, now: Option<u64>) -> BindingResult<Value> {
        let input: RequestInput = parse("request", request)?;
        self.explain_input(ctx, &input, now)
    }

    pub(crate) fn explain_input(
        &self,
        ctx: &ContextData,
        input: &RequestInput,
        now: Option<u64>,
    ) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let request = input.request();
        Ok(to_value(&self.engine.explain(&ctx.context_at(now), &request)))
    }

    /// `explain` of every request, in order, in one crossing.
    pub fn explain_many(&self, ctx: &ContextData, requests: Value, now: Option<u64>) -> BindingResult<Value> {
        let inputs: Vec<RequestInput> = parse("requests", requests)?;
        self.explain_inputs(ctx, &inputs, now)
    }

    pub(crate) fn explain_inputs(
        &self,
        ctx: &ContextData,
        inputs: &[RequestInput],
        now: Option<u64>,
    ) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let ctx = ctx.context_at(now);
        Ok(Value::Array(
            inputs
                .iter()
                .map(|input| to_value(&self.engine.explain(&ctx, &input.request())))
                .collect(),
        ))
    }

    /// For a denial, the verified changes that would allow it (`strig::Remedies`); `null` when the
    /// request is already allowed. The limits of the context (`maxDecisions`) bound the
    /// verifications; `options.maxRemedies` and `options.maxDecisions` narrow them for the call.
    pub fn why_not(
        &self,
        ctx: &ContextData,
        request: Value,
        now: Option<u64>,
        options: Option<Value>,
    ) -> BindingResult<Value> {
        let input: RequestInput = parse("request", request)?;
        let options = self.why_not_options(ctx, options)?;
        host::forbid_reentry()?;
        Ok(to_value(&self.engine.why_not(
            &ctx.context_at(now),
            &input.request(),
            &options,
        )))
    }

    fn why_not_options(&self, ctx: &ContextData, options: Option<Value>) -> BindingResult<strig::WhyNotOptions> {
        let mut out = strig::WhyNotOptions::default();
        if let Some(limits) = ctx.limits {
            out = out.with_limits(limits);
        }
        let Some(options) = options else {
            return Ok(out);
        };
        let Value::Object(map) = options else {
            return Err(BindingError::invalid_input("options", "esperado um objeto"));
        };
        if let Some(unknown) = map
            .keys()
            .find(|k| !matches!(k.as_str(), "maxDecisions" | "maxRemedies"))
        {
            return Err(BindingError::invalid_input(
                "options",
                format!("campo desconhecido: {unknown}"),
            ));
        }
        if let Some(decisions) = map.get("maxDecisions") {
            let limits = out
                .limits
                .with_max_decisions(count_value("options.maxDecisions", decisions)?);
            out = out.with_limits(limits);
        }
        if let Some(remedies) = map.get("maxRemedies") {
            out = out.with_max_remedies(count_value("options.maxRemedies", remedies)?);
        }
        Ok(out)
    }

    /// The fields the request's subject may use for its permission on its resource
    /// (`strig::FieldSet`). The `field` of the request, if any, is ignored.
    pub fn allowed_fields(&self, ctx: &ContextData, request: Value, now: Option<u64>) -> BindingResult<Value> {
        let input: RequestInput = parse("request", request)?;
        host::forbid_reentry()?;
        Ok(to_value(&self.engine.allowed_fields(
            &ctx.context_at(now),
            &input.subject,
            &input.permission,
            &input.resource,
        )))
    }

    /// `allowed_fields` with, for each field, the grants that gave it and the ones that took it
    /// away (`strig::FieldExplanation`).
    pub fn explain_fields(&self, ctx: &ContextData, request: Value, now: Option<u64>) -> BindingResult<Value> {
        let input: RequestInput = parse("request", request)?;
        host::forbid_reentry()?;
        Ok(to_value(&self.engine.explain_fields(
            &ctx.context_at(now),
            &input.subject,
            &input.permission,
            &input.resource,
        )))
    }

    pub fn capabilities(
        &self,
        ctx: &ContextData,
        subject: Value,
        scope: Value,
        now: Option<u64>,
    ) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let subject: Subject = parse("subject", subject)?;
        let scope: Resource = parse("scope", scope)?;
        Ok(to_value(&self.engine.capabilities(
            &ctx.context_at(now),
            &subject,
            &scope,
        )))
    }

    pub fn validate_grant(&self, grant: Value) -> BindingResult<()> {
        host::forbid_reentry()?;
        let grant: Grant = parse("grant", grant)?;
        self.engine
            .validate_grant(&grant)
            .map_err(|e| BindingError::new("INVALID_GRANT", e.to_string()))
    }

    pub fn catalog(&self) -> Value {
        to_value(&self.engine.catalog().export())
    }

    /// O alcance de `subject` com `permission` sobre os recursos de `kind`, sem enumerar a
    /// tabela: `{ kind, permission, exact, shape, expr, residual, warnings, ids }`. `expr` é a
    /// forma estrutural sobre `options.layout`; `ids` só vem com `options.resources`, e já traz
    /// os recursos que só o motor decide, resolvidos por `check`. O que só o recurso decide fica em
    /// `residual` e nunca conta como permissão.
    pub fn list(
        &self,
        ctx: &ContextData,
        subject: Value,
        permission: &str,
        kind: &str,
        options: Option<Value>,
        now: Option<u64>,
    ) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let subject: Subject = parse("subject", subject)?;
        let options: ListOptions = match options {
            Some(v) if !v.is_null() => parse("options", v)?,
            _ => ListOptions::default(),
        };
        let mut layout = PathLayout::new(kind);
        for step in options.layout.iter().filter(|step| step.as_str() != kind) {
            layout = layout.within(step.as_str());
        }
        let query = ctx.query_context(now);
        let filter = self.engine.list(&query, &subject, permission, kind);
        let ids = options
            .resources
            .as_ref()
            .map(|resources| filter.resolve_with(&self.engine, &query.context(), resources));
        Ok(out!({
            "kind": filter.kind(),
            "permission": filter.permission(),
            "exact": filter.is_exact(&layout),
            "shape": shape_json(&filter.shape(&layout)),
            "expr": expr_json(&filter.expr(&layout)),
            "residual": filter.residual_for(&layout).iter().map(residual_json).collect::<Vec<_>>(),
            "warnings": filter.warnings(),
            "ids": ids,
        }))
    }

    /// Partes nomeadas por um grant allow da permissão, em qualquer lugar.
    pub fn who_can(&self, ctx: &ContextData, permission: &str, now: Option<u64>) -> Value {
        let parties = self.engine.who_can(&ctx.query_context(now), permission);
        Value::Array(parties.iter().map(subject_ref_json).collect())
    }

    /// Quem tem a permissão sobre o recurso, com o caminho de cada parte.
    ///
    /// # Errors
    /// `QUERY_LIMIT_EXCEEDED` e `RELATION_DEPTH_EXCEEDED`.
    pub fn who_can_on(
        &self,
        ctx: &ContextData,
        permission: &str,
        resource: Value,
        now: Option<u64>,
    ) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let resource: Resource = parse("resource", resource)?;
        let who = self.engine.who_can_on(&ctx.query_context(now), permission, &resource)?;
        let entries: Vec<Value> = who
            .entries
            .iter()
            .map(|e| out!({"subject": subject_ref_json(&e.subject), "via": via_json(&e.via)}))
            .collect();
        let except: Vec<Value> = who
            .except
            .iter()
            .map(|e| out!({"allowed": subject_ref_json(&e.allowed), "with": subject_ref_json(&e.with)}))
            .collect();
        Ok(out!({"permission": who.permission, "resource": who.resource, "entries": entries, "except": except}))
    }

    /// O que cada parte pode fazer no recurso.
    ///
    /// # Errors
    /// `QUERY_LIMIT_EXCEEDED` e `RELATION_DEPTH_EXCEEDED`.
    pub fn access_of(&self, ctx: &ContextData, resource: Value, now: Option<u64>) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let resource: Resource = parse("resource", resource)?;
        let parties = self.engine.access_of(&ctx.query_context(now), &resource)?;
        Ok(Value::Array(
            parties
                .iter()
                .map(|p| out!({"subject": subject_ref_json(&p.subject), "permissions": p.permissions}))
                .collect(),
        ))
    }

    /// A decisão para um sujeito nomeado por referência, com o caminho que decidiu. `subjects`
    /// são os sujeitos que o resolvedor conhece (`user` e `object` por id); uma referência fora
    /// dele falha com `UNKNOWN_SUBJECT`, nunca responde como um sujeito inventado.
    pub fn check_for(
        &self,
        ctx: &ContextData,
        subject_ref: Value,
        permission: &str,
        resource: Value,
        subjects: Value,
        now: Option<u64>,
    ) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let reference = parse_subject_ref(subject_ref)?;
        let resource: Resource = parse("resource", resource)?;
        let subjects: Vec<Subject> = parse("subjects", subjects)?;
        let resolver = subjects
            .into_iter()
            .fold(InMemorySubjects::new(), |known, subject| known.with(subject));
        let answer = self
            .engine
            .check_for(&ctx.query_context(now), &resolver, &reference, permission, &resource)?;
        Ok(out!({
            "subject": subject_ref_json(&answer.subject),
            "allowed": answer.is_allowed(),
            "decision": answer.decision,
            "via": via_json(&answer.via),
            "explanation": answer.explanation,
        }))
    }

    /// Aplica uma mudança de grant ou de papel pelos invariantes, no instante `input.now` (ou em
    /// `clock`, o relógio do alvo, que só falha se a entrada não traz `now`). Devolve `{ ok, grants?, subject?, violations?, audit? }`;
    /// `subject` é o sujeito com o papel aplicado, numa mudança de papel aceita, e `audit` é o
    /// registro a gravar quando a entrada pede auditoria. As janelas de validade do ator contam
    /// nesse instante.
    pub fn apply(&self, input: Value, clock: BindingResult<u64>) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let mut input = input;
        let custom = host::take_custom(&mut input)?;
        let input: ApplyInput = parse("apply", input)?;
        let now = match &input.now {
            Some(v) if !v.is_null() => millis_value("now", v)?,
            _ => clock?,
        };
        let governed = Governed {
            invariants: &input.invariants,
            host: &self.host,
            custom: &custom,
            audit: input.audit.as_ref(),
            tuples: input.tuples.map(|t| t.into_iter().collect()),
            meta: &input.meta,
            now,
        };
        let capture = Arc::new(Capture::default());
        let governance = governed.governance(Some(&capture))?;
        let at = governance.at(now);
        let at = match governed.call_mode() {
            Some(mode) => at.fail_mode(mode),
            None => at,
        };
        let impact_options = input.impact.as_ref().map(|i| i.options(governed.tuples.as_ref(), now));
        let result = match &impact_options {
            Some(options) => at
                .apply_with_impact(
                    &self.engine,
                    &input.actor,
                    &input.current,
                    &input.mutation,
                    governed.store(),
                    governed.meta,
                    options,
                )
                .map(|applied| (applied.grants, Some(applied.impact))),
            None => at
                .apply_with(
                    &self.engine,
                    &input.actor,
                    &input.current,
                    &input.mutation,
                    governed.store(),
                    governed.meta,
                )
                .map(|grants| (grants, None)),
        };
        let items = capture.take();
        let status = worst_status(&items);
        let audit = items.last().map(|(r, _)| to_value(r));
        Ok(match result {
            Ok((grants, impact)) => {
                let mut out = out!({ "ok": true, "grants": grants, "audit": audit, "auditStatus": status });
                if let Some(impact) = impact {
                    out["impact"] = to_value(&impact);
                }
                if let Some(subject) = input.mutation.subject_after() {
                    out["subject"] = to_value(&subject);
                }
                out
            }
            Err(violations) => out!({ "ok": false, "violations": violations, "audit": audit, "auditStatus": status }),
        })
    }

    /// O impacto de uma mudança sobre o acesso, sem aplicá-la nem gravar auditoria: quem ganha, quem
    /// perde e o que não se decide. A entrada é a do `apply` e `impact` diz de onde vêm sujeitos e
    /// recursos (padrão: derivados das consultas reversas). Devolve `{ ok: true, impact }` ou
    /// `{ ok: false, violations }` quando as invariantes recusam a mudança.
    pub fn impact(&self, input: Value, clock: BindingResult<u64>) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let mut input = input;
        let custom = host::take_custom(&mut input)?;
        let input: ApplyInput = parse("impact", input)?;
        let now = match &input.now {
            Some(v) if !v.is_null() => millis_value("now", v)?,
            _ => clock?,
        };
        let governed = Governed {
            invariants: &input.invariants,
            host: &self.host,
            custom: &custom,
            audit: None,
            tuples: input.tuples.map(|t| t.into_iter().collect()),
            meta: &input.meta,
            now,
        };
        let governance = governed.governance(None)?;
        let spec = input.impact.unwrap_or_else(|| ImpactInput {
            source: ImpactSource::derived(),
            env: Attributes::new(),
            limits: ImpactLimits::default(),
        });
        let options = spec.options(governed.tuples.as_ref(), now);
        Ok(
            match governance
                .at(now)
                .impact(&self.engine, &input.actor, &input.current, &input.mutation, &options)
            {
                Ok(impact) => out!({ "ok": true, "impact": impact }),
                Err(violations) => out!({ "ok": false, "violations": violations }),
            },
        )
    }

    /// Materializa um template em grants comuns, sem vínculo com ele: o resultado é só uma cópia
    /// (`{ template, templateVersion, mutations, meta }`) e mudar o template depois não muda o que
    /// já foi aplicado.
    pub fn materialize(&self, input: Value) -> BindingResult<Value> {
        let input: TemplateInput = parse("template", input)?;
        let materialized = input.template.materialize(input.subject, input.scope, &input.id_prefix);
        Ok(to_value(&materialized))
    }

    /// Materializa o template e aplica o lote pela governança, na ordem das dependências
    /// (`depends_on`). O lote inteiro é simulado antes de gravar qualquer registro de auditoria:
    /// numa recusa, `ok` é `false`, só a recusa vai à trilha e nada deve ser gravado. Devolve
    /// `{ ok, grants?, violations?, audits }`.
    pub fn apply_template(&self, input: Value, clock: BindingResult<u64>) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let mut input = input;
        let custom = host::take_custom(&mut input)?;
        let input: ApplyTemplateInput = parse("template", input)?;
        let now = match &input.now {
            Some(v) if !v.is_null() => millis_value("now", v)?,
            _ => clock?,
        };
        let materialized = input.template.template.materialize(
            input.template.subject,
            input.template.scope,
            &input.template.id_prefix,
        );
        let mut meta = materialized.meta.clone();
        meta.extend(input.meta.clone());
        let governed = Governed {
            invariants: &input.invariants,
            host: &self.host,
            custom: &custom,
            audit: input.audit.as_ref(),
            tuples: input.tuples.map(|t| t.into_iter().collect()),
            meta: &meta,
            now,
        };
        let ordered = materialized.ordered(&self.engine);
        let capture = Arc::new(Capture::default());
        let audited = governed.governance(Some(&capture))?;
        let call_mode = governed.call_mode();
        let audited_at = |now: u64| {
            let at = audited.at(now);
            match call_mode {
                Some(mode) => at.fail_mode(mode),
                None => at,
            }
        };
        let reply = |ok: bool, extra: Value| {
            let items = capture.take();
            let audits: Vec<Value> = items.iter().map(|(r, _)| to_value(r)).collect();
            let status = worst_status(&items);
            let mut out = out!({"ok": ok, "audits": audits, "auditStatus": status});
            if let (Value::Object(base), Value::Object(more)) = (&mut out, extra) {
                base.extend(more);
            }
            out
        };

        // Simulação sem auditoria: a trilha nunca diz `applied` de um lote que será descartado.
        let silent = governed.governance(None)?;
        let mut grants = input.current.clone();
        for mutation in &ordered {
            match silent.at(now).apply_with(
                &self.engine,
                &input.actor,
                &grants,
                mutation,
                governed.store(),
                governed.meta,
            ) {
                Ok(next) => grants = next,
                Err(violations) => {
                    // Registra só a recusa, no estado em que o lote chegou nela.
                    let refused = audited_at(now).apply_with(
                        &self.engine,
                        &input.actor,
                        &grants,
                        mutation,
                        governed.store(),
                        governed.meta,
                    );
                    let violations = refused.err().unwrap_or(violations);
                    return Ok(reply(false, out!({"violations": violations})));
                }
            }
        }
        let mut grants = input.current;
        for mutation in &ordered {
            match audited_at(now).apply_with(
                &self.engine,
                &input.actor,
                &grants,
                mutation,
                governed.store(),
                governed.meta,
            ) {
                Ok(next) => grants = next,
                Err(violations) => return Ok(reply(false, out!({"violations": violations}))),
            }
        }
        Ok(reply(true, out!({"grants": grants})))
    }

    /// Prepara um passo do fluxo de pedido pendente: o instante, a governança com a auditoria
    /// capturada e a política.
    fn flow_parts(
        &self,
        flow: &mut FlowInput,
        custom: &[String],
        clock: BindingResult<u64>,
    ) -> BindingResult<FlowParts> {
        let now = match &flow.now {
            Some(v) if !v.is_null() => millis_value("now", v)?,
            _ => clock?,
        };
        let governed = Governed {
            invariants: &flow.invariants,
            host: &self.host,
            custom,
            audit: flow.audit.as_ref(),
            tuples: None,
            meta: &flow.meta,
            now,
        };
        let capture = Arc::new(Capture::default());
        let governance = governed.governance(Some(&capture))?;
        let policy = ApprovalPolicy::from_rules(std::mem::take(&mut flow.approval));
        let tuples = flow.tuples.take().map(|t| t.into_iter().collect());
        Ok((now, governance, capture, policy, tuples))
    }

    /// Propõe uma mudança. Sem regra de aprovação para o tipo dela, aplica na hora (`applied: true`,
    /// `grants`); com regra, devolve o pedido (`applied: false`, `request`) para o chamador guardar.
    /// Recusa: `{ ok: false, code: 'REFUSED', violations }`. `ok` é `true` quando a mudança foi aplicada ou
    /// ficou pendente.
    pub fn propose(&self, input: Value, clock: BindingResult<u64>) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let mut input = input;
        let custom = host::take_custom(&mut input)?;
        let mut input: ProposeInput = parse("propose", input)?;
        let (now, governance, capture, policy, tuples) = self.flow_parts(&mut input.flow, &custom, clock)?;
        let expires_at = match &input.expires_at {
            Some(v) if !v.is_null() => Some(millis_value("expiresAt", v)?),
            _ => None,
        };
        let store = MemoryPendingStore::new();
        let impact_options = input.flow.impact.as_ref().map(|i| i.options(tuples.as_ref(), now));
        let approvals = self.approvals(
            &governance,
            &policy,
            &store,
            input.flow.audit.as_ref(),
            impact_options.as_ref(),
        );
        let review = Review {
            engine: &self.engine,
            current: &input.flow.current,
            tuples: tuples.as_ref().map(|s| s as &dyn strig::TupleStore),
            now,
            meta: &input.flow.meta,
        };
        Ok(
            match approvals.propose(&review, &input.actor, &input.mutation, input.id, expires_at) {
                Ok(Proposed::Applied(grants)) => {
                    let mut extra = serde_json::json!({"applied": true, "grants": to_value(&grants)});
                    if let Some(subject) = input.mutation.subject_after() {
                        extra["subject"] = to_value(&subject);
                    }
                    flow_reply(&capture, true, extra)
                }
                Ok(Proposed::Pending(request)) => flow_reply(
                    &capture,
                    true,
                    serde_json::json!({"applied": false, "request": request_json(&request)}),
                ),
                Err(error) => refused_reply(&capture, error, None)?,
            },
        )
    }

    /// Aprova (`decision: 'approve'`) ou recusa (`'reject'`, com `reason`) o `request`. Na aprovação a
    /// mudança roda de novo pelas invariantes sobre `current` e só então se aplica: `{ ok: true,
    /// grants, subject?, request }`. Recusas do fluxo: `{ ok: false, code, ... }` com `code` em
    /// `REFUSED` (`violations`; o pedido segue pendente), `EXPIRED` (`request` já expirado) e
    /// `NOT_PENDING`.
    pub fn resolve(&self, input: Value, clock: BindingResult<u64>) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let mut input = input;
        let custom = host::take_custom(&mut input)?;
        let mut input: ResolveInput = parse("resolve", input)?;
        let (now, governance, capture, policy, tuples) = self.flow_parts(&mut input.flow, &custom, clock)?;
        let id = input.request.id.clone();
        let store = MemoryPendingStore::new();
        seed(&store, std::slice::from_ref(&input.request))?;
        let impact_options = input.flow.impact.as_ref().map(|i| i.options(tuples.as_ref(), now));
        let approvals = self.approvals(
            &governance,
            &policy,
            &store,
            input.flow.audit.as_ref(),
            impact_options.as_ref(),
        );
        let review = Review {
            engine: &self.engine,
            current: &input.flow.current,
            tuples: tuples.as_ref().map(|s| s as &dyn strig::TupleStore),
            now,
            meta: &input.flow.meta,
        };
        let stored = |store: &MemoryPendingStore| store.get(&id).ok().flatten();
        Ok(match input.decision.as_str() {
            "approve" => match approvals.approve(&review, &input.approver, &id) {
                Ok(approved) => {
                    let mut extra = serde_json::json!({"grants": to_value(&approved.grants), "request": request_json(&approved.request)});
                    if let Some(subject) = approved.request.mutation.subject_after() {
                        extra["subject"] = to_value(&subject);
                    }
                    if let Some(proposed) = &approved.proposed_impact {
                        extra["proposedImpact"] = to_value(proposed);
                    }
                    flow_reply(&capture, true, extra)
                }
                Err(error) => refused_reply(&capture, error, stored(&store).as_ref())?,
            },
            "reject" => {
                let reason = input.reason.as_deref().unwrap_or_default();
                match approvals.reject(&review, &input.approver, &id, reason) {
                    Ok(request) => flow_reply(&capture, true, serde_json::json!({"request": request_json(&request)})),
                    Err(error) => refused_reply(&capture, error, stored(&store).as_ref())?,
                }
            }
            other => {
                return Err(BindingError::invalid_argument(
                    "decision",
                    format!("esperado approve ou reject, veio {other}"),
                ));
            }
        })
    }

    /// A elevação temporária e o break-glass. `op: 'request'` pede (`elevationRequest`, `expiresAt?`):
    /// `{ ok: true, applied: false, request }` fica à espera de um aprovador e
    /// `{ ok: true, applied: true, grants, request }` é um break-glass já em vigor. `approve`, `reject`,
    /// `revoke` e `close_review` agem sobre o `request` guardado, como `by`: `approve` devolve
    /// `{ grants, request }` como `resolve`, `revoke` devolve `{ grants, request }` e `reject` e
    /// `close_review` devolvem `{ request }`. Recusas como as de `resolve`; nada se grava aqui.
    pub fn elevate(&self, input: Value, clock: BindingResult<u64>) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let mut input = input;
        let custom = host::take_custom(&mut input)?;
        let mut input: ElevateInput = parse("elevate", input)?;
        let (now, governance, capture, _policy, tuples) = self.flow_parts(&mut input.flow, &custom, clock)?;
        let policy = ElevationPolicy::from_rules(std::mem::take(&mut input.elevation));
        let store = MemoryPendingStore::new();
        let id = input.request.as_ref().map(|r| r.id.clone());
        if let Some(request) = &input.request {
            seed(&store, std::slice::from_ref(request))?;
        }
        let impact_options = input.flow.impact.as_ref().map(|i| i.options(tuples.as_ref(), now));
        let flow = Elevations::new(&governance, &policy, &store);
        let flow = match impact_options.as_ref() {
            Some(options) => flow.with_impact(options),
            None => flow,
        };
        let flow = match input.flow.audit.as_ref().and_then(|a| a.fail_mode) {
            Some(mode) => flow.fail_mode(mode),
            None => flow,
        };
        let review = Review {
            engine: &self.engine,
            current: &input.flow.current,
            tuples: tuples.as_ref().map(|s| s as &dyn strig::TupleStore),
            now,
            meta: &input.flow.meta,
        };
        let stored = |store: &MemoryPendingStore| id.as_deref().and_then(|id| store.get(id).ok().flatten());
        let who = |by: Option<&Subject>| {
            by.cloned()
                .ok_or_else(|| BindingError::invalid_argument("by", "falta quem age"))
        };
        let reason = input.reason.as_deref().unwrap_or_default();
        Ok(match input.op.as_str() {
            "request" => {
                let request = input
                    .elevation_request
                    .ok_or_else(|| BindingError::invalid_argument("elevationRequest", "falta o pedido"))?;
                let expires_at = match &input.expires_at {
                    Some(v) if !v.is_null() => Some(millis_value("expiresAt", v)?),
                    _ => None,
                };
                match flow.request(&review, &request, expires_at) {
                    Ok(Elevated::Pending(pending)) => flow_reply(
                        &capture,
                        true,
                        serde_json::json!({"applied": false, "request": request_json(&pending)}),
                    ),
                    Ok(Elevated::Active(approved)) => flow_reply(
                        &capture,
                        true,
                        serde_json::json!({"applied": true, "grants": to_value(&approved.grants), "request": request_json(&approved.request)}),
                    ),
                    Ok(_) => {
                        return Err(BindingError::invalid_input(
                            "elevate",
                            "resultado de elevação desconhecido",
                        ));
                    }
                    Err(error) => refused_reply(&capture, error, None)?,
                }
            }
            "approve" => match flow.approve(&review, &who(input.by.as_ref())?, &id.clone().unwrap_or_default()) {
                Ok(approved) => {
                    let mut extra = serde_json::json!({"grants": to_value(&approved.grants), "request": request_json(&approved.request)});
                    if let Some(proposed) = &approved.proposed_impact {
                        extra["proposedImpact"] = to_value(proposed);
                    }
                    flow_reply(&capture, true, extra)
                }
                Err(error) => refused_reply(&capture, error, stored(&store).as_ref())?,
            },
            "reject" => match flow.reject(
                &review,
                &who(input.by.as_ref())?,
                &id.clone().unwrap_or_default(),
                reason,
            ) {
                Ok(request) => flow_reply(&capture, true, serde_json::json!({"request": request_json(&request)})),
                Err(error) => refused_reply(&capture, error, stored(&store).as_ref())?,
            },
            "revoke" => {
                let why = input.reason.as_deref();
                match flow.revoke(&review, &who(input.by.as_ref())?, &id.clone().unwrap_or_default(), why) {
                    Ok(revoked) => flow_reply(
                        &capture,
                        true,
                        serde_json::json!({"grants": to_value(&revoked.grants), "request": request_json(&revoked.request)}),
                    ),
                    Err(error) => refused_reply(&capture, error, stored(&store).as_ref())?,
                }
            }
            "close_review" => match flow.close_review(
                &review,
                &who(input.by.as_ref())?,
                &id.clone().unwrap_or_default(),
                reason,
            ) {
                Ok(request) => flow_reply(&capture, true, serde_json::json!({"request": request_json(&request)})),
                Err(error) => refused_reply(&capture, error, stored(&store).as_ref())?,
            },
            other => {
                return Err(BindingError::invalid_argument(
                    "op",
                    format!("esperado request, approve, reject, revoke ou close_review, veio {other}"),
                ));
            }
        })
    }

    /// A recertificação de acesso. `op: 'open'` abre a campanha (`campaignSpec`, `subjects?`, `by`) e devolve
    /// `{ ok: true, campaign }`; `decide` (`campaign`, `item`, `decision`, `by`, `reason?`) devolve
    /// `{ grants, revokedRole, campaign, item }`; `close` (`campaign`, `by`) devolve
    /// `{ grants, revokedRoles, campaign, report }`; `report` (`campaign`) devolve `{ report }` e `list`
    /// (`campaigns`) devolve `{ campaigns }` só com as abertas. Recusas como as de `resolve`
    /// (`REFUSED`, `UNKNOWN`, `CLOSED`, `STALE`); nada se grava aqui, quem chama persiste.
    pub fn recertify(&self, input: Value, clock: BindingResult<u64>) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let mut input = input;
        let custom = host::take_custom(&mut input)?;
        let mut input: RecertInput = parse("recertify", input)?;
        let (now, governance, capture, _policy, tuples) = self.flow_parts(&mut input.flow, &custom, clock)?;
        let store = MemoryRecertStore::new();
        for campaign in input.campaign.iter().chain(input.campaigns.iter()) {
            store
                .insert(campaign.clone())
                .map_err(|e| BindingError::invalid_input("campaign", e))?;
        }
        let id = input.campaign.as_ref().map(|c| c.id.clone()).unwrap_or_default();
        let impact_options = input.flow.impact.as_ref().map(|i| i.options(tuples.as_ref(), now));
        let flow = Recertifications::new(&governance, &store);
        let flow = match impact_options.as_ref() {
            Some(options) => flow.with_impact(options),
            None => flow,
        };
        let flow = match input.flow.audit.as_ref().and_then(|a| a.fail_mode) {
            Some(mode) => flow.fail_mode(mode),
            None => flow,
        };
        let review = Review {
            engine: &self.engine,
            current: &input.flow.current,
            tuples: tuples.as_ref().map(|s| s as &dyn strig::TupleStore),
            now,
            meta: &input.flow.meta,
        };
        let who = |by: Option<&Subject>| {
            by.cloned()
                .ok_or_else(|| BindingError::invalid_argument("by", "falta quem age"))
        };
        Ok(match input.op.as_str() {
            "open" => {
                let spec = input
                    .campaign_spec
                    .take()
                    .ok_or_else(|| BindingError::invalid_argument("campaignSpec", "falta a campanha"))?;
                match flow.open(&review, &who(input.by.as_ref())?, spec, &input.subjects) {
                    Ok(campaign) => flow_reply(&capture, true, serde_json::json!({"campaign": to_value(&campaign)})),
                    Err(error) => recert_refused(&capture, error)?,
                }
            }
            "decide" => {
                let item = input
                    .item
                    .as_deref()
                    .ok_or_else(|| BindingError::invalid_argument("item", "falta o item"))?;
                let decision = input
                    .decision
                    .take()
                    .ok_or_else(|| BindingError::invalid_argument("decision", "falta a decisão"))?;
                match flow.decide(
                    &review,
                    &who(input.by.as_ref())?,
                    &id,
                    item,
                    decision,
                    input.reason.as_deref(),
                ) {
                    Ok(decided) => flow_reply(
                        &capture,
                        true,
                        serde_json::json!({
                            "grants": to_value(&decided.grants),
                            "revokedRole": decided.revoked_role.as_ref().map(to_value),
                            "campaign": to_value(&decided.campaign),
                            "item": to_value(&decided.item),
                        }),
                    ),
                    Err(error) => recert_refused(&capture, error)?,
                }
            }
            "close" => match flow.close(&review, &who(input.by.as_ref())?, &id) {
                Ok(closed) => flow_reply(
                    &capture,
                    true,
                    serde_json::json!({
                        "grants": to_value(&closed.grants),
                        "revokedRoles": to_value(&closed.revoked_roles),
                        "campaign": to_value(&closed.campaign),
                        "report": to_value(&closed.report),
                    }),
                ),
                Err(error) => recert_refused(&capture, error)?,
            },
            "report" => match flow.report(&id) {
                Ok(report) => flow_reply(&capture, true, serde_json::json!({"report": to_value(&report)})),
                Err(error) => recert_refused(&capture, error)?,
            },
            "list" => match flow.open_campaigns() {
                Ok(open) => flow_reply(&capture, true, serde_json::json!({"campaigns": to_value(&open)})),
                Err(error) => recert_refused(&capture, error)?,
            },
            other => {
                return Err(BindingError::invalid_argument(
                    "op",
                    format!("esperado open, decide, close, report ou list, veio {other}"),
                ));
            }
        })
    }

    /// O impacto do `request` pendente como foi proposto e como seria agora sobre `current`, para o
    /// aprovador ver antes de decidir: `{ ok: true, proposed, current, changed }`. Nada se grava.
    pub fn review_impact(&self, input: Value, clock: BindingResult<u64>) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let mut input = input;
        let custom = host::take_custom(&mut input)?;
        let mut input: ReviewImpactInput = parse("reviewImpact", input)?;
        let (now, governance, _capture, policy, tuples) = self.flow_parts(&mut input.flow, &custom, clock)?;
        let id = input.request.id.clone();
        let store = MemoryPendingStore::new();
        seed(&store, std::slice::from_ref(&input.request))?;
        let spec = input.flow.impact.take().unwrap_or_else(|| ImpactInput {
            source: ImpactSource::derived(),
            env: Attributes::new(),
            limits: ImpactLimits::default(),
        });
        let options = spec.options(tuples.as_ref(), now);
        let approvals = self.approvals(&governance, &policy, &store, None, Some(&options));
        let review = Review {
            engine: &self.engine,
            current: &input.flow.current,
            tuples: tuples.as_ref().map(|s| s as &dyn strig::TupleStore),
            now,
            meta: &input.flow.meta,
        };
        Ok(match approvals.review_impact(&review, &id) {
            Ok(reviewed) => {
                let mut out = to_value(&reviewed);
                out["ok"] = Value::Bool(true);
                out
            }
            Err(error) => refused_reply(&Capture::default(), error, None)?,
        })
    }

    /// Fecha os pedidos pendentes cujo prazo chegou em `now` e devolve `{ ok, expired, audits }`, com os
    /// pedidos já expirados para o chamador gravar.
    pub fn expire(&self, input: Value, clock: BindingResult<u64>) -> BindingResult<Value> {
        host::forbid_reentry()?;
        let mut input = input;
        let custom = host::take_custom(&mut input)?;
        let mut input: ExpireInput = parse("expire", input)?;
        let (now, governance, capture, policy, _) = self.flow_parts(&mut input.flow, &custom, clock)?;
        let store = MemoryPendingStore::new();
        seed(&store, &input.requests)?;
        let approvals = self.approvals(&governance, &policy, &store, input.flow.audit.as_ref(), None);
        Ok(match approvals.expire_due(now, &input.flow.meta) {
            Ok(expired) => {
                let expired: Vec<Value> = expired.iter().map(request_json).collect();
                flow_reply(&capture, true, serde_json::json!({"expired": expired}))
            }
            Err(error) => refused_reply(&capture, error, None)?,
        })
    }

    fn approvals<'a>(
        &self,
        governance: &'a Governance,
        policy: &'a ApprovalPolicy,
        store: &'a MemoryPendingStore,
        audit: Option<&AuditInput>,
        impact: Option<&'a ImpactOptions<'a>>,
    ) -> Approvals<'a> {
        let approvals = Approvals::new(governance, policy, store);
        let approvals = match impact {
            Some(options) => approvals.with_impact(options),
            None => approvals,
        };
        match audit.and_then(|a| a.fail_mode) {
            Some(mode) => approvals.fail_mode(mode),
            None => approvals,
        }
    }

    /// Tenta gravar agora os registros que esperam na fila (`failMode: 'open'`) e devolve os
    /// contadores: `{ pending, writtenLate, dropped, failures, nextRetryAt }`. `now` é o instante do
    /// relógio do alvo, ou o dado.
    pub fn flush_audit(&self, clock: BindingResult<u64>) -> BindingResult<Value> {
        host::forbid_reentry()?;
        Ok(camel_keys(self.host.flush_audit(clock?)))
    }

    /// Os contadores da fila de retentativa, sem tentar gravar.
    pub fn audit_stats(&self) -> Value {
        camel_keys(self.host.audit_stats())
    }
}

fn seed(store: &MemoryPendingStore, requests: &[PendingRequest]) -> BindingResult<()> {
    for request in requests {
        store
            .insert(request.clone())
            .map_err(|e| BindingError::invalid_input("requests", e))?;
    }
    Ok(())
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChainAnchors {
    /// O hash que o primeiro registro continua; sem ele, a lista começa a cadeia.
    #[serde(default)]
    start: Option<String>,
    /// A cabeça publicada, que o último registro tem de ter.
    #[serde(default)]
    head: Option<String>,
}

/// Verifica uma sequência de registros `forensic` na ordem em que foram gravados, contra as
/// âncoras conhecidas de fora. Devolve `{ ok: true, head }` ou `{ ok: false, code, index?, message }`
/// com `code` em `TAMPERED`, `BROKEN`, `UNCHAINED`, `ANCHOR_MISMATCH` e `HEAD_MISMATCH`.
pub fn verify_audit_chain(records: Value, anchors: Option<Value>) -> BindingResult<Value> {
    let records: Vec<AuditRecord> = parse("records", records)?;
    let anchors: ChainAnchors = match anchors {
        Some(v) if !v.is_null() => parse("anchors", v)?,
        _ => ChainAnchors::default(),
    };
    Ok(
        match verify_chain_anchored(&records, anchors.start.as_deref(), anchors.head.as_deref()) {
            Ok(()) => out!({"ok": true, "head": chain_head(&records)}),
            Err(error) => {
                let (code, index) = match &error {
                    ChainError::Tampered { index } => ("TAMPERED", Some(*index)),
                    ChainError::Broken { index } => ("BROKEN", Some(*index)),
                    ChainError::Unchained { index } => ("UNCHAINED", Some(*index)),
                    ChainError::AnchorMismatch => ("ANCHOR_MISMATCH", None),
                    ChainError::HeadMismatch => ("HEAD_MISMATCH", None),
                };
                out!({"ok": false, "code": code, "index": index, "message": error.to_string()})
            }
        },
    )
}

/// Bytes estimados para `records` registros de auditoria no nível dado. `records` é um número
/// finito (um fracionário arredonda para baixo e um negativo conta 0); outro tipo é `INVALID_ARGUMENT`.
pub fn audit_estimate(level: Value, records: Value) -> BindingResult<f64> {
    let level: AuditLevel = parse("level", level)?;
    let records = records
        .as_f64()
        .ok_or_else(|| BindingError::invalid_argument("records", "esperado um número"))?;
    let records = millis("records", records.max(0.0).floor())?;
    // O estimado passa de 2^53 só com registros absurdos: a perda de precisão é só de arredondamento.
    Ok(level.estimate_bytes(records) as f64)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn spec() -> Value {
        json!({
            "catalog": {
                "targetKinds": ["project"],
                "broadTargets": ["org"],
                "permissions": [
                    {"key": "project.view", "targets": ["project"]},
                    {"key": "project.edit", "targets": ["project"]}
                ]
            }
        })
    }

    #[test]
    fn decide_and_apply_through_json() {
        let engine = EngineHandle::new(spec()).unwrap();
        let ctx = ContextData::new(Some(json!({
            "grants": [{"id": "g", "subject": {"kind": "role", "id": "member"}, "permission": "project.view",
                        "target": {"kind": "project"}, "effect": "allow"}]
        })))
        .unwrap();
        let request = json!({
            "subject": {"kind": "user", "id": "u", "roles": [{"role": "member"}]},
            "permission": "project.view",
            "resource": {"path": [{"kind": "project", "id": "p1"}]}
        });
        assert!(engine.check(&ctx, request.clone(), None).unwrap());
        assert_eq!(engine.decide(&ctx, request, None).unwrap()["effect"], "allow");

        let out = engine
            .apply(
                json!({
                    "actor": {"kind": "user", "id": "admin"},
                    "current": ctx.grants(),
                    "mutation": {"add": {"id": "g2", "subject": {"kind": "any"}, "permission": "project.edit",
                                         "target": {"kind": "project"}, "effect": "allow"}},
                    "invariants": [{"kind": "catalog_conformance"}],
                    "audit": {"level": "forensic"}
                }),
                Ok(1_700_000_000_000),
            )
            .unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["grants"].as_array().unwrap().len(), 2);
        assert_eq!(out["audit"]["at"], 1_700_000_000_000u64);
        assert!(out["audit"]["hash"].is_string());
    }

    #[test]
    fn role_assignment_returns_the_new_subject() {
        let engine = EngineHandle::new(spec()).unwrap();
        let current = json!([{"id": "g", "subject": {"kind": "role", "id": "member"}, "permission": "project.view",
                              "target": {"kind": "project"}, "effect": "allow"}]);
        let input = |mutation: Value| {
            json!({
                "actor": {"kind": "user", "id": "admin"},
                "current": current,
                "mutation": mutation,
                "invariants": [{"kind": "catalog_conformance"}, {"kind": "no_self_management"}],
                "audit": {"level": "standard"}
            })
        };
        let out = engine
            .apply(
                input(json!({"assign_role": {"subject": {"kind": "user", "id": "bob"}, "role": {"role": "member"}}})),
                Ok(1),
            )
            .unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["subject"]["roles"], json!([{"role": "member"}]));
        assert_eq!(out["grants"].as_array().unwrap().len(), 1);
        assert_eq!(out["audit"]["action"], "role_assign");
        assert_eq!(out["audit"]["role"]["subject"], "bob");

        let out = engine
            .apply(
                input(json!({"revoke_role": {"subject": {"kind": "user", "id": "admin"}, "role": {"role": "member"}}})),
                Ok(1),
            )
            .unwrap();
        assert_eq!(out["ok"], false);
        assert!(out.get("subject").is_none());
        assert_eq!(out["audit"]["action"], "role_revoke");
        assert_eq!(out["audit"]["violations"], json!(["mutation"]));
    }

    #[test]
    fn errors_are_readable() {
        let err =
            EngineHandle::new(json!({"catalog": {"targetKinds": [], "permissions": [{"key": "Bad", "targets": []}]}}))
                .err()
                .unwrap();
        assert_eq!(err.code, "INVALID_SPEC");
        assert!(err.message.contains("chave inválida"));
        assert!(audit_estimate(json!("minimal"), json!(1e6)).unwrap() > 1e8);
    }
    const T0: u64 = 1_700_000_000_000;

    fn allow(id: &str, subject: Value, permission: &str, extra: Value) -> Value {
        let mut grant = json!({"id": id, "subject": subject, "permission": permission,
                               "target": {"kind": "project"}, "effect": "allow"});
        if let (Some(map), Some(extra)) = (grant.as_object_mut(), extra.as_object()) {
            map.extend(extra.clone());
        }
        grant
    }

    fn ana() -> Value {
        json!({"kind": "user", "id": "ana"})
    }

    fn project(id: &str) -> Value {
        json!({"path": [{"kind": "project", "id": id}]})
    }

    fn view(subject: &Value, id: &str) -> Value {
        json!({"subject": subject, "permission": "project.view", "resource": project(id)})
    }

    #[test]
    fn batches_and_json_text_answer_like_one_call_per_request() {
        let engine = EngineHandle::new(spec()).unwrap();
        let ctx = ContextData::new(Some(json!({
            "grants": [allow("g", json!({"kind": "user", "id": "ana"}), "project.view", json!({}))]
        })))
        .unwrap();
        let requests = vec![view(&ana(), "p1"), view(&json!({"kind": "user", "id": "bob"}), "p1")];
        let each: Vec<bool> = requests
            .iter()
            .map(|r| engine.check(&ctx, r.clone(), None).unwrap())
            .collect();
        assert_eq!(each, [true, false]);
        assert_eq!(
            engine.check_many(&ctx, Value::Array(requests.clone()), None).unwrap(),
            each
        );
        let text = serde_json::to_string(&requests).unwrap();
        let inputs = RequestInput::many_from_json(&text).unwrap();
        assert_eq!(engine.check_inputs(&ctx, &inputs, None).unwrap(), each);
        assert_eq!(
            engine.explain_many(&ctx, Value::Array(requests.clone()), None).unwrap(),
            Value::Array(
                requests
                    .iter()
                    .map(|r| engine.explain(&ctx, r.clone(), None).unwrap())
                    .collect()
            )
        );
        assert_eq!(
            engine.decide_input(&ctx, &inputs[0], None).unwrap(),
            engine.decide(&ctx, requests[0].clone(), None).unwrap()
        );
    }

    #[test]
    fn an_unreadable_request_in_a_batch_fails_the_whole_call() {
        let engine = EngineHandle::new(spec()).unwrap();
        let ctx = ContextData::default();
        let bad = json!([view(&ana(), "p1"), {"subject": ana()}]);
        assert_eq!(engine.check_many(&ctx, bad, None).unwrap_err().code, "INVALID_INPUT");
        assert_eq!(
            RequestInput::from_json("{").map(|_| ()).unwrap_err().code,
            "INVALID_INPUT"
        );
        assert_eq!(
            engine.check_many(&ctx, json!("nope"), None).unwrap_err().code,
            "INVALID_INPUT"
        );
    }

    #[test]
    fn decide_honors_the_validity_window_at_now() {
        let engine = EngineHandle::new(spec()).unwrap();
        let grants = json!([allow(
            "future",
            ana_matcher(),
            "project.view",
            json!({"validFrom": T0 + 10})
        ),]);
        let mut ctx = ContextData::new(Some(json!({"grants": grants}))).unwrap();
        ctx.set_now(json!(T0)).unwrap();
        assert!(
            !engine.check(&ctx, view(&ana(), "p1"), None).unwrap(),
            "grant futuro não vale"
        );
        ctx.set_now(json!(T0 + 10)).unwrap();
        assert!(
            engine.check(&ctx, view(&ana(), "p1"), None).unwrap(),
            "vale no início da janela"
        );

        let expiring = json!([allow("old", ana_matcher(), "project.view", json!({"validUntil": T0}))]);
        let mut ctx = ContextData::new(Some(json!({"grants": expiring}))).unwrap();
        ctx.set_now(json!(T0 - 1)).unwrap();
        assert!(engine.check(&ctx, view(&ana(), "p1"), None).unwrap());
        ctx.set_now(json!(T0)).unwrap();
        assert!(
            !engine.check(&ctx, view(&ana(), "p1"), None).unwrap(),
            "validUntil é exclusivo"
        );
    }

    fn ana_matcher() -> Value {
        json!({"kind": "user", "id": "ana"})
    }

    #[test]
    fn invalid_now_is_refused_with_a_code() {
        let mut ctx = ContextData::new(None).unwrap();
        for bad in [json!(-1), json!(1.5), json!("x"), json!(true), json!([]), json!("")] {
            assert_eq!(ctx.set_now(bad).unwrap_err().code, "INVALID_ARGUMENT");
        }
    }

    #[test]
    fn apply_judges_the_actor_window_at_now() {
        let engine = EngineHandle::new(spec()).unwrap();
        let mine = allow("a", ana_matcher(), "project.edit", json!({"validUntil": T0}));
        let input = |now: Value| {
            json!({
                "actor": ana(),
                "current": [mine],
                "mutation": {"add": allow("b", json!({"kind": "user", "id": "bob"}), "project.edit", json!({}))},
                "invariants": [{"kind": "no_escalation"}],
                "audit": {"level": "standard"},
                "now": now
            })
        };
        let before = engine.apply(input(json!(T0 - 1)), Ok(T0 + 5_000)).unwrap();
        assert_eq!(before["ok"], true, "o grant do ator ainda vale");
        assert_eq!(before["audit"]["at"], T0 - 1, "a auditoria usa o instante da entrada");
        let after = engine.apply(input(json!(T0)), Ok(T0 + 5_000)).unwrap();
        assert_eq!(after["ok"], false, "o grant do ator venceu: não pode repassar");
        assert_eq!(after["violations"][0]["invariant"], "no_escalation");

        let fallback = engine.apply(input(Value::Null), Ok(T0 - 1)).unwrap();
        assert_eq!(fallback["ok"], true, "sem now vale o relógio do alvo");
        assert_eq!(fallback["audit"]["at"], T0 - 1);

        for bad in [json!(-1), json!("x"), json!(1.5), json!(true), json!([])] {
            assert_eq!(engine.apply(input(bad), Ok(T0)).unwrap_err().code, "INVALID_ARGUMENT");
        }
        assert_eq!(
            engine.apply(json!({"actor": 5}), Ok(T0)).unwrap_err().code,
            "INVALID_INPUT"
        );
    }

    #[test]
    fn impact_reports_who_gains_before_apply() {
        let engine = EngineHandle::new(spec()).unwrap();
        let mine = allow("a", ana_matcher(), "project.edit", json!({}));
        let bob = json!({"kind": "user", "id": "bob"});
        let input = json!({
            "actor": ana(),
            "current": [mine],
            "mutation": {"add": allow("b", bob.clone(), "project.edit", json!({}))},
            "invariants": [{"kind": "no_escalation"}],
            "impact": {"source": {"kind": "sample", "subjects": [bob.clone()], "resources": [project("p1")]}},
            "now": T0
        });
        let preview = engine.impact(input.clone(), Ok(T0)).unwrap();
        assert_eq!(preview["ok"], true);
        assert_eq!(preview["impact"]["gained"][0]["subject"], "user:bob");
        assert_eq!(preview["impact"]["lost"], json!([]));

        let applied = engine.apply(input, Ok(T0)).unwrap();
        assert_eq!(applied["ok"], true);
        assert_eq!(
            applied["impact"], preview["impact"],
            "apply returns the impact it computed"
        );

        let refused = engine
            .impact(
                json!({
                    "actor": ana(),
                    "current": [],
                    "mutation": {"add": allow("b", bob, "project.edit", json!({}))},
                    "invariants": [{"kind": "no_escalation"}]
                }),
                Ok(T0),
            )
            .unwrap();
        assert_eq!(refused["ok"], false, "a refused change has no impact");
    }

    #[test]
    fn expired_deny_stops_denying_at_its_end() {
        let engine = EngineHandle::new(spec()).unwrap();
        let mut deny = allow("d", ana_matcher(), "project.view", json!({"validUntil": T0}));
        deny["effect"] = json!("deny");
        let grants = json!([allow("a", ana_matcher(), "project.view", json!({})), deny]);
        let mut ctx = ContextData::new(Some(json!({"grants": grants}))).unwrap();
        ctx.set_now(json!(T0 - 1)).unwrap();
        assert!(!engine.check(&ctx, view(&ana(), "p1"), None).unwrap(), "o deny vale");
        ctx.set_now(json!(T0)).unwrap();
        assert!(engine.check(&ctx, view(&ana(), "p1"), None).unwrap(), "o deny venceu");
    }

    #[test]
    fn templates_materialize_and_apply_through_governance() {
        let engine = EngineHandle::new(spec()).unwrap();
        let template = json!({"id": "viewer", "version": 2, "grants": [
            {"id": "view", "permission": "project.view", "target": {"kind": "project"}},
            {"id": "edit", "permission": "project.edit", "target": {"kind": "project"}}
        ]});
        let input = json!({
            "template": template,
            "subject": {"kind": "user", "id": "bob"},
            "idPrefix": "bob"
        });
        let copy = engine.materialize(input.clone()).unwrap();
        assert_eq!(copy["templateVersion"], 2);
        assert_eq!(copy["mutations"][0]["add"]["id"], "bob:view");

        let mut apply = input.clone();
        apply["actor"] = json!({"kind": "user", "id": "root"});
        apply["current"] = json!([]);
        apply["invariants"] = json!([{"kind": "catalog_conformance"}]);
        apply["audit"] = json!({"level": "standard"});
        let out = engine.apply_template(apply.clone(), Ok(T0)).unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["grants"].as_array().unwrap().len(), 2);
        assert_eq!(out["audits"].as_array().unwrap().len(), 2);

        apply["template"]["grants"][0]["permission"] = json!("nope");
        let refused = engine.apply_template(apply.clone(), Ok(T0)).unwrap();
        assert_eq!(refused["ok"], false);
        assert_eq!(
            refused["audits"].as_array().unwrap().len(),
            1,
            "só a recusa vai à trilha"
        );

        apply["now"] = json!("x");
        assert_eq!(
            engine.apply_template(apply, Ok(T0)).unwrap_err().code,
            "INVALID_ARGUMENT"
        );
        assert_eq!(
            engine.materialize(json!({"template": 5})).unwrap_err().code,
            "INVALID_INPUT"
        );
    }

    #[test]
    fn lockout_refusal_carries_the_reserve_suggestion() {
        let engine = EngineHandle::new(spec()).unwrap();
        let owner = json!({"kind": "user", "id": "ana", "roles": [{"role": "owner"}]});
        let zed = json!({"kind": "user", "id": "zed"});
        let input = |reserve: Value| {
            let mut lockout = json!({"kind": "no_lockout", "permissions": ["project.edit"],
                                     "members": [owner, zed], "resource": project("p1")});
            if !reserve.is_null() {
                lockout["reserve"] = reserve;
            }
            json!({
                "actor": {"kind": "user", "id": "root"},
                "current": [allow("o", json!({"kind": "role", "id": "owner"}), "project.edit", json!({}))],
                "mutation": {"revoke_role": {"subject": owner, "role": {"role": "owner"}}},
                "invariants": [lockout]
            })
        };
        let reserve = json!({"adminRole": {"role": "owner"}, "subjects": [zed]});
        let out = engine.apply(input(reserve), Ok(T0)).unwrap();
        assert_eq!(out["ok"], false);
        assert_eq!(out["violations"][0]["invariant"], "no_lockout");
        assert_eq!(out["violations"][0]["suggestion"]["subjectId"], "zed");

        let out = engine.apply(input(Value::Null), Ok(T0)).unwrap();
        assert_eq!(out["ok"], false);
        assert!(
            out["violations"][0].get("suggestion").is_none(),
            "sem reserva não há sugestão"
        );
    }

    #[test]
    fn invalid_grants_are_refused_with_a_code() {
        let engine = EngineHandle::new(spec()).unwrap();
        let inverted = allow(
            "w",
            ana_matcher(),
            "project.view",
            json!({"validFrom": T0, "validUntil": T0}),
        );
        assert_eq!(engine.validate_grant(inverted).unwrap_err().code, "INVALID_GRANT");
        let unknown = allow("u", ana_matcher(), "project.nope", json!({}));
        assert_eq!(engine.validate_grant(unknown).unwrap_err().code, "INVALID_GRANT");
    }

    #[test]
    fn list_returns_the_filter_and_the_ids() {
        let engine = EngineHandle::new(spec()).unwrap();
        let grants = json!([allow(
            "g",
            ana_matcher(),
            "project.edit",
            json!({"target": {"kind": "project", "id": "p1"}})
        )]);
        let mut ctx = ContextData::new(Some(json!({"grants": grants}))).unwrap();
        ctx.set_now(json!(T0)).unwrap();
        let out = engine
            .list(
                &ctx,
                json!({"kind": "user", "id": "ana"}),
                "project.edit",
                "project",
                Some(json!({"resources": [project("p1"), project("p2")]})),
                None,
            )
            .unwrap();
        assert_eq!(out["ids"], json!(["p1"]));
        assert_eq!(out["kind"], "project");

        let err = engine
            .list(&ctx, json!(5), "project.edit", "project", None, None)
            .unwrap_err();
        assert_eq!(err.code, "INVALID_INPUT");
    }

    #[test]
    fn reverse_queries_answer_and_close_over_limits() {
        let engine = EngineHandle::new(spec()).unwrap();
        let grants = json!([allow("g", ana_matcher(), "project.view", json!({}))]);
        let mut ctx = ContextData::new(Some(json!({"grants": grants}))).unwrap();
        ctx.set_now(json!(T0)).unwrap();
        assert_eq!(
            engine.who_can(&ctx, "project.view", None),
            json!([{"type": "user", "id": "ana"}])
        );
        let on = engine.who_can_on(&ctx, "project.view", project("p1"), None).unwrap();
        assert_eq!(on["entries"][0]["via"]["type"], "grant");
        let access = engine.access_of(&ctx, project("p1"), None).unwrap();
        assert_eq!(access[0]["permissions"], json!(["project.view"]));
        let checked = engine
            .check_for(
                &ctx,
                json!({"type": "user", "id": "ana"}),
                "project.view",
                project("p1"),
                json!([{"kind": "user", "id": "ana"}]),
                None,
            )
            .unwrap();
        assert_eq!(checked["allowed"], true);
        let unknown = engine
            .check_for(
                &ctx,
                json!({"type": "user", "id": "zed"}),
                "project.view",
                project("p1"),
                json!([]),
                None,
            )
            .unwrap_err();
        assert_eq!(unknown.code, "UNKNOWN_SUBJECT");

        ctx.set_limits(json!({"maxParties": 0})).unwrap();
        assert_eq!(
            engine
                .who_can_on(&ctx, "project.view", project("p1"), None)
                .unwrap_err()
                .code,
            "QUERY_LIMIT_EXCEEDED"
        );
        assert_eq!(ctx.set_limits(json!(5)).unwrap_err().code, "INVALID_INPUT");
        assert_eq!(
            ctx.set_limits(json!({"maxParties": "x"})).unwrap_err().code,
            "INVALID_ARGUMENT"
        );
    }

    #[test]
    fn exclusive_ownership_grants_preempts_and_refuses() {
        let spec = json!({
            "catalog": {
                "targetKinds": ["slot"],
                "broadTargets": ["org"],
                "permissions": [
                    {"key": "slot.hold", "targets": ["slot"]},
                    {"key": "slot.preempt", "targets": ["slot"]}
                ]
            }
        });
        let engine = EngineHandle::new(spec).unwrap();
        let mut ctx = ContextData::new(Some(json!({"grants": [
            {"id": "h", "subject": {"kind": "any"}, "permission": "slot.hold", "target": {"kind": "slot"}, "effect": "allow"},
        ]})))
        .unwrap();
        ctx.set_now(json!(T0)).unwrap();
        let mut exclusive = ExclusiveHandle::new(Some(
            json!({"permissions": {"hold": "slot.hold", "preempt": "slot.preempt"}}),
        ))
        .unwrap();
        exclusive.validate(&engine).unwrap();
        let slot = json!({"path": [{"kind": "slot", "id": "s1"}]});
        let low = json!({"kind": "user", "id": "low"});
        let out = exclusive
            .acquire(
                &engine,
                &ctx,
                low,
                slot.clone(),
                json!({"priority": 1, "ttlMs": 1000}),
                T0,
            )
            .unwrap();
        assert_eq!(out["outcome"], "granted");
        let high = json!({"kind": "user", "id": "high"});
        let denied = exclusive
            .acquire(
                &engine,
                &ctx,
                high,
                slot.clone(),
                json!({"priority": 9, "ttlMs": 1000}),
                T0,
            )
            .unwrap_err();
        assert_eq!(
            denied.code, "EXCLUSIVE_DENIED",
            "sem a permissão de preempção não toma a posse"
        );

        let err = exclusive
            .release(
                json!({"kind": "slot", "id": "s1"}),
                json!({"kind": "user", "id": "high"}),
                T0,
            )
            .unwrap_err();
        assert_eq!(err.code, "EXCLUSIVE_NOT_HOLDER");
        let err = exclusive
            .acquire(
                &engine,
                &ctx,
                json!({"kind": "user", "id": "x"}),
                slot,
                json!({"priority": 1, "ttlMs": 0}),
                T0,
            )
            .unwrap_err();
        assert_eq!(err.code, "EXCLUSIVE_ZERO_TTL");
        assert_eq!(exclusive.expire(T0 + 1000).unwrap().as_array().unwrap().len(), 1);

        let missing = ExclusiveHandle::new(None).unwrap();
        assert_eq!(
            missing.validate(&engine).unwrap_err().code,
            "EXCLUSIVE_UNKNOWN_PERMISSION"
        );
    }

    #[test]
    fn clock_before_1970_is_an_error_never_zero() {
        let before = std::time::UNIX_EPOCH - std::time::Duration::from_secs(1);
        assert_eq!(clock_ms(before).unwrap_err().code, "INVALID_ARGUMENT");
        let after = std::time::UNIX_EPOCH + std::time::Duration::from_millis(T0);
        assert_eq!(clock_ms(after).unwrap(), T0);
    }

    #[test]
    fn now_arg_refuses_what_is_not_an_instant() {
        assert_eq!(now_arg(None).unwrap(), None);
        assert_eq!(now_arg(Some(Value::Null)).unwrap(), None);
        assert_eq!(now_arg(Some(json!(0))).unwrap(), Some(0));
        assert_eq!(now_arg(Some(json!(T0))).unwrap(), Some(T0));
        for bad in [
            json!("0"),
            json!(""),
            json!(true),
            json!(false),
            json!([]),
            json!({}),
            json!(-1),
            json!(1.5),
        ] {
            assert_eq!(now_arg(Some(bad)).unwrap_err().code, "INVALID_ARGUMENT");
        }
    }

    #[test]
    fn per_call_now_wins_over_the_context_now() {
        let engine = EngineHandle::new(spec()).unwrap();
        let grants = json!([allow("g", ana_matcher(), "project.view", json!({"validUntil": T0}))]);
        let mut ctx = ContextData::new(Some(json!({"grants": grants}))).unwrap();
        ctx.set_now(json!(T0 - 1)).unwrap();
        assert!(engine.check(&ctx, view(&ana(), "p1"), None).unwrap());
        assert!(!engine.check(&ctx, view(&ana(), "p1"), Some(T0)).unwrap());
        assert_eq!(
            engine.decide(&ctx, view(&ana(), "p1"), Some(T0)).unwrap()["effect"],
            "deny"
        );
    }

    #[test]
    fn camel_keys_leaves_user_content_alone() {
        let out = camel_keys(json!({
            "grant_id": "g",
            "attrs": {"snake_key": 1},
            "nested": [{"subject_id": "s", "meta": {"keep_me": true}}]
        }));
        assert_eq!(out["grantId"], "g");
        assert_eq!(out["attrs"]["snake_key"], 1);
        assert_eq!(out["nested"][0]["subjectId"], "s");
        assert_eq!(out["nested"][0]["meta"]["keep_me"], true);
    }

    #[test]
    fn renew_confirms_the_permission_at_the_renewal_instant() {
        let spec = json!({"catalog": {"targetKinds": ["slot"], "broadTargets": ["org"],
                          "permissions": [{"key": "slot.hold", "targets": ["slot"]},
                                          {"key": "slot.preempt", "targets": ["slot"]}]}});
        let engine = EngineHandle::new(spec).unwrap();
        let hold = json!({"id": "h", "subject": {"kind": "any"}, "permission": "slot.hold",
                          "target": {"kind": "slot"}, "effect": "allow", "validUntil": T0 + 500});
        let ctx = ContextData::new(Some(json!({"grants": [hold]}))).unwrap();
        let mut exclusive = ExclusiveHandle::new(Some(
            json!({"permissions": {"hold": "slot.hold", "preempt": "slot.preempt"}}),
        ))
        .unwrap();
        let slot = json!({"path": [{"kind": "slot", "id": "s1"}]});
        let who = json!({"kind": "user", "id": "u"});
        exclusive
            .acquire(
                &engine,
                &ctx,
                who.clone(),
                slot.clone(),
                json!({"priority": 1, "ttlMs": 10_000}),
                T0,
            )
            .unwrap();
        let renewed = exclusive.renew(&engine, &ctx, who.clone(), slot.clone(), 10_000, T0 + 100);
        assert!(renewed.is_ok(), "ainda vale dentro da janela");
        let err = exclusive.renew(&engine, &ctx, who, slot, 10_000, T0 + 500).unwrap_err();
        assert_eq!(err.code, "EXCLUSIVE_DENIED", "o grant venceu: não renova");
    }

    fn host_fn(f: impl Fn(Value) -> Result<Value, String> + Send + Sync + 'static) -> Arc<dyn HostFn> {
        Arc::new(f)
    }

    fn host_request(permission: &str) -> Value {
        json!({
            "subject": {"kind": "user", "id": "u", "roles": [{"role": "member"}]},
            "permission": permission,
            "resource": {"path": [{"kind": "project", "id": "p1"}]}
        })
    }

    fn host_ctx(condition: Value) -> ContextData {
        ContextData::new(Some(json!({
            "grants": [{"id": "g", "subject": {"kind": "role", "id": "member"}, "permission": "project.view",
                        "target": {"kind": "project"}, "effect": "allow", "condition": condition}]
        })))
        .unwrap()
    }

    #[test]
    fn host_condition_function_decides_and_a_throw_does_not_allow() {
        let mut host = HostCallbacks::default();
        host.condition(
            "owns",
            host_fn(|args| match args[0].as_str() {
                Some("boom") => Err("boom".to_string()),
                Some(v) => Ok(json!(v == "yes")),
                None => Ok(json!("not a boolean")),
            }),
        );
        let engine = EngineHandle::with_host(spec(), host).unwrap();
        let call = |arg: &str| host_ctx(json!({"op": "call", "func": "owns", "args": [arg]}));
        assert!(engine.check(&call("yes"), host_request("project.view"), None).unwrap());
        assert!(!engine.check(&call("no"), host_request("project.view"), None).unwrap());
        assert!(!engine.check(&call("boom"), host_request("project.view"), None).unwrap());
        let explained = engine
            .explain(&call("boom"), host_request("project.view"), None)
            .unwrap();
        assert!(explained.to_string().contains("callback: boom"));
        assert!(!engine.check(&call("-"), host_request("project.view"), None).unwrap());
    }

    #[test]
    fn host_override_shows_in_the_trace_and_a_throw_denies() {
        let mut host = HostCallbacks::default();
        host.override_rule(
            "frozen",
            Vec::new(),
            host_fn(|req| match req["permission"].as_str() {
                Some("project.edit") => Ok(json!("allowed")),
                Some("project.view") => Err("down".to_string()),
                _ => Ok(Value::Null),
            }),
        );
        let engine = EngineHandle::with_host(spec(), host).unwrap();
        let ctx = ContextData::new(None).unwrap();
        let allowed = engine.explain(&ctx, host_request("project.edit"), None).unwrap();
        assert_eq!(allowed["decision"]["effect"], "allow");
        assert_eq!(allowed["overrides"][0]["name"], "frozen");
        assert_eq!(allowed["overrides"][0]["outcome"], "allowed");
        let thrown = engine.decide(&ctx, host_request("project.view"), None).unwrap();
        assert_eq!(thrown["effect"], "deny");
        assert_eq!(thrown["reason"]["name"], "frozen");
    }

    #[test]
    fn host_invariant_refuses_with_message_and_throw() {
        let mut host = HostCallbacks::default();
        host.invariant(
            "no_edit",
            host_fn(|input| match input["mutation"]["add"]["permission"].as_str() {
                Some("project.edit") => Ok(json!({"message": "edit is frozen"})),
                Some("project.view") => Err("db down".to_string()),
                _ => Ok(Value::Null),
            }),
        );
        let engine = EngineHandle::with_host(spec(), host).unwrap();
        let apply = |permission: &str, names: Value| {
            engine
                .apply(
                    json!({
                        "actor": {"kind": "user", "id": "admin"},
                        "current": [],
                        "mutation": {"add": {"id": "g", "subject": {"kind": "any"}, "permission": permission,
                                             "target": {"kind": "project"}, "effect": "allow"}},
                        "invariants": names,
                        "audit": {"level": "forensic"}
                    }),
                    Ok(1_700_000_000_000),
                )
                .unwrap()
        };
        let custom = json!([{"kind": "catalog_conformance"}, {"kind": "custom", "name": "no_edit"}]);
        let refused = apply("project.edit", custom.clone());
        assert_eq!(refused["ok"], false);
        assert_eq!(refused["violations"][0]["invariant"], "no_edit");
        assert_eq!(refused["violations"][0]["message"], "edit is frozen");
        assert!(refused["audit"]["hash"].is_string());
        let thrown = apply("project.view", custom.clone());
        assert_eq!(thrown["ok"], false);
        assert_eq!(thrown["violations"][0]["message"], "db down");
        let clean = json!([{"kind": "custom", "name": "no_edit"}]);
        assert_eq!(apply("project.other", clean)["ok"], true);
        let unknown = engine.apply(
            json!({"actor": {"kind": "user", "id": "a"}, "current": [], "mutation": {"remove": {"id": "g"}},
                   "invariants": [{"kind": "custom", "name": "nope"}]}),
            Ok(1),
        );
        assert_eq!(unknown.unwrap_err().code, "UNKNOWN_INVARIANT");
    }

    #[test]
    fn calls_from_inside_a_callback_are_refused() {
        assert!(host::forbid_reentry().is_ok());
        let probe = host_fn(|_| {
            let mut ctx = ContextData::new(None).map_err(|e| e.message)?;
            let err = ctx.set_env(json!({})).unwrap_err();
            assert_eq!(err.code, "REENTRANT_CALL");
            Ok(json!(host::forbid_reentry().is_err()))
        });
        assert_eq!(host::invoke(probe.as_ref(), Value::Null), Ok(json!(true)));
        assert!(host::forbid_reentry().is_ok());
    }
}
