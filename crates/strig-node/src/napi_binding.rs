use std::sync::Arc;

use napi::bindgen_prelude::JsObjectValue;
use napi::bindgen_prelude::{FromNapiValue, Function, FunctionRef, Object, Unknown};
use napi::{Env, JsValue, ValueType, sys};
use napi_derive::napi;
use serde_json::Value;

use crate::{BindingError, ContextData, EngineHandle, ExclusiveHandle, HostCallbacks, HostFn, RequestInput};

/// O `code` estável do erro vira `error.code` no JavaScript.
type Error = napi::Error<String>;
type Result<T> = std::result::Result<T, Error>;

fn err(error: BindingError) -> Error {
    Error::new(error.code.to_string(), error.message)
}

/// Um argumento JavaScript em `serde_json::Value`. O que não é JSON (`NaN`, `±Infinity`, função,
/// símbolo, `undefined` solto) é `INVALID_ARGUMENT`, o mesmo código do alvo wasm: o napi-rs teria
/// falhado com um `InvalidArg` próprio, fora do contrato.
fn json(env: &Env, arg: Unknown<'_>) -> Result<Value> {
    // SAFETY: `env` e `arg` são do mesmo escopo de chamada, e a conversão só lê o valor.
    unsafe { Value::from_napi_value(env.raw(), arg.raw()) }
        .map_err(|e| err(BindingError::invalid_argument("argumento", e)))
}

/// Um argumento opcional: `undefined` e `null` são "sem valor".
fn optional(env: &Env, arg: Option<Unknown<'_>>) -> Result<Option<Value>> {
    match arg {
        None => Ok(None),
        Some(arg) => match json(env, arg)? {
            Value::Null => Ok(None),
            value => Ok(Some(value)),
        },
    }
}

/// Um argumento de texto: qualquer outro tipo é `INVALID_ARGUMENT`, nunca coagido.
fn text(env: &Env, what: &str, arg: Unknown<'_>) -> Result<String> {
    match json(env, arg)? {
        Value::String(text) => Ok(text),
        _ => Err(err(BindingError::invalid_argument(what, "esperado um texto"))),
    }
}

/// O `now` opcional de uma chamada: `undefined` e `null` são "sem instante"; qualquer outra coisa
/// que não seja um inteiro em milissegundos é `INVALID_ARGUMENT`.
fn now_of(env: &Env, now: Option<Unknown<'_>>) -> Result<Option<u64>> {
    crate::now_arg(optional(env, now)?).map_err(err)
}

/// O instante da chamada: o do argumento, ou o relógio do sistema.
fn instant(env: &Env, now: Option<Unknown<'_>>) -> Result<u64> {
    match now_of(env, now)? {
        Some(ms) => Ok(ms),
        None => clock(),
    }
}

fn clock() -> Result<u64> {
    crate::clock_ms(std::time::SystemTime::now()).map_err(err)
}

/// A JavaScript function the engine calls back, kept alive by a reference. It only runs while a
/// call of the host is on the stack (the engine is synchronous), on the thread that registered it.
struct NapiFn {
    callback: FunctionRef<Value, Unknown<'static>>,
    env: sys::napi_env,
}

// SAFETY: the function is only called synchronously from inside an engine call made by JavaScript
// itself, so the `napi_env` is the one of the running thread; nothing is called from elsewhere.
unsafe impl Send for NapiFn {}
unsafe impl Sync for NapiFn {}

impl HostFn for NapiFn {
    fn call(&self, arg: Value) -> std::result::Result<Value, String> {
        let env = Env::from_raw(self.env);
        let function = self.callback.borrow_back(&env).map_err(|e| e.reason.clone())?;
        let answer = function.call(arg).map_err(|e| e.reason.clone())?;
        if answer.get_type().map_err(|e| e.reason.clone())? == ValueType::Undefined {
            return Ok(Value::Null);
        }
        // SAFETY: `answer` belongs to this env and the conversion only reads it.
        unsafe { Value::from_napi_value(self.env, answer.raw()) }.map_err(|e| e.reason.clone())
    }
}

trait Raw<T> {
    fn raw(self) -> Result<T>;
}

impl<T> Raw<T> for napi::Result<T> {
    fn raw(self) -> Result<T> {
        self.map_err(|e| Error::new("INTERNAL".to_string(), e.reason.clone()))
    }
}

fn host_fn(env: &Env, what: &str, value: Unknown<'_>) -> Result<Arc<dyn HostFn>> {
    if value.get_type().raw()? != ValueType::Function {
        return Err(err(BindingError::invalid_argument(what, "esperado uma função")));
    }
    // SAFETY: the value was just checked to be a function of this env.
    let function = unsafe { Function::<Value, Unknown<'static>>::from_napi_value(env.raw(), value.raw()) }.raw()?;
    Ok(Arc::new(NapiFn {
        callback: function.create_ref().raw()?,
        env: env.raw(),
    }))
}

fn object_of<'a>(env: &Env, what: &str, value: Unknown<'a>) -> Result<Object<'a>> {
    if value.get_type().raw()? != ValueType::Object {
        return Err(err(BindingError::invalid_argument(what, "esperado um objeto")));
    }
    // SAFETY: the value was just checked to be an object of this env.
    unsafe { Object::from_napi_value(env.raw(), value.raw()) }.raw()
}

/// The `hooks` argument of the `Engine` constructor: `conditions` (name → function), `overrides`
/// (`{ name, except?, evaluate }[]`) and `invariants` (name → function).
fn hooks_of(env: &Env, hooks: Unknown<'_>) -> Result<HostCallbacks> {
    let hooks = object_of(env, "hooks", hooks)?;
    let mut host = HostCallbacks::default();
    if let Some(conditions) = hooks.get::<Unknown>("conditions").raw()?.filter(is_set) {
        let conditions = object_of(env, "hooks.conditions", conditions)?;
        for name in Object::keys(&conditions).raw()? {
            let f = conditions
                .get::<Unknown>(&name)
                .raw()?
                .ok_or_else(|| err(BindingError::invalid_argument(&name, "ausente")))?;
            host.condition(name.clone(), host_fn(env, &format!("hooks.conditions.{name}"), f)?);
        }
    }
    if let Some(overrides) = hooks.get::<Unknown>("overrides").raw()?.filter(is_set) {
        let overrides = object_of(env, "hooks.overrides", overrides)?;
        for index in 0..overrides.get_array_length().raw()? {
            let rule = object_of(env, "hooks.overrides[]", overrides.get_element::<Unknown>(index).raw()?)?;
            let name: String = rule.get("name").raw()?.ok_or_else(|| {
                err(BindingError::invalid_argument(
                    "hooks.overrides[].name",
                    "esperado um texto",
                ))
            })?;
            let except: Vec<String> = rule.get("except").raw()?.unwrap_or_default();
            let evaluate = rule.get::<Unknown>("evaluate").raw()?.ok_or_else(|| {
                err(BindingError::invalid_argument(
                    "hooks.overrides[].evaluate",
                    "esperado uma função",
                ))
            })?;
            host.override_rule(name, except, host_fn(env, "hooks.overrides[].evaluate", evaluate)?);
        }
    }
    if let Some(invariants) = hooks.get::<Unknown>("invariants").raw()?.filter(is_set) {
        let invariants = object_of(env, "hooks.invariants", invariants)?;
        for name in Object::keys(&invariants).raw()? {
            let f = invariants
                .get::<Unknown>(&name)
                .raw()?
                .ok_or_else(|| err(BindingError::invalid_argument(&name, "ausente")))?;
            host.invariant(name.clone(), host_fn(env, &format!("hooks.invariants.{name}"), f)?);
        }
    }
    if let Some(sink) = hooks.get::<Unknown>("auditSink").raw()?.filter(is_set) {
        host.audit_sink(host_fn(env, "hooks.auditSink", sink)?);
    }
    if let Some(redact) = hooks.get::<Unknown>("auditRedact").raw()?.filter(is_set) {
        host.audit_redact(host_fn(env, "hooks.auditRedact", redact)?);
    }
    if let Some(on_drop) = hooks.get::<Unknown>("onAuditDrop").raw()?.filter(is_set) {
        host.on_audit_drop(host_fn(env, "hooks.onAuditDrop", on_drop)?);
    }
    if let Some(policy) = hooks.get::<Unknown>("auditPolicy").raw()?.filter(is_set) {
        let policy = crate::parse("hooks.auditPolicy", crate::integral(json(env, policy)?)).map_err(err)?;
        host.set_audit_policy(policy);
    }
    Ok(host)
}

fn is_set(value: &Unknown<'_>) -> bool {
    !matches!(value.get_type(), Ok(ValueType::Undefined | ValueType::Null))
}

#[napi(js_name = "Context")]
pub struct JsContext {
    inner: ContextData,
}

#[napi]
impl JsContext {
    #[napi(constructor)]
    pub fn new(env: &Env, init: Option<Unknown<'_>>) -> Result<Self> {
        Ok(Self {
            inner: ContextData::new(optional(env, init)?).map_err(err)?,
        })
    }

    #[napi]
    pub fn set_grants(&mut self, env: &Env, grants: Unknown<'_>) -> Result<()> {
        self.inner.set_grants(json(env, grants)?).map_err(err)
    }

    #[napi]
    pub fn add_grant(&mut self, env: &Env, grant: Unknown<'_>) -> Result<()> {
        self.inner.add_grant(json(env, grant)?).map_err(err)
    }

    #[napi]
    pub fn remove_grant(&mut self, env: &Env, id: Unknown<'_>) -> Result<bool> {
        self.inner.remove_grant(&text(env, "id", id)?).map_err(err)
    }

    #[napi]
    pub fn grants(&self) -> Value {
        self.inner.grants()
    }

    #[napi(getter)]
    pub fn size(&self) -> u32 {
        self.inner.grant_count() as u32
    }

    #[napi]
    pub fn add_tuple(&mut self, env: &Env, tuple: Unknown<'_>) -> Result<bool> {
        self.inner.add_tuple(json(env, tuple)?).map_err(err)
    }

    #[napi]
    pub fn remove_tuple(&mut self, env: &Env, tuple: Unknown<'_>) -> Result<bool> {
        self.inner.remove_tuple(json(env, tuple)?).map_err(err)
    }

    #[napi]
    pub fn set_env(&mut self, env: &Env, attrs: Unknown<'_>) -> Result<()> {
        self.inner.set_env(json(env, attrs)?).map_err(err)
    }

    #[napi]
    pub fn load_capabilities(&mut self, env: &Env, set: Unknown<'_>) -> Result<Value> {
        self.inner.load_capabilities(json(env, set)?).map_err(err)
    }

    /// Instante das decisões e das consultas, em milissegundos UTC; `null` o remove. Um valor que
    /// não é um inteiro em milissegundos (`NaN`, texto, negativo) é recusado e não mexe no instante.
    #[napi]
    pub fn set_now(&mut self, env: &Env, now: Option<Unknown<'_>>) -> Result<()> {
        self.inner
            .set_now(optional(env, now)?.unwrap_or(Value::Null))
            .map_err(err)
    }

    #[napi]
    pub fn set_limits(&mut self, env: &Env, limits: Unknown<'_>) -> Result<()> {
        self.inner.set_limits(json(env, limits)?).map_err(err)
    }
}

#[napi(js_name = "Engine")]
pub struct JsEngine {
    inner: EngineHandle,
}

#[napi]
impl JsEngine {
    #[napi(constructor)]
    pub fn new(env: &Env, spec: Unknown<'_>, hooks: Option<Unknown<'_>>) -> Result<Self> {
        let host = match hooks.filter(is_set) {
            Some(hooks) => hooks_of(env, hooks)?,
            None => HostCallbacks::default(),
        };
        Ok(Self {
            inner: EngineHandle::with_host(json(env, spec)?, host).map_err(err)?,
        })
    }

    #[napi]
    pub fn decide(&self, env: &Env, ctx: &JsContext, request: Unknown<'_>, now: Option<Unknown<'_>>) -> Result<Value> {
        self.inner
            .decide(&ctx.inner, json(env, request)?, now_of(env, now)?)
            .map_err(err)
    }

    #[napi]
    pub fn check(&self, env: &Env, ctx: &JsContext, request: Unknown<'_>, now: Option<Unknown<'_>>) -> Result<bool> {
        self.inner
            .check(&ctx.inner, json(env, request)?, now_of(env, now)?)
            .map_err(err)
    }

    #[napi]
    pub fn explain(&self, env: &Env, ctx: &JsContext, request: Unknown<'_>, now: Option<Unknown<'_>>) -> Result<Value> {
        self.inner
            .explain(&ctx.inner, json(env, request)?, now_of(env, now)?)
            .map_err(err)
    }

    /// The verified changes that would allow a denied request (`null` if it is allowed).
    #[napi]
    pub fn why_not(
        &self,
        env: &Env,
        ctx: &JsContext,
        request: Unknown<'_>,
        now: Option<Unknown<'_>>,
        options: Option<Unknown<'_>>,
    ) -> Result<Value> {
        self.inner
            .why_not(
                &ctx.inner,
                json(env, request)?,
                now_of(env, now)?,
                optional(env, options)?,
            )
            .map_err(err)
    }

    #[napi]
    pub fn allowed_fields(
        &self,
        env: &Env,
        ctx: &JsContext,
        request: Unknown<'_>,
        now: Option<Unknown<'_>>,
    ) -> Result<Value> {
        self.inner
            .allowed_fields(&ctx.inner, json(env, request)?, now_of(env, now)?)
            .map_err(err)
    }

    #[napi]
    pub fn explain_fields(
        &self,
        env: &Env,
        ctx: &JsContext,
        request: Unknown<'_>,
        now: Option<Unknown<'_>>,
    ) -> Result<Value> {
        self.inner
            .explain_fields(&ctx.inner, json(env, request)?, now_of(env, now)?)
            .map_err(err)
    }

    /// Decides every request of the array in one crossing: one boolean per request, in order.
    #[napi]
    pub fn check_many(
        &self,
        env: &Env,
        ctx: &JsContext,
        requests: Unknown<'_>,
        now: Option<Unknown<'_>>,
    ) -> Result<Vec<bool>> {
        self.inner
            .check_many(&ctx.inner, json(env, requests)?, now_of(env, now)?)
            .map_err(err)
    }

    /// `explain` of every request of the array in one crossing.
    #[napi]
    pub fn explain_many(
        &self,
        env: &Env,
        ctx: &JsContext,
        requests: Unknown<'_>,
        now: Option<Unknown<'_>>,
    ) -> Result<Value> {
        self.inner
            .explain_many(&ctx.inner, json(env, requests)?, now_of(env, now)?)
            .map_err(err)
    }

    /// Fast paths: the request arrives as the text the wrapper made with `JSON.stringify`, and
    /// the decision leaves as text for `JSON.parse`, instead of walking the object property by
    /// property through N-API.
    #[napi]
    pub fn check_json(&self, env: &Env, ctx: &JsContext, request: String, now: Option<Unknown<'_>>) -> Result<bool> {
        let input = RequestInput::from_json(&request).map_err(err)?;
        self.inner
            .check_input(&ctx.inner, &input, now_of(env, now)?)
            .map_err(err)
    }

    #[napi]
    pub fn decide_json(&self, env: &Env, ctx: &JsContext, request: String, now: Option<Unknown<'_>>) -> Result<String> {
        let input = RequestInput::from_json(&request).map_err(err)?;
        let decision = self
            .inner
            .decide_input(&ctx.inner, &input, now_of(env, now)?)
            .map_err(err)?;
        Ok(decision.to_string())
    }

    #[napi]
    pub fn explain_json(
        &self,
        env: &Env,
        ctx: &JsContext,
        request: String,
        now: Option<Unknown<'_>>,
    ) -> Result<String> {
        let input = RequestInput::from_json(&request).map_err(err)?;
        let explanation = self
            .inner
            .explain_input(&ctx.inner, &input, now_of(env, now)?)
            .map_err(err)?;
        Ok(explanation.to_string())
    }

    #[napi]
    pub fn check_many_json(
        &self,
        env: &Env,
        ctx: &JsContext,
        requests: String,
        now: Option<Unknown<'_>>,
    ) -> Result<Vec<bool>> {
        let inputs = RequestInput::many_from_json(&requests).map_err(err)?;
        self.inner
            .check_inputs(&ctx.inner, &inputs, now_of(env, now)?)
            .map_err(err)
    }

    #[napi]
    pub fn explain_many_json(
        &self,
        env: &Env,
        ctx: &JsContext,
        requests: String,
        now: Option<Unknown<'_>>,
    ) -> Result<String> {
        let inputs = RequestInput::many_from_json(&requests).map_err(err)?;
        let all = self
            .inner
            .explain_inputs(&ctx.inner, &inputs, now_of(env, now)?)
            .map_err(err)?;
        Ok(all.to_string())
    }

    #[napi]
    pub fn capabilities(
        &self,
        env: &Env,
        ctx: &JsContext,
        subject: Unknown<'_>,
        scope: Unknown<'_>,
        now: Option<Unknown<'_>>,
    ) -> Result<Value> {
        self.inner
            .capabilities(&ctx.inner, json(env, subject)?, json(env, scope)?, now_of(env, now)?)
            .map_err(err)
    }

    #[napi]
    pub fn validate_grant(&self, env: &Env, grant: Unknown<'_>) -> Result<()> {
        self.inner.validate_grant(json(env, grant)?).map_err(err)
    }

    #[napi]
    pub fn catalog(&self) -> Value {
        self.inner.catalog()
    }

    #[napi]
    pub fn apply(&self, env: &Env, input: Unknown<'_>) -> Result<Value> {
        self.inner
            .apply(json(env, input)?, crate::clock_ms(std::time::SystemTime::now()))
            .map_err(err)
    }

    /// What a change would do to access: who gains, who loses, what cannot be settled. Nothing is applied.
    #[napi]
    pub fn impact(&self, env: &Env, input: Unknown<'_>) -> Result<Value> {
        self.inner
            .impact(json(env, input)?, crate::clock_ms(std::time::SystemTime::now()))
            .map_err(err)
    }

    /// The impact of a pending request as proposed and as it would be now.
    #[napi]
    pub fn review_impact(&self, env: &Env, input: Unknown<'_>) -> Result<Value> {
        self.inner
            .review_impact(json(env, input)?, crate::clock_ms(std::time::SystemTime::now()))
            .map_err(err)
    }

    /// Proposes a change: applied at once, or kept as a pending request when the approval policy asks for it.
    #[napi]
    pub fn propose(&self, env: &Env, input: Unknown<'_>) -> Result<Value> {
        self.inner
            .propose(json(env, input)?, crate::clock_ms(std::time::SystemTime::now()))
            .map_err(err)
    }

    /// Approves or refuses a pending request.
    #[napi]
    pub fn resolve(&self, env: &Env, input: Unknown<'_>) -> Result<Value> {
        self.inner
            .resolve(json(env, input)?, crate::clock_ms(std::time::SystemTime::now()))
            .map_err(err)
    }

    /// Requests, approves, refuses, revokes or reviews a temporary elevation (break-glass included).
    #[napi]
    pub fn elevate(&self, env: &Env, input: Unknown<'_>) -> Result<Value> {
        self.inner
            .elevate(json(env, input)?, crate::clock_ms(std::time::SystemTime::now()))
            .map_err(err)
    }

    /// Opens, decides, closes or reports an access recertification campaign.
    #[napi]
    pub fn recertify(&self, env: &Env, input: Unknown<'_>) -> Result<Value> {
        self.inner
            .recertify(json(env, input)?, crate::clock_ms(std::time::SystemTime::now()))
            .map_err(err)
    }

    /// Closes the pending requests whose expiry has come.
    #[napi]
    pub fn expire(&self, env: &Env, input: Unknown<'_>) -> Result<Value> {
        self.inner
            .expire(json(env, input)?, crate::clock_ms(std::time::SystemTime::now()))
            .map_err(err)
    }

    /// Tries to write the audit records waiting in the retry queue and answers its counters.
    #[napi]
    pub fn flush_audit(&self) -> Result<Value> {
        self.inner
            .flush_audit(crate::clock_ms(std::time::SystemTime::now()))
            .map_err(err)
    }

    #[napi]
    pub fn audit_stats(&self) -> Value {
        self.inner.audit_stats()
    }

    #[napi]
    pub fn materialize(&self, env: &Env, input: Unknown<'_>) -> Result<Value> {
        self.inner.materialize(json(env, input)?).map_err(err)
    }

    #[napi]
    pub fn apply_template(&self, env: &Env, input: Unknown<'_>) -> Result<Value> {
        self.inner
            .apply_template(json(env, input)?, crate::clock_ms(std::time::SystemTime::now()))
            .map_err(err)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the JavaScript signature, one argument per parameter"
    )]
    #[napi]
    pub fn list(
        &self,
        env: &Env,
        ctx: &JsContext,
        subject: Unknown<'_>,
        permission: Unknown<'_>,
        kind: Unknown<'_>,
        options: Option<Unknown<'_>>,
        now: Option<Unknown<'_>>,
    ) -> Result<Value> {
        self.inner
            .list(
                &ctx.inner,
                json(env, subject)?,
                &text(env, "permission", permission)?,
                &text(env, "kind", kind)?,
                optional(env, options)?,
                now_of(env, now)?,
            )
            .map_err(err)
    }

    #[napi]
    pub fn who_can(
        &self,
        env: &Env,
        ctx: &JsContext,
        permission: Unknown<'_>,
        now: Option<Unknown<'_>>,
    ) -> Result<Value> {
        Ok(self
            .inner
            .who_can(&ctx.inner, &text(env, "permission", permission)?, now_of(env, now)?))
    }

    #[napi]
    pub fn who_can_on(
        &self,
        env: &Env,
        ctx: &JsContext,
        permission: Unknown<'_>,
        resource: Unknown<'_>,
        now: Option<Unknown<'_>>,
    ) -> Result<Value> {
        self.inner
            .who_can_on(
                &ctx.inner,
                &text(env, "permission", permission)?,
                json(env, resource)?,
                now_of(env, now)?,
            )
            .map_err(err)
    }

    #[napi]
    pub fn access_of(
        &self,
        env: &Env,
        ctx: &JsContext,
        resource: Unknown<'_>,
        now: Option<Unknown<'_>>,
    ) -> Result<Value> {
        self.inner
            .access_of(&ctx.inner, json(env, resource)?, now_of(env, now)?)
            .map_err(err)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the JavaScript signature, one argument per parameter"
    )]
    #[napi]
    pub fn check_for(
        &self,
        env: &Env,
        ctx: &JsContext,
        subject_ref: Unknown<'_>,
        permission: Unknown<'_>,
        resource: Unknown<'_>,
        subjects: Unknown<'_>,
        now: Option<Unknown<'_>>,
    ) -> Result<Value> {
        self.inner
            .check_for(
                &ctx.inner,
                json(env, subject_ref)?,
                &text(env, "permission", permission)?,
                json(env, resource)?,
                json(env, subjects)?,
                now_of(env, now)?,
            )
            .map_err(err)
    }
}

#[napi(js_name = "Exclusive")]
pub struct JsExclusive {
    inner: ExclusiveHandle,
}

#[napi]
impl JsExclusive {
    #[napi(constructor)]
    pub fn new(env: &Env, options: Option<Unknown<'_>>) -> Result<Self> {
        Ok(Self {
            inner: ExclusiveHandle::new(optional(env, options)?).map_err(err)?,
        })
    }

    #[napi]
    pub fn validate(&self, engine: &JsEngine) -> Result<()> {
        self.inner.validate(&engine.inner).map_err(err)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the JavaScript signature, one argument per parameter"
    )]
    #[napi]
    pub fn acquire(
        &mut self,
        env: &Env,
        engine: &JsEngine,
        ctx: &JsContext,
        subject: Unknown<'_>,
        resource: Unknown<'_>,
        terms: Unknown<'_>,
        now: Option<Unknown<'_>>,
    ) -> Result<Value> {
        let now = instant(env, now)?;
        self.inner
            .acquire(
                &engine.inner,
                &ctx.inner,
                json(env, subject)?,
                json(env, resource)?,
                json(env, terms)?,
                now,
            )
            .map_err(err)
    }

    #[napi]
    pub fn holder(&self, env: &Env, resource: Unknown<'_>, now: Option<Unknown<'_>>) -> Result<Value> {
        self.inner.holder(json(env, resource)?, instant(env, now)?).map_err(err)
    }

    #[napi]
    pub fn release(
        &mut self,
        env: &Env,
        resource: Unknown<'_>,
        holder: Unknown<'_>,
        now: Option<Unknown<'_>>,
    ) -> Result<Value> {
        self.inner
            .release(json(env, resource)?, json(env, holder)?, instant(env, now)?)
            .map_err(err)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the JavaScript signature, one argument per parameter"
    )]
    #[napi]
    pub fn renew(
        &mut self,
        env: &Env,
        engine: &JsEngine,
        ctx: &JsContext,
        subject: Unknown<'_>,
        resource: Unknown<'_>,
        ttl_ms: Unknown<'_>,
        now: Option<Unknown<'_>>,
    ) -> Result<Value> {
        let ttl = crate::exclusive::ttl(&json(env, ttl_ms)?).map_err(err)?;
        let now = instant(env, now)?;
        self.inner
            .renew(
                &engine.inner,
                &ctx.inner,
                json(env, subject)?,
                json(env, resource)?,
                ttl,
                now,
            )
            .map_err(err)
    }

    #[napi]
    pub fn expire(&mut self, env: &Env, now: Option<Unknown<'_>>) -> Result<Value> {
        self.inner.expire(instant(env, now)?).map_err(err)
    }
}

#[napi]
pub fn audit_estimate(env: &Env, level: Unknown<'_>, records: Unknown<'_>) -> Result<f64> {
    crate::audit_estimate(json(env, level)?, json(env, records)?).map_err(err)
}

#[napi]
pub fn verify_audit_chain(env: &Env, records: Unknown<'_>, anchors: Option<Unknown<'_>>) -> Result<Value> {
    crate::verify_audit_chain(json(env, records)?, optional(env, anchors)?).map_err(err)
}

#[napi]
pub fn verify_merkle_inclusion(env: &Env, input: Unknown<'_>) -> Result<Value> {
    crate::verify_merkle_inclusion(json(env, input)?).map_err(err)
}

#[napi]
pub fn verify_merkle_consistency(env: &Env, input: Unknown<'_>) -> Result<Value> {
    crate::verify_merkle_consistency(json(env, input)?).map_err(err)
}

#[napi]
pub fn verify_timestamp(env: &Env, input: Unknown<'_>) -> Result<Value> {
    crate::verify_timestamp(json(env, input)?).map_err(err)
}

/// Um argumento da linguagem: o que não é JSON vira o `INVALID_ARGUMENT` do envelope.
fn dsl_arg(env: &Env, arg: Unknown<'_>) -> std::result::Result<Value, crate::dsl::DslFailure> {
    json(env, arg).map_err(|e| BindingError::invalid_argument("argumento", &e.reason).into())
}

#[napi]
pub fn dsl_compile(env: &Env, text: Unknown<'_>, options: Option<Unknown<'_>>) -> Value {
    crate::dsl::envelope((|| {
        let options = match options {
            Some(o) => Some(dsl_arg(env, o)?),
            None => None,
        };
        crate::dsl::compile(&dsl_arg(env, text)?, options.as_ref())
    })())
}

#[napi]
pub fn dsl_print(env: &Env, policy: Unknown<'_>, language: Unknown<'_>) -> Value {
    crate::dsl::envelope((|| crate::dsl::print(&dsl_arg(env, policy)?, &dsl_arg(env, language)?))())
}

#[napi]
pub fn dsl_convert(env: &Env, text: Unknown<'_>, language: Unknown<'_>) -> Value {
    crate::dsl::envelope((|| crate::dsl::convert(&dsl_arg(env, text)?, &dsl_arg(env, language)?))())
}

#[napi]
pub fn dsl_format(env: &Env, text: Unknown<'_>, options: Option<Unknown<'_>>) -> Value {
    crate::dsl::envelope((|| {
        let options = match options {
            Some(o) => Some(dsl_arg(env, o)?),
            None => None,
        };
        crate::dsl::format(&dsl_arg(env, text)?, options.as_ref())
    })())
}

#[napi]
pub fn dsl_is_formatted(env: &Env, text: Unknown<'_>, options: Option<Unknown<'_>>) -> Value {
    crate::dsl::envelope((|| {
        let options = match options {
            Some(o) => Some(dsl_arg(env, o)?),
            None => None,
        };
        crate::dsl::is_formatted(&dsl_arg(env, text)?, options.as_ref())
    })())
}

#[napi]
pub fn dsl_load_project(env: &Env, sources: Unknown<'_>) -> Value {
    crate::dsl::envelope((|| crate::dsl::load_project(&dsl_arg(env, sources)?))())
}

#[napi]
pub fn dsl_run_tests(env: &Env, policy: Unknown<'_>, tests: Unknown<'_>) -> Value {
    crate::dsl::envelope((|| {
        crate::dsl::run_tests(&dsl_arg(env, policy)?, &dsl_arg(env, tests)?)
    })())
}

#[napi]
pub fn dsl_diff(env: &Env, before: Unknown<'_>, after: Unknown<'_>, options: Option<Unknown<'_>>) -> Value {
    crate::dsl::envelope((|| {
        let options = match options {
            Some(o) => Some(dsl_arg(env, o)?),
            None => None,
        };
        crate::dsl::diff_policies(&dsl_arg(env, before)?, &dsl_arg(env, after)?, options.as_ref())
    })())
}

#[napi]
pub fn dsl_lint(env: &Env, policy: Unknown<'_>, options: Option<Unknown<'_>>) -> Value {
    crate::dsl::envelope((|| {
        let options = match options {
            Some(o) => Some(dsl_arg(env, o)?),
            None => None,
        };
        crate::dsl::lint_policy(&dsl_arg(env, policy)?, options.as_ref())
    })())
}

#[napi]
pub fn dsl_load_project_dir(env: &Env, dir: Unknown<'_>) -> Value {
    crate::dsl::envelope((|| crate::dsl::load_project_dir(&dsl_arg(env, dir)?))())
}

#[napi]
pub fn backend() -> &'static str {
    "native"
}
