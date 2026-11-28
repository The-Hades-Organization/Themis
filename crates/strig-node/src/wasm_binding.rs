use serde::Serialize;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use wasm_bindgen::prelude::*;

use std::sync::Arc;

use crate::{BindingError, ContextData, EngineHandle, ExclusiveHandle, HostCallbacks, HostFn, RequestInput};

/// Um `Error` do JavaScript com o `code` estável do binding.
type JsFailure = JsValue;

fn err(error: BindingError) -> JsFailure {
    let failure = js_sys::Error::new(&error.message);
    // Definir uma propriedade num objeto novo e extensível não falha; se falhasse, o erro sairia
    // sem `code`, mas ainda com a mensagem.
    js_sys::Reflect::set(&failure, &JsValue::from_str("code"), &JsValue::from_str(error.code)).ok();
    failure.into()
}

/// Um valor JavaScript em `serde_json::Value` que recusa o que não é JSON: `NaN` e `±Infinity`
/// viram erro, em vez de `null` (que é o que o `Value` faz com um float não finito e que, num
/// `now`, apagaria o instante).
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Walk;

        impl<'de> Visitor<'de> for Walk {
            type Value = Strict;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("um valor JSON")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }

            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Strict, E> {
                if v.is_finite() {
                    Ok(Strict(Value::from(v)))
                } else {
                    Err(E::custom("número não finito (NaN ou Infinity)"))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(v.to_string())))
            }

            fn visit_string<E>(self, v: String) -> Result<Strict, E> {
                Ok(Strict(Value::String(v)))
            }

            fn visit_unit<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }

            fn visit_none<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }

            fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Strict, D::Error> {
                Strict::deserialize(deserializer)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut items = Vec::new();
                while let Some(Strict(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Strict(Value::Array(items)))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut fields = Map::new();
                while let Some((key, Strict(value))) = map.next_entry::<String, Strict>()? {
                    fields.insert(key, value);
                }
                Ok(Strict(Value::Object(fields)))
            }
        }

        deserializer.deserialize_any(Walk)
    }
}

fn from_js(value: JsValue) -> Result<Value, JsFailure> {
    Strict::deserialize(serde_wasm_bindgen::Deserializer::from(value))
        .map(|strict| strict.0)
        .map_err(|e| err(BindingError::invalid_argument("argumento", e)))
}

/// Um argumento de texto: qualquer outro tipo é `INVALID_ARGUMENT`, nunca coagido.
fn text(what: &str, value: &JsValue) -> Result<String, JsFailure> {
    value
        .as_string()
        .ok_or_else(|| err(BindingError::invalid_argument(what, "esperado um texto")))
}

fn to_js(value: &Value) -> Result<JsValue, JsFailure> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| err(BindingError::new("INTERNAL", e.to_string())))
}

fn optional(value: JsValue) -> Result<Option<Value>, JsFailure> {
    if value.is_undefined() || value.is_null() {
        Ok(None)
    } else {
        from_js(value).map(Some)
    }
}

/// O `now` opcional de uma chamada: `undefined` e `null` são "sem instante"; qualquer outra coisa
/// que não seja um inteiro em milissegundos é `INVALID_ARGUMENT`.
fn now_of(now: JsValue) -> Result<Option<u64>, JsFailure> {
    crate::now_arg(optional(now)?).map_err(err)
}

/// O instante da chamada: o do argumento, ou o relógio do navegador.
fn instant(now: JsValue) -> Result<u64, JsFailure> {
    match now_of(now)? {
        Some(ms) => Ok(ms),
        None => crate::millis("now", js_sys::Date::now()).map_err(err),
    }
}

#[wasm_bindgen(js_name = Context)]
pub struct WasmContext {
    inner: ContextData,
}

#[wasm_bindgen(js_class = Context)]
impl WasmContext {
    #[wasm_bindgen(constructor)]
    pub fn new(init: JsValue) -> Result<WasmContext, JsFailure> {
        Ok(Self {
            inner: ContextData::new(optional(init)?).map_err(err)?,
        })
    }

    #[wasm_bindgen(js_name = setGrants)]
    pub fn set_grants(&mut self, grants: JsValue) -> Result<(), JsFailure> {
        self.inner.set_grants(from_js(grants)?).map_err(err)
    }

    #[wasm_bindgen(js_name = addGrant)]
    pub fn add_grant(&mut self, grant: JsValue) -> Result<(), JsFailure> {
        self.inner.add_grant(from_js(grant)?).map_err(err)
    }

    #[wasm_bindgen(js_name = removeGrant)]
    pub fn remove_grant(&mut self, id: JsValue) -> Result<bool, JsFailure> {
        self.inner.remove_grant(&text("id", &id)?).map_err(err)
    }

    pub fn grants(&self) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.grants())
    }

    #[wasm_bindgen(getter)]
    pub fn size(&self) -> u32 {
        self.inner.grant_count() as u32
    }

    #[wasm_bindgen(js_name = addTuple)]
    pub fn add_tuple(&mut self, tuple: JsValue) -> Result<bool, JsFailure> {
        self.inner.add_tuple(from_js(tuple)?).map_err(err)
    }

    #[wasm_bindgen(js_name = removeTuple)]
    pub fn remove_tuple(&mut self, tuple: JsValue) -> Result<bool, JsFailure> {
        self.inner.remove_tuple(from_js(tuple)?).map_err(err)
    }

    #[wasm_bindgen(js_name = setEnv)]
    pub fn set_env(&mut self, env: JsValue) -> Result<(), JsFailure> {
        self.inner.set_env(from_js(env)?).map_err(err)
    }

    #[wasm_bindgen(js_name = loadCapabilities)]
    pub fn load_capabilities(&mut self, set: JsValue) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.load_capabilities(from_js(set)?).map_err(err)?)
    }

    /// Instante das decisões e das consultas, em milissegundos UTC; `null` o remove.
    #[wasm_bindgen(js_name = setNow)]
    pub fn set_now(&mut self, now: JsValue) -> Result<(), JsFailure> {
        self.inner.set_now(optional(now)?.unwrap_or(Value::Null)).map_err(err)
    }

    #[wasm_bindgen(js_name = setLimits)]
    pub fn set_limits(&mut self, limits: JsValue) -> Result<(), JsFailure> {
        self.inner.set_limits(from_js(limits)?).map_err(err)
    }
}

/// A JavaScript function the engine calls back, synchronously, from inside a call of the host.
struct WasmFn(js_sys::Function);

// SAFETY: wasm32 here is single-threaded; the function is never touched from another thread.
unsafe impl Send for WasmFn {}
unsafe impl Sync for WasmFn {}

fn thrown(error: JsValue) -> String {
    match error.dyn_ref::<js_sys::Error>() {
        Some(e) => String::from(e.message()),
        None => error.as_string().unwrap_or_else(|| "a callback threw".to_string()),
    }
}

impl HostFn for WasmFn {
    fn call(&self, arg: Value) -> Result<Value, String> {
        let arg = to_js(&arg).map_err(thrown)?;
        let answer = self.0.call1(&JsValue::UNDEFINED, &arg).map_err(thrown)?;
        if answer.is_undefined() {
            return Ok(Value::Null);
        }
        from_js(answer).map_err(thrown)
    }
}

fn host_fn(what: &str, value: JsValue) -> Result<Arc<dyn HostFn>, JsFailure> {
    value
        .dyn_into::<js_sys::Function>()
        .map(|f| Arc::new(WasmFn(f)) as Arc<dyn HostFn>)
        .map_err(|_| err(BindingError::invalid_argument(what, "esperado uma função")))
}

fn field(target: &JsValue, key: &str) -> Result<JsValue, JsFailure> {
    js_sys::Reflect::get(target, &JsValue::from_str(key))
        .map_err(|_| err(BindingError::invalid_argument(key, "ilegível")))
}

fn entries_of(what: &str, value: &JsValue) -> Result<Vec<(String, JsValue)>, JsFailure> {
    if !value.is_object() {
        return Err(err(BindingError::invalid_argument(what, "esperado um objeto")));
    }
    js_sys::Object::keys(value.unchecked_ref::<js_sys::Object>())
        .iter()
        .map(|key| {
            let name = key.as_string().unwrap_or_default();
            Ok((name.clone(), field(value, &name)?))
        })
        .collect()
}

/// The `hooks` argument of the `Engine` constructor: `conditions` (name → function), `overrides`
/// (`{ name, except?, evaluate }[]`) and `invariants` (name → function).
fn hooks_of(hooks: &JsValue) -> Result<HostCallbacks, JsFailure> {
    if !hooks.is_object() {
        return Err(err(BindingError::invalid_argument("hooks", "esperado um objeto")));
    }
    let mut host = HostCallbacks::default();
    let set = |v: &JsValue| !(v.is_undefined() || v.is_null());
    let conditions = field(hooks, "conditions")?;
    if set(&conditions) {
        for (name, f) in entries_of("hooks.conditions", &conditions)? {
            host.condition(name.clone(), host_fn(&format!("hooks.conditions.{name}"), f)?);
        }
    }
    let overrides = field(hooks, "overrides")?;
    if set(&overrides) {
        if !js_sys::Array::is_array(&overrides) {
            return Err(err(BindingError::invalid_argument(
                "hooks.overrides",
                "esperado uma lista",
            )));
        }
        for rule in js_sys::Array::from(&overrides).iter() {
            let name = text("hooks.overrides[].name", &field(&rule, "name")?)?;
            let except = match optional(field(&rule, "except")?)? {
                None => Vec::new(),
                Some(value) => crate::parse::<Vec<String>>("hooks.overrides[].except", value).map_err(err)?,
            };
            host.override_rule(
                name,
                except,
                host_fn("hooks.overrides[].evaluate", field(&rule, "evaluate")?)?,
            );
        }
    }
    let invariants = field(hooks, "invariants")?;
    if set(&invariants) {
        for (name, f) in entries_of("hooks.invariants", &invariants)? {
            host.invariant(name.clone(), host_fn(&format!("hooks.invariants.{name}"), f)?);
        }
    }
    let sink = field(hooks, "auditSink")?;
    if set(&sink) {
        host.audit_sink(host_fn("hooks.auditSink", sink)?);
    }
    let redact = field(hooks, "auditRedact")?;
    if set(&redact) {
        host.audit_redact(host_fn("hooks.auditRedact", redact)?);
    }
    let on_drop = field(hooks, "onAuditDrop")?;
    if set(&on_drop) {
        host.on_audit_drop(host_fn("hooks.onAuditDrop", on_drop)?);
    }
    let policy = field(hooks, "auditPolicy")?;
    if set(&policy) {
        host.set_audit_policy(crate::parse("hooks.auditPolicy", from_js(policy)?).map_err(err)?);
    }
    Ok(host)
}

#[wasm_bindgen(js_name = Engine)]
pub struct WasmEngine {
    inner: EngineHandle,
}

#[wasm_bindgen(js_class = Engine)]
impl WasmEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(spec: JsValue, hooks: JsValue) -> Result<WasmEngine, JsFailure> {
        let host = if hooks.is_undefined() || hooks.is_null() {
            HostCallbacks::default()
        } else {
            hooks_of(&hooks)?
        };
        Ok(Self {
            inner: EngineHandle::with_host(from_js(spec)?, host).map_err(err)?,
        })
    }

    pub fn decide(&self, ctx: &WasmContext, request: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .decide(&ctx.inner, from_js(request)?, now_of(now)?)
                .map_err(err)?,
        )
    }

    pub fn check(&self, ctx: &WasmContext, request: JsValue, now: JsValue) -> Result<bool, JsFailure> {
        self.inner
            .check(&ctx.inner, from_js(request)?, now_of(now)?)
            .map_err(err)
    }

    pub fn explain(&self, ctx: &WasmContext, request: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .explain(&ctx.inner, from_js(request)?, now_of(now)?)
                .map_err(err)?,
        )
    }

    #[wasm_bindgen(js_name = whyNot)]
    pub fn why_not(
        &self,
        ctx: &WasmContext,
        request: JsValue,
        now: JsValue,
        options: JsValue,
    ) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .why_not(&ctx.inner, from_js(request)?, now_of(now)?, optional(options)?)
                .map_err(err)?,
        )
    }

    #[wasm_bindgen(js_name = allowedFields)]
    pub fn allowed_fields(&self, ctx: &WasmContext, request: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .allowed_fields(&ctx.inner, from_js(request)?, now_of(now)?)
                .map_err(err)?,
        )
    }

    #[wasm_bindgen(js_name = explainFields)]
    pub fn explain_fields(&self, ctx: &WasmContext, request: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .explain_fields(&ctx.inner, from_js(request)?, now_of(now)?)
                .map_err(err)?,
        )
    }

    #[wasm_bindgen(js_name = checkMany)]
    pub fn check_many(&self, ctx: &WasmContext, requests: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        let answers = self
            .inner
            .check_many(&ctx.inner, from_js(requests)?, now_of(now)?)
            .map_err(err)?;
        to_js(&Value::Array(answers.into_iter().map(Value::Bool).collect()))
    }

    #[wasm_bindgen(js_name = explainMany)]
    pub fn explain_many(&self, ctx: &WasmContext, requests: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .explain_many(&ctx.inner, from_js(requests)?, now_of(now)?)
                .map_err(err)?,
        )
    }

    /// Fast paths: the request arrives as the text the wrapper made with `JSON.stringify`, and the
    /// decision leaves as text for `JSON.parse`, instead of walking the object through the glue.
    #[wasm_bindgen(js_name = checkJson)]
    pub fn check_json(&self, ctx: &WasmContext, request: &str, now: JsValue) -> Result<bool, JsFailure> {
        let input = RequestInput::from_json(request).map_err(err)?;
        self.inner.check_input(&ctx.inner, &input, now_of(now)?).map_err(err)
    }

    #[wasm_bindgen(js_name = decideJson)]
    pub fn decide_json(&self, ctx: &WasmContext, request: &str, now: JsValue) -> Result<String, JsFailure> {
        let input = RequestInput::from_json(request).map_err(err)?;
        let decision = self.inner.decide_input(&ctx.inner, &input, now_of(now)?).map_err(err)?;
        Ok(decision.to_string())
    }

    #[wasm_bindgen(js_name = explainJson)]
    pub fn explain_json(&self, ctx: &WasmContext, request: &str, now: JsValue) -> Result<String, JsFailure> {
        let input = RequestInput::from_json(request).map_err(err)?;
        let explanation = self
            .inner
            .explain_input(&ctx.inner, &input, now_of(now)?)
            .map_err(err)?;
        Ok(explanation.to_string())
    }

    #[wasm_bindgen(js_name = checkManyJson)]
    pub fn check_many_json(&self, ctx: &WasmContext, requests: &str, now: JsValue) -> Result<JsValue, JsFailure> {
        let inputs = RequestInput::many_from_json(requests).map_err(err)?;
        let answers = self
            .inner
            .check_inputs(&ctx.inner, &inputs, now_of(now)?)
            .map_err(err)?;
        to_js(&Value::Array(answers.into_iter().map(Value::Bool).collect()))
    }

    #[wasm_bindgen(js_name = explainManyJson)]
    pub fn explain_many_json(&self, ctx: &WasmContext, requests: &str, now: JsValue) -> Result<String, JsFailure> {
        let inputs = RequestInput::many_from_json(requests).map_err(err)?;
        let all = self
            .inner
            .explain_inputs(&ctx.inner, &inputs, now_of(now)?)
            .map_err(err)?;
        Ok(all.to_string())
    }

    pub fn capabilities(
        &self,
        ctx: &WasmContext,
        subject: JsValue,
        scope: JsValue,
        now: JsValue,
    ) -> Result<JsValue, JsFailure> {
        let set = self
            .inner
            .capabilities(&ctx.inner, from_js(subject)?, from_js(scope)?, now_of(now)?)
            .map_err(err)?;
        to_js(&set)
    }

    #[wasm_bindgen(js_name = validateGrant)]
    pub fn validate_grant(&self, grant: JsValue) -> Result<(), JsFailure> {
        self.inner.validate_grant(from_js(grant)?).map_err(err)
    }

    pub fn catalog(&self) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.catalog())
    }

    pub fn apply(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .apply(from_js(input)?, crate::millis("now", js_sys::Date::now()))
                .map_err(err)?,
        )
    }

    pub fn impact(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .impact(from_js(input)?, crate::millis("now", js_sys::Date::now()))
                .map_err(err)?,
        )
    }

    #[wasm_bindgen(js_name = reviewImpact)]
    pub fn review_impact(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .review_impact(from_js(input)?, crate::millis("now", js_sys::Date::now()))
                .map_err(err)?,
        )
    }

    pub fn propose(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .propose(from_js(input)?, crate::millis("now", js_sys::Date::now()))
                .map_err(err)?,
        )
    }

    pub fn resolve(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .resolve(from_js(input)?, crate::millis("now", js_sys::Date::now()))
                .map_err(err)?,
        )
    }

    pub fn elevate(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .elevate(from_js(input)?, crate::millis("now", js_sys::Date::now()))
                .map_err(err)?,
        )
    }

    pub fn recertify(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .recertify(from_js(input)?, crate::millis("now", js_sys::Date::now()))
                .map_err(err)?,
        )
    }

    pub fn expire(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .expire(from_js(input)?, crate::millis("now", js_sys::Date::now()))
                .map_err(err)?,
        )
    }

    #[wasm_bindgen(js_name = flushAudit)]
    pub fn flush_audit(&self) -> Result<JsValue, JsFailure> {
        let now = crate::millis("now", js_sys::Date::now());
        to_js(&self.inner.flush_audit(now).map_err(err)?)
    }

    #[wasm_bindgen(js_name = auditStats)]
    pub fn audit_stats(&self) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.audit_stats())
    }

    pub fn materialize(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.materialize(from_js(input)?).map_err(err)?)
    }

    #[wasm_bindgen(js_name = applyTemplate)]
    pub fn apply_template(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .apply_template(from_js(input)?, crate::millis("now", js_sys::Date::now()))
                .map_err(err)?,
        )
    }

    pub fn list(
        &self,
        ctx: &WasmContext,
        subject: JsValue,
        permission: JsValue,
        kind: JsValue,
        options: JsValue,
        now: JsValue,
    ) -> Result<JsValue, JsFailure> {
        let out = self
            .inner
            .list(
                &ctx.inner,
                from_js(subject)?,
                &text("permission", &permission)?,
                &text("kind", &kind)?,
                optional(options)?,
                now_of(now)?,
            )
            .map_err(err)?;
        to_js(&out)
    }

    #[wasm_bindgen(js_name = whoCan)]
    pub fn who_can(&self, ctx: &WasmContext, permission: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .who_can(&ctx.inner, &text("permission", &permission)?, now_of(now)?),
        )
    }

    #[wasm_bindgen(js_name = whoCanOn)]
    pub fn who_can_on(
        &self,
        ctx: &WasmContext,
        permission: JsValue,
        resource: JsValue,
        now: JsValue,
    ) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .who_can_on(
                    &ctx.inner,
                    &text("permission", &permission)?,
                    from_js(resource)?,
                    now_of(now)?,
                )
                .map_err(err)?,
        )
    }

    #[wasm_bindgen(js_name = accessOf)]
    pub fn access_of(&self, ctx: &WasmContext, resource: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .access_of(&ctx.inner, from_js(resource)?, now_of(now)?)
                .map_err(err)?,
        )
    }

    #[wasm_bindgen(js_name = checkFor)]
    pub fn check_for(
        &self,
        ctx: &WasmContext,
        subject_ref: JsValue,
        permission: JsValue,
        resource: JsValue,
        subjects: JsValue,
        now: JsValue,
    ) -> Result<JsValue, JsFailure> {
        let out = self
            .inner
            .check_for(
                &ctx.inner,
                from_js(subject_ref)?,
                &text("permission", &permission)?,
                from_js(resource)?,
                from_js(subjects)?,
                now_of(now)?,
            )
            .map_err(err)?;
        to_js(&out)
    }
}

#[wasm_bindgen(js_name = Exclusive)]
pub struct WasmExclusive {
    inner: ExclusiveHandle,
}

#[wasm_bindgen(js_class = Exclusive)]
impl WasmExclusive {
    #[wasm_bindgen(constructor)]
    pub fn new(options: JsValue) -> Result<WasmExclusive, JsFailure> {
        Ok(Self {
            inner: ExclusiveHandle::new(optional(options)?).map_err(err)?,
        })
    }

    pub fn validate(&self, engine: &WasmEngine) -> Result<(), JsFailure> {
        self.inner.validate(&engine.inner).map_err(err)
    }

    pub fn acquire(
        &mut self,
        engine: &WasmEngine,
        ctx: &WasmContext,
        subject: JsValue,
        resource: JsValue,
        terms: JsValue,
        now: JsValue,
    ) -> Result<JsValue, JsFailure> {
        let now = instant(now)?;
        let out = self
            .inner
            .acquire(
                &engine.inner,
                &ctx.inner,
                from_js(subject)?,
                from_js(resource)?,
                from_js(terms)?,
                now,
            )
            .map_err(err)?;
        to_js(&out)
    }

    pub fn holder(&self, resource: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.holder(from_js(resource)?, instant(now)?).map_err(err)?)
    }

    pub fn release(&mut self, resource: JsValue, holder: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        let out = self
            .inner
            .release(from_js(resource)?, from_js(holder)?, instant(now)?)
            .map_err(err)?;
        to_js(&out)
    }

    pub fn renew(
        &mut self,
        engine: &WasmEngine,
        ctx: &WasmContext,
        subject: JsValue,
        resource: JsValue,
        #[wasm_bindgen(js_name = ttlMs)] ttl_ms: JsValue,
        now: JsValue,
    ) -> Result<JsValue, JsFailure> {
        let ttl = crate::exclusive::ttl(&from_js(ttl_ms)?).map_err(err)?;
        let now = instant(now)?;
        let out = self
            .inner
            .renew(
                &engine.inner,
                &ctx.inner,
                from_js(subject)?,
                from_js(resource)?,
                ttl,
                now,
            )
            .map_err(err)?;
        to_js(&out)
    }

    pub fn expire(&mut self, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.expire(instant(now)?).map_err(err)?)
    }
}

#[wasm_bindgen(js_name = auditEstimate)]
pub fn audit_estimate(level: JsValue, records: JsValue) -> Result<f64, JsFailure> {
    crate::audit_estimate(from_js(level)?, from_js(records)?).map_err(err)
}

#[wasm_bindgen(js_name = verifyAuditChain)]
pub fn verify_audit_chain(records: JsValue, anchors: JsValue) -> Result<JsValue, JsFailure> {
    to_js(&crate::verify_audit_chain(from_js(records)?, optional(anchors)?).map_err(err)?)
}

#[wasm_bindgen(js_name = verifyMerkleInclusion)]
pub fn verify_merkle_inclusion(input: JsValue) -> Result<JsValue, JsFailure> {
    to_js(&crate::verify_merkle_inclusion(from_js(input)?).map_err(err)?)
}

#[wasm_bindgen(js_name = verifyMerkleConsistency)]
pub fn verify_merkle_consistency(input: JsValue) -> Result<JsValue, JsFailure> {
    to_js(&crate::verify_merkle_consistency(from_js(input)?).map_err(err)?)
}

#[wasm_bindgen(js_name = verifyTimestamp)]
pub fn verify_timestamp(input: JsValue) -> Result<JsValue, JsFailure> {
    to_js(&crate::verify_timestamp(from_js(input)?).map_err(err)?)
}

/// Um argumento da linguagem: o que não é JSON vira o `INVALID_ARGUMENT` do envelope.
fn dsl_arg(value: JsValue) -> Result<Value, crate::dsl::DslFailure> {
    Strict::deserialize(serde_wasm_bindgen::Deserializer::from(value))
        .map(|strict| strict.0)
        .map_err(|e| BindingError::invalid_argument("argumento", e).into())
}

fn dsl_out(result: crate::dsl::DslResult<impl Into<Value>>) -> Result<JsValue, JsFailure> {
    to_js(&crate::dsl::envelope(result))
}

#[wasm_bindgen(js_name = dslCompile)]
pub fn dsl_compile(text: JsValue, options: JsValue) -> Result<JsValue, JsFailure> {
    dsl_out((|| {
        let options = if options.is_undefined() || options.is_null() {
            None
        } else {
            Some(dsl_arg(options)?)
        };
        crate::dsl::compile(&dsl_arg(text)?, options.as_ref())
    })())
}

#[wasm_bindgen(js_name = dslPrint)]
pub fn dsl_print(policy: JsValue, language: JsValue) -> Result<JsValue, JsFailure> {
    dsl_out((|| crate::dsl::print(&dsl_arg(policy)?, &dsl_arg(language)?))())
}

#[wasm_bindgen(js_name = dslConvert)]
pub fn dsl_convert(text: JsValue, language: JsValue) -> Result<JsValue, JsFailure> {
    dsl_out((|| crate::dsl::convert(&dsl_arg(text)?, &dsl_arg(language)?))())
}

#[wasm_bindgen(js_name = dslFormat)]
pub fn dsl_format(text: JsValue, options: JsValue) -> Result<JsValue, JsFailure> {
    dsl_out((|| {
        let options = if options.is_undefined() || options.is_null() {
            None
        } else {
            Some(dsl_arg(options)?)
        };
        crate::dsl::format(&dsl_arg(text)?, options.as_ref())
    })())
}

#[wasm_bindgen(js_name = dslIsFormatted)]
pub fn dsl_is_formatted(text: JsValue, options: JsValue) -> Result<JsValue, JsFailure> {
    dsl_out((|| {
        let options = if options.is_undefined() || options.is_null() {
            None
        } else {
            Some(dsl_arg(options)?)
        };
        crate::dsl::is_formatted(&dsl_arg(text)?, options.as_ref())
    })())
}

#[wasm_bindgen(js_name = dslLoadProject)]
pub fn dsl_load_project(sources: JsValue) -> Result<JsValue, JsFailure> {
    dsl_out((|| crate::dsl::load_project(&dsl_arg(sources)?))())
}

#[wasm_bindgen(js_name = dslRunTests)]
pub fn dsl_run_tests(policy: JsValue, tests: JsValue) -> Result<JsValue, JsFailure> {
    dsl_out((|| crate::dsl::run_tests(&dsl_arg(policy)?, &dsl_arg(tests)?))())
}

#[wasm_bindgen(js_name = dslDiff)]
pub fn dsl_diff(before: JsValue, after: JsValue, options: JsValue) -> Result<JsValue, JsFailure> {
    dsl_out((|| {
        let options = if options.is_undefined() || options.is_null() {
            None
        } else {
            Some(dsl_arg(options)?)
        };
        crate::dsl::diff_policies(&dsl_arg(before)?, &dsl_arg(after)?, options.as_ref())
    })())
}

#[wasm_bindgen(js_name = dslLint)]
pub fn dsl_lint(policy: JsValue, options: JsValue) -> Result<JsValue, JsFailure> {
    dsl_out((|| {
        let options = if options.is_undefined() || options.is_null() {
            None
        } else {
            Some(dsl_arg(options)?)
        };
        crate::dsl::lint_policy(&dsl_arg(policy)?, options.as_ref())
    })())
}

#[wasm_bindgen]
pub fn backend() -> String {
    "wasm".to_string()
}
