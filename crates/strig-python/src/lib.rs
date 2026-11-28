//! Python binding for Strig: a native extension over the same core as the JavaScript binding.
//!
//! Every argument crosses as JSON (`serde_json::Value`), so the spec, the requests and the results
//! are the ones of the Rust and JavaScript APIs. Field names stay camelCase, as in JavaScript;
//! method names are snake_case. A failure raises `strig.StrigError` with the same stable `code` as
//! the JavaScript `error.code`. The GIL is held for the whole call: a callback runs on the thread
//! that is deciding, and the core's re-entry guard refuses a call made from inside one.

#![allow(
    clippy::too_many_arguments,
    reason = "each method mirrors the JavaScript signature, one argument per parameter"
)]

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use serde_json::{Map, Number, Value};
use strig_node::{
    AuditPolicy, BindingError, ContextData, EngineHandle, ExclusiveHandle, HostCallbacks, HostFn, clock_ms, now_arg,
};

fn raise(py: Python<'_>, code: &str, message: &str, diagnostics: Option<Value>) -> PyErr {
    let built = (|| -> PyResult<PyErr> {
        let errors = py.import("strig.errors")?;
        let class = match diagnostics {
            Some(_) => errors.getattr("DslError")?,
            None => errors.getattr("StrigError")?,
        };
        let instance = match diagnostics {
            Some(list) => class.call1((code, message, to_py(py, &list)?))?,
            None => class.call1((code, message))?,
        };
        Ok(PyErr::from_value(instance))
    })();
    built.unwrap_or_else(|e| e)
}

fn fail(py: Python<'_>, error: BindingError) -> PyErr {
    raise(py, error.code, &error.message, None)
}

fn invalid(py: Python<'_>, what: &str, cause: &str) -> PyErr {
    fail(py, BindingError::invalid_argument(what, cause))
}

/// A Python value as JSON. What is not JSON (`nan`, `inf`, a function, a set, a non-text key) is
/// `INVALID_ARGUMENT`; nothing is coerced.
fn from_py(value: &Bound<'_, PyAny>) -> Result<Value, String> {
    if value.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(flag) = value.cast::<PyBool>() {
        return Ok(Value::Bool(flag.is_true()));
    }
    if value.is_instance_of::<PyInt>() {
        if let Ok(n) = value.extract::<i64>() {
            return Ok(Value::from(n));
        }
        if let Ok(n) = value.extract::<u64>() {
            return Ok(Value::from(n));
        }
        return Err("integer out of range".to_string());
    }
    if value.is_instance_of::<PyFloat>() {
        let f = value.extract::<f64>().map_err(|e| e.to_string())?;
        return Number::from_f64(f)
            .map(Value::Number)
            .ok_or_else(|| "a non-finite number is not JSON".to_string());
    }
    if let Ok(text) = value.cast::<PyString>() {
        return text.extract::<String>().map(Value::String).map_err(|e| e.to_string());
    }
    if let Ok(list) = value.cast::<PyList>() {
        return list
            .iter()
            .map(|item| from_py(&item))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    if let Ok(tuple) = value.cast::<PyTuple>() {
        return tuple
            .iter()
            .map(|item| from_py(&item))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let mut map = Map::new();
        for (key, item) in dict.iter() {
            let key = key
                .cast::<PyString>()
                .map_err(|_| "an object key must be text".to_string())?
                .extract::<String>()
                .map_err(|e| e.to_string())?;
            map.insert(key, from_py(&item)?);
        }
        return Ok(Value::Object(map));
    }
    Err(format!(
        "{} is not JSON",
        value.get_type().name().map_err(|e| e.to_string())?
    ))
}

fn to_py<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    Ok(match value {
        Value::Null => py.None().into_bound(py),
        Value::Bool(b) => PyBool::new(py, *b).to_owned().into_any(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_pyobject(py)?.into_any()
            } else if let Some(u) = n.as_u64() {
                u.into_pyobject(py)?.into_any()
            } else {
                n.as_f64().unwrap_or(f64::NAN).into_pyobject(py)?.into_any()
            }
        }
        Value::String(s) => PyString::new(py, s).into_any(),
        Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(to_py(py, item)?)?;
            }
            list.into_any()
        }
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (key, item) in map {
                dict.set_item(key, to_py(py, item)?)?;
            }
            dict.into_any()
        }
    })
}

fn json(py: Python<'_>, what: &str, value: &Bound<'_, PyAny>) -> PyResult<Value> {
    from_py(value).map_err(|cause| invalid(py, what, &cause))
}

fn optional(py: Python<'_>, what: &str, value: Option<&Bound<'_, PyAny>>) -> PyResult<Option<Value>> {
    match value {
        None => Ok(None),
        Some(v) => match json(py, what, v)? {
            Value::Null => Ok(None),
            other => Ok(Some(other)),
        },
    }
}

fn now_of(py: Python<'_>, now: Option<&Bound<'_, PyAny>>) -> PyResult<Option<u64>> {
    now_arg(optional(py, "now", now)?).map_err(|e| fail(py, e))
}

fn instant(py: Python<'_>, now: Option<&Bound<'_, PyAny>>) -> PyResult<u64> {
    match now_of(py, now)? {
        Some(ms) => Ok(ms),
        None => system_clock(py),
    }
}

fn system_clock(py: Python<'_>) -> PyResult<u64> {
    clock_ms(std::time::SystemTime::now()).map_err(|e| fail(py, e))
}

fn text(py: Python<'_>, what: &str, value: &Bound<'_, PyAny>) -> PyResult<String> {
    match json(py, what, value)? {
        Value::String(s) => Ok(s),
        _ => Err(invalid(py, what, "expected text")),
    }
}

fn out<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    to_py(py, value)
}

/// What the Python exception said, for the message the engine records.
fn describe(py: Python<'_>, error: &PyErr) -> String {
    let message = error.value(py).str().map(|s| s.to_string()).unwrap_or_default();
    if message.is_empty() {
        error.get_type(py).name().map(|n| n.to_string()).unwrap_or_default()
    } else {
        message
    }
}

/// A Python callable the engine calls back. It only runs while a call of the host is on the
/// stack, on the thread that is deciding, so it re-attaches to the interpreter that already holds
/// the GIL.
struct PyFn(Py<PyAny>);

impl HostFn for PyFn {
    fn call(&self, arg: Value) -> Result<Value, String> {
        Python::attach(|py| {
            let argument = to_py(py, &arg).map_err(|e| describe(py, &e))?;
            let answer = self.0.bind(py).call1((argument,)).map_err(|e| describe(py, &e))?;
            from_py(&answer)
        })
    }
}

fn callable(py: Python<'_>, what: &str, value: &Bound<'_, PyAny>) -> PyResult<Arc<dyn HostFn>> {
    if !value.is_callable() {
        return Err(invalid(py, what, "expected a function"));
    }
    Ok(Arc::new(PyFn(value.clone().unbind())))
}

fn mapping<'a, 'py>(py: Python<'_>, what: &str, value: &'a Bound<'py, PyAny>) -> PyResult<&'a Bound<'py, PyDict>> {
    value.cast::<PyDict>().map_err(|_| invalid(py, what, "expected a dict"))
}

#[pyclass(name = "Context", module = "strig._native")]
struct PyContext {
    inner: ContextData,
}

#[pymethods]
impl PyContext {
    #[new]
    #[pyo3(signature = (grants=None, *, tuples=None, env=None, now=None, limits=None))]
    fn new(
        py: Python<'_>,
        grants: Option<&Bound<'_, PyAny>>,
        tuples: Option<&Bound<'_, PyAny>>,
        env: Option<&Bound<'_, PyAny>>,
        now: Option<&Bound<'_, PyAny>>,
        limits: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let mut init = Map::new();
        for (key, value) in [
            ("grants", grants),
            ("tuples", tuples),
            ("env", env),
            ("now", now),
            ("limits", limits),
        ] {
            if let Some(value) = optional(py, key, value)? {
                init.insert(key.to_string(), value);
            }
        }
        let inner = ContextData::new(Some(Value::Object(init))).map_err(|e| fail(py, e))?;
        Ok(Self { inner })
    }

    fn set_grants(&mut self, py: Python<'_>, grants: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner
            .set_grants(json(py, "grants", grants)?)
            .map_err(|e| fail(py, e))
    }

    fn add_grant(&mut self, py: Python<'_>, grant: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.add_grant(json(py, "grant", grant)?).map_err(|e| fail(py, e))
    }

    fn remove_grant(&mut self, py: Python<'_>, id: &Bound<'_, PyAny>) -> PyResult<bool> {
        self.inner.remove_grant(&text(py, "id", id)?).map_err(|e| fail(py, e))
    }

    fn grants<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        out(py, &self.inner.grants())
    }

    #[getter]
    fn size(&self) -> usize {
        self.inner.grant_count()
    }

    fn __len__(&self) -> usize {
        self.inner.grant_count()
    }

    fn add_tuple(&mut self, py: Python<'_>, tuple: &Bound<'_, PyAny>) -> PyResult<bool> {
        self.inner.add_tuple(json(py, "tuple", tuple)?).map_err(|e| fail(py, e))
    }

    fn remove_tuple(&mut self, py: Python<'_>, tuple: &Bound<'_, PyAny>) -> PyResult<bool> {
        self.inner
            .remove_tuple(json(py, "tuple", tuple)?)
            .map_err(|e| fail(py, e))
    }

    fn set_env(&mut self, py: Python<'_>, env: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.set_env(json(py, "env", env)?).map_err(|e| fail(py, e))
    }

    fn load_capabilities<'py>(
        &mut self,
        py: Python<'py>,
        capabilities: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let subject = self
            .inner
            .load_capabilities(json(py, "capabilities", capabilities)?)
            .map_err(|e| fail(py, e))?;
        out(py, &subject)
    }

    #[pyo3(signature = (now=None))]
    fn set_now(&mut self, py: Python<'_>, now: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
        let value = optional(py, "now", now)?.unwrap_or(Value::Null);
        self.inner.set_now(value).map_err(|e| fail(py, e))
    }

    #[pyo3(signature = (limits=None))]
    fn set_limits(&mut self, py: Python<'_>, limits: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
        let value = optional(py, "limits", limits)?.unwrap_or(Value::Null);
        self.inner.set_limits(value).map_err(|e| fail(py, e))
    }
}

fn hooks_of(
    py: Python<'_>,
    conditions: Option<&Bound<'_, PyAny>>,
    overrides: Option<&Bound<'_, PyAny>>,
    invariants: Option<&Bound<'_, PyAny>>,
    audit_sink: Option<&Bound<'_, PyAny>>,
    audit_redact: Option<&Bound<'_, PyAny>>,
    on_audit_drop: Option<&Bound<'_, PyAny>>,
    audit_policy: Option<&Bound<'_, PyAny>>,
) -> PyResult<HostCallbacks> {
    let mut host = HostCallbacks::default();
    if let Some(conditions) = conditions.filter(|v| !v.is_none()) {
        for (name, f) in mapping(py, "conditions", conditions)?.iter() {
            let name = text(py, "conditions", &name)?;
            host.condition(name.clone(), callable(py, &format!("conditions.{name}"), &f)?);
        }
    }
    if let Some(overrides) = overrides.filter(|v| !v.is_none()) {
        for rule in overrides.try_iter()? {
            let rule = rule?;
            let rule = mapping(py, "overrides[]", &rule)?;
            let name = match rule.get_item("name")? {
                Some(name) => text(py, "overrides[].name", &name)?,
                None => return Err(invalid(py, "overrides[].name", "expected text")),
            };
            let except = match rule.get_item("except")?.or(rule.get_item("except_")?) {
                Some(list) => match json(py, "overrides[].except", &list)? {
                    Value::Array(items) => items
                        .into_iter()
                        .map(|v| v.as_str().map(str::to_string))
                        .collect::<Option<Vec<_>>>()
                        .ok_or_else(|| invalid(py, "overrides[].except", "expected a list of text"))?,
                    _ => return Err(invalid(py, "overrides[].except", "expected a list of text")),
                },
                None => Vec::new(),
            };
            let evaluate = rule
                .get_item("evaluate")?
                .ok_or_else(|| invalid(py, "overrides[].evaluate", "expected a function"))?;
            host.override_rule(name, except, callable(py, "overrides[].evaluate", &evaluate)?);
        }
    }
    if let Some(invariants) = invariants.filter(|v| !v.is_none()) {
        for (name, f) in mapping(py, "invariants", invariants)?.iter() {
            let name = text(py, "invariants", &name)?;
            host.invariant(name.clone(), callable(py, &format!("invariants.{name}"), &f)?);
        }
    }
    if let Some(sink) = audit_sink.filter(|v| !v.is_none()) {
        host.audit_sink(callable(py, "audit_sink", sink)?);
    }
    if let Some(redact) = audit_redact.filter(|v| !v.is_none()) {
        host.audit_redact(callable(py, "audit_redact", redact)?);
    }
    if let Some(on_drop) = on_audit_drop.filter(|v| !v.is_none()) {
        host.on_audit_drop(callable(py, "on_audit_drop", on_drop)?);
    }
    if let Some(policy) = audit_policy.filter(|v| !v.is_none()) {
        let policy: AuditPolicy = serde_json::from_value(json(py, "audit_policy", policy)?)
            .map_err(|e| fail(py, BindingError::invalid_input("audit_policy", e)))?;
        host.set_audit_policy(policy);
    }
    Ok(host)
}

#[pyclass(name = "Engine", module = "strig._native")]
struct PyEngine {
    inner: EngineHandle,
}

#[pymethods]
impl PyEngine {
    #[new]
    #[pyo3(signature = (spec, *, conditions=None, overrides=None, invariants=None, audit_sink=None, audit_redact=None, on_audit_drop=None, audit_policy=None))]
    #[allow(
        clippy::too_many_arguments,
        reason = "one keyword per hook, as in the JavaScript `hooks`"
    )]
    fn new(
        py: Python<'_>,
        spec: &Bound<'_, PyAny>,
        conditions: Option<&Bound<'_, PyAny>>,
        overrides: Option<&Bound<'_, PyAny>>,
        invariants: Option<&Bound<'_, PyAny>>,
        audit_sink: Option<&Bound<'_, PyAny>>,
        audit_redact: Option<&Bound<'_, PyAny>>,
        on_audit_drop: Option<&Bound<'_, PyAny>>,
        audit_policy: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let host = hooks_of(
            py,
            conditions,
            overrides,
            invariants,
            audit_sink,
            audit_redact,
            on_audit_drop,
            audit_policy,
        )?;
        let inner = EngineHandle::with_host(json(py, "spec", spec)?, host).map_err(|e| fail(py, e))?;
        Ok(Self { inner })
    }

    #[pyo3(signature = (context, request, now=None))]
    fn decide<'py>(
        &self,
        py: Python<'py>,
        context: &PyContext,
        request: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let decision = self
            .inner
            .decide(&context.inner, json(py, "request", request)?, now_of(py, now)?)
            .map_err(|e| fail(py, e))?;
        out(py, &decision)
    }

    #[pyo3(signature = (context, request, now=None))]
    fn check(
        &self,
        py: Python<'_>,
        context: &PyContext,
        request: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<bool> {
        self.inner
            .check(&context.inner, json(py, "request", request)?, now_of(py, now)?)
            .map_err(|e| fail(py, e))
    }

    #[pyo3(signature = (context, request, now=None))]
    fn explain<'py>(
        &self,
        py: Python<'py>,
        context: &PyContext,
        request: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let explanation = self
            .inner
            .explain(&context.inner, json(py, "request", request)?, now_of(py, now)?)
            .map_err(|e| fail(py, e))?;
        out(py, &explanation)
    }

    /// For a denied request, the verified changes that would allow it; `None` when it is allowed.
    #[pyo3(signature = (context, request, now=None, options=None))]
    fn why_not<'py>(
        &self,
        py: Python<'py>,
        context: &PyContext,
        request: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
        options: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let remedies = self
            .inner
            .why_not(
                &context.inner,
                json(py, "request", request)?,
                now_of(py, now)?,
                optional(py, "options", options)?,
            )
            .map_err(|e| fail(py, e))?;
        out(py, &remedies)
    }

    #[pyo3(signature = (context, requests, now=None))]
    fn check_many(
        &self,
        py: Python<'_>,
        context: &PyContext,
        requests: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Vec<bool>> {
        self.inner
            .check_many(&context.inner, json(py, "requests", requests)?, now_of(py, now)?)
            .map_err(|e| fail(py, e))
    }

    #[pyo3(signature = (context, requests, now=None))]
    fn explain_many<'py>(
        &self,
        py: Python<'py>,
        context: &PyContext,
        requests: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let all = self
            .inner
            .explain_many(&context.inner, json(py, "requests", requests)?, now_of(py, now)?)
            .map_err(|e| fail(py, e))?;
        out(py, &all)
    }

    #[pyo3(signature = (context, subject, scope, now=None))]
    fn capabilities<'py>(
        &self,
        py: Python<'py>,
        context: &PyContext,
        subject: &Bound<'_, PyAny>,
        scope: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let set = self
            .inner
            .capabilities(
                &context.inner,
                json(py, "subject", subject)?,
                json(py, "scope", scope)?,
                now_of(py, now)?,
            )
            .map_err(|e| fail(py, e))?;
        out(py, &set)
    }

    fn validate_grant(&self, py: Python<'_>, grant: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner
            .validate_grant(json(py, "grant", grant)?)
            .map_err(|e| fail(py, e))
    }

    fn catalog<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        out(py, &self.inner.catalog())
    }

    fn apply<'py>(&self, py: Python<'py>, input: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .apply(json(py, "input", input)?, clock_ms(std::time::SystemTime::now()))
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    fn impact<'py>(&self, py: Python<'py>, input: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .impact(json(py, "input", input)?, clock_ms(std::time::SystemTime::now()))
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    fn review_impact<'py>(&self, py: Python<'py>, input: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .review_impact(json(py, "input", input)?, clock_ms(std::time::SystemTime::now()))
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    fn propose<'py>(&self, py: Python<'py>, input: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .propose(json(py, "input", input)?, clock_ms(std::time::SystemTime::now()))
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    fn resolve<'py>(&self, py: Python<'py>, input: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .resolve(json(py, "input", input)?, clock_ms(std::time::SystemTime::now()))
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    fn elevate<'py>(&self, py: Python<'py>, input: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .elevate(json(py, "input", input)?, clock_ms(std::time::SystemTime::now()))
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    fn recertify<'py>(&self, py: Python<'py>, input: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .recertify(json(py, "input", input)?, clock_ms(std::time::SystemTime::now()))
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    fn expire<'py>(&self, py: Python<'py>, input: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .expire(json(py, "input", input)?, clock_ms(std::time::SystemTime::now()))
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    fn flush_audit<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let stats = self
            .inner
            .flush_audit(clock_ms(std::time::SystemTime::now()))
            .map_err(|e| fail(py, e))?;
        out(py, &stats)
    }

    fn audit_stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        out(py, &self.inner.audit_stats())
    }

    fn materialize<'py>(&self, py: Python<'py>, input: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .materialize(json(py, "input", input)?)
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    fn apply_template<'py>(&self, py: Python<'py>, input: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .apply_template(json(py, "input", input)?, clock_ms(std::time::SystemTime::now()))
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    #[pyo3(signature = (context, subject, permission, kind, options=None, now=None))]
    fn list<'py>(
        &self,
        py: Python<'py>,
        context: &PyContext,
        subject: &Bound<'_, PyAny>,
        permission: &Bound<'_, PyAny>,
        kind: &Bound<'_, PyAny>,
        options: Option<&Bound<'_, PyAny>>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .list(
                &context.inner,
                json(py, "subject", subject)?,
                &text(py, "permission", permission)?,
                &text(py, "kind", kind)?,
                optional(py, "options", options)?,
                now_of(py, now)?,
            )
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    #[pyo3(signature = (context, permission, now=None))]
    fn who_can<'py>(
        &self,
        py: Python<'py>,
        context: &PyContext,
        permission: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .who_can(&context.inner, &text(py, "permission", permission)?, now_of(py, now)?);
        out(py, &result)
    }

    #[pyo3(signature = (context, permission, resource, now=None))]
    fn who_can_on<'py>(
        &self,
        py: Python<'py>,
        context: &PyContext,
        permission: &Bound<'_, PyAny>,
        resource: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .who_can_on(
                &context.inner,
                &text(py, "permission", permission)?,
                json(py, "resource", resource)?,
                now_of(py, now)?,
            )
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    #[pyo3(signature = (context, resource, now=None))]
    fn access_of<'py>(
        &self,
        py: Python<'py>,
        context: &PyContext,
        resource: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .access_of(&context.inner, json(py, "resource", resource)?, now_of(py, now)?)
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    #[pyo3(signature = (context, subject_ref, permission, resource, subjects, now=None))]
    fn check_for<'py>(
        &self,
        py: Python<'py>,
        context: &PyContext,
        subject_ref: &Bound<'_, PyAny>,
        permission: &Bound<'_, PyAny>,
        resource: &Bound<'_, PyAny>,
        subjects: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .check_for(
                &context.inner,
                json(py, "subject_ref", subject_ref)?,
                &text(py, "permission", permission)?,
                json(py, "resource", resource)?,
                json(py, "subjects", subjects)?,
                now_of(py, now)?,
            )
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }
}

#[pyclass(name = "Exclusive", module = "strig._native")]
struct PyExclusive {
    inner: ExclusiveHandle,
}

#[pymethods]
impl PyExclusive {
    #[new]
    #[pyo3(signature = (options=None))]
    fn new(py: Python<'_>, options: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let inner = ExclusiveHandle::new(optional(py, "options", options)?).map_err(|e| fail(py, e))?;
        Ok(Self { inner })
    }

    fn validate(&self, py: Python<'_>, engine: &PyEngine) -> PyResult<()> {
        self.inner.validate(&engine.inner).map_err(|e| fail(py, e))
    }

    #[pyo3(signature = (engine, context, subject, resource, terms, now=None))]
    fn acquire<'py>(
        &mut self,
        py: Python<'py>,
        engine: &PyEngine,
        context: &PyContext,
        subject: &Bound<'_, PyAny>,
        resource: &Bound<'_, PyAny>,
        terms: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let now = instant(py, now)?;
        let result = self
            .inner
            .acquire(
                &engine.inner,
                &context.inner,
                json(py, "subject", subject)?,
                json(py, "resource", resource)?,
                json(py, "terms", terms)?,
                now,
            )
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    #[pyo3(signature = (resource, now=None))]
    fn holder<'py>(
        &self,
        py: Python<'py>,
        resource: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .holder(json(py, "resource", resource)?, instant(py, now)?)
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    #[pyo3(signature = (resource, holder, now=None))]
    fn release<'py>(
        &mut self,
        py: Python<'py>,
        resource: &Bound<'_, PyAny>,
        holder: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let result = self
            .inner
            .release(
                json(py, "resource", resource)?,
                json(py, "holder", holder)?,
                instant(py, now)?,
            )
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    #[pyo3(signature = (engine, context, subject, resource, ttl_ms, now=None))]
    fn renew<'py>(
        &mut self,
        py: Python<'py>,
        engine: &PyEngine,
        context: &PyContext,
        subject: &Bound<'_, PyAny>,
        resource: &Bound<'_, PyAny>,
        ttl_ms: &Bound<'_, PyAny>,
        now: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let ttl = strig_node::exclusive::ttl(&json(py, "ttl_ms", ttl_ms)?).map_err(|e| fail(py, e))?;
        let now = instant(py, now)?;
        let result = self
            .inner
            .renew(
                &engine.inner,
                &context.inner,
                json(py, "subject", subject)?,
                json(py, "resource", resource)?,
                ttl,
                now,
            )
            .map_err(|e| fail(py, e))?;
        out(py, &result)
    }

    #[pyo3(signature = (now=None))]
    fn expire<'py>(&mut self, py: Python<'py>, now: Option<&Bound<'_, PyAny>>) -> PyResult<Bound<'py, PyAny>> {
        let result = self.inner.expire(instant(py, now)?).map_err(|e| fail(py, e))?;
        out(py, &result)
    }
}

#[pyfunction]
fn audit_estimate(py: Python<'_>, level: &Bound<'_, PyAny>, records: &Bound<'_, PyAny>) -> PyResult<f64> {
    strig_node::audit_estimate(json(py, "level", level)?, json(py, "records", records)?).map_err(|e| fail(py, e))
}

#[pyfunction]
#[pyo3(signature = (records, anchors=None))]
fn verify_audit_chain<'py>(
    py: Python<'py>,
    records: &Bound<'_, PyAny>,
    anchors: Option<&Bound<'_, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    let result = strig_node::verify_audit_chain(json(py, "records", records)?, optional(py, "anchors", anchors)?)
        .map_err(|e| fail(py, e))?;
    out(py, &result)
}

/// The policy-language functions return the `{ ok, value }` envelope; `strig.dsl` opens it and
/// raises `DslError`.
fn dsl_arg(value: &Bound<'_, PyAny>) -> Result<Value, strig_node::dsl::DslFailure> {
    from_py(value).map_err(|cause| BindingError::invalid_argument("argument", cause).into())
}

fn envelope<'py, T: Into<Value>>(
    py: Python<'py>,
    result: Result<T, strig_node::dsl::DslFailure>,
) -> PyResult<Bound<'py, PyAny>> {
    out(py, &strig_node::dsl::envelope(result))
}

#[pyfunction]
#[pyo3(signature = (text, options=None))]
fn dsl_compile<'py>(
    py: Python<'py>,
    text: &Bound<'_, PyAny>,
    options: Option<&Bound<'_, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    envelope(
        py,
        (|| {
            let options = options.map(|o| dsl_arg(o)).transpose()?;
            strig_node::dsl::compile(&dsl_arg(text)?, options.as_ref())
        })(),
    )
}

#[pyfunction]
fn dsl_print<'py>(
    py: Python<'py>,
    policy: &Bound<'_, PyAny>,
    language: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    envelope(
        py,
        (|| strig_node::dsl::print(&dsl_arg(policy)?, &dsl_arg(language)?))(),
    )
}

#[pyfunction]
fn dsl_convert<'py>(
    py: Python<'py>,
    text: &Bound<'_, PyAny>,
    language: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    envelope(
        py,
        (|| strig_node::dsl::convert(&dsl_arg(text)?, &dsl_arg(language)?))(),
    )
}

#[pyfunction]
#[pyo3(signature = (text, options=None))]
fn dsl_format<'py>(
    py: Python<'py>,
    text: &Bound<'_, PyAny>,
    options: Option<&Bound<'_, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    envelope(
        py,
        (|| {
            let options = options.map(|o| dsl_arg(o)).transpose()?;
            strig_node::dsl::format(&dsl_arg(text)?, options.as_ref())
        })(),
    )
}

#[pyfunction]
#[pyo3(signature = (text, options=None))]
fn dsl_is_formatted<'py>(
    py: Python<'py>,
    text: &Bound<'_, PyAny>,
    options: Option<&Bound<'_, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    envelope(
        py,
        (|| {
            let options = options.map(|o| dsl_arg(o)).transpose()?;
            strig_node::dsl::is_formatted(&dsl_arg(text)?, options.as_ref())
        })(),
    )
}

#[pyfunction]
fn dsl_load_project<'py>(py: Python<'py>, sources: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    envelope(py, (|| strig_node::dsl::load_project(&dsl_arg(sources)?))())
}

#[pyfunction]
fn dsl_load_project_dir<'py>(py: Python<'py>, dir: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    envelope(py, (|| strig_node::dsl::load_project_dir(&dsl_arg(dir)?))())
}

#[pyfunction]
fn dsl_run_tests<'py>(
    py: Python<'py>,
    policy: &Bound<'_, PyAny>,
    tests: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    envelope(
        py,
        (|| strig_node::dsl::run_tests(&dsl_arg(policy)?, &dsl_arg(tests)?))(),
    )
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyContext>()?;
    m.add_class::<PyEngine>()?;
    m.add_class::<PyExclusive>()?;
    m.add_function(wrap_pyfunction!(audit_estimate, m)?)?;
    m.add_function(wrap_pyfunction!(verify_audit_chain, m)?)?;
    m.add_function(wrap_pyfunction!(dsl_compile, m)?)?;
    m.add_function(wrap_pyfunction!(dsl_print, m)?)?;
    m.add_function(wrap_pyfunction!(dsl_convert, m)?)?;
    m.add_function(wrap_pyfunction!(dsl_format, m)?)?;
    m.add_function(wrap_pyfunction!(dsl_is_formatted, m)?)?;
    m.add_function(wrap_pyfunction!(dsl_load_project, m)?)?;
    m.add_function(wrap_pyfunction!(dsl_load_project_dir, m)?)?;
    m.add_function(wrap_pyfunction!(dsl_run_tests, m)?)?;
    Ok(())
}
