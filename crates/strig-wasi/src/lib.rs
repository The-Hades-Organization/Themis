//! C-ABI WebAssembly build of the engine for hosts that are not JavaScript (Go on wazero, the JVM
//! on Chicory).
//!
//! The module exports three functions and a linear memory; no wasm-bindgen, no imports:
//!
//! - `strig_alloc(len) -> ptr` and `strig_free(ptr, len)` hand the host memory to write inputs into
//!   and to release outputs.
//! - `strig_call(op_ptr, op_len, in_ptr, in_len) -> u64` runs one operation. `op` is UTF-8 text,
//!   the input is a JSON object. The result packs `(ptr << 32) | len` of a JSON envelope the host
//!   reads and then frees: `{"ok":true,"value":...}` or
//!   `{"ok":false,"code":"...","message":"...","diagnostics":...}`. `code` is the same stable
//!   `errorCode` the JavaScript binding raises.
//!
//! Engines and contexts live inside the module and are named by integer ids (`engine.new`,
//! `context.new`, ...), released with `engine.free` and `context.free`. The module is
//! single-threaded: a host that wants concurrency instantiates one module per worker.
//!
//! Callbacks (`call`, overrides, invariants) are not part of this ABI. A request that needs one
//! fails closed with the engine's own error. There is no clock either: calls that need the
//! instant take `now` in the input, and the host fills it.

use std::cell::RefCell;
use std::collections::HashMap;

use serde_json::{Value, json};
use strig_node::{BindingError, BindingResult, ContextData, EngineHandle, dsl};

#[derive(Default)]
struct Registry {
    next: u64,
    engines: HashMap<u64, EngineHandle>,
    contexts: HashMap<u64, ContextData>,
}

thread_local! {
    static REGISTRY: RefCell<Registry> = RefCell::new(Registry::default());
}

fn field<'a>(input: &'a Value, name: &str) -> BindingResult<&'a Value> {
    input
        .get(name)
        .ok_or_else(|| BindingError::invalid_input("input", format!("missing field `{name}`")))
}

fn text<'a>(input: &'a Value, name: &str) -> BindingResult<&'a str> {
    field(input, name)?
        .as_str()
        .ok_or_else(|| BindingError::invalid_input(name, "expected text"))
}

fn id(input: &Value, name: &str) -> BindingResult<u64> {
    field(input, name)?
        .as_u64()
        .ok_or_else(|| BindingError::invalid_input(name, "expected a handle"))
}

fn optional(input: &Value, name: &str) -> Option<Value> {
    input.get(name).filter(|v| !v.is_null()).cloned()
}

fn now_of(input: &Value) -> BindingResult<Option<u64>> {
    strig_node::now_arg(optional(input, "now"))
}

fn clock_of(input: &Value) -> BindingResult<u64> {
    now_of(input)?.ok_or_else(|| BindingError::invalid_input("now", "this host has no clock; pass `now`"))
}

fn unknown(what: &str) -> BindingError {
    BindingError::new("INVALID_ARGUMENT", format!("unknown or released {what} handle"))
}

fn with_engine<T>(
    reg: &Registry,
    input: &Value,
    run: impl FnOnce(&EngineHandle, &ContextData) -> BindingResult<T>,
) -> BindingResult<T> {
    let engine = reg
        .engines
        .get(&id(input, "engine")?)
        .ok_or_else(|| unknown("engine"))?;
    let ctx = reg
        .contexts
        .get(&id(input, "context")?)
        .ok_or_else(|| unknown("context"))?;
    run(engine, ctx)
}

fn engine_only<T>(
    reg: &Registry,
    input: &Value,
    run: impl FnOnce(&EngineHandle) -> BindingResult<T>,
) -> BindingResult<T> {
    run(reg
        .engines
        .get(&id(input, "engine")?)
        .ok_or_else(|| unknown("engine"))?)
}

fn context_mut<T>(
    reg: &mut Registry,
    input: &Value,
    run: impl FnOnce(&mut ContextData) -> BindingResult<T>,
) -> BindingResult<T> {
    run(reg
        .contexts
        .get_mut(&id(input, "context")?)
        .ok_or_else(|| unknown("context"))?)
}

fn dispatch(reg: &mut Registry, op: &str, input: &Value) -> Result<Value, dsl::DslFailure> {
    if let Some(name) = op.strip_prefix("dsl.") {
        return dsl_op(name, input);
    }
    run(reg, op, input).map_err(Into::into)
}

fn dsl_op(name: &str, input: &Value) -> Result<Value, dsl::DslFailure> {
    match name {
        "compile" => dsl::compile(field(input, "text")?, input.get("options")),
        "format" => dsl::format(field(input, "text")?, input.get("options")).map(Value::from),
        "print" => dsl::print(field(input, "policy")?, field(input, "to")?).map(Value::from),
        "convert" => dsl::convert(field(input, "text")?, field(input, "to")?).map(Value::from),
        "isFormatted" => dsl::is_formatted(field(input, "text")?, input.get("options")).map(Value::from),
        "loadProject" => dsl::load_project(field(input, "sources")?),
        "runTests" => dsl::run_tests(field(input, "policy")?, field(input, "tests")?),
        "diff" => dsl::diff_policies(field(input, "before")?, field(input, "after")?, input.get("options")),
        "lint" => dsl::lint_policy(field(input, "policy")?, input.get("options")),
        other => Err(BindingError::new("INVALID_ARGUMENT", format!("unknown operation `dsl.{other}`")).into()),
    }
}

fn run(reg: &mut Registry, op: &str, input: &Value) -> BindingResult<Value> {
    match op {
        "engine.new" => {
            let engine = EngineHandle::new(field(input, "spec")?.clone())?;
            reg.next += 1;
            reg.engines.insert(reg.next, engine);
            Ok(json!(reg.next))
        }
        "engine.free" => Ok(json!(reg.engines.remove(&id(input, "engine")?).is_some())),
        "context.new" => {
            let data = ContextData::new(optional(input, "init"))?;
            reg.next += 1;
            reg.contexts.insert(reg.next, data);
            Ok(json!(reg.next))
        }
        "context.free" => Ok(json!(reg.contexts.remove(&id(input, "context")?).is_some())),
        "context.setGrants" => {
            context_mut(reg, input, |c| c.set_grants(field(input, "grants")?.clone())).map(|()| Value::Null)
        }
        "context.addGrant" => {
            context_mut(reg, input, |c| c.add_grant(field(input, "grant")?.clone())).map(|()| Value::Null)
        }
        "context.removeGrant" => context_mut(reg, input, |c| c.remove_grant(text(input, "id")?)).map(Value::from),
        "context.grants" => context_mut(reg, input, |c| Ok(c.grants())),
        "context.addTuple" => context_mut(reg, input, |c| c.add_tuple(field(input, "tuple")?.clone())).map(Value::from),
        "context.removeTuple" => {
            context_mut(reg, input, |c| c.remove_tuple(field(input, "tuple")?.clone())).map(Value::from)
        }
        "context.setEnv" => context_mut(reg, input, |c| c.set_env(field(input, "env")?.clone())).map(|()| Value::Null),
        "context.setNow" => context_mut(reg, input, |c| c.set_now(field(input, "now")?.clone())).map(|()| Value::Null),
        "context.setLimits" => {
            context_mut(reg, input, |c| c.set_limits(field(input, "limits")?.clone())).map(|()| Value::Null)
        }
        "check" => with_engine(reg, input, |e, c| {
            e.check(c, field(input, "request")?.clone(), now_of(input)?)
                .map(Value::from)
        }),
        "decide" => with_engine(reg, input, |e, c| {
            e.decide(c, field(input, "request")?.clone(), now_of(input)?)
        }),
        "explain" => with_engine(reg, input, |e, c| {
            e.explain(c, field(input, "request")?.clone(), now_of(input)?)
        }),
        "whyNot" => with_engine(reg, input, |e, c| {
            e.why_not(
                c,
                field(input, "request")?.clone(),
                now_of(input)?,
                optional(input, "options"),
            )
        }),
        "checkMany" => with_engine(reg, input, |e, c| {
            e.check_many(c, field(input, "requests")?.clone(), now_of(input)?)
                .map(|v| json!(v))
        }),
        "explainMany" => with_engine(reg, input, |e, c| {
            e.explain_many(c, field(input, "requests")?.clone(), now_of(input)?)
        }),
        "list" => with_engine(reg, input, |e, c| {
            e.list(
                c,
                field(input, "subject")?.clone(),
                text(input, "permission")?,
                text(input, "kind")?,
                optional(input, "options"),
                now_of(input)?,
            )
        }),
        "whoCan" => with_engine(reg, input, |e, c| {
            Ok(e.who_can(c, text(input, "permission")?, now_of(input)?))
        }),
        "catalog" => engine_only(reg, input, |e| Ok(e.catalog())),
        "apply" => engine_only(reg, input, |e| e.apply(input_of(input)?, clock_of(input))),
        "impact" => engine_only(reg, input, |e| e.impact(input_of(input)?, clock_of(input))),
        "reviewImpact" => engine_only(reg, input, |e| e.review_impact(input_of(input)?, clock_of(input))),
        "propose" => engine_only(reg, input, |e| e.propose(input_of(input)?, clock_of(input))),
        "resolve" => engine_only(reg, input, |e| e.resolve(input_of(input)?, clock_of(input))),
        "elevate" => engine_only(reg, input, |e| e.elevate(input_of(input)?, clock_of(input))),
        "recertify" => engine_only(reg, input, |e| e.recertify(input_of(input)?, clock_of(input))),
        "expire" => engine_only(reg, input, |e| e.expire(input_of(input)?, clock_of(input))),
        other => Err(BindingError::new(
            "INVALID_ARGUMENT",
            format!("unknown operation `{other}`"),
        )),
    }
}

fn input_of(input: &Value) -> BindingResult<Value> {
    Ok(field(input, "input")?.clone())
}

/// One call as the host sees it: the JSON envelope, as text.
pub fn call(op: &str, input: &str) -> String {
    let envelope = match serde_json::from_str::<Value>(input) {
        Err(e) => json!({ "ok": false, "code": "INVALID_INPUT", "message": format!("input is not JSON: {e}") }),
        Ok(input) => REGISTRY.with(|reg| match reg.try_borrow_mut() {
            Err(_) => {
                json!({ "ok": false, "code": "REENTRANT_CALL", "message": "the engine is already running a call" })
            }
            Ok(mut reg) => match dispatch(&mut reg, op, &input) {
                Ok(value) => json!({ "ok": true, "value": value }),
                Err(e) => {
                    json!({ "ok": false, "code": e.code.as_str(), "message": e.message, "diagnostics": e.diagnostics })
                }
            },
        }),
    };
    envelope.to_string()
}

#[cfg(target_arch = "wasm32")]
mod abi {
    /// Memory the host writes an input into, or reads an output from.
    #[unsafe(no_mangle)]
    pub extern "C" fn strig_alloc(len: usize) -> *mut u8 {
        Box::into_raw(vec![0u8; len].into_boxed_slice()).cast()
    }

    /// # Safety
    /// `ptr` and `len` come from `strig_alloc` or from the result of `strig_call`, and are freed once.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn strig_free(ptr: *mut u8, len: usize) {
        if !ptr.is_null() {
            drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
        }
    }

    /// # Safety
    /// Both ranges are readable memory the host wrote through `strig_alloc`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn strig_call(op_ptr: *const u8, op_len: usize, in_ptr: *const u8, in_len: usize) -> u64 {
        let op = unsafe { std::slice::from_raw_parts(op_ptr, op_len) };
        let input = unsafe { std::slice::from_raw_parts(in_ptr, in_len) };
        let answer = match (std::str::from_utf8(op), std::str::from_utf8(input)) {
            (Ok(op), Ok(input)) => super::call(op, input),
            _ => r#"{"ok":false,"code":"INVALID_INPUT","message":"input is not UTF-8"}"#.to_string(),
        };
        let len = answer.len();
        let ptr = Box::into_raw(answer.into_bytes().into_boxed_slice()).cast::<u8>();
        ((ptr as u64) << 32) | len as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> Value {
        json!({ "catalog": { "targetKinds": ["project"], "broadTargets": ["org"],
            "permissions": [{ "key": "project.view", "targets": ["project"] }] } })
    }

    fn grant() -> Value {
        json!({ "id": "g", "subject": { "kind": "role", "id": "member" }, "permission": "project.view",
            "target": { "kind": "project" }, "effect": "allow" })
    }

    fn request(permission: &str) -> Value {
        json!({ "subject": { "kind": "user", "id": "ana", "roles": [{ "role": "member" }] }, "permission": permission,
            "resource": { "path": [{ "kind": "project", "id": "p1" }, { "kind": "org", "id": "o1" }] } })
    }

    #[test]
    fn grant_allows_and_the_rest_is_denied() {
        let engine = value("engine.new", json!({ "spec": spec() }));
        let ctx = value("context.new", json!({ "init": { "grants": [grant()] } }));
        let ask = |p| json!({ "engine": engine, "context": ctx, "request": request(p) });
        assert_eq!(value("check", ask("project.view")), true);
        assert_eq!(value("decide", ask("project.view"))["effect"], "allow");
        assert_eq!(value("check", ask("project.edit")), false);
        assert_eq!(value("whyNot", ask("project.view")), Value::Null);
        let why = value("whyNot", ask("project.edit"));
        assert_eq!(why["cause"]["kind"], "unknown_permission");
        assert_eq!(why["remedies"], json!([]));
        assert_eq!(value("explain", ask("project.view"))["permission"], "project.view");
        assert_eq!(value("context.removeGrant", json!({ "context": ctx, "id": "g" })), true);
        assert_eq!(value("check", ask("project.view")), false);
    }

    fn value(op: &str, input: Value) -> Value {
        let out: Value = serde_json::from_str(&call(op, &input.to_string())).unwrap();
        assert_eq!(out["ok"], true, "{out}");
        out["value"].clone()
    }

    fn code(op: &str, input: Value) -> String {
        let out: Value = serde_json::from_str(&call(op, &input.to_string())).unwrap();
        assert_eq!(out["ok"], false, "{out}");
        out["code"].as_str().unwrap().to_string()
    }

    #[test]
    fn unknown_op_and_bad_json_are_coded_errors() {
        assert_eq!(code("nope", json!({})), "INVALID_ARGUMENT");
        let out: Value = serde_json::from_str(&call("check", "{")).unwrap();
        assert_eq!(out["code"], "INVALID_INPUT");
    }

    #[test]
    fn released_handle_is_refused() {
        let engine = value("engine.new", json!({ "spec": spec() }));
        assert_eq!(value("engine.free", json!({ "engine": engine })), true);
        let ctx = value("context.new", json!({}));
        assert_eq!(
            code("check", json!({ "engine": engine, "context": ctx, "request": {} })),
            "INVALID_ARGUMENT"
        );
    }

    #[test]
    fn apply_without_now_fails_closed() {
        let engine = value("engine.new", json!({ "spec": spec() }));
        assert_eq!(code("apply", json!({ "engine": engine, "input": {} })), "INVALID_INPUT");
    }

    #[test]
    fn compile_reports_parse_errors_with_code() {
        assert_eq!(
            code("dsl.compile", json!({ "text": "language blocks\n\npermission {" })),
            "DSL_PARSE"
        );
    }
}
