<p align="center">
  <img src="assets/banner.svg" alt="Strig: who can do what, and why. RBAC, ABAC and ReBAC, one decision engine for Rust." width="100%">
</p>

# Strig

[![CI](https://github.com/The-Hades-Organization/Strig/actions/workflows/ci.yml/badge.svg)](https://github.com/The-Hades-Organization/Strig/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)
[![crates.io](https://img.shields.io/crates/v/strig.svg)](https://crates.io/crates/strig)
[![docs.rs](https://img.shields.io/docsrs/strig)](https://docs.rs/strig)
[![npm](https://img.shields.io/npm/v/@the-hades-organization/strig.svg)](https://www.npmjs.com/package/@the-hades-organization/strig)

**English** · [Português (Brasil)](README.pt-BR.md)

Strig is an authorization library for Rust. You declare a permission catalog, hand the engine your grants, and ask whether a subject may do something to a resource. RBAC, ABAC and ReBAC are evaluated over the same grants. Changes to grants go through governance rules, are audited, and can be pushed in real time to other instances and to the browser.

The core does no IO, needs no async runtime and compiles to WebAssembly. Real time, transports and the JavaScript bindings are separate, optional crates.

[Documentation](https://strig.vercel.app/docs) · [Playground](https://strig-playground.vercel.app) · [API on docs.rs](https://docs.rs/strig) · [Changelog](CHANGELOG.md)

> [!NOTE]
> Strig is pre-1.0: the API can change between minor versions. Versions up to 0.5.0 were published as Themis. The [versioning and deprecation policy](docs/versioning.md) says what counts as public API and what breaks it, [migration.md](docs/migration.md) shows what to change when you upgrade, and [benchmarks](docs/benchmarks.md) has the numbers.

## Install

```sh
cargo add strig                             # Rust
cargo add strig --features dsl              # Rust, with the policy language
npm install @the-hades-organization/strig   # Node, Bun and the browser
pip install strig-auth                     # Python (import strig)
```

Features of the `strig` crate:

| Feature | Default | Adds |
|---|---|---|
| `audit` | yes | Audit trail for grant changes and decisions, with a hash chain |
| `exclusive` | no | One holder per resource, with priority and preemption |
| `conformance` | no | Turns on `exclusive` and adds `strig::exclusive_conformance`, the battery an `ExclusiveStore` adapter runs in its tests (not stable API) |
| `dsl` | no | The policy language: parse, validate, convert, format. No IO, works in wasm |
| `dsl-fs` | no | `dsl` plus reading and writing `.strig` files and directories |

## Quick start

```rust
use strig::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = Catalog::builder()
        .target_kinds(["project", "doc_type", "document"])
        .broad_target("org")
        .permission(PermissionDef::new("document.export").targets(["project", "document"]))
        .permission(
            PermissionDef::new("document.invoice.export")
                .targets(["doc_type", "document"])
                .implied_by(["document.export"]),
        )
        .build()?;

    let engine = Engine::builder(catalog).build()?;

    let grants = vec![
        Grant::allow("g1", SubjectMatcher::role("member"), "document.export", TargetSelector::kind("org"))
            .scoped(Anchor::new("org", "acme")),
        Grant::deny("g2", SubjectMatcher::Any, "document.invoice.export", TargetSelector::exact("doc_type", "invoice")),
    ];

    let dave = Subject::user("dave").with_role_in("member", Anchor::new("org", "acme"));
    let invoice = Resource::new("document", "d1")
        .within("doc_type", "invoice")
        .within("project", "p1")
        .within("org", "acme");

    let ctx = Context::new(&grants);
    let export_invoice = engine.decide(&ctx, &Request::new(&dave, "document.invoice.export", &invoice));
    let export = engine.decide(&ctx, &Request::new(&dave, "document.export", &invoice));
    println!("{:?} {:?}", export_invoice.effect, export_invoice.reason);
    println!("{:?} {:?}", export.effect, export.reason);
    Ok(())
}
```

```text
Deny Grant { grant_id: "g2", permission: "document.invoice.export", rank: 1, strategy: "most_specific" }
Allow Grant { grant_id: "g1", permission: "document.export", rank: 3, strategy: "most_specific" }
```

Dave may export documents anywhere in `acme` (`g1`), but not invoices: `g2` sits on `doc_type:invoice`, one step from the document (`rank: 1`), while `g1` sits on `org:acme`, three steps away (`rank: 3`). The rank counts steps from the resource itself (rank 0), and the default strategy lets the lowest rank decide.

The same engine runs in Node, Bun and the browser; see [JavaScript](#javascript-node-bun-and-the-browser).

The same engine can be configured from JSON, TOML or YAML through `EngineSpec`, or from a `.strig` file in the [policy language](#policy-language). `EngineSpec::builder()` returns the `EngineBuilder`, so you can add in code what does not serialize, such as condition functions.

More to run:

```sh
cargo run -p strig --example documents        # RBAC, ABAC and ReBAC in one domain
cargo run -p strig-axum --example server      # real-time server over SSE and WebSocket
```

## Crates

All crates except `strig-inspect`, `strig-node`, `strig-python`, `strig-wasi` and `strig-lsp` are on crates.io at the same version.

| Crate | Use it for | Main dependencies |
|---|---|---|
| `strig` | Catalog, decision engine, governance, auditing, JSON spec, policy language | `serde`, `thiserror`; `sha2` with `audit` |
| `strig-sync` | Change hub, `Transport` trait, SSE/WebSocket sessions independent of any web framework, capability cache | `tokio` |
| `strig-redis` | `Transport` over Redis pub/sub | `redis` |
| `strig-postgres` | `Transport` over Postgres `LISTEN/NOTIFY`, sent inside your transaction; grants, tuples, roles and pending requests stored in Postgres | `tokio-postgres` |
| `strig-axum` | axum SSE and WebSocket routes over `strig-sync` sessions | `axum` |
| `strig-server` | HTTP decision server, and a Rust client that denies when it gets no answer | `axum`, `hyper-util` (client) |
| `strig-macros` | `policy!` and `include_policy!`: the policy is validated at compile time | `strig` |
| `strig-node` | The npm package: native module (N-API) for Node and Bun, WebAssembly for the browser | `napi` or `wasm-bindgen` |
| `strig-python` | The PyPI package `strig-auth` (`import strig`): native extension (PyO3, abi3) over the same core as `strig-node` | `pyo3` |
| `strig-wasi` | The C-ABI WebAssembly module the Go and JVM bindings run: JSON in, JSON out, no `wasm-bindgen` | `strig-node` |
| `strig-cli` | The `strig` command: `strig test` runs the tests of a policy, for people and for CI (JUnit) | `strig` |
| `strig-lsp` | Language server for `.strig` files over stdio: diagnostics, formatting, completion, hover, go to definition, convert (built from source; the VS Code extension is in `editors/vscode`) | `strig`, `lsp-server` |
| `strig-inspect` | Inspector: decision traces, grant simulation, access matrix, audit trail. Desktop window and terminal commands | `gpui-pre`, `gpui-component` |

```toml
[dependencies]
strig = "0.6"
strig-sync = "0.6"
```

## Concepts

| Concept | Type | What it holds |
|---|---|---|
| Catalog | `Catalog`, `PermissionDef` | Dotted permission keys (`document.invoice.export`), the targets each accepts, `implied_by`, free-form `meta`. Exports and imports JSON. |
| Resource | `Resource`, `Anchor` | A path of steps (anchors) from the most specific to the broadest (`document:7 → doc_type:invoice → project:42 → org:9`), with an implicit `global` at the end, plus attributes. |
| Subject | `Subject` | Id, roles (optionally scoped), principals (`authenticated`, `anonymous` or your own), attributes. |
| Grant | `Grant` | Who (`User`, `Role`, `Principal`, `Relation`, `Any`), which permission, on which target (a kind or an exact step), allow or deny, with an optional scope (an anchor the resource path must pass through) and condition. |
| Engine | `Engine` | Decides. Returns a `Decision` with the effect, the reason, the matched grants and warnings. |
| Governance | `Governance`, `Invariant` | Applies a grant change only if every invariant passes, and audits the outcome. |

The catalog is validated when it is built. It refuses a malformed key, a duplicate, an unregistered target, a missing parent, a cycle, and anything your own `CatalogRule` rejects.

## How a decision is made

1. **Unknown permission.** Deny with `Reason::UnknownPermission`.
2. **Overrides.** They run in order, and the first one that answers decides. `override_except` takes permissions, and the ones they imply, out of an override's reach.
3. **Collection.** A grant is a candidate when all of these hold:
   - its permission is the requested one, or one that implies it;
   - its scope is on the resource path;
   - its target matches a step of the path;
   - its subject matches;
   - its condition is true.
4. **Strategy.** The strategy picks the deciding grant. With no candidate, deny.

A condition or relation that cannot be evaluated (missing attribute, engine without a `TupleStore`) never opens access: the `allow` is dropped, the `deny` still applies, and the reason goes into `Decision::warnings`.

| Strategy | Rule |
|---|---|
| `MostSpecific` (default) | The most specific step with any grant decides; on that step, `deny` wins. |
| `DenyOverrides` | Any `deny` wins. |
| `PermitOverrides` | Any `allow` wins. |
| `FirstApplicable` | The first grant in source order decides. |

## The three models

### RBAC

`RoleGraph::builder().inherit("maintainer", "member")` gives `maintainer` the grants of `member`. `Subject::with_role_in(role, anchor)` limits a role to the resources under that step.

### ABAC

`Grant::when(condition)` attaches a serializable `Condition`. Operands read `subject.*`, `resource.*` and `env.*`.

| Operators | On |
|---|---|
| `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `is_in`, `exists` | Any value |
| `starts_with`, `ends_with`, `contains` | Text (`contains` also tests list membership) |
| `any_in`, `all_in` | Lists |
| `ip_in` | An address in a CIDR or a list of CIDRs |
| `time_between`, `weekday_in` | The decision instant, in UTC or in the IANA zone `tz` |
| `all`, `any`, `not` | Other conditions |
| `call` | Your own function, registered with `ConditionRegistry::register` |

The time conditions read the instant given by `Context::at`; without it they cannot be resolved, so the `allow` does not apply. There is no regular-expression condition. `Engine::validate_grant` checks that every `call` names a registered function.

#### Time zones

Office hours are local, so `time_between` and `weekday_in` take an optional IANA zone: `Condition::time_between("09:00", "18:00").in_tz("America/Sao_Paulo")` in Rust, `{"op": "time_between", "from": "09:00", "until": "18:00", "tz": "America/Sao_Paulo"}` in JSON or JavaScript, and `time_between "09:00" "18:00" tz "America/Sao_Paulo"` or `weekday_in ["mon", "tue"] tz "Europe/Lisbon"` in the policy language. Without `tz` the clock is UTC, as before.

- **Daylight saving time.** The instant decides the local time. A window inside the hour that a spring-forward jump skips never holds that day; the hour that a fall-back repeats holds on both passes. A window that crosses midnight (`"22:00"` to `"06:00"`) and the weekday follow the local date.
- **Unknown names.** The validator refuses a zone it does not know when the policy loads, with position and hint. A condition built without validation fails when evaluated, and an `allow` with an error never applies.
- **Trace.** `explain` shows the local time it used, for example `12:30 America/Sao_Paulo (UTC-03:00)`.
- **Cost.** The zone database is the default feature `tz` of the `strig` crate (`chrono-tz`) and adds about 0.9 MB (0.13 MB gzipped) to the `.wasm`. Without the feature a `tz` is refused at load.

### ReBAC

Store `object#relation@subject` tuples in a `TupleStore` and describe each type in a `RelationSchema` with `This`, `Computed`, `TupleToUserset`, `Union`, `Intersection` and `Exclusion`. `user:*` stands for every user.

A grant with `SubjectMatcher::relation("editor")` applies to whoever holds `editor` on the step its target matched. The search stops at `max_relation_depth` (32 by default) and cuts cycles.

## Governance

`Governance` runs a grant change through a list of invariants and returns the new grant set only if all of them pass. Persist the result on `Ok`; on `Err` you get the violations.

From here on, snippets reuse the `engine`, `grants` and subjects of earlier examples; names such as `actor`, `current` (the grants you hold today) and `request_meta` stand for your own values. The `None` argument is an optional `TupleStore` for ReBAC, and `apply_with` is `apply` plus request metadata for the audit trail.

```rust
let governance = Governance::new()
    .with(CatalogConformance)
    .with(RequirePermission::new("org.roles.edit", org_resource.clone()))
    .with(NoSelfManagement)
    .with(NoLockout::new(["org.invite"], members, org_resource))
    .with(Forbid::new(SubjectMatcher::principal(AUTHENTICATED), ["project.delete"]))
    .audited(auditor);

let next = governance.apply_with(&engine, &actor, &current, &Mutation::Add(grant), None, &request_meta)?;
// persist `next`
```

Assigning or revoking a role goes through the same invariants and is audited as `role_assign` or `role_revoke`. The grant set comes back unchanged; the subject to persist comes from `Mutation::subject_after`.

```rust
let change = Mutation::AssignRole { subject: bob, role: RoleAssignment::in_scope("editor", org) };
governance.apply_with(&engine, &actor, &current, &change, None, &request_meta)?;
let bob = change.subject_after().expect("role change"); // persist bob's roles
```

`Forbid` applies to a role assignment only when the assignment targets a user, and it ignores scope. Write your own rule by implementing `Invariant`. The invariant list can also come from JSON (`InvariantSpec`).

### Approving a change before it applies

A change the policy marks as needing approval does not apply on the spot: it waits as a pending request that another actor approves or refuses. The policy is per kind of change and names who approves.

```rust
let policy = ApprovalPolicy::new()
    .require(MutationKind::Add, "org.approve", org_resource.clone())
    .require(MutationKind::AssignRole, "org.approve", org_resource);
let store = MemoryPendingStore::new();
let flow = Approvals::new(&governance, &policy, &store);
let review = Review { engine: &engine, current: &current, tuples: None, now, meta: &request_meta };

// Ana proposes; the invariants judge it and, if they accept, it is kept (expires in an hour).
let Proposed::Pending(request) = flow.propose(&review, &ana, &Mutation::Add(grant), "req-1", Some(now + 3_600_000))? else {
    unreachable!("the policy covers Add");
};

// Caio approves: he needs `org.approve`, he is not Ana, and the invariants run again over `current`.
let approved = flow.approve(&review, &caio, &request.id)?;
// persist `approved.grants`
```

An approver who is the author, lacks the permission, or meets invariants that now refuse gets `ApprovalError::Refused` and the request stays pending; `reject(&review, &caio, id, "reason")` closes it with a reason, and `expire_due(now, &meta)` closes the ones whose expiry came (approving a due request closes it too). With an auditor on the governance, every step is a record (`mutation_propose`, `mutation_approve`, `mutation_reject`, `mutation_expire`; see [`docs/audit-format.md`](docs/audit-format.md)), and the approval record is written before the change is applied. The crate keeps no clock and no database: pass the instant, and serialise approvals of one request when several processes share a store. Not covered: several approvers (quorum) and the author withdrawing their own request.

In JavaScript the engine judges and audits each step and `Approvals` keeps the requests:

```js
import { Approvals, MemoryPendingStore } from '@the-hades-organization/strig/approvals';

const flow = new Approvals(engine, new MemoryPendingStore(), {
  approval: [{ kind: 'add', permission: 'org.approve', resource: orgResource }],
  invariants,
});
const proposed = await flow.propose(ana, { add: grant }, grants, { id: 'req-1', expiresAt: Date.now() + 3_600_000 });
const done = await flow.approve('req-1', caio, grants, { persist: (r) => saveGrants(r.grants) }); // `persist` runs before the request is marked approved
await flow.reject('req-2', caio, 'outside the change window', grants);
await flow.expire();
```

`JsonFileStore` keeps the requests in the same file (`new Approvals(engine, store.pendingStore, options)`, and `store.approvePending(flow, id, approver)` persists the grants before marking the request approved). Without a rule for its kind, `propose` applies the change at once (`applied: true`).

### Seeing the impact of a change before it applies

`Governance::apply` says whether a change passes the invariants, not what it does to access. `Governance::impact` answers that without applying anything: it judges the change as `apply` does (a refused change returns its violations), then asks the same questions over the grants before and after, and returns an `Impact`: who gains, who loses, which permission, on which resource (and field).

```rust
let options = ImpactOptions::new(ImpactSource::sample(
    SampleSpec::new().subject(bob).resource(project),
)); // or ImpactSource::derived()
let impact = governance.impact(&engine, &ana, &current, &Mutation::Add(grant), &options)?;
for change in &impact.gained { /* change.subject, change.permission, change.resource */ }
```

The questions come from one of two sources. A **sample** is yours: subjects × resources × permissions (and fields); leave resources or permissions empty and they are the ones the change reaches and touches. **Derived** uses the reverse queries (`who_can_on`, `list`, `access_of`), restricted to the permissions the change touches, with the ones that imply them (`implied_by`) and the ones that depend on them (`depends_on`). A deny that cuts, an override and a field count as in `check`. `ImpactOptions` takes the tuples, the `env`, the `QueryLimits` and an instant; when a limit cuts, `partial` is `true` and `notes` says which, so absence from the list is not proof. What cannot be settled (a condition or an override that cannot be evaluated) is in `indeterminate`, never in `gained`: a change is a gain only when the answer was a certain deny and is now an allow.

`Governance::apply_with_impact` applies and returns the grants with the impact; with an auditor at `detailed` or `forensic`, the record carries `impact` (counts and up to 10 examples, see [`docs/audit-format.md`](docs/audit-format.md)). `Approvals::with_impact(&options)` stores the impact in the pending request when it is proposed; `approve` recomputes it over the grants of that moment (`Approved::proposed_impact` keeps the first one) and `review_impact` shows the approver both and whether they differ, before deciding. The JSON store keeps the request whole, so older stores open unchanged.

In JavaScript, `engine.impact(input)` takes the input of `apply` plus `impact: { source, env, limits }`, `apply` with `impact` returns it in `result.impact`, and `Approvals` takes `impact` in its options and has `reviewImpact(id, current)`; the Python binding has `engine.impact` and `engine.review_impact` and the Go and JVM ones `Impact`/`ReviewImpact`.

```js
const preview = engine.impact({
  actor: ana, current: grants, mutation: { add: grant },
  impact: { source: { kind: 'sample', subjects: [bob], resources: [project] } },
});
if (preview.ok) console.log(preview.impact.gained, preview.impact.lost, preview.impact.partial);
```

### Temporary elevation and break-glass

An elevation is a role or a permission held for a while. It rides on the approval flow: the policy says, per role or permission, how long it can last, who approves it, whether a justification is required and whether the actor may take it in an emergency (break-glass).

```rust
let target = ElevationTarget::permission("project.edit", TargetSelector::exact("project", "p1")).scoped(org());
let policy = ElevationPolicy::new().with(
    ElevationRule::new(target.key(), 4 * HOUR, "org.approve", org_resource)
        .requiring_justification()
        .allowing_break_glass(HOUR), // never longer than the rule's own maximum
);
let flow = Elevations::new(&governance, &policy, &store); // + .with_impact(&options)

// Ana asks; it waits for an approver.
let Elevated::Pending(request) = flow.request(&review, &ElevationRequest::new("e1", ana, target, 2 * HOUR).justified("incident 42"), None)? else { unreachable!() };
// Caio approves: the window is [approval, approval + 2h), never past the maximum.
let approved = flow.approve(&review, &caio, "e1")?; // persist approved.grants
flow.revoke(&review, &ana, "e1", Some("done"))?;    // early, by the actor or by an approver
```

- **Approval.** `approve` is `Approvals::approve` with the window opening at the instant of the approval: the elevation becomes an allow grant `elevation:<id>` or a role assignment with `valid_from` and `valid_until`, so the engine drops it at the instant, with no job. The author never approves their own request, the invariants run again over `current` and the impact (`with_impact`) is in the request, as for any change. A policy tightened after the request refuses an approval that would go past the new maximum. A duration over the maximum, a missing justification and a role or permission the policy does not list are refused when asked.
- **Break-glass.** `ElevationRequest::break_glass()` is allowed only where the rule has `allowing_break_glass`, with its own, shorter maximum and a justification. The actor approves it themselves: it is in force at once, marked `break_glass` and with a review `pending`. It needs an auditor at `forensic`, and its records are written with `FailMode::Closed` whatever the call, the permission or the auditor say: if the sink fails, the elevation is denied. Another actor who holds the approver permission closes the review with `close_review` (`elevation_review` record, also forensic and closed); `pending_reviews()` lists what is open. The actor cannot close their own.
- **Revocation and renewal.** `revoke` takes the grant or the role back through the governance and keeps the `Revocation` in the request. Renewing is a new request.
- **Where it is kept.** The elevation is the `elevation` field of the `PendingRequest`, so the stores need no schema change. A decided request is annotated with the revocation or the review through `PendingStore::annotate` (the decision is not touched); implement it in your own store, the default refuses. `Elevations::active(now)` lists what is in force.
- **Real time.** In `strig-sync`, `hub.elevation_approved(&request, now)` publishes the `Change` of the elevation and schedules the expiry notice at `valid_until` (the same mechanism as the windows the `CapabilityCache` follows); `hub.elevation_revoked(&request)` publishes the revocation.
- **Choices to know.** Revocation is judged by the invariants as the one who revokes, so an invariant such as `NoSelfManagement` can refuse a self-revocation. A request for a role or permission the policy does not list is an attempt to escalate: it is refused with the violation `not_in_policy` and audited (`mutation_propose`, outcome `rejected`, `refusal: not_in_policy` in the metadata) at the auditor's level, with no rule needed; a failing sink in `closed` mode turns it into an `audit` refusal. A refused `revoke` on a request that is not an elevation, not approved, already revoked or already over leaves no record. `annotate` runs after the grant was applied: if it fails the grant is already gone and the request lacks the mark, so the caller keeps the grants it was given.

In JavaScript, `Elevations` (`@the-hades-organization/strig/approvals`) keeps the requests over a `PendingStore` that has `annotate` (`MemoryPendingStore` and `JsonFileStore.pendingStore` do) and calls `engine.elevate(input)`, which is also in Python (`engine.elevate`) and the Wasm ABI (`elevate`):

```js
const flow = new Elevations(engine, store.pendingStore, {
  elevation: [{ key: { permission: 'project.edit' }, maxDurationMs: 4 * HOUR, approverPermission: 'org.approve', approverResource: orgResource, requireJustification: true, breakGlass: { maxDurationMs: HOUR } }],
  invariants,
  audit: { level: 'forensic' },
});
await flow.request({ id: 'e1', actor: ana, target, durationMs: 2 * HOUR, justification: 'incident 42' }, grants);
await flow.approve('e1', caio, grants, { persist: (r) => saveGrants(r.grants) });
await flow.revoke('e1', ana, grants, { reason: 'done', persist: (r) => saveGrants(r.grants) });
await flow.closeReview('e2', caio, 'legitimate use', grants); // after a break-glass
```

### Separation of duties

The catalog declares what nobody may accumulate and what nobody may do twice on the same resource.

```rust
let catalog = Catalog::builder()
    .target_kinds(["org", "payment"])
    .permission(PermissionDef::new("payment.create").targets(["payment"]))
    .permission(PermissionDef::new("payment.approve").targets(["payment"]))
    // static: nobody holds both roles inside the same org
    .mutually_exclusive(MutualExclusion::new("payment_duties", ExclusiveKind::Roles, ["maker", "checker"]).per_anchor("org"))
    // dynamic: whoever created a payment does not approve it
    .conflicting_actions(ActionConflict::new("four_eyes", ["payment.create"], ["payment.approve"]))
    .build()?;
let governance = Governance::new().with(SeparationOfDuties::new());
```

**Static.** A `mutually_exclusive` set lists roles or permissions, with a name and a scope: global, or `per_anchor("org")`
to clash only inside the same anchor. The `SeparationOfDuties` invariant refuses the change that would create an
accumulation that did not exist, whichever way the member is reached: a direct role, an inherited one (`RoleGraph`), a
grant or a temporary elevation. The `Violation` names the set and both sides. Removing and revoking never create a clash,
so a set that is already violated can always be repaired; a `deny` is never read as taking a member away. `with_subjects`
adds subjects whose holdings an added grant is also judged against. `Impact` lists the clashes a change would create in
`separation` whether or not the invariant is on, and `strig lint` reports the sets already violated (`L009`).

**Dynamic.** A `conflicting_actions` rule says that whoever did a `first` action on a resource does not do a `then`
action on it. The engine evaluates it in every decision, before the overrides, with no IO: the history is an attribute
of the resource (`history` by default, or the one the rule names) or of `env`, a list of `"<permission>:<actor>"`
entries (`"payment.create:ana"`). The denial reads `Reason::Override` named `separation:<rule>`. With `distinct_roles`,
an entry also carries the roles the author acted with (`"payment.create:ana|maker"`) and a subject who holds one of
them is refused too; an entry with no roles refuses, and so does a history that cannot be read: the rule fails closed.
A listing or a reverse query never lets the rule open anything: for a permission in `then` the answer stays a residue.

In an approval flow, `Approvals::with_distinct_roles()` also refuses an approver who shares a role with the author, on
top of the author never approving their own request.

In the policy language it is `mutually_exclusive` and `conflicting_actions` in the catalog and the `separation_of_duties`
invariant; see [docs/dsl.md](docs/dsl.md). A policy that uses them exports `"schema": 5`.

### Rules declared in the catalog

Some rules belong to a permission, so they are declared on its `PermissionDef`:

| Flag | Effect |
|---|---|
| `depends_on` | Holding the permission requires holding each listed one on the same resource (checked by `Prerequisites`). |
| `non_delegable` | Only a manager hands it out, not whoever merely holds it. |
| `management_only` | Grantable only to management roles. |
| `override_only` | Valid only through an override; a plain grant of it does not count. |

`NoEscalation` keeps an actor from handing out what they do not hold: an `allow` grant or a role assignment is refused unless the actor holds every permission it confers, and every permission those imply, wherever it would apply. Holding `org.roles.edit` is therefore not a way to give someone a stronger role than your own.

```rust
let catalog = Catalog::builder()
    .target_kind("project")
    .permission(PermissionDef::new("project.view").targets(["project"]))
    .permission(PermissionDef::new("project.edit").targets(["project"]).depends_on(["project.view"]))
    .permission(PermissionDef::new("project.share").targets(["project"]).non_delegable())
    .permission(PermissionDef::new("project.purge").targets(["project"]).override_only())
    .build()?;
let engine = Engine::builder(catalog).build()?;

let governance = Governance::new()
    .with(CatalogConformance)
    .with(Prerequisites)
    .with(NoEscalation::new());

// `lead` holds `project.edit` only, so handing out `project.view` is an escalation.
let current = vec![Grant::allow("l", SubjectMatcher::user("lead"), "project.edit", TargetSelector::kind("project"))];
let handout = Mutation::Add(Grant::allow("a", SubjectMatcher::user("ana"), "project.view", TargetSelector::kind("project")));
let refused = governance.apply(&engine, &Subject::user("lead"), &current, &handout, None).unwrap_err();
assert_eq!(refused[0].invariant, "no_escalation");
```

Two more tools:

- **Lockout reserve.** `NoLockout::with_reserve` names who should take over a critical permission. When a change would leave that permission with no holder, the `Violation` carries a `Suggestion` with the role assignment that fixes it. Nothing is applied; the suggestion is also written to the audit record.
- **Role templates.** `RoleTemplate::materialize` turns a template into ordinary grants. The template id and version go into the change metadata; the grants keep no link to the template.

## Auditing

With the `audit` feature, every change that goes through governance becomes an `AuditRecord`, applied or refused. Record ReBAC tuples and role assignments with `Auditor::tuple_change` and `Auditor::role_change`. If the sink fails to write, governance refuses the change with the `audit` violation: no record, no change (unless you choose `FailMode::Open`, below).

```rust
let auditor = Arc::new(Auditor::new(AuditLevel::Standard, Arc::new(JsonLinesAudit::new(file))));
```

Built-in sinks are `MemoryAuditLog` and `JsonLinesAudit`, which writes to any `io::Write`. To send records to a database, a queue or a SIEM, implement `AuditSink`.

### What each level keeps

Each level keeps everything from the one above it. Sizes are compact JSON bytes per line of JSON Lines, without compression or indexes, measured on a reference record (`audit::reference_record`): a grant with a scope and a two-clause condition, UUID ids, an actor with two roles and three request metadata entries.

| Level | Change records keep | Bytes | Per 1M records |
|---|---|---:|---:|
| `minimal` | When, who, action, object id, outcome | 175 | 175 MB |
| `standard` | + grant summary (permission, subject, target, effect, scope, has a condition) and the names of the invariants that refused | 388 | 388 MB |
| `detailed` | + the whole grant with its condition, the full actor, the violation messages, the request metadata | 1,097 | 1.10 GB |
| `forensic` | + SHA-256 digest of the grant set before and after, and the hash chain | 1,415 | 1.42 GB |

Decisions can be audited too: `Auditor::decide(&engine, &ctx, &request, &meta)` decides and records. The reference decision (`audit::reference_decision_record`) has three grants in the source, one with a condition, a resource with three steps, UUID ids and three metadata entries.

| Level | Decision records keep | Bytes | Per 1M records |
|---|---|---:|---:|
| `minimal` | When, subject, `permission@resource`, allowed or denied | 285 | 285 MB |
| `standard` | + the reason (override, deciding grant and step, or no grant) and the matched grants | 669 | 669 MB |
| `detailed` | + the full subject and resource, the warnings, the request metadata. Enough to re-evaluate the decision later | 1,239 | 1.24 GB |
| `forensic` | + the full trace from `Engine::explain`, and the hash chain | 3,582 | 3.58 GB |

To project your own volume, call `AuditLevel::estimate_bytes(n)` for changes and `AuditLevel::estimate_decision_bytes(n)` for decisions; the forensic decision size grows with the number of grants the source returns. In a database, add the row overhead (about 28 bytes per row in Postgres) and your indexes.

The numbers are checked: the `estimates_match_reference_records` and `decision_estimates_match_reference_records` tests fail if a measured size drifts more than 10% from the table, and `cargo run -p strig --example audit_storage` measures again.

### Hash chain

At the `forensic` level each record carries the hash of the previous one. `audit::verify_chain` detects an edited or removed record, and `Auditor::resume_chain` continues the chain after a restart.

The exact bytes of a record and the hash computation, with a test vector another language can reproduce, are in [docs/audit-format.md](docs/audit-format.md). The same page explains how to take only the records and chain them in your own log, and how to anchor the head of the chain outside (`Auditor::chain_head`, then `verify_chain_anchored(&records, start, head)`), which is what catches records cut off the end.

### Verifiable by third parties

A hash chain proves the log is intact to whoever holds all of it. Three additions let an auditor check the trail without trusting the host, and none changes the record or its hash:

- **Merkle proofs** (`strig::merkle`, feature `audit`): the records are the leaves of an RFC 6962 / RFC 9162 tree. `MerkleTree::from_records(&records)` gives the root, an inclusion proof for one record and a consistency proof between two heads, so you can hand one record or one stretch to an auditor without the rest. `verify_inclusion` and `verify_consistency` are pure; in JS, `verifyMerkleInclusion({ record, index, size, proof, root })` and `verifyMerkleConsistency({ first, second, firstRoot, secondRoot, proof })`.
- **RFC 3161 time stamps** (feature `timestamp`, off by default; the core without it gains no dependency): `TimestampRequest::for_chain_head(head, nonce)` builds the request for the head, you send it to a TSA, and `timestamp::verify_response` (JS: `verifyTimestamp({ response, head, roots, nonce? })`, no network) checks the imprint, nonce, policy, signature and the certificate chain against the roots **you** supply. Without a root it refuses everything. `examples/timestamp_http.rs` sends the request with `curl`.
- **Conformance report**: `strig audit report trail.jsonl --anchor-head <hash> --timestamp head.tsr --root ca.pem [--json]` summarizes the period, records per action and outcome, changes per actor, refusals per invariant, chain breaks, anchors and stamps, and exits `1` when the trail does not conform. The same data is `strig::audit_report::ConformanceReport`.

The tree, the stamp and their test vectors, reproducible in another language, are in [docs/audit-format.md](docs/audit-format.md).

### When the sink fails

By default a sink that fails refuses the change (`FailMode::Closed`). With `FailMode::Open` the change goes ahead and the record waits in an in-memory retry queue, in order, with a capacity and a backoff you set (`RetryPolicy`); `AuditStatus::Pending` says it is waiting and `Auditor::stats()` counts what is waiting or was dropped. The mode is chosen per call (`governance.at(now).fail_mode(..)`, `Auditor::grant_mutation_with`), per permission (`with_permission_fail_mode`) or as the auditor's default (`with_fail_mode`), in that order of precedence.

```rust
let auditor = Auditor::new(AuditLevel::Forensic, sink)
    .with_fail_mode(FailMode::Closed)
    .with_permission_fail_mode("report.view", FailMode::Open)
    .with_retry(RetryPolicy { capacity: 500, ..RetryPolicy::default() })
    .with_redactor(mask_attributes(["ip", "email"], "[redacted]"));
```

`with_redactor` masks attributes before the record is hashed and written, so the hash covers the masked version.

In JS the sink is a synchronous function; a throw is a failure of the sink:

```js
const engine = new Engine(spec, {
  auditSink: (record) => log.append(record),
  auditPolicy: { failMode: 'closed', permissions: { 'report.view': 'open' }, capacity: 500 },
  onAuditDrop: (record) => spill.write(record),
});
const out = engine.apply({ actor, current, mutation, audit: { level: 'forensic', prevHash, failMode: 'open' } });
out.auditStatus;                 // 'written' | 'pending' | 'dropped'
engine.flushAudit();             // retries the queue, answers { pending, writtenLate, dropped, failures, nextRetryAt }
verifyAuditChain(records, { start, head }); // { ok: true, head } or { ok: false, code }
```

## Validity windows

`Grant::valid_between(from, until)` limits a grant in time; `valid_from` and `valid_until` set one end.

- Times are milliseconds since the Unix epoch. The window includes `from` and excludes `until`.
- The caller supplies the instant: `Context::at(now)` for decisions, `Governance::at(now)` for changes.
- Without an instant, a grant with a window does not apply, so a missing clock denies.

```rust
let grant = Grant::allow("w", SubjectMatcher::user("ana"), "project.view", TargetSelector::kind("project"))
    .valid_between(1_000, 2_000);
let grants = vec![grant];
let ana = Subject::user("ana");
let project = Resource::new("project", "p1");
let request = Request::new(&ana, "project.view", &project);

assert!(engine.check(&Context::new(&grants).at(1_500), &request));
assert!(!engine.check(&Context::new(&grants).at(2_000), &request));
assert!(!engine.check(&Context::new(&grants), &request));
```

`CapabilityCache` expires its entries at the next window boundary. Removing expired grants from storage is left to a job of yours.

## Field permissions

A grant can name the fields of the resource it covers, as CASL does: "`document.edit` only on `title` and `body`". A grant without fields covers the whole resource, exactly as before.

```rust
let catalog = Catalog::builder()
    .target_kinds(["document"])
    .permission(PermissionDef::new("document.edit").targets(["document"]).fields(["title", "body", "status"]))
    .build()?;
let engine = Engine::builder(catalog).build()?;

let grants = vec![
    Grant::allow("edit", SubjectMatcher::role("editor"), "document.edit", TargetSelector::kind("document")),
    Grant::deny("freeze", SubjectMatcher::role("editor"), "document.edit", TargetSelector::kind("document"))
        .fields(["status"]),
];
let ana = Subject::user("ana").with_role("editor");
let doc = Resource::new("document", "d1");
let ctx = Context::new(&grants);

engine.allowed_fields(&ctx, &ana, "document.edit", &doc); // FieldSet::Only { title, body }
engine.check(&ctx, &Request::new(&ana, "document.edit", &doc).field("title")); // true
engine.check(&ctx, &Request::new(&ana, "document.edit", &doc).field("status")); // false
```

How the pieces combine:

- **One field is one decision.** A question about a field (`Request::field`) is decided by the same strategy (`MostSpecific`, `DenyOverrides`, `PermitOverrides`, `FirstApplicable`) over the grants that cover that field. A `deny` with fields takes away only those fields; an `allow` with fields gives only those. There is no new rule to learn: each field is judged as if the grants that do not name it did not exist.
- **The whole resource needs every field.** A question without a field is allowed only by a grant without fields, and a `deny` with fields blocks it as soon as the strategy would deny any of its fields. So `check` stays safe to use as a gate: a field-restricted `allow` never opens the resource, and it is `allowed_fields` that answers "which fields".
- **`implied_by` carries the fields.** A grant of `document.manage` restricted to `title` gives `document.edit` on `title` only.
- **`depends_on` is judged on the same field.** `document.edit` on `body` needs `document.view` on `body` (or on the whole resource).
- **The catalog can declare the fields** of a permission. Then a grant that names another field is refused by `validate_grant` (and by the policy validator, with the line and a hint), and a request for an undeclared field is denied. Without a declaration the engine trusts the names the grants use, and `allowed_fields` can answer `AllExcept` ("everything but `status`"), since it cannot list the rest.
- **It fails closed.** A condition that cannot be evaluated drops an `allow` and keeps a `deny`, field by field. An override that allows gives every field.
- **A policy without fields decides as it always did.** The tests pin this.

`Engine::explain_fields` returns, for each field, the grants that gave it and the ones that took it away; `Engine::explain` of a request with a field marks the grants that do not cover it (`FieldNotCovered`). Listings (`list`) and `who_can` answer for the whole resource: a field-restricted `allow` is left out and a field-restricted `deny` counts as a plain one.

Governance follows: `NoEscalation` refuses to hand out a field the actor does not hold (and a whole-resource grant to someone who holds only some fields), and `CatalogConformance` validates the fields against the catalog.

In the policy language, `fields` is a field of `permission` and of `grant` in the three syntaxes (`fields = [title, body]` in Blocks, `fields title, body` in Rules and Actors). A policy that uses fields exports `"schema": 4`, so a reader of an older schema refuses it instead of reading a field-restricted grant as a whole-resource one. See [docs/dsl.md](docs/dsl.md).

In JavaScript, `engine.allowedFields(ctx, request)` returns `{ kind: 'all' | 'all_except' | 'only' | 'none', fields? }`, `request.field` asks about one field, and `pickAllowed(object, fields)` masks a response:

```ts
const fields = engine.allowedFields(ctx, { subject, permission: 'document.edit', resource });
res.json(pickAllowed(document, fields)); // only title and body leave
```

`PermissionClient.allowedFields(permission, resource)` and `can(permission, resource, field)` decide locally. Capabilities that carry field-restricted grants are sent in two forms (`grants` for older readers, which never see a restricted `allow` and read a restricted `deny` as whole, and `withFields` with the real ones), so an older client fails closed.

## Why not? What would allow it

`Engine::explain` says why a decision came out as it did. When it is a denial, `Engine::why_not(ctx, request, options)` adds what would turn it into an `allow`: the smallest changes, smallest and most specific first. It returns `None` when the request is already allowed.

```rust
let answer = engine.why_not(&ctx, &request, &WhyNotOptions::default()).expect("denied");
println!("{:?}", answer.cause); // what denied it: Cause::NoApplicableGrant, Cause::Deny { .. }, Cause::Override { .. }, ...
for remedy in &answer.remedies {
    println!("{:?} {:?}", remedy.change, remedy.caveats);
}
```

| Change | Meaning |
|---|---|
| `SatisfyCondition` | an otherwise applicable `allow` has a condition that failed (`failed`, with the values the engine saw) or could not be evaluated (`unresolved`, a missing attribute for example). No value is invented: it names what has to hold. |
| `AddGrant` | an `allow` for the subject on the most specific step of the path (the exact target, then the kind), checked with `validate_grant`, so it respects the catalog's `targets` and `fields`; a field question asks for that field only |
| `NarrowDeny` | take the asked field out of the `fields` of the `deny` that decided |
| `AssignRole` | a role that has an applicable `allow`, scoped to the narrowest step of the path |
| `RemoveDeny` | remove the `deny` that decided |

Every remedy is **verified**: the engine applies it alone to a copy of the subject or of the grants and decides the request again. Only a change that comes out as `allow` is returned, so a suggestion that would not work (a role blocked by a deny, a grant a `DenyOverrides` strategy still beats) does not appear. Nothing is written.

- A denial by an **override** (a suspended account, for example) comes back as `Cause::Override { name }` with no remedy: no change of grants or roles undoes it. The same goes for `UnknownPermission` and for an `override_only` permission (`Cause::OverrideOnlyPermission`). When a prerequisite (`depends_on`) is what is missing, the cause says which, with the cause of the prerequisite, and the remedies are for the prerequisite.
- Each remedy carries `caveats` for the governance the catalog knows (`ManagementOnly`, `NonDelegable`, `OverrideOnly`) and `AffectsOthers` when the change edits a grant that is not the subject's own. The invariants of a `Governance` are not consulted: the change may still be refused when applied.
- Grants of other subjects are never listed: only the `deny` that decided is named, and only a role's `allow` is used to suggest that role.
- `WhyNotOptions` bounds the work: `limits.max_decisions` caps the verifications (the engine has no clock, so the bound is a count, as in the reverse queries) and `max_remedies` the list (16 by default). When either cuts the answer, `partial` is true.
- Changes are single: a denial that needs two changes at once (an allow that is also beaten by a deny) shows the deny's removal only if that alone is enough.

In JavaScript and Python: `engine.whyNot(ctx, request, now?, options?)` and `engine.why_not(ctx, request, now=None, options=None)`, with `options = { maxDecisions, maxRemedies }` (the limits of the `Context` apply by default); `null`/`None` when allowed. Values are JSON with the same camelCase names; `Remedies`, `Remedy` and the cause are typed in `index.d.ts`. The Wasm ABI has the `whyNot` operation. `strig-inspect explain` prints the remedies after a denial.

## Reverse queries and filtered listing

Ask who can do something, or what a subject can reach, instead of checking one request. `QueryContext` carries the grants (and `.at(now)`), `QueryLimits` bounds the work, and `PgTables` turns the answers into SQL.

```rust
let qctx = QueryContext::new(&grants).at(1_500);
let filter = engine.list(&qctx, &ana, "project.view", "project");
let who = engine.who_can(&qctx, "project.view");
assert_eq!(who, vec![SubjectRef::User { id: "ana".into() }]);
```

| Call | Returns |
|---|---|
| `engine.list(&qctx, &subject, permission, kind)` | An `AccessFilter` over the resources of that kind the subject can reach, ready to become a `WHERE` clause. |
| `engine.who_can(&qctx, permission)` | Everyone named by an allow grant of the permission, anywhere. Denies, overrides and conditions are not evaluated. |
| `engine.who_can_on(..)` | The same on one resource, with denies, overrides and conditions evaluated. |
| `engine.access_of(..)` | Everyone with access to a resource, and their permissions. |
| `engine.check_for(..)` | A check by subject reference: a `SubjectResolver` loads the subject, and the answer names the path that decided. |

## Exclusive resources

With the `exclusive` feature, a resource can have one holder at a time. `Terms::new(priority, ttl_ms)` sets how strong the claim is and how long it lasts. A higher priority takes the resource over only when the claimant also holds `exclusive.preempt`. Permissions and time are checked by the same engine as any other decision.

```rust
let mut registry = ExclusiveRegistry::default();
let now = 0; // milliseconds since the Unix epoch, passed by the caller
let first = registry.acquire_checked(&engine, &ctx, &ana, &document, Terms::new(1, 60_000), now)?;
assert_eq!(first, Acquisition::Granted);

let second = registry.acquire_checked(&engine, &ctx, &bob, &document, Terms::new(9, 60_000), now + 10)?;
assert!(matches!(second, Acquisition::Preempted { .. }));
```

### Across processes

`ExclusiveRegistry::default()` keeps the leases in memory, so a resource is exclusive inside one process. To share it between instances, give the registry a store that decides atomically in the database:

```rust
// Postgres: run `migrate_with` first (schema version 4 adds `<prefix>_exclusive`).
let store = PgExclusiveStore::connect(&url, PgTables::default()).await?;
let mut registry = ExclusiveRegistry::new(store);

// Redis: every instance that shares the resource uses the same prefix.
let mut registry = ExclusiveRegistry::new(RedisExclusiveStore::new("redis://127.0.0.1/", "strig:exclusive")?);
```

Acquire, renew, release and the sweep (`expire`) are one atomic step in each store: a row lock in a transaction for Postgres, `WATCH`/`MULTI`/`EXEC` for Redis. Two instances racing for the same resource have exactly one winner. Both give the same answers as the in-memory store (`strig::exclusive_conformance::run` (feature `conformance`) is the battery every store passes), and whether a lease is active is always decided with the `now` you pass, never the clock of the database. In Redis the native expiry only reclaims memory, after the lease's lifetime plus a retention (one hour by default). The trait is synchronous: both stores block the caller for the round trip (use `spawn_blocking` inside an async task) and fail closed with a `StoreError` on a timeout or a lost connection. Postgres keeps its connection on a thread of its own, like `PgPendingStore`; Redis uses the synchronous connection of the `redis` crate with timeouts. Both crates have the `exclusive` feature, on by default. The JavaScript binding does not expose them yet.

## Real time

```text
grant change ──► Hub::publish ──► local sessions (SSE/WebSocket) and CapabilityCache
                      │
                      └─► Transport (Redis, Postgres, your own) ──► Hub on the other instances
```

```rust
let hub = Hub::builder()
    .transport(RedisTransport::new("redis://127.0.0.1/", "strig:changes")?)
    .build();
let _relay = hub.spawn_relay();

let cache = Arc::new(CapabilityCache::new(Duration::from_secs(30), 10_000));
hub.on_change(cache.clone());
let provider = EngineProvider::new(engine, my_grant_loader).with_cache(cache);
let realtime = strig_axum::Realtime::new(hub).with_provider(Arc::new(provider));
// in the routes: realtime.sse(subject, scopes) or realtime.websocket(upgrade, subject, scopes)
```

A change notice (`Change`) says what kind of change happened and on which step, without the grants. Receivers reload from their own source, so any transport can carry it.

A session watches scopes, that is, anchors such as `org:acme`. With a `CapabilityProvider`, it sends its client the capabilities (the permissions the subject holds) of each affected scope, and changes that arrive together are recomputed once. When the transport drops and comes back, or a client falls behind, the hub emits `Resync` and everything is reloaded.

| Transport | Crate | Notes |
|---|---|---|
| Redis | `strig-redis` | Pub/sub; publishing reconnects on its own. |
| Postgres | `strig-postgres` | `LISTEN/NOTIFY`. Call `strig_postgres::notify(&tx, channel, &change)` inside the transaction that writes the grant, and the notice goes out only on commit. TLS through `PgTransport::with_tls`. |
| Your own | | NATS, Kafka or any broker: implement `Transport` (`publish` and `subscribe`). |

The client protocol is JSON and identical over SSE and WebSocket. The server sends `hello`, `capabilities`, `change`, `resync`, `error` and `ping`; the client sends `watch`, `unwatch`, `refresh` and `refresh_at_least` (WebSocket only). For a web framework other than axum, forward the stream from `Session::open` and write each message with `ServerMessage::to_sse` or `to_json`.

### Reading your own writes

After a change, no instance and no client should decide from state older than it. Each accepted change gets a **revision**: an opaque, serializable text `scope@value` that only grows within a data scope (the scope names the data a counter orders, for example a tenant). The store hands it out: `Governance::with_revisions(Arc<dyn RevisionSource>)` for the memory and file stores (`MemoryRevisions`), or `strig_postgres::next_revision(&tx, "my_sequence", "tenant")` inside the transaction that writes the change, so the revision commits with it. `apply_revised` and `apply_with_impact` return it (`Revised`, `AppliedWithImpact::revision`), and `Change::with_revision` carries it on the notice.

```rust
let applied = governance.apply_revised(&engine, &actor, &grants, &mutation, None, &Attributes::new())?;
let revision = applied.revision.expect("a source was configured");   // "tenant@42"
// hand it to whoever reads next: a header, a cookie, the response of the write

let provider = EngineProvider::new(engine, loader)
    .with_cache(cache)
    .with_consistency(ConsistencyOptions::default().timeout(Duration::from_secs(1)));
// provider.evaluate_revised(&subject, &scope, Some(&revision)) reloads, or waits for the Change, up to the timeout
```

An instance that is behind reloads (or waits for the `Change`) until the timeout and, without getting there, **denies with its own reason**: `revision_not_reached`, `revision_scope_mismatch` (a token of another scope), `revision_untracked` (the source cannot tell its revision) or `source_unavailable`. It never decides from older state. The `CapabilityCache` remembers the revision of each entry (`get_at_least`, `insert_revised`).

- **Client protocol (version 2, additive).** `hello` carries `version`, `capabilities` carries the `revision` of the data the set was computed from, `change` carries the write's `revision`, and the client may send `refresh_at_least` with a revision; a scope that cannot be brought that far gets an `error` (`revision_not_reached`, ...), never an older set. Over SSE, which has no upstream channel, the client reconnects with `?min_revision=` and the endpoint passes it to the session.
- **Decision server.** `/v1` accepts the token in the `x-strig-min-revision` header on every route, and in the `min_revision` field of `check` and `check/batch`. A source behind it answers `503` with `revision_not_reached` (or `revision_mismatch` for another scope); the answers carry the `revision` they were made from. These refusals do not count against the client's circuit breaker. In Rust: `Client::check_at_least` and `check_batch_at_least`; `Snapshot::with_revision` on the source.
- **JavaScript.** `new PermissionClient({ ..., minRevision: 'tenant@42' })` or `client.requireRevision(rev)` after a write: until the capabilities reach it every decision denies (`client.behind()`, `client.revision(scope)`). The React and Angular bindings expose it: `useStrigStatus().behind` and `useRequireRevision()`, `StrigService.status().behind` and `requireRevision()`. `RemoteClient` takes `minRevision` in its options, per `check` or per `checkBatch(requests, { minRevision })`, sends the header, and denies an answer that does not prove the revision, so a server that ignores it cannot talk the client past it. `openSession` takes `revision` (what this instance has loaded) and `minRevision`.

## Postgres storage

`strig-postgres` also keeps the data in Postgres: grants, ReBAC tuples, role assignments and pending requests, behind the same traits the engine already reads (`GrantSource`, `GrantIndex`, `TupleStore`, `TupleIndex`, `PendingStore`).

```rust
use strig_postgres::{PgPendingStore, PgStore, PgTables, connect, migrate_with};

let tables = PgTables::default().in_schema("authz")?.with_prefix("strig")?; // schema and names are yours
let client = connect(&url).await?;
migrate_with(&client, &tables).await?; // idempotent, versioned, safe on every boot

let store = PgStore::load(&client, tables.clone()).await?;
let grants = store.grants(); // GrantSource + GrantIndex, served from memory
let tuples = store.tuples(); // TupleStore + TupleIndex
let _follower = store.follow(hub.subscribe(), move || connect(&url), Duration::from_secs(1));
```

- **Why a snapshot.** The core does no IO and `GrantSource` is synchronous, so `PgStore::load` reads the tables and the engine is served from memory. The snapshot reloads when the transport delivers a `Change` (grants, tuples or resync; a lagging receiver reloads everything). A store only exists loaded, so the engine never decides over an empty set that is missing a deny. If a reload fails the previous snapshot stays and `is_stale()` turns true: put it in your readiness probe. The snapshot holds every grant and tuple, so size it for that; for very large tuple sets keep answering `TupleStore` from your own indexed query.
- **Writing.** `put_grant`, `delete_grant`, `put_tuple`, `delete_tuple`, `assign_role` and `revoke_role` take a client or a transaction. `commit_mutation(&tx, channel, &mutation)` writes what a `Mutation` changes and sends its `NOTIFY` in the same transaction, so the notice goes out if, and only if, the change commits. Call `lock_governance(&tx)` first and read `all_grants(&tx)` inside the transaction, so two instances never judge a change against the same stale set.
- **Governance end to end.** Read the grants and the actor (`tables.subject(&tx, "user", id)` builds the `Subject` with its stored roles), run `Governance::apply`, then `commit_mutation` and commit. Other instances reload on the notice.
- **Roles.** `strig_roles` keeps the assignments per subject (role, optional scope, optional window). A subject read from it carries the `authenticated` principal when its kind is `user`.
- **Pending requests.** `PgPendingStore` is a `PendingStore` over a table, with the expiry in an indexed column (`due(now)` lists what `expire_due` closes). The trait is synchronous, so the store owns a connection on its own thread and each call blocks for one round trip: call it from `spawn_blocking` inside async code. A call that does not answer in time (10 s by default) is a `PendingError::Store`, which refuses, and `update` is one `UPDATE ... WHERE state = 'pending'`, so a request decided meanwhile by another process is never decided twice.
- **Migrations.** `migrate`/`migrate_with` embed the SQL, record each version in `<prefix>_migrations` and run in one transaction under an advisory lock. They are additive (`CREATE ... IF NOT EXISTS`); nothing drops or rewrites data. Schema and table names are validated as plain identifiers.

The tests run against a real Postgres when `STRIG_PG_URL` is set (see Development) and skip without it.

## Decision server and remote client

`strig-server` answers decisions over HTTP, for services that do not embed the engine.

```rust
let source = Arc::new(MemorySource::new(Snapshot::new(Arc::new(engine), grants)));
let router = DecisionServer::new(source).router();
let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
axum::serve(listener, router).await?;
```

The router serves `POST /v1/check`, `/v1/check/batch`, `/v1/list`, `/v1/who` and `/v1/access`, plus `GET /health/live` and `/health/ready`. Grants come from a `DecisionSource`; `MemorySource` holds a `Snapshot` you can `replace`. Decisions use the server's clock. The full contract is in [`crates/strig-server/API.md`](crates/strig-server/API.md).

The client fails closed. Only a `200` counts as an answer: a timeout, a refused connection, a `503` or an unreadable body becomes `ClientDecision::Denied` with the reason, and a circuit breaker stops calling a server that keeps failing.

```rust
let config = ClientConfig::default()
    .with_timeout(Duration::from_millis(250))
    .with_breaker(BreakerConfig::default().with_failure_threshold(5).with_open_for(Duration::from_secs(10)));
let client = Client::http("http://127.0.0.1:8080", config);

let request = CheckRequest::new(Subject::user("alice"), "document.view", Resource::new("document", "d1"));
if client.check(&request).await.is_allowed() {
    // serve the document
}
```

### AuthZEN

`DecisionServer::new(source).with_authzen(AuthzenConfig::default())` also serves the [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html) (Final, January 2026) next to `/v1`, so gateways and platforms that speak the standard query Strig with no adapter: `POST /access/v1/evaluation`, `/access/v1/evaluations` (with the three `evaluations_semantic`s), `/access/v1/search/subject`, `/access/v1/search/action`, `/access/v1/search/resource` (with a `ResourceCatalog`) and `GET /.well-known/authzen-configuration` (with an issuer). `subject.properties` become attributes, with `roles` and `principals` properties for roles and principals; the broader steps of the resource path come from a `path` property or from a `PathResolver` the server owns; `context` is `env`. It fails closed like `/v1`: a malformed request is a `400`, a permission that is not in the catalog is `{"decision": false}`, and a server that cannot decide answers `500`. The mapping and what is left out are in [`crates/strig-server/API.md`](crates/strig-server/API.md#authzen-authorization-api).

```rust
let config = AuthzenConfig::default()
    .with_issuer("https://pdp.example.com")?
    .with_path_resolver(Arc::new(MyOrgTree));
let router = DecisionServer::new(source).with_authzen(config).router();
```

### Envoy

With the `envoy` feature (off by default, no `tonic` or `prost` without it), `DecisionServer::envoy_service(EnvoyConfig)` serves Envoy's External Authorization (`envoy.service.auth.v3.Authorization/Check`, gRPC) over the same source as the HTTP routes, so a service mesh or a gateway built on Envoy asks Strig before it forwards a request. A declarative `EnvoyConfig` maps the request: the subject comes from a header or from the filter metadata (for example the claims `jwt_authn` validated), each method and path pattern asks one permission, and the resource is a template over the path parameters. `OK` on an allow; `PERMISSION_DENIED` with HTTP 403 on a deny, a path no rule covers, a missing subject, a source that is down or a deadline that passed, with an optional fixed `x-strig-reason`. A path with dot segments or encoded separators matches nothing. See [`crates/strig-server/API.md`](crates/strig-server/API.md#envoy-external-authorization-grpc-feature-envoy) and [`examples/envoy.yaml`](crates/strig-server/examples/envoy.yaml).

```rust
let envoy = EnvoyConfig::default()
    .with_subject_header("x-user")?
    .with_route("GET", "/healthz", RouteRule::public())?
    .with_route(
        "GET,HEAD",
        "/documents/{id}",
        RouteRule::require("document.view", ResourceTemplate::new("document", "{id}")),
    )?;
let service = DecisionServer::new(source).envoy_service(envoy);
service.serve(TcpListener::bind("127.0.0.1:9191").await?, shutdown).await?;
```

## Observability

Every crate has an optional `tracing` feature, off by default. It adds spans through [`tracing`](https://docs.rs/tracing) and metrics through the [`metrics`](https://docs.rs/metrics) facade, so you pick the backend: Prometheus, OpenTelemetry or your own recorder. The features chain (`strig-sync/tracing` turns on `strig/tracing`, `strig-postgres/tracing` and `strig-redis/tracing` turn on `strig-sync/tracing`, `strig-server/tracing` turns on `strig/tracing`).

```toml
strig = { version = "0.8", features = ["tracing"] }
strig-server = { version = "0.8", features = ["tracing"] }
```

With the feature off nothing is compiled in: the instrumented entry points are the plain calls. With it on and no subscriber or recorder installed, a decision costs about 110 ns more (`decide/simple`: 518 ns off, 630 ns on, against 517 ns before the feature existed; the bigger operations are within noise). The core still does no IO and still compiles to WebAssembly with and without the feature; there the decision latency histogram is not recorded, because `std::time::Instant` is not available on `wasm32-unknown-unknown`. The JavaScript binding is not instrumented yet.

**No personal data.** A metric label is one of: operation, permission (only a permission the catalog knows; anything else is `unknown`), effect, reason kind, invariant name, step, outcome, status, change kind, transport name, route, error code, breaker phase. Never a subject id, a resource id, an attribute or a request body, and spans carry the same fields. Tests in each crate run a scenario with recognizable ids and fail if one shows up in a label or a span. An invariant you write labels the metric with the name you gave it, so keep it a constant.

A decision a custom invariant or override makes while governance judges a change belongs to that change: only the outermost operation on a thread feeds the metrics, so `strig_decisions_total` counts what your application asked for. Spans nest either way.

| Metric | Type | Labels |
|---|---|---|
| `strig_decisions_total` | counter | `operation` (`decide`, `explain`), `effect`, `reason`, `permission` |
| `strig_decision_duration_seconds` | histogram | `operation` |
| `strig_query_duration_seconds` | histogram | `operation` (`list`, `who_can`, `who_can_on`) |
| `strig_mutations_total` | counter | `outcome` (`applied`, `refused`) |
| `strig_mutation_violations_total` | counter | `invariant` |
| `strig_approvals_total` | counter | `step` (`propose`, `approve`, `reject`, `expire`), `outcome` |
| `strig_audit_writes_total` | counter | `status` (`written`, `pending`, `dropped`, `refused`) |
| `strig_audit_pending` | gauge | none (depth of the retry queue) |
| `strig_audit_write_failures_total` | counter | none |
| `strig_audit_dropped_total` | counter | none |
| `strig_sync_changes_total` | counter | `kind`, `direction` (`published`, `received`) |
| `strig_sync_publish_errors_total` | counter | `transport` |
| `strig_sync_sessions_open` / `strig_sync_sessions_opened_total` | gauge / counter | none |
| `strig_sync_resyncs_total` | counter | `reason` (`reconnect`, `lagged`, `notice`) |
| `strig_sync_transport_reconnects_total` | counter | `transport` |
| `strig_sync_transport_failures_total` | counter | `transport`, `stage` (`subscribe`, `stream`) |
| `strig_server_requests_total` | counter | `route`, `status` |
| `strig_server_request_duration_seconds` | histogram | `route` |
| `strig_server_errors_total` | counter | `code` |
| `strig_client_calls_total` | counter | `route`, `outcome` |
| `strig_client_call_duration_seconds` | histogram | `route` |
| `strig_client_breaker_transitions_total` | counter | `to` (`closed`, `half_open`, `open`) |
| `strig_client_breaker_state` | gauge | none (`0` closed, `1` half open, `2` open) |

| Span | Where | Fields |
|---|---|---|
| `strig.decision` | `decide`, `check`, `explain` | `operation`, `permission`, `effect`, `reason` |
| `strig.query` | `list`, `who_can`, `who_can_on` | `operation`, `permission`, `kind` |
| `strig.governance.apply` | `Governance::apply` and `GovernanceAt` | `outcome` |
| `strig.approval` | `propose`, `approve`, `reject`, `expire_due` | `step`, `outcome` |
| `strig.audit.write` | each audit record sent to the sink | `mode` |
| `strig.sync.publish`, `strig.sync.relay`, `strig.sync.session` | hub publish, transport relay, one client session | `transport` on publish |
| `strig.postgres.publish`, `strig.postgres.subscribe`, `strig.postgres.store.load`, `strig.postgres.store.reload`, `strig.postgres.store.commit_mutation`, `strig.redis.publish`, `strig.redis.subscribe` | the transports | none |
| `strig.server.request`, `strig.client.call` | the decision server and its client | `route`, `status` or `outcome` |

Events (a dropped audit record, a lost `LISTEN` connection, a breaker changing phase) go out at `warn` or `info`. Decision and query spans are `debug`, the rest `info`.

[`crates/strig-server/examples/otlp.rs`](crates/strig-server/examples/otlp.rs) exports both over OTLP/HTTP with `tracing-opentelemetry` and `metrics-exporter-opentelemetry`:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 cargo run -p strig-server --features tracing --example otlp
```

## JavaScript: Node, Bun and the browser

```sh
npm install @the-hades-organization/strig
```

```js
import { load } from '@the-hades-organization/strig';
const { Engine, Context } = await load(); // native on Node/Bun, wasm in the browser

const engine = new Engine(spec); // the same EngineSpec JSON as in Rust
const ctx = new Context({ grants });
engine.check(ctx, { subject, permission: 'document.view', resource });
engine.apply({ actor, current, mutation: { add: grant }, invariants, audit: { level: 'standard' } });
```

On Node and Bun, `load()` tries the native module and falls back to wasm. Set `STRIG_BACKEND=native` or `STRIG_BACKEND=wasm` to force one.

The native module ships as one small package per platform, installed by npm as an optional dependency of `@the-hades-organization/strig` (a typical install is about 2 MB to download and 8 MB on disk):

| Platform | Package |
| --- | --- |
| Linux x64 and arm64 (glibc) | `strig-linux-x64-gnu`, `strig-linux-arm64-gnu` |
| macOS Intel and Apple silicon | `strig-darwin-x64`, `strig-darwin-arm64` |
| Windows x64 | `strig-win32-x64-msvc` |

Any other platform (Alpine/musl, for example) runs on the wasm backend, which is bundled in the main package. If you install with `--omit=optional` (or `--no-optional`), `load()` falls back to wasm too, and `STRIG_BACKEND=native` throws an error naming the package to install.

The JSON spec covers the built-in overrides, `resource_owner` and `permission_holder`. Custom condition functions (`call`), custom overrides and custom invariants are not part of the spec: in JS they are synchronous callbacks passed to the `Engine` constructor (see "Rules written in JavaScript").

### In the browser

`PermissionClient` (`/client`) connects over SSE or WebSocket, keeps the capabilities of each scope and decides locally with the same engine. Use it to shape the interface; the server still decides on every operation.

```js
import { PermissionClient } from '@the-hades-organization/strig/client';
const client = new PermissionClient({ url: '/permissions/events', scopes, strig, engine }).connect();
client.on('capabilities', () => render());
client.can('document.edit', resource);
```

### Cost of a call and batches

A `Context` keeps its grants, tuples, `env` and instant on the Rust side, so a decision never sends them again; change them with `addGrant` (the same `id` replaces), `removeGrant`, `addTuple`, `removeTuple`, `setNow` and `setEnv`. What still crosses the boundary on each call is the request, and the binding sends it as one `JSON.stringify` string (the decision comes back the same way) when it is plain JSON; a request with `undefined`, `NaN`, functions, bigints or class instances takes the original path and its errors. `check` answers a boolean without building the `Decision`.

To decide many requests against one `Context` and one instant, cross the boundary once:

```js
const allowed = engine.checkMany(ctx, requests);   // boolean[], in order
const traces = engine.explainMany(ctx, requests);  // Explanation[], in order
```

A request that cannot be read throws and decides none; it never becomes a silent `false`. Numbers per case are in [`docs/benchmarks.md`](docs/benchmarks.md).

### Rules written in JavaScript

The `call` condition function, your own override and your own `Invariant` exist in JS too, as synchronous callbacks passed to the `Engine` constructor. The engine calls them in the middle of a decision or of `apply`; they show up like the native ones: the `explain` trace names the override, a refusal carries your violation, and the audit records it as it records the built-in invariants.

```js
const engine = new Engine(spec, {
  // `call` conditions: { op: 'call', func: 'same_dept', args: [{ attr: 'subject.dept' }, { attr: 'resource.dept' }] }
  conditions: { same_dept: ([a, b]) => a === b },
  // Decides before the grants: 'allowed', 'denied' or 'abstained' (nothing). `except` skips permissions.
  overrides: [{ name: 'frozen', except: ['project.view'], evaluate: ({ permission }) => (frozen ? 'denied' : undefined) }],
  invariants: {
    // The role of an environment never exceeds the global one.
    env_role_within_global({ mutation }) {
      if (!('assign_role' in mutation)) return;
      const { subject, role } = mutation.assign_role;
      if (role.scope?.kind !== 'environment' || rank(role.role) <= globalRank(subject)) return;
      return { message: `${role.role} in the environment exceeds the global role`, suggestion: downgrade(subject, role) };
    },
    // A role in use is not deleted.
    role_in_use({ mutation, before }) {
      if (!('remove' in mutation)) return;
      const grant = before.find((g) => g.id === mutation.remove.id);
      if (grant?.subject.kind === 'role' && inUse(grant.subject.id)) return `role ${grant.subject.id} is in use`;
    },
  },
});

engine.apply({ actor, current, mutation, invariants: [{ kind: 'custom', name: 'env_role_within_global' }, { kind: 'custom', name: 'role_in_use' }] });
```

- A condition function gets the resolved operands and returns a boolean. An invariant gets `{ actor, mutation, before, after, now }` (the `mutation` has the shape `apply` takes) and returns nothing to accept, or a text, or `{ message, suggestion? }` to refuse. The `suggestion` is a change; the governance re-checks it against every invariant before it surfaces.
- **A throw denies, never crashes.** A condition that throws (or does not return a boolean) is a condition error: an allow grant does not apply, a deny grant still does, and the trace carries the message. An override that throws answers `denied`. An invariant that throws refuses with the message of the error.
- **Callbacks are synchronous.** A promise is not awaited; it is a wrong answer and denies like a throw.
- **No re-entry.** A callback that calls the engine, or changes another `Context`, gets `REENTRANT_CALL`; changing the `Context` under decision is refused by the runtime. Read what you need before the call and keep it in the closure.
- A custom override is opaque to listings (`list`), like any override that does not describe its reach: the resources it might decide on stay as residue, never as allowed.

### Real time on a JS backend

`/server` has `Hub`, `openSession`, `sseResponse` (Fetch API: Bun.serve, Hono, Deno), `pipeSse` (Node's `http`) and three transports: `redisTransport` (node-redis and Bun's `RedisClient`), `ioredisTransport` and `pgTransport` (the `pg` package). Notices use the `strig-sync` format, so Rust and JS instances can share a channel.

### Grants and roles in a JSON file

For a system with neither Postgres nor Redis, `/store` keeps the grants and the role assignments in one JSON file (Node and Bun):

```ts
import { openJsonStore } from '@the-hades-organization/strig/store';

const store = await openJsonStore({ path: './strig.json', createIfMissing: true });
const provider = engineProvider({ engine, Context, loadGrants: store.loadGrants }); // the grant source
const subject = store.subject({ kind: 'user', id: 'ana' });                          // + the roles in the file

const result = await store.apply(engine, { actor, mutation: { assign_role: { subject, role: { role: 'admin' } } }, invariants });
// accepted: the new grants and roles are written; refused: nothing is written
```

- **File:** `{ "version": 1, "grants": [...], "roles": { "<subject id>": [<assignment>, ...] } }`. Roles themselves (the hierarchy) stay in the engine spec; the file holds who has which.
- **Fails closed.** A missing file, invalid JSON, a repeated grant id or a `version` other than 1 throws `JsonStoreError` (`STORE_NOT_FOUND`, `STORE_CORRUPT`, `STORE_VERSION`) on load. The store never starts empty on its own; `createIfMissing` is the explicit way to start one.
- **Writes are atomic and serialised.** Temp file in the same directory, `fsync`, `rename`, then `fsync` of the directory. Calls in one process queue up; between processes a `<file>.lock` (created with `O_EXCL`) is held, and a lock whose owner died on this host, or that is older than `lockStaleMs` (30 s), is taken over. Each change re-reads the file under the lock, so processes do not overwrite each other. `STORE_LOCK_TIMEOUT` after `lockTimeoutMs` (5 s).
- **Changes:** `addGrant`, `updateGrant`, `removeGrant`, `assignRole`, `revokeRole`, `setRoles`, or `apply(engine, input)`, which runs the governance over the grants the file holds right now and persists what it accepts.
- **Reload:** `reload()` after an outside edit, or `watch()` to reload on its own (it watches the directory, since the rename replaces the file). A bad file on reload keeps the last good snapshot, throws from `reload()` and goes to `onError` from `watch()`. `onChange` fires after every reload and write.
- Not here: audit records and a Rust-only store.

### Express, Fastify and NestJS

The three integrations take the same options and decide on each route:

```js
import { load, scopeFromString } from '@the-hades-organization/strig';
import { authorize } from '@the-hades-organization/strig/express';

const { Engine, Context } = await load();
const options = {
  subject: (req) => (req.headers['x-user'] ? { kind: 'user', id: req.headers['x-user'] } : undefined),
  resource: (req) => scopeFromString(`document:${req.params.id}/org:o1`),
  local: { engine: new Engine(spec), context: new Context({ grants }), now: () => Date.now() },
};

app.get('/doc/:id', authorize({ ...options, permission: 'document.view' }), handler);
```

| Option | Meaning |
|---|---|
| `subject(req)` | The subject; returning nothing answers `401`. |
| `resource(req)` | The resource. |
| `local: { engine, context, now }` or `remote: RemoteClient` | Where the decision comes from. Pass exactly one. |

The request never passes unless the decision allows it:

| Outcome | Status | Change it with |
|---|---|---|
| No subject | `401` | `unauthenticatedStatus` |
| Denied | `403` | `denyStatus` |
| The decision could not be made | `503` | `failureStatus` |
| Your `subject` or `resource` function threw | `500`, with no detail | `errorStatus`, `onError` |

- **Fastify** (`/fastify`): the same `authorize`, plus a `plugin` that adds `fastify.strigCan`.
- **NestJS** (`/nestjs`): `@Can('document.view')` on a handler or controller, with `new StrigGuard(options)` as the guard.

#### One route table, deny by default

To keep every rule in one place, give the integration a table instead of a permission per handler. A request no rule covers is refused (`denyStatus`, 403); a route is public only when its rule says `public: true`.

```js
import { authorizeRoutes } from '@the-hades-organization/strig/express';

const routes = [
  { method: 'GET', path: '/health', public: true },
  { method: 'GET', path: '/doc/:id', permission: 'document.view', resource: (req, params) => docScope(params.id) },
  { method: ['PUT', 'DELETE'], path: '/doc/:id', permission: 'document.edit', resource: (req, params) => docScope(params.id) },
];
app.use(authorizeRoutes({ subject, local: { engine, context }, routes })); // before the routers
```

Paths use the framework syntax: literal segments, `:name` for one segment, a trailing `*` for one or more. The first matching rule decides, so write the specific ones first; `HEAD` falls under `GET` rules, and `*` as the method means any. The table matches the way the framework routes, so no request can slip past a protected rule into a broader public one: every segment is percent-decoded before the comparison (`/%61dmin/1` is `/admin/1`; `%2F` stays inside its segment; a malformed escape matches nothing), and literals ignore case with `caseSensitive: false`. The default is the framework's own: Express ignores case, Fastify is case sensitive (set `caseSensitive` on the table if you changed the Fastify option), Nest follows its platform. Pass `{ caseSensitive: false }` to `assertRoutesCovered` for an Express app. Each rule has `permission` or `public: true` (a bad table throws at startup). `resource` receives the request and the matched `params`: at app level Express has not filled `req.params` yet.

- **Express** (`/express`) and **Fastify** (`/fastify`): `authorizeRoutes(options)` is a global middleware or `onRequest` hook (`fastify.addHook('onRequest', ...)`). It also answers 403 for URLs with no route, and a CORS preflight needs a rule or has to be answered before it.
- **NestJS** (`/nestjs`): `{ provide: APP_GUARD, useValue: new StrigRouteGuard(options) }`. The table decides first. If it allows, a `@Can` on the handler adds a second check that must also pass: `@Can` narrows, it never opens what the table denies (and it applies on a `public` rule too). A handler without `@Can` needs nothing else.

Put the table under test so it cannot drift from the app (`/testing`):

```js
import { expressRoutes, assertRoutesCovered } from '@the-hades-organization/strig/testing';

assertRoutesCovered(expressRoutes(app), routes); // throws listing routes with no rule and rules with no route
```

`expressRoutes(app)` reads an Express 4 or 5 app or router (nested routers included, not mounted sub-apps); `nestRoutes(app)` does it for a Nest app on the Express adapter after `app.init()`; on Fastify call `collectFastifyRoutes(fastify)` before registering routes and pass the array it returns once the app is ready. `auditRoutes(routes, table)` returns `{ uncovered, unusedRules, ok }` if you prefer to assert yourself.

Express, Fastify and NestJS are optional peer dependencies. An integration you do not import costs nothing, and importing one whose peer is missing throws `MissingPeerError`.

To get decisions from a [decision server](#decision-server-and-remote-client) instead, pass a `RemoteClient` (`/remote`) as `remote`. It has a timeout and a breaker, and denies when there is no answer:

```js
import { RemoteClient } from '@the-hades-organization/strig/remote';
const remote = new RemoteClient({ url: 'http://127.0.0.1:8080', timeoutMs: 250 });
const { allowed } = await remote.check({ subject, permission: 'document.view', resource });
```

### Catalog types for the frontend

A permission can carry its display name and description per locale (`labels` / `descriptions`, next to `label` / `description`; in Rust `PermissionDef::localized_label("pt-BR", "Editar")`). They are optional and are not declared in the policy language, only in the catalog export (JSON) or the builder. `strig-types` turns an exported catalog into one `.ts` file with the `PermissionId` union, a `PERMISSIONS` constant with the metadata and the helpers `isPermissionId`, `permissionLabel` and `permissionDescription` (locale with fallback to the default text). The output is sorted, so it only changes when the catalog does.

```sh
npx strig-types catalog.json -o src/permissions.generated.ts
```

```ts
import { generateTypes } from '@the-hades-organization/strig/types'; // same thing, as a function
import { PermissionClient } from '@the-hades-organization/strig/client';
import type { PermissionId } from './permissions.generated';

const engine = new strig.Engine<PermissionId>(spec); // strict: check, explain, list, whoCan... take only the ids; without the parameter, any string
const client = new PermissionClient<PermissionId>(/* ... */);
client.can('users:read', resource); // only ids of the union compile; narrow a plain string with isPermissionId first
```

### React and Angular

`/react` and `/angular` put the real-time [`PermissionClient`](#real-time) (`/client`) behind the usual UI primitives. The decision is local, on the capabilities the stream delivers, and the answer is **deny** whenever there is none: before the first capabilities, after a disconnect, during a resync, on the server (SSR) and for a scope the grants do not cover. React 18 and 19, Angular 17+ (standalone, signals). Both take the `PermissionId` generated by `strig-types` as the type parameter.

```tsx
import { PermissionClient } from '@the-hades-organization/strig/client';
import { StrigProvider, useCan, Can, useStrigStatus } from '@the-hades-organization/strig/react';
import type { PermissionId } from './permissions.generated';

const client = new PermissionClient<PermissionId>({ url: '/strig/stream', scopes: [project], strig, engine });

<StrigProvider client={client}>
  <Can<PermissionId> permission="document.edit" resource={doc} fallback={<ReadOnly />}>
    <Editor />
  </Can>
</StrigProvider>;

const canEdit = useCan<PermissionId>('document.edit', doc); // re-renders when capabilities arrive
const { connected, resyncing, error } = useStrigStatus();
```

`StrigProvider` opens the stream on mount and closes it on unmount (`connect={false}` leaves that to you), and never connects on the server. Without a provider every hook denies.

```ts
// app.config.ts
import { provideStrig } from '@the-hades-organization/strig/angular';
providers: [provideStrig(client)]; // { connect: false } to open the stream yourself

// component
import { StrigCanDirective, StrigService, strigCanActivate } from '@the-hades-organization/strig/angular';
// template: <button *strigCan="'document.edit'; resource: doc; else readOnly">Edit</button>
canEdit = inject(StrigService<PermissionId>).can('document.edit', this.doc); // Signal<boolean>; arguments may be signals

// routes
{ path: 'doc/:id', canActivate: [strigCanActivate<PermissionId>('document.view', (route) => resourceOf(route))] }
```

The route guard waits for the first capabilities (`waitMs`, default 5000 ms) so a deep link is not refused while the stream opens, then decides locally; a timeout or a deny returns `false`, or whatever `onDeny` returns (run in the injection context, so it can return a `UrlTree`).

React and Angular are optional peer dependencies and are imported statically, so your bundler resolves its own copy (a copy loaded behind its back could be a second React and break the hooks). A missing peer therefore fails at module resolution with the loader's own error naming the package, not with `MissingPeerError` as the Express, Fastify and NestJS integrations do. The package ships Angular as partial Ivy output for the Angular linker. Vue and Svelte can follow the same way: the bridge in `client-bridge.ts` is framework-neutral and each binding is about a hundred lines.

### Filtering a listing in Prisma, Drizzle and Kysely

`engine.list(...)` says what a subject can reach in a kind; `/prisma`, `/drizzle` and `/kysely` turn that answer into the `where` of your ORM, with the same meaning as `PgTables` has in Rust. Each takes the `list` result and a mapping of where the resource keeps what the filter reads, and returns `{ permission, where, settled?, residual }`. Drizzle and Kysely are optional peers (Kysely is never imported: its builder arrives as the callback argument); Prisma needs none, since the `where` is a plain object.

```ts
import { toWhere } from '@the-hades-organization/strig/prisma';

const result = engine.list(ctx, subject, 'document.view', 'document', { layout: ['document', 'project', 'org'] });
const { where, settled, residual } = toWhere(result, {
  kind: 'document',
  id: 'id',
  paths: { project: 'projectId', org: 'project.orgId' }, // a dotted path crosses a to-one relation
  attrs: { owner: 'ownerId' },
  optionalRelations: ['project'], // Prisma only: relations that may be absent
});
const documents = await prisma.document.findMany({ where });
```

```ts
import { toWhere } from '@the-hades-organization/strig/drizzle'; // paths: { project: documents.projectId, ... }
const { where } = toWhere(result, { kind: 'document', id: documents.id, paths: { project: documents.projectId, org: documents.orgId } });
const rows = await db.select().from(documents).where(where);

import { toWhere as toKyselyWhere } from '@the-hades-organization/strig/kysely'; // columns as strings
const { where: kyselyWhere } = toKyselyWhere(result, { kind: 'document', id: 'id', paths: { project: 'project_id', org: 'org_id' } });
const rows2 = await db.selectFrom('document').selectAll().where(kyselyWhere).execute();
```

- **Fails closed.** A kind or attribute the filter reads and the mapping lacks, an expression node with no query form, a filter for another kind than the mapping's: all throw `OrmFilterError` (`code`: `UNMAPPED_KIND`, `UNMAPPED_ATTRIBUTE`, `UNSUPPORTED_EXPR`, `UNSUPPORTED_VALUE`, `KIND_MISMATCH`). Nothing becomes "all rows"; what is certainly empty becomes an impossible condition.
- **A deny reaches only what it names.** Every test is true or false, never `NULL`, so `NOT (project_id = 'p2')` keeps the rows with no project, as `engine.check` does. In Prisma the negation is pushed to the fields (`{ OR: [{ projectId: null }, { projectId: { not: 'p2' } }] }`), and a relation that can be absent is listed in `optionalRelations`; one left out only costs rows a deny would drop, never opens access.
- **A residue is not permission.** A condition over the resource, an override or a strategy the database cannot settle stays in `residual`. `where` is the upper bound (every row that may be allowed) and `settled` the lower bound (rows allowed whatever the residue says), present only with a residue: check the rows of `where` outside `settled` with `engine.check`. Without a residue `where` is exact.
- **One contract.** Each module also exports an object (`prisma`, `drizzle`, `kysely`) with `toWhere(filter, mapping)`, typed over the `PermissionId` from `strig-types`.

The unit tests check the object each adapter builds, and an oracle runs every scenario (allow by kind, by anchor, by exact id, denies that cut, a condition that stays a residue) against SQLite (Drizzle and Kysely) and an evaluator of the Prisma shape, comparing the rows with the ids `engine.list` resolves. TypeORM, Sequelize and MikroORM have no adapter yet; the mapping and the compiler (`bounds`, `Emitter`) are what a new one would reuse.

## Python

`strig-auth` is the Python binding over the same engine and the same JSON `EngineSpec` as the Rust and JavaScript APIs: a native extension (PyO3), one `abi3` wheel per platform for Python 3.9 and later, with type stubs (`py.typed`).

```sh
pip install strig-auth
```

```python
import strig
from strig import dsl

spec = dsl.load_project_dir("policies")          # or a plain dict: the EngineSpec JSON
engine = strig.Engine(spec)

ctx = strig.Context(grants, tuples=[...], env={"dept": "eng"}, now=1_700_000_000_000)
ctx.add_grant(grant); ctx.remove_grant("g1"); ctx.set_now(None)

request = {"subject": {"kind": "user", "id": "ana"}, "permission": "project.edit",
           "resource": strig.scope_from_string("project:p1/org:o1")}
engine.check(ctx, request)                        # bool
engine.decide(ctx, request)                       # {"effect": "allow", "matched": [...], "reason": {...}}
engine.explain(ctx, request)                      # the trace
engine.check_many(ctx, [request, other], now=1_700_000_000_000)
engine.list(ctx, subject, "project.view", "project")
engine.who_can(ctx, "project.view")

result = engine.apply({"actor": actor, "current": grants, "mutation": {"add": grant},
                       "invariants": [{"kind": "custom", "name": "role_in_use"}],
                       "audit": {"level": "forensic", "failMode": "open"}})
```

- **Same JSON, same names.** Arguments and results are the dicts and lists the JavaScript API takes and returns, with the same camelCase fields (`validFrom`, `grantId`, `auditStatus`); methods and keyword arguments are snake_case (`check_many`, `who_can_on`, `audit_sink`). Anything that is not JSON (`nan`, a `set`, a non-text key, an int over 64 bits) is refused with `INVALID_ARGUMENT`; nothing is coerced.
- **Errors are exceptions with a `code`.** A failed call raises `strig.StrigError` with `.code` equal to the `errorCode` of the JavaScript binding (`INVALID_INPUT`, `INVALID_ARGUMENT`, `UNKNOWN_SUBJECT`, `REENTRANT_CALL`, ...); match on the code, not on the message. The policy language raises `strig.DslError` (a `StrigError`) with `.diagnostics`.
- **Rules written in Python.** `Engine(spec, conditions={...}, overrides=[{"name": ..., "except": [...], "evaluate": fn}], invariants={...}, audit_sink=fn, audit_redact=fn, on_audit_drop=fn, audit_policy={...})` take synchronous callables with the same contract as the JavaScript hooks: an exception denies (a condition that raises does not grant, an override that raises answers `denied`, an invariant that raises refuses with its message), a coroutine is a wrong answer, and a callback that calls the engine or changes a `Context` gets `REENTRANT_CALL`. The GIL stays held during a call, so a callback runs on the thread that is deciding.
- **Time is explicit.** Every method that decides takes an optional `now` (ms UTC) that wins over `ctx.set_now`; without one the engine fails closed on validity windows. The system clock is used only by `apply`/`propose` for the audit record and by `Exclusive` when `now` is omitted.
- `strig.Exclusive(...)`, `strig.verify_audit_chain(records, anchors)` and `strig.audit_estimate(level, records)` mirror the JavaScript ones. `strig.dsl` has `compile`, `print`, `convert`, `format`, `is_formatted`, `load_project` and `load_project_dir`.

To build it from the repository: `pip install maturin && cd crates/strig-python && maturin develop && pytest`.

## Go

`github.com/The-Hades-Organization/Strig/bindings/go` is the Go binding over the same engine and the same JSON `EngineSpec` as the other APIs. It runs the engine compiled to WebAssembly (`crates/strig-wasi`, a plain C ABI with JSON in and out) on [wazero](https://wazero.io), pure Go with no cgo, and the module is embedded with `go:embed`. Go 1.22 or later.

```sh
go get github.com/The-Hades-Organization/Strig/bindings/go@<tag>   # a release tag of this repository
```

```go
import strig "github.com/The-Hades-Organization/Strig/bindings/go"

engine, err := strig.NewEngine(spec)               // spec: a map, a struct or a json.RawMessage
defer engine.Close()

ctx, _ := engine.NewContext(map[string]any{"grants": grants, "env": map[string]any{"dept": "eng"}})
ctx.AddGrant(grant); ctx.RemoveGrant("g1")

request := map[string]any{"subject": subject, "permission": "project.edit", "resource": resource}
allowed, err := engine.Check(ctx, request)         // (bool, error): an error is never an allow
decision, err := engine.Decide(ctx, request)       // *Decision{Effect, Reason, Matched, Warnings}
explanation, err := engine.Explain(ctx, request, strig.WithNow(time.Now()))
many, err := engine.CheckMany(ctx, []any{request, other})
policy, err := strig.Compile(text)                 // the policy language, no engine needed
```

- **Same JSON, same codes.** Requests and results are the JSON of the JavaScript API with the same camelCase fields. A failure is a `*strig.Error` whose `Code` is the `errorCode` of the JavaScript binding (`INVALID_INPUT`, `UNKNOWN_SUBJECT`, `DSL_PARSE`, ...), with `Diagnostics` for the policy language; use `strig.CodeOf(err)` or `errors.As`.
- **Fails closed.** `Check` returns `false` with the error, never `true`. If the module traps, the instance is discarded and every later call returns `strig.ErrBroken`. A closed engine or context, or a context of another engine, is an error.
- **Concurrency.** An `Engine` is safe for concurrent use, but one WebAssembly instance is single-threaded, so calls are serialized. For parallel throughput give each worker its own `engine.Fork()` (its own instance, same spec, no shared state). A `Context` belongs to the engine that made it.
- **Time is explicit.** `WithNow(t)` or `ctx.SetNow(t)` set the instant; without one the engine fails closed on validity windows. `Apply`, `Propose`, `Resolve` and `Expire` take the host clock when the input has no `now`.
- **Not in this binding yet:** callbacks (the `call` condition, overrides, invariants written in Go), the audit sink and exclusive resources. A spec that needs a callback fails closed.

The `.wasm` is also a release asset (`strig-<version>.wasm`) for any other host that speaks WebAssembly. To rebuild the embedded module: `sh bindings/scripts/build-wasi.sh`, then `cd bindings/go && go test ./...`.

## Java and Kotlin

`io.github.the-hades-organization:strig` is the JVM binding: the same WebAssembly module, run on [Chicory](https://github.com/dylibso/chicory) (pure JVM, no native code), with the same JSON `EngineSpec`. Java 17 or later; Kotlin uses the same classes.

```xml
<dependency>
  <groupId>io.github.the-hades-organization</groupId>
  <artifactId>strig</artifactId>
  <version>${strig.version}</version>
</dependency>
```

```java
import io.github.thehadesorganization.strig.*;

try (Engine engine = new Engine(spec);                 // spec: a Map, a record or a JsonNode
     Context ctx = engine.newContext(Map.of("grants", grants))) {
  ctx.addGrant(grant);
  boolean allowed = engine.check(ctx, request);        // an exception is never an allow
  Decision decision = engine.decide(ctx, request, Instant.now());
  Map<String, Object> explanation = engine.explain(ctx, request);
  List<Boolean> many = engine.checkMany(ctx, List.of(request, other));
} catch (StrigException e) {
  e.code();                                            // INVALID_INPUT, UNKNOWN_SUBJECT, DSL_PARSE, ...
}
Map<String, Object> policy = Strig.compile(text);      // the policy language, no engine needed
```

```kotlin
Engine(spec).use { engine ->
    engine.newContext(mapOf("grants" to grants)).use { ctx -> engine.check(ctx, request) }
}
```

- **Same JSON, same codes.** `StrigException.code()` is the `errorCode` of the JavaScript binding; `diagnostics()` carries the policy-language positions.
- **Fails closed.** `check` throws instead of returning `true` when it cannot decide; a trapped instance is discarded and every later call throws `INTERNAL`.
- **Concurrency.** An `Engine` is safe for concurrent use with serialized calls; give each worker `engine.fork()` for parallel throughput. A `Context` belongs to its engine. Close both.
- **Time is explicit.** Every deciding method has an overload taking an `Instant`; without one the engine fails closed on validity windows.
- **Not in this binding yet:** callbacks (the `call` condition, overrides, invariants written in Java), the audit sink and exclusive resources.

Publishing to Maven Central is not enabled yet (it needs the project's account and signing key). Until then, build the jar from the repository: `sh bindings/scripts/build-wasi.sh jvm && cd bindings/jvm && mvn verify`.

## Policy language

With the `dsl` feature, a policy can be written as text instead of JSON. The same policy has three syntaxes, Blocks, Rules and Actors, and `convert` moves between them. Every error carries a position and a hint. The validated JSON stays the source of truth.

Try it in the [playground](https://strig-playground.vercel.app), which runs the real engine compiled to WebAssembly. The [guide](docs/dsl.md) has the three syntaxes side by side and the grammar.

```rust
use strig::dsl::{self, Language};

const SOURCE: &str = "language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
";

let parsed = dsl::parse("policy.strig", SOURCE)?;
let json = parsed.policy.to_json()?;
let as_rules = dsl::convert(SOURCE, Language::Rules)?;
```

`as_rules` holds:

```text
language rules

kinds org

permission org.read on org
```

Conditions in `when` read the same in the three syntaxes, for example `a starts_with b`, `env.ip ip_in "10.0.0.0/8"`, `time_between "09:00" "17:30"` and `weekday_in ["mon", "tue"]`. The validator refuses a CIDR, a time of day, a weekday or a time zone it cannot read. When a name is one typo away from a declared permission, role or parent, the hint adds ``did you mean `x`?``.

- **Formatting.** `strig::dsl::format` and `is_formatted` rewrite a source in the canonical layout of its syntax and keep the comments. `strig-inspect fmt [--check] <file|dir>` does the same for `.strig` files; `--check` lists the files that would change and exits with 1.
- **Files.** With `dsl-fs`, `strig::dsl::fs::read_dir` reads every `*.strig` file of a directory into a `Project`, and `write_file` writes a policy back.

### In Node

The binding exposes the same language, native and WebAssembly, behind `load()`. A compiled policy is the canonical JSON, the same for the three syntaxes, with the comments in `notes`.

```js
import { load } from '@the-hades-organization/strig';
const strig = await load();

const source = `language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
`;

const policy = strig.compile(source, { file: 'policy.strig' }); // canonical JSON
const rules = strig.print(policy, 'rules'); // 'blocks' | 'rules' | 'actors'
const actors = strig.convert(source, 'actors'); // text to text
const merged = strig.loadProject([
  { path: 'org.strig', text: source },
  { path: 'team.strig', text: strig.convert(source.replaceAll('org', 'team'), 'actors') },
]);
const fromDisk = strig.loadProjectDir?.('./policy'); // native module only
```

- `format(source)` returns the source in the canonical layout of its syntax; `isFormatted(source)` says whether it already is.
- `loadProjectDir(dir)` exists only on the native module, since WebAssembly has no file access. It reads the `*.strig` files of the directory and refuses a policy file that is a symbolic link. Pass only a `dir` from a trusted source.

Every failure is an `Error` whose `code` is the same on both targets:

| `code` | Cause |
|---|---|
| `DSL_PARSE` | The text does not parse. |
| `DSL_VALIDATE` | The policy parses but is invalid. |
| `DSL_CONFLICT` | Two sources declare the same thing; both positions are reported. |
| `DSL_UNREPRESENTABLE` | The target syntax cannot express the policy. |
| `DSL_UNSUPPORTED` | The syntax is not available in this build. |
| `DSL_LIMIT` | A size or count limit was exceeded. |
| `DSL_DUPLICATE_SOURCE` | The same `path` appears twice in `loadProject`. |
| `DSL_IO` | A file or a link in `loadProjectDir`. The message carries the path, so do not forward it to a remote client. |

`error.diagnostics` lists up to 100 `{ file, line, column, message, hint, related? }` entries; when more were found, the last entry says "and N more". `file`, `line` and `column` are `null` for a policy that did not come from text. `related` (`{ file, line, column }`) appears on a `DSL_CONFLICT`.

```js
try {
  strig.compile('language blocks\n\npermission {', { file: 'a.strig' });
} catch (error) {
  error.code; // 'DSL_PARSE'
  const [first] = error.diagnostics; // first.file === 'a.strig', first.line === 3
}
```

### Diff and lint of a policy

`strig diff <before> <after>` lists the decisions that change between two versions of a policy (directories or `.strig`
files): who, which permission, on what, whether access `widened` or `narrowed`, and the grant or override responsible on
each side. `strig lint <dir>` finds policy that never acts: a shadowed grant, an unreachable deny, a permission nobody
holds, an unused role, a redundant `implied_by`, a condition that is always false or true, a field never granted.

```sh
strig diff main/policies policies --fail-on allow     # exit 1 if any access widened
strig lint policies/ --json                           # codes L001..L009, severity, position, hint
```

```js
const found = strig.diff(before, after, { fixture: { resources: ['org:1'] } });
const findings = strig.lint(policy, { ignore: ['unused-role'] });
```

Without a fixture the questions are derived from the catalogs and the grants and bounded by `QueryLimits`; a diff cut by
a limit is marked `partial`, and finding no change then is not proof there is none. In Rust it is `strig::dsl::analysis`.
The `strig-test` action takes `diff-base` to diff against the base of the pull request. See
[the guide](docs/dsl.md#analyzing-a-policy).

### Testing a policy

Tests sit beside the policy: `*.strig-test.json` files of `check` cases (subject, permission, resource, optional instant
and environment, expected `allow` or `deny`, optionally the reason and the deciding grant) and `mutation` cases (an actor
and a change, accepted or refused, optionally by which invariant). `strig test` runs them, and an error in the test itself
is never a pass:

```sh
cargo install strig-cli --locked
strig test policies/ --junit test-results/strig.xml   # exit 1 on a failure, 2 on a bad input
```

```yaml
- uses: The-Hades-Organization/Strig/.github/actions/strig-test@v0.9.0
  with: { path: policies, version: 0.9.0 }
```

The same runner is `strig::dsl::testing` in Rust and `strig.runTests(policy, tests)` in JavaScript and `strig.dsl.run_tests(policy, tests)` in Python. The format, the
report and the exit codes are in [the guide](docs/dsl.md#testing-a-policy); `examples/policy-tests/` has a project that
passes.

### Editor

`strig-lsp` is a language server for `.strig` files, and `editors/vscode` is the VS Code extension that uses it. Both read the project the way `strig test` does: every `*.strig` file of the directory of the open file is one policy, in any mix of the three syntaxes, and every `*.strig-test.json` beside it is a test file. Unsaved buffers count.

- **Diagnostics while you type**, with the position and the hint of the validator, including clashes between files (the other side is a related location) and the errors of a `*.strig-test.json`.
- **Format document**, the same layout as `strig::dsl::format`; a source that does not compile is left alone.
- **Completion** of permission ids, kinds, roles, subjects and condition operators from the project, narrowed by the line (`depends_on = [`, `inherits `, `when = ...`).
- **Hover** on a permission with its targets, `implied_by`, `depends_on`, fields and labels per locale, and on a role or a kind.
- **Go to definition** of a permission, role, grant or subject across files.
- **Code action** "Convert to rules/actors/blocks syntax" for the whole file.

```sh
cargo install --git https://github.com/The-Hades-Organization/Strig strig-lsp --locked   # the server
cargo install strig-cli --locked                                                            # `strig test`, for the command below
```

The extension finds `strig-lsp` and `strig` on `PATH`, or at `strig.server.path` and `strig.cli.path`, and says how to install them when they are missing. The command "Strig: Run policy tests" runs `strig test .` in the folder of the open file. To build the extension: `cd editors/vscode && npm ci && npm test && npx vsce package`. Publishing it to the Marketplace and Open VSX is not set up yet. Other editors that speak LSP can run `strig-lsp` directly: it talks over stdio and takes no arguments.

### Macros

`policy!` and `include_policy!`, from the `strig-macros` crate, validate the policy at compile time: a policy that does not validate does not build. They live in their own crate rather than behind a `strig` feature; the guide explains [why](docs/dsl.md#macros).

```rust
use strig_macros::{include_policy, policy};

let inline: strig::dsl::Policy = policy!(r#"
language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
"#);
let from_file: strig::dsl::Policy = include_policy!("policies/main.strig");
```

## Migrating from Casbin / OpenFGA

`strig import` reads the model and the policy of another library and writes a `.strig` file. Nothing runs Casbin or OpenFGA: the converter is a module of the library (feature `import`, on in `strig-cli`, no IO) that takes text and returns a policy and a report.

```sh
strig import casbin model.conf policy.csv -o ./policy [--language blocks|rules|actors] [--action read]...
strig import openfga model.fga tuples.csv -o ./policy [--language blocks|rules|actors]
```

It writes `<dir>/policy.strig` and prints what was converted, what was converted with a narrower reach and what was not. Exit `0` when everything converted, `1` when something has no faithful translation (nothing is written), `2` for usage errors. The result is checked like any policy: run it with `strig test`.

**Casbin.** ACL, RBAC (`g = _, _`, and domains with `g = _, _, _`), RBAC with `keyMatch` on the resource, and ABAC over attributes are read. A `p` line becomes grants, a `g` line a role assignment or an edge of the role graph, and the policy effect picks the strategy (`some(where (p.eft == allow))` is `most_specific`, with a `deny` line dropped and reported; `!some(where (p.eft == deny))`, allow-and-deny and `priority(p.eft)` become `deny_overrides` or `first_applicable`). A model that does not constrain the action (ABAC) needs `--action <name>`. `keyMatch` becomes a `starts_with` condition and `regexMatch` is read only over alternations of literals, expanded over the actions the policy names. A matcher with no faithful translation (`keyMatch2`, `globMatch`, arithmetic, `!=` between request and policy) is an error with the file, line and column and the reason, never an approximation that allows more.

**OpenFGA.** The DSL and the JSON of the model are read, and the tuples as JSON, CSV, YAML or one per line. Types and relations become a `RelationSchema` (`This`, `Computed`, `TupleToUserset`, `Union`, `Intersection`, `Exclusion`), tuples go to the `TupleStore`, and each relation gets a permission and a grant. Conditions (CEL) are not translated: a model or a tuple that uses one is an error that points at it.

Each fixture under `crates/strig/tests/fixtures/import/` holds a model, a policy and a table of requests with the answers the source library gives (from its documentation); the tests decide the same requests with the imported policy, in the three syntaxes, and compare.

## Inspector (`strig-inspect`)

`strig-inspect` shows why a decision came out the way it did. It is built on `Engine::explain`, which Rust and JS can also call directly. From the example scenario:

```sh
strig-inspect explain --scenario crates/strig-inspect/examples/scenario.json \
    --subject ben --permission document.view --resource secret
```

```text
DENIED — ben asks document.view on document:secret → project:roadmap → org:acme → global
reason: grant no-secret (document.view, step 0) chosen by strategy most_specific
permissions that grant: document.view, project.view
effective roles: member
override resource_owner: abstained
grants (5):
  + members-view allow project.view → role member on org [step 2]
      candidate
  - editors-edit allow project.edit → relation editor on project
      permission not related
  ★ no-secret deny document.view → any subject on document:secret [step 0]
      candidate
  - pro-export allow document.export → role member on org
      permission not related
  - no-invoice-export deny document.invoice.export → role member on doc_type:invoice
      permission not related
```

The crate is not on crates.io and is outside the workspace `default-members`. Install it from a clone:

```sh
cargo install --path crates/strig-inspect                          # window and terminal commands
cargo install --path crates/strig-inspect --no-default-features    # terminal commands only, no gpui
```

```sh
strig-inspect --scenario scenario.json --audit trail.jsonl          # window
strig-inspect --scenario scenario.json --subject ben --permission document.export --resource invoice-7 \
               --disable pro-export --tab matrix                    # window opened on a selection and tab
strig-inspect matrix --scenario scenario.json --resource secret --disable no-secret --add grant.json
strig-inspect audit  --audit trail.jsonl --scenario scenario.json
strig-inspect fmt [--check] <file|dir>
```

A scenario is a JSON file with the policy (`spec`, an `EngineSpec`), the data (`grants`, `tuples`, `env`) and the named subjects and resources to examine. The example in `crates/strig-inspect/examples/` comes with a forensic trail of six decisions, `audit.jsonl`, generated by:

```sh
cargo run -p strig-inspect --no-default-features --example trail -- \
    crates/strig-inspect/examples/scenario.json > crates/strig-inspect/examples/audit.jsonl
```

The window has three tabs:

- **Evaluation:** pick a subject, permission and resource and see the decision, the reason, the resource path with the deciding step, the effective roles, each override, and why each grant did or did not apply, with its condition tree and the resolved values.
- **Matrix:** every catalog permission for every subject on one resource. Click a cell to open its trace.
- **Audit:** reads a JSON Lines trail, checks the hash chain of the `forensic` records, shows the recorded trace and re-evaluates `detailed` and `forensic` decisions against the current policy, flagging the ones that would change.

**Simulation** works across the tabs: turn grants off or on, or add some with `--add`, and see whether the set would allow the access. When a decision changes, the original decision is shown next to it, and changed matrix cells are marked.

Files reload when they change on disk. The window follows the system light or dark appearance, uses the playground's palette, and embeds its fonts (Noto Sans and JetBrains Mono, OFL) and icons, so it looks the same on any machine. The interface is in English.

### In the browser

The playground also hosts the inspector: [strig-playground.vercel.app/inspector.html](https://strig-playground.vercel.app/inspector.html). It has the same three tabs and the same simulation, over the engine compiled to WebAssembly, so there is nothing to install. It reads the same scenario JSON as `strig-inspect`, from a file, a paste or the built-in example (`crates/strig-inspect/examples/scenario.json`).

- **Evaluation:** the decision, the reason, the path, the effective roles, each override and why each grant did or did not apply, over `explain`.
- **Matrix:** every catalog permission for every subject on one resource. Click a cell to open its evaluation.
- **Audit:** load a JSON Lines trail, verify the `forensic` chain with `verifyAuditChain` and re-evaluate `detailed` and `forensic` decisions against the current policy, flagging the ones that would change.
- **Simulation:** turn grants off or add some from a form; a changed decision shows the original beside it, and changed matrix cells are marked.

The page uses the playground's identity, follows the light or dark scheme and works from 360 px wide. The scenario and the trail are read in the page and never leave the browser. To run it locally, see [`playground/README.md`](playground/README.md).

## Extension points

| Trait | Implement it to |
|---|---|
| `GrantSource` | Read grants from a database, a cache, or several sources (`(A, B)` tuples chain). |
| `TupleStore` | Keep ReBAC tuples outside memory. |
| `Override` | Decide before the grants: owner, superadmin, suspended account, maintenance window. `FnOverride` takes a closure. |
| `Strategy` | Combine grants with another rule. |
| `Invariant` | Add a rule for grant changes. |
| `CatalogRule` | Validate the catalog your way (`RequireMeta`, `FnRule`). |
| `AuditSink` | Send the audit trail somewhere else. |
| `Transport` | Carry change notices between instances. |
| `CapabilityProvider`, `GrantLoader` | Control how a session computes the capabilities it sends. |
| `ChangeSink` | React synchronously to each change (cache, metric). |

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --exclude strig-inspect --exclude strig-python --all-targets -- -D warnings
cargo test --workspace --exclude strig-inspect --exclude strig-python
cargo test -p strig-inspect --no-default-features

# transports against real servers (skipped without the variables)
STRIG_REDIS_URL=redis://127.0.0.1:6379/ STRIG_PG_URL=postgres://postgres:pw@127.0.0.1/postgres \
    cargo test --workspace --exclude strig-inspect
```

The npm package lives in `crates/strig-node/js`. `crates/strig-node/scripts/build.sh` builds the native module (`js/native/strig.<platform>-<arch>.node`, the local-build fallback of the loader) and the WebAssembly (`js/wasm/`); the release splits the native modules into per-platform packages with `scripts/package-platforms.mjs`; the wasm part needs the `wasm32-unknown-unknown` target and `wasm-bindgen-cli` 0.2.130.

```sh
sh crates/strig-node/scripts/build.sh
cd crates/strig-node/js
npm ci
npm test              # Node
npm run test:bun      # Bun
```

Set `STRIG_RUST_SERVER` to the URL of the `strig-axum` `server` example to also test the JS client against the Rust server.

To run the playground locally, see [`playground/README.md`](playground/README.md).

Building the `strig-inspect` window on Linux needs the Wayland and X11 development libraries, for example `libxkbcommon-dev`, `libwayland-dev`, `libxcb1-dev` and `libvulkan-dev`.

Benchmarks: `cargo bench -p strig --bench engine`, and `node bench/bench.mjs` in `crates/strig-node/js` (or `bun`); see [docs/benchmarks.md](docs/benchmarks.md).

Fuzzing: `./fuzz/run.sh <target> [seconds]` (nightly and `cargo install cargo-fuzz`) runs the targets in `fuzz/` for the policy language, `EngineSpec`, conditions, decisions, the sync and server messages and the audit chain; see [CONTRIBUTING.md](CONTRIBUTING.md#fuzzing).

Source comments are in Brazilian Portuguese. Issues and pull requests are welcome in English or Portuguese; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE). The fonts embedded in `strig-inspect` are under the SIL Open Font License 1.1 (see `crates/strig-inspect/assets/fonts`).
