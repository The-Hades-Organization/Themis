# Strig decision server: HTTP contract

All bodies are JSON (`Content-Type: application/json`). All times are milliseconds since the Unix epoch, UTC.
The server decides with its own clock. The contract has no authentication and no rate limiting: put the server
behind the embedder's gateway.

## Fail-closed rule

Any answer other than a successful `200` from a decision route means **no access**. Only `200` is a success: `1xx`,
`3xx`, any other `2xx` and any `4xx`/`5xx` are failures. A client must treat a network error, a timeout, any
non-`200` status and an unreadable `200` as a deny. The server never answers a decision it could
not compute: it answers `503`.

## Errors

```json
{"error": {"code": "source_unavailable", "message": "the grant source is unavailable; access is denied"}}
```

`code` is stable and safe to branch on. `message` is fixed per code and never carries table names, paths or driver
text; those stay in the server log.

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `malformed_json` | The body is not JSON. |
| 400 | `invalid_request` | Valid JSON that does not fit the route, an unknown field, a `layout` that does not fit `kind`, or a bad deadline header. |
| 400 | `batch_too_large` | More checks than the server's batch limit (default 256). |
| 400 | `too_many_resources` | More candidate resources than the limit (default 1000). |
| 404 | `not_found` | No such route. |
| 405 | `method_not_allowed` | Wrong method. |
| 413 | `body_too_large` | Body over the limit (default 1 MiB). |
| 415 | `unsupported_media_type` | Body is not `application/json`. |
| 503 | `source_unavailable` | The grants or the policy could not be loaded. |
| 503 | `query_limit_exceeded` | The query went past the server's `QueryLimits`, or a batch or `list` went past the work budget (checks × grants, default 1 000 000). |
| 503 | `overloaded` | No work slot was free before the deadline (default: one per CPU). |
| 503 | `relation_depth_exceeded` | A relation chain was too deep to read a deny. |
| 503 | `deadline_exceeded` | The deadline passed before an answer was ready. |
| 503 | `revision_not_reached` | `x-strig-min-revision` (or `min_revision`) asked for a revision the source has not reached. Deny, retry later. |
| 503 | `revision_mismatch` | The required revision belongs to another data scope than the source's, or the source tracks none. |
| 503 | `clock_unavailable` | The server clock has no usable instant. |
| 503 | `internal` | Anything else that went wrong inside the server, including a panic in a handler (caught; the process keeps running). |

`4xx` means the caller's request is wrong and retrying it unchanged will fail again. `503` means the server could not
decide: deny, and retry later.

## Deadline

Send `x-strig-timeout-ms: <positive integer>` to set the deadline of one request. Without it the server uses its
default (2 s). The server caps the value at its ceiling (default 10 s). `0`, a negative number or text is `400
invalid_request`. When the deadline passes the answer is `503 deadline_exceeded`. The deadline covers reading the body
and the work itself, and is checked between the items of a batch and around queries, so abandoned work stops early. It
starts when the headers arrive: a read timeout for the headers belongs to the listener (hyper `header_read_timeout`).

## Minimum revision

Read your own writes: send `x-strig-min-revision: <scope>@<value>` (any route) or the `min_revision` field of `check`
and `check/batch` to answer only from data at that revision or later. A source whose revision is behind is polled until the deadline and then answers `503 revision_not_reached`; one that
tracks another scope, or no revision at all, answers `503 revision_mismatch` at once, never an answer from unproven data.
A malformed token is `400
invalid_request`. The answers of `check` and `check/batch` carry `revision` when the source tracks one. The Rust client
has `check_at_least` and `check_batch_at_least`, which also refuse an answer that does not prove the revision.

## Limits

* Body: 1 MiB by default (`413 body_too_large`).
* Batch: 256 checks by default, and a work budget of checks × max(grants, 1) (`503 query_limit_exceeded`).
* `list`, `who` and `access` apply the server's `QueryLimits` (defaults 1000 and 100 000); going past them is
  `503 query_limit_exceeded`. `list` applies the work budget to resolving candidates.
* Blocking work runs in a bounded pool. Work abandoned after a deadline keeps its slot until it stops, so a flood of
  timeouts ends in `503 overloaded`, never in unbounded work.
* Each request reads one snapshot of policy and grants, then reads the clock, so `evaluated_at` is never older than the
  data it decided on.

## Routes

### `POST /v1/check`

```json
{"subject": {...}, "permission": "document.view", "resource": {...}, "env": {}, "at": 1700000000000}
```

`subject` and `resource` use the JSON of the Strig `Subject` and `Resource` types. `env` (optional) carries attributes
for conditions; its `now` is replaced by the server clock. `at` (optional) is what the caller thinks the time is, kept for
audit: it is echoed and never used to decide.

Answer `200`:

```json
{"decision": {"effect": "allow", ...}, "evaluated_at": 1700000000000, "requested_at": 1700000000000}
```

`decision.effect` is `allow` or `deny`. A deny is a normal `200`.

### `POST /v1/check/batch`

Body `{"checks": [<check>, ...]}`. Answer `{"results": [<check answer>, ...]}`, one per check, in request order. The
batch is all or nothing: if the server cannot answer, the whole call is an error and no result is partial.

### `POST /v1/list`

Body: `subject`, `permission`, `kind`, optional `layout` (path steps, most specific first), optional `resources`
(candidates), `env`, `at`.

Answer: `kind`, `permission`, `exact`, `shape`, `residual`, `warnings`, `evaluated_at`, and `ids` when `resources` was
sent. `shape.type` is one of `nothing`, `kind` (with `except`), `ids`, `within` (with `anchors`), `compound` (with
`expr`). `residual` lists what only the resource can settle: **never read it as an allow**. `ids` are the candidates the
subject reaches, with the undecided ones settled by a real check.

### `POST /v1/who`

Body: `permission`, optional `resource`, `env`, `at`. With `resource` it answers who holds the permission on it
(`who_can_on`); without, who is named by an allow grant anywhere (`who_can`).

Answer: `permission`, `entries` (each with a `subject` tagged by `type`: `user`, `object`, `role`, `principal`,
`userset`, `wildcard`, `anyone`, and the `via` that grants it), `except`, `evaluated_at`.

### `POST /v1/access`

Body: `resource`, `env`, `at`. Answer: who holds which permission on the resource (`access_of`), with the path that
decided each one.

### `GET /health/live`

`200 {"status":"live"}` while the process runs.

### `GET /health/ready`

`200 {"status":"ready"}` when the grant source answers. Otherwise `503` with the error body above, so an instance that
cannot load grants leaves the pool instead of denying everything.

## AuthZEN Authorization API

With `DecisionServer::with_authzen(AuthzenConfig)` the router also serves the OpenID AuthZEN Authorization API 1.0
(Final, 11 January 2026, <https://openid.net/specs/authorization-api-1_0.html>) next to `/v1`. Without it these routes do
not exist (`404`). It is the same server: the same body limit, deadline (`x-strig-timeout-ms`), work budget, batch limit
(`max_batch` also bounds `evaluations`) and observability (the routes are spans and metric labels like the others), and
the same absence of authentication: the layers the embedder puts around the router cover both.

All bodies are JSON objects; unknown fields are ignored; a missing required field is `400 invalid_request`.

| Route | Spec | Notes |
| --- | --- | --- |
| `POST /access/v1/evaluation` | 6 | `{subject, action, resource, context?}` answers `{decision, context?}`. |
| `POST /access/v1/evaluations` | 7 | Top-level `subject`/`action`/`resource`/`context` are defaults an item overrides. `options.evaluations_semantic` is `execute_all` (default), `deny_on_first_deny` or `permit_on_first_permit`; anything else is `400`. Without `evaluations` (or empty) it is one evaluation and answers `{decision}`. |
| `POST /access/v1/search/subject` | 8.4 | Subjects of `subject.type` that hold `action.name` on `resource` (`who_can_on`). |
| `POST /access/v1/search/action` | 8.6 | The permissions of the catalog that `subject` holds on `resource`. |
| `POST /access/v1/search/resource` | 8.5 | Only with `AuthzenConfig::with_resource_catalog`; otherwise `404`. |
| `GET /.well-known/authzen-configuration` | 9 | Only with `AuthzenConfig::with_issuer` (an `https` URL); otherwise `404`. |

### Mapping

| AuthZEN | Strig |
| --- | --- |
| `subject.type`, `subject.id` | `Subject.kind`, `Subject.id`. The kinds in `authenticated_kinds` (default `user`) also carry the `authenticated` principal, as `Subject::user` does. |
| `subject.properties` | Attributes. A property named `roles` (default) holds the roles: strings, or `{role, scope?, valid_from?, valid_until?}`. A property named `principals` (default) holds principal names. Neither becomes an attribute. The names are configurable. |
| `resource.type`, `resource.id` | The first step of the path, `type:id`. |
| `resource.properties` | Attributes. A property named `path` (default) holds the broader steps, most specific first: `[{"kind": "org", "id": "o1"}]`. With a `PathResolver` configured the server's answer is used and the property is ignored; a resource it does not know is a deny with `context.error.status` `404`. |
| `action.name` | The permission. `action.properties` is not read. |
| `context` | `env`. The server replaces `now` with its clock. |

Nested objects in `properties` and `context` become dotted attributes (`device.managed`); arrays must hold scalars. A value
that cannot be an attribute, or two properties that write the same attribute, is a malformed request: `400` on
`/evaluation`, and in `/evaluations` a deny for that item with `context.error` (`status` 400).

### Answers

`decision` is `true` only for an `allow`. A permission that is not in the catalog is `200 {"decision": false}`. With
`with_reasons(true)` a request that sends `x-strig-reason: true` gets `context.reason`, one of `override`, `grant`,
`no_applicable_grant`, `unknown_permission`, `missing_prerequisite`; never a grant id, role or permission.
`deny_on_first_deny` marks the denial that ends the run with `context: {"code": "200", "reason": "deny_on_first_deny"}`, as the
spec's example does, and the answer stops there; `permit_on_first_permit` stops at the first permit.

### Errors

The body is the error body above. Statuses are the ones of the spec: `400` for a request that does not fit, `500` for
everything the server could not decide (the codes `source_unavailable`, `deadline_exceeded`, `overloaded`,
`query_limit_exceeded`, ... are the `503` ones of `/v1`, answered `500` here), plus the transport statuses `404`, `405`,
`413` and `415`. As everywhere, anything that is not a `200` is no access. `X-Request-ID` of the request is echoed on every
answer.

### Search

Results are sorted, and every search takes `page: {token?, limit?}` and answers `page: {next_token, count, total}`;
`next_token` is `""` on the last page. `limit` defaults to and is capped by `AuthzenConfig::with_max_page_size` (1000). The
token is stateless and bound to the request: change an entity, the context or the limit and it is `400`.

* **Subject search** answers the parties `who_can_on` names that are of the requested type (`user` for users, the kind for
  `Object` parties), each one confirmed by a real decision. Roles, principals, usersets, wildcards and `anyone` are not
  subjects of a type: when any is left out, `context.incomplete` is `true`.
* **Resource search** decides every resource the `ResourceCatalog` lists for `resource.type` (at most `max_resources`,
  inside the work budget). Strig does not enumerate resources it was never told about, so without the catalog the route is
  not served and the metadata does not list it.
* **Action search** decides every permission of the catalog on the resource.

### Not covered

`signed_metadata`, `capabilities`, tenant suffixes of the well-known URI, `action.properties` and `page.properties` are not
read. The Rust client has no AuthZEN methods: a PEP that speaks the standard uses its own SDK.

## Envoy External Authorization (gRPC, feature `envoy`)

With the `envoy` feature, `DecisionServer::envoy_service(EnvoyConfig)` builds the
`envoy.service.auth.v3.Authorization` service (method `Check`) over the same source, clock, limits and work slots as the
HTTP routes. Take it before `router()`, which consumes the server. It is a tower service: add it to a
`tonic::transport::Server`, or call `EnvoyService::serve(listener, shutdown)`, which also bounds each call with
`ServerConfig::max_timeout` and the open streams per connection with `EnvoyConfig::with_max_concurrent_streams`.
Without the feature the crate has no `tonic` or `prost` in its build. The messages are the part of the Envoy protos the
adapter uses, as prost structs in `strig_server::envoy` (no `protoc`, no code generation); fields it does not declare are
skipped, so newer Envoys decode. An example Envoy configuration is `examples/envoy.yaml`, with `examples/envoy.rs`.

### Mapping

| `CheckRequest` | Strig |
| --- | --- |
| `attributes.request.http.method` and `path` | The first route whose methods and pattern match decides. The query and fragment are dropped, segments are percent-decoded; a path with dot segments, an empty segment in the middle, an encoded `/`, `\` or NUL, invalid UTF-8 or more than 64 segments matches no route. |
| A header (`with_subject_header`) or a string in the filter metadata (`with_subject_metadata("envoy.filters.http.jwt_authn", ["payload", "sub"])`) | The subject id, of the kind `with_subject_kind` (default `user`), with the `authenticated` principal. Sources are tried in order. A value that is empty, longer than 512 bytes or holds a comma is no subject. |
| A header (`with_roles_header`), comma-separated | The roles of the subject, up to 64 of at most 512 bytes; past that there is no subject. |
| The route's `RouteRule::require(permission, ResourceTemplate::new(kind, id))` | The permission and the resource; `{param}` in `kind` and `id` is filled from the path parameters, and a template that names a parameter the pattern lacks fails at configuration. |
| `with_path_resolver` | The broader steps of the resource, as for AuthZEN. A resolver that does not know the resource makes the answer a deny. |

Patterns start with `/`; a segment is a literal, `{name}` (one segment, captured), `*` (one segment) or, last, `**` (the
rest). Methods are `*` or a list such as `GET,HEAD`. Rules are tried in the order they were added.

The adapter trusts the subject and roles it reads. Envoy must set those headers itself and overwrite what the client sent
(for example `claim_to_headers` of the JWT filter), or read them from the metadata of a filter that validated the token.

### Answers

| Case | `status.code` | HTTP | `x-strig-reason` (only with `with_reasons(true)`) |
| --- | --- | --- | --- |
| The engine allows, or the route is `public` | `OK` (0), `ok_response` | | |
| The engine denies | `PERMISSION_DENIED` (7), `denied_response` | 403 | `denied` |
| No route matches | same | 403 | `no_route` |
| No usable subject on a route that needs one | same | 403 | `no_subject` |
| The resolver does not know the resource | same | 403 | `unknown_resource` |
| The source is down, the deadline passed, no work slot, the clock or the work failed | same | 403 | `unavailable` |
| No HTTP attributes, or a template that cannot be filled | same | 403 | `bad_request` |

The reason is a fixed code, never a grant, a role or a permission. A `public` route decides nothing and does not read the
source, so it allows even while the source is down. A panic in the work is a deny too. A message over `max_body_bytes`
or a call that outlives `max_timeout` is a gRPC error instead (`RESOURCE_EXHAUSTED`, `CANCELLED`): leave
`failure_mode_allow: false` in the Envoy filter so that Envoy denies on those as well. The deadline is
`ServerConfig::default_timeout` (capped by `max_timeout`); Envoy's own `grpc_service.timeout` should be at least as long.

### Observability

With `tracing`, each check is a `strig.server.envoy.check` span with its `outcome`, and the counter
`strig_server_envoy_checks_total{outcome, reason}` (`reason` is `none` on an allow). No subject, route or resource is a
label.

## Client behavior (Rust, feature `client`)

* Every call has a timeout, sent to the server as the deadline header.
* The circuit breaker opens after N consecutive failures (network error, timeout, `5xx`, any status other than `200`), refuses calls for a wait, then lets one probe through. A successful probe closes it, a failed one reopens it. `4xx` does not count. A late answer from an old call never closes the circuit: each permit belongs to one generation of the breaker. If the clock does not answer, the breaker uses a local monotonic clock, so an open circuit still probes again.
* A failed check is `Denied(Failure)` with a typed reason: `CircuitOpen`, `Timeout`, `Unreachable`, `Server`, `Rejected`, `InvalidResponse`, `UnexpectedStatus`.
* An error code the client does not know becomes `ErrorCode::Unknown(String)`; decoding does not fail.
* A batch is one call; the answers keep the request order. If the call fails, every check is denied with the same reason.
* `list`, `who` and `access` have no deny to fall back on: they return `Err(Failure)` and the caller must not list or show anything.
