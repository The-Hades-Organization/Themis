# Versioning and deprecation policy

Strig follows [Semantic Versioning](https://semver.org/). This page says what the public API is, what counts as a
breaking change in each part of it, how versions behave before and after 1.0, which toolchains are supported, and how
a feature is deprecated before it is removed.

All crates, the npm package, the Python package, the Go module tag and the Java artifact share one version number. A release bumps them together.

## What is public API

| Surface | What is covered |
|---|---|
| **Rust crates** | Everything reachable from the public items of `strig`, `strig-sync`, `strig-redis`, `strig-postgres`, `strig-axum`, `strig-macros` and `strig-server` with the documented feature flags. The `strig-node`, `strig-python`, `strig-wasi` and `strig-inspect` crates are not libraries: their API is the npm package, the Python package, the Go and Java bindings and the command line below. |
| **npm package** | The exports of `@the-hades-organization/strig` and its subpaths (`/client`, `/server`, `/protocol`, `/remote`, `/express`, `/fastify`, `/nestjs`, `/store`, `/testing`, `/types`), their TypeScript types, and the `strig-types` command. |
| **Python package** | The exports of `strig` (`pip install strig-auth`): `Engine`, `Context`, `Exclusive`, `StrigError`, `DslError`, `scope_from_string`, `audit_estimate`, `verify_audit_chain` and `strig.dsl`, their method names and keyword arguments, and the type stubs. Values are the same JSON as the JavaScript API, with the same camelCase field names. |
| **Go module** | The exports of `github.com/The-Hades-Organization/Strig/bindings/go`: `Engine`, `Context`, `Decision`, `Error`, `CodeOf`, `WithNow`, `Compile`, `Format` and their methods. Values are the same JSON as the JavaScript API, with the same camelCase field names. |
| **Java and Kotlin package** | The public classes of `io.github.the-hades-organization:strig` (`Engine`, `Context`, `Decision`, `StrigException`, `Strig`) and their methods. Values are the same JSON as the JavaScript API. |
| **Wasm ABI** | The exports of `strig-<version>.wasm` (`memory`, `strig_alloc`, `strig_free`, `strig_call`), the operation names and JSON inputs of `strig_call`, and the envelope it answers with. |
| **Policy language** | The grammar and meaning of the three syntaxes (Blocks, Rules, Actors) described in [dsl.md](dsl.md), and the canonical JSON the parser produces. |
| **JSON spec** | The shape of `EngineSpec`, `Grant`, `Condition`, `Catalog`, the exported catalog and the files read by the JSON store, including their `schema` numbers (`DSL_SCHEMA` for the policy JSON). |
| **Audit format** | The canonical form of a record and the hash of the chain, fixed in [audit-format.md](audit-format.md), with its test vector. |
| **`errorCode`s** | The `code` of every error the JS, Python, Go and Java bindings raise (`ErrorCode`) and the stable machine-readable names the Rust errors map to. |
| **Wire protocol** | The messages of `strig-sync`, `strig-server` and the JS `/protocol` module. The client protocol is version 2 (`hello.version`, 1 when absent): version 2 adds revisions (`capabilities.revision`, `change.revision`, `refresh_at_least`, the `x-strig-min-revision` header and the `min_revision` field) as optional fields, so a peer that sends none keeps working. |
| **`strig-inspect` command line** | Subcommands, flags and exit codes. The window and the text of messages are not covered. |

Not public, and free to change in any release: items marked `#[doc(hidden)]`, anything under an `internal` or
`__private` name, the layout of the built `dist/` and `wasm/` folders (use the exports map), the wording of error
messages and hints (match on `code`, never on the text), the exact text of `explain` traces, the playground and the
`strig-inspect` window, and benchmark numbers.

## What counts as a breaking change

**Rust.** Removing or renaming a public item; changing a signature or a trait; adding a required method to a public
trait that users implement (`AuditSink`, `Invariant`, `ExclusiveStore`, `TupleStore` and the others); adding a variant
to a public enum or a field to a public struct that is not `#[non_exhaustive]`, since an exhaustive `match` or a struct
literal stops compiling; changing a default feature; raising the MSRV (see below); changing what a method returns for
the same input in a way a caller can observe.

**Go and Java packages.** Removing or renaming an exported function, type, method or exception; changing the `Code` of an error; dropping a supported Go or Java version; changing a result field. Adding a method or an optional argument is not breaking.

**Wasm ABI.** Changing the signature of an export, removing or renaming an operation, or changing the envelope. New operations and new optional input fields are not breaking.

**Python package.** Removing or renaming a function, class, method, keyword argument or exception; changing the `code` of an error; dropping a supported Python version; changing a result field. Adding a keyword argument with a default is not breaking.

**npm package.** Removing or renaming an export, an option or a field; narrowing an accepted type or widening a
returned one; changing the `code` of an error; dropping a supported Node or Bun version; moving a subpath.

**Policy language and JSON spec.** A source or document that parsed before must parse to the same policy. Removing a
keyword, `op`, field or syntax is breaking. Adding one is not, but a policy that uses it exports a higher `schema`
number, so older readers refuse it instead of reading it wrongly (`DSL_SCHEMA` is 5 today). Making the validator
reject what it accepted is breaking, and fixing the validator to stop accepting what the documentation never allowed is
a fix.

**Audit format.** Any change to the canonical form or the hash computation is breaking, because it invalidates stored
chains and anchors. A change here needs a major version and a documented migration of existing chains.

**`errorCode`s.** Codes are added, never changed or reused. Removing a code or making an existing situation report a
different one is breaking.

**Decisions.** A bug fix that makes the engine deny where it allowed wrongly is not breaking, even if a caller relied
on it, and it is announced under **Fixed** in the changelog, as security fixes are. A change that allows where it
denied needs a test showing the deny cases that must still deny, and is announced under **Changed** or **Breaking**.

Anything breaking is listed under **Breaking** in the [changelog](../CHANGELOG.md) with the step the user takes, and
the larger ones are written out in [migration.md](migration.md).

## Versions before and after 1.0

- **Before 1.0** (`0.y.z`): a minor version (`0.y`) may contain breaking changes; a patch version (`0.y.z`) never does.
  Every breaking change is in the changelog and, when it needs more than one line, in the migration guide.
- **From 1.0** (`x.y.z`): a major version is the only one that breaks the public API; a minor adds features and
  deprecations; a patch only fixes. Security fixes ship in a patch of every supported line (see
  [SECURITY.md](../SECURITY.md)).
- A pre-release (`1.0.0-rc.1`) can change until the final version.

## Supported toolchains

- **Rust (MSRV)**: 1.88 today (`rust-version` in `Cargo.toml`). Raising it is a minor change before 1.0. From 1.0, the
  MSRV may be raised only in a minor version, never in a patch, stays at least six months old, and is announced in the
  changelog.
- **Node**: 18.17 or newer (`engines.node`), and **Bun** 1.1 or newer (`engines.bun`). Dropping a version is a breaking
  change before 1.0 as well; from 1.0 it needs a major version, except when the runtime has been end-of-life for more
  than six months.
- **Python**: 3.9 or newer (CPython, one `abi3` wheel per platform covers every later version). Dropping a version is a breaking change before 1.0 as well; from 1.0 it needs a major version, except when the version has been end-of-life for more than six months. Wheels: `linux-x64` and `linux-arm64` (manylinux), `darwin-x64`, `darwin-arm64`, `win32-x64`; the source distribution builds on anything else with a Rust toolchain.
- **Go**: 1.22 or newer (`go` in `bindings/go/go.mod`). **Java**: 17 or newer, and Kotlin on any version that targets it. Dropping a version is a breaking change before 1.0 as well; from 1.0 it needs a major version, except when the runtime has been end-of-life for more than six months. Both run the engine on a WebAssembly runtime written in the host language, so any OS and architecture that runs Go or the JVM is supported.
- **Browsers and others**: the WebAssembly backend needs WebAssembly with the features the shipped `.wasm` uses; the
  `browser` export of the package is built for current evergreen browsers.
- **Platforms with a native module**: `linux-x64` and `linux-arm64` (glibc), `darwin-x64`, `darwin-arm64`,
  `win32-x64`. Linux musl uses the WebAssembly backend. Adding a platform is not breaking; removing one is.

## Deprecation policy

1. **Warn in a minor.** A feature is deprecated in a minor release (before 1.0: in a `0.y` release, with at least one
   `0.y` release before removal). The release notes list it under **Deprecated**, naming the replacement and the
   version where it will go.
2. **Remove only in the next major.** From 1.0, a deprecated item stays through the rest of the major line and is
   removed in the next major. Before 1.0, it is removed no sooner than the next minor after the one that deprecated it.
3. **Keep it working.** A deprecated item keeps its behaviour. The only change allowed is the warning.
4. **Security is the exception.** When keeping something works against safety, it can be removed or made to fail
   closed in a minor or a patch; the advisory and the changelog say so.

How the warning reaches you:

- **Rust**: `#[deprecated(since = "0.y.0", note = "use `new_name`; removed in 2.0")]` on the item. The compiler warns at
  every use; CI builds with `-D warnings`, so a project that denies warnings fails at the first build after the
  upgrade, which is the point.
- **JavaScript and TypeScript**: a `@deprecated` JSDoc tag in the `.d.ts`, with the replacement, which editors strike
  through, and a one-time runtime `process.emitWarning(message, 'DeprecationWarning', 'STRIG_DEPnnn')` on Node and Bun
  (`console.warn` in the browser). Run Node with `--throw-deprecation` in your tests to fail on a use. Each deprecation
  has a stable `STRIG_DEPnnn` code that the changelog repeats.
- **Policy language and JSON**: a deprecated keyword or field still parses. The validator will report it as a
  warning, not an error, with the position and the replacement in the hint, and the release notes say how to rewrite
  it.
- **Error codes**: a deprecated code keeps being thrown until the major version; the changelog names the code that will
  replace it.

Changes made before this policy, such as the `needs` to `depends_on` rename in 0.5.0, were breaking at once and are
recorded under **Breaking** in the changelog; from now on a rename goes through the steps above.
