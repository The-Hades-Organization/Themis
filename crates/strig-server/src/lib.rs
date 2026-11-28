//! Strig as a remote decision service: an axum router that fails closed, and a Rust client that does too.
//!
//! The server ([`DecisionServer`]) answers `check`, `check/batch`, `list`, `who` and `access` over
//! JSON from a [`DecisionSource`] the embedder provides. The instant of every decision is the
//! server's clock. When the source is down, a query goes over its limits, the deadline passes or
//! anything else breaks, the answer is a 503 with a stable error body, never an allow.
//!
//! [`DecisionServer::with_authzen`] adds the OpenID AuthZEN Authorization API (`/access/v1`) next to them.
//!
//! With the `envoy` feature, [`DecisionServer::envoy_service`] serves Envoy's External Authorization
//! (`envoy.service.auth.v3.Authorization/Check`, gRPC) over the same source.
//!
//! With the `client` feature (on by default) [`client::Client`] calls it with a timeout and a
//! circuit breaker, and turns every failure into a typed deny. The HTTP contract is in `API.md`.

pub mod authzen;
pub mod clock;
pub mod config;
#[cfg(feature = "envoy")]
pub mod envoy;
pub mod error;
mod obs;
pub mod server;
pub mod source;
pub mod wire;

#[cfg(feature = "client")]
pub mod client;

pub use authzen::{AuthzenConfig, AuthzenConfigError, PathResolver, ResourceCatalog};
pub use clock::{BrokenClock, Clock, ManualClock, MonotonicClock, SystemClock};
pub use config::{MIN_REVISION_HEADER, ServerConfig, TIMEOUT_HEADER};
#[cfg(feature = "envoy")]
pub use envoy::{EnvoyConfig, EnvoyConfigError, EnvoyService, ResourceTemplate, RouteRule};
pub use error::{ApiError, ErrorBody, ErrorCode, ErrorDetail};
pub use server::DecisionServer;
pub use source::{DecisionSource, MemorySource, Snapshot, SourceError};
