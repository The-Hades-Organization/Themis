//! The router: routes, deadlines and the fail-closed mapping of every error.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, FromRequest, FromRequestParts, Request as HttpRequest, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, response::IntoResponse};
use futures_util::FutureExt;
use serde::Serialize;
use serde::de::DeserializeOwned;
use strig::{Attributes, Context, PathLayout, QueryContext, QueryLimits, Reached, Request, Revision, Subject, Value};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout_at};

use crate::authzen::{self, AuthzenConfig};
use crate::clock::{Clock, SystemClock};
use crate::config::{MIN_REVISION_HEADER, ServerConfig};
use crate::error::{ApiError, ErrorCode};
use crate::source::{DecisionSource, Snapshot};
use crate::wire::{
    AccessRequest, AccessResponse, BatchRequest, BatchResponse, CheckRequest, CheckResponse, ListRequest, ListResponse,
    PartyDto, WhoEntry, WhoExcept, WhoRequest, WhoResponse, filter_parts, subject_dto, via_dto,
};

/// The decision service: build it from a source, take the [`Router`], serve it.
///
/// It does no authentication and no rate limiting: put the router behind the layers of the
/// application that embeds it. The deadline starts when the request headers are in; the time a
/// client takes to send them is the listener's to bound (hyper's `header_read_timeout`). See
/// `API.md` for the contract.
pub struct DecisionServer {
    source: Arc<dyn DecisionSource>,
    clock: Arc<dyn Clock>,
    config: ServerConfig,
    authzen: Option<AuthzenConfig>,
    /// The work slots, shared by every protocol the server speaks.
    workers: Arc<Semaphore>,
}

impl DecisionServer {
    /// A server over `source`, with the system clock and the default [`ServerConfig`].
    pub fn new(source: Arc<dyn DecisionSource>) -> Self {
        Self {
            source,
            clock: Arc::new(SystemClock),
            config: ServerConfig::default(),
            authzen: None,
            workers: Arc::new(Semaphore::new(ServerConfig::default().max_concurrent_work.max(1))),
        }
    }

    /// Replaces the clock that gives the instant of every decision.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    #[must_use]
    pub fn with_config(mut self, config: ServerConfig) -> Self {
        self.workers = Arc::new(Semaphore::new(config.max_concurrent_work.max(1)));
        self.config = config;
        self
    }

    /// The Envoy External Authorization service over this server's source, clock and limits, with
    /// the mapping of `config`. It shares the work slots with [`DecisionServer::router`], so the
    /// two protocols together stay inside `max_concurrent_work`. Take it before `router`, which
    /// consumes the server.
    #[cfg(feature = "envoy")]
    pub fn envoy_service(&self, config: crate::envoy::EnvoyConfig) -> crate::envoy::EnvoyService {
        let state = AppState::sharing(
            Arc::clone(&self.source),
            Arc::clone(&self.clock),
            self.config,
            Arc::clone(&self.workers),
        );
        crate::envoy::EnvoyService::new(state, config)
    }

    /// Serves the OpenID AuthZEN Authorization API next to `/v1`, with the conventions of `config`.
    /// Without it the `/access/v1` routes do not exist.
    #[must_use]
    pub fn with_authzen(mut self, config: AuthzenConfig) -> Self {
        self.authzen = Some(config);
        self
    }

    /// The routes, ready for `axum::serve` or to be nested in a bigger router.
    ///
    /// A panic in any handler is caught and answered `503 internal`, so the connection never
    /// drops without a body.
    pub fn router(self) -> Router {
        let body_limit = self.config.max_body_bytes;
        let mut state = AppState::sharing(self.source, self.clock, self.config, self.workers);
        let mut decisions = Router::new()
            .route("/v1/check", post(check))
            .route("/v1/check/batch", post(check_batch))
            .route("/v1/list", post(list))
            .route("/v1/who", post(who))
            .route("/v1/access", post(access));
        if let Some(config) = self.authzen {
            decisions = decisions.merge(authzen::routes(&config));
            state.authzen = Some(Arc::new(config));
        }
        // The deadline layer covers the decision routes only: the probes have their own wait.
        let decisions = decisions.layer(middleware::from_fn_with_state(state.clone(), set_deadline));
        #[cfg(feature = "tracing")]
        let decisions = decisions.layer(middleware::from_fn(crate::obs::http::observe));
        Router::new()
            .merge(decisions)
            .route("/health/live", get(live))
            .route("/health/ready", get(ready))
            .fallback(not_found)
            .method_not_allowed_fallback(method_not_allowed)
            .layer(DefaultBodyLimit::max(body_limit))
            .layer(middleware::from_fn(catch_panic))
            .with_state(state)
    }
}

#[derive(Clone)]
pub(crate) struct AppState {
    source: Arc<dyn DecisionSource>,
    clock: Arc<dyn Clock>,
    pub(crate) config: ServerConfig,
    pub(crate) authzen: Option<Arc<AuthzenConfig>>,
    /// One permit per engine job in flight; see [`ServerConfig::max_concurrent_work`].
    workers: Arc<Semaphore>,
}

impl AppState {
    #[cfg(test)]
    fn new(source: Arc<dyn DecisionSource>, clock: Arc<dyn Clock>, config: ServerConfig) -> Self {
        let workers = Arc::new(Semaphore::new(config.max_concurrent_work.max(1)));
        Self::sharing(source, clock, config, workers)
    }

    /// Like [`AppState::new`], over work slots another state already has.
    fn sharing(
        source: Arc<dyn DecisionSource>,
        clock: Arc<dyn Clock>,
        config: ServerConfig,
        workers: Arc<Semaphore>,
    ) -> Self {
        Self {
            source,
            clock,
            workers,
            config,
            authzen: None,
        }
    }
}

/// The instant a request has to be answered by. It covers the body, the source, the wait for a
/// work slot and the work.
///
/// It also carries the revisions the request requires (header and body), which the snapshot must
/// have reached before the work runs.
#[derive(Debug, Clone)]
pub(crate) struct Deadline(Instant, Vec<Revision>);

/// Pause between two reads of the source while the data is behind a required revision.
const REVISION_POLL: Duration = Duration::from_millis(25);

impl Deadline {
    pub(crate) fn after(wait: Duration) -> Self {
        Self(Instant::now() + wait, Vec::new())
    }

    /// Also requires `revision`, when there is one.
    #[must_use]
    pub(crate) fn requiring(mut self, revision: Option<Revision>) -> Self {
        self.1.extend(revision);
        self
    }
}

/// The revision the header asks for, if it has one. A header that is not a token is a bad request,
/// never ignored: ignoring it would answer from data the caller said was too old.
fn required_revision(headers: &axum::http::HeaderMap) -> Result<Option<Revision>, ApiError> {
    let Some(raw) = headers.get(MIN_REVISION_HEADER) else {
        return Ok(None);
    };
    raw.to_str()
        .ok()
        .and_then(|text| text.trim().parse::<Revision>().ok())
        .map(Some)
        .ok_or(ApiError::new(ErrorCode::InvalidRequest))
}

impl<S: Send + Sync> FromRequestParts<S> for Deadline {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        // `set_deadline` runs before every decision route, so a miss is a wiring bug.
        parts.extensions.get::<Deadline>().cloned().ok_or_else(|| {
            tracing::error!("a decision route ran without a deadline");
            ApiError::new(ErrorCode::Internal)
        })
    }
}

async fn set_deadline(State(state): State<AppState>, mut request: HttpRequest, next: Next) -> Response {
    let deadline = state
        .config
        .timeout_for(request.headers())
        .and_then(|wait| Ok(Deadline::after(wait).requiring(required_revision(request.headers())?)));
    match deadline {
        Ok(deadline) => {
            request.extensions_mut().insert(deadline);
            next.run(request).await
        }
        Err(error) => error.into_response(),
    }
}

async fn catch_panic(request: HttpRequest, next: Next) -> Response {
    match AssertUnwindSafe(next.run(request)).catch_unwind().await {
        Ok(response) => response,
        Err(_panic) => {
            tracing::error!("a request handler panicked");
            ApiError::new(ErrorCode::Internal).into_response()
        }
    }
}

/// Tells the blocking work that nobody waits for it any more.
#[derive(Clone, Default)]
struct Cancel(Arc<AtomicBool>);

impl Cancel {
    fn is_set(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// Sets the flag when the returned guard is dropped: the deadline passed, the client left or
    /// the answer is done.
    fn on_drop(&self) -> CancelOnDrop {
        CancelOnDrop(self.clone())
    }
}

struct CancelOnDrop(Cancel);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.0.store(true, Ordering::Relaxed);
    }
}

/// What a request's work needs besides the snapshot.
pub(crate) struct Run {
    pub(crate) now: u64,
    pub(crate) limits: QueryLimits,
    max_work: usize,
    cancel: Cancel,
}

impl Run {
    /// Stops the work once nobody waits for its answer.
    pub(crate) fn ensure_live(&self) -> Result<(), ApiError> {
        if self.cancel.is_set() {
            return Err(ApiError::new(ErrorCode::DeadlineExceeded));
        }
        Ok(())
    }

    /// Refuses `items` evaluations over `grants` grants when they cost more than the budget.
    pub(crate) fn ensure_budget(&self, items: usize, grants: usize) -> Result<(), ApiError> {
        if items.saturating_mul(grants.max(1)) > self.max_work {
            tracing::warn!(items, grants, "the work of the request is over the server budget");
            return Err(ApiError::new(ErrorCode::QueryLimitExceeded));
        }
        Ok(())
    }
}

impl AppState {
    /// Loads the snapshot, and when the request requires a revision, reads again until the data has
    /// reached it or the deadline passes. Data of another scope, or with no revision at all, is
    /// refused at once: waiting would never settle it. All inside the request deadline.
    async fn settled_snapshot(&self, deadline: &Deadline) -> Result<Arc<Snapshot>, ApiError> {
        loop {
            let snapshot = timeout_at(deadline.0, self.source.snapshot())
                .await
                .map_err(|_elapsed| ApiError::new(ErrorCode::DeadlineExceeded))?
                .map_err(|error| {
                    tracing::error!(error = ?error, "the grant source failed");
                    ApiError::new(ErrorCode::SourceUnavailable)
                })?;
            let mut behind = false;
            for required in &deadline.1 {
                match Revision::reached_by(required, snapshot.revision.as_ref()) {
                    Reached::Yes => {}
                    Reached::Behind => behind = true,
                    _ => {
                        tracing::warn!(required = %required, "the data cannot be compared with the required revision");
                        return Err(ApiError::new(ErrorCode::RevisionMismatch));
                    }
                }
            }
            if !behind {
                return Ok(snapshot);
            }
            let wake = Instant::now() + REVISION_POLL;
            if wake >= deadline.0 {
                tracing::warn!("the data did not reach the required revision before the deadline");
                return Err(ApiError::new(ErrorCode::RevisionNotReached));
            }
            tokio::time::sleep_until(wake).await;
        }
    }

    /// Loads the snapshot and runs `work` on a blocking thread, all inside the request deadline.
    /// Whatever goes wrong becomes an [`ApiError`]; nothing here can end in an allow.
    ///
    /// The blocking job cannot be killed, so it is bounded three ways: it holds one of
    /// `max_concurrent_work` slots until it really ends, it reads `Run::ensure_live` between its
    /// steps and stops once the deadline has passed, and a request that finds no slot before its
    /// deadline is answered `overloaded` instead of queueing.
    pub(crate) async fn answer<T>(
        &self,
        deadline: Deadline,
        work: impl FnOnce(&Snapshot, &Run) -> Result<T, ApiError> + Send + 'static,
    ) -> Result<Json<T>, ApiError>
    where
        T: Serialize + Send + 'static,
    {
        self.answer_raw(deadline, work).await.map(Json)
    }

    /// [`AppState::answer`] without the JSON wrapper, for the protocols that are not JSON.
    pub(crate) async fn answer_raw<T>(
        &self,
        deadline: Deadline,
        work: impl FnOnce(&Snapshot, &Run) -> Result<T, ApiError> + Send + 'static,
    ) -> Result<T, ApiError>
    where
        T: Send + 'static,
    {
        let cancel = Cancel::default();
        let _stop = cancel.on_drop();
        let snapshot = self.settled_snapshot(&deadline).await?;
        let permit = match timeout_at(deadline.0, Arc::clone(&self.workers).acquire_owned()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(error)) => {
                tracing::error!(error = %error, "the work slots are closed");
                return Err(ApiError::new(ErrorCode::Internal));
            }
            Err(_elapsed) => {
                tracing::warn!("no work slot was free before the deadline");
                return Err(ApiError::new(ErrorCode::Overloaded));
            }
        };
        let clock = Arc::clone(&self.clock);
        let limits = self.config.query_limits;
        let max_work = self.config.max_work;
        let job_cancel = cancel.clone();
        let job = tokio::task::spawn_blocking(move || {
            // Held until the work ends, whatever happens to the request that asked for it.
            let _slot = permit;
            // The instant of the decision is read as late as possible: after the source and after
            // the wait for a slot, so a grant that expired meanwhile is not decided at the old time.
            let now = clock.now_ms().ok_or(ApiError::new(ErrorCode::ClockUnavailable))?;
            let run = Run {
                now,
                limits,
                max_work,
                cancel: job_cancel,
            };
            run.ensure_live()?;
            work(&snapshot, &run)
        });
        match timeout_at(deadline.0, job).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                tracing::error!(error = %error, "the decision task did not finish");
                Err(ApiError::new(ErrorCode::Internal))
            }
            Err(_elapsed) => Err(ApiError::new(ErrorCode::DeadlineExceeded)),
        }
    }
}

/// `Json` with the stable error body for every way the body can be refused.
pub(crate) struct ApiJson<T>(pub(crate) T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: HttpRequest, state: &S) -> Result<Self, Self::Rejection> {
        // The body is read inside the request deadline, so a client that sends it slowly is cut.
        let deadline = request.extensions().get::<Deadline>().cloned();
        let read = Json::<T>::from_request(request, state);
        let outcome = match deadline {
            Some(Deadline(at, _)) => timeout_at(at, read)
                .await
                .map_err(|_elapsed| ApiError::new(ErrorCode::DeadlineExceeded))?,
            None => read.await,
        };
        match outcome {
            Ok(Json(value)) => Ok(ApiJson(value)),
            Err(rejection) => {
                tracing::debug!(error = %rejection, "request body refused");
                Err(ApiError::new(rejection_code(&rejection)))
            }
        }
    }
}

fn rejection_code(rejection: &JsonRejection) -> ErrorCode {
    match rejection {
        JsonRejection::JsonSyntaxError(_) => ErrorCode::MalformedJson,
        JsonRejection::MissingJsonContentType(_) => ErrorCode::UnsupportedMediaType,
        JsonRejection::BytesRejection(_) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            ErrorCode::BodyTooLarge
        }
        _ => ErrorCode::InvalidRequest,
    }
}

// ---------------------------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------------------------

async fn check(
    State(state): State<AppState>,
    deadline: Deadline,
    ApiJson(request): ApiJson<CheckRequest>,
) -> Result<Json<CheckResponse>, ApiError> {
    state
        .answer(
            deadline.requiring(request.min_revision.clone()),
            move |snapshot, run| decide(snapshot, run.now, &request),
        )
        .await
}

async fn check_batch(
    State(state): State<AppState>,
    deadline: Deadline,
    ApiJson(request): ApiJson<BatchRequest>,
) -> Result<Json<BatchResponse>, ApiError> {
    if request.checks.len() > state.config.max_batch {
        return Err(ApiError::new(ErrorCode::BatchTooLarge));
    }
    state
        .answer(
            deadline.requiring(request.min_revision.clone()),
            move |snapshot, run| {
                run.ensure_budget(request.checks.len(), snapshot.grants.len())?;
                // All or nothing: one failing item fails the batch, never a partial answer. The
                // deadline is read between items, so a batch nobody waits for stops early.
                let results = request
                    .checks
                    .iter()
                    .map(|check| {
                        run.ensure_live()?;
                        decide(snapshot, run.now, check)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(BatchResponse {
                    results,
                    revision: snapshot.revision.clone(),
                })
            },
        )
        .await
}

async fn list(
    State(state): State<AppState>,
    deadline: Deadline,
    ApiJson(request): ApiJson<ListRequest>,
) -> Result<Json<ListResponse>, ApiError> {
    if request
        .resources
        .as_ref()
        .is_some_and(|r| r.len() > state.config.max_resources)
    {
        return Err(ApiError::new(ErrorCode::TooManyResources));
    }
    // Checked before the source is asked: a request that cannot be right is a 400 whatever the
    // source is doing.
    let layout = layout_of(&request)?;
    state
        .answer(deadline, move |snapshot, run| {
            list_filter(snapshot, run, &request, &layout)
        })
        .await
}

async fn who(
    State(state): State<AppState>,
    deadline: Deadline,
    ApiJson(request): ApiJson<WhoRequest>,
) -> Result<Json<WhoResponse>, ApiError> {
    state
        .answer(deadline, move |snapshot, run| who_holds(snapshot, run, &request))
        .await
}

async fn access(
    State(state): State<AppState>,
    deadline: Deadline,
    ApiJson(request): ApiJson<AccessRequest>,
) -> Result<Json<AccessResponse>, ApiError> {
    state
        .answer(deadline, move |snapshot, run| access_on(snapshot, run, &request))
        .await
}

#[derive(Serialize)]
struct Status {
    status: &'static str,
}

async fn live() -> Json<Status> {
    Json(Status { status: "live" })
}

/// Ready means the source answers now, so an instance that cannot load grants leaves the pool
/// instead of denying everything.
async fn ready(State(state): State<AppState>) -> Result<Json<Status>, ApiError> {
    let wait = state.config.default_timeout.min(state.config.max_timeout);
    match tokio::time::timeout(wait, state.source.snapshot()).await {
        Ok(Ok(_)) => Ok(Json(Status { status: "ready" })),
        Ok(Err(error)) => {
            tracing::error!(error = ?error, "readiness: the grant source failed");
            Err(ApiError::new(ErrorCode::SourceUnavailable))
        }
        Err(_) => Err(ApiError::new(ErrorCode::DeadlineExceeded)),
    }
}

async fn not_found() -> impl IntoResponse {
    ApiError::new(ErrorCode::NotFound)
}

async fn method_not_allowed() -> impl IntoResponse {
    ApiError::new(ErrorCode::MethodNotAllowed)
}

// ---------------------------------------------------------------------------------------------
// Work, on the blocking thread
// ---------------------------------------------------------------------------------------------

/// The request's environment with `now` taken from the server clock, so the validity windows and
/// the ABAC `env.now` read the same instant.
pub(crate) fn env_at(env: &Attributes, now: u64) -> Result<Attributes, ApiError> {
    let now = i64::try_from(now).map_err(|_| ApiError::new(ErrorCode::ClockUnavailable))?;
    let mut env = env.clone();
    env.insert("now".to_string(), Value::Int(now));
    Ok(env)
}

/// The path layout of a listing: `[kind]` by default, otherwise the steps sent, which must start
/// with `kind`.
fn layout_of(request: &ListRequest) -> Result<PathLayout, ApiError> {
    let Some(kinds) = &request.layout else {
        return Ok(PathLayout::new(request.kind.as_str()));
    };
    let mut kinds = kinds.iter();
    match kinds.next() {
        Some(first) if *first == request.kind => Ok(kinds.fold(PathLayout::new(first.as_str()), |layout, kind| {
            layout.within(kind.as_str())
        })),
        _ => Err(ApiError::new(ErrorCode::InvalidRequest)),
    }
}

pub(crate) fn query_context<'a>(snapshot: &'a Snapshot, env: &'a Attributes, run: &Run) -> QueryContext<'a> {
    let mut ctx = QueryContext::new(&snapshot.grants)
        .with_limits(run.limits)
        .with_env(env)
        .at(run.now);
    if let Some(tuples) = &snapshot.tuples {
        ctx = ctx.with_tuples(tuples);
    }
    ctx
}

fn decide(snapshot: &Snapshot, now: u64, request: &CheckRequest) -> Result<CheckResponse, ApiError> {
    Ok(CheckResponse {
        decision: decide_parts(
            snapshot,
            now,
            &request.subject,
            &request.permission,
            &request.resource,
            &request.env,
        )?,
        evaluated_at: now,
        requested_at: request.at,
        revision: snapshot.revision.clone(),
    })
}

/// One decision at `now`, with the request's `env` and the server clock in `env.now`.
pub(crate) fn decide_parts(
    snapshot: &Snapshot,
    now: u64,
    subject: &Subject,
    permission: &str,
    resource: &strig::Resource,
    env: &Attributes,
) -> Result<strig::Decision, ApiError> {
    let env = env_at(env, now)?;
    let mut ctx = Context::new(&snapshot.grants).with_env(&env).at(now);
    if let Some(tuples) = &snapshot.tuples {
        ctx = ctx.with_tuples(tuples);
    }
    let asked = Request::new(subject, permission, resource);
    Ok(snapshot.engine.decide(&ctx, &asked))
}

fn list_filter(
    snapshot: &Snapshot,
    run: &Run,
    request: &ListRequest,
    layout: &PathLayout,
) -> Result<ListResponse, ApiError> {
    if let Some(resources) = &request.resources {
        run.ensure_budget(resources.len(), snapshot.grants.len())?;
    }
    let env = env_at(&request.env, run.now)?;
    let ctx = query_context(snapshot, &env, run);
    let filter = snapshot
        .engine
        .list(&ctx, &request.subject, &request.permission, &request.kind);
    run.ensure_live()?;
    let (exact, shape, residual, warnings) = filter_parts(&filter, layout)?;
    let ids = request
        .resources
        .as_ref()
        .map(|resources| {
            run.ensure_live()?;
            let mut ids = filter.resolve_with(&snapshot.engine, &ctx.context(), resources);
            ids.sort();
            ids.dedup();
            Ok::<_, ApiError>(ids)
        })
        .transpose()?;
    Ok(ListResponse {
        evaluated_at: run.now,
        requested_at: request.at,
        kind: request.kind.clone(),
        permission: request.permission.clone(),
        exact,
        shape,
        residual,
        warnings,
        ids,
    })
}

fn who_holds(snapshot: &Snapshot, run: &Run, request: &WhoRequest) -> Result<WhoResponse, ApiError> {
    let env = env_at(&request.env, run.now)?;
    let ctx = query_context(snapshot, &env, run);
    run.ensure_live()?;
    let (entries, except) = match &request.resource {
        Some(resource) => {
            let found = snapshot.engine.who_can_on(&ctx, &request.permission, resource)?;
            let entries = found
                .entries
                .iter()
                .map(|entry| {
                    Ok(WhoEntry {
                        subject: subject_dto(&entry.subject)?,
                        via: Some(via_dto(&entry.via)?),
                    })
                })
                .collect::<Result<Vec<_>, ApiError>>()?;
            let except = found
                .except
                .iter()
                .map(|pair| {
                    Ok(WhoExcept {
                        allowed: subject_dto(&pair.allowed)?,
                        with: subject_dto(&pair.with)?,
                    })
                })
                .collect::<Result<Vec<_>, ApiError>>()?;
            (entries, except)
        }
        None => {
            let entries = snapshot
                .engine
                .who_can(&ctx, &request.permission)
                .iter()
                .map(|subject| {
                    Ok(WhoEntry {
                        subject: subject_dto(subject)?,
                        via: None,
                    })
                })
                .collect::<Result<Vec<_>, ApiError>>()?;
            (entries, Vec::new())
        }
    };
    Ok(WhoResponse {
        evaluated_at: run.now,
        requested_at: request.at,
        permission: request.permission.clone(),
        entries,
        except,
    })
}

fn access_on(snapshot: &Snapshot, run: &Run, request: &AccessRequest) -> Result<AccessResponse, ApiError> {
    let env = env_at(&request.env, run.now)?;
    let ctx = query_context(snapshot, &env, run);
    run.ensure_live()?;
    let parties = snapshot
        .engine
        .access_of(&ctx, &request.resource)?
        .iter()
        .map(|party| {
            Ok(PartyDto {
                subject: subject_dto(&party.subject)?,
                permissions: party.permissions.iter().cloned().collect(),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(AccessResponse {
        evaluated_at: run.now,
        requested_at: request.at,
        parties,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;
    use crate::clock::ManualClock;
    use crate::source::MemorySource;

    fn state(slots: usize) -> AppState {
        let engine = strig::Engine::builder(
            strig::Catalog::builder()
                .target_kinds(["document"])
                .permission(strig::PermissionDef::new("document.view").targets(["document"]))
                .build()
                .expect("catalog"),
        )
        .build()
        .expect("engine");
        let source = MemorySource::new(Snapshot::new(Arc::new(engine), Vec::new()));
        AppState::new(
            Arc::new(source),
            Arc::new(ManualClock::new(1)),
            ServerConfig::default().with_max_concurrent_work(slots),
        )
    }

    fn done<T>(rx: &mpsc::Receiver<T>) -> T {
        rx.recv_timeout(Duration::from_secs(10))
            .expect("the blocking job ended")
    }

    // These two run on the real clock: tokio does not advance a paused clock while a blocking
    // job is in flight, so the deadline would never fire and the job would never be cancelled.
    #[tokio::test]
    async fn work_nobody_waits_for_stops_at_its_next_check() {
        let state = state(1);
        let (ended_tx, ended) = mpsc::channel();
        let answer = state
            .answer(Deadline::after(Duration::from_millis(50)), move |_, run| {
                // A long job that reads the deadline between its steps, as the batch does.
                while run.ensure_live().is_ok() {
                    std::thread::yield_now();
                }
                ended_tx.send(()).expect("the test is listening");
                Ok::<_, ApiError>(0_u8)
            })
            .await;
        assert_eq!(answer.err(), Some(ApiError::new(ErrorCode::DeadlineExceeded)));
        done(&ended);
        // the slot comes back when the job ends, not when the request does
        tokio::task::spawn_blocking(|| ()).await.expect("pool alive");
        assert!(state.workers.try_acquire().is_ok(), "the slot is free again");
    }

    #[tokio::test]
    async fn an_expired_request_keeps_its_slot_until_the_work_ends_and_others_get_overloaded() {
        let state = state(1);
        let (release, held) = mpsc::channel::<()>();
        let (ended_tx, ended) = mpsc::channel();
        // Ignores the deadline on purpose: the worst case the slot has to contain.
        let first = state
            .answer(Deadline::after(Duration::from_millis(50)), move |_, _| {
                held.recv().expect("released by the test");
                ended_tx.send(()).expect("the test is listening");
                Ok::<_, ApiError>(0_u8)
            })
            .await;
        assert_eq!(first.err(), Some(ApiError::new(ErrorCode::DeadlineExceeded)));

        let second = state
            .answer(Deadline::after(Duration::from_millis(50)), |_, _| {
                Ok::<_, ApiError>(0_u8)
            })
            .await;
        assert_eq!(
            second.err(),
            Some(ApiError::new(ErrorCode::Overloaded)),
            "the abandoned job still owns the only slot"
        );

        release.send(()).expect("the job waits for it");
        done(&ended);
        // the job has sent its last message; wait for the slot to be handed back
        let third = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match state
                    .answer(Deadline::after(Duration::from_millis(50)), |_, _| {
                        Ok::<_, ApiError>(7_u8)
                    })
                    .await
                {
                    Err(error) if error.code == ErrorCode::Overloaded => {
                        tokio::task::yield_now().await;
                    }
                    other => break other,
                }
            }
        })
        .await
        .expect("the slot came back");
        assert_eq!(third.ok().map(|Json(n)| n), Some(7));
    }
}
