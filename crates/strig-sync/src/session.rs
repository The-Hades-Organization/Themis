//! Session of a connected client, independent of the HTTP framework.
//!
//! [`Session::open`] returns a stream of [`ServerMessage`]s to write to the SSE or the
//! WebSocket, and a [`SessionControl`] to pass on the messages the client sends (WebSocket
//! only). The framework adapter only bridges; the logic lives here.

use std::future::pending;
use std::sync::Arc;
use std::time::Duration;

use strig::{Resource, Subject};
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tokio::sync::{broadcast, mpsc};
use tokio::time::{Instant, Interval, interval_at};
use tokio_stream::wrappers::ReceiverStream;

use crate::change::{Change, ChangeKind};
use crate::consistency::ConsistencyError;
use crate::hub::Hub;
use crate::protocol::{ClientMessage, PROTOCOL_VERSION, ServerMessage};
use crate::provider::CapabilityProvider;
use strig::Revision;

#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// Interval of the `ping`. Keeps proxies and load balancers from closing an idle connection.
    pub heartbeat: Option<Duration>,
    /// Messages queued for a slow client before the session waits for it.
    pub buffer: usize,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            heartbeat: Some(Duration::from_secs(25)),
            buffer: 64,
        }
    }
}

pub type SessionStream = ReceiverStream<ServerMessage>;

/// Channel for the messages the client sends.
#[derive(Clone)]
pub struct SessionControl {
    tx: mpsc::Sender<ClientMessage>,
}

impl SessionControl {
    /// Returns `false` if the session has already ended.
    pub async fn send(&self, message: ClientMessage) -> bool {
        self.tx.send(message).await.is_ok()
    }

    /// Passes on a WebSocket text frame. Invalid JSON comes back as an error and the session continues.
    pub async fn handle_text(&self, text: &str) -> Result<bool, serde_json::Error> {
        Ok(self.send(ClientMessage::from_json(text)?).await)
    }
}

pub struct Session;

impl Session {
    /// Opens the session of `subject` watching `scopes`. Without a `provider`, the client receives only the
    /// change notices and reloads on its own. The session ends when the stream is
    /// dropped.
    pub fn open(
        hub: &Hub,
        subject: Subject,
        scopes: Vec<Resource>,
        provider: Option<Arc<dyn CapabilityProvider>>,
        options: SessionOptions,
    ) -> (SessionControl, SessionStream) {
        let changes = hub.subscribe();
        let (out, stream) = mpsc::channel(options.buffer.max(1));
        let (tx, control) = mpsc::channel(16);
        let heartbeat = options
            .heartbeat
            .map(|period| interval_at(Instant::now() + period, period));
        let worker = Worker {
            id: hub.new_session_id(),
            hub: hub.clone(),
            out,
            subject,
            scopes,
            provider,
            deadline: None,
            #[cfg(feature = "tracing")]
            _open: crate::obs::SessionGuard::open(),
        };
        let run = worker.run(hub.origin().to_string(), changes, control, heartbeat);
        #[cfg(feature = "tracing")]
        let run = tracing::Instrument::instrument(run, tracing::info_span!("strig.sync.session"));
        tokio::spawn(run);
        (SessionControl { tx }, ReceiverStream::new(stream))
    }
}

struct Worker {
    /// Names this session to the hub's expiry scheduler, which cancels notices nobody wants.
    id: u64,
    hub: Hub,
    out: mpsc::Sender<ServerMessage>,
    subject: Subject,
    scopes: Vec<Resource>,
    provider: Option<Arc<dyn CapabilityProvider>>,
    /// Next validity boundary of a subject without an id: nothing narrower than "everyone" can name
    /// it on the hub, so the session waits for it itself instead of waking every session.
    deadline: Option<Instant>,
    #[cfg(feature = "tracing")]
    _open: crate::obs::SessionGuard,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.hub.release_session(self.id);
    }
}

async fn until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => pending().await,
    }
}

async fn tick(heartbeat: &mut Option<Interval>) {
    match heartbeat {
        Some(interval) => {
            interval.tick().await;
        }
        None => pending().await,
    }
}

impl Worker {
    async fn run(
        mut self,
        origin: String,
        mut changes: broadcast::Receiver<Change>,
        mut control: mpsc::Receiver<ClientMessage>,
        mut heartbeat: Option<Interval>,
    ) {
        let hello = ServerMessage::Hello {
            origin,
            subject: self.subject.id.clone(),
            version: PROTOCOL_VERSION,
        };
        if !self.send(hello).await || !self.push_all().await {
            return;
        }
        let mut control_open = true;
        let closed = self.out.clone();
        loop {
            let alive = tokio::select! {
                () = closed.closed() => false,
                () = until(self.deadline) => self.on_own_boundary().await,
                received = changes.recv() => match received {
                    Err(RecvError::Closed) => false,
                    first => self.on_changes(first.ok(), &mut changes).await,
                },
                message = control.recv(), if control_open => match message {
                    None => {
                        control_open = false;
                        true
                    }
                    Some(message) => self.on_client(message).await,
                },
                _ = tick(&mut heartbeat) => self.send(ServerMessage::Ping).await,
            };
            if !alive {
                return;
            }
        }
    }

    async fn send(&self, message: ServerMessage) -> bool {
        self.out.send(message).await.is_ok()
    }

    async fn push(&mut self, scope: &Resource) -> bool {
        self.push_at_least(scope, None).await
    }

    /// Sends the capabilities of `scope`. With `required`, they are computed from data at that
    /// revision or later; when the provider cannot bring them there the client gets an `error` with
    /// the reason code and no set.
    async fn push_at_least(&mut self, scope: &Resource, required: Option<&Revision>) -> bool {
        let Some(provider) = &self.provider else {
            return true;
        };
        let provider = provider.clone();
        let message = match provider.evaluate_revised(&self.subject, scope, required).await {
            Ok(revised) => {
                self.schedule_expiry(provider.as_ref(), revised.value.next_boundary);
                ServerMessage::Capabilities {
                    scope: scope.clone(),
                    set: revised.value.set,
                    revision: revised.revision,
                }
            }
            Err(error) => ServerMessage::Error {
                message: match error {
                    ConsistencyError::Source(source) => source.to_string(),
                    other => other.code().to_owned(),
                },
            },
        };
        self.send(message).await
    }

    /// Arranges a recompute at `next_boundary`, the next moment a grant or role in force for this
    /// subject starts or stops. A subject with an id asks the hub for a notice naming it, which comes
    /// back through the broadcast like any change and reaches that subject's sessions only. A subject
    /// without an id keeps the deadline in this session, so one anonymous session never wakes the
    /// others. The wait counts from the provider's current instant, so a boundary that passed while
    /// the grants were loading fires at once.
    fn schedule_expiry(&mut self, provider: &dyn CapabilityProvider, next_boundary: Option<u64>) {
        let Some(boundary) = next_boundary else {
            return;
        };
        let now = provider.now_ms();
        match self.subject.id.clone() {
            Some(id) => {
                self.hub
                    .schedule_for_session(self.id, boundary, now, Change::expiry(id));
            }
            None => {
                let wait = Duration::from_millis(boundary.saturating_sub(now).max(1));
                let at = Instant::now() + wait;
                self.deadline = Some(self.deadline.map_or(at, |current| current.min(at)));
            }
        }
    }

    /// The boundary a session without an id waited for: tell the client and recompute everything.
    async fn on_own_boundary(&mut self) -> bool {
        self.deadline = None;
        self.send(ServerMessage::Change {
            change: Change::expiry_for_everyone(),
        })
        .await
            && self.push_all().await
    }

    async fn push_all(&mut self) -> bool {
        self.deadline = None;
        for scope in self.scopes.clone() {
            if !self.push(&scope).await {
                return false;
            }
        }
        true
    }

    /// Gathers the changes already queued and recomputes each affected scope only once.
    async fn on_changes(&mut self, first: Option<Change>, changes: &mut broadcast::Receiver<Change>) -> bool {
        let mut batch: Vec<Change> = first.into_iter().collect();
        let mut lost = batch.is_empty();
        loop {
            match changes.try_recv() {
                Ok(change) => batch.push(change),
                Err(TryRecvError::Lagged(_)) => lost = true,
                Err(_) => break,
            }
        }
        if lost || batch.iter().any(|c| c.kind == ChangeKind::Resync) {
            #[cfg(feature = "tracing")]
            crate::obs::resync(if lost { "lagged" } else { "notice" });
            return self.send(ServerMessage::Resync).await && self.push_all().await;
        }
        let subject = self.subject.id.clone();
        let mut affected = vec![false; self.scopes.len()];
        for change in batch {
            let mut relevant = false;
            for (i, scope) in self.scopes.iter().enumerate() {
                if change.affects(subject.as_deref(), scope) {
                    affected[i] = true;
                    relevant = true;
                }
            }
            if relevant && !self.send(ServerMessage::Change { change }).await {
                return false;
            }
        }
        for (i, scope) in self.scopes.clone().iter().enumerate() {
            if affected[i] && !self.push(scope).await {
                return false;
            }
        }
        true
    }

    async fn on_client(&mut self, message: ClientMessage) -> bool {
        match message {
            ClientMessage::Watch { scopes } => {
                for scope in scopes {
                    if self.scopes.contains(&scope) {
                        continue;
                    }
                    self.scopes.push(scope.clone());
                    if !self.push(&scope).await {
                        return false;
                    }
                }
                true
            }
            ClientMessage::Unwatch { scopes } => {
                self.scopes.retain(|s| !scopes.contains(s));
                true
            }
            ClientMessage::Refresh => self.push_all().await,
            ClientMessage::RefreshAtLeast { revision } => {
                for scope in self.scopes.clone() {
                    if !self.push_at_least(&scope, Some(&revision)).await {
                        return false;
                    }
                }
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::EngineProvider;
    use futures_util::StreamExt;
    use strig::{Anchor, Catalog, Engine, Grant, PermissionDef, SubjectMatcher, TargetSelector};

    fn view_catalog() -> Catalog {
        Catalog::builder()
            .target_kinds(["project"])
            .broad_target("org")
            .permission(PermissionDef::new("project.view").targets(["project"]))
            .build()
            .unwrap()
    }

    fn provider(grants: Vec<Grant>) -> Arc<dyn CapabilityProvider> {
        let engine = Arc::new(Engine::builder(view_catalog()).build().unwrap());
        Arc::new(EngineProvider::new(engine, grants))
    }

    async fn next(stream: &mut SessionStream) -> ServerMessage {
        tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("mensagem")
            .expect("stream aberto")
    }

    #[tokio::test]
    async fn pushes_capabilities_then_changes() {
        let hub = Hub::new();
        let grants = vec![Grant::allow(
            "g",
            SubjectMatcher::user("alice"),
            "project.view",
            TargetSelector::kind("project"),
        )];
        let p1 = Resource::new("project", "p1").within("org", "o1");
        let (control, mut stream) = Session::open(
            &hub,
            Subject::user("alice"),
            vec![p1.clone()],
            Some(provider(grants)),
            SessionOptions::default(),
        );
        assert!(matches!(next(&mut stream).await, ServerMessage::Hello { .. }));
        match next(&mut stream).await {
            ServerMessage::Capabilities { scope, set, .. } => {
                assert_eq!(scope, p1);
                assert_eq!(set.grants.len(), 1);
            }
            other => panic!("{other:?}"),
        }

        hub.publish(Change::grants(Anchor::new("org", "o2"))).await.unwrap();
        hub.publish(Change::grants(Anchor::new("org", "o1"))).await.unwrap();
        match next(&mut stream).await {
            ServerMessage::Change { change } => assert_eq!(change.scope, Anchor::new("org", "o1")),
            other => panic!("{other:?}"),
        }
        assert!(matches!(next(&mut stream).await, ServerMessage::Capabilities { .. }));

        let p2 = Resource::new("project", "p2");
        assert!(
            control
                .send(ClientMessage::Watch {
                    scopes: vec![p2.clone()]
                })
                .await
        );
        match next(&mut stream).await {
            ServerMessage::Capabilities { scope, .. } => assert_eq!(scope, p2),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn heartbeat_and_resync() {
        let hub = Hub::new();
        let options = SessionOptions {
            heartbeat: Some(Duration::from_millis(30)),
            buffer: 8,
        };
        let (_control, mut stream) = Session::open(&hub, Subject::anonymous(), Vec::new(), None, options);
        assert!(matches!(next(&mut stream).await, ServerMessage::Hello { .. }));
        assert_eq!(next(&mut stream).await, ServerMessage::Ping);
        hub.publish(Change::resync()).await.unwrap();
        assert_eq!(next(&mut stream).await, ServerMessage::Resync);
    }

    #[tokio::test(start_paused = true)]
    async fn emits_change_and_recomputes_at_the_validity_boundary() {
        const START: u64 = 10_000;
        let started = Instant::now();
        let clock = move || START + started.elapsed().as_millis() as u64;
        let grants = vec![
            Grant::allow(
                "g",
                SubjectMatcher::user("alice"),
                "project.view",
                TargetSelector::kind("project"),
            )
            .valid_until(START + 500),
        ];
        let engine = Arc::new(Engine::builder(view_catalog()).build().unwrap());
        let provider = Arc::new(EngineProvider::new(engine, grants).with_clock(clock));

        let hub = Hub::new();
        let options = SessionOptions {
            heartbeat: None,
            buffer: 8,
        };
        let scope = Resource::new("project", "p1");
        let (_control, mut stream) = Session::open(&hub, Subject::user("alice"), vec![scope], Some(provider), options);

        assert!(matches!(next(&mut stream).await, ServerMessage::Hello { .. }));
        match next(&mut stream).await {
            ServerMessage::Capabilities { set, .. } => assert_eq!(set.grants.len(), 1),
            other => panic!("{other:?}"),
        }
        match next(&mut stream).await {
            ServerMessage::Change { change } => {
                assert_eq!(change.kind, ChangeKind::Grants);
                assert_eq!(change.subject.as_deref(), Some("alice"));
            }
            other => panic!("{other:?}"),
        }
        match next(&mut stream).await {
            ServerMessage::Capabilities { set, .. } => assert!(set.grants.is_empty()),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_grant_that_starts_later_reaches_the_session_at_its_start() {
        const START: u64 = 10_000;
        let started = Instant::now();
        let clock = move || START + started.elapsed().as_millis() as u64;
        let grants = vec![
            Grant::allow(
                "g",
                SubjectMatcher::user("alice"),
                "project.view",
                TargetSelector::kind("project"),
            )
            .valid_from(START + 500),
        ];
        let provider = Arc::new(
            EngineProvider::new(Arc::new(Engine::builder(view_catalog()).build().unwrap()), grants).with_clock(clock),
        );

        let hub = Hub::new();
        let options = SessionOptions {
            heartbeat: None,
            buffer: 8,
        };
        let scope = Resource::new("project", "p1");
        let (_control, mut stream) = Session::open(&hub, Subject::user("alice"), vec![scope], Some(provider), options);

        assert!(matches!(next(&mut stream).await, ServerMessage::Hello { .. }));
        match next(&mut stream).await {
            ServerMessage::Capabilities { set, .. } => assert!(set.grants.is_empty(), "not started yet"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(next(&mut stream).await, ServerMessage::Change { .. }));
        match next(&mut stream).await {
            ServerMessage::Capabilities { set, .. } => assert_eq!(set.grants.len(), 1),
            other => panic!("{other:?}"),
        }
    }

    fn windowed_provider(until: u64, started: Instant) -> Arc<dyn CapabilityProvider> {
        const START: u64 = 10_000;
        let clock = move || START + started.elapsed().as_millis() as u64;
        let grants = vec![
            Grant::allow(
                "g",
                SubjectMatcher::Any,
                "project.view",
                TargetSelector::kind("project"),
            )
            .valid_until(START + until),
        ];
        let engine = Arc::new(Engine::builder(view_catalog()).build().unwrap());
        Arc::new(EngineProvider::new(engine, grants).with_clock(clock))
    }

    fn quiet() -> SessionOptions {
        SessionOptions {
            heartbeat: None,
            buffer: 8,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_anonymous_boundary_does_not_wake_the_other_sessions() {
        let started = Instant::now();
        let hub = Hub::new();
        let scope = Resource::new("project", "p1");
        let (_c1, mut anonymous) = Session::open(
            &hub,
            Subject::anonymous(),
            vec![scope.clone()],
            Some(windowed_provider(500, started)),
            quiet(),
        );
        let (_c2, mut alice) = Session::open(
            &hub,
            Subject::user("alice"),
            vec![scope],
            Some(windowed_provider(10_000, started)),
            quiet(),
        );
        for stream in [&mut anonymous, &mut alice] {
            assert!(matches!(next(stream).await, ServerMessage::Hello { .. }));
            assert!(matches!(next(stream).await, ServerMessage::Capabilities { .. }));
        }

        // The anonymous session's own boundary: it recomputes, nobody else is told.
        assert!(matches!(next(&mut anonymous).await, ServerMessage::Change { .. }));
        match next(&mut anonymous).await {
            ServerMessage::Capabilities { set, .. } => assert!(set.grants.is_empty()),
            other => panic!("{other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), alice.next())
                .await
                .is_err(),
            "another session was woken by an anonymous boundary"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn closing_the_session_cancels_its_pending_notice() {
        let started = Instant::now();
        let hub = Hub::new();
        let (control, mut stream) = Session::open(
            &hub,
            Subject::user("alice"),
            vec![Resource::new("project", "p1")],
            Some(windowed_provider(5_000_000, started)),
            quiet(),
        );
        assert!(matches!(next(&mut stream).await, ServerMessage::Hello { .. }));
        assert!(matches!(next(&mut stream).await, ServerMessage::Capabilities { .. }));
        assert_eq!(hub.pending_expiries(), 1);

        drop(stream);
        drop(control);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(hub.pending_expiries(), 0, "a notice outlived its only session");
    }
}
