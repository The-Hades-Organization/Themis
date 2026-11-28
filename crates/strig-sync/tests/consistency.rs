//! Read your own writes: a decision that requires a revision never answers from older state.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use strig::{
    Attributes, Catalog, Engine, Governance, Grant, MemoryRevisions, Mutation, PermissionDef, Resource, Revision,
    RevisionSource, Subject, SubjectMatcher, TargetSelector,
};
use strig_sync::SessionStream;
use strig_sync::{
    BoxError, CapabilityCache, CapabilityProvider, Change, ClientMessage, ConsistencyError, ConsistencyOptions,
    EngineProvider, GrantLoader, Hub, MemoryTransport, ServerMessage, Session, SessionOptions,
};
use tokio_stream::StreamExt;

async fn next(stream: &mut SessionStream) -> ServerMessage {
    tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap()
}

fn engine() -> Arc<Engine> {
    let catalog = Catalog::builder()
        .target_kinds(["project"])
        .broad_target("org")
        .permission(PermissionDef::new("project.view").targets(["project"]))
        .build()
        .unwrap();
    Arc::new(Engine::builder(catalog).build().unwrap())
}

fn view_grant() -> Grant {
    Grant::allow(
        "g1",
        SubjectMatcher::Any,
        "project.view",
        TargetSelector::kind("project"),
    )
}

#[derive(Clone)]
struct Handle(Arc<Db>);

impl std::ops::Deref for Handle {
    type Target = Db;
    fn deref(&self) -> &Db {
        &self.0
    }
}

/// A database the writer and the readers share, where a reader can see the data lagging behind.
struct Db {
    scope: String,
    state: Mutex<(Vec<Grant>, u64)>,
    tracked: bool,
}

impl Db {
    fn handle(scope: &str) -> Handle {
        Handle(Arc::new(Self {
            scope: scope.into(),
            state: Mutex::new((Vec::new(), 1)),
            tracked: true,
        }))
    }

    fn write(&self, grants: Vec<Grant>, revision: &Revision) {
        *self.state.lock().unwrap() = (grants, revision.value());
    }
}

#[async_trait]
impl GrantLoader for Handle {
    async fn load(&self, _: &Subject, _: &Resource) -> Result<Vec<Grant>, BoxError> {
        Ok(self.state.lock().unwrap().0.clone())
    }

    async fn revision(&self) -> Result<Option<Revision>, BoxError> {
        Ok(self
            .tracked
            .then(|| Revision::new(self.scope.clone(), self.state.lock().unwrap().1)))
    }
}

fn alice() -> Subject {
    Subject::user("alice")
}

fn project() -> Resource {
    Resource::new("project", "p1")
}

fn instance(db: &Handle) -> (Arc<CapabilityCache>, EngineProvider<Handle>) {
    let cache = Arc::new(CapabilityCache::new(Duration::from_secs(60), 100));
    let provider = EngineProvider::new(engine(), db.clone()).with_cache(cache.clone());
    (cache, provider)
}

#[tokio::test]
async fn a_write_is_read_by_another_instance_that_holds_older_state() {
    let db = Db::handle("tenant");
    let transport = MemoryTransport::default();
    let writer = Hub::builder().origin("a").transport(transport.clone()).build();
    let reader = Hub::builder().origin("b").transport(transport).build();
    let (cache, provider) = instance(&db);
    reader.on_change(cache.clone());
    let _relay = reader.spawn_relay();

    let before = provider.evaluate_revised(&alice(), &project(), None).await.unwrap();
    assert!(before.value.set.grants.is_empty());
    assert_eq!(before.revision, Some(Revision::new("tenant", 1)));

    let revisions = MemoryRevisions::starting_at("tenant", 1);
    let governance = Governance::new().with_revisions(Arc::new(revisions));
    let written = governance
        .apply_revised(
            &engine(),
            &Subject::user("admin"),
            &[],
            &Mutation::Add(view_grant()),
            None,
            &Attributes::new(),
        )
        .unwrap();
    let revision = written.revision.expect("the governance has a source");
    assert_eq!(revision, Revision::new("tenant", 2));
    db.write(written.value, &revision);

    // The notice has not reached the reader yet: the cached entry is at revision 1 and does not
    // count, so the decision reloads instead of answering from it.
    let after = provider
        .evaluate_revised(&alice(), &project(), Some(&revision))
        .await
        .unwrap();
    assert_eq!(after.value.set.grants.len(), 1);
    assert_eq!(after.revision, Some(revision.clone()));

    // And the notice itself carries the token across the transport.
    let mut seen = reader.subscribe();
    // Lets the relay open its subscription: the memory transport only delivers to open ones.
    tokio::time::sleep(Duration::from_millis(50)).await;
    writer
        .publish(Change::grants(strig::Anchor::global()).with_revision(revision.clone()))
        .await
        .unwrap();
    let change = tokio::time::timeout(Duration::from_secs(1), seen.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(change.revision, Some(revision));
}

#[tokio::test]
async fn an_instance_behind_catches_up_within_the_timeout() {
    let db = Db::handle("tenant");
    let (_, provider) = instance(&db);
    let provider = provider.with_consistency(
        ConsistencyOptions::default()
            .timeout(Duration::from_secs(2))
            .poll(Duration::from_millis(5)),
    );
    let lagging = db.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(60)).await;
        lagging.write(vec![view_grant()], &Revision::new("tenant", 5));
    });
    let answer = provider
        .evaluate_revised(&alice(), &project(), Some(&Revision::new("tenant", 5)))
        .await
        .unwrap();
    assert_eq!(answer.value.set.grants.len(), 1);
    assert_eq!(provider.known_revision(), Some(Revision::new("tenant", 5)));
}

#[tokio::test]
async fn an_instance_that_cannot_catch_up_denies_with_its_own_reason() {
    let db = Db::handle("tenant");
    let (_, provider) = instance(&db);
    let provider = provider.with_consistency(
        ConsistencyOptions::default()
            .timeout(Duration::from_millis(40))
            .poll(Duration::from_millis(5)),
    );
    let error = provider
        .evaluate_revised(&alice(), &project(), Some(&Revision::new("tenant", 9)))
        .await
        .unwrap_err();
    assert!(matches!(&error, ConsistencyError::NotReached { have, .. } if have.value() == 1));
    assert_eq!(error.code(), "revision_not_reached");
}

#[tokio::test]
async fn a_token_of_another_scope_is_never_compared() {
    let db = Db::handle("tenant-a");
    let (_, provider) = instance(&db);
    let error = provider
        .evaluate_revised(&alice(), &project(), Some(&Revision::new("tenant-b", 1)))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "revision_scope_mismatch");
}

#[tokio::test]
async fn a_loader_that_does_not_number_its_writes_cannot_prove_a_revision() {
    let db = Handle(Arc::new(Db {
        scope: "t".into(),
        state: Mutex::new((vec![view_grant()], 0)),
        tracked: false,
    }));
    let (_, provider) = instance(&db);
    let required = Revision::new("t", 1);
    let error = provider
        .evaluate_revised(&alice(), &project(), Some(&required))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "revision_untracked");
    // Without a requirement the answer is the one it always was.
    assert_eq!(
        provider
            .evaluate_revised(&alice(), &project(), None)
            .await
            .unwrap()
            .revision,
        None
    );
}

#[tokio::test]
async fn a_provider_that_knows_no_revision_refuses_a_requirement() {
    struct Plain;
    #[async_trait]
    impl CapabilityProvider for Plain {
        async fn capabilities(&self, subject: &Subject, scope: &Resource) -> Result<strig::CapabilitySet, BoxError> {
            Ok(engine().capabilities(&strig::Context::new(&Vec::<Grant>::new()), subject, scope))
        }
    }
    let error = Plain
        .evaluate_revised(&alice(), &project(), Some(&Revision::new("t", 1)))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "revision_untracked");
}

#[tokio::test]
async fn a_cached_entry_at_the_revision_is_served_without_reloading() {
    let db = Db::handle("tenant");
    db.write(vec![view_grant()], &Revision::new("tenant", 3));
    let (cache, provider) = instance(&db);
    provider.evaluate_revised(&alice(), &project(), None).await.unwrap();
    assert!(
        cache
            .get_at_least(&alice(), &project(), &Revision::new("tenant", 3))
            .is_some()
    );
    assert!(
        cache
            .get_at_least(&alice(), &project(), &Revision::new("tenant", 4))
            .is_none()
    );
    assert!(
        cache
            .get_at_least(&alice(), &project(), &Revision::new("other", 1))
            .is_none()
    );
}

#[tokio::test]
async fn a_session_sends_the_revision_and_refuses_to_send_an_older_set() {
    let db = Db::handle("tenant");
    db.write(vec![view_grant()], &Revision::new("tenant", 3));
    let provider: Arc<dyn CapabilityProvider> = Arc::new(
        EngineProvider::new(engine(), db.clone()).with_consistency(
            ConsistencyOptions::default()
                .timeout(Duration::from_millis(30))
                .poll(Duration::from_millis(5)),
        ),
    );
    let (control, mut stream) = Session::open(
        &Hub::new(),
        alice(),
        vec![project()],
        Some(provider),
        SessionOptions {
            heartbeat: None,
            ..SessionOptions::default()
        },
    );
    assert!(matches!(
        next(&mut stream).await,
        ServerMessage::Hello { version: 2, .. }
    ));
    match next(&mut stream).await {
        ServerMessage::Capabilities { revision, .. } => assert_eq!(revision, Some(Revision::new("tenant", 3))),
        other => panic!("{other:?}"),
    }

    assert!(
        control
            .send(ClientMessage::RefreshAtLeast {
                revision: Revision::new("tenant", 3)
            })
            .await
    );
    assert!(matches!(next(&mut stream).await, ServerMessage::Capabilities { .. }));

    assert!(
        control
            .send(ClientMessage::RefreshAtLeast {
                revision: Revision::new("tenant", 8)
            })
            .await
    );
    match next(&mut stream).await {
        ServerMessage::Error { message } => assert_eq!(message, "revision_not_reached"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn memory_revisions_never_go_back() {
    let source = MemoryRevisions::new("t");
    let first = source.next();
    let second = source.next();
    assert!(second.reaches(&first).is_reached());
    assert!(!first.reaches(&second).is_reached());
}
