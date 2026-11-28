//! Needs a Postgres in `STRIG_PG_URL` (e.g. `postgres://postgres:pw@127.0.0.1:5432/postgres`); without
//! the variable every test skips. Each test works in a schema of its own.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use strig::{
    Anchor, ApprovalPolicy, Approvals, Attributes, Campaign, Catalog, CatalogConformance, Context, Engine, Governance,
    Grant, GrantIndex, GrantSource, Mutation, MutationKind, ObjectRef, PendingError, PendingRequest, PendingStatus,
    PendingStore, PermissionDef, Proposed, RecertError, RecertStore, Request, RequirePermission, Resource, Review,
    RoleAssignment, Subject, SubjectMatcher, TargetSelector, Tuple, TupleIndex, TupleStore, TupleSubject,
};
use strig_postgres::{
    LATEST_VERSION, PgPendingStore, PgRecertStore, PgStore, PgTables, PgTransport, connect, migrate_with,
    schema_version,
};
use strig_sync::Hub;
use tokio_postgres::Client;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Db {
    url: String,
    tables: PgTables,
    client: Client,
    schema: String,
}

impl Db {
    async fn new() -> Option<Self> {
        let Ok(url) = std::env::var("STRIG_PG_URL") else {
            eprintln!("STRIG_PG_URL absent: test skipped");
            return None;
        };
        let schema = format!(
            "strig_t{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let tables = PgTables::default().in_schema(&schema).unwrap();
        let client = connect(&url).await.unwrap();
        migrate_with(&client, &tables).await.unwrap();
        Some(Self {
            url,
            tables,
            client,
            schema,
        })
    }

    async fn drop_schema(self) {
        self.client
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema))
            .await
            .unwrap();
    }
}

fn catalog() -> Catalog {
    Catalog::builder()
        .target_kinds(["project"])
        .broad_target("org")
        .permission(PermissionDef::new("project.view").targets(["project"]))
        .permission(PermissionDef::new("project.edit").targets(["project"]))
        .permission(PermissionDef::new("org.manage").targets(["org"]))
        .permission(
            PermissionDef::new("org.roles.edit")
                .targets(["org"])
                .implied_by(["org.manage"]),
        )
        .build()
        .unwrap()
}

fn engine() -> Engine {
    Engine::builder(catalog()).build().unwrap()
}

fn org() -> Anchor {
    Anchor::new("org", "o1")
}

fn project() -> Resource {
    Resource::new("project", "p1").within("org", "o1")
}

fn role_grant(id: &str, role: &str, key: &str) -> Grant {
    Grant::allow(id, SubjectMatcher::role(role), key, TargetSelector::exact("org", "o1")).scoped(org())
}

fn can(source: &dyn GrantSource, subject: &Subject, key: &str) -> bool {
    engine().check(&Context::new(source), &Request::new(subject, key, &project()))
}

#[tokio::test]
async fn migrate_is_idempotent_versioned_and_never_destructive() {
    let Some(db) = Db::new().await else { return };
    assert_eq!(
        schema_version(&db.client, &db.tables).await.unwrap(),
        Some(LATEST_VERSION)
    );
    db.tables
        .put_grant(&db.client, &role_grant("g1", "member", "project.view"))
        .await
        .unwrap();
    assert!(migrate_with(&db.client, &db.tables).await.unwrap().is_empty());
    assert_eq!(db.tables.all_grants(&db.client).await.unwrap().len(), 1);

    let other = PgTables::default()
        .in_schema(&db.schema)
        .unwrap()
        .with_prefix("alt")
        .unwrap();
    assert_eq!(migrate_with(&db.client, &other).await.unwrap(), vec![1, 2, 3, 4, 5]);
    assert!(other.all_grants(&db.client).await.unwrap().is_empty());
    assert!(PgTables::default().in_schema("bad\"schema").is_err());
    db.drop_schema().await;
}

#[tokio::test]
async fn grant_snapshot_serves_the_engine_and_the_index_and_reloads() {
    let Some(db) = Db::new().await else { return };
    let t = &db.tables;
    t.put_grant(&db.client, &role_grant("b", "member", "project.view"))
        .await
        .unwrap();
    t.put_grant(&db.client, &role_grant("a", "member", "project.edit"))
        .await
        .unwrap();
    let store = PgStore::load(&db.client, t.clone()).await.unwrap();
    let grants = store.grants();
    let member = Subject::user("u1").with_role_in("member", org());
    assert!(can(&grants, &member, "project.view"));
    assert!(!can(&grants, &member, "org.manage"));

    let mut ids = Vec::new();
    grants.visit_by_permission(&["project.view", "project.edit"], &mut |g| ids.push(g.id.clone()));
    assert_eq!(ids, ["a", "b"]);
    let mut by_kind = 0;
    grants.visit_by_target_kind("org", &mut |_| by_kind += 1);
    assert_eq!(by_kind, 2);
    let mut by_role = Vec::new();
    grants.visit_by_subject(&SubjectMatcher::role("member"), &mut |g| by_role.push(g.id.clone()));
    assert_eq!(by_role, ["a", "b"]);

    t.delete_grant(&db.client, "b").await.unwrap();
    assert!(
        can(&grants, &member, "project.view"),
        "the snapshot holds until reloaded"
    );
    store.reload(&db.client).await.unwrap();
    assert!(!can(&grants, &member, "project.view"));
    assert!(!store.is_stale());
    db.drop_schema().await;
}

#[tokio::test]
async fn tuple_snapshot_serves_the_store_and_the_index() {
    let Some(db) = Db::new().await else { return };
    let t = &db.tables;
    let doc = ObjectRef::new("document", "d1");
    let group = ObjectRef::new("group", "g1");
    t.put_tuple(
        &db.client,
        &Tuple::new(doc.clone(), "viewer", ObjectRef::new("user", "alice")),
    )
    .await
    .unwrap();
    t.put_tuple(
        &db.client,
        &Tuple::userset(doc.clone(), "viewer", group.clone(), "member"),
    )
    .await
    .unwrap();
    t.put_tuple(
        &db.client,
        &Tuple::new(ObjectRef::new("document", "d2"), "owner", ObjectRef::new("user", "bob")),
    )
    .await
    .unwrap();
    let store = PgStore::load(&db.client, t.clone()).await.unwrap();
    let tuples = store.tuples();

    let mut viewers = Vec::new();
    tuples.visit(&doc, "viewer", &mut |s| viewers.push(s.clone()));
    assert_eq!(viewers.len(), 2);
    assert!(viewers.contains(&TupleSubject::Userset(group, "member".into())));
    let mut objects = Vec::new();
    tuples.visit_objects("document", &mut |o| objects.push(o.id.clone()));
    assert_eq!(objects, ["d1", "d2"]);
    let mut written = Vec::new();
    tuples.visit_subjects(&doc, &mut |relation, _| written.push(relation.to_string()));
    assert_eq!(written, ["viewer", "viewer"]);

    let alice = Tuple::new(doc.clone(), "viewer", ObjectRef::new("user", "alice"));
    assert!(t.delete_tuple(&db.client, &alice).await.unwrap());
    assert!(!t.delete_tuple(&db.client, &alice).await.unwrap());
    store.reload_tuples(&db.client).await.unwrap();
    let mut left = 0;
    tuples.visit(&doc, "viewer", &mut |_| left += 1);
    assert_eq!(left, 1);
    db.drop_schema().await;
}

#[tokio::test]
async fn roles_are_stored_per_subject_and_build_the_subject() {
    let Some(db) = Db::new().await else { return };
    let t = &db.tables;
    let bob = Subject::user("bob");
    t.assign_role(&db.client, &bob, &RoleAssignment::in_scope("member", org()))
        .await
        .unwrap();
    t.assign_role(&db.client, &bob, &RoleAssignment::new("auditor").valid_between(10, 20))
        .await
        .unwrap();
    t.assign_role(&db.client, &bob, &RoleAssignment::new("auditor").valid_between(10, 30))
        .await
        .unwrap();

    let loaded = t.subject(&db.client, "user", "bob").await.unwrap();
    assert_eq!(loaded.id.as_deref(), Some("bob"));
    assert!(loaded.principals.contains(&"authenticated".to_string()));
    assert_eq!(
        loaded.roles,
        [
            RoleAssignment::new("auditor").valid_between(10, 30),
            RoleAssignment::in_scope("member", org()),
        ]
    );
    let service = t.subject(&db.client, "service", "billing").await.unwrap();
    assert!(service.roles.is_empty() && service.principals.is_empty());

    assert!(
        t.revoke_role(&db.client, &bob, &RoleAssignment::in_scope("member", org()))
            .await
            .unwrap()
    );
    assert!(
        !t.revoke_role(&db.client, &bob, &RoleAssignment::in_scope("member", org()))
            .await
            .unwrap()
    );
    assert!(
        !t.revoke_role(&db.client, &bob, &RoleAssignment::new("member"))
            .await
            .unwrap(),
        "a role in another scope is not the same assignment"
    );

    assert!(
        t.assign_role(&db.client, &Subject::anonymous(), &RoleAssignment::new("x"))
            .await
            .is_err()
    );
    assert!(
        t.assign_role(&db.client, &bob, &RoleAssignment::new("x").valid_between(9, 3))
            .await
            .is_err()
    );
    db.drop_schema().await;
}

fn request(id: &str, requested_at: u64, expires_at: Option<u64>) -> PendingRequest {
    PendingRequest::new(
        id,
        Subject::user("ana"),
        Mutation::Add(role_grant(&format!("g-{id}"), "member", "project.edit")),
        requested_at,
    )
    .expiring_at(expires_at)
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_store_keeps_requests_and_never_decides_one_twice() {
    let Some(db) = Db::new().await else { return };
    let store = PgPendingStore::connect(&db.url, db.tables.clone()).await.unwrap();
    let schema = db.schema.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        store.insert(request("r2", 200, Some(900))).unwrap();
        store.insert(request("r1", 100, None)).unwrap();
        assert_eq!(
            store.insert(request("r1", 100, None)),
            Err(PendingError::Duplicate("r1".into()))
        );
        assert_eq!(store.get("r1").unwrap().unwrap().requested_at, 100);
        assert_eq!(store.get("none").unwrap(), None);
        let ids: Vec<_> = store.list().unwrap().into_iter().map(|r| r.id).collect();
        assert_eq!(ids, ["r1", "r2"]);

        assert!(store.due(899).unwrap().is_empty());
        assert_eq!(store.due(900).unwrap().len(), 1);

        let mut decided = store.get("r2").unwrap().unwrap();
        decided.status = PendingStatus::Approved {
            by: "bob".into(),
            at: 300,
        };
        store.update(decided.clone()).unwrap();
        assert_eq!(store.update(decided), Err(PendingError::NotPending("r2".into())));
        assert_eq!(
            store.update(request("ghost", 1, None)),
            Err(PendingError::Unknown("ghost".into()))
        );
        assert!(
            store.due(10_000).unwrap().is_empty(),
            "a decided request is no longer due"
        );
        schema
    })
    .await
    .unwrap();
    assert_eq!(outcome, db.schema);
    db.drop_schema().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_store_annotates_a_decided_request_without_changing_the_decision() {
    let Some(db) = Db::new().await else { return };
    let store = PgPendingStore::connect(&db.url, db.tables.clone()).await.unwrap();
    tokio::task::spawn_blocking(move || {
        let info = strig::ElevationInfo::new(
            strig::ElevationTarget::permission("project.edit", strig::TargetSelector::exact("project", "p1")),
            1_000,
        );
        store.insert(request("e1", 100, None).with_elevation(info)).unwrap();
        let mut decided = store.get("e1").unwrap().unwrap();
        decided.status = PendingStatus::Approved {
            by: "bob".into(),
            at: 200,
        };
        store.update(decided.clone()).unwrap();

        let mut revoked = decided.clone();
        revoked.elevation.as_mut().unwrap().revoked = Some(strig::Revocation::new("ana", 300, None));
        store.annotate(revoked.clone()).unwrap();
        assert_eq!(store.get("e1").unwrap().unwrap(), revoked);

        let mut flipped = revoked.clone();
        flipped.status = PendingStatus::Rejected {
            by: "eve".into(),
            at: 400,
            reason: "x".into(),
        };
        assert!(matches!(store.annotate(flipped), Err(PendingError::Store(_))));
        assert_eq!(store.get("e1").unwrap().unwrap(), revoked);
        assert_eq!(
            store.annotate(request("ghost", 1, None)),
            Err(PendingError::Unknown("ghost".into()))
        );
    })
    .await
    .unwrap();
    db.drop_schema().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_store_fails_closed_when_the_database_does_not_answer() {
    let Some(db) = Db::new().await else { return };
    let store = PgPendingStore::connect(&db.url, db.tables.clone())
        .await
        .unwrap()
        .with_timeout(Duration::from_millis(400));
    let (mut holder, _) = {
        let c = connect(&db.url).await.unwrap();
        (c, ())
    };
    let lock = holder.transaction().await.unwrap();
    lock.batch_execute(&format!(
        "LOCK TABLE \"{}\".\"strig_pending\" IN ACCESS EXCLUSIVE MODE",
        db.schema
    ))
    .await
    .unwrap();
    let error = tokio::task::spawn_blocking(move || store.get("r1"))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(error, PendingError::Store(_)), "{error:?}");
    lock.rollback().await.unwrap();
    assert!(
        PgPendingStore::connect("postgres://nobody@127.0.0.1:1/none", PgTables::default())
            .await
            .is_err()
    );
    db.drop_schema().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn approvals_run_over_the_postgres_store() {
    let Some(db) = Db::new().await else { return };
    let t = &db.tables;
    t.put_grant(&db.client, &role_grant("admin-manage", "admin", "org.manage"))
        .await
        .unwrap();
    t.assign_role(
        &db.client,
        &Subject::user("ana"),
        &RoleAssignment::in_scope("admin", org()),
    )
    .await
    .unwrap();
    t.assign_role(
        &db.client,
        &Subject::user("bia"),
        &RoleAssignment::in_scope("admin", org()),
    )
    .await
    .unwrap();
    let ana = t.subject(&db.client, "user", "ana").await.unwrap();
    let bia = t.subject(&db.client, "user", "bia").await.unwrap();
    let grants = t.all_grants(&db.client).await.unwrap();
    let store = PgPendingStore::connect(&db.url, t.clone()).await.unwrap();

    let approved = tokio::task::spawn_blocking(move || {
        let (gov, engine) = (
            Governance::new()
                .with(CatalogConformance)
                .with(RequirePermission::new("org.roles.edit", project())),
            engine(),
        );
        let policy = ApprovalPolicy::new().require(MutationKind::Add, "org.manage", project());
        let flow = Approvals::new(&gov, &policy, &store);
        let meta = Attributes::new();
        let review = |now| Review {
            engine: &engine,
            current: &grants,
            tuples: None,
            now,
            meta: &meta,
        };
        let mutation = Mutation::Add(role_grant("m-edit", "member", "project.edit"));
        let Proposed::Pending(pending) = flow
            .propose(&review(1_000), &ana, &mutation, "r1", Some(1_500))
            .unwrap()
        else {
            panic!("the policy asks for approval")
        };
        assert_eq!(store.get("r1").unwrap().unwrap(), pending);
        assert!(
            flow.approve(&review(1_100), &ana, "r1").is_err(),
            "nobody approves their own request"
        );
        let approved = flow.approve(&review(1_100), &bia, "r1").unwrap();
        assert!(matches!(
            store.get("r1").unwrap().unwrap().status,
            PendingStatus::Approved { .. }
        ));

        flow.propose(
            &review(2_000),
            &ana,
            &Mutation::Add(role_grant("m-view", "member", "project.view")),
            "r2",
            Some(2_100),
        )
        .unwrap();
        let expired = flow.expire_due(2_100, &meta).unwrap();
        assert_eq!(expired.len(), 1);
        assert!(matches!(
            store.get("r2").unwrap().unwrap().status,
            PendingStatus::Expired { .. }
        ));
        approved
    })
    .await
    .unwrap();
    assert_eq!(approved.grants.len(), 2);
    db.drop_schema().await;
}

async fn wait_until(mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..60 {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn governance_result_is_written_with_the_notify_and_another_instance_reloads() {
    let Some(mut db) = Db::new().await else { return };
    let t = db.tables.clone();
    let channel = format!("strig_gov_{}", db.schema);
    t.put_grant(&db.client, &role_grant("admin-manage", "admin", "org.manage"))
        .await
        .unwrap();
    t.assign_role(
        &db.client,
        &Subject::user("ana"),
        &RoleAssignment::in_scope("admin", org()),
    )
    .await
    .unwrap();

    let node = |origin: &'static str| {
        let hub = Hub::builder()
            .origin(origin)
            .transport(PgTransport::new(&db.url, channel.clone()).unwrap())
            .build();
        (hub.spawn_relay(), hub)
    };
    let ((_relay_a, _hub_a), (_relay_b, hub_b)) = (node("a"), node("b"));
    let store_b = PgStore::load(&db.client, t.clone()).await.unwrap();
    let url = db.url.clone();
    let _follower = store_b.follow(
        hub_b.subscribe(),
        move || {
            let url = url.clone();
            async move { connect(&url).await }
        },
        Duration::from_millis(100),
    );
    tokio::time::sleep(Duration::from_millis(400)).await;

    let gov = Governance::new()
        .with(CatalogConformance)
        .with(RequirePermission::new("org.roles.edit", project()));
    let member = Subject::user("u1").with_role_in("member", org());
    let b_grants = store_b.grants();
    assert!(!can(&b_grants, &member, "project.edit"));

    let tx = db.client.transaction().await.unwrap();
    t.lock_governance(&tx).await.unwrap();
    let current = t.all_grants(&tx).await.unwrap();
    let ana = t.subject(&tx, "user", "ana").await.unwrap();
    let add = Mutation::Add(role_grant("m-edit", "member", "project.edit"));
    gov.apply(&engine(), &ana, &current, &add, None)
        .expect("governance accepts");
    let sent = t.commit_mutation(&tx, &channel, &add).await.unwrap().expect("a notice");
    assert_eq!(sent.id.as_deref(), Some("m-edit"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !can(&b_grants, &member, "project.edit"),
        "nothing leaves before the commit"
    );
    tx.commit().await.unwrap();
    assert!(
        wait_until(|| can(&b_grants, &member, "project.edit")).await,
        "instance B reloaded"
    );

    let tx = db.client.transaction().await.unwrap();
    let rejected = Mutation::Add(role_grant("bad", "member", "project.nope"));
    let current = t.all_grants(&tx).await.unwrap();
    assert!(gov.apply(&engine(), &ana, &current, &rejected, None).is_err());
    tx.rollback().await.unwrap();
    assert_eq!(
        t.all_grants(&db.client).await.unwrap().len(),
        2,
        "a refused change writes nothing"
    );

    let tx = db.client.transaction().await.unwrap();
    let revoke = Mutation::Remove { id: "m-edit".into() };
    t.commit_mutation(&tx, &channel, &revoke).await.unwrap();
    tx.rollback().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        can(&b_grants, &member, "project.edit"),
        "a rolled back change sends no notice"
    );

    let tx = db.client.transaction().await.unwrap();
    t.commit_mutation(&tx, &channel, &revoke).await.unwrap();
    tx.commit().await.unwrap();
    assert!(
        wait_until(|| !can(&b_grants, &member, "project.edit")).await,
        "the removal reaches B"
    );
    assert!(
        t.commit_mutation(&db.client, &channel, &revoke)
            .await
            .unwrap()
            .is_none(),
        "removing what is not there notifies nothing"
    );

    let assign = Mutation::AssignRole {
        subject: Subject::user("u1"),
        role: RoleAssignment::in_scope("admin", org()),
    };
    let tx = db.client.transaction().await.unwrap();
    let current = t.all_grants(&tx).await.unwrap();
    gov.apply(&engine(), &ana, &current, &assign, None)
        .expect("governance accepts the role");
    t.commit_mutation(&tx, &channel, &assign).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(t.roles_of(&db.client, "user", "u1").await.unwrap().len(), 1);
    assert!(!store_b.is_stale());
    db.drop_schema().await;
}

fn campaign(id: &str, opened_at: u64, revision: u64, closed: bool) -> Campaign {
    let status = if closed {
        serde_json::json!({ "state": "closed", "by": "bia", "at": 900 })
    } else {
        serde_json::json!({ "state": "open" })
    };
    serde_json::from_value(serde_json::json!({
        "id": id,
        "scope": {},
        "reviewer": { "kind": "permission", "permission": "org.manage", "resource": { "path": [] } },
        "reviewerPermission": "org.recertify",
        "reviewerResource": { "path": [] },
        "openedBy": "bia",
        "openedAt": opened_at,
        "dueAt": opened_at + 1_000,
        "keepPeriodMs": 86_400_000,
        "defaultAction": "expire",
        "status": status,
        "items": [],
        "revision": revision,
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn recert_store_keeps_campaigns_and_refuses_stale_and_closed_writes() {
    let Some(db) = Db::new().await else { return };
    let store = PgRecertStore::connect(&db.url, db.tables.clone()).await.unwrap();
    tokio::task::spawn_blocking(move || {
        store.insert(campaign("c2", 200, 0, false)).unwrap();
        store.insert(campaign("c1", 100, 0, false)).unwrap();
        assert_eq!(
            store.insert(campaign("c1", 100, 0, false)),
            Err(RecertError::Duplicate("c1".into()))
        );
        assert_eq!(store.get("c1").unwrap().unwrap().opened_at, 100);
        assert_eq!(store.get("none").unwrap(), None);
        let ids: Vec<_> = store.list().unwrap().into_iter().map(|c| c.id).collect();
        assert_eq!(ids, ["c1", "c2"]);

        store.update(campaign("c1", 100, 1, false)).unwrap();
        assert_eq!(store.get("c1").unwrap().unwrap().revision, 1);
        assert_eq!(
            store.update(campaign("c1", 100, 1, false)),
            Err(RecertError::Stale("c1".into()))
        );
        assert_eq!(
            store.update(campaign("c1", 100, 5, false)),
            Err(RecertError::Stale("c1".into()))
        );
        assert_eq!(
            store.update(campaign("ghost", 1, 1, false)),
            Err(RecertError::Unknown("ghost".into()))
        );

        store.update(campaign("c1", 100, 2, true)).unwrap();
        assert_eq!(
            store.update(campaign("c1", 100, 3, false)),
            Err(RecertError::Closed("c1".into()))
        );
    })
    .await
    .unwrap();
    db.drop_schema().await;
}
