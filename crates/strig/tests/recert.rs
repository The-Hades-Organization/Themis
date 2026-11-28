//! Campanhas de recertificação de acesso (feature `audit`).

mod support;

use std::sync::Arc;

use strig::audit::{AuditAction, AuditLevel, AuditOutcome, Auditor, MemoryAuditLog, verify_chain};
use strig::{
    Attributes, Campaign, CampaignSpec, Catalog, CatalogConformance, DefaultAction, Engine, ExclusiveKind, Governance,
    Grant, ItemState, MemoryRecertStore, MutualExclusion, PermissionDef, RecertDecision, RecertError, RecertScope,
    RecertStore, Recertifications, RequirePermission, Review, ReviewerRoute, ReviewerRule, Subject, SubjectMatcher,
    TargetSelector,
};
use support::*;

const T0: u64 = 10_000;
const DUE: u64 = T0 + 10_000;
const PERIOD: u64 = 86_400_000;

fn admin(id: &str) -> Subject {
    Subject::user(id).with_role_in("admin", org())
}

fn member(id: &str) -> Subject {
    Subject::user(id).with_role_in("member", org())
}

fn grants() -> Vec<Grant> {
    vec![
        role_grant("admin-manage", "admin", "org.manage", true, at_org()),
        Grant::allow(
            "ana-edit",
            SubjectMatcher::user("ana"),
            "project.edit",
            TargetSelector::exact("project", PROJECT),
        )
        .scoped(org()),
        Grant::allow(
            "dan-edit",
            SubjectMatcher::user("dan"),
            "project.edit",
            TargetSelector::exact("project", PROJECT),
        )
        .scoped(org()),
        Grant::deny(
            "carl-no-export",
            SubjectMatcher::user("carl"),
            "document.export",
            TargetSelector::exact("project", PROJECT),
        )
        .scoped(org()),
    ]
}

fn people() -> Vec<Subject> {
    vec![member("ana"), member("carl"), admin("bia"), admin("dan")]
}

fn spec(id: &str) -> CampaignSpec {
    CampaignSpec::new(
        id,
        ReviewerRule::permission("org.manage", project()),
        "org.manage",
        project(),
        DUE,
        PERIOD,
    )
}

struct Scene {
    engine: Engine,
    grants: Vec<Grant>,
    meta: Attributes,
}

impl Scene {
    fn new() -> Self {
        Self {
            engine: engine(),
            grants: grants(),
            meta: Attributes::new(),
        }
    }

    fn review(&self, now: u64) -> Review<'_> {
        Review {
            engine: &self.engine,
            current: &self.grants,
            tuples: None,
            now,
            meta: &self.meta,
        }
    }
}

fn governance() -> Governance {
    Governance::new().with(CatalogConformance)
}

fn audited() -> (Governance, Arc<MemoryAuditLog>) {
    let log = Arc::new(MemoryAuditLog::new());
    let auditor = Auditor::new(AuditLevel::Forensic, log.clone());
    (governance().audited(Arc::new(auditor)), log)
}

fn invariants(error: RecertError) -> Vec<String> {
    match error {
        RecertError::Refused(violations) => violations.into_iter().map(|v| v.invariant).collect(),
        other => panic!("esperava recusa, veio {other:?}"),
    }
}

fn open(scene: &Scene, flow: &Recertifications<'_>, spec: CampaignSpec) -> Campaign {
    flow.open(&scene.review(T0), &admin("opener"), spec, &people()).unwrap()
}

#[test]
fn opening_generates_an_item_per_allow_grant_and_role_assignment() {
    let scene = Scene::new();
    let (gov, store) = (governance(), MemoryRecertStore::new());
    let flow = Recertifications::new(&gov, &store);
    let campaign = open(&scene, &flow, spec("c1"));

    let ids: Vec<&str> = campaign.items.iter().map(|i| i.id.as_str()).collect();
    assert!(ids.contains(&"grant:admin-manage") && ids.contains(&"grant:ana-edit"));
    assert!(ids.iter().any(|id| id.starts_with("role:admin#org:o1@bia")));
    assert!(!ids.contains(&"grant:carl-no-export"), "um deny não confere acesso");
    assert_eq!(campaign.items.len(), 3 + 4);
    assert!(campaign.open_items().count() == campaign.items.len());
    assert_eq!(store.get("c1").unwrap().unwrap(), campaign);
}

#[test]
fn the_scope_narrows_the_items() {
    let scene = Scene::new();
    let (gov, store) = (governance(), MemoryRecertStore::new());
    let flow = Recertifications::new(&gov, &store);

    let grants_only = open(
        &scene,
        &flow,
        spec("g").scoped(RecertScope::new().permissions(["project.edit"])),
    );
    assert_eq!(grants_only.items.len(), 2);

    let roles_only = open(&scene, &flow, spec("r").scoped(RecertScope::new().roles(["admin"])));
    assert_eq!(roles_only.items.len(), 2);

    let kinds = open(
        &scene,
        &flow,
        spec("k").scoped(RecertScope::new().subject_kinds(["role"])),
    );
    assert_eq!(kinds.items.len(), 1, "só o grant cujo matcher é um papel");

    let anchored = open(
        &scene,
        &flow,
        spec("a").scoped(RecertScope::new().anchored(strig::Anchor::new("org", "o1"))),
    );
    assert_eq!(anchored.items.len(), 7);
}

#[test]
fn an_empty_scope_a_past_deadline_and_a_missing_escalation_are_refused() {
    let scene = Scene::new();
    let (gov, store) = (governance(), MemoryRecertStore::new());
    let flow = Recertifications::new(&gov, &store);
    let review = scene.review(T0);

    let nothing = spec("n").scoped(RecertScope::new().permissions(["org.invite"]));
    assert_eq!(
        invariants(flow.open(&review, &admin("o"), nothing, &people()).unwrap_err()),
        ["recert_campaign"]
    );
    let mut late = spec("l");
    late.due_at = T0;
    assert!(flow.open(&review, &admin("o"), late, &people()).is_err());
    let escalating = spec("e").defaulting_to(DefaultAction::Escalate);
    assert!(flow.open(&review, &admin("o"), escalating, &people()).is_err());
    let anonymous = Subject::anonymous();
    assert!(flow.open(&review, &anonymous, spec("x"), &people()).is_err());
    assert!(store.list().unwrap().is_empty());

    open(&scene, &flow, spec("dup"));
    assert!(matches!(
        flow.open(&review, &admin("o"), spec("dup"), &people()),
        Err(RecertError::Duplicate(_))
    ));
}

#[test]
fn keeping_certifies_the_access_for_the_period_and_touches_nothing() {
    let scene = Scene::new();
    let (gov, store) = (governance(), MemoryRecertStore::new());
    let flow = Recertifications::new(&gov, &store);
    open(&scene, &flow, spec("c1"));

    let decided = flow
        .decide(
            &scene.review(T0 + 1),
            &admin("bia"),
            "c1",
            "grant:ana-edit",
            RecertDecision::Keep,
            None,
        )
        .unwrap();
    assert_eq!(decided.grants, scene.grants);
    assert!(matches!(
        decided.item.state,
        ItemState::Kept { until, .. } if until == T0 + 1 + PERIOD
    ));
    assert_eq!(decided.campaign.certified(T0 + 2).count(), 1);
    assert_eq!(decided.campaign.certified(T0 + 1 + PERIOD).count(), 0);

    let again = flow.decide(
        &scene.review(T0 + 2),
        &admin("bia"),
        "c1",
        "grant:ana-edit",
        RecertDecision::Keep,
        None,
    );
    assert_eq!(invariants(again.unwrap_err()), ["recert_state"]);
}

#[test]
fn revoking_a_grant_goes_through_the_governance() {
    let scene = Scene::new();
    let (gov, log) = audited();
    let store = MemoryRecertStore::new();
    let flow = Recertifications::new(&gov, &store);
    open(&scene, &flow, spec("c1"));

    let no_reason = flow.decide(
        &scene.review(T0 + 1),
        &admin("bia"),
        "c1",
        "grant:ana-edit",
        RecertDecision::Revoke,
        None,
    );
    assert_eq!(invariants(no_reason.unwrap_err()), ["recert_reviewer"]);

    let decided = flow
        .decide(
            &scene.review(T0 + 2),
            &admin("bia"),
            "c1",
            "grant:ana-edit",
            RecertDecision::Revoke,
            Some("saiu do projeto"),
        )
        .unwrap();
    assert!(decided.grants.iter().all(|g| g.id != "ana-edit"));
    assert_eq!(decided.grants.len(), scene.grants.len() - 1);
    assert!(matches!(decided.item.state, ItemState::Revoked { ref by, .. } if by == "bia"));

    let actions: Vec<AuditAction> = log.records().iter().map(|r| r.action).collect();
    assert!(actions.contains(&AuditAction::RecertOpen));
    assert!(actions.contains(&AuditAction::RecertDecide));
    assert!(actions.contains(&AuditAction::GrantRemove));
}

#[test]
fn revoking_a_role_returns_the_subject_to_write() {
    let scene = Scene::new();
    let gov = governance();
    let store = MemoryRecertStore::new();
    let flow = Recertifications::new(&gov, &store);
    let campaign = open(&scene, &flow, spec("c1").scoped(RecertScope::new().roles(["member"])));
    let item = campaign
        .items
        .iter()
        .find(|i| i.id.contains("@ana"))
        .unwrap()
        .id
        .clone();

    let decided = flow
        .decide(
            &scene.review(T0 + 1),
            &admin("bia"),
            "c1",
            &item,
            RecertDecision::Revoke,
            Some("mudou de área"),
        )
        .unwrap();
    let subject = decided.revoked_role.expect("sujeito a gravar");
    assert_eq!(subject.id.as_deref(), Some("ana"));
    assert!(subject.roles.is_empty());
}

#[test]
fn the_reviewer_needs_the_declared_permission_and_never_reviews_their_own_access() {
    let scene = Scene::new();
    let (gov, log) = audited();
    let store = MemoryRecertStore::new();
    let flow = Recertifications::new(&gov, &store);
    open(&scene, &flow, spec("c1"));

    let no_permission = flow.decide(
        &scene.review(T0 + 1),
        &member("carl"),
        "c1",
        "grant:ana-edit",
        RecertDecision::Keep,
        None,
    );
    assert!(invariants(no_permission.unwrap_err()).contains(&"recert_reviewer".to_string()));

    let own_grant = flow.decide(
        &scene.review(T0 + 1),
        &admin("dan"),
        "c1",
        "grant:dan-edit",
        RecertDecision::Keep,
        None,
    );
    assert_eq!(invariants(own_grant.unwrap_err()), ["recert_self_review"]);

    let own_role = flow.decide(
        &scene.review(T0 + 1),
        &admin("bia"),
        "c1",
        "grant:admin-manage",
        RecertDecision::Keep,
        None,
    );
    assert_eq!(invariants(own_role.unwrap_err()), ["recert_self_review"]);

    let anonymous = flow.decide(
        &scene.review(T0 + 1),
        &Subject::anonymous(),
        "c1",
        "grant:ana-edit",
        RecertDecision::Keep,
        None,
    );
    assert!(anonymous.is_err());

    let rejected = log
        .records()
        .iter()
        .filter(|r| r.action == AuditAction::RecertDecide && r.outcome == AuditOutcome::Rejected)
        .count();
    assert_eq!(rejected, 4);
    assert!(store.get("c1").unwrap().unwrap().open_items().count() == 7);
}

#[test]
fn only_the_reviewer_the_rule_names_decides_and_a_route_overrides_the_default() {
    let scene = Scene::new();
    let gov = governance();
    let store = MemoryRecertStore::new();
    let flow = Recertifications::new(&gov, &store);
    let campaign = flow
        .open(
            &scene.review(T0),
            &admin("opener"),
            spec("c1")
                .scoped(RecertScope::new().permissions(["project.edit"]))
                .routed(ReviewerRoute::for_permission(
                    "project.edit",
                    ReviewerRule::subject("eve"),
                )),
            &people(),
        )
        .unwrap();
    assert!(
        campaign
            .items
            .iter()
            .all(|i| i.reviewer == ReviewerRule::subject("eve"))
    );

    let wrong = flow.decide(
        &scene.review(T0 + 1),
        &admin("bia"),
        "c1",
        "grant:ana-edit",
        RecertDecision::Keep,
        None,
    );
    assert!(invariants(wrong.unwrap_err()).contains(&"recert_reviewer".to_string()));

    let mut grants = scene.grants.clone();
    grants.push(role_grant("eve-manage", "reviewer", "org.manage", true, at_org()));
    let eve = Subject::user("eve").with_role_in("reviewer", org());
    let review = Review {
        current: &grants,
        ..scene.review(T0 + 1)
    };
    flow.decide(&review, &eve, "c1", "grant:ana-edit", RecertDecision::Keep, None)
        .unwrap();
}

#[test]
fn delegating_hands_the_item_to_someone_who_holds_the_permission() {
    let scene = Scene::new();
    let gov = governance();
    let store = MemoryRecertStore::new();
    let flow = Recertifications::new(&gov, &store);
    open(&scene, &flow, spec("c1"));

    let to_nobody = flow.decide(
        &scene.review(T0 + 1),
        &admin("bia"),
        "c1",
        "grant:ana-edit",
        RecertDecision::Delegate { to: member("carl") },
        Some("é da área dele"),
    );
    assert!(invariants(to_nobody.unwrap_err()).contains(&"recert_delegate".to_string()));

    let to_self = flow.decide(
        &scene.review(T0 + 1),
        &admin("bia"),
        "c1",
        "grant:ana-edit",
        RecertDecision::Delegate { to: admin("bia") },
        Some("eu mesmo"),
    );
    assert!(to_self.is_err());

    let delegated = flow
        .decide(
            &scene.review(T0 + 2),
            &admin("bia"),
            "c1",
            "grant:ana-edit",
            RecertDecision::Delegate { to: admin("fred") },
            Some("é da área dele"),
        )
        .unwrap();
    assert_eq!(delegated.item.assignee.as_deref(), Some("fred"));
    assert!(delegated.item.is_open());
    assert_eq!(delegated.item.delegations.len(), 1);

    let former = flow.decide(
        &scene.review(T0 + 3),
        &admin("bia"),
        "c1",
        "grant:ana-edit",
        RecertDecision::Keep,
        None,
    );
    assert!(invariants(former.unwrap_err()).contains(&"recert_reviewer".to_string()));
    flow.decide(
        &scene.review(T0 + 3),
        &admin("fred"),
        "c1",
        "grant:ana-edit",
        RecertDecision::Keep,
        None,
    )
    .unwrap();

    let report = store.get("c1").unwrap().unwrap().report();
    assert_eq!((report.kept, report.delegated, report.open), (1, 1, 6));
    assert_eq!(report.by_reviewer["fred"].kept, 1);
    assert_eq!(report.by_reviewer["bia"].delegated, 1);
}

#[test]
fn a_reviewer_who_accumulates_conflicting_duties_does_not_review() {
    let catalog = Catalog::builder()
        .target_kinds(["org", "project"])
        .permission(PermissionDef::new("org.manage").targets(["org"]))
        .permission(PermissionDef::new("project.edit").targets(["project"]))
        .mutually_exclusive(MutualExclusion::new(
            "duties",
            ExclusiveKind::Roles,
            ["maker", "checker"],
        ))
        .build()
        .unwrap();
    let engine = Engine::builder(catalog).build().unwrap();
    let grants = vec![role_grant("admin-manage", "admin", "org.manage", true, at_org())];
    let meta = Attributes::new();
    let review = Review {
        engine: &engine,
        current: &grants,
        tuples: None,
        now: T0,
        meta: &meta,
    };
    let (gov, store) = (Governance::new(), MemoryRecertStore::new());
    let flow = Recertifications::new(&gov, &store);
    let subjects = vec![member("ana")];
    flow.open(&review, &admin("opener"), spec("c1"), &subjects).unwrap();

    let mixed = admin("gil").with_role_in("maker", org()).with_role_in("checker", org());
    let refused = flow.decide(
        &Review { now: T0 + 1, ..review },
        &mixed,
        "c1",
        "role:member#org:o1@ana",
        RecertDecision::Keep,
        None,
    );
    assert!(invariants(refused.unwrap_err()).contains(&"recert_reviewer_separation".to_string()));

    let clean = admin("hal").with_role_in("maker", org());
    flow.decide(
        &Review { now: T0 + 1, ..review },
        &clean,
        "c1",
        "role:member#org:o1@ana",
        RecertDecision::Keep,
        None,
    )
    .unwrap();
}

#[test]
fn nobody_decides_after_the_deadline_and_closing_waits_for_it() {
    let scene = Scene::new();
    let gov = governance();
    let store = MemoryRecertStore::new();
    let flow = Recertifications::new(&gov, &store);
    open(&scene, &flow, spec("c1"));

    let late = flow.decide(
        &scene.review(DUE),
        &admin("bia"),
        "c1",
        "grant:ana-edit",
        RecertDecision::Keep,
        None,
    );
    assert!(invariants(late.unwrap_err()).contains(&"recert_overdue".to_string()));
    let early = flow.close(&scene.review(DUE - 1), &admin("opener"), "c1");
    assert_eq!(invariants(early.unwrap_err()), ["recert_not_due"]);
    let stranger = flow.close(&scene.review(DUE), &member("carl"), "c1");
    assert!(stranger.is_err());
}

#[test]
fn closing_expires_what_nobody_reviewed() {
    let scene = Scene::new();
    let (gov, log) = audited();
    let store = MemoryRecertStore::new();
    let flow = Recertifications::new(&gov, &store);
    open(
        &scene,
        &flow,
        spec("c1").scoped(RecertScope::new().permissions(["project.edit"])),
    );
    flow.decide(
        &scene.review(T0 + 1),
        &admin("bia"),
        "c1",
        "grant:ana-edit",
        RecertDecision::Keep,
        None,
    )
    .unwrap();

    let closed = flow.close(&scene.review(DUE), &admin("opener"), "c1").unwrap();
    assert!(closed.grants.iter().all(|g| g.id != "dan-edit"));
    assert!(
        closed.grants.iter().any(|g| g.id == "ana-edit"),
        "o que foi mantido fica"
    );
    assert!(matches!(
        closed.campaign.item("grant:dan-edit").unwrap().state,
        ItemState::Expired { ref by, .. } if by == "opener"
    ));
    assert_eq!(
        (closed.report.kept, closed.report.expired, closed.report.open),
        (1, 1, 0)
    );
    assert!(!closed.campaign.is_open());

    let again = flow.close(&scene.review(DUE + 1), &admin("opener"), "c1");
    assert!(matches!(again, Err(RecertError::Closed(_))));
    let after = flow.decide(
        &scene.review(DUE + 1),
        &admin("bia"),
        "c1",
        "grant:dan-edit",
        RecertDecision::Keep,
        None,
    );
    assert!(matches!(after, Err(RecertError::Closed(_))));

    let records = log.records();
    let actions: Vec<AuditAction> = records.iter().map(|r| r.action).collect();
    assert_eq!(actions.iter().filter(|a| **a == AuditAction::RecertClose).count(), 1);
    assert_eq!(actions.iter().filter(|a| **a == AuditAction::RecertDecide).count(), 2);
    let expire = records
        .iter()
        .find(|r| {
            r.recert
                .as_ref()
                .is_some_and(|c| c.decision.as_deref() == Some("expire"))
        })
        .expect("registro da expiração");
    assert_eq!(expire.recert.as_ref().unwrap().item.as_deref(), Some("grant:dan-edit"));
    assert!(verify_chain(&records).is_ok());
}

#[test]
fn the_other_default_actions_flag_or_escalate() {
    let scene = Scene::new();
    let gov = governance();
    let store = MemoryRecertStore::new();
    let flow = Recertifications::new(&gov, &store);
    let scope = RecertScope::new().permissions(["project.edit"]);
    open(
        &scene,
        &flow,
        spec("f").scoped(scope.clone()).defaulting_to(DefaultAction::Flag),
    );
    let flagged = flow.close(&scene.review(DUE), &admin("opener"), "f").unwrap();
    assert_eq!(flagged.grants, scene.grants);
    assert_eq!(flagged.report.flagged, 2);
    assert_eq!(flagged.report.unresolved.len(), 2);

    open(
        &scene,
        &flow,
        spec("e")
            .scoped(scope)
            .defaulting_to(DefaultAction::Escalate)
            .escalating_to(ReviewerRule::role("security")),
    );
    let escalated = flow.close(&scene.review(DUE), &admin("opener"), "e").unwrap();
    assert_eq!(escalated.grants, scene.grants);
    assert!(matches!(
        escalated.campaign.item("grant:ana-edit").unwrap().state,
        ItemState::Escalated { ref to, .. } if *to == ReviewerRule::role("security")
    ));
}

#[test]
fn an_expiry_the_invariants_refuse_is_flagged_not_silently_kept() {
    let scene = Scene::new();
    let gov = Governance::new().with(RequirePermission::new("org.manage", project()));
    let store = MemoryRecertStore::new();
    let flow = Recertifications::new(&gov, &store);
    flow.open(
        &scene.review(T0),
        &member("carl"),
        spec("c1").scoped(RecertScope::new().permissions(["project.edit"])),
        &people(),
    )
    .unwrap();

    let closed = flow.close(&scene.review(DUE), &member("carl"), "c1").unwrap();
    assert_eq!(closed.grants, scene.grants);
    match &closed.campaign.item("grant:ana-edit").unwrap().state {
        ItemState::Flagged {
            reason: Some(reason), ..
        } => assert!(reason.contains("require_permission")),
        other => panic!("esperava Flagged, veio {other:?}"),
    }
    assert_eq!(closed.report.flagged, 2);
}

#[test]
fn a_failing_audit_sink_denies_the_decision() {
    use strig::audit::{AuditError, AuditRecord, AuditSink, FailMode};

    struct Broken;
    impl AuditSink for Broken {
        fn write(&self, _record: &AuditRecord) -> Result<(), AuditError> {
            Err(AuditError::Sink("fora do ar".into()))
        }
    }

    let scene = Scene::new();
    let working = Governance::new();
    let store = MemoryRecertStore::new();
    Recertifications::new(&working, &store)
        .open(&scene.review(T0), &admin("o"), spec("c1"), &people())
        .unwrap();

    let auditor = Auditor::new(AuditLevel::Standard, Arc::new(Broken));
    let gov = Governance::new().audited(Arc::new(auditor));
    let flow = Recertifications::new(&gov, &store).fail_mode(FailMode::Closed);
    let denied = flow.decide(
        &scene.review(T0 + 1),
        &admin("bia"),
        "c1",
        "grant:ana-edit",
        RecertDecision::Revoke,
        Some("x"),
    );
    assert!(denied.is_err());
    let stored = store.get("c1").unwrap().unwrap();
    assert!(stored.item("grant:ana-edit").unwrap().is_open());
}

#[test]
fn the_store_refuses_a_stale_write_and_a_closed_campaign() {
    let scene = Scene::new();
    let gov = governance();
    let store = MemoryRecertStore::new();
    let flow = Recertifications::new(&gov, &store);
    let campaign = open(&scene, &flow, spec("c1"));

    let mut first = campaign.clone();
    first.revision += 1;
    store.update(first).unwrap();
    let mut stale = campaign.clone();
    stale.revision += 1;
    assert!(matches!(store.update(stale), Err(RecertError::Stale(_))));
    let mut ghost = campaign.clone();
    ghost.id = "nope".into();
    assert!(matches!(store.update(ghost), Err(RecertError::Unknown(_))));

    flow.close(&scene.review(DUE), &admin("opener"), "c1").unwrap();
    let closed = store.get("c1").unwrap().unwrap();
    let mut next = closed;
    next.revision += 1;
    assert!(matches!(store.update(next), Err(RecertError::Closed(_))));
}

#[test]
fn campaigns_survive_json() {
    let scene = Scene::new();
    let gov = governance();
    let store = MemoryRecertStore::new();
    let flow = Recertifications::new(&gov, &store);
    let campaign = open(
        &scene,
        &flow,
        spec("c1")
            .named("Q4")
            .routed(ReviewerRoute::for_role("admin", ReviewerRule::role("ciso"))),
    );
    let json = serde_json::to_string(&campaign).unwrap();
    let back: Campaign = serde_json::from_str(&json).unwrap();
    assert_eq!(back, campaign);
}
