//! Governance revisions: an accepted change takes the next revision, a refused one takes none.

use std::sync::Arc;

use strig::{
    Catalog, Engine, Governance, Grant, MemoryRevisions, Mutation, NoEscalation, PermissionDef, Revision,
    RevisionSource, Subject, SubjectMatcher, TargetSelector,
};

fn engine() -> Engine {
    let catalog = Catalog::builder()
        .target_kind("document")
        .permission(PermissionDef::new("document.edit").targets(["document"]))
        .build()
        .expect("catalog");
    Engine::builder(catalog).build().expect("engine")
}

fn grant(id: &str, user: &str) -> Grant {
    Grant::allow(
        id,
        SubjectMatcher::user(user),
        "document.edit",
        TargetSelector::kind("document"),
    )
}

fn tracked(source: &Arc<MemoryRevisions>) -> Governance {
    Governance::new()
        .with(NoEscalation::new())
        .with_revisions(source.clone())
}

#[test]
fn accepted_changes_get_increasing_revisions_of_the_scope() {
    let engine = engine();
    let source = Arc::new(MemoryRevisions::new("tenant-a"));
    let governance = tracked(&source);
    let held = vec![grant("l", "lead")];
    let actor = Subject::user("lead");

    let first = governance
        .apply_revised(
            &engine,
            &actor,
            &held,
            &Mutation::Add(grant("a", "ana")),
            None,
            &Default::default(),
        )
        .expect("accepted");
    let second = governance
        .apply_revised(
            &engine,
            &actor,
            &held,
            &Mutation::Add(grant("b", "bob")),
            None,
            &Default::default(),
        )
        .expect("accepted");

    assert_eq!(first.revision, Some(Revision::new("tenant-a", 1)));
    assert_eq!(second.revision, Some(Revision::new("tenant-a", 2)));
    assert_eq!(source.current(), Revision::new("tenant-a", 2));
}

#[test]
fn a_refused_change_takes_no_revision() {
    let engine = engine();
    let source = Arc::new(MemoryRevisions::new("tenant-a"));
    let governance = tracked(&source);
    let outsider = Subject::user("nobody");

    let refused = governance.apply_revised(
        &engine,
        &outsider,
        &[],
        &Mutation::Add(grant("a", "ana")),
        None,
        &Default::default(),
    );

    assert!(refused.is_err());
    assert_eq!(source.current(), Revision::new("tenant-a", 0));
}

#[test]
fn without_a_source_the_result_has_no_revision() {
    let engine = engine();
    let governance = Governance::new().with(NoEscalation::new());
    let held = vec![grant("l", "lead")];

    let applied = governance
        .apply_revised(
            &engine,
            &Subject::user("lead"),
            &held,
            &Mutation::Add(grant("a", "ana")),
            None,
            &Default::default(),
        )
        .expect("accepted");

    assert_eq!(applied.revision, None);
}
