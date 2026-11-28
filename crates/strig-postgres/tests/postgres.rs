//! Precisa de um Postgres em `STRIG_PG_URL` (ex.: `postgres://postgres:pw@127.0.0.1:5432/postgres`);
//! sem a variável o teste não roda nada.

use std::time::Duration;

use strig::Anchor;
use strig_postgres::{PgTransport, notify};
use strig_sync::{Change, ChangeKind, Hub};

#[tokio::test]
async fn hubs_exchange_changes_and_transactional_notify_reaches_everyone() {
    let Ok(url) = std::env::var("STRIG_PG_URL") else {
        eprintln!("STRIG_PG_URL ausente: teste pulado");
        return;
    };
    let channel = format!("strig_test_{}", std::process::id());
    let a = Hub::builder()
        .origin("a")
        .transport(PgTransport::new(&url, channel.clone()).unwrap())
        .build();
    let b = Hub::builder()
        .origin("b")
        .transport(PgTransport::new(&url, channel.clone()).unwrap())
        .build();
    let _ra = a.spawn_relay();
    let _rb = b.spawn_relay();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut at_a = a.subscribe();
    let mut at_b = b.subscribe();
    a.publish(Change::grants(Anchor::new("org", "o1"))).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), at_b.recv())
        .await
        .expect("mudança chega pelo Postgres")
        .unwrap();
    assert_eq!(got.origin, "a");
    assert_eq!(at_a.recv().await.unwrap().origin, "a");

    let (mut client, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(conn);
    let tx = client.transaction().await.unwrap();
    notify(&tx, &channel, &Change::tuples(Anchor::new("project", "p1")))
        .await
        .unwrap();
    let early = tokio::time::timeout(Duration::from_millis(300), at_b.recv()).await;
    assert!(early.is_err(), "NOTIFY não pode sair antes do commit");
    tx.commit().await.unwrap();

    for rx in [&mut at_a, &mut at_b] {
        let got = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("aviso transacional chega a todos")
            .unwrap();
        assert_eq!(got.kind, ChangeKind::Tuples);
    }
}

#[tokio::test]
async fn sequence_revisions_grow_and_roll_back_leaves_a_gap() {
    let Ok(url) = std::env::var("STRIG_PG_URL") else {
        eprintln!("STRIG_PG_URL ausente: teste pulado");
        return;
    };
    let (mut client, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(conn);
    let sequence = format!("strig_rev_test_{}", std::process::id());
    client
        .batch_execute(&format!("CREATE SEQUENCE {sequence}"))
        .await
        .unwrap();

    let none = strig_postgres::current_revision(&client, &sequence, "tenant")
        .await
        .unwrap();
    assert_eq!(none, strig::Revision::new("tenant", 0));
    let first = strig_postgres::next_revision(&client, &sequence, "tenant")
        .await
        .unwrap();
    assert_eq!(first, strig::Revision::new("tenant", 1));

    let tx = client.transaction().await.unwrap();
    strig_postgres::next_revision(&tx, &sequence, "tenant").await.unwrap();
    tx.rollback().await.unwrap();

    let after = strig_postgres::next_revision(&client, &sequence, "tenant")
        .await
        .unwrap();
    assert!(
        after.value() > 2,
        "the rolled-back revision leaves a gap, never repeats"
    );
    let current = strig_postgres::current_revision(&client, &sequence, "tenant")
        .await
        .unwrap();
    assert_eq!(current, after);
    assert!(
        strig_postgres::next_revision(&client, "no_such_sequence", "tenant")
            .await
            .is_err()
    );
    client
        .batch_execute(&format!("DROP SEQUENCE {sequence}"))
        .await
        .unwrap();
}
