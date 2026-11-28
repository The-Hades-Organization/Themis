//! Versioned schema of the stores, embedded in the library.

use tokio_postgres::Client;

use crate::query::{PgQueryError, PgTables};
use crate::quote_ident;

/// Highest schema version this build of the library knows.
pub const LATEST_VERSION: u32 = 5;

struct Migration {
    version: u32,
    sql: fn(&PgTables) -> String,
}

const MIGRATIONS: [Migration; LATEST_VERSION as usize] = [
    Migration {
        version: 1,
        sql: |tables| tables.schema_sql(),
    },
    Migration {
        version: 2,
        sql: roles_sql,
    },
    Migration {
        version: 3,
        sql: pending_sql,
    },
    Migration {
        version: 4,
        sql: exclusive_sql,
    },
    Migration {
        version: 5,
        sql: recert_sql,
    },
];

fn roles_sql(tables: &PgTables) -> String {
    let roles = tables.qualified(&tables.roles);
    let index = quote_ident(&format!("{}_role_idx", tables.roles));
    format!(
        "CREATE TABLE IF NOT EXISTS {roles} (\
            subject_kind text NOT NULL, \
            subject_id text NOT NULL, \
            role text NOT NULL, \
            scope_kind text NOT NULL DEFAULT '', \
            scope_id text NOT NULL DEFAULT '', \
            valid_from bigint, \
            valid_until bigint, \
            PRIMARY KEY (subject_kind, subject_id, role, scope_kind, scope_id));\
        CREATE INDEX IF NOT EXISTS {index} ON {roles} (role);"
    )
}

fn pending_sql(tables: &PgTables) -> String {
    let pending = tables.qualified(&tables.pending);
    let due = quote_ident(&format!("{}_due_idx", tables.pending));
    let order = quote_ident(&format!("{}_order_idx", tables.pending));
    format!(
        "CREATE TABLE IF NOT EXISTS {pending} (\
            id text PRIMARY KEY, \
            state text NOT NULL, \
            requested_at bigint NOT NULL, \
            expires_at bigint, \
            data jsonb NOT NULL, \
            CHECK (state = data->'status'->>'state'), \
            CHECK (requested_at = (data->>'requestedAt')::bigint), \
            CHECK (expires_at IS NOT DISTINCT FROM (data->>'expiresAt')::bigint));\
        CREATE INDEX IF NOT EXISTS {order} ON {pending} (requested_at, id);\
        CREATE INDEX IF NOT EXISTS {due} ON {pending} (expires_at) WHERE state = 'pending';"
    )
}

fn exclusive_sql(tables: &PgTables) -> String {
    let exclusive = tables.qualified(&tables.exclusive);
    let due = quote_ident(&format!("{}_due_idx", tables.exclusive));
    format!(
        "CREATE TABLE IF NOT EXISTS {exclusive} (\
            resource_kind text NOT NULL, \
            resource_id text NOT NULL, \
            holder_kind text NOT NULL, \
            holder_id text NOT NULL, \
            priority bigint NOT NULL, \
            acquired_at bigint NOT NULL, \
            expires_at bigint NOT NULL, \
            PRIMARY KEY (resource_kind, resource_id));\
        CREATE INDEX IF NOT EXISTS {due} ON {exclusive} (expires_at);"
    )
}

fn recert_sql(tables: &PgTables) -> String {
    let recert = tables.qualified(&tables.recert);
    let order = quote_ident(&format!("{}_order_idx", tables.recert));
    format!(
        "CREATE TABLE IF NOT EXISTS {recert} (\
            id text PRIMARY KEY, \
            state text NOT NULL, \
            opened_at bigint NOT NULL, \
            revision bigint NOT NULL, \
            data jsonb NOT NULL, \
            CHECK (state = data->'status'->>'state'), \
            CHECK (opened_at = (data->>'openedAt')::bigint), \
            CHECK (revision = (data->>'revision')::bigint));\
        CREATE INDEX IF NOT EXISTS {order} ON {recert} (opened_at, id);"
    )
}

/// Applies the pending migrations with the default table names. See [`migrate_with`].
///
/// # Errors
///
/// [`PgQueryError::Database`] when a statement fails; the failed migration is rolled back.
pub async fn migrate(client: &Client) -> Result<Vec<u32>, PgQueryError> {
    migrate_with(client, &PgTables::default()).await
}

/// Brings the schema up to [`LATEST_VERSION`] and returns the versions it applied.
///
/// Idempotent and additive: every migration is `CREATE ... IF NOT EXISTS`, none drops or rewrites
/// data. The versions applied are recorded in `<prefix>_migrations`, and the run happens in one
/// transaction under an advisory lock, so two instances booting together do not race. A database
/// already at a newer version than this build knows is left alone.
///
/// # Errors
///
/// [`PgQueryError::Database`] when a statement fails; the transaction is rolled back.
pub async fn migrate_with(client: &Client, tables: &PgTables) -> Result<Vec<u32>, PgQueryError> {
    client.batch_execute("BEGIN").await?;
    match run(client, tables).await {
        Ok(applied) => {
            client.batch_execute("COMMIT").await?;
            Ok(applied)
        }
        Err(error) => {
            let _ = client.batch_execute("ROLLBACK").await;
            Err(error)
        }
    }
}

async fn run(client: &Client, tables: &PgTables) -> Result<Vec<u32>, PgQueryError> {
    if let Some(schema) = &tables.schema {
        client
            .batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {}", quote_ident(schema)))
            .await?;
    }
    let ledger = tables.qualified(&tables.migrations);
    client
        .execute(
            "SELECT pg_advisory_xact_lock(hashtext($1))",
            &[&format!("strig-migrate:{ledger}")],
        )
        .await?;
    client
        .batch_execute(&format!(
            "CREATE TABLE IF NOT EXISTS {ledger} (\
                version integer PRIMARY KEY, \
                applied_at timestamptz NOT NULL DEFAULT now())"
        ))
        .await?;
    let done: Vec<i32> = client
        .query(&format!("SELECT version FROM {ledger}"), &[])
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect();
    let mut applied = Vec::new();
    for migration in &MIGRATIONS {
        let version = i32::try_from(migration.version).expect("version fits i32");
        if done.contains(&version) {
            continue;
        }
        client.batch_execute(&(migration.sql)(tables)).await?;
        client
            .execute(&format!("INSERT INTO {ledger} (version) VALUES ($1)"), &[&version])
            .await?;
        applied.push(migration.version);
    }
    Ok(applied)
}

/// Highest version recorded, or `None` before the first [`migrate`].
///
/// # Errors
///
/// [`PgQueryError::Database`] when the query fails. A missing ledger table is `None`.
pub async fn schema_version(client: &Client, tables: &PgTables) -> Result<Option<u32>, PgQueryError> {
    let ledger = tables.qualified(&tables.migrations);
    let exists = client
        .query_one("SELECT to_regclass($1) IS NOT NULL", &[&ledger])
        .await?
        .get::<_, bool>(0);
    if !exists {
        return Ok(None);
    }
    let version: Option<i32> = client
        .query_one(&format!("SELECT max(version) FROM {ledger}"), &[])
        .await?
        .get(0);
    Ok(version.map(|v| u32::try_from(v).unwrap_or(0)))
}
