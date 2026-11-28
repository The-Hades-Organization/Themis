//! Production persistence in Postgres: grants, ReBAC tuples, role assignments and pending approval
//! requests, with versioned migrations.
//!
//! - [`migrate`] / [`migrate_with`]: the schema, embedded and versioned, safe to run on every boot.
//! - [`PgStore`]: a loaded snapshot of grants and tuples serving the synchronous
//!   [`strig::GrantSource`], [`strig::GrantIndex`], [`strig::TupleStore`] and [`strig::TupleIndex`],
//!   reloaded when a [`strig_sync::Change`] arrives.
//! - [`PgTables`](crate::query::PgTables): the writes (`put_grant`, `delete_grant`, `put_tuple`,
//!   `assign_role`, `commit_mutation`, ...), all generic over a client or a transaction.
//! - [`PgPendingStore`]: a [`strig::PendingStore`] with expiry.
//! - `PgExclusiveStore` (feature `exclusive`): a [`strig::ExclusiveStore`] whose every decision is one
//!   transaction with a row lock, shared by any number of processes.

#[cfg(feature = "exclusive")]
mod exclusive;
mod govern;
mod migrate;
mod pending;
mod recert;
mod roles;
mod snapshot;

#[cfg(feature = "exclusive")]
pub use exclusive::PgExclusiveStore;
pub use migrate::{LATEST_VERSION, migrate, migrate_with, schema_version};
pub use pending::PgPendingStore;
pub use recert::PgRecertStore;
pub use snapshot::{PgGrants, PgStore, PgTuples, connect};
