//! Postgres `LISTEN/NOTIFY` transport for the [`strig_sync::Hub`], and Postgres storage for grants,
//! tuples, roles and pending requests (see [`PgStore`], [`PgPendingStore`] and [`migrate`]).
//!
//! See the [repository README](https://github.com/The-Hades-Organization/Strig) for the full guide.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use strig_sync::Hub;
//! use strig_postgres::PgTransport;
//!
//! let hub = Hub::builder()
//!     .transport(PgTransport::new("postgres://app@localhost/app", "strig_changes")?)
//!     .build();
//! let _relay = hub.spawn_relay();
//! # Ok(()) }
//! ```
//!
//! # Notifying in the same transaction as the change
//!
//! `NOTIFY` is delivered only on commit. Writing the grant and calling [`notify`] in the same
//! transaction guarantees that the notice goes out if, and only if, the change was written. A notice
//! sent this way does not go through [`strig_sync::Hub::publish`] and arrives without an origin, so
//! the relay delivers it on every instance, including the one that wrote it.
//!
//! TLS: [`PgTransport::with_tls`] accepts any `tokio-postgres` connector
//! (`postgres-native-tls`, `tokio-postgres-rustls`).

pub mod query;
mod store;
mod window;

pub use query::PgTables;
#[cfg(feature = "exclusive")]
pub use store::PgExclusiveStore;
pub use store::{
    LATEST_VERSION, PgGrants, PgPendingStore, PgStore, PgTuples, connect, migrate, migrate_with, schema_version,
};

pub use window::{InstantOutOfRange, WindowColumns, WindowPredicate, candidate_predicate, window_predicate};

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::{StreamExt, stream};
use strig::Revision;
use strig_sync::{Change, ChangeStream, Transport, TransportError};
use tokio::sync::{Mutex, mpsc};
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::{AsyncMessage, Client, Config, GenericClient, NoTls, Socket};
use tokio_stream::wrappers::UnboundedReceiverStream;

type Notifications = mpsc::UnboundedReceiver<Result<String, TransportError>>;
type Connect = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<(Client, Notifications), TransportError>> + Send>> + Send + Sync,
>;

fn connection(error: tokio_postgres::Error) -> TransportError {
    TransportError::Connection(error.to_string())
}

/// Largest payload `pg_notify` accepts with the default Postgres configuration.
pub const MAX_PAYLOAD: usize = 7999;

pub struct PgTransport {
    channel: String,
    connect: Connect,
    publisher: Mutex<Option<Client>>,
}

impl PgTransport {
    /// Connection without TLS.
    pub fn new(url: &str, channel: impl Into<String>) -> Result<Self, TransportError> {
        Self::with_tls(url, channel, NoTls)
    }

    pub fn with_tls<T>(url: &str, channel: impl Into<String>, tls: T) -> Result<Self, TransportError>
    where
        T: MakeTlsConnect<Socket> + Clone + Send + Sync + 'static,
        T::Stream: Send + 'static,
        T::TlsConnect: Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        let config: Config = url.parse().map_err(connection)?;
        let connect: Connect = Arc::new(move || {
            let config = config.clone();
            let tls = tls.clone();
            Box::pin(async move {
                let (client, mut conn) = config.connect(tls).await.map_err(connection)?;
                let (tx, rx) = mpsc::unbounded_channel();
                tokio::spawn(async move {
                    let mut messages = stream::poll_fn(move |cx| conn.poll_message(cx));
                    while let Some(message) = messages.next().await {
                        let item = match message {
                            Ok(AsyncMessage::Notification(n)) => Ok(n.payload().to_string()),
                            Ok(_) => continue,
                            Err(e) => {
                                #[cfg(feature = "tracing")]
                                tracing::warn!("the LISTEN connection was lost");
                                Err(connection(e))
                            }
                        };
                        let failed = item.is_err();
                        if tx.send(item).is_err() || failed {
                            break;
                        }
                    }
                });
                Ok((client, rx))
            })
        });
        Ok(Self {
            channel: channel.into(),
            connect,
            publisher: Mutex::new(None),
        })
    }

    pub fn channel(&self) -> &str {
        &self.channel
    }
}

/// Takes the next revision of `scope` from the Postgres sequence `sequence` (a name `regclass` accepts,
/// optionally schema-qualified).
///
/// Call it inside the transaction that writes the change, so the revision commits with the change and
/// a rolled-back change leaves only a gap, which revisions allow (they only grow). The scope names the
/// data the sequence orders, for example one sequence per tenant.
pub async fn next_revision<C: GenericClient + Sync>(
    client: &C,
    sequence: &str,
    scope: &str,
) -> Result<Revision, TransportError> {
    let row = client
        .query_one("SELECT nextval($1::text::regclass)", &[&sequence])
        .await
        .map_err(connection)?;
    revision_from(scope, row.get::<_, i64>(0))
}

/// The latest revision `sequence` has handed out for `scope`; revision 0 when it has handed out none.
pub async fn current_revision<C: GenericClient + Sync>(
    client: &C,
    sequence: &str,
    scope: &str,
) -> Result<Revision, TransportError> {
    let row = client
        .query_one("SELECT pg_sequence_last_value($1::text::regclass)", &[&sequence])
        .await
        .map_err(connection)?;
    revision_from(scope, row.get::<_, Option<i64>>(0).unwrap_or(0))
}

fn revision_from(scope: &str, value: i64) -> Result<Revision, TransportError> {
    let value = u64::try_from(value).map_err(|_| TransportError::Decode("negative revision".to_string()))?;
    Ok(Revision::new(scope, value))
}

/// Sends `change` on the channel through the given client or transaction.
pub async fn notify<C: GenericClient + Sync>(client: &C, channel: &str, change: &Change) -> Result<(), TransportError> {
    let payload = change.to_json();
    if payload.len() > MAX_PAYLOAD {
        #[cfg(feature = "tracing")]
        tracing::warn!(
            bytes = payload.len(),
            limit = MAX_PAYLOAD,
            "change notice over the pg_notify limit"
        );
        return Err(TransportError::Decode(format!(
            "aviso com {} bytes passa do limite do pg_notify",
            payload.len()
        )));
    }
    client
        .execute("SELECT pg_notify($1, $2)", &[&channel, &payload])
        .await
        .map(|_| ())
        .map_err(connection)
}

pub(crate) fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

#[async_trait]
impl Transport for PgTransport {
    fn name(&self) -> &str {
        "postgres"
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "strig.postgres.publish", level = "info", skip_all)
    )]
    async fn publish(&self, change: &Change) -> Result<(), TransportError> {
        let mut publisher = self.publisher.lock().await;
        if publisher.as_ref().is_none_or(Client::is_closed) {
            #[cfg(feature = "tracing")]
            tracing::info!("opening the publisher connection");
            let (client, _notifications) = (self.connect)().await?;
            *publisher = Some(client);
        }
        let client = publisher.as_ref().expect("cliente recém-conectado");
        let result = notify(client, &self.channel, change).await;
        if result.is_err() && client.is_closed() {
            #[cfg(feature = "tracing")]
            tracing::warn!("the publisher connection closed during a publish; the next one reconnects");
            *publisher = None;
        }
        result
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "strig.postgres.subscribe", level = "info", skip_all)
    )]
    async fn subscribe(&self) -> Result<ChangeStream, TransportError> {
        let (client, notifications) = (self.connect)().await?;
        client
            .batch_execute(&format!("LISTEN {}", quote_ident(&self.channel)))
            .await
            .map_err(connection)?;
        let stream = UnboundedReceiverStream::new(notifications).map(move |item| {
            let _keep_alive = &client;
            item.and_then(|payload| Change::from_json(&payload).map_err(|e| TransportError::Decode(e.to_string())))
        });
        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_identifiers() {
        assert_eq!(quote_ident("strig_changes"), "\"strig_changes\"");
        assert_eq!(quote_ident("a\"b"), "\"a\"\"b\"");
    }
}
