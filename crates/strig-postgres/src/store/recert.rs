//! Recertification campaigns in Postgres.

use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use strig::{Campaign, RecertError, RecertStore};
use tokio::sync::{mpsc, oneshot};
use tokio_postgres::error::SqlState;
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::{Client, Config, GenericClient, NoTls, Socket};

use crate::query::{PgQueryError, PgTables};

fn store_error(error: impl std::fmt::Display) -> RecertError {
    RecertError::Store(error.to_string())
}

fn decode(text: &str) -> Result<Campaign, RecertError> {
    serde_json::from_str(text).map_err(store_error)
}

fn bigint(value: u64) -> Result<i64, RecertError> {
    i64::try_from(value).map_err(|_| store_error("value does not fit a bigint column"))
}

fn state_of(campaign: &Campaign) -> &'static str {
    if campaign.is_open() { "open" } else { "closed" }
}

impl PgTables {
    /// Stores a new campaign.
    ///
    /// # Errors
    ///
    /// [`RecertError::Duplicate`] when the id is taken, [`RecertError::Store`] otherwise.
    pub async fn insert_recert<C: GenericClient>(&self, client: &C, campaign: &Campaign) -> Result<(), RecertError> {
        let data = serde_json::to_string(campaign).map_err(store_error)?;
        let sql = format!(
            "INSERT INTO {} (id, state, opened_at, revision, data) VALUES ($1, $2, $3, $4, $5::text::jsonb)",
            self.qualified(&self.recert)
        );
        client
            .execute(
                &sql,
                &[
                    &campaign.id,
                    &state_of(campaign),
                    &bigint(campaign.opened_at)?,
                    &bigint(campaign.revision)?,
                    &data,
                ],
            )
            .await
            .map(|_| ())
            .map_err(|error| {
                if error.code() == Some(&SqlState::UNIQUE_VIOLATION) {
                    RecertError::Duplicate(campaign.id.clone())
                } else {
                    store_error(error)
                }
            })
    }

    /// The campaign with this id, open or closed.
    ///
    /// # Errors
    ///
    /// [`RecertError::Store`] when the query fails or the stored row does not decode.
    pub async fn get_recert<C: GenericClient>(&self, client: &C, id: &str) -> Result<Option<Campaign>, RecertError> {
        let sql = format!("SELECT data::text FROM {} WHERE id = $1", self.qualified(&self.recert));
        let row = client.query_opt(&sql, &[&id]).await.map_err(store_error)?;
        row.map(|row| decode(row.get::<_, &str>(0))).transpose()
    }

    /// Replaces an open campaign whose stored revision is one behind `campaign`, in one statement: a
    /// campaign changed meanwhile by another process is not touched.
    ///
    /// # Errors
    ///
    /// [`RecertError::Unknown`] when there is no such campaign, [`RecertError::Closed`] when it was
    /// closed, [`RecertError::Stale`] when its revision moved, [`RecertError::Store`] otherwise.
    pub async fn update_recert<C: GenericClient>(&self, client: &C, campaign: &Campaign) -> Result<(), RecertError> {
        let data = serde_json::to_string(campaign).map_err(store_error)?;
        let revision = bigint(campaign.revision)?;
        let table = self.qualified(&self.recert);
        let sql = format!(
            "UPDATE {table} SET state = $2, revision = $3, data = $4::text::jsonb \
             WHERE id = $1 AND state = 'open' AND revision = $3::bigint - 1"
        );
        let changed = client
            .execute(&sql, &[&campaign.id, &state_of(campaign), &revision, &data])
            .await
            .map_err(store_error)?;
        if changed > 0 {
            return Ok(());
        }
        let row = client
            .query_opt(&format!("SELECT state FROM {table} WHERE id = $1"), &[&campaign.id])
            .await
            .map_err(store_error)?;
        Err(match row {
            None => RecertError::Unknown(campaign.id.clone()),
            Some(row) if row.get::<_, &str>(0) != "open" => RecertError::Closed(campaign.id.clone()),
            Some(_) => RecertError::Stale(campaign.id.clone()),
        })
    }

    /// Every campaign, oldest first.
    ///
    /// # Errors
    ///
    /// [`RecertError::Store`] when the query fails or a row does not decode.
    pub async fn list_recert<C: GenericClient>(&self, client: &C) -> Result<Vec<Campaign>, RecertError> {
        let sql = format!(
            "SELECT data::text FROM {} ORDER BY opened_at, id",
            self.qualified(&self.recert)
        );
        let rows = client.query(&sql, &[]).await.map_err(store_error)?;
        rows.iter().map(|row| decode(row.get::<_, &str>(0))).collect()
    }
}

enum Op {
    Insert(Campaign),
    Get(String),
    Update(Campaign),
    List,
}

enum Reply {
    Done,
    One(Box<Option<Campaign>>),
    Many(Vec<Campaign>),
}

type Job = (Op, std_mpsc::Sender<Result<Reply, RecertError>>);

/// [`RecertStore`] over a Postgres table.
///
/// The trait is synchronous, so the store owns one connection on a thread of its own and a call waits
/// for the answer there. A call blocks the thread that makes it for the length of the round trip:
/// inside an async task use [`tokio::task::spawn_blocking`] (the approvals are rare and human-paced).
/// A call that does not answer within the timeout is a [`RecertError::Store`], and a dropped
/// connection is reopened on the next call.
pub struct PgRecertStore {
    jobs: mpsc::UnboundedSender<Job>,
    timeout: Duration,
}

impl PgRecertStore {
    /// Connects without TLS. See [`PgRecertStore::connect_with_tls`].
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Database`] when the first connection fails.
    pub async fn connect(url: &str, tables: PgTables) -> Result<Self, PgQueryError> {
        Self::connect_with_tls(url, tables, NoTls).await
    }

    /// Connects with the given TLS connector and starts the worker thread.
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Database`] when the first connection fails (or the url does not parse).
    pub async fn connect_with_tls<T>(url: &str, tables: PgTables, tls: T) -> Result<Self, PgQueryError>
    where
        T: MakeTlsConnect<Socket> + Clone + Send + Sync + 'static,
        T::Stream: Send + 'static,
        T::TlsConnect: Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        let config: Config = url.parse()?;
        let (jobs, mut queue) = mpsc::unbounded_channel::<Job>();
        let (ready, started) = oneshot::channel::<Result<(), tokio_postgres::Error>>();
        std::thread::Builder::new()
            .name("strig-pg-recert".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
                let Ok(runtime) = runtime else { return };
                runtime.block_on(async move {
                    let open = || async {
                        let (client, connection) = config.connect(tls.clone()).await?;
                        tokio::spawn(connection);
                        Ok::<Client, tokio_postgres::Error>(client)
                    };
                    let mut client = match open().await {
                        Ok(client) => {
                            let _ = ready.send(Ok(()));
                            Some(client)
                        }
                        Err(error) => {
                            let _ = ready.send(Err(error));
                            return;
                        }
                    };
                    while let Some((op, reply)) = queue.recv().await {
                        if client.as_ref().is_none_or(Client::is_closed) {
                            client = open().await.ok();
                        }
                        let result = match &client {
                            Some(client) => run(&tables, client, op).await,
                            None => Err(store_error("no connection to the database")),
                        };
                        let _ = reply.send(result);
                    }
                });
            })
            .map_err(|error| PgQueryError::Invalid(error.to_string()))?;
        match started.await {
            Ok(Ok(())) => Ok(Self {
                jobs,
                timeout: Duration::from_secs(10),
            }),
            Ok(Err(error)) => Err(error.into()),
            Err(_) => Err(PgQueryError::Invalid("the worker thread did not start".into())),
        }
    }

    /// How long a call waits for the database before it fails closed. Default 10 seconds.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn call(&self, op: Op) -> Result<Reply, RecertError> {
        let (reply, answer) = std_mpsc::channel();
        self.jobs
            .send((op, reply))
            .map_err(|_| store_error("the store worker stopped"))?;
        answer
            .recv_timeout(self.timeout)
            .map_err(|_| store_error("the database did not answer in time"))?
    }
}

async fn run(tables: &PgTables, client: &Client, op: Op) -> Result<Reply, RecertError> {
    match op {
        Op::Insert(campaign) => tables.insert_recert(client, &campaign).await.map(|()| Reply::Done),
        Op::Get(id) => tables.get_recert(client, &id).await.map(|r| Reply::One(Box::new(r))),
        Op::Update(campaign) => tables.update_recert(client, &campaign).await.map(|()| Reply::Done),
        Op::List => tables.list_recert(client).await.map(Reply::Many),
    }
}

impl RecertStore for PgRecertStore {
    fn insert(&self, campaign: Campaign) -> Result<(), RecertError> {
        self.call(Op::Insert(campaign)).map(|_| ())
    }

    fn get(&self, id: &str) -> Result<Option<Campaign>, RecertError> {
        match self.call(Op::Get(id.to_string()))? {
            Reply::One(campaign) => Ok(*campaign),
            _ => Err(store_error("unexpected reply")),
        }
    }

    fn update(&self, campaign: Campaign) -> Result<(), RecertError> {
        self.call(Op::Update(campaign)).map(|_| ())
    }

    fn list(&self) -> Result<Vec<Campaign>, RecertError> {
        match self.call(Op::List)? {
            Reply::Many(campaigns) => Ok(campaigns),
            _ => Err(store_error("unexpected reply")),
        }
    }
}
