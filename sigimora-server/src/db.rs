//! Database layer — SQLite via sqlx.
//!
//! Stores networks, nodes, API keys, ledger entries, and signed transactions.

use chrono::Utc;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

use crate::error::ApiError;

/// Shared database handle.
#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Open (or create) the SQLite database and run migrations.
    pub async fn open(database_url: &str) -> Result<Self, ApiError> {
        let opts = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;

        let db = Database { pool };
        db.run_migrations().await?;
        Ok(db)
    }

    async fn run_migrations(&self) -> Result<(), ApiError> {
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS api_keys (
                id          TEXT PRIMARY KEY,
                key_hash    TEXT NOT NULL,
                key_prefix  TEXT NOT NULL,
                label       TEXT NOT NULL,
                role        TEXT NOT NULL DEFAULT 'user',
                created_at  TEXT NOT NULL,
                last_used_at TEXT
            );"
        ).execute(&self.pool).await?;

        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS networks (
                id               TEXT PRIMARY KEY,
                n                INTEGER NOT NULL,
                t                INTEGER NOT NULL,
                f                INTEGER NOT NULL,
                quorum           INTEGER NOT NULL,
                collective_pk    BLOB,
                tracking_pk      BLOB,
                tracking_sk      BLOB,
                state            TEXT NOT NULL DEFAULT 'created',
                created_at       TEXT NOT NULL
            );"
        ).execute(&self.pool).await?;

        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS nodes (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id        INTEGER NOT NULL,
                network_id     TEXT NOT NULL REFERENCES networks(id),
                public_key     BLOB NOT NULL,
                secret_key     BLOB NOT NULL,
                company_name   TEXT,
                epoch          INTEGER NOT NULL DEFAULT 0,
                created_at     TEXT NOT NULL,
                UNIQUE(node_id, network_id)
            );"
        ).execute(&self.pool).await?;

        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS ledger (
                block_index    INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_id          TEXT NOT NULL,
                network_id     TEXT NOT NULL REFERENCES networks(id),
                message_hash   BLOB NOT NULL,
                signature      BLOB,
                signers        TEXT NOT NULL,
                epoch          INTEGER NOT NULL DEFAULT 0,
                created_at     TEXT NOT NULL
            );"
        ).execute(&self.pool).await?;

        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS signed_txs (
                tx_id          TEXT PRIMARY KEY,
                network_id     TEXT NOT NULL REFERENCES networks(id),
                message        BLOB NOT NULL,
                signature      BLOB NOT NULL,
                quorum         TEXT NOT NULL,
                created_at     TEXT NOT NULL
            );"
        ).execute(&self.pool).await?;

        sqlx::raw_sql(
            "CREATE INDEX IF NOT EXISTS idx_ledger_network ON ledger(network_id);"
        ).execute(&self.pool).await?;

        sqlx::raw_sql(
            "CREATE INDEX IF NOT EXISTS idx_nodes_network ON nodes(network_id);"
        ).execute(&self.pool).await?;

        sqlx::raw_sql(
            "CREATE INDEX IF NOT EXISTS idx_signed_txs_network ON signed_txs(network_id);"
        ).execute(&self.pool).await?;

        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                action      TEXT NOT NULL,
                actor       TEXT NOT NULL,
                target      TEXT NOT NULL,
                details     TEXT NOT NULL
            );"
        ).execute(&self.pool).await?;

        Ok(())
    }

    // ── Helpers ────────────────────────────────────────────────────────

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn count_networks(&self) -> Result<usize, ApiError> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM networks")
            .fetch_one(&self.pool)
            .await?;
        Ok(count as usize)
    }

    pub async fn count_all_nodes(&self) -> Result<usize, ApiError> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM nodes")
            .fetch_one(&self.pool)
            .await?;
        Ok(count as usize)
    }

    pub async fn count_all_ledger_entries(&self) -> Result<usize, ApiError> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ledger")
            .fetch_one(&self.pool)
            .await?;
        Ok(count as usize)
    }

    // ── API Key operations ─────────────────────────────────────────────

    pub async fn insert_api_key(&self, key: &ApiKeyRow) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO api_keys (id, key_hash, key_prefix, label, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&key.id)
        .bind(&key.key_hash)
        .bind(&key.key_prefix)
        .bind(&key.label)
        .bind(&key.role)
        .bind(&key.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_api_key_by_hash(&self, hash: &str) -> Result<Option<ApiKeyRow>, ApiError> {
        let row = sqlx::query_as::<_, ApiKeyRow>(
            "SELECT id, key_hash, key_prefix, label, role, created_at, last_used_at FROM api_keys WHERE key_hash = ?",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn list_api_keys(&self) -> Result<Vec<ApiKeyRow>, ApiError> {
        let rows = sqlx::query_as::<_, ApiKeyRow>(
            "SELECT id, key_hash, key_prefix, label, role, created_at, last_used_at FROM api_keys ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn list_api_keys_paginated(
        &self, offset: usize, limit: usize,
    ) -> Result<Vec<ApiKeyRow>, ApiError> {
        let rows = sqlx::query_as::<_, ApiKeyRow>(
            "SELECT id, key_hash, key_prefix, label, role, created_at, last_used_at FROM api_keys ORDER BY created_at DESC LIMIT ? OFFSET ?",
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn count_api_keys(&self) -> Result<usize, ApiError> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM api_keys")
            .fetch_one(&self.pool)
            .await?;
        Ok(count as usize)
    }

    pub async fn delete_api_key(&self, id: &str) -> Result<bool, ApiError> {
        let result = sqlx::query("DELETE FROM api_keys WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn touch_api_key(&self, id: &str) -> Result<(), ApiError> {
        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
            .bind(&now)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── Network operations ─────────────────────────────────────────────

    pub async fn insert_network(&self, net: &NetworkRow) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO networks (id, n, t, f, quorum, collective_pk, tracking_pk, tracking_sk, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&net.id)
        .bind(net.n as i64)
        .bind(net.t as i64)
        .bind(net.f as i64)
        .bind(net.quorum as i64)
        .bind(&net.collective_pk)
        .bind(&net.tracking_pk)
        .bind(&net.tracking_sk)
        .bind(&net.state)
        .bind(&net.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_network(&self, id: &str) -> Result<Option<NetworkRow>, ApiError> {
        let row = sqlx::query_as::<_, NetworkRow>(
            "SELECT id, n, t, f, quorum, collective_pk, tracking_pk, tracking_sk, state, created_at FROM networks WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn list_networks(&self) -> Result<Vec<NetworkRow>, ApiError> {
        let rows = sqlx::query_as::<_, NetworkRow>(
            "SELECT id, n, t, f, quorum, collective_pk, tracking_pk, tracking_sk, state, created_at FROM networks ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn update_network_state(
        &self, id: &str, state: &str, collective_pk: Option<&[u8]>,
    ) -> Result<(), ApiError> {
        sqlx::query("UPDATE networks SET state = ?, collective_pk = ? WHERE id = ?")
            .bind(state)
            .bind(collective_pk)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }



    // ── Node operations ────────────────────────────────────────────────

    pub async fn insert_node(&self, node: &NodeRow) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO nodes (node_id, network_id, public_key, secret_key, company_name, epoch, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(node.node_id as i64)
        .bind(&node.network_id)
        .bind(&node.public_key)
        .bind(&node.secret_key)
        .bind(&node.company_name)
        .bind(node.epoch as i64)
        .bind(&node.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_nodes_by_network(&self, network_id: &str) -> Result<Vec<NodeRow>, ApiError> {
        let rows = sqlx::query_as::<_, NodeRow>(
            "SELECT id, node_id, network_id, public_key, secret_key, company_name, epoch, created_at FROM nodes WHERE network_id = ? ORDER BY node_id",
        )
        .bind(network_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn get_nodes_by_network_paginated(
        &self, network_id: &str, offset: usize, limit: usize,
    ) -> Result<Vec<NodeRow>, ApiError> {
        let rows = sqlx::query_as::<_, NodeRow>(
            "SELECT id, node_id, network_id, public_key, secret_key, company_name, epoch, created_at FROM nodes WHERE network_id = ? ORDER BY node_id LIMIT ? OFFSET ?",
        )
        .bind(network_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn get_node(&self, network_id: &str, node_id: u16) -> Result<Option<NodeRow>, ApiError> {
        let row = sqlx::query_as::<_, NodeRow>(
            "SELECT id, node_id, network_id, public_key, secret_key, company_name, epoch, created_at FROM nodes WHERE network_id = ? AND node_id = ?",
        )
        .bind(network_id)
        .bind(node_id as i64)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn update_node_secret(&self, network_id: &str, node_id: u16, secret_key: &[u8]) -> Result<(), ApiError> {
        sqlx::query("UPDATE nodes SET secret_key = ? WHERE network_id = ? AND node_id = ?")
            .bind(secret_key)
            .bind(network_id)
            .bind(node_id as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn count_nodes_by_network(&self, network_id: &str) -> Result<usize, ApiError> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM nodes WHERE network_id = ?",
        )
        .bind(network_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count as usize)
    }

    // ── Ledger operations ──────────────────────────────────────────────

    pub async fn insert_ledger_entry(&self, entry: &LedgerRow) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO ledger (tx_id, network_id, message_hash, signature, signers, epoch, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&entry.tx_id)
        .bind(&entry.network_id)
        .bind(&entry.message_hash)
        .bind(&entry.signature)
        .bind(&entry.signers)
        .bind(entry.epoch as i64)
        .bind(&entry.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_ledger_by_network(
        &self, network_id: &str, offset: usize, limit: usize,
    ) -> Result<Vec<LedgerRow>, ApiError> {
        let rows = sqlx::query_as::<_, LedgerRow>(
            "SELECT block_index, tx_id, network_id, message_hash, signature, signers, epoch, created_at FROM ledger WHERE network_id = ? ORDER BY block_index DESC LIMIT ? OFFSET ?",
        )
        .bind(network_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn count_ledger_by_network(&self, network_id: &str) -> Result<usize, ApiError> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM ledger WHERE network_id = ?",
        )
        .bind(network_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count as usize)
    }

    // ── Signed transactions ────────────────────────────────────────────

    pub async fn insert_signed_tx(&self, tx: &SignedTxRow) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO signed_txs (tx_id, network_id, message, signature, quorum, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&tx.tx_id)
        .bind(&tx.network_id)
        .bind(&tx.message)
        .bind(&tx.signature)
        .bind(&tx.quorum)
        .bind(&tx.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_signed_tx(&self, tx_id: &str) -> Result<Option<SignedTxRow>, ApiError> {
        let row = sqlx::query_as::<_, SignedTxRow>(
            "SELECT tx_id, network_id, message, signature, quorum, created_at FROM signed_txs WHERE tx_id = ?",
        )
        .bind(tx_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

}

// ══════════════════════════════════════════════════════════════════════════
//  Database row types (internal, mapped to SQLite columns)
// ══════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct ApiKeyRow {
    pub id: String,
    pub key_hash: String,
    pub key_prefix: String,
    pub label: String,
    pub role: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct NetworkRow {
    pub id: String,
    pub n: i64,
    pub t: i64,
    pub f: i64,
    pub quorum: i64,
    pub collective_pk: Option<Vec<u8>>,
    pub tracking_pk: Option<Vec<u8>>,
    pub tracking_sk: Option<Vec<u8>>,
    pub state: String,
    pub created_at: String,
}

#[derive(Debug, sqlx::FromRow)]
pub struct NodeRow {
    pub id: i64,
    pub node_id: i64,
    pub network_id: String,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub company_name: Option<String>,
    pub epoch: i64,
    pub created_at: String,
}

#[derive(Debug, sqlx::FromRow)]
pub struct LedgerRow {
    pub block_index: i64,
    pub tx_id: String,
    pub network_id: String,
    pub message_hash: Vec<u8>,
    pub signature: Option<Vec<u8>>,
    pub signers: String,
    pub epoch: i64,
    pub created_at: String,
}

#[derive(Debug, sqlx::FromRow)]
pub struct SignedTxRow {
    pub tx_id: String,
    pub network_id: String,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub quorum: String,
    pub created_at: String,
}
