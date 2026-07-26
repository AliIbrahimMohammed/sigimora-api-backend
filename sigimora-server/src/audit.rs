//! Audit logging for security-relevant operations.
//!
//! Writes structured JSON events to both:
//!   - the `tracing` log (at info level, target "audit")
//!   - the `audit_log` SQLite table (best-effort)
//!
//! The DB writer requires a `Database` reference stored via `set_audit_db()`
//! at startup.  If no DB is set, only tracing logging occurs.

use chrono::Utc;
use serde::Serialize;
use std::sync::OnceLock;

use crate::db::Database;

static AUDIT_DB: OnceLock<Database> = OnceLock::new();

/// Register the database handle for audit log persistence.
/// Called once at server startup.
pub fn set_audit_db(db: Database) {
    let _ = AUDIT_DB.set(db);
}

/// A security audit event.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub action: String,
    pub actor: String,
    pub target: String,
    pub details: String,
}

/// Log an audit event — writes to tracing log and (best-effort) to the DB.
pub fn audit(action: &str, actor: &str, target: &str, details: &str) {
    let event = AuditEvent {
        timestamp: Utc::now().to_rfc3339(),
        action: action.to_string(),
        actor: actor.to_string(),
        target: target.to_string(),
        details: details.to_string(),
    };

    // Always log via tracing
    tracing::info!(
        target: "audit",
        "{}",
        serde_json::to_string(&event).unwrap_or_else(|_| "audit serialization failed".to_string())
    );

    // Best-effort DB write
    if let Some(db) = AUDIT_DB.get() {
        let action = event.action.clone();
        let actor = event.actor.clone();
        let target = event.target.clone();
        let details = event.details.clone();
        tokio::spawn(async move {
            if let Err(e) = db.insert_audit_log(&action, &actor, &target, &details).await {
                tracing::warn!("Failed to write audit log to DB: {}", e);
            }
        });
    }
}
