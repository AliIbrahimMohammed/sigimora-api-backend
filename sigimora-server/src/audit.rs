//! Audit logging for security-relevant operations.

use chrono::Utc;
use serde::Serialize;

/// A security audit event.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub action: String,
    pub actor: String,
    pub target: String,
    pub details: String,
}

/// Log an audit event using structured tracing at info level.
/// In production this would go to a secure audit log sink.
pub fn audit(action: &str, actor: &str, target: &str, details: &str) {
    let event = AuditEvent {
        timestamp: Utc::now().to_rfc3339(),
        action: action.to_string(),
        actor: actor.to_string(),
        target: target.to_string(),
        details: details.to_string(),
    };
    tracing::info!(
        target: "audit",
        "{}",
        serde_json::to_string(&event).unwrap_or_else(|_| "audit serialization failed".to_string())
    );
}
