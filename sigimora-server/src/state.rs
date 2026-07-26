//! Application state shared across all route handlers.

use crate::db::Database;

/// Global application state.
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub start_time: tokio::time::Instant,
}

impl AppState {
    #[allow(unused_variables)]
    pub fn new(config: crate::config::ServerConfig, db: Database) -> Self {
        Self {
            db,
            start_time: tokio::time::Instant::now(),
        }
    }
}
