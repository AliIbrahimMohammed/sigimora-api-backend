//! Application state shared across all route handlers.
//! Includes rate limiter and audit support.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::db::Database;

/// Simple sliding-window rate limiter per IP.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<RwLock<HashMap<IpAddr, Window>>>,
    max_requests: u64,
    window_secs: u64,
}

#[derive(Clone, Copy, Debug)]
struct Window {
    count: u64,
    start: std::time::Instant,
}

impl RateLimiter {
    pub fn new(max_requests: u64, window_secs: u64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window_secs,
        }
    }

    /// Check if a request from this IP is allowed.
    /// Returns `true` if under the limit, `false` if rate-limited.
    pub async fn check(&self, ip: IpAddr) -> bool {
        let mut map = self.inner.write().await;
        let now = std::time::Instant::now();
        let window = map
            .entry(ip)
            .or_insert(Window { count: 0, start: now });

        if now.duration_since(window.start).as_secs() >= self.window_secs {
            // Reset window
            window.count = 0;
            window.start = now;
        }

        if window.count >= self.max_requests {
            return false; // Rate limited
        }

        window.count += 1;
        true
    }
}

/// Global application state.
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub start_time: tokio::time::Instant,
    pub rate_limiter: RateLimiter,
    pub request_counter: Arc<AtomicU64>,
}

impl AppState {
    pub fn new(config: crate::config::ServerConfig, db: Database) -> Self {
        Self {
            db,
            start_time: tokio::time::Instant::now(),
            rate_limiter: RateLimiter::new(config.rate_limit_per_minute, 60),
            request_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Increment and return the current request counter.
    pub fn next_request_id(&self) -> u64 {
        self.request_counter.fetch_add(1, Ordering::Relaxed)
    }
}
