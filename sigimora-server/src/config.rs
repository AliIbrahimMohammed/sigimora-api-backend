//! Server configuration — loaded from CLI args / environment / .env file.
//!
//! Run `sigimora-server --help` to see all configuration options.
//! Every option can also be set via the corresponding `SIGIMORA_*` environment
//! variable or a `.env` file in the working directory.

use std::path::PathBuf;
use clap::Parser;

/// BFT Accountable Threshold Signing Backend.
#[derive(Parser, Clone, Debug)]
#[command(name = "sigimora-server", version, about)]
pub struct ServerConfig {
    /// TCP address to listen on.
    #[arg(long = "listen", env = "SIGIMORA_LISTEN", default_value = "0.0.0.0:8080")]
    pub listen_addr: String,

    /// Directory to store the SQLite database and key material.
    #[arg(long = "data-dir", env = "SIGIMORA_DATA_DIR", default_value = "./data")]
    pub data_dir: PathBuf,

    /// Database URL (sqlite://path).  Overrides data_dir if set.
    #[arg(long = "database-url", env = "SIGIMORA_DATABASE_URL")]
    pub database_url: Option<String>,

    /// Log level (trace / debug / info / warn / error).
    #[arg(long = "log-level", env = "SIGIMORA_LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    /// Comma-separated list of bootstrap API keys for first-run admin access.
    #[arg(
        long = "bootstrap-keys",
        env = "SIGIMORA_BOOTSTRAP_KEYS",
        value_delimiter = ',',
        num_args = 0..,
        default_value = ""
    )]
    pub bootstrap_keys: Vec<String>,

    /// Enable CORS for all origins.
    #[arg(
        long = "cors-enabled",
        env = "SIGIMORA_CORS_ENABLED",
        default_value = "true",
        action = clap::ArgAction::Set
    )]
    pub cors_enabled: bool,

    /// Comma-separated list of allowed CORS origins (default: allow any).
    #[arg(
        long = "cors-origins",
        env = "SIGIMORA_CORS_ORIGINS",
        value_delimiter = ',',
        num_args = 0..,
        default_value = ""
    )]
    pub cors_allowed_origins: Vec<String>,

    /// Maximum request body size in bytes (default: 10 MiB).
    #[arg(long = "max-body", env = "SIGIMORA_MAX_BODY", default_value = "10485760")]
    pub max_body_size: usize,

    /// Maximum hex message length for signing/verify in bytes (default: 1 MiB).
    #[arg(long = "max-msg-bytes", env = "SIGIMORA_MAX_MSG_BYTES", default_value = "1048576")]
    pub max_message_bytes: usize,

    /// Rate limit: max requests per minute per IP (0 = disabled).
    #[arg(long = "rate-limit", env = "SIGIMORA_RATE_LIMIT", default_value = "60")]
    pub rate_limit_per_minute: u64,

    /// Database connection pool size (default: 8).
    #[arg(long = "db-pool-size", env = "SIGIMORA_DB_POOL_SIZE", default_value = "8")]
    pub db_pool_size: u32,

    /// Database busy timeout in milliseconds (default: 5000).
    #[arg(long = "db-busy-timeout", env = "SIGIMORA_DB_BUSY_TIMEOUT", default_value = "5000")]
    pub db_busy_timeout_ms: u32,

    /// Enable TLS.
    #[arg(
        long = "tls-enabled",
        env = "SIGIMORA_TLS_ENABLED",
        default_value = "false",
        action = clap::ArgAction::Set
    )]
    pub tls_enabled: bool,

    /// Path to TLS certificate file (PEM).
    #[arg(long = "tls-cert", env = "SIGIMORA_TLS_CERT")]
    pub tls_cert_path: Option<String>,

    /// Path to TLS private key file (PEM).
    #[arg(long = "tls-key", env = "SIGIMORA_TLS_KEY")]
    pub tls_key_path: Option<String>,
}

impl ServerConfig {
    /// Resolve the database URL.
    pub fn database_url(&self) -> String {
        self.database_url.clone().unwrap_or_else(|| {
            let db_path = self.data_dir.join("sigimora.db");
            format!("sqlite:{}?mode=rwc", db_path.display())
        })
    }

    /// Ensure the data directory exists.
    pub fn ensure_dirs(&self) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(&self.data_dir)
    }

    /// Load configuration from environment variables (for tests / backward compat).
    /// Prefer `ServerConfig::parse()` in production.
    pub fn from_env() -> Self {
        // Load .env file if present (silently ignore if missing)
        let _ = dotenvy::dotenv();

        let data_dir = std::env::var("SIGIMORA_DATA_DIR")
            .unwrap_or_else(|_| "./data".to_string());

        Self {
            listen_addr: std::env::var("SIGIMORA_LISTEN")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            data_dir: PathBuf::from(&data_dir),
            database_url: std::env::var("SIGIMORA_DATABASE_URL").ok(),
            log_level: std::env::var("SIGIMORA_LOG_LEVEL")
                .unwrap_or_else(|_| "info".to_string()),
            bootstrap_keys: std::env::var("SIGIMORA_BOOTSTRAP_KEYS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            cors_enabled: std::env::var("SIGIMORA_CORS_ENABLED")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(true),
            cors_allowed_origins: std::env::var("SIGIMORA_CORS_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            max_body_size: std::env::var("SIGIMORA_MAX_BODY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10 * 1024 * 1024),
            max_message_bytes: std::env::var("SIGIMORA_MAX_MSG_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1_048_576),
            rate_limit_per_minute: std::env::var("SIGIMORA_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            tls_enabled: std::env::var("SIGIMORA_TLS_ENABLED")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false),
            tls_cert_path: std::env::var("SIGIMORA_TLS_CERT").ok(),
            tls_key_path: std::env::var("SIGIMORA_TLS_KEY").ok(),
            db_pool_size: std::env::var("SIGIMORA_DB_POOL_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8),
            db_busy_timeout_ms: std::env::var("SIGIMORA_DB_BUSY_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5000),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        // Clear relevant env vars for test isolation
        std::env::remove_var("SIGIMORA_LISTEN");
        std::env::remove_var("SIGIMORA_DATA_DIR");
        std::env::remove_var("SIGIMORA_LOG_LEVEL");

        let cfg = ServerConfig::from_env();
        assert_eq!(cfg.listen_addr, "0.0.0.0:8080");
        assert_eq!(cfg.data_dir, PathBuf::from("./data"));
        assert_eq!(cfg.log_level, "info");
        assert!(cfg.cors_enabled);
        assert_eq!(cfg.max_body_size, 10 * 1024 * 1024);
        assert_eq!(cfg.rate_limit_per_minute, 60);
        assert!(!cfg.tls_enabled);
    }

    #[test]
    fn test_config_bootstrap_keys_parsing() {
        std::env::set_var("SIGIMORA_BOOTSTRAP_KEYS_TEST1", "key1,key2,key3");
        let raw = std::env::var("SIGIMORA_BOOTSTRAP_KEYS_TEST1").unwrap_or_default();
        let keys: Vec<String> = raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0], "key1");
        std::env::remove_var("SIGIMORA_BOOTSTRAP_KEYS_TEST1");
    }

    #[test]
    fn test_config_empty_bootstrap_keys() {
        let cfg = ServerConfig::from_env();
        assert!(cfg.bootstrap_keys.is_empty());
    }

    #[test]
    fn test_database_url_default() {
        let cfg = ServerConfig::from_env();
        let url = cfg.database_url();
        assert!(url.starts_with("sqlite:"));
        assert!(url.contains("sigimora.db"));
    }
}
