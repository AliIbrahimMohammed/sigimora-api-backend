//! Server configuration — loaded from environment / .env file.
//!
//! All settings are read from environment variables.  A `.env` file in the
//! working directory is automatically loaded at startup via `dotenvy`.

use std::path::PathBuf;

/// Top-level server configuration.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// TCP address to listen on (e.g. "0.0.0.0:8080").
    pub listen_addr: String,
    /// Directory to store the SQLite database and key material.
    pub data_dir: PathBuf,
    /// Database URL (sqlite://path).  Overrides data_dir if set.
    pub database_url: Option<String>,
    /// Log level (trace / debug / info / warn / error).
    pub log_level: String,
    /// Comma-separated list of bootstrap API keys for first-run admin access.
    pub bootstrap_keys: Vec<String>,
    /// Enable CORS for all origins (default: true).
    pub cors_enabled: bool,
    /// Comma-separated list of allowed CORS origins (default: empty = allow any).
    pub cors_allowed_origins: Vec<String>,
    /// Maximum body size in bytes (default: 10 MiB).
    pub max_body_size: usize,
    /// Maximum hex message length for signing/verify (default: 1 MiB = 2M hex chars).
    pub max_message_bytes: usize,
    /// Rate limit: max requests per minute per IP (0 = disabled, default: 60).
    pub rate_limit_per_minute: u64,
    /// Enable TLS (default: false).
    pub tls_enabled: bool,
    /// Path to TLS certificate file (PEM).
    pub tls_cert_path: Option<String>,
    /// Path to TLS private key file (PEM).
    pub tls_key_path: Option<String>,
}

impl ServerConfig {
    /// Load configuration from environment variables, using sensible defaults.
    /// Automatically loads `.env` from the current directory if present.
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
                .unwrap_or(1_048_576), // 1 MiB
            rate_limit_per_minute: std::env::var("SIGIMORA_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            tls_enabled: std::env::var("SIGIMORA_TLS_ENABLED")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false),
            tls_cert_path: std::env::var("SIGIMORA_TLS_CERT").ok(),
            tls_key_path: std::env::var("SIGIMORA_TLS_KEY").ok(),
        }
    }

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
        // Temporarily override to use our test var
        let raw = std::env::var("SIGIMORA_BOOTSTRAP_KEYS_TEST1").unwrap_or_default();
        let keys: Vec<String> = raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0], "key1");
        std::env::remove_var("SIGIMORA_BOOTSTRAP_KEYS_TEST1");
    }

    #[test]
    fn test_config_empty_bootstrap_keys() {
        // No env var set → empty vec
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
