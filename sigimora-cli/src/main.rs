//! SIGIMORA CLI — admin tool for the threshold signing backend.
//!
//! Communicates with a running sigimora-server via its REST API.
//!
//! # Usage
//! ```bash
//! # Set defaults via env or --api-key / --url
//! export SIGIMORA_API_KEY="sigimora_..."
//! export SIGIMORA_URL="http://127.0.0.1:8080"
//!
//! sigimora-cli health
//! sigimora-cli networks
//! sigimora-cli network create --n 4 --t 2
//! sigimora-cli network dkg <id>
//! sigimora-cli sign <id> --message deadbeef --quorum 1,2,3
//! sigimora-cli verify <id> --message deadbeef --signature <hex>
//! sigimora-cli trace <id> --tx-id <uuid> --tracking-key <hex>
//! sigimora-cli api-keys
//! sigimora-cli api-key create --label my-key --role admin
//! sigimora-cli api-key delete <id>
//! ```

use clap::{Parser, Subcommand};
use serde_json::Value;

#[derive(Parser)]
#[command(name = "sigimora-cli", version, about = "SIGIMORA admin CLI")]
struct Cli {
    /// API key for authentication.
    #[arg(short = 'k', long, env = "SIGIMORA_API_KEY")]
    api_key: String,

    /// Server URL.
    #[arg(short = 'u', long, env = "SIGIMORA_URL", default_value = "http://127.0.0.1:8080")]
    url: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check server health.
    Health,
    /// List all networks.
    Networks,
    /// Network operations.
    Network {
        #[command(subcommand)]
        action: NetworkAction,
    },
    /// Sign a message.
    Sign {
        /// Network ID.
        id: String,
        /// Hex-encoded message.
        #[arg(short, long)]
        message: String,
        /// Quorum node IDs (comma-separated).
        #[arg(short, long)]
        quorum: String,
    },
    /// Verify a signature.
    Verify {
        /// Network ID.
        id: String,
        /// Hex-encoded message.
        #[arg(short, long)]
        message: String,
        /// Hex-encoded signature.
        #[arg(short = 's', long)]
        signature: String,
        /// Quorum node IDs (comma-separated, optional).
        #[arg(short, long)]
        quorum: Option<String>,
    },
    /// Trace signers of a transaction.
    Trace {
        /// Network ID.
        id: String,
        /// Transaction ID.
        #[arg(short = 't', long)]
        tx_id: String,
        /// Tracking secret key (hex).
        #[arg(short = 'k', long)]
        tracking_key: String,
    },
    /// List API keys.
    ApiKeys,
    /// API key operations.
    ApiKey {
        #[command(subcommand)]
        action: ApiKeyAction,
    },
    /// List nodes in a network.
    Nodes {
        /// Network ID.
        id: String,
    },
    /// View ledger for a network.
    Ledger {
        /// Network ID.
        id: String,
        /// Offset (default 0).
        #[arg(long, default_value = "0")]
        offset: usize,
        /// Limit (default 50).
        #[arg(long, default_value = "50")]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum NetworkAction {
    /// Create a new network.
    Create {
        /// Number of nodes.
        #[arg(short, long)]
        n: usize,
        /// Threshold.
        #[arg(short, long)]
        t: usize,
    },
    /// Run DKG on a network.
    Dkg {
        /// Network ID.
        id: String,
    },
    /// Get network details.
    Get {
        /// Network ID.
        id: String,
    },
}

#[derive(Subcommand)]
enum ApiKeyAction {
    /// Create a new API key.
    Create {
        /// Label for the key.
        #[arg(short, long)]
        label: String,
        /// Role (admin or user).
        #[arg(short, long, default_value = "user")]
        role: String,
    },
    /// Delete (revoke) an API key.
    Delete {
        /// Key ID.
        id: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = reqwest::Client::new();
    let headers = {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", cli.api_key).parse().unwrap(),
        );
        h.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        h
    };

    let result = match &cli.command {
        Command::Health => cmd_health(&client, &cli.url, &headers).await,
        Command::Networks => cmd_networks(&client, &cli.url, &headers).await,
        Command::Network { action } => match action {
            NetworkAction::Create { n, t } => cmd_network_create(&client, &cli.url, &headers, *n, *t).await,
            NetworkAction::Dkg { id } => cmd_dkg(&client, &cli.url, &headers, id).await,
            NetworkAction::Get { id } => cmd_network_get(&client, &cli.url, &headers, id).await,
        },
        Command::Sign { id, message, quorum } => {
            cmd_sign(&client, &cli.url, &headers, id, message, quorum).await
        }
        Command::Verify { id, message, signature, quorum } => {
            cmd_verify(&client, &cli.url, &headers, id, message, signature, quorum.as_deref()).await
        }
        Command::Trace { id, tx_id, tracking_key } => {
            cmd_trace(&client, &cli.url, &headers, id, tx_id, tracking_key).await
        }
        Command::ApiKeys => cmd_api_keys(&client, &cli.url, &headers).await,
        Command::ApiKey { action } => match action {
            ApiKeyAction::Create { label, role } => cmd_api_key_create(&client, &cli.url, &headers, label, role).await,
            ApiKeyAction::Delete { id } => cmd_api_key_delete(&client, &cli.url, &headers, id).await,
        },
        Command::Nodes { id } => cmd_nodes(&client, &cli.url, &headers, id).await,
        Command::Ledger { id, offset, limit } => cmd_ledger(&client, &cli.url, &headers, id, *offset, *limit).await,
    };

    match result {
        Ok(json) => println!("{}", serde_json::to_string_pretty(&json).unwrap()),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

async fn get_json(client: &reqwest::Client, url: &str, headers: &reqwest::header::HeaderMap) -> Result<Value, String> {
    let resp = client.get(url).headers(headers.clone()).send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("HTTP {}: {}", status, body));
    }
    resp.json().await.map_err(|e| e.to_string())
}

async fn post_json(client: &reqwest::Client, url: &str, headers: &reqwest::header::HeaderMap, body: &Value) -> Result<Value, String> {
    let resp = client.post(url).headers(headers.clone()).json(body).send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("HTTP {}: {}", status, text));
    }
    resp.json().await.map_err(|e| e.to_string())
}

async fn delete_req(client: &reqwest::Client, url: &str, headers: &reqwest::header::HeaderMap) -> Result<Value, String> {
    let resp = client.delete(url).headers(headers.clone()).send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("HTTP {}: {}", status, text));
    }
    resp.json().await.map_err(|e| e.to_string())
}

async fn cmd_health(client: &reqwest::Client, base_url: &str, headers: &reqwest::header::HeaderMap) -> Result<Value, String> {
    get_json(client, &format!("{}/api/v1/health", base_url), headers).await
}

async fn cmd_networks(client: &reqwest::Client, base_url: &str, headers: &reqwest::header::HeaderMap) -> Result<Value, String> {
    get_json(client, &format!("{}/api/v1/networks", base_url), headers).await
}

async fn cmd_network_get(client: &reqwest::Client, base_url: &str, headers: &reqwest::header::HeaderMap, id: &str) -> Result<Value, String> {
    get_json(client, &format!("{}/api/v1/networks/{}", base_url, id), headers).await
}

async fn cmd_network_create(client: &reqwest::Client, base_url: &str, headers: &reqwest::header::HeaderMap, n: usize, t: usize) -> Result<Value, String> {
    post_json(client, &format!("{}/api/v1/networks", base_url), headers, &serde_json::json!({ "n": n, "t": t })).await
}

async fn cmd_dkg(client: &reqwest::Client, base_url: &str, headers: &reqwest::header::HeaderMap, id: &str) -> Result<Value, String> {
    post_json(client, &format!("{}/api/v1/networks/{}/dkg", base_url, id), headers, &serde_json::json!({})).await
}

async fn cmd_sign(client: &reqwest::Client, base_url: &str, headers: &reqwest::header::HeaderMap, id: &str, message: &str, quorum: &str) -> Result<Value, String> {
    let quorum: Vec<u16> = quorum.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    post_json(client, &format!("{}/api/v1/networks/{}/sign", base_url, id), headers, &serde_json::json!({ "message": message, "quorum": quorum })).await
}

async fn cmd_verify(client: &reqwest::Client, base_url: &str, headers: &reqwest::header::HeaderMap, id: &str, message: &str, signature: &str, quorum: Option<&str>) -> Result<Value, String> {
    let q: Vec<u16> = quorum.map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect()).unwrap_or_default();
    post_json(client, &format!("{}/api/v1/networks/{}/verify", base_url, id), headers, &serde_json::json!({ "message": message, "signature_hex": signature, "quorum": q })).await
}

async fn cmd_trace(client: &reqwest::Client, base_url: &str, headers: &reqwest::header::HeaderMap, id: &str, tx_id: &str, tracking_key: &str) -> Result<Value, String> {
    post_json(client, &format!("{}/api/v1/networks/{}/trace", base_url, id), headers, &serde_json::json!({ "tx_id": tx_id, "tracking_key_hex": tracking_key })).await
}

async fn cmd_api_keys(client: &reqwest::Client, base_url: &str, headers: &reqwest::header::HeaderMap) -> Result<Value, String> {
    get_json(client, &format!("{}/api/v1/api-keys", base_url), headers).await
}

async fn cmd_api_key_create(client: &reqwest::Client, base_url: &str, headers: &reqwest::header::HeaderMap, label: &str, role: &str) -> Result<Value, String> {
    post_json(client, &format!("{}/api/v1/api-keys", base_url), headers, &serde_json::json!({ "label": label, "role": role })).await
}

async fn cmd_api_key_delete(client: &reqwest::Client, base_url: &str, headers: &reqwest::header::HeaderMap, id: &str) -> Result<Value, String> {
    delete_req(client, &format!("{}/api/v1/api-keys/{}", base_url, id), headers).await
}

async fn cmd_nodes(client: &reqwest::Client, base_url: &str, headers: &reqwest::header::HeaderMap, id: &str) -> Result<Value, String> {
    get_json(client, &format!("{}/api/v1/networks/{}/nodes", base_url, id), headers).await
}

async fn cmd_ledger(client: &reqwest::Client, base_url: &str, headers: &reqwest::header::HeaderMap, id: &str, offset: usize, limit: usize) -> Result<Value, String> {
    get_json(client, &format!("{}/api/v1/networks/{}/ledger?offset={}&limit={}", base_url, id, offset, limit), headers).await
}
