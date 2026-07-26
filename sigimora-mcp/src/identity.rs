//! Node identity system (reused from BFT, adapted for MCP).
//!
//! Each node generates a BLS key pair when started. The node address is
//! derived from the public key hash (similar to Ethereum addresses).

use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Sha3_256, Digest};
use sigimora_crypto::bls::{PublicKey, Signature};
use sigimora_math::{G2Point, Scalar};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::McpError;

#[derive(Clone)]
pub struct NodeIdentity {
    pub node_id: u16,
    pub secret_key: NodeSecretKey,
    pub public_key: PublicKey,
    pub address: NodeAddress,
    pub company_name: Option<String>,
    pub created_at: u64,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NodeSecretKey {
    secret: Scalar,
}

impl NodeSecretKey {
    pub fn random(rng: &mut impl RngCore) -> Self {
        NodeSecretKey {
            secret: Scalar::random(rng),
        }
    }

    pub fn from_scalar(s: Scalar) -> Self {
        NodeSecretKey { secret: s }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(G2Point::generator().mul(&self.secret))
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        let h = sigimora_math::hash_to_g1(msg, b"SIGIMORA-NODE-SIGN");
        Signature(h.mul(&self.secret))
    }

    pub fn as_scalar(&self) -> &Scalar {
        &self.secret
    }
}

impl NodeIdentity {
    pub fn new(
        node_id: u16,
        rng: &mut impl RngCore,
        company_name: Option<String>,
    ) -> Self {
        let secret_key = NodeSecretKey::random(rng);
        let public_key = secret_key.public_key();
        let address = NodeAddress::from_public_key(&public_key);

        NodeIdentity {
            node_id,
            secret_key,
            public_key,
            address,
            company_name,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub fn sign_message(&self, msg: &[u8]) -> Signature {
        self.secret_key.sign(msg)
    }

    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), McpError> {
        let json = self.to_json()?;
        std::fs::write(path, json)
            .map_err(|e| McpError::SerializationError(format!("write identity: {}", e)))
    }

    pub fn load_from_file(path: &std::path::Path) -> Result<Self, McpError> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| McpError::SerializationError(format!("read identity: {}", e)))?;
        let json: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| McpError::SerializationError(format!("parse identity: {}", e)))?;

        let node_id = json["node_id"].as_u64().ok_or_else(|| {
            McpError::SerializationError("missing node_id".to_string())
        })? as u16;

        // Restore secret key (included in JSON as hex)
        let sk_hex = json["secret_key"].as_str().ok_or_else(|| {
            McpError::SerializationError("missing secret_key".to_string())
        })?;
        let sk_bytes = hex::decode(sk_hex)
            .map_err(|e| McpError::SerializationError(format!("hex decode secret: {}", e)))?;
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk_bytes);
        let secret_scalar = sigimora_math::Scalar::from_bytes(&sk_arr)
            .map_err(|_| McpError::SerializationError("invalid secret key".to_string()))?;
        let secret_key = NodeSecretKey::from_scalar(secret_scalar);

        let pk_hex = json["public_key"].as_str().ok_or_else(|| {
            McpError::SerializationError("missing public_key".to_string())
        })?;
        let pk_bytes = hex::decode(pk_hex)
            .map_err(|e| McpError::SerializationError(format!("hex decode: {}", e)))?;
        let mut pk_arr = [0u8; 96];
        pk_arr.copy_from_slice(&pk_bytes);
        let public_key = sigimora_crypto::bls::PublicKey(
            sigimora_math::G2Point::from_bytes(&pk_arr)
                .map_err(|_| McpError::SerializationError("invalid public key".to_string()))?
        );

        let addr_hex = json["address"].as_str().ok_or_else(|| {
            McpError::SerializationError("missing address".to_string())
        })?;
        let addr_bytes = hex::decode(addr_hex)
            .map_err(|e| McpError::SerializationError(format!("hex decode: {}", e)))?;
        let mut addr_arr = [0u8; 20];
        addr_arr.copy_from_slice(&addr_bytes);
        let address = NodeAddress(addr_arr);

        let company_name = json["company_name"].as_str().map(|s| s.to_string());
        let created_at = json["created_at"].as_u64().unwrap_or(0);

        Ok(NodeIdentity {
            node_id,
            secret_key,
            public_key,
            address,
            company_name,
            created_at,
        })
    }

    pub fn to_json(&self) -> Result<String, McpError> {
        let data = serde_json::json!({
            "node_id": self.node_id,
            "secret_key": hex::encode(self.secret_key.as_scalar().to_bytes()),
            "public_key": hex::encode(self.public_key.to_bytes()),
            "address": self.address.to_hex(),
            "company_name": self.company_name,
            "created_at": self.created_at,
        });
        serde_json::to_string_pretty(&data).map_err(|e| McpError::SerializationError(e.to_string()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeAddress([u8; 20]);

impl NodeAddress {
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(public_key.to_bytes());
        let hash = hasher.finalize();

        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[..20]);
        NodeAddress(address)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn short(&self) -> String {
        let hex = self.to_hex();
        format!("{}...{}", &hex[..6], &hex[hex.len() - 4..])
    }
}

impl std::fmt::Display for NodeAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeCredential {
    pub address: NodeAddress,
    pub node_id: u16,
    pub proof_of_possession: Vec<u8>,
    pub timestamp: u64,
    pub expires_at: u64,
    pub network_id: String,
}

pub struct AuthorizedNodes {
    authorized_addresses: std::collections::HashSet<NodeAddress>,
    authorized_public_keys: std::collections::HashMap<NodeAddress, PublicKey>,
}

impl AuthorizedNodes {
    pub fn new() -> Self {
        AuthorizedNodes {
            authorized_addresses: std::collections::HashSet::new(),
            authorized_public_keys: std::collections::HashMap::new(),
        }
    }

    pub fn add_authorized(
        &mut self,
        address: NodeAddress,
        public_key: PublicKey,
    ) {
        self.authorized_addresses.insert(address.clone());
        self.authorized_public_keys.insert(address, public_key);
    }

    pub fn is_authorized(&self, address: &NodeAddress) -> bool {
        self.authorized_addresses.contains(address)
    }
}

impl Default for AuthorizedNodes {
    fn default() -> Self {
        Self::new()
    }
}
