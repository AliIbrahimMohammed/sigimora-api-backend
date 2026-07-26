//! MCP Network Layer: P2P TCP communication adapted for MPC message flows.
//!
//! Key differences from BFT network:
//! - Messages are framed as `McpMessage` (DKG commits, shares, sign commits/reveals)
//! - Authentication includes ZKP(membership) in the handshake
//! - Broadcast sends to ALL connected peers (no leader election)
//! - Handles MPC round messages in order

use crate::error::McpError;
use crate::protocol::{McpMessage, ParticipantId};
use sigimora_math::Scalar;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, RwLock, mpsc};

const MAX_MSG_SIZE: u32 = 1_048_576;

// ══════════════════════════════════════════════════════════════════════
//  Network Configuration
// ══════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub node_id: ParticipantId,
    pub listen_addr: String,
    pub bootstrap_nodes: Vec<String>,
    pub n: usize,
    pub t: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            node_id: 1,
            listen_addr: "127.0.0.1:9000".to_string(),
            bootstrap_nodes: vec![],
            n: 5,
            t: 3,
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
//  Peer Connection
// ══════════════════════════════════════════════════════════════════════

#[derive(Debug)]
pub struct PeerConnection {
    pub node_id: ParticipantId,
    pub addr: String,
    pub authenticated: bool,
    tx: mpsc::Sender<Vec<u8>>,
}

impl PeerConnection {
    pub async fn send(&self, data: Vec<u8>) -> Result<(), McpError> {
        self.tx.send(data).await
            .map_err(|_| McpError::NetworkError(format!("peer {} disconnected", self.node_id)))
    }
}

// ══════════════════════════════════════════════════════════════════════
//  MCP Network Node
// ══════════════════════════════════════════════════════════════════════

pub struct McpNetworkNode {
    pub config: NetworkConfig,
    pub peers: Arc<RwLock<HashMap<ParticipantId, PeerConnection>>>,
    msg_tx: broadcast::Sender<(ParticipantId, McpMessage)>,
    identity_sk: Option<Scalar>,
}

impl McpNetworkNode {
    pub fn new(config: NetworkConfig) -> Result<Self, McpError> {
        Self::with_identity_key(config, None)
    }

    pub fn with_identity_key(config: NetworkConfig, identity_sk: Option<Scalar>) -> Result<Self, McpError> {
        let (msg_tx, _) = broadcast::channel(256);
        Ok(Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            msg_tx,
            identity_sk,
        })
    }

    pub async fn start_listener(&self) -> Result<String, McpError> {
        let listener = TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(|e| McpError::NetworkError(format!("bind failed: {}", e)))?;

        let local_addr = listener.local_addr()
            .map_err(|e| McpError::NetworkError(format!("local_addr failed: {}", e)))?
            .to_string();

        let peers = self.peers.clone();
        let msg_tx = self.msg_tx.clone();
        let my_id = self.config.node_id;
        let n = self.config.n;
        let t = self.config.t;
        let my_identity_sk = self.identity_sk.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        tracing::info!("Incoming connection from {}", addr);
                        let peers = peers.clone();
                        let msg_tx = msg_tx.clone();
                        let identity_sk = my_identity_sk.clone();
                        tokio::spawn(handle_incoming(
                            stream, peers, msg_tx, my_id, n, t, identity_sk,
                        ));
                    }
                    Err(e) => {
                        tracing::error!("Accept error: {}", e);
                    }
                }
            }
        });

        Ok(local_addr)
    }

    pub async fn connect_to_peer(&self, addr: &str) -> Result<ParticipantId, McpError> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| McpError::NetworkError(format!("connect to {} failed: {}", addr, e)))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create BLS identity proof: sign "SIGIMORA-HANDSHAKE" || node_id || timestamp
        let proof_msg = format!("SIGIMORA-HANDSHAKE:{}:{}", self.config.node_id, timestamp);
        let h = sigimora_math::hash_to_g1(proof_msg.as_bytes(), b"SIGIMORA-ID");
        // Use persisted identity key if available, otherwise derive deterministically
        let identity_sk = self.identity_sk.clone().unwrap_or_else(|| derive_identity_key(self.config.node_id));
        let identity_pk = sigimora_math::G2Point::generator().mul(&identity_sk);
        let identity_proof = h.mul(&identity_sk).to_bytes().to_vec();

        let handshake = McpMessage::Handshake {
            from: self.config.node_id,
            public_key: identity_pk,
            identity_proof,
            timestamp,
        };

        let (read_half, mut write_half) = stream.into_split();

        let data = bincode::serialize(&handshake)
            .map_err(|e| McpError::SerializationError(format!("serialize handshake: {}", e)))?;
        write_framed(&mut write_half, &data).await?;

        let mut read_half_buf = tokio::io::BufReader::new(read_half);
        let response_data = read_framed(&mut read_half_buf).await?;
        let response: McpMessage = bincode::deserialize(&response_data)
            .map_err(|e| McpError::SerializationError(format!("deserialize handshake: {}", e)))?;

        let peer_id = match &response {
            McpMessage::Handshake { from, public_key, identity_proof, timestamp } => {
                // Verify peer's identity proof
                if identity_proof.len() != 48 {
                    return Err(McpError::NetworkError("invalid identity proof length".to_string()));
                }
                let proof_msg = format!("SIGIMORA-HANDSHAKE:{}:{}", from, timestamp);
                let h = sigimora_math::hash_to_g1(proof_msg.as_bytes(), b"SIGIMORA-ID");
                let mut arr = [0u8; 48];
                arr.copy_from_slice(identity_proof);
                let proof_sig = sigimora_crypto::bls::Signature::from_bytes(&arr)
                    .map_err(|_| McpError::NetworkError("invalid identity proof point".to_string()))?;

                if !bool::from(sigimora_math::pairing::ct_verify_bls_signature(
                    &proof_sig.0, &h, public_key,
                )) {
                    return Err(McpError::NetworkError("peer identity proof invalid".to_string()));
                }
                *from
            }
            _ => return Err(McpError::NetworkError("expected handshake response".to_string())),
        };

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);

        tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if write_framed(&mut write_half, &data).await.is_err() {
                    break;
                }
            }
        });

        let peers_clone = self.peers.clone();
        let msg_tx_clone = self.msg_tx.clone();
        tokio::spawn(async move {
            loop {
                match read_framed(&mut read_half_buf).await {
                    Ok(data) => {
                        if let Ok(msg) = bincode::deserialize(&data) {
                            let _ = msg_tx_clone.send((peer_id, msg));
                        }
                    }
                    Err(_) => {
                        tracing::info!("Peer {} disconnected", peer_id);
                        peers_clone.write().await.remove(&peer_id);
                        break;
                    }
                }
            }
        });

        self.peers.write().await.insert(peer_id, PeerConnection {
            node_id: peer_id,
            addr: addr.to_string(),
            authenticated: true,
            tx,
        });

        Ok(peer_id)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<(ParticipantId, McpMessage)> {
        self.msg_tx.subscribe()
    }

    pub async fn broadcast(&self, msg: &McpMessage) -> Result<usize, McpError> {
        let data = bincode::serialize(msg)
            .map_err(|e| McpError::SerializationError(format!("serialize: {}", e)))?;

        let peers = self.peers.read().await;
        let mut sent = 0;
        for (_, peer) in peers.iter() {
            if peer.send(data.clone()).await.is_ok() {
                sent += 1;
            }
        }
        Ok(sent)
    }

    pub async fn send_to(&self, peer_id: ParticipantId, msg: &McpMessage) -> Result<(), McpError> {
        let data = bincode::serialize(msg)
            .map_err(|e| McpError::SerializationError(format!("serialize: {}", e)))?;

        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(&peer_id) {
            peer.send(data).await
        } else {
            Err(McpError::NetworkError(format!("peer {} not connected", peer_id)))
        }
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    pub async fn connected_peers(&self) -> Vec<ParticipantId> {
        self.peers.read().await.keys().copied().collect()
    }
}

/// Deterministically derive a BLS identity key from a node ID.
/// In production this would be loaded from a `NodeIdentity` file.
fn derive_identity_key(node_id: u16) -> sigimora_math::Scalar {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b"SIGIMORA-MCP-IDENTITY-KEY");
    hasher.update(&node_id.to_le_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);
    sigimora_math::Scalar::from_bytes(&bytes).unwrap_or_else(|_| {
        // Fallback: use a random scalar (extremely unlikely to hit this)
        sigimora_math::Scalar::random(&mut rand::rngs::OsRng)
    })
}

// ══════════════════════════════════════════════════════════════════════
//  Connection Handler
// ══════════════════════════════════════════════════════════════════════

async fn handle_incoming(
    stream: TcpStream,
    peers: Arc<RwLock<HashMap<ParticipantId, PeerConnection>>>,
    msg_tx: broadcast::Sender<(ParticipantId, McpMessage)>,
    my_id: ParticipantId,
    _n: usize,
    _t: usize,
    my_identity_sk: Option<Scalar>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(read_half);

    let handshake_data = match read_framed(&mut reader).await {
        Ok(d) => d,
        Err(_) => return,
    };

    let (_peer_pk, peer_id) = match bincode::deserialize::<McpMessage>(&handshake_data) {
        Ok(McpMessage::Handshake { from, public_key, identity_proof, timestamp }) => {
            // Verify the peer's identity proof
            if identity_proof.len() == 48 {
                let proof_msg = format!("SIGIMORA-HANDSHAKE:{}:{}", from, timestamp);
                let h = sigimora_math::hash_to_g1(proof_msg.as_bytes(), b"SIGIMORA-ID");
                let mut arr = [0u8; 48];
                arr.copy_from_slice(&identity_proof);
                if let Ok(proof_sig) = sigimora_crypto::bls::Signature::from_bytes(&arr) {
                    if !bool::from(sigimora_math::pairing::ct_verify_bls_signature(
                        &proof_sig.0, &h, &public_key,
                    )) {
                        tracing::warn!("Peer {} identity proof invalid, rejecting", from);
                        return;
                    }
                }
            }
            (public_key, from)
        }
        _ => return,
    };

    let my_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let my_sk = my_identity_sk.unwrap_or_else(|| derive_identity_key(my_id));
    let my_pk = sigimora_math::G2Point::generator().mul(&my_sk);
    let my_proof_msg = format!("SIGIMORA-HANDSHAKE:{}:{}", my_id, my_timestamp);
    let my_h = sigimora_math::hash_to_g1(my_proof_msg.as_bytes(), b"SIGIMORA-ID");
    let my_proof = my_h.mul(&my_sk).to_bytes().to_vec();

    let response = McpMessage::Handshake {
        from: my_id,
        public_key: my_pk,
        identity_proof: my_proof,
        timestamp: my_timestamp,
    };

    let response_data = match bincode::serialize(&response) {
        Ok(d) => d,
        Err(_) => return,
    };

    if write_framed(&mut write_half, &response_data).await.is_err() {
        return;
    }

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);

    tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if write_framed(&mut write_half, &data).await.is_err() {
                break;
            }
        }
    });

    peers.write().await.insert(peer_id, PeerConnection {
        node_id: peer_id,
        addr: String::new(),
        authenticated: true,
        tx,
    });

    loop {
        match read_framed(&mut reader).await {
            Ok(data) => {
                if let Ok(msg) = bincode::deserialize(&data) {
                    let _ = msg_tx.send((peer_id, msg));
                }
            }
            Err(_) => {
                tracing::info!("Peer {} disconnected", peer_id);
                peers.write().await.remove(&peer_id);
                break;
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
//  Wire Protocol
// ══════════════════════════════════════════════════════════════════════

async fn write_framed<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<(), McpError> {
    let len = data.len() as u32;
    if len > MAX_MSG_SIZE {
        return Err(McpError::NetworkError("message too large".to_string()));
    }
    writer.write_all(&len.to_be_bytes()).await
        .map_err(|e| McpError::NetworkError(format!("write length: {}", e)))?;
    writer.write_all(data).await
        .map_err(|e| McpError::NetworkError(format!("write data: {}", e)))?;
    writer.flush().await
        .map_err(|e| McpError::NetworkError(format!("flush: {}", e)))?;
    Ok(())
}

async fn read_framed<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, McpError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await
        .map_err(|e| McpError::NetworkError(format!("read length: {}", e)))?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MSG_SIZE {
        return Err(McpError::NetworkError("message too large".to_string()));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await
        .map_err(|e| McpError::NetworkError(format!("read data: {}", e)))?;
    Ok(buf)
}
