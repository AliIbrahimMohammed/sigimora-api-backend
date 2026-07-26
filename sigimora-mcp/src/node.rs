//! MCP Node: connects TCP P2P network with MPC threshold signing.
//!
//! This is the core of the MCP-based SIGIMORA system:
//! - No leader election (all peers are equal in MPC)
//! - DKG runs in rounds (commit → share → verify)
//! - Signing runs in rounds (commit → reveal → combine → verify)
//! - ZKP verification at each step

use crate::error::McpError;
use crate::network::{McpNetworkNode, NetworkConfig};
use crate::protocol::McpMessage;
use sigimora_math::Scalar;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct McpNode {
    pub network: Option<McpNetworkNode>,
    config: NetworkConfig,
    state: Arc<RwLock<NodeState>>,
    identity_sk: Option<Scalar>,
}

#[derive(Debug, Clone)]
pub struct NodeState {
    pub node_id: u16,
    pub phase: NodePhase,
    pub connected_peers: usize,
    pub height: u64,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NodePhase {
    Init,
    Connected,
    DkgActive,
    Ready,
    MpcSigning,
    Refreshing,
}

impl McpNode {
    pub fn new(
        node_id: u16,
        listen_addr: &str,
        network_id: &str,
        n: usize,
        t: usize,
    ) -> Result<Self, McpError> {
        Self::with_identity(node_id, listen_addr, network_id, n, t, None)
    }

    pub fn with_identity(
        node_id: u16,
        listen_addr: &str,
        _network_id: &str,
        n: usize,
        t: usize,
        identity_sk: Option<Scalar>,
    ) -> Result<Self, McpError> {
        let config = NetworkConfig {
            node_id,
            listen_addr: listen_addr.to_string(),
            bootstrap_nodes: vec![],
            n,
            t,
        };

        Ok(Self {
            network: None,
            config,
            state: Arc::new(RwLock::new(NodeState {
                node_id,
                phase: NodePhase::Init,
                connected_peers: 0,
                height: 0,
                epoch: 0,
            })),
            identity_sk,
        })
    }

    pub async fn start(&mut self) -> Result<String, McpError> {
        let network = McpNetworkNode::with_identity_key(self.config.clone(), self.identity_sk.clone())?;
        let addr = network.start_listener().await?;

        self.network = Some(network);
        {
            let mut s = self.state.write().await;
            s.phase = NodePhase::Connected;
        }

        Ok(addr)
    }

    pub async fn connect_to_bootstrap(&mut self, addr: &str) -> Result<u16, McpError> {
        if let Some(ref network) = self.network {
            network.connect_to_peer(addr).await
        } else {
            Err(McpError::NetworkError("Network not started".to_string()))
        }
    }

    pub async fn broadcast_message(&self, msg: &McpMessage) -> Result<usize, McpError> {
        if let Some(ref network) = self.network {
            network.broadcast(msg).await
        } else {
            Err(McpError::NetworkError("Network not started".to_string()))
        }
    }

    pub async fn get_status(&self) -> NodeStatus {
        let state = self.state.read().await;
        let peer_count = if let Some(ref network) = self.network {
            network.peer_count().await
        } else {
            0
        };

        NodeStatus {
            node_id: state.node_id,
            phase: format!("{:?}", state.phase),
            connected_peers: peer_count,
            height: state.height,
            epoch: state.epoch,
            network_id: "sigimora-mcp".to_string(),
        }
    }

    pub fn subscribe(&self) -> Option<tokio::sync::broadcast::Receiver<(u16, McpMessage)>> {
        self.network.as_ref().map(|n| n.subscribe())
    }
}

pub struct NodeStatus {
    pub node_id: u16,
    pub phase: String,
    pub connected_peers: usize,
    pub height: u64,
    pub epoch: u64,
    pub network_id: String,
}

pub async fn start_mcp_node(
    node_id: u16,
    listen_addr: &str,
    bootstrap_nodes: Vec<String>,
    network_id: &str,
    n: usize,
    t: usize,
    identity_sk: Option<Scalar>,
) -> Result<(), McpError> {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║  SIGIMORA — MPC Threshold Signing Network               ║");
    println!("╠═══════════════════════════════════════════════════════════╣");
    println!("║  Protocol: Multi-Party Computation (MCP)                  ║");
    println!("║  Features: ZKP-Verified Stake, Compliance, Threshold      ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();

    let mut node = McpNode::with_identity(node_id, listen_addr, network_id, n, t, identity_sk)?;
    let addr = node.start().await?;

    println!();
    println!("═══════════════════════════════════════════════════════════");
    println!("  ✅ MCP NODE STARTED SUCCESSFULLY");
    println!("═══════════════════════════════════════════════════════════");
    println!();
    println!("  📋 NODE INFO:");
    println!("     Node ID:    {}", node_id);
    println!("     Listen:     {}", addr);
    println!("     Network:    {}", network_id);
    println!("     N={}, T={}, Quorum={}", n, t, t + 1);
    println!();
    println!("  MPC Protocol Rounds:");
    println!("     DKG:   Commit → Share → Verify");
    println!("     SIGN:  Commit → Reveal → Combine → Verify ZKP");
    println!();

    for bootstrap in &bootstrap_nodes {
        match node.connect_to_bootstrap(bootstrap).await {
            Ok(peer_id) => println!("  ✅ Connected to bootstrap node {}电子 at {}", peer_id, bootstrap),
            Err(e) => println!("  ❌ Failed to connect to {}: {}", bootstrap, e),
        }
    }

    println!();
    println!("═══════════════════════════════════════════════════════════");
    println!("  📊 LIVE STATUS (Ctrl+C to stop)");
    println!("═══════════════════════════════════════════════════════════");
    println!();

    let mut tick = 0u64;
    loop { // Changed use to if let Some for better error handling
        tokio::select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {
                tick += 1;
                let status = node.get_status().await;
                println!("[MCP-{}] Node {} | Phase: {} | Peers: {} | Height: {} | Epoch: {}",
                    tick, status.node_id, status.phase, status.connected_peers, status.height, status.epoch);
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\n[🛑] Shutting down MCP node...");
                break;
            }
        }
    }
    Ok(())
}
