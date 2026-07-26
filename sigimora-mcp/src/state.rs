//! Node state management for MCP protocol.
//!
//! Similar to BFT state but tracks MCP-specific phases and ZKP receipts.

use serde::{Deserialize, Serialize};
use sigimora_crypto::pedersen::PedersenSetup;
use sigimora_math::{G2Point, Scalar};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodePhase {
    Idle,
    DkgCommit,
    DkgShare,
    DkgVerify,
    Ready,
    MpcSigningCommit,
    MpcSigningReveal,
    MpcSigningCombine,
    Refreshing,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedState {
    pub node_id: u16,
    pub n: usize,
    pub t: usize,
    pub phase: String,
    pub epoch: u64,
    pub known_nodes: Vec<KnownNode>,
    pub connected_nodes: Vec<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KnownNode {
    pub node_id: u16,
    pub listen_addr: Option<String>,
    pub is_connected: bool,
    pub is_bootstrap: bool,
}

#[derive(Clone, Debug)]
pub struct NodeState {
    pub phase: NodePhase,
    pub node_id: u16,
    pub n: usize,
    pub t: usize,
    pub my_key: Option<Scalar>,
    pub my_public_key: Option<G2Point>,
    pub all_public_keys: HashMap<u16, G2Point>,
    pub pedersen: PedersenSetup,
    pub connected_peers: HashSet<u16>,
    pub peer_addresses: HashMap<u16, String>,
    pub signature_cache: HashMap<String, Vec<u8>>,
    pub pending_signatures: HashMap<String, Vec<(u16, Vec<u8>)>>,
    pub network_key: String,
    pub my_listen_addr: Option<String>,
    pub zkp_verified_commits: HashMap<u16, bool>,
}

impl NodeState {
    pub fn new(node_id: u16, n: usize, t: usize) -> Self {
        let pedersen = PedersenSetup::deterministic();
        NodeState {
            phase: NodePhase::Idle,
            node_id,
            n,
            t,
            my_key: None,
            my_public_key: None,
            all_public_keys: HashMap::new(),
            pedersen,
            connected_peers: HashSet::new(),
            peer_addresses: HashMap::new(),
            signature_cache: HashMap::new(),
            pending_signatures: HashMap::new(),
            network_key: String::new(),
            my_listen_addr: None,
            zkp_verified_commits: HashMap::new(),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.phase == NodePhase::Ready
    }

    pub fn quorum_size(&self) -> usize {
        self.t + 1
    }

    pub fn add_peer(&mut self, peer_id: u16) {
        if self.connected_peers.insert(peer_id) {
            println!("[MCP-NETWORK] Node {} connected! (Total: {}/{})", peer_id, self.connected_peers.len(), self.n);
        }
    }

    pub fn remove_peer(&mut self, peer_id: u16) {
        if self.connected_peers.remove(&peer_id) {
            println!("[MCP-NETWORK] Node {} disconnected! (Total: {}/{})", peer_id, self.connected_peers.len(), self.n);
        }
    }

    pub fn all_peers_connected(&self) -> bool {
        self.connected_peers.len() >= self.n - 1
    }

    pub fn get_network_summary(&self) -> NetworkSummary {
        let all_nodes: Vec<KnownNode> = (1..=self.n as u16).map(|id| {
            KnownNode {
                node_id: id,
                listen_addr: self.peer_addresses.get(&id).cloned(),
                is_connected: self.connected_peers.contains(&id),
                is_bootstrap: id == 1,
            }
        }).collect();

        NetworkSummary {
            node_id: self.node_id,
            n: self.n,
            t: self.t,
            phase: format!("{:?}", self.phase),
            connected_peers: self.connected_peers.len(),
            all_nodes,
            my_listen_addr: self.my_listen_addr.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct NetworkSummary {
    pub node_id: u16,
    pub n: usize,
    pub t: usize,
    pub phase: String,
    pub connected_peers: usize,
    pub all_nodes: Vec<KnownNode>,
    pub my_listen_addr: Option<String>,
}
