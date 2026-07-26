//! Transaction Ledger adapted for MCP protocol.
//!
//! Same three-tier state but with MCP-specific fields for ZKP receipts.

use serde::{Deserialize, Serialize};
use sigimora_ats::{AtsSignature, ParticipantId, PartialSignature};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const EXPIRY_SECONDS: u64 = 24 * 60 * 60;

pub type TxId = String;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovedTransaction {
    pub id: TxId,
    pub payload: Vec<u8>,
    pub signature: AtsSignature,
    pub signers: Vec<ParticipantId>,
    pub submitted_by: ParticipantId,
    pub submitted_at: u64,
    pub approved_at: u64,
    pub height: u64,
    pub zkp_threshold_verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingTransaction {
    pub id: TxId,
    pub payload: Vec<u8>,
    pub partial_sigs: Vec<PartialSignature>,
    pub submitted_by: ParticipantId,
    pub submitted_at: u64,
    pub threshold: usize,
    pub zkp_compliance_verified: Vec<ParticipantId>,
}

impl PendingTransaction {
    pub fn is_expired(&self) -> bool {
        let now = now_secs();
        now.saturating_sub(self.submitted_at) > EXPIRY_SECONDS
    }

    pub fn is_threshold_met(&self) -> bool {
        let unique: std::collections::HashSet<ParticipantId> =
            self.partial_sigs.iter().map(|p| p.node_id).collect();
        unique.len() >= self.threshold
    }

    pub fn add_partial(&mut self, partial: PartialSignature) -> bool {
        if self.partial_sigs.iter().any(|p| p.node_id == partial.node_id) {
            return self.is_threshold_met();
        }
        self.partial_sigs.push(partial);
        self.is_threshold_met()
    }

    pub fn signer_count(&self) -> usize {
        let unique: std::collections::HashSet<ParticipantId> =
            self.partial_sigs.iter().map(|p| p.node_id).collect();
        unique.len()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RejectedTransaction {
    pub id: TxId,
    pub payload: Vec<u8>,
    pub partial_count: usize,
    pub threshold: usize,
    pub submitted_by: ParticipantId,
    pub submitted_at: u64,
    pub rejected_at: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct TransactionLedger {
    pub approved: HashMap<TxId, ApprovedTransaction>,
    pub pending: HashMap<TxId, PendingTransaction>,
    pub rejected: HashMap<TxId, RejectedTransaction>,
    pub height: u64,
}

impl TransactionLedger {
    pub fn new() -> Self {
        TransactionLedger::default()
    }

    pub fn submit(
        &mut self,
        payload: Vec<u8>,
        submitted_by: ParticipantId,
        threshold: usize,
    ) -> TxId {
        let id = compute_tx_id(&payload);

        if self.approved.contains_key(&id) || self.pending.contains_key(&id) {
            return id;
        }

        let pending = PendingTransaction {
            id: id.clone(),
            payload,
            partial_sigs: Vec::new(),
            submitted_by,
            submitted_at: now_secs(),
            threshold,
            zkp_compliance_verified: Vec::new(),
        };

        self.pending.insert(id.clone(), pending);
        id
    }

    pub fn add_partial_signature(
        &mut self,
        tx_id: &str,
        partial: PartialSignature,
    ) -> Option<TxId> {
        if let Some(pending) = self.pending.get_mut(tx_id) {
            if pending.add_partial(partial) {
                return Some(tx_id.to_string());
            }
        }
        None
    }

    pub fn approve(
        &mut self,
        tx_id: &str,
        signature: AtsSignature,
    ) -> Option<ApprovedTransaction> {
        if let Some(pending) = self.pending.remove(tx_id) {
            self.height += 1;
            let approved = ApprovedTransaction {
                id: pending.id.clone(),
                payload: pending.payload,
                signature: signature.clone(),
                signers: signature.quorum.clone(),
                submitted_by: pending.submitted_by,
                submitted_at: pending.submitted_at,
                approved_at: now_secs(),
                height: self.height,
                zkp_threshold_verified: false,
            };
            self.approved.insert(pending.id.clone(), approved.clone());
            Some(approved)
        } else {
            None
        }
    }

    pub fn sweep_expired(&mut self) -> usize {
        let expired_ids: Vec<TxId> = self
            .pending
            .iter()
            .filter(|(_, tx)| tx.is_expired())
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired_ids.len();
        for id in expired_ids {
            if let Some(pending) = self.pending.remove(&id) {
                let sig_count = pending.signer_count();
                let rejected = RejectedTransaction {
                    id: pending.id.clone(),
                    partial_count: sig_count,
                    threshold: pending.threshold,
                    submitted_by: pending.submitted_by,
                    submitted_at: pending.submitted_at,
                    rejected_at: now_secs(),
                    reason: format!(
                        "Expired: {}/{} signatures after 24h",
                        sig_count,
                        pending.threshold
                    ),
                    payload: pending.payload,
                };
                self.rejected.insert(pending.id, rejected);
            }
        }
        count
    }

    pub fn find_transaction(&self, tx_id: &str) -> Option<TransactionInfo> {
        if let Some(tx) = self.approved.get(tx_id) {
            return Some(TransactionInfo::Approved(tx.clone()));
        }
        if let Some(tx) = self.pending.get(tx_id) {
            return Some(TransactionInfo::Pending(tx.clone()));
        }
        if let Some(tx) = self.rejected.get(tx_id) {
            return Some(TransactionInfo::Rejected(tx.clone()));
        }
        None
    }

    pub fn stats(&self) -> LedgerStats {
        LedgerStats {
            approved: self.approved.len(),
            pending: self.pending.len(),
            rejected: self.rejected.len(),
            height: self.height,
        }
    }
}

#[derive(Clone, Debug)]
pub enum TransactionInfo {
    Approved(ApprovedTransaction),
    Pending(PendingTransaction),
    Rejected(RejectedTransaction),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerStats {
    pub approved: usize,
    pub pending: usize,
    pub rejected: usize,
    pub height: u64,
}

fn compute_tx_id(payload: &[u8]) -> TxId {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let result = hasher.finalize();
    hex::encode(result)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
