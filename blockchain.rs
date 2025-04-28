use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use sha3::Sha3_256;
use sha2::{Sha256, Digest as Sha2Digest};
use hex;
use p256::AffinePoint;
use p256::ecdsa::{VerifyingKey, SigningKey,};
use ecdsa::Signature;
use merkletree::store::VecStore;
use merkletree::merkle::MerkleTree;
use super::utils::Sha256Algorithm;
use super::cryptography::verify_transaction;
use tracing::error;

#[derive(Clone)]
pub struct Peer {
    pub addr: SocketAddr,
    pub public_key: VerifyingKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub public_key: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Transaction {
    pub sender: String,
    pub receiver: String,
    pub amount: f64,
    pub fee: f64,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UserData {
    pub user_id: String,
    pub profile: Option<Vec<u8>>,
    pub messages: Vec<Vec<u8>>,
    pub encryption_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BlockHeader {
    pub index: u64,
    pub timestamp: u64,
    pub previous_hash: String,
    pub merkle_root: String,
    pub hash: String,
    pub nonce: u64,
    pub difficulty: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub user_data: Vec<UserData>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct PendingPool {
    pub transactions: Vec<Transaction>,
    pub user_data: Vec<UserData>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Balance {
    pub balances: std::collections::HashMap<String, f64>,
}

#[derive(Serialize, Deserialize)]
pub struct NodeKey {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub fn calculate_merkle_root(_transactions: &[Transaction]) -> String {
    let leaves: Vec<Vec<u8>> = _transactions.iter()
        .map(|tx| {
            let input = format!("{}{}{}{}", tx.sender, tx.receiver, tx.amount, tx.fee);
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            hasher.finalize().to_vec()
        })
        .collect();
    if leaves.is_empty() {
        return "0".to_string();
    }
    let tree = MerkleTree::<[u8; 32], Sha256Algorithm, VecStore<_>>::try_from_iter(leaves.iter().map(|leaf| {
        let mut array = [0u8; 32];
        array.copy_from_slice(&leaf[..32]);
        Ok(array)
    })).expect("Failed to create merkle tree");
    hex::encode(tree.root())
}

pub fn calculate_hash(header: &BlockHeader, _transactions: &[Transaction]) -> String {
    let input = format!(
        "{}{}{}{}",
        header.index,
        header.timestamp,
        header.merkle_root,
        header.previous_hash
    );
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    let result = hasher.finalize();
    hex::encode(result)
}

pub fn mine_block(header: &mut BlockHeader, _transactions: &[Transaction]) -> bool {
    let target = "0".repeat(header.difficulty as usize);
    while header.nonce < u64::MAX {
        header.hash = calculate_hash(header, _transactions);
        if header.hash.starts_with(&target) {
            return true;
        }
        header.nonce += 1;
    }
    false
}

pub fn calculate_difficulty(chain: &[Block], target_time: u64) -> u32 {
    if chain.len() < 2 {
        return 4;
    }
    let last_block = chain.last().unwrap();
    let prev_block = chain.get(chain.len() - 2).unwrap();
    let time_diff = last_block.header.timestamp - prev_block.header.timestamp;
    if time_diff < target_time / 2 {
        last_block.header.difficulty + 1
    } else if time_diff > target_time * 2 {
        last_block.header.difficulty.saturating_sub(1).max(1)
    } else {
        last_block.header.difficulty
    }
}

pub async fn validate_block(block: &Block, previous_block: &Block, peers: &Arc<Mutex<Vec<Peer>>>, _balances: &Arc<Mutex<Balance>>) -> bool {
    if block.header.index != previous_block.header.index + 1 {
        return false;
    }
    if block.header.previous_hash != previous_block.header.hash {
        return false;
    }
    let calculated_merkle_root = calculate_merkle_root(&block.transactions);
    if calculated_merkle_root != block.header.merkle_root {
        return false;
    }
    let calculated_hash = calculate_hash(&block.header, &block.transactions);
    if calculated_hash != block.header.hash {
        return false;
    }
    if !block.header.hash.starts_with(&"0".repeat(block.header.difficulty as usize)) {
        return false;
    }
    let _peers_lock = peers.lock().await;
    let mut balances_lock = _balances.lock().await;
    for tx in &block.transactions {
        let public_key_bytes = hex::decode(&tx.sender).unwrap_or_default();
        let public_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
            .unwrap_or(VerifyingKey::from_affine(AffinePoint::default()).unwrap());
        if !verify_transaction(tx, &public_key) {
            return false;
        }
        let total_amount = tx.amount + tx.fee;
        let sender_balance = balances_lock.balances.entry(tx.sender.clone()).or_insert(1000.0);
        if *sender_balance < total_amount {
            return false;
        }
        *sender_balance -= total_amount;
        let receiver_balance = balances_lock.balances.entry(tx.receiver.clone()).or_insert(0.0);
        *receiver_balance += tx.amount;
        let miner = block.transactions.get(0).map(|t| t.sender.clone()).unwrap_or_default();
        let miner_balance = balances_lock.balances.entry(miner).or_insert(0.0);
        *miner_balance += tx.fee;
    }
    let miner = block.transactions.get(0).map(|t| t.sender.clone()).unwrap_or_default();
    let miner_balance = balances_lock.balances.entry(miner).or_insert(0.0);
    *miner_balance += super::MINING_REWARD;
    true
}

pub async fn resolve_chain(blockchain: Arc<Mutex<Vec<Block>>>, new_chain: Vec<Block>, peers: Arc<Mutex<Vec<Peer>>>, _balances: Arc<Mutex<Balance>>) -> bool {
    let mut blockchain_lock = blockchain.lock().await;
    if new_chain.len() <= blockchain_lock.len() {
        return false;
    }
    let genesis = Block {
        header: BlockHeader {
            index: 0,
            timestamp: 0,
            previous_hash: "0".to_string(),
            merkle_root: "0".to_string(),
            hash: "0".to_string(),
            nonce: 0,
            difficulty: 4,
        },
        transactions: vec![],
        user_data: vec![],
    };
    let mut prev_block = new_chain.first().unwrap_or(&genesis);
    let temp_balances = _balances.lock().await.clone();
    drop(temp_balances);
    for block in new_chain.iter().skip(1) {
        if !validate_block(block, prev_block, &peers, &_balances).await {
            return false;
        }
        prev_block = block;
    }
    *blockchain_lock = new_chain;
    drop(blockchain_lock);
    for block in blockchain.lock().await.iter() {
        if let Err(e) = super::storage::save_block_to_file(block).await {
            error!("Failed to save block {}: {}", block.header.index, e);
        }
    }
    let balances_clone = _balances.lock().await.clone();
    if let Err(e) = super::storage::save_balances(&balances_clone).await {
        error!("Failed to save balances: {}", e);
    }
    true
}