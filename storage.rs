use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde_json;
use super::blockchain::{PeerInfo, Block, PendingPool, Balance};
use tracing::error;

pub async fn save_peer_list(peers: &[PeerInfo]) -> Result<(), String> {
    let path = "peers.json";
    let json = serde_json::to_string(peers).map_err(|e| format!("Failed to serialize peers: {}", e))?;
    tokio::fs::write(path, json).await
        .map_err(|e| format!("Failed to write peers: {}", e))?;
    Ok(())
}

pub async fn load_peer_list() -> Result<Vec<PeerInfo>, String> {
    let path = "peers.json";
    if !Path::new(path).exists() {
        return Ok(vec![]);
    }
    let contents = tokio::fs::read_to_string(path).await
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;
    let peers: Vec<PeerInfo> = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse {}: {}", path, e))?;
    Ok(peers)
}

pub async fn save_block_to_file(block: &Block) -> Result<(), String> {
    let path = format!("blocks/block_{}.json", block.header.index);
    tokio::fs::create_dir_all("blocks").await
        .map_err(|e| format!("Failed to create blocks dir: {}", e))?;
    let json = serde_json::to_string(block).map_err(|e| format!("Failed to serialize block: {}", e))?;
    tokio::fs::write(&path, json).await
        .map_err(|e| format!("Failed to write block: {}", e))?;
    Ok(())
}

pub async fn load_blockchain() -> Result<Vec<Block>, String> {
    let mut chain = Vec::new();
    if !Path::new("blocks").exists() {
        return Ok(chain);
    }
    let mut entries = tokio::fs::read_dir("blocks").await
        .map_err(|e| format!("Failed to read blocks dir: {}", e))?;
    let mut block_files = Vec::new();
    while let Some(entry) = entries.next_entry().await.map_err(|e| format!("Failed to read dir: {}", e))? {
        if entry.path().extension().map(|ext| ext == "json").unwrap_or(false) {
            block_files.push(entry);
        }
    }
    block_files.sort_by_key(|e| e.path().to_string_lossy().to_string());
    for entry in block_files {
        let path = entry.path();
        let contents = tokio::fs::read_to_string(&path).await
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        let block: Block = serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;
        chain.push(block);
    }
    Ok(chain)
}

pub async fn save_pending_pool(pool: &PendingPool) -> Result<(), String> {
    let path = "pending_pool.json";
    let json = serde_json::to_string(pool).map_err(|e| format!("Failed to serialize pool: {}", e))?;
    tokio::fs::write(path, json).await
        .map_err(|e| format!("Failed to write pool: {}", e))?;
    Ok(())
}

pub async fn load_pending_pool() -> Result<PendingPool, String> {
    let path = "pending_pool.json";
    if !Path::new(path).exists() {
        return Ok(PendingPool { transactions: vec![], user_data: vec![] });
    }
    let contents = tokio::fs::read_to_string(path).await
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;
    let pool: PendingPool = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse {}: {}", path, e))?;
    Ok(pool)
}

pub async fn save_balances(_balances: &Balance) -> Result<(), String> {
    let path = "balances.json";
    let json = serde_json::to_string(_balances).map_err(|e| format!("Failed to serialize balances: {}", e))?;
    tokio::fs::write(path, json).await
        .map_err(|e| format!("Failed to write balances: {}", e))?;
    Ok(())
}

pub async fn load_balances() -> Result<Balance, String> {
    let path = "balances.json";
    if !Path::new(path).exists() {
        return Ok(Balance { balances: std::collections::HashMap::new() });
    }
    let contents = tokio::fs::read_to_string(path).await
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;
    let balances: Balance = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse {}: {}", path, e))?;
    Ok(balances)
}

pub async fn delete_user_data(blockchain: Arc<Mutex<Vec<Block>>>, user_id: &str) {
    let mut modified = false;
    {
        let mut blockchain_lock = blockchain.lock().await;
        for block in blockchain_lock.iter_mut() {
            for user_data in block.user_data.iter_mut() {
                if user_data.user_id == user_id {
                    user_data.profile = None;
                    user_data.messages.clear();
                    modified = true;
                }
            }
        }
    }
    if modified {
        let blocks_to_save = blockchain.lock().await.clone();
        for block in blocks_to_save {
            if let Err(e) = save_block_to_file(&block).await {
                error!("Failed to save block {}: {}", block.header.index, e);
            }
        }
    }
}