use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc::Sender, Mutex};
use tokio::time::sleep;
use tokio::process::Command;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_rustls::rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
use tokio_rustls::rustls::client::ServerName;
use serde::{Serialize, Deserialize};
use serde_json;
use sha3::Sha3_256;
use sha2::{Sha256, Digest as Sha2Digest};
use hex;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use ecdsa::Signature;
use ecdsa::signature::{Signer, Verifier};
use p256::{ecdsa::{SigningKey, VerifyingKey}, SecretKey, AffinePoint};
use rand::rngs::OsRng;
use tracing::{info, error};
use tracing_subscriber::{fmt, EnvFilter, Layer};
use tracing_subscriber::prelude::*;
use std::fs::File;
use merkletree::store::VecStore;
use merkletree::merkle::MerkleTree;
use merkletree::hash::Algorithm;
use igd::{SearchOptions, PortMappingProtocol};
use std::hash::Hasher as StdHasher;
use if_addrs::get_if_addrs;
use yasna::models::ObjectIdentifier;
use generic_array::GenericArray;
use typenum::U32;

const MAX_PEERS: usize = 50;
const BANDWIDTH_LIMIT: u64 = 1024 * 1024;
const MINING_REWARD: f64 = 50.0;
const TRANSACTION_FEE: f64 = 0.1;
const MINING_INTERVAL: u64 = 600;
const INITIAL_NODES: &[&str] = &["82.25.86.57", "47.17.52.8"];
const DEFAULT_PORT: u16 = 8080;

#[derive(Clone)]
struct Peer {
    addr: SocketAddr,
    public_key: VerifyingKey,
}

#[derive(Serialize, Deserialize, Clone)]
struct PeerInfo {
    addr: SocketAddr,
    public_key: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Transaction {
    sender: String,
    receiver: String,
    amount: f64,
    fee: f64,
    signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct UserData {
    user_id: String,
    profile: Option<Vec<u8>>,
    messages: Vec<Vec<u8>>,
    encryption_key: Vec<u8>,
    nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
struct BlockHeader {
    index: u64,
    timestamp: u64,
    previous_hash: String,
    merkle_root: String,
    hash: String,
    nonce: u64,
    difficulty: u32,
}

#[derive(Serialize, Deserialize, Clone)]
struct Block {
    header: BlockHeader,
    transactions: Vec<Transaction>,
    user_data: Vec<UserData>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct PendingPool {
    transactions: Vec<Transaction>,
    user_data: Vec<UserData>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct Balance {
    balances: std::collections::HashMap<String, f64>,
}

#[derive(Serialize, Deserialize)]
struct NodeKey {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

fn generate_key_pair() -> (SigningKey, VerifyingKey) {
    let secret_key = SecretKey::random(&mut OsRng);
    let signing_key = SigningKey::from(secret_key);
    let binding = signing_key.clone();
    let verifying_key = binding.verifying_key();
    (signing_key, *verifying_key)
}

fn load_or_generate_node_key() -> (SigningKey, VerifyingKey) {
    let path = "node_key.json";
    if Path::new(path).exists() {
        let contents = std::fs::read_to_string(path).expect("Failed to read node_key.json");
        let node_key: NodeKey = serde_json::from_str(&contents).expect("Failed to parse node_key.json");
        let signing_key = SigningKey::from_bytes(
            GenericArray::from_slice(&node_key.private_key)
        ).expect("Invalid private key");
        let verifying_key = VerifyingKey::from_sec1_bytes(&node_key.public_key).expect("Invalid public key");
        (signing_key, verifying_key)
    } else {
        let (signing_key, verifying_key) = generate_key_pair();
        let node_key = NodeKey {
            private_key: signing_key.to_bytes().to_vec(),
            public_key: verifying_key.to_encoded_point(false).as_bytes().to_vec(),
        };
        let mut file = File::create(path).expect("Failed to create node_key.json");
        let json = serde_json::to_string(&node_key).expect("Failed to serialize node key");
        file.write_all(json.as_bytes()).expect("Failed to write node_key.json");
        (signing_key, verifying_key)
    }
}

fn generate_user_key_nonce(user_id: &str) -> (Vec<u8>, Vec<u8>) {
    let mut hasher = Sha3_256::new();
    hasher.update(user_id);
    hasher.update(b"salt_for_weave");
    let result = hasher.finalize();
    let key = result[..32].to_vec();
    let nonce = result[32..44].to_vec();
    (key, nonce)
}

fn sign_transaction(tx: &Transaction, signing_key: &SigningKey) -> String {
    let input = format!("{}{}{}{}", tx.sender, tx.receiver, tx.amount, tx.fee);
    let mut hasher = Sha256::new();
hasher.update(input.as_bytes());
let digest = hasher.finalize(); // Use finalize directly
let signature: Signature<p256::NistP256> = signing_key.sign(&digest);
    hex::encode(signature.to_der().as_bytes())
}

fn verify_transaction(tx: &Transaction, verifying_key: &VerifyingKey) -> bool {
    let input = format!("{}{}{}{}", tx.sender, tx.receiver, tx.amount, tx.fee);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let finalized = hasher.finalize();
    let digest = GenericArray::<u8, U32>::from_slice(&finalized[..32]);
    let signature_bytes = hex::decode(&tx.signature).unwrap_or_default();
    match Signature::<p256::NistP256>::from_der(&signature_bytes) {
        Ok(signature) => verifying_key.verify(digest, &signature).is_ok(),
        Err(_) => false,
    }
}

fn generate_certificates() -> Result<(rcgen::Certificate, rcgen::KeyPair), String> {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".to_string()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)))
    ];
    let key_pair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| format!("Failed to generate key pair: {}", e))?;
    let cert = rcgen::Certificate::from_params(params)
        .map_err(|e| format!("Failed to generate certificate: {}", e))?;
    Ok((cert, key_pair))
}

fn save_certificates(cert: &rcgen::Certificate, key_pair: &rcgen::KeyPair) -> Result<(), String> {
    let mut cert_file = File::create("cert.pem").map_err(|e| format!("Failed to create cert.pem: {}", e))?;
    cert_file.write_all(cert.serialize_pem().unwrap().as_bytes())
        .map_err(|e| format!("Failed to write cert.pem: {}", e))?;
    let mut key_file = File::create("key.pem").map_err(|e| format!("Failed to create key.pem: {}", e))?;
    key_file.write_all(key_pair.serialize_pem().as_bytes()).map_err(|e| format!("Failed to write key.pem: {}", e))?;
    Ok(())
}

async fn load_certificates() -> Result<(Vec<Certificate>, PrivateKey), String> {
    if !Path::new("cert.pem").exists() || !Path::new("key.pem").exists() {
        let (cert, key_pair) = generate_certificates()?;
        save_certificates(&cert, &key_pair)?;
    }

    let cert_file = tokio::fs::read("cert.pem").await.map_err(|e| format!("Failed to read cert.pem: {}", e))?;
    let key_file = tokio::fs::read("key.pem").await.map_err(|e| format!("Failed to read key.pem: {}", e))?;

    let certs = rustls_pemfile::certs(&mut &cert_file[..])
    .map_err(|e| format!("Failed to parse certificates: {}", e))?;
let certs = certs.into_iter().map(Certificate).collect();

let key = rustls_pemfile::pkcs8_private_keys(&mut &key_file[..])
    .map_err(|e| format!("Failed to parse private key: {}", e))?;
let key = key.into_iter().next().ok_or("No private key found")?;
let key = PrivateKey(key);

    Ok((certs, key))
}

async fn setup_tls_server_config() -> Result<Arc<ServerConfig>, String> {
    let (certs, key) = load_certificates().await?;
    let config = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .map_err(|e| format!("Failed to configure TLS protocols: {}", e))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("Failed to build server config: {}", e))?;
    Ok(Arc::new(config))
}

async fn setup_tls_client_config() -> Result<Arc<ClientConfig>, String> {
    let (certs, _) = load_certificates().await?;
    let mut root_store = RootCertStore::empty();
    for cert in &certs {
        root_store.add(cert).map_err(|e| format!("Failed to add cert to root store: {}", e))?;
    }

    let config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .map_err(|e| format!("Failed to configure TLS protocols: {}", e))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

async fn connect_tls(
    addr: SocketAddr,
    _public_key: VerifyingKey,
    signing_key: &SigningKey,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let client_config = setup_tls_client_config().await?;
    let connector = TlsConnector::from(client_config);
    let server_name = ServerName::try_from("localhost").map_err(|e| format!("Invalid server name: {}", e))?;
    let stream = TcpStream::connect(addr).await
        .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;
    let mut stream = connector.connect(server_name, stream).await
        .map_err(|e| format!("Failed to establish TLS with {}: {}", addr, e))?;

    let auth_message = format!("AUTH|{}", hex::encode(signing_key.verifying_key().to_encoded_point(false)));
    stream.write_all(auth_message.as_bytes()).await
        .map_err(|e| format!("Failed to send auth: {}", e))?;
    stream.flush().await
        .map_err(|e| format!("Failed to flush auth: {}", e))?;

    Ok(stream)
}

async fn setup_upnp(listen_addr: &str, port: u16) -> Result<(), String> {
    let addr = listen_addr.parse::<SocketAddr>()
        .map_err(|e| format!("Invalid listen address: {}", e))?;
    let addr_v4 = match addr {
        SocketAddr::V4(v4) => v4,
        _ => return Err("IPv6 not supported".to_string()),
    };
    let gateway = igd::search_gateway(SearchOptions::default())
        .map_err(|e| format!("Failed to find gateway: {}", e))?;
    gateway.add_port(
        PortMappingProtocol::TCP,
        port,
        addr_v4,
        3600,
        "Cuneos Blockchain P2P"
    ).map_err(|e| format!("Failed to add UPnP port mapping: {}", e))?;
    Ok(())
}

async fn cleanup_upnp(port: u16) {
    if let Ok(gateway) = igd::search_gateway(SearchOptions::default()) {
        if let Err(e) = gateway.remove_port(PortMappingProtocol::TCP, port) {
            error!("Failed to remove UPnP port mapping: {}", e);
        }
    }
}

async fn setup_firewall(port: u16) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("netsh")
            .args(&[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name=Cuneos_P2P_{}", port),
                "dir=in",
                "action=allow",
                "protocol=TCP",
                &format!("localport={}", port),
            ])
            .output()
            .await
            .map_err(|e| format!("Failed to execute netsh: {}", e))?;
        if !output.status.success() {
            return Err(format!("Failed to add firewall rule: {:?}", output.stderr));
        }
    }
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ufw")
            .args(&["allow", &port.to_string()])
            .output()
            .await
            .map_err(|e| format!("Failed to execute ufw: {}", e))?;
        if !output.status.success() {
            return Err(format!("Failed to add firewall rule: {:?}", output.stderr));
        }
    }
    Ok(())
}

async fn cleanup_firewall(port: u16) {
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = Command::new("netsh")
            .args(&[
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name=Cuneos_P2P_{}", port),
            ])
            .output()
            .await
        {
            error!("Failed to remove firewall rule: {}", e);
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = Command::new("ufw")
            .args(&["delete", "allow", &port.to_string()])
            .output()
            .await
        {
            error!("Failed to remove firewall rule: {}", e);
        }
    }
}

async fn save_peer_list(peers: &[PeerInfo]) -> Result<(), String> {
    let path = "peers.json";
    let json = serde_json::to_string(peers).map_err(|e| format!("Failed to serialize peers: {}", e))?;
    tokio::fs::write(path, json).await
        .map_err(|e| format!("Failed to write peers: {}", e))?;
    Ok(())
}

async fn load_peer_list() -> Result<Vec<PeerInfo>, String> {
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

fn encrypt_data(data: &str, key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("Invalid key length: expected 32 bytes, got {}", key.len()));
    }
    if nonce.len() != 12 {
        return Err(format!("Invalid nonce length: expected 12 bytes, got {}", nonce.len()));
    }
    let key_array: [u8; 32] = key.try_into().map_err(|_| "Failed to convert key to array")?;
    let key = Key::<Aes256Gcm>::from_slice(&key_array);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);
    let ciphertext = cipher.encrypt(nonce, data.as_bytes())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;
    Ok(ciphertext)
}

fn decrypt_data(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<String, String> {
    if key.len() != 32 {
        return Err(format!("Invalid key length: expected 32 bytes, got {}", key.len()));
    }
    if nonce.len() != 12 {
        return Err(format!("Invalid nonce length: expected 12 bytes, got {}", nonce.len()));
    }
    let key_array: [u8; 32] = key.try_into().map_err(|_| "Failed to convert key to array")?;
    let key = Key::<Aes256Gcm>::from_slice(&key_array);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;
    String::from_utf8(plaintext)
        .map_err(|e| format!("Failed to convert decrypted data to string: {}", e))
}

fn sanitize_filename(filename: &str) -> String {
    filename
        .replace("..", "")
        .replace("/", "")
        .replace("\\", "")
        .replace(":", "")
}

#[derive(Clone, Default)]
struct Sha256Algorithm(Sha256);

impl Sha256Algorithm {
    fn new() -> Sha256Algorithm {
        Sha256Algorithm(Sha256::new())
    }
}

impl Algorithm<[u8; 32]> for Sha256Algorithm {
    fn hash(&mut self) -> [u8; 32] {
        let digest = self.0.finalize_reset();
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest[..32]);
        result
    }

    fn reset(&mut self) {
        self.0 = Sha256::new();
    }

    fn leaf(&mut self, leaf: [u8; 32]) -> [u8; 32] {
        self.0.update(&leaf[..]);
        let digest = self.0.finalize_reset();
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest[..32]);
        result
    }

    fn node(&mut self, left: [u8; 32], right: [u8; 32], _depth: usize) -> [u8; 32] {
        self.0.update(&left[..]);
        self.0.update(&right[..]);
        let digest = self.0.finalize_reset();
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest[..32]);
        result
    }
}

impl StdHasher for Sha256Algorithm {
    fn finish(&self) -> u64 {
        let digest = self.0.clone().finalize();
        u64::from_le_bytes(digest[..8].try_into().unwrap())
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

fn calculate_merkle_root(_transactions: &[Transaction]) -> String {
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

fn calculate_hash(header: &BlockHeader, _transactions: &[Transaction]) -> String {
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

fn mine_block(header: &mut BlockHeader, _transactions: &[Transaction]) -> bool {
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

fn calculate_difficulty(chain: &[Block], target_time: u64) -> u32 {
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
async fn validate_block(block: &Block, previous_block: &Block, peers: &Arc<Mutex<Vec<Peer>>>, _balances: &Arc<Mutex<Balance>>) -> bool {
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
    *miner_balance += MINING_REWARD;
    true
}

async fn save_block_to_file(block: &Block) -> Result<(), String> {
    let path = format!("blocks/block_{}.json", block.header.index);
    tokio::fs::create_dir_all("blocks").await
        .map_err(|e| format!("Failed to create blocks dir: {}", e))?;
    let json = serde_json::to_string(block).map_err(|e| format!("Failed to serialize block: {}", e))?;
    tokio::fs::write(&path, json).await
        .map_err(|e| format!("Failed to write block: {}", e))?;
    Ok(())
}

async fn load_blockchain() -> Result<Vec<Block>, String> {
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

async fn save_pending_pool(pool: &PendingPool) -> Result<(), String> {
    let path = "pending_pool.json";
    let json = serde_json::to_string(pool).map_err(|e| format!("Failed to serialize pool: {}", e))?;
    tokio::fs::write(path, json).await
        .map_err(|e| format!("Failed to write pool: {}", e))?;
    Ok(())
}

async fn load_pending_pool() -> Result<PendingPool, String> {
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

async fn save_balances(_balances: &Balance) -> Result<(), String> {
    let path = "balances.json";
    let json = serde_json::to_string(_balances).map_err(|e| format!("Failed to serialize balances: {}", e))?;
    tokio::fs::write(path, json).await
        .map_err(|e| format!("Failed to write balances: {}", e))?;
    Ok(())
}

async fn load_balances() -> Result<Balance, String> {
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

async fn delete_user_data(blockchain: Arc<Mutex<Vec<Block>>>, user_id: &str) {
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

async fn resolve_chain(blockchain: Arc<Mutex<Vec<Block>>>, new_chain: Vec<Block>, peers: Arc<Mutex<Vec<Peer>>>, _balances: Arc<Mutex<Balance>>) -> bool {
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
        if let Err(e) = save_block_to_file(block).await {
            error!("Failed to save block {}: {}", block.header.index, e);
        }
    }
    let balances_clone = _balances.lock().await.clone();
    if let Err(e) = save_balances(&balances_clone).await {
        error!("Failed to save balances: {}", e);
    }
    true
}
async fn send_ack(stream: &mut (impl AsyncWriteExt + Unpin), message_id: &str) {
    let payload = format!("ACK|{}\n", message_id);
    if let Err(e) = stream.write_all(payload.as_bytes()).await {
        error!("Failed to send ACK: {}", e);
    }
    if let Err(e) = stream.flush().await {
        error!("Failed to flush ACK: {}", e);
    }
}

async fn handle_client_stream(
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    tx: Sender<String>,
    peers: Arc<Mutex<Vec<Peer>>>,
    blockchain: Arc<Mutex<Vec<Block>>>,
    pending_pool: Arc<Mutex<PendingPool>>,
    _balances: Arc<Mutex<Balance>>,
    signing_key: SigningKey,
) {
    let mut stream = stream;
    let mut buffer = [0; 4096];
    let mut public_key: Option<VerifyingKey> = None;
    let mut bytes_sent = 0;
    let start_time = SystemTime::now();
    let (new_peer_tx, mut new_peer_rx) = tokio::sync::mpsc::channel::<(tokio_rustls::client::TlsStream<TcpStream>, SocketAddr, VerifyingKey)>(100);

    // Spawn a separate task to handle new peer connections iteratively
    let peers_clone = Arc::clone(&peers);
    let tx_clone = tx.clone();
    let blockchain_clone = Arc::clone(&blockchain);
    let pending_pool_clone = Arc::clone(&pending_pool);
    let balances_clone = Arc::clone(&_balances);
    let signing_key_clone = signing_key.clone();
    tokio::spawn(async move {
        while let Some((new_stream, addr, _pub_key)) = new_peer_rx.recv().await {
            let mut inner_stream = new_stream;
            let mut inner_buffer = [0; 4096];
            let mut inner_public_key: Option<VerifyingKey> = None;
            let mut inner_bytes_sent = 0;
            let inner_start_time = SystemTime::now();

            loop {
                if inner_bytes_sent >= BANDWIDTH_LIMIT {
                    let elapsed = SystemTime::now().duration_since(inner_start_time).unwrap().as_secs();
                    if elapsed < 1 {
                        sleep(Duration::from_secs(1) - Duration::from_secs(elapsed)).await;
                    }
                    inner_bytes_sent = 0;
                }

                match inner_stream.read(&mut inner_buffer).await {
                    Ok(n) if n == 0 => {
                        info!("Connection closed by peer: {}", addr);
                        break;
                    }
                    Ok(n) => {
                        inner_bytes_sent += n as u64;
                        let message = String::from_utf8_lossy(&inner_buffer[..n]).to_string();
                        if message.starts_with("AUTH|") {
                            let key_hex = message[5..].trim();
                            let key_bytes = hex::decode(key_hex).unwrap_or_default();
                            inner_public_key = Some(VerifyingKey::from_sec1_bytes(&key_bytes)
                                .unwrap_or(VerifyingKey::from_affine(AffinePoint::default()).unwrap()));
                            let peer = Peer {
                                addr,
                                public_key: inner_public_key.unwrap(),
                            };
                            let peer_infos = {
                                let mut peers_lock = peers_clone.lock().await;
                                if peers_lock.len() < MAX_PEERS && !peers_lock.iter().any(|p| p.addr == peer.addr) {
                                    peers_lock.push(peer.clone());
                                    peers_lock.iter().map(|p| PeerInfo {
                                        addr: p.addr,
                                        public_key: hex::encode(p.public_key.to_encoded_point(false)),
                                    }).collect::<Vec<PeerInfo>>()
                                } else {
                                    vec![]
                                }
                            };
                            if !peer_infos.is_empty() {
                                if let Err(e) = save_peer_list(&peer_infos).await {
                                    error!("Failed to save peer list: {}", e);
                                }
                            }
                            send_peer_list(Arc::clone(&peers_clone), &mut inner_stream).await;
                            continue;
                        }
                        if inner_public_key.is_none() {
                            tx_clone.send("Peer not authenticated".to_string()).await.expect("Failed to send to main thread");
                            break;
                        }
                        let _inner_public_key = inner_public_key.as_ref().unwrap();
                        if message.starts_with("TEXT|") {
                            let text = message[5..].trim();
                            if !text.is_empty() {
                                info!("Received text from {}: {}", addr, text);
                                tx_clone.send(format!("Received text: {}", text)).await.expect("Failed to send to main thread");
                                send_ack(&mut inner_stream, "TEXT").await;
                            }
                        } else if message.starts_with("FILE|") {
                            let parts: Vec<&str> = message[5..].splitn(3, '|').collect();
                            if parts.len() == 3 {
                                let filename = parts[0];
                                let size: u64 = parts[1].parse().unwrap_or(0);
                                let content = parts[2].as_bytes();
                                let safe_filename = sanitize_filename(filename);
                                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                                let output_path = format!("received_files/{}_{}", timestamp, safe_filename);
                                tokio::fs::create_dir_all("received_files").await.map_err(|e| error!("Failed to create received_files dir: {}", e)).ok();
                                tokio::fs::write(&output_path, content).await.map_err(|e| error!("Failed to write file: {}", e)).ok();
                                info!("Received file from {}: {} ({} bytes)", addr, output_path, size);
                                tx_clone.send(format!("Received file: {} ({} bytes)", output_path, size))
                                    .await
                                    .expect("Failed to send to main thread");
                                send_ack(&mut inner_stream, "FILE").await;
                            }
                        } else if message.starts_with("BLOCK|") {
                            let json = message[6..].trim();
                            if let Ok(block) = serde_json::from_str::<Block>(json) {
                                let (last_block, is_valid) = {
                                    let blockchain_lock = blockchain_clone.lock().await;
                                    let last_block = blockchain_lock.last().unwrap_or(&Block {
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
                                    }).clone();
                                    let is_valid = validate_block(&block, &last_block, &peers_clone, &balances_clone).await;
                                    (last_block, is_valid)
                                };
                                if is_valid {
                                    let block_clone = block.clone();
                                    {
                                        let mut blockchain_lock = blockchain_clone.lock().await;
                                        blockchain_lock.push(block_clone);
                                    }
                                    if let Err(e) = save_block_to_file(&block).await {
                                        error!("Failed to save block {}: {}", block.header.index, e);
                                    }
                                    let balances_clone = balances_clone.lock().await.clone();
                                    if let Err(e) = save_balances(&balances_clone).await {
                                        error!("Failed to save balances: {}", e);
                                    }
                                    info!("Received block from {}: index {}", addr, block.header.index);
                                    tx_clone.send(format!("Received block: index {}", block.header.index))
                                        .await
                                        .expect("Failed to send to main thread");
                                    send_ack(&mut inner_stream, "BLOCK").await;
                                } else {
                                    tx_clone.send("Invalid block".to_string()).await.expect("Failed to send to main thread");
                                }
                            } else {
                                tx_clone.send("Failed to parse block".to_string()).await.expect("Failed to send to main thread");
                            }
                        } else if message.starts_with("TX|") {
                            let json = message[3..].trim();
                            if let Ok(tx_data) = serde_json::from_str::<Transaction>(json) {
                                let public_key_bytes = hex::decode(&tx_data.sender).unwrap_or_default();
                                let public_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
                                    .unwrap_or(VerifyingKey::from_affine(AffinePoint::default()).unwrap());
                                if verify_transaction(&tx_data, &public_key) {
                                    let pool_clone = {
                                        let mut pool_lock = pending_pool_clone.lock().await;
                                        pool_lock.transactions.push(tx_data.clone());
                                        pool_lock.clone()
                                    };
                                    if let Err(e) = save_pending_pool(&pool_clone).await {
                                        error!("Failed to save pending pool: {}", e);
                                    }
                                    info!("Received transaction from {}: {} -> {} ({})", addr, tx_data.sender, tx_data.receiver, tx_data.amount);
                                    tx_clone.send(format!("Received transaction: {} -> {} ({})", tx_data.sender, tx_data.receiver, tx_data.amount))
                                        .await
                                        .expect("Failed to send to main thread");
                                    send_ack(&mut inner_stream, "TX").await;
                                } else {
                                    tx_clone.send("Invalid transaction".to_string()).await.expect("Failed to send to main thread");
                                }
                            } else {
                                tx_clone.send("Failed to parse transaction".to_string()).await.expect("Failed to send to main thread");
                            }
                        } else if message.starts_with("USER_DATA|") {
                            let json = message[10..].trim();
                            if let Ok(user_data) = serde_json::from_str::<UserData>(json) {
                                let pool_clone = {
                                    let mut pool_lock = pending_pool_clone.lock().await;
                                    pool_lock.user_data.push(user_data.clone());
                                    pool_lock.clone()
                                };
                                if let Err(e) = save_pending_pool(&pool_clone).await {
                                    error!("Failed to save pending pool: {}", e);
                                }
                                info!("Received user data from {} for ID: {}", addr, user_data.user_id);
                                tx_clone.send(format!("Received user data for ID: {}", user_data.user_id))
                                    .await
                                    .expect("Failed to send to main thread");
                                send_ack(&mut inner_stream, "USER_DATA").await;
                            } else {
                                tx_clone.send("Failed to parse user data".to_string()).await.expect("Failed to send to main thread");
                            }
                        } else if message.starts_with("SYNC|") {
                            let height: u64 = message[5..].trim().parse().unwrap_or(0);
                            let headers = {
                                let blockchain_lock = blockchain_clone.lock().await;
                                blockchain_lock.iter()
                                    .filter(|b| b.header.index > height)
                                    .map(|b| b.header.clone())
                                    .collect::<Vec<BlockHeader>>()
                            };
                            if !headers.is_empty() {
                                let json = serde_json::to_string(&headers).expect("Failed to serialize headers");
                                let payload = format!("HEADERS|{}\n", json);
                                if let Err(e) = inner_stream.write_all(payload.as_bytes()).await {
                                    error!("Failed to send headers to {}: {}", addr, e);
                                }
                                if let Err(e) = inner_stream.flush().await {
                                    error!("Failed to flush headers to {}: {}", addr, e);
                                }
                            }
                            send_ack(&mut inner_stream, "SYNC").await;
                        } else if message.starts_with("HEADERS|") {
                            let json = message[8..].trim();
                            if let Ok(headers) = serde_json::from_str::<Vec<BlockHeader>>(json) {
                                let missing = {
                                    let blockchain_lock = blockchain_clone.lock().await;
                                    headers.iter()
                                        .filter(|h| !blockchain_lock.iter().any(|b| b.header.index == h.index))
                                        .map(|h| h.index)
                                        .collect::<Vec<u64>>()
                                };
                                for index in missing {
                                    let payload = format!("REQUEST_BLOCK|{}\n", index);
                                    if let Err(e) = inner_stream.write_all(payload.as_bytes()).await {
                                        error!("Failed to request block {} from {}: {}", index, addr, e);
                                    }
                                    if let Err(e) = inner_stream.flush().await {
                                        error!("Failed to flush request to {}: {}", addr, e);
                                    }
                                }
                            }
                            send_ack(&mut inner_stream, "HEADERS").await;
                        } else if message.starts_with("REQUEST_BLOCK|") {
                            let index: u64 = message[14..].trim().parse().unwrap_or(0);
                            let block = {
                                let blockchain_lock = blockchain_clone.lock().await;
                                blockchain_lock.iter().find(|b| b.header.index == index).cloned()
                            };
                            if let Some(block) = block {
                                let json = serde_json::to_string(&block).expect("Failed to serialize block");
                                let payload = format!("BLOCK|{}\n", json);
                                if let Err(e) = inner_stream.write_all(payload.as_bytes()).await {
                                    error!("Failed to send block {} to {}: {}", index, addr, e);
                                }
                                if let Err(e) = inner_stream.flush().await {
                                    error!("Failed to flush block {} to {}: {}", index, addr, e);
                                }
                            }
                            send_ack(&mut inner_stream, "REQUEST_BLOCK").await;
                        } else if message.starts_with("CHAIN|") {
                            let json = message[6..].trim();
                            if let Ok(new_chain) = serde_json::from_str::<Vec<Block>>(json) {
                                let success = resolve_chain(Arc::clone(&blockchain_clone), new_chain, Arc::clone(&peers_clone), Arc::clone(&balances_clone)).await;
                                if success {
                                    info!("Updated to longer chain from {}", addr);
                                    tx_clone.send("Updated to longer chain".to_string()).await.expect("Failed to send to main thread");
                                }
                                send_ack(&mut inner_stream, "CHAIN").await;
                            } else {
                                tx_clone.send("Failed to parse chain".to_string()).await.expect("Failed to send to main thread");
                            }
                        } else if message.starts_with("ACK|") {
                            let message_id = message[4..].trim();
                            info!("Received ACK for {} from {}", message_id, addr);
                            tx_clone.send(format!("Received ACK for {}", message_id)).await.expect("Failed to send to main thread");
                        }
                    }
                    Err(e) => {
                        error!("Error reading from stream for {}: {}", addr, e);
                        break;
                    }
                }
            }
        }
    });

    loop {
        if bytes_sent >= BANDWIDTH_LIMIT {
            let elapsed = SystemTime::now().duration_since(start_time).unwrap().as_secs();
            if elapsed < 1 {
                sleep(Duration::from_secs(1) - Duration::from_secs(elapsed)).await;
            }
            bytes_sent = 0;
        }

        match stream.read(&mut buffer).await {
            Ok(n) if n == 0 => {
                info!("Connection closed by peer");
                break;
            }
            Ok(n) => {
                bytes_sent += n as u64;
                let message = String::from_utf8_lossy(&buffer[..n]).to_string();
                if message.starts_with("AUTH|") {
                    let key_hex = message[5..].trim();
                    let key_bytes = hex::decode(key_hex).unwrap_or_default();
                    public_key = Some(VerifyingKey::from_sec1_bytes(&key_bytes)
                        .unwrap_or(VerifyingKey::from_affine(AffinePoint::default()).unwrap()));
                    let peer = Peer {
                        addr: stream.get_ref().0.peer_addr().unwrap(),
                        public_key: public_key.unwrap(),
                    };
                    let peer_infos = {
                        let mut peers_lock = peers.lock().await;
                        if peers_lock.len() < MAX_PEERS && !peers_lock.iter().any(|p| p.addr == peer.addr) {
                            peers_lock.push(peer.clone());
                            peers_lock.iter().map(|p| PeerInfo {
                                addr: p.addr,
                                public_key: hex::encode(p.public_key.to_encoded_point(false)),
                            }).collect::<Vec<PeerInfo>>()
                        } else {
                            vec![]
                        }
                    };
                    if !peer_infos.is_empty() {
                        if let Err(e) = save_peer_list(&peer_infos).await {
                            error!("Failed to save peer list: {}", e);
                        }
                    }
                    send_peer_list(Arc::clone(&peers), &mut stream).await;
                    continue;
                }
                if public_key.is_none() {
                    tx.send("Peer not authenticated".to_string()).await.expect("Failed to send to main thread");
                    break;
                }
                let public_key = public_key.as_ref().unwrap();
                if message.starts_with("TEXT|") {
                    let text = message[5..].trim();
                    if !text.is_empty() {
                        info!("Received text: {}", text);
                        tx.send(format!("Received text: {}", text)).await.expect("Failed to send to main thread");
                        send_ack(&mut stream, "TEXT").await;
                    }
                } else if message.starts_with("FILE|") {
                    let parts: Vec<&str> = message[5..].splitn(3, '|').collect();
                    if parts.len() == 3 {
                        let filename = parts[0];
                        let size: u64 = parts[1].parse().unwrap_or(0);
                        let content = parts[2].as_bytes();
                        let safe_filename = sanitize_filename(filename);
                        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                        let output_path = format!("received_files/{}_{}", timestamp, safe_filename);
                        tokio::fs::create_dir_all("received_files").await.map_err(|e| error!("Failed to create received_files dir: {}", e)).ok();
                        tokio::fs::write(&output_path, content).await.map_err(|e| error!("Failed to write file: {}", e)).ok();
                        info!("Received file: {} ({} bytes)", output_path, size);
                        tx.send(format!("Received file: {} ({} bytes)", output_path, size))
                            .await
                            .expect("Failed to send to main thread");
                        send_ack(&mut stream, "FILE").await;
                    }
                } else if message.starts_with("PEERS|") {
                    let peer_addrs = message[6..].split(',').filter(|s| !s.is_empty());
                    let mut new_peers = vec![];
                    for addr_str in peer_addrs {
                        if let Ok(socket_addr) = addr_str.parse::<SocketAddr>() {
                            let should_connect = {
                                let peers_lock = peers.lock().await;
                                !peers_lock.iter().any(|p| p.addr == socket_addr) && peers_lock.len() < MAX_PEERS
                            };
                            if should_connect {
                                let signing_key_clone = signing_key.clone();
                                if let Ok(new_stream) = connect_tls(socket_addr, *public_key, &signing_key_clone).await {
                                    new_peers.push(Peer {
                                        addr: socket_addr,
                                        public_key: *public_key,
                                    });
                                    info!("Connected to new peer: {}", socket_addr);
                                    tx.send(format!("Connected to new peer: {}", socket_addr))
                                        .await
                                        .expect("Failed to send to main thread");
                                    let _ = new_peer_tx.send((new_stream, socket_addr, *public_key)).await;
                                }
                            }
                        } else {
                            error!("Invalid peer address: {}", addr_str);
                        }
                    }
                    if !new_peers.is_empty() {
                        let peer_infos = {
                            let mut peers_lock = peers.lock().await;
                            peers_lock.extend(new_peers);
                            peers_lock.iter().map(|p| PeerInfo {
                                addr: p.addr,
                                public_key: hex::encode(p.public_key.to_encoded_point(false)),
                            }).collect::<Vec<PeerInfo>>()
                        };
                        if let Err(e) = save_peer_list(&peer_infos).await {
                            error!("Failed to save peer list: {}", e);
                        }
                    }
                } else if message.starts_with("BLOCK|") {
                    let json = message[6..].trim();
                    if let Ok(block) = serde_json::from_str::<Block>(json) {
                        let (last_block, is_valid) = {
                            let blockchain_lock = blockchain.lock().await;
                            let last_block = blockchain_lock.last().unwrap_or(&Block {
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
                            }).clone();
                            let is_valid = validate_block(&block, &last_block, &peers, &_balances).await;
                            (last_block, is_valid)
                        };
                        if is_valid {
                            let block_clone = block.clone();
                            {
                                let mut blockchain_lock = blockchain.lock().await;
                                blockchain_lock.push(block_clone);
                            }
                            if let Err(e) = save_block_to_file(&block).await {
                                error!("Failed to save block {}: {}", block.header.index, e);
                            }
                            let balances_clone = _balances.lock().await.clone();
                            if let Err(e) = save_balances(&balances_clone).await {
                                error!("Failed to save balances: {}", e);
                            }
                            info!("Received block: index {}", block.header.index);
                            tx.send(format!("Received block: index {}", block.header.index))
                                .await
                                .expect("Failed to send to main thread");
                            send_ack(&mut stream, "BLOCK").await;
                        } else {
                            tx.send("Invalid block".to_string()).await.expect("Failed to send to main thread");
                        }
                    } else {
                        tx.send("Failed to parse block".to_string()).await.expect("Failed to send to main thread");
                    }
                } else if message.starts_with("TX|") {
                    let json = message[3..].trim();
                    if let Ok(tx_data) = serde_json::from_str::<Transaction>(json) {
                        let public_key_bytes = hex::decode(&tx_data.sender).unwrap_or_default();
                        let public_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
                            .unwrap_or(VerifyingKey::from_affine(AffinePoint::default()).unwrap());
                        if verify_transaction(&tx_data, &public_key) {
                            let pool_clone = {
                                let mut pool_lock = pending_pool.lock().await;
                                pool_lock.transactions.push(tx_data.clone());
                                pool_lock.clone()
                            };
                            if let Err(e) = save_pending_pool(&pool_clone).await {
                                error!("Failed to save pending pool: {}", e);
                            }
                            info!("Received transaction: {} -> {} ({})", tx_data.sender, tx_data.receiver, tx_data.amount);
                            tx.send(format!("Received transaction: {} -> {} ({})", tx_data.sender, tx_data.receiver, tx_data.amount))
                                .await
                                .expect("Failed to send to main thread");
                            send_ack(&mut stream, "TX").await;
                        } else {
                            tx.send("Invalid transaction".to_string()).await.expect("Failed to send to main thread");
                        }
                    } else {
                        tx.send("Failed to parse transaction".to_string()).await.expect("Failed to send to main thread");
                    }
                } else if message.starts_with("USER_DATA|") {
                    let json = message[10..].trim();
                    if let Ok(user_data) = serde_json::from_str::<UserData>(json) {
                        let pool_clone = {
                            let mut pool_lock = pending_pool.lock().await;
                            pool_lock.user_data.push(user_data.clone());
                            pool_lock.clone()
                        };
                        if let Err(e) = save_pending_pool(&pool_clone).await {
                            error!("Failed to save pending pool: {}", e);
                        }
                        info!("Received user data for ID: {}", user_data.user_id);
                        tx.send(format!("Received user data for ID: {}", user_data.user_id))
                            .await
                            .expect("Failed to send to main thread");
                        send_ack(&mut stream, "USER_DATA").await;
                    } else {
                        tx.send("Failed to parse user data".to_string()).await.expect("Failed to send to main thread");
                    }
                } else if message.starts_with("SYNC|") {
                    let height: u64 = message[5..].trim().parse().unwrap_or(0);
                    let headers = {
                        let blockchain_lock = blockchain.lock().await;
                        blockchain_lock.iter()
                            .filter(|b| b.header.index > height)
                            .map(|b| b.header.clone())
                            .collect::<Vec<BlockHeader>>()
                    };
                    if !headers.is_empty() {
                        let json = serde_json::to_string(&headers).expect("Failed to serialize headers");
                        let payload = format!("HEADERS|{}\n", json);
                        if let Err(e) = stream.write_all(payload.as_bytes()).await {
                            error!("Failed to send headers: {}", e);
                        }
                        if let Err(e) = stream.flush().await {
                            error!("Failed to flush headers: {}", e);
                        }
                    }
                    send_ack(&mut stream, "SYNC").await;
                } else if message.starts_with("HEADERS|") {
                    let json = message[8..].trim();
                    if let Ok(headers) = serde_json::from_str::<Vec<BlockHeader>>(json) {
                        let missing = {
                            let blockchain_lock = blockchain.lock().await;
                            headers.iter()
                                .filter(|h| !blockchain_lock.iter().any(|b| b.header.index == h.index))
                                .map(|h| h.index)
                                .collect::<Vec<u64>>()
                        };
                        for index in missing {
                            let payload = format!("REQUEST_BLOCK|{}\n", index);
                            if let Err(e) = stream.write_all(payload.as_bytes()).await {
                                error!("Failed to request block {}: {}", index, e);
                            }
                            if let Err(e) = stream.flush().await {
                                error!("Failed to flush request: {}", e);
                            }
                        }
                    }
                    send_ack(&mut stream, "HEADERS").await;
                } else if message.starts_with("REQUEST_BLOCK|") {
                    let index: u64 = message[14..].trim().parse().unwrap_or(0);
                    let block = {
                        let blockchain_lock = blockchain.lock().await;
                        blockchain_lock.iter().find(|b| b.header.index == index).cloned()
                    };
                    if let Some(block) = block {
                        let json = serde_json::to_string(&block).expect("Failed to serialize block");
                        let payload = format!("BLOCK|{}\n", json);
                        if let Err(e) = stream.write_all(payload.as_bytes()).await {
                            error!("Failed to send block {}: {}", index, e);
                        }
                        if let Err(e) = stream.flush().await {
                            error!("Failed to flush stream: {}", e);
                        }
                    }
                    send_ack(&mut stream, "REQUEST_BLOCK").await;
                } else if message.starts_with("CHAIN|") {
                    let json = message[6..].trim();
                    if let Ok(new_chain) = serde_json::from_str::<Vec<Block>>(json) {
                        let success = resolve_chain(Arc::clone(&blockchain), new_chain, Arc::clone(&peers), Arc::clone(&_balances)).await;
                        if success {
                            info!("Updated to longer chain");
                            tx.send("Updated to longer chain".to_string()).await.expect("Failed to send to main thread");
                        }
                        send_ack(&mut stream, "CHAIN").await;
                    } else {
                        tx.send("Failed to parse chain".to_string()).await.expect("Failed to send to main thread");
                    }
                } else if message.starts_with("ACK|") {
                    let message_id = message[4..].trim();
                    info!("Received ACK for {}", message_id);
                    tx.send(format!("Received ACK for {}", message_id)).await.expect("Failed to send to main thread");
                }
            }
            Err(e) => {
                error!("Error reading from stream: {}", e);
                break;
            }
        }
    }
}

async fn handle_server_client(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    tx: Sender<String>,
    peers: Arc<Mutex<Vec<Peer>>>,
    blockchain: Arc<Mutex<Vec<Block>>>,
    pending_pool: Arc<Mutex<PendingPool>>,
    _balances: Arc<Mutex<Balance>>,
    signing_key: SigningKey,
) {
    let mut stream = stream;
    let mut buffer = [0; 4096];
    let mut public_key: Option<VerifyingKey> = None;
    let mut bytes_sent = 0;
    let start_time = SystemTime::now();

    loop {
        if bytes_sent >= BANDWIDTH_LIMIT {
            let elapsed = SystemTime::now().duration_since(start_time).unwrap().as_secs();
            if elapsed < 1 {
                sleep(Duration::from_secs(1) - Duration::from_secs(elapsed)).await;
            }
            bytes_sent = 0;
        }

        match stream.read(&mut buffer).await {
            Ok(n) if n == 0 => {
                info!("Connection closed by peer");
                break;
            }
            Ok(n) => {
                bytes_sent += n as u64;
                let message = String::from_utf8_lossy(&buffer[..n]).to_string();
                if message.starts_with("AUTH|") {
                    let key_hex = message[5..].trim();
                    let key_bytes = hex::decode(key_hex).unwrap_or_default();
                    public_key = Some(VerifyingKey::from_sec1_bytes(&key_bytes)
                        .unwrap_or(VerifyingKey::from_affine(AffinePoint::default()).unwrap()));
                    let peer = Peer {
                        addr: stream.get_ref().0.peer_addr().unwrap(),
                        public_key: public_key.unwrap(),
                    };
                    let peer_infos = {
                        let mut peers_lock = peers.lock().await;
                        if peers_lock.len() < MAX_PEERS && !peers_lock.iter().any(|p| p.addr == peer.addr) {
                            peers_lock.push(peer.clone());
                            peers_lock.iter().map(|p| PeerInfo {
                                addr: p.addr,
                                public_key: hex::encode(p.public_key.to_encoded_point(false)),
                            }).collect::<Vec<PeerInfo>>()
                        } else {
                            vec![]
                        }
                    };
                    if !peer_infos.is_empty() {
                        if let Err(e) = save_peer_list(&peer_infos).await {
                            error!("Failed to save peer list: {}", e);
                        }
                    }
                    send_peer_list(Arc::clone(&peers), &mut stream).await;
                    continue;
                }
                if public_key.is_none() {
                    tx.send("Peer not authenticated".to_string()).await.expect("Failed to send to main thread");
                    break;
                }
                let public_key = public_key.as_ref().unwrap();
                if message.starts_with("TEXT|") {
                    let text = message[5..].trim();
                    if !text.is_empty() {
                        info!("Received text: {}", text);
                        tx.send(format!("Received text: {}", text)).await.expect("Failed to send to main thread");
                        send_ack(&mut stream, "TEXT").await;
                    }
                } else if message.starts_with("FILE|") {
                    let parts: Vec<&str> = message[5..].splitn(3, '|').collect();
                    if parts.len() == 3 {
                        let filename = parts[0];
                        let size: u64 = parts[1].parse().unwrap_or(0);
                        let content = parts[2].as_bytes();
                        let safe_filename = sanitize_filename(filename);
                        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                        let output_path = format!("received_files/{}_{}", timestamp, safe_filename);
                        tokio::fs::create_dir_all("received_files").await.map_err(|e| error!("Failed to create received_files dir: {}", e)).ok();
                        tokio::fs::write(&output_path, content).await.map_err(|e| error!("Failed to write file: {}", e)).ok();
                        info!("Received file: {} ({} bytes)", output_path, size);
                        tx.send(format!("Received file: {} ({} bytes)", output_path, size))
                            .await
                            .expect("Failed to send to main thread");
                        send_ack(&mut stream, "FILE").await;
                    }
                } else if message.starts_with("PEERS|") {
                    let peer_addrs = message[6..].split(',').filter(|s| !s.is_empty());
                    let mut new_peers = vec![];
                    for addr_str in peer_addrs {
                        if let Ok(socket_addr) = addr_str.parse::<SocketAddr>() {
                            let should_connect = {
                                let peers_lock = peers.lock().await;
                                !peers_lock.iter().any(|p| p.addr == socket_addr) && peers_lock.len() < MAX_PEERS
                            };
                            if should_connect {
                                let signing_key_clone = signing_key.clone();
                                if let Ok(new_stream) = connect_tls(socket_addr, *public_key, &signing_key_clone).await {
                                    new_peers.push(Peer {
                                        addr: socket_addr,
                                        public_key: *public_key,
                                    });
                                    info!("Connected to new peer: {}", socket_addr);
                                    tx.send(format!("Connected to new peer: {}", socket_addr))
                                        .await
                                        .expect("Failed to send to main thread");
                                    let tx_clone = tx.clone();
                                    let peers_clone = Arc::clone(&peers);
                                    let blockchain_clone = Arc::clone(&blockchain);
                                    let pending_pool_clone = Arc::clone(&pending_pool);
                                    let balances_clone = Arc::clone(&_balances);
                                    let signing_key_clone = signing_key.clone();
                                    tokio::spawn(async move {
                                        handle_client_stream(
                                            new_stream,
                                            tx_clone,
                                            peers_clone,
                                            blockchain_clone,
                                            pending_pool_clone,
                                            balances_clone,
                                            signing_key_clone,
                                        ).await;
                                    });
                                }
                            }
                        } else {
                            error!("Invalid peer address: {}", addr_str);
                        }
                    }
                    if !new_peers.is_empty() {
                        let peer_infos = {
                            let mut peers_lock = peers.lock().await;
                            peers_lock.extend(new_peers);
                            peers_lock.iter().map(|p| PeerInfo {
                                addr: p.addr,
                                public_key: hex::encode(p.public_key.to_encoded_point(false)),
                            }).collect::<Vec<PeerInfo>>()
                        };
                        if let Err(e) = save_peer_list(&peer_infos).await {
                            error!("Failed to save peer list: {}", e);
                        }
                    }
                } else if message.starts_with("BLOCK|") {
                    let json = message[6..].trim();
                    if let Ok(block) = serde_json::from_str::<Block>(json) {
                        let (last_block, is_valid) = {
                            let blockchain_lock = blockchain.lock().await;
                            let last_block = blockchain_lock.last().unwrap_or(&Block {
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
                            }).clone();
                            let is_valid = validate_block(&block, &last_block, &peers, &_balances).await;
                            (last_block, is_valid)
                        };
                        if is_valid {
                            let block_clone = block.clone();
                            {
                                let mut blockchain_lock = blockchain.lock().await;
                                blockchain_lock.push(block_clone);
                            }
                            if let Err(e) = save_block_to_file(&block).await {
                                error!("Failed to save block {}: {}", block.header.index, e);
                            }
                            let balances_clone = _balances.lock().await.clone();
                            if let Err(e) = save_balances(&balances_clone).await {
                                error!("Failed to save balances: {}", e);
                            }
                            info!("Received block: index {}", block.header.index);
                            tx.send(format!("Received block: index {}", block.header.index))
                                .await
                                .expect("Failed to send to main thread");
                            send_ack(&mut stream, "BLOCK").await;
                        } else {
                            tx.send("Invalid block".to_string()).await.expect("Failed to send to main thread");
                        }
                    } else {
                        tx.send("Failed to parse block".to_string()).await.expect("Failed to send to main thread");
                    }
                } else if message.starts_with("TX|") {
                    let json = message[3..].trim();
                    if let Ok(tx_data) = serde_json::from_str::<Transaction>(json) {
                        let public_key_bytes = hex::decode(&tx_data.sender).unwrap_or_default();
                        let public_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
                            .unwrap_or(VerifyingKey::from_affine(AffinePoint::default()).unwrap());
                        if verify_transaction(&tx_data, &public_key) {
                            let pool_clone = {
                                let mut pool_lock = pending_pool.lock().await;
                                pool_lock.transactions.push(tx_data.clone());
                                pool_lock.clone()
                            };
                            if let Err(e) = save_pending_pool(&pool_clone).await {
                                error!("Failed to save pending pool: {}", e);
                            }
                            info!("Received transaction: {} -> {} ({})", tx_data.sender, tx_data.receiver, tx_data.amount);
                            tx.send(format!("Received transaction: {} -> {} ({})", tx_data.sender, tx_data.receiver, tx_data.amount))
                                .await
                                .expect("Failed to send to main thread");
                            send_ack(&mut stream, "TX").await;
                        } else {
                            tx.send("Invalid transaction".to_string()).await.expect("Failed to send to main thread");
                        }
                    } else {
                        tx.send("Failed to parse transaction".to_string()).await.expect("Failed to send to main thread");
                    }
                } else if message.starts_with("USER_DATA|") {
                    let json = message[10..].trim();
                    if let Ok(user_data) = serde_json::from_str::<UserData>(json) {
                        let pool_clone = {
                            let mut pool_lock = pending_pool.lock().await;
                            pool_lock.user_data.push(user_data.clone());
                            pool_lock.clone()
                        };
                        if let Err(e) = save_pending_pool(&pool_clone).await {
                            error!("Failed to save pending pool: {}", e);
                        }
                        info!("Received user data for ID: {}", user_data.user_id);
                        tx.send(format!("Received user data for ID: {}", user_data.user_id))
                            .await
                            .expect("Failed to send to main thread");
                        send_ack(&mut stream, "USER_DATA").await;
                    } else {
                        tx.send("Failed to parse user data".to_string()).await.expect("Failed to send to main thread");
                    }
                } else if message.starts_with("SYNC|") {
                    let height: u64 = message[5..].trim().parse().unwrap_or(0);
                    let headers = {
                        let blockchain_lock = blockchain.lock().await;
                        blockchain_lock.iter()
                            .filter(|b| b.header.index > height)
                            .map(|b| b.header.clone())
                            .collect::<Vec<BlockHeader>>()
                    };
                    if !headers.is_empty() {
                        let json = serde_json::to_string(&headers).expect("Failed to serialize headers");
                        let payload = format!("HEADERS|{}\n", json);
                        if let Err(e) = stream.write_all(payload.as_bytes()).await {
                            error!("Failed to send headers: {}", e);
                        }
                        if let Err(e) = stream.flush().await {
                            error!("Failed to flush headers: {}", e);
                        }
                    }
                    send_ack(&mut stream, "SYNC").await;
                } else if message.starts_with("HEADERS|") {
                    let json = message[8..].trim();
                    if let Ok(headers) = serde_json::from_str::<Vec<BlockHeader>>(json) {
                        let missing = {
                            let blockchain_lock = blockchain.lock().await;
                            headers.iter()
                                .filter(|h| !blockchain_lock.iter().any(|b| b.header.index == h.index))
                                .map(|h| h.index)
                                .collect::<Vec<u64>>()
                        };
                        for index in missing {
                            let payload = format!("REQUEST_BLOCK|{}\n", index);
                            if let Err(e) = stream.write_all(payload.as_bytes()).await {
                                error!("Failed to request block {}: {}", index, e);
                            }
                            if let Err(e) = stream.flush().await {
                                error!("Failed to flush request: {}", e);
                            }
                        }
                    }
                    send_ack(&mut stream, "HEADERS").await;
                } else if message.starts_with("REQUEST_BLOCK|") {
                    let index: u64 = message[14..].trim().parse().unwrap_or(0);
                    let block = {
                        let blockchain_lock = blockchain.lock().await;
                        blockchain_lock.iter().find(|b| b.header.index == index).cloned()
                    };
                    if let Some(block) = block {
                        let json = serde_json::to_string(&block).expect("Failed to serialize block");
                        let payload = format!("BLOCK|{}\n", json);
                        if let Err(e) = stream.write_all(payload.as_bytes()).await {
                            error!("Failed to send block {}: {}", index, e);
                        }
                        if let Err(e) = stream.flush().await {
                            error!("Failed to flush stream: {}", e);
                        }
                    }
                    send_ack(&mut stream, "REQUEST_BLOCK").await;
                } else if message.starts_with("CHAIN|") {
                    let json = message[6..].trim();
                    if let Ok(new_chain) = serde_json::from_str::<Vec<Block>>(json) {
                        let success = resolve_chain(Arc::clone(&blockchain), new_chain, Arc::clone(&peers), Arc::clone(&_balances)).await;
                        if success {
                            info!("Updated to longer chain");
                            tx.send("Updated to longer chain".to_string()).await.expect("Failed to send to main thread");
                        }
                        send_ack(&mut stream, "CHAIN").await;
                    } else {
                        tx.send("Failed to parse chain".to_string()).await.expect("Failed to send to main thread");
                    }
                } else if message.starts_with("ACK|") {
                    let message_id = message[4..].trim();
                    info!("Received ACK for {}", message_id);
                    tx.send(format!("Received ACK for {}", message_id)).await.expect("Failed to send to main thread");
                }
            }
            Err(e) => {
                error!("Error reading from stream: {}", e);
                break;
            }
        }
    }
}

async fn send_message(peers: Arc<Mutex<Vec<Peer>>>, message: &str, signing_key: &SigningKey) {
    let payload = format!("TEXT|{}\n", message);
    let peers_to_process = {
        let peers_lock = peers.lock().await;
        peers_lock.clone()
    };
    let mut disconnected = vec![];
    for (i, peer) in peers_to_process.iter().enumerate() {
        if let Ok(mut stream) = connect_tls(peer.addr, peer.public_key, signing_key).await {
            if stream.write_all(payload.as_bytes()).await.is_err() || stream.flush().await.is_err() {
                disconnected.push(i);
            }
        } else {
            disconnected.push(i);
        }
    }
    if !disconnected.is_empty() {
        let mut peers_lock = peers.lock().await;
        for i in disconnected.iter().rev() {
            peers_lock.remove(*i);
        }
    }
}

async fn send_file(peers: Arc<Mutex<Vec<Peer>>>, file_path: &str, signing_key: &SigningKey) -> Result<(), String> {
    let path = Path::new(file_path);
    if !path.exists() || !path.is_file() {
        return Err("File does not exist or is not a file".to_string());
    }
    let filename = path.file_name().unwrap().to_str().unwrap();
    let safe_filename = sanitize_filename(filename);
    let mut file = tokio::fs::File::open(path).await
        .map_err(|e| format!("Failed to open file: {}", e))?;
    let size = tokio::fs::metadata(path).await
        .map_err(|e| format!("Failed to get file size: {}", e))?
        .len();
    let mut buffer = vec![0; 4096];
    let mut total_sent = 0;
    let mut bytes_sent = 0;
    let start_time = SystemTime::now();

    let peers_to_process = {
        let peers_lock = peers.lock().await;
        peers_lock.clone()
    };
    let mut disconnected = vec![];
    for (i, peer) in peers_to_process.iter().enumerate() {
        if let Ok(mut stream) = connect_tls(peer.addr, peer.public_key, signing_key).await {
            let header = format!("FILE|{}|{}\n", safe_filename, size);
            if stream.write_all(header.as_bytes()).await.is_err() || stream.flush().await.is_err() {
                disconnected.push(i);
            }
        } else {
            disconnected.push(i);
        }
    }

    while total_sent < size {
        if bytes_sent >= BANDWIDTH_LIMIT {
            let elapsed = SystemTime::now().duration_since(start_time).unwrap().as_secs();
            if elapsed < 1 {
                sleep(Duration::from_secs(1) - Duration::from_secs(elapsed)).await;
            }
            bytes_sent = 0;
        }

        let bytes_read = file.read(&mut buffer).await
            .map_err(|e| format!("Failed to read file: {}", e))?;
        if bytes_read == 0 {
            break;
        }
        bytes_sent += bytes_read as u64;
        for (i, peer) in peers_to_process.iter().enumerate() {
            if !disconnected.contains(&i) {
                if let Ok(mut stream) = connect_tls(peer.addr, peer.public_key, signing_key).await {
                    if stream.write_all(&buffer[..bytes_read]).await.is_err() || stream.flush().await.is_err() {
                        disconnected.push(i);
                    }
                } else {
                    disconnected.push(i);
                }
            }
        }
        total_sent += bytes_read as u64;
    }
    if !disconnected.is_empty() {
        let mut peers_lock = peers.lock().await;
        for i in disconnected.iter().rev() {
            peers_lock.remove(*i);
        }
    }
    Ok(())
}
async fn send_block(peers: Arc<Mutex<Vec<Peer>>>, block: &mut Block, signing_key: &SigningKey) {
    block.header.merkle_root = calculate_merkle_root(&block.transactions);
    if mine_block(&mut block.header, &block.transactions) {
        if let Err(e) = save_block_to_file(block).await {
            error!("Failed to save block {}: {}", block.header.index, e);
        }
        let json = serde_json::to_string(block).expect("Failed to serialize block");
        let payload = format!("BLOCK|{}\n", json);
        let peers_to_process = {
            let peers_lock = peers.lock().await;
            peers_lock.clone()
        };
        let mut disconnected = vec![];
        for (i, peer) in peers_to_process.iter().enumerate() {
            if let Ok(mut stream) = connect_tls(peer.addr, peer.public_key, signing_key).await {
                if stream.write_all(payload.as_bytes()).await.is_err() || stream.flush().await.is_err() {
                    disconnected.push(i);
                }
            } else {
                disconnected.push(i);
            }
        }
        if !disconnected.is_empty() {
            let mut peers_lock = peers.lock().await;
            for i in disconnected.iter().rev() {
                peers_lock.remove(*i);
            }
        }
    }
}

async fn send_transaction(peers: Arc<Mutex<Vec<Peer>>>, tx: &Transaction, pending_pool: Arc<Mutex<PendingPool>>, signing_key: &SigningKey) {
    let json = serde_json::to_string(tx).expect("Failed to serialize transaction");
    let payload = format!("TX|{}\n", json);
    let peers_to_process = {
        let peers_lock = peers.lock().await;
        peers_lock.clone()
    };
    let mut disconnected = vec![];
    for (i, peer) in peers_to_process.iter().enumerate() {
        if let Ok(mut stream) = connect_tls(peer.addr, peer.public_key, signing_key).await {
            if stream.write_all(payload.as_bytes()).await.is_err() || stream.flush().await.is_err() {
                disconnected.push(i);
            }
        } else {
            disconnected.push(i);
        }
    }
    if !disconnected.is_empty() {
        let mut peers_lock = peers.lock().await;
        for i in disconnected.iter().rev() {
            peers_lock.remove(*i);
        }
    }
    let mut pool_clone = PendingPool { transactions: vec![], user_data: vec![] };
    {
        let mut pool_lock = pending_pool.lock().await;
        pool_lock.transactions.push(tx.clone());
        pool_clone = pool_lock.clone();
    }
    if let Err(e) = save_pending_pool(&pool_clone).await {
        error!("Failed to save pending pool: {}", e);
    }
}

async fn send_user_data(peers: Arc<Mutex<Vec<Peer>>>, user_data: &UserData, pending_pool: Arc<Mutex<PendingPool>>, signing_key: &SigningKey) {
    let json = serde_json::to_string(user_data).expect("Failed to serialize user data");
    let payload = format!("USER_DATA|{}\n", json);
    let peers_to_process = {
        let peers_lock = peers.lock().await;
        peers_lock.clone()
    };
    let mut disconnected = vec![];
    for (i, peer) in peers_to_process.iter().enumerate() {
        if let Ok(mut stream) = connect_tls(peer.addr, peer.public_key, signing_key).await {
            if stream.write_all(payload.as_bytes()).await.is_err() || stream.flush().await.is_err() {
                disconnected.push(i);
            }
        } else {
            disconnected.push(i);
        }
    }
    if !disconnected.is_empty() {
        let mut peers_lock = peers.lock().await;
        for i in disconnected.iter().rev() {
            peers_lock.remove(*i);
        }
    }
    let mut pool_clone = PendingPool { transactions: vec![], user_data: vec![] };
    {
        let mut pool_lock = pending_pool.lock().await;
        pool_lock.user_data.push(user_data.clone());
        pool_clone = pool_lock.clone();
    }
    if let Err(e) = save_pending_pool(&pool_clone).await {
        error!("Failed to save pending pool: {}", e);
    }
}

async fn request_sync(peers: Arc<Mutex<Vec<Peer>>>, height: u64, signing_key: &SigningKey) {
    let payload = format!("SYNC|{}\n", height);
    let peers_to_process = {
        let peers_lock = peers.lock().await;
        peers_lock.clone()
    };
    let mut disconnected = vec![];
    for (i, peer) in peers_to_process.iter().enumerate() {
        if let Ok(mut stream) = connect_tls(peer.addr, peer.public_key, signing_key).await {
            if stream.write_all(payload.as_bytes()).await.is_err() || stream.flush().await.is_err() {
                disconnected.push(i);
            }
        } else {
            disconnected.push(i);
        }
    }
    if !disconnected.is_empty() {
        let mut peers_lock = peers.lock().await;
        for i in disconnected.iter().rev() {
            peers_lock.remove(*i);
        }
    }
}

async fn send_peer_list(peers: Arc<Mutex<Vec<Peer>>>, stream: &mut (impl AsyncWriteExt + Unpin)) {
    let peer_addrs = {
        let peers_lock = peers.lock().await;
        peers_lock.iter().map(|p| format!("{}:{}", p.addr.ip(), p.addr.port())).collect::<Vec<String>>()
    };
    let payload = format!("PEERS|{}\n", peer_addrs.join(","));
    if let Err(e) = stream.write_all(payload.as_bytes()).await {
        error!("Failed to send peer list: {}", e);
    }
    if let Err(e) = stream.flush().await {
        error!("Failed to flush peer list: {}", e);
    }
}

async fn get_status(
    peers: &Arc<Mutex<Vec<Peer>>>,
    blockchain: &Arc<Mutex<Vec<Block>>>,
    pending_pool: &Arc<Mutex<PendingPool>>,
    _balances: &Arc<Mutex<Balance>>,
) -> String {
    let peers_lock = peers.lock().await;
    let blockchain_lock = blockchain.lock().await;
    let pool_lock = pending_pool.lock().await;
    let balances_lock = _balances.lock().await;
    let status = format!(
        "Peer Count: {}\nChain Height: {}\nPending Transactions: {}\nPending User Data: {}\nTotal Balances: {}",
        peers_lock.len(),
        blockchain_lock.len(),
        pool_lock.transactions.len(),
        pool_lock.user_data.len(),
        balances_lock.balances.len()
    );
    drop(peers_lock);
    drop(blockchain_lock);
    drop(pool_lock);
    drop(balances_lock);
    status
}

async fn auto_mine_blocks(
    peers: Arc<Mutex<Vec<Peer>>>,
    blockchain: Arc<Mutex<Vec<Block>>>,
    pending_pool: Arc<Mutex<PendingPool>>,
    _balances: Arc<Mutex<Balance>>,
    tx: Sender<String>,
    signing_key: SigningKey,
) {
    loop {
        sleep(Duration::from_secs(MINING_INTERVAL)).await;
        let (transactions, user_data, pool_clone) = {
            let mut pool_lock = pending_pool.lock().await;
            if pool_lock.transactions.is_empty() && pool_lock.user_data.is_empty() {
                continue;
            }
            let transactions = pool_lock.transactions.drain(..).collect::<Vec<Transaction>>();
            let user_data = pool_lock.user_data.drain(..).collect::<Vec<UserData>>();
            let pool_clone = pool_lock.clone();
            (transactions, user_data, pool_clone)
        };
        let (index, previous_hash, difficulty) = {
            let blockchain_lock = blockchain.lock().await;
            (
                blockchain_lock.len() as u64 + 1,
                blockchain_lock.last().map(|b| b.header.hash.clone()).unwrap_or("0".to_string()),
                calculate_difficulty(&blockchain_lock, MINING_INTERVAL),
            )
        };
        if let Err(e) = save_pending_pool(&pool_clone).await {
            error!("Failed to save pending pool: {}", e);
        }
        let mut new_block = Block {
            header: BlockHeader {
                index,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                previous_hash,
                merkle_root: calculate_merkle_root(&transactions),
                hash: String::new(),
                nonce: 0,
                difficulty,
            },
            transactions,
            user_data,
        };
        info!("Automatically mining block: index {}", index);
        let peers_clone = Arc::clone(&peers);
        let signing_key_clone = signing_key.clone();
        send_block(peers_clone, &mut new_block, &signing_key_clone).await;
        tx.send(format!("Automatically mined block: index {}", index))
            .await
            .expect("Failed to send to main thread");
    }
}

#[tokio::main]
async fn main() {
    let subscriber = fmt::layer().with_filter(EnvFilter::from_default_env());
    tracing_subscriber::registry().with(subscriber).init();

    let local_ip = get_if_addrs()
        .expect("Failed to get network interfaces")
        .into_iter()
        .filter_map(|iface| {
            if iface.is_loopback() {
                None
            } else {
                match iface.ip() {
                    std::net::IpAddr::V4(ip) => Some(ip.to_string()),
                    _ => None,
                }
            }
        })
        .find(|ip| INITIAL_NODES.contains(&ip.as_str()))
        .unwrap_or_else(|| {
            info!("Local IP not in INITIAL_NODES, assuming new node");
            "0.0.0.0".to_string()
        });

    let listen_addr = format!("0.0.0.0:{}", DEFAULT_PORT);
    let seed_addr = if local_ip == INITIAL_NODES[0] {
        format!("{}:{}", INITIAL_NODES[1], DEFAULT_PORT)
    } else if local_ip == INITIAL_NODES[1] {
        format!("{}:{}", INITIAL_NODES[0], DEFAULT_PORT)
    } else {
        INITIAL_NODES.iter().map(|ip| format!("{}:{}", ip, DEFAULT_PORT)).collect::<Vec<_>>().join(",")
    };

    let port = DEFAULT_PORT;

    if let Err(e) = setup_upnp(&listen_addr, port).await {
        error!("Failed to setup UPnP: {}. Manual port forwarding may be required.", e);
    }

    if let Err(e) = setup_firewall(port).await {
        error!("Failed to setup firewall rule: {}. Please allow port {} manually.", e, port);
    }

    let peers = Arc::new(Mutex::new(Vec::new()));
    let blockchain = Arc::new(Mutex::new(load_blockchain().await.unwrap_or_default()));
    let pending_pool = Arc::new(Mutex::new(load_pending_pool().await.unwrap_or_default()));
    let balances = Arc::new(Mutex::new(load_balances().await.unwrap_or_default()));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(100);
    let (signing_key, public_key) = load_or_generate_node_key();

    let server_config = match setup_tls_server_config().await {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to setup TLS server config: {}", e);
            cleanup_upnp(port).await;
            cleanup_firewall(port).await;
            return;
        }
    };
    let acceptor = TlsAcceptor::from(server_config);

    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(listener) => {
            info!("Listening on {}", listen_addr);
            listener
        }
        Err(e) => {
            error!("Failed to bind to {}: {}", listen_addr, e);
            cleanup_upnp(port).await;
            cleanup_firewall(port).await;
            return;
        }
    };

    let peers_clone = Arc::clone(&peers);
    let tx_clone = tx.clone();
    let blockchain_clone = Arc::clone(&blockchain);
    let pending_pool_clone = Arc::clone(&pending_pool);
    let balances_clone = Arc::clone(&balances);
    let acceptor_clone = acceptor.clone();
    let signing_key_clone = signing_key.clone();
    tokio::spawn(async move {
        while let Ok((stream, addr)) = listener.accept().await {
            let acceptor_clone = acceptor_clone.clone();
            let tx_clone = tx_clone.clone();
            let peers_clone = Arc::clone(&peers_clone);
            let blockchain_clone = Arc::clone(&blockchain_clone);
            let pending_pool_clone = Arc::clone(&pending_pool_clone);
            let balances_clone = Arc::clone(&balances_clone);
            let signing_key_clone = signing_key_clone.clone();
            tokio::spawn(async move {
                if let Ok(stream) = acceptor_clone.accept(stream).await {
                    handle_server_client(
                        stream,
                        tx_clone,
                        peers_clone,
                        blockchain_clone,
                        pending_pool_clone,
                        balances_clone,
                        signing_key_clone,
                    ).await;
                } else {
                    error!("Failed to establish TLS with {}", addr);
                }
            });
        }
    });

    let peers_clone = Arc::clone(&peers);
    let tx_clone = tx.clone();
    let blockchain_clone = Arc::clone(&blockchain);
    let pending_pool_clone = Arc::clone(&pending_pool);
    let balances_clone = Arc::clone(&balances);
    let signing_key_clone = signing_key.clone();
    tokio::spawn(async move {
        loop {
            let known_peers = load_peer_list().await.unwrap_or_default();
            let mut new_peers = vec![];
            for peer_info in &known_peers {
                let should_connect = {
                    let peers_lock = peers_clone.lock().await;
                    !peers_lock.iter().any(|p| p.addr == peer_info.addr) && peers_lock.len() < MAX_PEERS
                };
                if should_connect {
                    let public_key_bytes = hex::decode(&peer_info.public_key).unwrap_or_default();
                    let public_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
                        .unwrap_or(VerifyingKey::from_affine(AffinePoint::default()).unwrap());
                    let signing_key_clone = signing_key_clone.clone();
                    if let Ok(new_stream) = connect_tls(peer_info.addr, public_key, &signing_key_clone).await {
                        new_peers.push(Peer {
                            addr: peer_info.addr,
                            public_key,
                        });
                        info!("Reconnected to peer: {}", peer_info.addr);
                        tx_clone.send(format!("Reconnected to peer: {}", peer_info.addr))
                            .await
                            .expect("Failed to send to main thread");
                        let tx_clone = tx_clone.clone();
                        let peers_clone = Arc::clone(&peers_clone);
                        let blockchain_clone = Arc::clone(&blockchain_clone);
                        let pending_pool_clone = Arc::clone(&pending_pool_clone);
                        let balances_clone = Arc::clone(&balances_clone);
                        let signing_key_clone = signing_key_clone.clone();
                        tokio::spawn(async move {
                            handle_client_stream(
                                new_stream,
                                tx_clone,
                                peers_clone,
                                blockchain_clone,
                                pending_pool_clone,
                                balances_clone,
                                signing_key_clone,
                            ).await;
                        });
                    }
                }
            }
            if !new_peers.is_empty() {
                let peer_infos = {
                    let mut peers_lock = peers_clone.lock().await;
                    peers_lock.extend(new_peers);
                    peers_lock.iter().map(|p| PeerInfo {
                        addr: p.addr,
                        public_key: hex::encode(p.public_key.to_encoded_point(false)),
                    }).collect::<Vec<PeerInfo>>()
                };
                if let Err(e) = save_peer_list(&peer_infos).await {
                    error!("Failed to save peer list: {}", e);
                }
            }
            sleep(Duration::from_secs(10)).await;
        }
    });

    let peers_clone = Arc::clone(&peers);
    let tx_clone = tx.clone();
    let blockchain_clone = Arc::clone(&blockchain);
    let pending_pool_clone = Arc::clone(&pending_pool);
    let balances_clone = Arc::clone(&balances);
    let signing_key_clone = signing_key.clone();
    tokio::spawn(async move {
        auto_mine_blocks(
            peers_clone,
            blockchain_clone,
            pending_pool_clone,
            balances_clone,
            tx_clone,
            signing_key_clone,
        ).await;
    });

    let peers_clone = Arc::clone(&peers);
    let tx_clone = tx.clone();
    let blockchain_clone = Arc::clone(&blockchain);
    let pending_pool_clone = Arc::clone(&pending_pool);
    let balances_clone = Arc::clone(&balances);
    let signing_key_clone = signing_key.clone();
    tokio::spawn(async move {
        let signing_key_clone_2 = signing_key_clone.clone();
        let seed_addrs: Vec<String> = seed_addr.split(',').map(|s| s.to_string()).collect();
        let mut connected = false;
        for addr in seed_addrs {
            if let Ok(seed_socket) = addr.parse::<SocketAddr>() {
                if let Ok(seed_stream) = connect_tls(seed_socket, public_key, &signing_key_clone).await {
                    let addr = seed_stream.get_ref().0.peer_addr().unwrap();
                    let peer_infos = {
                        let mut peers_lock = peers_clone.lock().await;
                        if peers_lock.len() < MAX_PEERS && !peers_lock.iter().any(|p| p.addr == addr) {
                            peers_lock.push(Peer { addr, public_key });
                            peers_lock.iter().map(|p| PeerInfo {
                                addr: p.addr,
                                public_key: hex::encode(p.public_key.to_encoded_point(false)),
                            }).collect::<Vec<PeerInfo>>()
                        } else {
                            vec![]
                        }
                    };
                    if !peer_infos.is_empty() {
                        info!("Connected to seed at {}", addr);
                        if let Err(e) = save_peer_list(&peer_infos).await {
                            error!("Failed to save peer list: {}", e);
                        }
                        connected = true;
                    }
                    let tx_clone = tx_clone.clone();
                    let peers_clone_inner = Arc::clone(&peers_clone);
                    let blockchain_clone = Arc::clone(&blockchain_clone);
                    let pending_pool_clone = Arc::clone(&pending_pool_clone);
                    let balances_clone = Arc::clone(&balances_clone);
                    let signing_key_clone_3 = signing_key_clone_2.clone();
                    tokio::spawn(async move {
                        handle_client_stream(
                            seed_stream,
                            tx_clone,
                            peers_clone_inner,
                            blockchain_clone,
                            pending_pool_clone,
                            balances_clone,
                            signing_key_clone_3,
                        ).await;
                    });
                    let peers_clone_for_list = Arc::clone(&peers_clone);
                    if let Ok(mut seed_stream) = connect_tls(addr, public_key, &signing_key_clone_2).await {
                        send_peer_list(peers_clone_for_list, &mut seed_stream).await;
                    }
                    break;
                } else {
                    error!("Could not connect to seed {}: retrying", addr);
                }
            }
        }
        if !connected {
            error!("Could not connect to any seed nodes: starting with no peers");
        }
    });

    while let Some(msg) = rx.recv().await {
        println!("{}", msg);
        let mut input = String::new();
        println!("Enter command (send_text <msg>, send_file <path>, send_block <index>, send_tx <receiver> <amount>, add_user_data <user_id> <profile> [message], delete_user <user_id>, view_user_data <user_id>, request_sync <height>, status, list_peers, or quit):");
        io::stdin().read_line(&mut input).expect("Failed to read input");
        let input = input.trim();

        if input == "quit" {
            break;
        }

        if input.starts_with("send_text ") {
            let message = input[10..].trim();
            if !message.is_empty() {
                let peers_clone = Arc::clone(&peers);
                let signing_key_clone = signing_key.clone();
                send_message(peers_clone, message, &signing_key_clone).await;
            } else {
                println!("Text message cannot be empty");
            }
        } else if input.starts_with("send_file ") {
            let file_path = input[10..].trim();
            let peers_clone = Arc::clone(&peers);
            let signing_key_clone = signing_key.clone();
            match send_file(peers_clone, file_path, &signing_key_clone).await {
                Ok(()) => println!("File sent successfully: {}", file_path),
                Err(e) => eprintln!("Failed to send file: {}", e),
            }
        } else if input.starts_with("send_block ") {
            let index: u64 = input[11..].trim().parse().unwrap_or(0);
            let (previous_hash, difficulty) = {
                let blockchain_lock = blockchain.lock().await;
                (
                    blockchain_lock.last().map(|b| b.header.hash.clone()).unwrap_or("0".to_string()),
                    calculate_difficulty(&blockchain_lock, MINING_INTERVAL),
                )
            };
            let (transactions, user_data, pool_clone) = {
                let mut pool_lock = pending_pool.lock().await;
                (
                    pool_lock.transactions.drain(..).collect::<Vec<Transaction>>(),
                    pool_lock.user_data.drain(..).collect::<Vec<UserData>>(),
                    pool_lock.clone(),
                )
            };
            if let Err(e) = save_pending_pool(&pool_clone).await {
                error!("Failed to save pending pool: {}", e);
            }
            let mut new_block = Block {
                header: BlockHeader {
                    index,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    previous_hash,
                    merkle_root: calculate_merkle_root(&transactions),
                    hash: String::new(),
                    nonce: 0,
                    difficulty,
                },
                transactions,
                user_data,
            };
            let peers_clone = Arc::clone(&peers);
            let signing_key_clone = signing_key.clone();
            send_block(peers_clone, &mut new_block, &signing_key_clone).await;
            println!("Sent block: index {}", index);
        } else if input.starts_with("send_tx ") {
            let parts: Vec<&str> = input[8..].split_whitespace().collect();
            if parts.len() == 2 {
                let sender = hex::encode(public_key.to_encoded_point(false));
                let receiver = parts[0].to_string();
                let amount: f64 = parts[1].parse().unwrap_or(0.0);
                let signing_key_clone = signing_key.clone();
                let tx = Transaction {
                    sender: sender.clone(),
                    receiver: receiver.clone(),
                    amount,
                    fee: TRANSACTION_FEE,
                    signature: sign_transaction(&Transaction {
                        sender,
                        receiver,
                        amount,
                        fee: TRANSACTION_FEE,
                        signature: String::new(),
                    }, &signing_key_clone),
                };
                if verify_transaction(&tx, &public_key) {
                    let peers_clone = Arc::clone(&peers);
                    let pending_pool_clone = Arc::clone(&pending_pool);
                    let signing_key_clone = signing_key.clone();
                    send_transaction(peers_clone, &tx, pending_pool_clone, &signing_key_clone).await;
                    println!("Sent transaction: {} -> {} ({})", tx.sender, tx.receiver, tx.amount);
                } else {
                    println!("Invalid transaction");
                }
            } else {
                println!("Invalid send_tx format. Use: send_tx <receiver> <amount>");
            }
        } else if input.starts_with("add_user_data ") {
            let parts: Vec<&str> = input[14..].splitn(3, ' ').collect();
            if parts.len() >= 2 {
                let user_id = parts[0].to_string();
                let profile = parts[1].to_string();
                let message = parts.get(2).map(|s| s.to_string()).unwrap_or_default();
                let (encryption_key, nonce) = generate_user_key_nonce(&user_id);
                let profile_encrypted = encrypt_data(&profile, &encryption_key, &nonce).unwrap_or_default();
                let message_encrypted = if !message.is_empty() {
                    encrypt_data(&message, &encryption_key, &nonce).unwrap_or_default()
                } else {
                    vec![]
                };
                let user_data = UserData {
                    user_id,
                    profile: Some(profile_encrypted),
                    messages: if !message_encrypted.is_empty() { vec![message_encrypted] } else { vec![] },
                    encryption_key,
                    nonce,
                };
                let peers_clone = Arc::clone(&peers);
                let pending_pool_clone = Arc::clone(&pending_pool);
                let signing_key_clone = signing_key.clone();
                send_user_data(peers_clone, &user_data, pending_pool_clone, &signing_key_clone).await;
                println!("Added user data for ID: {}", user_data.user_id);
            } else {
                println!("Invalid add_user_data format. Use: add_user_data <user_id> <profile> [message]");
            }
        } else if input.starts_with("delete_user ") {
            let user_id = input[12..].trim();
            if !user_id.is_empty() {
                delete_user_data(Arc::clone(&blockchain), user_id).await;
                println!("Deleted user data for ID: {}", user_id);
            } else {
                println!("User ID cannot be empty");
            }
        } else if input.starts_with("view_user_data ") {
            let user_id = input[15..].trim();
            if !user_id.is_empty() {
                let blockchain_lock = blockchain.lock().await;
                let mut found = false;
                for block in blockchain_lock.iter() {
                    for user_data in block.user_data.iter() {
                        if user_data.user_id == user_id {
                            found = true;
                            if let Some(profile) = &user_data.profile {
                                if let Ok(profile_text) = decrypt_data(profile, &user_data.encryption_key, &user_data.nonce) {
                                    println!("Profile for {}: {}", user_id, profile_text);
                                } else {
                                    println!("Failed to decrypt profile for {}", user_id);
                                }
                            } else {
                                println!("No profile for {}", user_id);
                            }
                            if !user_data.messages.is_empty() {
                                println!("Messages for {}:", user_id);
                                for (i, msg) in user_data.messages.iter().enumerate() {
                                    if let Ok(msg_text) = decrypt_data(msg, &user_data.encryption_key, &user_data.nonce) {
                                        println!("  {}: {}", i + 1, msg_text);
                                    } else {
                                        println!("  {}: Failed to decrypt", i + 1);
                                    }
                                }
                            } else {
                                println!("No messages for {}", user_id);
                            }
                        }
                    }
                }
                if !found {
                    println!("No data found for user ID: {}", user_id);
                }
            } else {
                println!("User ID cannot be empty");
            }
        } else if input.starts_with("request_sync ") {
            let height: u64 = input[13..].trim().parse().unwrap_or(0);
            let peers_clone = Arc::clone(&peers);
            let signing_key_clone = signing_key.clone();
            request_sync(peers_clone, height, &signing_key_clone).await;
            println!("Requested sync from height {}", height);
        } else if input == "status" {
            let status = get_status(&peers, &blockchain, &pending_pool, &balances).await;
            println!("{}", status);
        } else if input == "list_peers" {
            let peers_lock = peers.lock().await;
            if peers_lock.is_empty() {
                println!("No connected peers");
            } else {
                println!("Connected peers:");
                for peer in peers_lock.iter() {
                    println!("- {} (PubKey: {})", peer.addr, hex::encode(peer.public_key.to_encoded_point(false)));
                }
            }
        } else {
            println!("Invalid command. Use 'send_text <msg>', 'send_file <path>', 'send_block <index>', 'send_tx <receiver> <amount>', 'add_user_data <user_id> <profile> [message]', 'delete_user <user_id>', 'view_user_data <user_id>', 'request_sync <height>', 'status', 'list_peers', or 'quit'.");
        }
    }

    cleanup_upnp(port).await;
    cleanup_firewall(port).await;
}