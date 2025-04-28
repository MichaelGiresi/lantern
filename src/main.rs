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
use crate::cryptography::encrypt_data;
use sha3::Sha3_256;
use sha2::{Sha256, Digest as Sha2Digest};
use hex;
use crate::cryptography::decrypt_data;
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

// Import modules
mod cryptography;
mod networking;
mod blockchain;
mod storage;
mod utils;

use cryptography::{generate_key_pair, load_or_generate_node_key, generate_user_key_nonce, sign_transaction, verify_transaction};
use networking::{
    setup_tls_server_config, setup_tls_client_config, connect_tls, setup_upnp, cleanup_upnp,
    setup_firewall, cleanup_firewall, send_message, send_file, send_block, send_transaction,
    send_user_data, request_sync, send_peer_list, get_status, auto_mine_blocks,
    handle_client_stream, handle_server_client, send_ack
};
use blockchain::{
    Peer, PeerInfo, Transaction, UserData, BlockHeader, Block, PendingPool, Balance, NodeKey,
    calculate_merkle_root, calculate_hash, mine_block, calculate_difficulty, validate_block, resolve_chain
};
use storage::{
    save_peer_list, load_peer_list, save_block_to_file, load_blockchain, save_pending_pool,
    load_pending_pool, save_balances, load_balances, delete_user_data
};
use utils::{sanitize_filename, Sha256Algorithm};

const MAX_PEERS: usize = 50;
const BANDWIDTH_LIMIT: u64 = 1024 * 1024;
const MINING_REWARD: f64 = 50.0;
const TRANSACTION_FEE: f64 = 0.1;
const MINING_INTERVAL: u64 = 600;
const INITIAL_NODES: &[&str] = &["82.25.86.57", "47.17.52.8"];
const DEFAULT_PORT: u16 = 8080;

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