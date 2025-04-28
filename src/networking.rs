use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc::Sender, Mutex};
use tokio::time::sleep;
use tokio::process::Command;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_rustls::rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
use tokio_rustls::rustls::client::ServerName;
use serde_json;
use p256::AffinePoint;
use if_addrs::get_if_addrs;
use std::net::{IpAddr, SocketAddrV4};
use igd::{SearchOptions, PortMappingProtocol};
use tracing::{info, error};
use p256::ecdsa::{SigningKey, VerifyingKey,};
use super::blockchain::{Peer, PeerInfo, Transaction, UserData, Block, PendingPool, Balance, BlockHeader};
use super::cryptography::{generate_certificates, save_certificates, verify_transaction};
use super::storage::{save_peer_list, load_peer_list, save_block_to_file, save_pending_pool, save_balances};
use super::utils::sanitize_filename;
use std::net::{Ipv4Addr};

pub async fn load_certificates() -> Result<(Vec<Certificate>, PrivateKey), String> {
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

pub async fn setup_tls_server_config() -> Result<Arc<ServerConfig>, String> {
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

pub async fn setup_tls_client_config() -> Result<Arc<ClientConfig>, String> {
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

pub async fn connect_tls(
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

pub async fn setup_upnp(listen_addr: &str, port: u16) -> Result<(), String> {
    // Get the local IPv4 address (non-loopback)
    let local_ip = get_if_addrs()
        .map_err(|e| format!("Failed to get network interfaces: {}", e))?
        .into_iter()
        .filter(|iface| !iface.is_loopback())
        .find_map(|iface| match iface.ip() {
            IpAddr::V4(ip) => Some(ip),
            _ => None,
        })
        .ok_or_else(|| "No valid IPv4 address found".to_string())?;

    // Parse listen_addr but use local_ip for UPnP
    let addr = listen_addr
        .parse::<SocketAddr>()
        .map_err(|e| format!("Invalid listen address: {}", e))?;
    let addr_v4 = SocketAddrV4::new(local_ip, port);

    // Retry logic
    let max_retries = 3;
    let mut last_error = None;

    for attempt in 1..=max_retries {
        info!("Attempting UPnP setup (attempt {}/{})", attempt, max_retries);

        // Create SearchOptions for this attempt
        let search_options = SearchOptions {
            timeout: Some(std::time::Duration::from_secs(10)),
            broadcast_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900), // Standard UPnP multicast address
            bind_addr: SocketAddr::new(IpAddr::V4(local_ip), 0), // Bind to local IP, ephemeral port
        };

        // Search for gateway
        let gateway = match igd::search_gateway(search_options) {
            Ok(gateway) => gateway,
            Err(e) => {
                last_error = Some(format!("Failed to find gateway: {}", e));
                error!("Gateway search failed on attempt {}: {}", attempt, e);
                if attempt < max_retries {
                    sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
                break;
            }
        };

        // Attempt port mapping
        match gateway.add_port(
            PortMappingProtocol::TCP,
            port,
            addr_v4,
            86400, // 24-hour lease
            "Cuneos Blockchain P2P",
        ) {
            Ok(_) => {
                info!("UPnP port mapping added for {}:{}", local_ip, port);

                // Verify gateway responsiveness by fetching external IP
                match gateway.get_external_ip() {
                    Ok(external_ip) => {
                        info!("Verified UPnP setup: External IP is {}", external_ip);
                        return Ok(());
                    }
                    Err(e) => {
                        last_error = Some(format!("Failed to verify UPnP setup: {}", e));
                        error!("Verification failed on attempt {}: {}", attempt, e);
                        if attempt < max_retries {
                            sleep(std::time::Duration::from_secs(2)).await;
                            continue;
                        }
                    }
                }
            }
            Err(e) => {
                last_error = Some(format!("Failed to add UPnP port mapping: {}", e));
                error!("Port mapping failed on attempt {}: {}", attempt, e);
                if attempt < max_retries {
                    sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "Unknown UPnP setup failure".to_string()))
}

pub async fn cleanup_upnp(port: u16) {
    if let Ok(gateway) = igd::search_gateway(SearchOptions::default()) {
        if let Err(e) = gateway.remove_port(PortMappingProtocol::TCP, port) {
            error!("Failed to remove UPnP port mapping: {}", e);
        }
    }
}

pub async fn setup_firewall(port: u16) -> Result<(), String> {
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

pub async fn cleanup_firewall(port: u16) {
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

pub async fn send_ack(stream: &mut (impl AsyncWriteExt + Unpin), message_id: &str) {
    let payload = format!("ACK|{}\n", message_id);
    if let Err(e) = stream.write_all(payload.as_bytes()).await {
        error!("Failed to send ACK: {}", e);
    }
    if let Err(e) = stream.flush().await {
        error!("Failed to flush ACK: {}", e);
    }
}

pub async fn handle_client_stream(
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
                if inner_bytes_sent >= super::BANDWIDTH_LIMIT {
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
                                if peers_lock.len() < super::MAX_PEERS && !peers_lock.iter().any(|p| p.addr == peer.addr) {
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
                                    let is_valid = super::blockchain::validate_block(&block, &last_block, &peers_clone, &balances_clone).await;
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
                                let success = super::blockchain::resolve_chain(Arc::clone(&blockchain_clone), new_chain, Arc::clone(&peers_clone), Arc::clone(&balances_clone)).await;
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
        if bytes_sent >= super::BANDWIDTH_LIMIT {
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
                        if peers_lock.len() < super::MAX_PEERS && !peers_lock.iter().any(|p| p.addr == peer.addr) {
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
                                !peers_lock.iter().any(|p| p.addr == socket_addr) && peers_lock.len() < super::MAX_PEERS
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
                            let is_valid = super::blockchain::validate_block(&block, &last_block, &peers, &_balances).await;
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
                    match serde_json::from_str::<UserData>(json) {
                        Ok(user_data) => {
                            let mut pool_lock = pending_pool.lock().await;
                            pool_lock.user_data.push(user_data.clone());
                            if let Err(e) = save_pending_pool(&*pool_lock).await {
                                error!("Failed to save pending pool: {}", e);
                            }
                            info!("Received user data for ID: {}", user_data.user_id);
                            tx.send(format!("Received user data for ID: {}", user_data.user_id))
                                .await
                                .expect("Failed to send to main thread");
                            send_ack(&mut stream, "USER_DATA").await;
                        }
                        Err(_) => {
                            tx.send("Failed to parse user data".to_string())
                                .await
                                .expect("Failed to send to main thread");
                        }
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
                            error!("Failed to flush block {}: {}", index, e);
                        }
                    }
                    send_ack(&mut stream, "REQUEST_BLOCK").await;
                } else if message.starts_with("CHAIN|") {
                    let json = message[6..].trim();
                    if let Ok(new_chain) = serde_json::from_str::<Vec<Block>>(json) {
                        let success = super::blockchain::resolve_chain(Arc::clone(&blockchain), new_chain, Arc::clone(&peers), Arc::clone(&_balances)).await;
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

pub async fn handle_server_client(
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
        if bytes_sent >= super::BANDWIDTH_LIMIT {
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
                        if peers_lock.len() < super::MAX_PEERS && !peers_lock.iter().any(|p| p.addr == peer.addr) {
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
                                !peers_lock.iter().any(|p| p.addr == socket_addr) && peers_lock.len() < super::MAX_PEERS
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
                            let is_valid = super::blockchain::validate_block(&block, &last_block, &peers, &_balances).await;
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
                            error!("Failed to flush block {}: {}", index, e);
                        }
                    }
                    send_ack(&mut stream, "REQUEST_BLOCK").await;
                } else if message.starts_with("CHAIN|") {
                    let json = message[6..].trim();
                    if let Ok(new_chain) = serde_json::from_str::<Vec<Block>>(json) {
                        let success = super::blockchain::resolve_chain(Arc::clone(&blockchain), new_chain, Arc::clone(&peers), Arc::clone(&_balances)).await;
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

pub async fn send_message(peers: Arc<Mutex<Vec<Peer>>>, message: &str, signing_key: &SigningKey) {
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

pub async fn send_file(peers: Arc<Mutex<Vec<Peer>>>, file_path: &str, signing_key: &SigningKey) -> Result<(), String> {
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
        if bytes_sent >= super::BANDWIDTH_LIMIT {
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

pub async fn send_block(peers: Arc<Mutex<Vec<Peer>>>, block: &mut Block, signing_key: &SigningKey) {
    block.header.merkle_root = super::blockchain::calculate_merkle_root(&block.transactions);
    if super::blockchain::mine_block(&mut block.header, &block.transactions) {
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

pub async fn send_transaction(peers: Arc<Mutex<Vec<Peer>>>, tx: &Transaction, pending_pool: Arc<Mutex<PendingPool>>, signing_key: &SigningKey) {
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

pub async fn send_user_data(peers: Arc<Mutex<Vec<Peer>>>, user_data: &UserData, pending_pool: Arc<Mutex<PendingPool>>, signing_key: &SigningKey) {
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

pub async fn request_sync(peers: Arc<Mutex<Vec<Peer>>>, height: u64, signing_key: &SigningKey) {
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

pub async fn send_peer_list(peers: Arc<Mutex<Vec<Peer>>>, stream: &mut (impl AsyncWriteExt + Unpin)) {
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

pub async fn get_status(
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

pub async fn auto_mine_blocks(
    peers: Arc<Mutex<Vec<Peer>>>,
    blockchain: Arc<Mutex<Vec<Block>>>,
    pending_pool: Arc<Mutex<PendingPool>>,
    _balances: Arc<Mutex<Balance>>,
    tx: Sender<String>,
    signing_key: SigningKey,
) {
    loop {
        sleep(Duration::from_secs(super::MINING_INTERVAL)).await;
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
                super::blockchain::calculate_difficulty(&blockchain_lock, super::MINING_INTERVAL),
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
                merkle_root: super::blockchain::calculate_merkle_root(&transactions),
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