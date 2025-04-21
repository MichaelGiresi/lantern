mod network;
mod peer;
mod message;

use network::Network;
use peer::Peer;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::time;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    println!("Starting P2P network...");

    // Create three nodes
    let node1 = Arc::new(Network::new(rand::random::<u64>()));
    let node2 = Arc::new(Network::new(rand::random::<u64>()));
    let node3 = Arc::new(Network::new(rand::random::<u64>()));

    // Define addresses
    let addr1 = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);
    let addr2 = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8081);
    let addr3 = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8082);

    // Create peers
    let peer1 = Peer::new(addr1);
    let peer2 = Peer::new(addr2);
    let peer3 = Peer::new(addr3);

    // Start servers
    let node1_server = Arc::clone(&node1);
    let node1_handle = tokio::spawn(async move {
        if let Err(e) = node1_server.start("127.0.0.1:8080").await {
            eprintln!("Node1 error: {}", e);
        }
    });

    let node2_server = Arc::clone(&node2);
    let node2_handle = tokio::spawn(async move {
        if let Err(e) = node2_server.start("127.0.0.1:8081").await {
            eprintln!("Node2 error: {}", e);
        }
    });

    let node3_server = Arc::clone(&node3);
    let node3_handle = tokio::spawn(async move {
        if let Err(e) = node3_server.start("127.0.0.1:8082").await {
            eprintln!("Node3 error: {}", e);
        }
    });

    // Wait for servers to start
    time::sleep(time::Duration::from_millis(200)).await;

    // Initial connections
    if let Err(e) = node1.connect_to_peer(peer2.clone()).await {
        eprintln!("Node1 connect error: {}", e);
    }
    if let Err(e) = node2.connect_to_peer(peer3.clone()).await {
        eprintln!("Node2 connect error: {}", e);
    }

    // Let discovery happen
    time::sleep(time::Duration::from_secs(2)).await;

    // Stop servers
    node1_handle.abort();
    node2_handle.abort();
    node3_handle.abort();

    println!("P2P test complete.");
    Ok(())
}