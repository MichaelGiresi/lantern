use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::message::Message;
use crate::peer::Peer;
use std::io;
use bincode;
use std::sync::Arc;
use tokio::sync::Mutex;
use futures::FutureExt;

pub struct Network {
    peers: Arc<Mutex<Vec<Peer>>>,
    own_id: u64,
}

impl Network {
    pub fn new(own_id: u64) -> Self {
        Network {
            peers: Arc::new(Mutex::new(Vec::new())),
            own_id,
        }
    }

    pub async fn start(&self, address: &str) -> io::Result<()> {
        let listener = TcpListener::bind(address).await?;
        println!("Server listening on {}", address);

        loop {
            let (socket, addr) = listener.accept().await?;
            println!("New connection from {}", addr);
            let peers = Arc::clone(&self.peers);
            let own_id = self.own_id;
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(socket, peers, own_id).await {
                    eprintln!("Error handling connection from {}: {}", addr, e);
                }
            });
        }
    }

    pub async fn connect_to_peer(&self, peer: Peer) -> io::Result<()> {
        if peer.id == self.own_id {
            println!("Skipping connection to self (ID: {})", peer.id);
            return Ok(());
        }

        let mut socket = TcpStream::connect(peer.address).await?;
        println!("Connected to peer {} at {}", peer.id, peer.address);

        // Send a Ping
        let message = Message::Ping;
        let serialized = bincode::serialize(&message)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        socket.write_all(&serialized).await?;
        socket.flush().await?;
        println!("Sent Ping to peer {}", peer.id);

        // Read response (Pong and PeerList)
        let mut buffer = [0u8; 1024];
        let n = socket.read(&mut buffer).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed"));
        }
        let response: Message = bincode::deserialize(&buffer[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        println!("Received {:?} from peer {}", response, peer.id);

        // Expect Pong
        if let Message::Pong = response {
            // Read PeerList
            let n = socket.read(&mut buffer).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed"));
            }
            let peer_list_msg: Message = bincode::deserialize(&buffer[..n])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if let Message::PeerList(peers_received) = peer_list_msg {
                println!("Received PeerList from {}: {:?}", peer.id, peers_received);
                let mut peers = self.peers.lock().await;
                for p in peers_received {
                    if p.id != self.own_id && !peers.iter().any(|existing| existing.id == p.id) {
                        peers.push(p.clone());
                        let p_for_connect = p.clone();
                        drop(peers);
                        if let Err(e) = Box::pin(self.connect_to_peer(p_for_connect)).await {
                            eprintln!("Failed to connect to peer {}: {}", p.id, e);
                        }
                        peers = self.peers.lock().await;
                    }
                }
            }
        }

        // Add original peer to known peers
        let mut peers = self.peers.lock().await;
        if !peers.iter().any(|p| p.id == peer.id) {
            peers.push(peer);
        }

        Ok(())
    }

    async fn handle_connection(mut socket: TcpStream, peers: Arc<Mutex<Vec<Peer>>>, own_id: u64) -> io::Result<()> {
        let mut buffer = [0u8; 1024];
        let n = socket.read(&mut buffer).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed"));
        }

        let message: Message = bincode::deserialize(&buffer[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        println!("Received message: {:?}", message);

        if let Message::Ping = message {
            // Send Pong
            let pong = Message::Pong;
            let serialized = bincode::serialize(&pong)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            socket.write_all(&serialized).await?;
            socket.flush().await?;
            println!("Sent response: {:?}", pong);

            // Send PeerList
            let peers = peers.lock().await;
            let peer_list = Message::PeerList(peers.clone());
            let serialized = bincode::serialize(&peer_list)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            socket.write_all(&serialized).await?;
            socket.flush().await?;
            println!("Sent PeerList: {:?}", peer_list);
        }

        Ok(())
    }
}