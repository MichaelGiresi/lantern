use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::message::Message;
use crate::peer::Peer;
use std::io;
use bincode;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct Network {
    peers: Arc<Mutex<Vec<Peer>>>,
}

impl Network {
    pub fn new() -> Self {
        Network {
            peers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn start(&self, address: &str) -> io::Result<()> {
        let listener = TcpListener::bind(address).await?;
        println!("Server listening on {}", address);

        loop {
            let (socket, addr) = listener.accept().await?;
            println!("New connection from {}", addr);
            let peers = Arc::clone(&self.peers);
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(socket, peers).await {
                    eprintln!("Error handling connection from {}: {}", addr, e);
                }
            });
        }
    }

    pub async fn connect_to_peer(&self, peer: Peer) -> io::Result<()> {
        let mut socket = TcpStream::connect(peer.address).await?;
        println!("Connected to peer {} at {}", peer.id, peer.address);

        // Send a Ping
        let message = Message::Ping;
        let serialized = bincode::serialize(&message)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        socket.write_all(&serialized).await?;
        socket.flush().await?;
        println!("Sent Ping to peer {}", peer.id);

        // Read response
        let mut buffer = [0u8; 1024];
        let n = socket.read(&mut buffer).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed"));
        }
        let response: Message = bincode::deserialize(&buffer[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        println!("Received {:?} from peer {}", response, peer.id);

        // Add peer to known peers
        let mut peers = self.peers.lock().await;
        if !peers.iter().any(|p| p.id == peer.id) {
            peers.push(peer);
        }

        Ok(())
    }

    async fn handle_connection(mut socket: TcpStream, _peers: Arc<Mutex<Vec<Peer>>>) -> io::Result<()> {
        let mut buffer = [0u8; 1024];
        let n = socket.read(&mut buffer).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed"));
        }

        let message: Message = bincode::deserialize(&buffer[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        println!("Received message: {:?}", message);

        if let Message::Ping = message {
            let response = Message::Pong;
            let serialized = bincode::serialize(&response)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            socket.write_all(&serialized).await?;
            socket.flush().await?;
            println!("Sent response: {:?}", response);
        }

        Ok(())
    }
}