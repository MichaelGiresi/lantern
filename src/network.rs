use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::message::Message;
use std::io;
use bincode;

pub async fn start_server(address: &str) -> io::Result<()> {
    let listener= TcpListener::bind(address).await?;
    println!("Server listening on {}", address);

    loop {
        let (mut socket, addr) = listener.accept().await?;
        println!("New connection from {}", addr);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(&mut socket).await {
                eprintln!("Error handling connection from {}: {}", addr, e);
            }
        });
    }
}

async fn handle_connection(socket: &mut TcpStream) -> io::Result<()> {
    let mut buffer = [0u8; 1024];
    let n = socket.read(&mut buffer).await?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed"));
    }

    let message: Message = bincode::deserialize(&buffer[..n]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    println!("Received message: {:?}", message);

    if let Message::Ping = message {
        let response = Message::Pong;
        let serialized = bincode::serialize(&response).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        socket.write_all(&serialized).await?;
        socket.flush().await?;
        println!("Sent response: {:?}", response);
    }

    Ok(())
}