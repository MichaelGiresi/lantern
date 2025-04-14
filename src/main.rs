mod network;
mod peer;
mod message;

use network::start_server;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::message::Message;
use std::io;
use bincode;

#[tokio::main]
async fn main() -> io:: Result<()> {
    println!("**********");
    println!("*");
    println!("*");
    println!("*");
    println!("Welcome to Lantern");
    println!("*");
    println!("*");
    println!("*");
    println!("**********");
    println!("");
    
    println!("Illuminate!");

    let server_address = "127.0.0.1:8080";
    tokio::spawn(async move {
        if let Err(e) = start_server(server_address).await {
            eprintln!("Server error:{}", e);
        }
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    println!("Running test client...");
    let mut client = TcpStream::connect(server_address).await?;
    println!("Client connected tp {}", server_address);

    let ping = Message::Ping;
    let serialized = bincode::serialize(&ping).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    client.write_all(&serialized).await?;
    println!("Client sent: {:?}", ping);

    let mut buffer = [0u8; 1024];
    let n = client.read(&mut buffer).await?;
    let response: Message = bincode::deserialize(&buffer[..n]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    println!("Client received: {:?}", response);

    Ok(())
}
