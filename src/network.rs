use tokio::net::TcpListener;
use std::io;

pub async fn start_server(address: &str) -> io::Result<()> {
    let listener= TcpListener::bind(address).await?;
    println!("Server listening on {}", address);

    loop {
        let (_socket, addr) = listener.accept().await?;
        println!("New connection from {}", addr);
    }
}