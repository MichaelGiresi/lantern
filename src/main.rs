mod network;
mod peer;
mod message;

use network::start_server;

#[tokio::main]
async fn main() {
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
    let address = "127.0.0.1:8080";
    if let Err(e) = start_server(address).await {
        eprintln!("Server error: {}", e);
    }
    
}
