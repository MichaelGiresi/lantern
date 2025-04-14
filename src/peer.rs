use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use rand::Rng;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Peer {
    pub id: u64,
    pub address: SocketAddr,
}

impl Peer {
    pub fn new(address: SocketAddr) -> Self {
        Peer {
            id: rand::thread_rng().r#gen(),
            address,
        }
    }
}