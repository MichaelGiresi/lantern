use serde::{Serialize, Deserialize};
use crate::peer::Peer;

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    Ping,
    Pong,
    PeerList(Vec<Peer>),
}