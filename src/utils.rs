use sha2::{Sha256, Digest as Sha2Digest};
use std::hash::Hasher as StdHasher;
use merkletree::hash::Algorithm;

pub fn sanitize_filename(filename: &str) -> String {
    filename
        .replace("..", "")
        .replace("/", "")
        .replace("\\", "")
        .replace(":", "")
}

#[derive(Clone, Default)]
pub struct Sha256Algorithm(Sha256);

impl Sha256Algorithm {
    pub fn new() -> Sha256Algorithm {
        Sha256Algorithm(Sha256::new())
    }
}

impl Algorithm<[u8; 32]> for Sha256Algorithm {
    fn hash(&mut self) -> [u8; 32] {
        let digest = self.0.finalize_reset();
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest[..32]);
        result
    }

    fn reset(&mut self) {
        self.0 = Sha256::new();
    }

    fn leaf(&mut self, leaf: [u8; 32]) -> [u8; 32] {
        self.0.update(&leaf[..]);
        let digest = self.0.finalize_reset();
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest[..32]);
        result
    }

    fn node(&mut self, left: [u8; 32], right: [u8; 32], _depth: usize) -> [u8; 32] {
        self.0.update(&left[..]);
        self.0.update(&right[..]);
        let digest = self.0.finalize_reset();
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest[..32]);
        result
    }
}

impl StdHasher for Sha256Algorithm {
    fn finish(&self) -> u64 {
        let digest = self.0.clone().finalize();
        u64::from_le_bytes(digest[..8].try_into().unwrap())
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}