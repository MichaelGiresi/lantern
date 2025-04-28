use std::fs::File;
use std::path::Path;
use std::io::Write;
use sha3::Sha3_256;
use sha2::{Sha256, Digest as Sha2Digest};
use hex;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use ecdsa::Signature;
use ecdsa::signature::{Signer, Verifier};
use p256::{ecdsa::{SigningKey, VerifyingKey}, SecretKey, AffinePoint};
use rand::rngs::OsRng;
use serde_json;
use rcgen;
use generic_array::GenericArray;
use typenum::U32;
use super::blockchain::{Transaction, NodeKey};
use tracing::error;

pub fn generate_key_pair() -> (SigningKey, VerifyingKey) {
    let secret_key = SecretKey::random(&mut OsRng);
    let signing_key = SigningKey::from(secret_key);
    let binding = signing_key.clone();
    let verifying_key = binding.verifying_key();
    (signing_key, *verifying_key)
}

pub fn load_or_generate_node_key() -> (SigningKey, VerifyingKey) {
    let path = "node_key.json";
    if Path::new(path).exists() {
        let contents = std::fs::read_to_string(path).expect("Failed to read node_key.json");
        let node_key: NodeKey = serde_json::from_str(&contents).expect("Failed to parse node_key.json");
        let signing_key = SigningKey::from_bytes(
            GenericArray::from_slice(&node_key.private_key)
        ).expect("Invalid private key");
        let verifying_key = VerifyingKey::from_sec1_bytes(&node_key.public_key).expect("Invalid public key");
        (signing_key, verifying_key)
    } else {
        let (signing_key, verifying_key) = generate_key_pair();
        let node_key = NodeKey {
            private_key: signing_key.to_bytes().to_vec(),
            public_key: verifying_key.to_encoded_point(false).as_bytes().to_vec(),
        };
        let mut file = File::create(path).expect("Failed to create node_key.json");
        let json = serde_json::to_string(&node_key).expect("Failed to serialize node key");
        file.write_all(json.as_bytes()).expect("Failed to write node_key.json");
        (signing_key, verifying_key)
    }
}

pub fn generate_user_key_nonce(user_id: &str) -> (Vec<u8>, Vec<u8>) {
    let mut hasher = Sha3_256::new();
    hasher.update(user_id);
    hasher.update(b"salt_for_weave");
    let result = hasher.finalize();
    let key = result[..32].to_vec();
    let nonce = result[32..44].to_vec();
    (key, nonce)
}

pub fn sign_transaction(tx: &Transaction, signing_key: &SigningKey) -> String {
    let input = format!("{}{}{}{}", tx.sender, tx.receiver, tx.amount, tx.fee);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let signature: Signature<p256::NistP256> = signing_key.sign(&digest);
    hex::encode(signature.to_der().as_bytes())
}

pub fn verify_transaction(tx: &Transaction, verifying_key: &VerifyingKey) -> bool {
    let input = format!("{}{}{}{}", tx.sender, tx.receiver, tx.amount, tx.fee);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let finalized = hasher.finalize();
    let digest = GenericArray::<u8, U32>::from_slice(&finalized[..32]);
    let signature_bytes = hex::decode(&tx.signature).unwrap_or_default();
    match Signature::<p256::NistP256>::from_der(&signature_bytes) {
        Ok(signature) => verifying_key.verify(digest, &signature).is_ok(),
        Err(_) => false,
    }
}

pub fn generate_certificates() -> Result<(rcgen::Certificate, rcgen::KeyPair), String> {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".to_string()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)))
    ];
    let key_pair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| format!("Failed to generate key pair: {}", e))?;
    let cert = rcgen::Certificate::from_params(params)
        .map_err(|e| format!("Failed to generate certificate: {}", e))?;
    Ok((cert, key_pair))
}

pub fn save_certificates(cert: &rcgen::Certificate, key_pair: &rcgen::KeyPair) -> Result<(), String> {
    let mut cert_file = File::create("cert.pem").map_err(|e| format!("Failed to create cert.pem: {}", e))?;
    cert_file.write_all(cert.serialize_pem().unwrap().as_bytes())
        .map_err(|e| format!("Failed to write cert.pem: {}", e))?;
    let mut key_file = File::create("key.pem").map_err(|e| format!("Failed to create key.pem: {}", e))?;
    key_file.write_all(key_pair.serialize_pem().as_bytes()).map_err(|e| format!("Failed to write key.pem: {}", e))?;
    Ok(())
}

pub fn encrypt_data(data: &str, key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("Invalid key length: expected 32 bytes, got {}", key.len()));
    }
    if nonce.len() != 12 {
        return Err(format!("Invalid nonce length: expected 12 bytes, got {}", nonce.len()));
    }
    let key_array: [u8; 32] = key.try_into().map_err(|_| "Failed to convert key to array")?;
    let key = Key::<Aes256Gcm>::from_slice(&key_array);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);
    let ciphertext = cipher.encrypt(nonce, data.as_bytes())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;
    Ok(ciphertext)
}

pub fn decrypt_data(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<String, String> {
    if key.len() != 32 {
        return Err(format!("Invalid key length: expected 32 bytes, got {}", key.len()));
    }
    if nonce.len() != 12 {
        return Err(format!("Invalid nonce length: expected 12 bytes, got {}", nonce.len()));
    }
    let key_array: [u8; 32] = key.try_into().map_err(|_| "Failed to convert key to array")?;
    let key = Key::<Aes256Gcm>::from_slice(&key_array);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;
    String::from_utf8(plaintext)
        .map_err(|e| format!("Failed to convert decrypted data to string: {}", e))
}