use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use log::info;
use bincode::serialize;
use failure::Error;
use serde::Serialize;
use serde::Deserialize;

pub type Result<T> = std::result::Result<T, Error>;
const TARGET_HEXT: usize = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    timestamp: u128,
    transaction: String,
    prev_block_hash: String,
    hash: String,   
    height: usize,
    nonce: i32,
}

#[derive(Debug)]
pub struct Blockchain {
    blocks: Vec<Block>,
}

impl Block {
    pub fn get_hash(&self) -> String {  
        self.hash.clone()
    }
    pub fn new_genesis_block() -> Block {
        let mut hasher = Sha256::new();
        hasher.update("Genesis Block".as_bytes());
        let hash = hasher.finalize().to_vec();
        Block {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),
            transaction: "Genesis Block".to_string(),
            prev_block_hash: "".to_string(),
            hash: hex::encode(hash),
            height: 0,
            nonce: 0,
        }
    }

    pub fn new_block(data: String, prev_block_hash: String, height: usize) -> Result<Block> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let mut block = Block {
            timestamp,
            transaction: data,
            prev_block_hash,
            hash: String::new(),
            height,
            nonce: 0,
        };
        block.run_proof_of_work()?;
        Ok(block)
    }

    fn run_proof_of_work(&mut self) -> Result<()> {
        info!("Майнинг блока");
        loop {
            let data = self.prepare_hash_data()?;
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let hash = hasher.finalize();
            let hash_hex = hex::encode(hash);

            if hash_hex.starts_with(&"0".repeat(TARGET_HEXT)) {
                self.hash = hash_hex;
                break;
            }
            self.nonce += 1;
        }
        Ok(())
    }

    fn prepare_hash_data(&self) -> Result<Vec<u8>> {
        Ok(serialize(&(
            self.prev_block_hash.clone(),
            self.transaction.clone(),
            self.timestamp,
            self.nonce,
        ))?)
    }

    fn validate(&self) -> Result<bool> {
        let data = self.prepare_hash_data()?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash_hex = hex::encode(hasher.finalize());
        Ok(hash_hex.starts_with(&"0".repeat(TARGET_HEXT)))
    }
}

impl Blockchain {
    pub fn new() -> Blockchain {
        Blockchain {
            blocks: vec![Block::new_genesis_block()],
        }
    }

    pub fn add_block(&mut self, data: String) -> Result<()> {
        let prev_block = self.blocks.last().unwrap();
        let new_block = Block::new_block(data.clone(), prev_block.get_hash(), self.blocks.len())?;
        self.blocks.push(new_block);
        Ok(())
    }
}


fn main() -> Result<()> {
    env_logger::init();
    let mut blockchain = Blockchain::new();
    blockchain.add_block("Транзакция 1".to_string())?;
    blockchain.add_block("Транзакция 2".to_string())?;
    blockchain.add_block("Транзакция 3".to_string())?;
    println!("{:?}", blockchain);
    Ok(())
}