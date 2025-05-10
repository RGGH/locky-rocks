use rocksdb::{DB, Options};
use std::path::Path;
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::{aead::Aead, Nonce};
use rand::{Rng, rngs::OsRng};

struct EncryptedCounter {
    db: DB,
    counter_key: Vec<u8>,
    cipher: Aes256Gcm,
}

impl EncryptedCounter {
    // This is your secret key - in production, derive this from a password or store securely
    // For true security, don't hardcode it like this
    const KEY_BYTES: [u8; 32] = [
        0x25, 0x19, 0x83, 0xee, 0x4f, 0x65, 0xb1, 0xc3,
        0x7d, 0x9a, 0x6e, 0x5b, 0x0f, 0x4a, 0xcf, 0xd5,
        0x3c, 0x2b, 0xdb, 0x37, 0x17, 0xb6, 0xac, 0x8e,
        0x1f, 0x44, 0x0a, 0xd8, 0x6c, 0x55, 0x91, 0xe2,
    ];
    
    // Initialize the counter database with encryption
    pub fn new(db_path: &str, counter_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        
        let db = DB::open(&opts, Path::new(db_path))?;
        let counter_key = counter_name.as_bytes().to_vec();
        
        // Create cipher using the KeyInit trait
        let cipher = Aes256Gcm::new_from_slice(&Self::KEY_BYTES)
            .expect("Invalid key length");
        
        let counter = Self {
            db,
            counter_key,
            cipher,
        };
        
        // Only initialize if the counter doesn't exist or is corrupted
        match counter.get() {
            Ok(_) => {}, // Counter exists and is valid
            Err(_) => {
                // Counter doesn't exist or is corrupted, initialize it
                counter.set(0)?;
            }
        }
        
        Ok(counter)
    }
    
    // Check if counter exists
    pub fn exists(&self) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(self.db.get(&self.counter_key)?.is_some())
    }
    
    // Get the current value
    pub fn get(&self) -> Result<u64, Box<dyn std::error::Error>> {
        match self.db.get(&self.counter_key)? {
            Some(encrypted_data) => {
                // The first 12 bytes are the nonce, the rest is the encrypted value
                if encrypted_data.len() <= 12 {
                    return Err("Corrupted data: too short".into());
                }
                
                let (nonce_bytes, encrypted_value) = encrypted_data.split_at(12);
                let nonce = Nonce::from_slice(nonce_bytes);
                
                // Decrypt the value
                let decrypted = self.cipher.decrypt(nonce, encrypted_value)
                    .map_err(|_| "Decryption failed - data may be corrupted")?;
                
                if decrypted.len() == 8 {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&decrypted);
                    Ok(u64::from_le_bytes(bytes))
                } else {
                    Err("Corrupted data: wrong length after decryption".into())
                }
            },
            None => Err("Counter not found".into()),
        }
    }
    
    // Set to specific value
    pub fn set(&self, value: u64) -> Result<(), Box<dyn std::error::Error>> {
        let value_bytes = value.to_le_bytes();
        
        // Generate a new nonce for each write
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the value
        let encrypted = self.cipher.encrypt(nonce, value_bytes.as_ref())
            .map_err(|_| "Encryption failed")?;
        
        // Store nonce + encrypted data together
        let mut data_to_store = Vec::with_capacity(12 + encrypted.len());
        data_to_store.extend_from_slice(&nonce_bytes);
        data_to_store.extend_from_slice(&encrypted);
        
        self.db.put(&self.counter_key, data_to_store)?;
        Ok(())
    }
    
    // Increment by 1 and return new value
    pub fn increment(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let current = match self.get() {
            Ok(value) => value,
            Err(_) => {
                // If there's an error reading, initialize to 0 first
                self.set(0)?;
                0
            }
        };
        let new_value = current + 1;
        self.set(new_value)?;
        Ok(new_value)
    }
    
    // Increment by specified amount
    pub fn increment_by(&self, amount: u64) -> Result<u64, Box<dyn std::error::Error>> {
        let current = match self.get() {
            Ok(value) => value,
            Err(_) => {
                // If there's an error reading, initialize to 0 first
                self.set(0)?;
                0
            }
        };
        let new_value = current + amount;
        self.set(new_value)?;
        Ok(new_value)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example usage
    let counter = EncryptedCounter::new("./counter_db", "my_secure_counter")?;
    
    println!("Current value: {}", counter.get()?);
    println!("After increment: {}", counter.increment()?);
    println!("After incrementing by 5: {}", counter.increment_by(5)?);
    
    Ok(())
}
