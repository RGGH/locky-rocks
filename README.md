# Locky-Rocks: Encrypted Counter with RocksDB

A secure, persistent counter implementation that uses RocksDB for storage and AES-GCM for encryption.

## Overview

Locky-Rocks provides a simple yet secure way to maintain encrypted counters that persist across application restarts. Built on top of RocksDB, it offers:

- **Data Persistence**: Counter values are stored on disk and survive application restarts
- **Value Encryption**: AES-256-GCM encryption protects counter values from tampering
- **Atomic Operations**: Reliable increment operations even with concurrent access
- **Performance**: Optimized for high-throughput counter operations

## Security Features

### Encryption Details

- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Length**: 256-bit encryption key
- **Authentication**: Built-in authentication with GCM mode
- **Nonce Handling**: Unique 96-bit (12-byte) nonce generated for each write operation

### Security Properties

1. **Confidentiality**: Counter values are encrypted, preventing unauthorized users from seeing the actual values even if they access the database files.

2. **Integrity and Authentication**: The GCM mode provides built-in authentication, detecting any tampering with the encrypted data.

3. **Freshness**: Each update uses a new random nonce, preventing replay attacks where an attacker might try to replace current values with older encrypted values.

4. **Tamper Evidence**: Any attempt to modify the encrypted data manually (e.g., using a hex editor) will result in authentication failure during decryption.

### Security Level

This implementation provides:

- **Strong Protection Against Manual Tampering**: The AES-GCM authentication makes it computationally infeasible to modify the encrypted counter value without knowing the encryption key.

- **Targeted Protection**: Rather than encrypting the entire database, this approach encrypts only the sensitive counter values, providing a balance between security and performance.

- **Protection Against Database Inspection**: Even with direct access to the database files, an attacker cannot determine the counter values without the encryption key.

### Security Limitations

- **Key Management**: The encryption key is currently hardcoded in the application. In a production environment, this key should be securely managed (via environment variables, a secure key management service, etc.).

- **Key in Memory**: While running, the encryption key exists in the application's memory space.

- **Metadata Visibility**: While the counter values are encrypted, the counter names (keys) are stored in plaintext within the RocksDB files.

## Usage Example

```rust
use locky_rocks::EncryptedCounter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create or open an encrypted counter
    let counter = EncryptedCounter::new("./counter_db", "my_secure_counter")?;
    
    // Get the current value
    println!("Current value: {}", counter.get()?);
    
    // Increment counter by 1
    let new_value = counter.increment()?;
    println!("After increment: {}", new_value);
    
    // Increment by specific amount
    let new_value = counter.increment_by(5)?;
    println!("After incrementing by 5: {}", new_value);
    
    Ok(())
}
```

## Build and Run

```bash
# Debug build
cargo build

# Release build with optimizations
cargo build --release

# Run
cargo run --release
```

## Technical Details

The `EncryptedCounter` stores values in RocksDB as follows:

1. The counter name serves as the key in the RocksDB database
2. For each value stored:
   - A fresh 12-byte nonce is generated
   - The u64 counter value is encrypted using AES-GCM with this nonce
   - The nonce and encrypted data are concatenated and stored as the value

When reading the counter value:
1. The encrypted data is retrieved from RocksDB using the counter name
2. The first 12 bytes are extracted as the nonce
3. The remaining bytes are decrypted using the encryption key and nonce
4. The decrypted value is converted back to a u64 counter value

This approach ensures that every update to the counter results in completely different ciphertext, even when incrementing by 1.
