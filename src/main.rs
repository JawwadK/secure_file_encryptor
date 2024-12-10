use clap::Parser;
use std::path::PathBuf;
use std::fs::{self, File};
use std::io::Read;
use sha2::{Sha256, Digest};
use rand::RngCore;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// File to encrypt/decrypt
    #[arg(short, long)]
    file: PathBuf,

    /// Password for encryption/decryption
    #[arg(short, long)]
    password: String,

    /// Encrypt or decrypt mode
    #[arg(short, long)]
    encrypt: bool,
}

#[derive(Debug)]
enum CryptoError {
    IoError(std::io::Error),
    AesError(String),
    InvalidSalt,
    InvalidFileFormat,
}

impl std::error::Error for CryptoError {}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::IoError(e) => write!(f, "IO Error: {}", e),
            CryptoError::AesError(e) => write!(f, "Encryption Error: {}", e),
            CryptoError::InvalidSalt => write!(f, "Invalid salt format"),
            CryptoError::InvalidFileFormat => write!(f, "Invalid encrypted file format"),
        }
    }
}

impl From<std::io::Error> for CryptoError {
    fn from(error: std::io::Error) -> Self {
        CryptoError::IoError(error)
    }
}

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};

const MAGIC_BYTES: &[u8] = b"AESFILE";
const VERSION: u8 = 1;

fn derive_key(password: &str, salt: Option<&str>) -> Result<([u8; 32], [u8; 12], String), CryptoError> {
    let salt = match salt {
        Some(s) => SaltString::from_b64(s).map_err(|_| CryptoError::InvalidSalt)?,
        None => SaltString::generate(&mut OsRng)
    };
    
    let argon2 = Argon2::default();
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::AesError(e.to_string()))?
        .to_string();
    
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    
    // Generate a random nonce instead of deriving it
    OsRng.fill_bytes(&mut nonce);
    
    // Use HKDF to derive the key
    let mut okm = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(
        Some(salt.as_ref().as_bytes()),  // Convert SaltString to &[u8]
        password_hash.as_bytes()
    )
    .expand(&[], &mut okm)
    .map_err(|e| CryptoError::AesError(e.to_string()))?;
    
    key.copy_from_slice(&okm);
    
    Ok((key, nonce, salt.to_string()))
}

fn encrypt_file(input_path: &PathBuf, password: &str) -> Result<(), CryptoError> {
    let (key, nonce, salt) = derive_key(password, None)?;
    
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CryptoError::AesError(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce);
    
    let mut file = File::open(input_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    
    let file_size = contents.len();
    let original_hash = format!("{:x}", Sha256::digest(&contents));
    println!("Original file size: {} bytes", file_size);
    println!("Original file hash: {}", original_hash);
    
    let encrypted_data = cipher
        .encrypt(nonce, contents.as_ref())
        .map_err(|e| CryptoError::AesError(e.to_string()))?;
    
    // File format:
    // MAGIC_BYTES (7 bytes)
    // VERSION (1 byte)
    // SALT_LENGTH (1 byte)
    // SALT (variable)
    // NONCE (12 bytes)
    // ENCRYPTED_DATA (rest)
    let mut final_data = Vec::with_capacity(
        MAGIC_BYTES.len() + 1 + 1 + salt.len() + 12 + encrypted_data.len()
    );
    
    final_data.extend_from_slice(MAGIC_BYTES);
    final_data.push(VERSION);
    final_data.push(salt.len() as u8);
    final_data.extend(salt.as_bytes());
    final_data.extend_from_slice(&nonce);
    final_data.extend(encrypted_data);
    
    let output_path = input_path.to_string_lossy().to_string() + ".encrypted";
    fs::write(&output_path, &final_data)?;
    
    println!("Encrypted file size: {} bytes", final_data.len());
    println!("Output file: {}", output_path);
    Ok(())
}

fn decrypt_file(input_path: &PathBuf, password: &str) -> Result<(), CryptoError> {
    let encrypted_data = fs::read(input_path)?;
    
    // Verify magic bytes and version
    if encrypted_data.len() < MAGIC_BYTES.len() + 2 {
        return Err(CryptoError::InvalidFileFormat);
    }
    
    if &encrypted_data[..MAGIC_BYTES.len()] != MAGIC_BYTES {
        return Err(CryptoError::InvalidFileFormat);
    }
    
    let version = encrypted_data[MAGIC_BYTES.len()];
    if version != VERSION {
        return Err(CryptoError::InvalidFileFormat);
    }
    
    let salt_len = encrypted_data[MAGIC_BYTES.len() + 1] as usize;
    if encrypted_data.len() < MAGIC_BYTES.len() + 2 + salt_len + 12 {
        return Err(CryptoError::InvalidFileFormat);
    }
    
    let start = MAGIC_BYTES.len() + 2;
    let salt = std::str::from_utf8(&encrypted_data[start..start + salt_len])
        .map_err(|_| CryptoError::InvalidFileFormat)?;
    
    let nonce_start = start + salt_len;
    let nonce = &encrypted_data[nonce_start..nonce_start + 12];
    let encrypted_content = &encrypted_data[nonce_start + 12..];
    
    let (key, _, _) = derive_key(password, Some(salt))?;
    
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CryptoError::AesError(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce);
    
    let decrypted_data = cipher
        .decrypt(nonce, encrypted_content)
        .map_err(|e| CryptoError::AesError(e.to_string()))?;
    
    let output_path = input_path.to_string_lossy()
        .replace(".encrypted", "")
        + ".decrypted";
    fs::write(&output_path, &decrypted_data)?;
    
    println!("Decryption successful!");
    println!("Decrypted file size: {} bytes", decrypted_data.len());
    println!("Decrypted hash: {}", format!("{:x}", Sha256::digest(&decrypted_data)));
    println!("Output file: {}", output_path);
    
    Ok(())
}

fn main() {
    let args = Args::parse();

    let result = if args.encrypt {
        println!("Encrypting file...");
        encrypt_file(&args.file, &args.password)
    } else {
        println!("Decrypting file...");
        decrypt_file(&args.file, &args.password)
    };

    match result {
        Ok(_) => println!("Operation completed successfully!"),
        Err(e) => eprintln!("Error: {}", e),
    }
}