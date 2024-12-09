use clap::Parser;
use std::path::PathBuf;
use std::fs::{self, File};
use std::io::Read;


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
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};

fn derive_key(password: &str) -> ([u8; 32], [u8; 12]) {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    
    key.copy_from_slice(&password_hash.as_bytes()[0..32]);
    nonce.copy_from_slice(&password_hash.as_bytes()[32..44]);
    
    (key, nonce)
}

fn encrypt_file(input_path: &PathBuf, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Generate key and nonce from password
    let (key, nonce) = derive_key(password);
    
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce = Nonce::from_slice(&nonce);
    
    // Read file contents
    let mut file = File::open(input_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    
    // Encrypt the data
    let encrypted_data = cipher.encrypt(nonce, contents.as_ref())?;
    
    // Write encrypted data to new file
    let output_path = input_path.with_extension("encrypted");
    fs::write(output_path, encrypted_data)?;
    
    Ok(())
}

fn decrypt_file(input_path: &PathBuf, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Generate key and nonce from password
    let (key, nonce) = derive_key(password);
    
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce = Nonce::from_slice(&nonce);
    
    // Read encrypted data
    let encrypted_data = fs::read(input_path)?;
    
    // Decrypt the data
    let decrypted_data = cipher.decrypt(nonce, encrypted_data.as_ref())?;
    
    // Write decrypted data to new file
    let output_path = input_path.with_extension("decrypted");
    fs::write(output_path, decrypted_data)?;
    
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