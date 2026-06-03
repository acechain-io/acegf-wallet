// src/main.rs
use acegf::acegf_core::ACEGFCore;
use acegf::ACEGF;
use aes_gcm::{aead::Aead, Aes256Gcm, Error as AesGcmError, KeyInit, Nonce as AesNonce};
use arrayref::array_ref;
use base64ct::{Base64, Encoding};
use crypto_common::{
    rand_core::{OsRng, RngCore},
    InvalidLength,
};
use serde_json;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

// Custom error type (unchanged)
#[derive(Debug)]
enum CryptoTestError {
    AesGcmError(String),
    InvalidLengthError(String),
    Base64Error(String),
    CustomError(String),
    InternalError(String),
}

impl fmt::Display for CryptoTestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoTestError::AesGcmError(msg) => write!(f, "AES-GCM error: {}", msg),
            CryptoTestError::InvalidLengthError(msg) => write!(f, "Invalid length error: {}", msg),
            CryptoTestError::Base64Error(msg) => write!(f, "Base64 error: {}", msg),
            CryptoTestError::CustomError(msg) => write!(f, "Error: {}", msg),
            CryptoTestError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl Error for CryptoTestError {}

impl From<InvalidLength> for CryptoTestError {
    fn from(e: InvalidLength) -> Self {
        CryptoTestError::InvalidLengthError(format!("{}", e))
    }
}

impl From<AesGcmError> for CryptoTestError {
    fn from(e: AesGcmError) -> Self {
        CryptoTestError::AesGcmError(format!("{}", e))
    }
}

fn main() {
    println!("------ ACEGF Version -------");
    println!("     ACE-GF V{}", ACEGF::VERSION.to_string());
    println!("----------------------------");

    let passphrase = "my_strong_password";
    let secondary_passphrase = Some("my_salt_or_extra_pass");

    // End-to-end test harness state
    let mut current_ace_mnemonic = String::new();

    println!("\n--- Generating Native ACEGF Entity ---");
    let mut native_mnemonic = String::new();
    match ACEGFCore::generate_ace_internal(passphrase, secondary_passphrase) {
        Ok(entity) => {
            native_mnemonic = (*entity.mnemonic).clone(); // keep generated native mnemonic
            match serde_json::to_string_pretty(&entity) {
                Ok(json) => println!("{}", json),
                Err(_) => println!(
                    "Crypto entity generated but failed to serialize json, mnemonic: {}",
                    entity.mnemonic.as_str()
                ),
            }
        }
        Err(e) => {
            eprintln!("❌ Generation failed! Error: {:?}", e);
        }
    }

    let new_passphrase = "my_new_password";
    let mut rekeyed_mnemonic = String::new();
    println!("\n--- Rekeying ACEGF Entity (Using Native Mnemonic) ---");
    // Use the generated native_mnemonic, not a hardcoded string
    match ACEGFCore::change_passphrase_internal(
        &native_mnemonic,
        passphrase,
        new_passphrase,
        secondary_passphrase,
    ) {
        Ok(new_mnemonic) => {
            rekeyed_mnemonic = new_mnemonic.clone();
            println!("✅ Rekeying succeeded! New mnemonic: {}", rekeyed_mnemonic);
        }
        Err(e) => {
            eprintln!("❌ Rekeying failed! Error: {:?}", e);
        }
    }

    println!("\n--- View ACEGF Entity ---");
    // Use rekeyed mnemonic and new_passphrase from rekey
    match ACEGFCore::view_wallet_internal(&rekeyed_mnemonic, new_passphrase, secondary_passphrase) {
        Ok(entity) => match serde_json::to_string_pretty(&entity) {
            Ok(json) => println!("{}", json),
            Err(_) => println!("ACEGF entity exported successfully, but failed to serialize json"),
        },
        Err(e) => {
            eprintln!("❌ Failed to export ACEGF entity! Error: {:?}", e);
        }
    }

    println!("\n=== Testing Encryption & Decryption ===");
    let plaintext_data =
        b"Hello ACEGF! This is a secret message for testing encryption and decryption.";

    // Decrypt with a valid mnemonic (here: post-rekey)
    let decrypt_mnemonic = &rekeyed_mnemonic;
    let decrypt_passphrase = new_passphrase;
    let decrypt_secondary_pass = secondary_passphrase;

    let (ephemeral_secret, ephemeral_pub_b64) = generate_ephemeral_x25519_key();
    println!(
        "✅ Generated ephemeral X25519 public key (base64): {}",
        ephemeral_pub_b64
    );

    let recipient_pub_b64 = match get_recipient_x25519_pubkey(
        decrypt_mnemonic,
        decrypt_passphrase,
        decrypt_secondary_pass,
    ) {
        Ok(pub_key) => pub_key,
        Err(e) => {
            eprintln!("❌ Failed to get X25519 public key: {:?}", e);
            return;
        }
    };
    println!(
        "✅ Recipient X25519 public key (base64): {}",
        recipient_pub_b64
    );

    let (encrypted_data, encrypted_aes_key_b64, iv_b64) = match encrypt_data_with_recipient_pub(
        plaintext_data,
        &ephemeral_secret,
        &recipient_pub_b64,
    ) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("❌ Failed to encrypt data: {:?}", e);
            return;
        }
    };
    println!("✅ Data encrypted successfully!");

    let decrypted_data = match ACEGF::decrypt_internal(
        decrypt_mnemonic,
        decrypt_passphrase,
        &ephemeral_pub_b64,
        &encrypted_aes_key_b64,
        &iv_b64,
        &encrypted_data,
        decrypt_secondary_pass,
    ) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("❌ Decryption failed! Error: {:?}", e);
            return;
        }
    };

    println!("\n=== Decryption Result ===");
    println!(
        "Original plaintext: {}",
        String::from_utf8_lossy(plaintext_data)
    );
    println!(
        "Decrypted plaintext: {}",
        String::from_utf8_lossy(&decrypted_data)
    );

    if decrypted_data == plaintext_data {
        println!("✅ Decryption SUCCESS! Data matches original.");
    } else {
        eprintln!("❌ Decryption FAILED! Data does not match.");
    }

    // =========================================================================
    // View wallet addresses for known mnemonic/passphrase pairs
    // =========================================================================
    println!("\n=== View Wallet Addresses ===");

    let wallet_pairs: &[(&str, &str)] = &[
        (
            "obey trust cruel undo because focus true portion wise indoor endless goat canvas basic mixed focus atom aim rude monitor boil feature seed genuine",
            "2wsxzaq1",
        ),
        (
            "awkward shift carpet hazard peasant embark total into whisper minimum knife coach cousin treat pledge company help oval thought exit play cheese rocket spatial",
            "test_passphrase_do_not_use",
        ),
    ];

    for (i, (mnemonic, pass)) in wallet_pairs.iter().enumerate() {
        println!("\n========== Wallet {} ==========", i + 1);
        println!("Passphrase: {}", pass);

        // Unified view
        match ACEGFCore::view_wallet_unified(mnemonic, pass, None) {
            Ok(entity) => {
                println!("  Solana:    {}", entity.solana_address);
                println!("  EVM:       {}", entity.evm_address);
                println!("  Bitcoin:   {}", entity.bitcoin_address);
                println!("  Cosmos:    {}", entity.cosmos_address);
                println!("  Polkadot:  {}", entity.polkadot_address);
                println!("  XIdentity: {}", entity.xidentity);
                println!("  XAddress:  {}", entity.xaddress);
            }
            Err(e) => {
                eprintln!("  ❌ view_wallet_unified failed: {:?}", e);
            }
        }

        // With vault context
        let ctx = ACEGFCore::build_vault_context(&["corp-abc", "OperatingFund", "0"]);
        println!("\n  --- With context: \"{}\" ---", ctx);
        match ACEGFCore::view_wallet_unified_with_context(mnemonic, pass, None, &ctx) {
            Ok(entity) => {
                println!("  Solana:    {}", entity.solana_address);
                println!("  EVM:       {}", entity.evm_address);
                println!("  Bitcoin:   {}", entity.bitcoin_address);
                println!("  Cosmos:    {}", entity.cosmos_address);
                println!("  Polkadot:  {}", entity.polkadot_address);
                println!("  XIdentity: {}", entity.xidentity);
                println!("  XAddress:  {}", entity.xaddress);
            }
            Err(e) => {
                println!("  Context not supported for this mnemonic format: {:?}", e);
            }
        }
    }
}

// Helper functions (unchanged behavior)
fn generate_ephemeral_x25519_key() -> (StaticSecret, String) {
    let mut csprng = OsRng;
    let ephemeral_secret = StaticSecret::random_from_rng(&mut csprng);
    let ephemeral_pub = XPublic::from(&ephemeral_secret);
    let ephemeral_pub_b64 = Base64::encode_string(ephemeral_pub.as_bytes());
    (ephemeral_secret, ephemeral_pub_b64)
}

fn get_recipient_x25519_pubkey(
    mnemonic: &str,
    passphrase: &str,
    secondary_passphrase: Option<&str>,
) -> Result<String, Box<dyn Error>> {
    let mut seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, secondary_passphrase)
        .map_err(|e| {
            Box::new(CryptoTestError::InternalError(format!(
                "Derive seeds failed: {:?}",
                e
            ))) as Box<dyn Error>
        })?;
    let x25519_seed = &seeds.x25519;

    let mut raw = **x25519_seed;
    raw[0] &= 248;
    raw[31] &= 127;
    raw[31] |= 64;
    let private = StaticSecret::from(raw);

    let public = XPublic::from(&private);
    let pub_b64 = Base64::encode_string(public.as_bytes());

    ACEGFCore::clear_scheme_seeds(&mut seeds);
    Ok(pub_b64)
}

fn encrypt_data_with_recipient_pub(
    plaintext: &[u8],
    ephemeral_secret: &StaticSecret,
    recipient_pub_b64: &str,
) -> Result<(Vec<u8>, String, String), Box<dyn Error>> {
    let recipient_pub_bytes = Base64::decode_vec(recipient_pub_b64)
        .map_err(|e| Box::new(CryptoTestError::Base64Error(format!("{}", e))) as Box<dyn Error>)?;

    let recipient_pub = XPublic::from(*array_ref![recipient_pub_bytes, 0, 32]);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pub);
    let dh_hash = Sha256::digest(shared_secret.as_bytes());
    let mut dh_key = vec![0u8; 32];
    dh_key.copy_from_slice(&dh_hash[..]);

    let mut real_aes_key = vec![0u8; 32];
    OsRng.fill_bytes(&mut real_aes_key);

    let mut iv_bytes = vec![0u8; 12];
    OsRng.fill_bytes(&mut iv_bytes);
    let nonce = AesNonce::from_slice(&iv_bytes);

    let master_key = Aes256Gcm::new_from_slice(&dh_key).map_err(|e| CryptoTestError::from(e))?;
    let encrypted_aes_key = master_key
        .encrypt(nonce, &real_aes_key[..])
        .map_err(|e| CryptoTestError::from(e))?;

    let data_cipher =
        Aes256Gcm::new_from_slice(&real_aes_key).map_err(|e| CryptoTestError::from(e))?;
    let encrypted_data = data_cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoTestError::from(e))?;

    Ok((
        encrypted_data,
        Base64::encode_string(&encrypted_aes_key),
        Base64::encode_string(&iv_bytes),
    ))
}
