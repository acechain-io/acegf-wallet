// src/signer/tron_signer.rs
//
// TronSigner: Tron transaction and message signing helper built on top of ACE-GF.
//
// Tron uses secp256k1 (same curve as EVM) but has its own:
//   - Address format: Base58Check with 0x41 prefix (starts with "T")
//   - Message signing prefix: "\x19TRON Signed Message:\n32\n"
//   - Transaction signing: raw txID (32-byte SHA256 hash), recoverable ECDSA
//
// Compatible with: Tron mainnet, TRC-10, TRC-20 tokens.

use crate::acegf_core::ACEGFCore;
use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;
use k256::ecdsa::SigningKey;
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use std::error::Error;

pub struct TronSigner;

impl TronSigner {
    // ==============================
    // Key Derivation
    // ==============================

    /// Derive secp256k1 keypair and Tron address from mnemonic + passphrase.
    ///
    /// Returns (signing_key, tron_address_string).
    pub fn derive_keypair(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<(SigningKey, String), Box<dyn Error>> {
        let mut seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, secondary_passphrase)
            .map_err(|e| format!("Unseal failed: {:?}", e))?;

        let signing_key = SigningKey::from_bytes((&*seeds.secp256k1_tron).into())
            .map_err(|e| format!("Invalid secp256k1 key: {:?}", e))?;

        let address = ACEGFCore::derive_tron_address(&seeds.secp256k1_tron)
            .map_err(|e| format!("Address derivation failed: {:?}", e))?;

        ACEGFCore::clear_scheme_seeds(&mut seeds);

        Ok((signing_key, address))
    }

    /// Derive keypair using a pre-derived base_key (skips Argon2).
    pub fn derive_keypair_with_base_key(
        mnemonic: &str,
        base_key: &[u8; 32],
    ) -> Result<(SigningKey, String), Box<dyn Error>> {
        let mut seeds = ACEGFCore::unseal_to_seeds_with_base_key(mnemonic, base_key)?;

        let signing_key = SigningKey::from_bytes((&*seeds.secp256k1_tron).into())
            .map_err(|e| format!("Invalid secp256k1 key: {:?}", e))?;

        let address = ACEGFCore::derive_tron_address(&seeds.secp256k1_tron)
            .map_err(|e| format!("Address derivation failed: {:?}", e))?;

        ACEGFCore::clear_scheme_seeds(&mut seeds);

        Ok((signing_key, address))
    }

    // ==============================
    // Context-Aware Key Derivation (REV32 only)
    // ==============================

    pub fn derive_keypair_with_context(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        context_info: &str,
    ) -> Result<(SigningKey, String), Box<dyn Error>> {
        if context_info.is_empty() {
            return Self::derive_keypair(mnemonic, passphrase, secondary_passphrase);
        }

        let sealed_bytes = ACEGFCore::decode_mnemonic_to_sealed(mnemonic)
            .map_err(|e| format!("Decode mnemonic failed: {:?}", e))?;

        let full_passphrase =
            PassphraseSealingUtil::combine_passphrase(passphrase, secondary_passphrase);
        let kmaster = PassphraseSealingUtil::derive_kmaster_from_rev32(
            full_passphrase.as_bytes(),
            &sealed_bytes,
        )
        .map_err(|e| format!("Derive Kmaster failed: {:?}", e))?;

        let seed = ACEGFCore::derive_secp256k1_tron_seed_from_rev32_with_context(
            &kmaster,
            context_info.as_bytes(),
        )
        .map_err(|e| format!("Context derivation failed: {:?}", e))?;

        let signing_key = SigningKey::from_bytes((&*seed).into())
            .map_err(|e| format!("Invalid secp256k1 key: {:?}", e))?;

        let address = ACEGFCore::derive_tron_address(&seed)
            .map_err(|e| format!("Address derivation failed: {:?}", e))?;

        Ok((signing_key, address))
    }

    /// Derive Tron keypair with context using PRF `base_key` (passkey path; skips mnemonic Argon2).
    ///
    /// Matches the EVM/Solana PRF+context convention: derive `identity_root` from `base_key`,
    /// then HKDF-expand to chain seeds via `derive_from_rev32_with_context` for the Tron slot.
    ///
    /// Note: Passphrase REV32 vault context (`derive_keypair_with_context`) uses `kmaster` directly
    /// in Tron's HKDF; this PRF entry point intentionally mirrors EVM/Solana WASM `*_with_context_prf`.
    pub fn derive_keypair_with_context_base_key(
        mnemonic: &str,
        base_key: &[u8; 32],
        context_info: &str,
    ) -> Result<(SigningKey, String), Box<dyn Error>> {
        if context_info.is_empty() {
            return Self::derive_keypair_with_base_key(mnemonic, base_key);
        }

        let identity_root =
            PassphraseSealingUtil::derive_identity_root(base_key)
                .map_err(|e| format!("Derive identity root failed: {:?}", e))?;

        let mut seeds = ACEGFCore::derive_from_rev32_with_context(
            &identity_root,
            context_info.as_bytes(),
        )
        .map_err(|e| format!("Derive seeds with context failed: {:?}", e))?;

        let signing_key = SigningKey::from_bytes((&*seeds.secp256k1_tron).into())
            .map_err(|e| format!("Invalid secp256k1 key: {:?}", e))?;

        let address =
            ACEGFCore::derive_tron_address(&seeds.secp256k1_tron)
                .map_err(|e| format!("Address derivation failed: {:?}", e))?;

        ACEGFCore::clear_scheme_seeds(&mut seeds);

        Ok((signing_key, address))
    }

    // ==============================
    // Address Utilities
    // ==============================

    /// Get the Tron address for a mnemonic without exposing the signing key.
    pub fn get_address(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<String, Box<dyn Error>> {
        let mut seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, secondary_passphrase)
            .map_err(|e| format!("Unseal failed: {:?}", e))?;
        let address = ACEGFCore::derive_tron_address(&seeds.secp256k1_tron)
            .map_err(|e| format!("Address derivation failed: {:?}", e))?;
        ACEGFCore::clear_scheme_seeds(&mut seeds);
        Ok(address)
    }

    // ==============================
    // Message Signing
    // ==============================

    /// Sign an arbitrary message using the Tron personal-sign convention.
    ///
    /// Tron message hash:
    ///   Keccak256("\x19TRON Signed Message:\n32\n" || Keccak256(message))
    ///
    /// Returns hex-encoded 65-byte signature: r(32) || s(32) || v(1), v = 27 + recovery_id.
    pub fn sign_message(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        message: &[u8],
    ) -> Result<String, Box<dyn Error>> {
        let (signing_key, _) = Self::derive_keypair(mnemonic, passphrase, secondary_passphrase)?;
        Self::sign_message_with_key(&signing_key, message)
    }

    /// Sign arbitrary message bytes with an existing signing key (Tron personal-sign).
    pub fn sign_message_with_key(
        signing_key: &SigningKey,
        message: &[u8],
    ) -> Result<String, Box<dyn Error>> {
        let hash = Self::tron_message_hash(message);
        let (sig_bytes, v) = Self::sign_prehash(signing_key, &hash)?;
        Ok(format!("{}{:02x}", hex::encode(sig_bytes), v))
    }

    /// Sign a pre-computed 32-byte message hash (already hashed by caller).
    ///
    /// Returns hex-encoded 65-byte signature: r(32) || s(32) || v(1), v = 27 + recovery_id.
    pub fn sign_message_hash(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        hash_hex: &str,
    ) -> Result<String, Box<dyn Error>> {
        let hash_bytes = hex::decode(hash_hex).map_err(|_| "invalid hex for message hash")?;
        if hash_bytes.len() != 32 {
            return Err("message hash must be 32 bytes".into());
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);

        let (signing_key, _) = Self::derive_keypair(mnemonic, passphrase, secondary_passphrase)?;
        Self::sign_message_hash_with_key(&signing_key, &hash)
    }

    pub fn sign_message_hash_with_key(
        signing_key: &SigningKey,
        hash: &[u8; 32],
    ) -> Result<String, Box<dyn Error>> {
        let (sig_bytes, v) = Self::sign_prehash(signing_key, hash)?;
        Ok(format!("{}{:02x}", hex::encode(sig_bytes), v))
    }

    // ==============================
    // Transaction Signing
    // ==============================

    /// Sign a Tron transaction by its txID (the 32-byte SHA256 transaction hash).
    ///
    /// Tron transaction signing is simply recoverable ECDSA over the raw txID.
    /// v = recovery_id (0 or 1), NOT offset by 27 (differs from message signing).
    ///
    /// `tx_id_hex`: 64 hex characters (32 bytes).
    /// Returns hex-encoded 65-byte signature: r(32) || s(32) || v(1).
    pub fn sign_transaction(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        tx_id_hex: &str,
    ) -> Result<String, Box<dyn Error>> {
        let (signing_key, _) = Self::derive_keypair(mnemonic, passphrase, secondary_passphrase)?;
        Self::sign_transaction_with_key(&signing_key, tx_id_hex)
    }

    /// Sign Tron txID (32-byte hex) — `v` is recovery id only (no +27), unlike personal-sign.
    pub fn sign_transaction_with_key(
        signing_key: &SigningKey,
        tx_id_hex: &str,
    ) -> Result<String, Box<dyn Error>> {
        let tx_id_bytes = hex::decode(tx_id_hex).map_err(|_| "invalid hex for txID")?;
        if tx_id_bytes.len() != 32 {
            return Err("txID must be 32 bytes".into());
        }
        let mut tx_id = [0u8; 32];
        tx_id.copy_from_slice(&tx_id_bytes);

        let (sig, recovery_id) = signing_key
            .sign_prehash_recoverable(&tx_id)
            .map_err(|e| format!("Sign failed: {:?}", e))?;
        let sig_bytes = sig.to_bytes();
        let v = recovery_id.to_byte();

        Ok(format!("{}{:02x}", hex::encode(sig_bytes), v))
    }

    /// Sign a raw Tron transaction body (bytes), computing txID = SHA256(raw_tx) internally.
    ///
    /// Returns hex-encoded 65-byte signature: r(32) || s(32) || v(1).
    pub fn sign_raw_transaction(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        raw_tx_hex: &str,
    ) -> Result<String, Box<dyn Error>> {
        let (signing_key, _) = Self::derive_keypair(mnemonic, passphrase, secondary_passphrase)?;
        Self::sign_raw_transaction_with_key(&signing_key, raw_tx_hex)
    }

    pub fn sign_raw_transaction_with_key(
        signing_key: &SigningKey,
        raw_tx_hex: &str,
    ) -> Result<String, Box<dyn Error>> {
        let raw_tx = hex::decode(raw_tx_hex).map_err(|_| "invalid hex for raw transaction")?;

        let tx_id: [u8; 32] = Sha256::digest(&raw_tx).into();
        Self::sign_transaction_with_key(signing_key, &hex::encode(tx_id))
    }

    // ==============================
    // TRC-20 ABI Encoding Helpers
    // ==============================

    /// Encode a TRC-20 transfer call data.
    ///
    /// selector: keccak256("transfer(address,uint256)")[..4] = 0xa9059cbb
    /// to_address: Tron address hex (without 0x41 prefix, 20 bytes)
    /// amount: token amount (raw, no decimals adjustment)
    ///
    /// Returns hex-encoded ABI-encoded call data (68 bytes).
    pub fn encode_trc20_transfer(
        to_address_hex: &str,
        amount: u128,
    ) -> Result<String, Box<dyn Error>> {
        let to_bytes = hex::decode(to_address_hex).map_err(|_| "invalid hex for to_address")?;
        if to_bytes.len() != 20 {
            return Err("to_address must be 20 bytes (hex without 0x41 prefix)".into());
        }

        let mut data = Vec::with_capacity(68);
        // transfer(address,uint256) selector
        data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        // address padded to 32 bytes
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&to_bytes);
        // amount padded to 32 bytes (big-endian)
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&amount.to_be_bytes());

        Ok(hex::encode(data))
    }

    // ==============================
    // Internal Helpers
    // ==============================

    /// Compute Tron personal-sign message hash.
    ///
    /// hash = Keccak256("\x19TRON Signed Message:\n32\n" || Keccak256(message))
    fn tron_message_hash(message: &[u8]) -> [u8; 32] {
        let inner_hash = Keccak256::digest(message);
        let prefix = b"\x19TRON Signed Message:\n32\n";
        let mut hasher = Keccak256::new();
        hasher.update(prefix);
        hasher.update(&inner_hash);
        hasher.finalize().into()
    }

    /// Sign a 32-byte prehash, returning (r||s bytes, v) where v = 27 + recovery_id.
    fn sign_prehash(
        signing_key: &SigningKey,
        hash: &[u8; 32],
    ) -> Result<([u8; 64], u8), Box<dyn Error>> {
        let (sig, recovery_id) = signing_key
            .sign_prehash_recoverable(hash)
            .map_err(|e| format!("Sign failed: {:?}", e))?;
        let sig_bytes: [u8; 64] = sig.to_bytes().into();
        let v = 27u8 + recovery_id.to_byte();
        Ok((sig_bytes, v))
    }

    /// Convert a Tron Base58Check address to its 20-byte hex form (without 0x41 prefix).
    ///
    /// Returns lowercase hex string (40 chars).
    pub fn address_to_hex(tron_address: &str) -> Result<String, Box<dyn Error>> {
        let payload = bs58::decode(tron_address)
            .into_vec()
            .map_err(|e| format!("Base58 decode failed: {:?}", e))?;
        if payload.len() != 25 {
            return Err("invalid Tron address length".into());
        }
        // Verify checksum
        let raw = &payload[..21];
        let checksum = &payload[21..];
        let first = Sha256::digest(raw);
        let second = Sha256::digest(&first);
        if &second[..4] != checksum {
            return Err("invalid Tron address checksum".into());
        }
        if raw[0] != 0x41 {
            return Err("not a Tron mainnet address (expected 0x41 prefix)".into());
        }
        Ok(hex::encode(&raw[1..]))
    }

    /// Convert a 20-byte hex address (without 0x41 prefix) to Tron Base58Check format.
    pub fn hex_to_address(hex_addr: &str) -> Result<String, Box<dyn Error>> {
        let addr20 = hex::decode(hex_addr).map_err(|_| "invalid hex address")?;
        if addr20.len() != 20 {
            return Err("address must be 20 bytes".into());
        }
        let mut raw = [0u8; 21];
        raw[0] = 0x41;
        raw[1..].copy_from_slice(&addr20);

        let first = Sha256::digest(&raw);
        let second = Sha256::digest(&first);

        let mut payload = [0u8; 25];
        payload[..21].copy_from_slice(&raw);
        payload[21..].copy_from_slice(&second[..4]);

        Ok(bs58::encode(&payload).into_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acegf_core::ACEGFCore;

    fn test_mnemonic() -> String {
        let entity = ACEGFCore::generate_ace_internal("testpass", None).unwrap();
        entity.mnemonic.as_str().to_string()
    }

    #[test]
    fn test_tron_address_format() {
        let mnemonic = test_mnemonic();
        let result = TronSigner::get_address(&mnemonic, "testpass", None);
        assert!(
            result.is_ok(),
            "address derivation failed: {:?}",
            result.err()
        );
        let addr = result.unwrap();
        assert!(
            addr.starts_with('T'),
            "Tron address should start with T, got: {}",
            addr
        );
        assert_eq!(
            addr.len(),
            34,
            "Tron address should be 34 chars, got: {}",
            addr.len()
        );
    }

    #[test]
    fn test_tron_address_is_deterministic() {
        let mnemonic = test_mnemonic();
        let a1 = TronSigner::get_address(&mnemonic, "testpass", None).unwrap();
        let a2 = TronSigner::get_address(&mnemonic, "testpass", None).unwrap();
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_tron_address_differs_from_evm() {
        // Tron and EVM use different HKDF labels → different seeds → different addresses
        let mnemonic = test_mnemonic();
        let tron_addr = TronSigner::get_address(&mnemonic, "testpass", None).unwrap();
        let tron_hex = TronSigner::address_to_hex(&tron_addr).unwrap();

        let mut seeds = ACEGFCore::unseal_to_seeds(&mnemonic, "testpass", None).unwrap();
        let evm_address = ACEGFCore::derive_evm_address(&seeds.secp256k1_evm).unwrap();
        ACEGFCore::clear_scheme_seeds(&mut seeds);

        let evm_hex = evm_address.trim_start_matches("0x").to_lowercase();
        assert_ne!(
            tron_hex, evm_hex,
            "Tron and EVM addresses must not share the same key"
        );
    }

    #[test]
    fn test_address_roundtrip() {
        let mnemonic = test_mnemonic();
        let tron_addr = TronSigner::get_address(&mnemonic, "testpass", None).unwrap();
        let hex = TronSigner::address_to_hex(&tron_addr).unwrap();
        let back = TronSigner::hex_to_address(&hex).unwrap();
        assert_eq!(tron_addr, back);
    }

    #[test]
    fn test_sign_transaction_length() {
        let mnemonic = test_mnemonic();
        let tx_id = format!("{:0>64}", "1"); // 000...001
        let result = TronSigner::sign_transaction(&mnemonic, "testpass", None, &tx_id);
        assert!(result.is_ok(), "{:?}", result.err());
        let sig = result.unwrap();
        assert_eq!(
            sig.len(),
            130,
            "signature should be 65 bytes = 130 hex chars"
        );
    }

    #[test]
    fn test_sign_message_length() {
        let mnemonic = test_mnemonic();
        let result = TronSigner::sign_message(&mnemonic, "testpass", None, b"hello tron");
        assert!(result.is_ok(), "{:?}", result.err());
        let sig = result.unwrap();
        assert_eq!(
            sig.len(),
            130,
            "signature should be 65 bytes = 130 hex chars"
        );
    }

    #[test]
    fn test_trc20_transfer_encoding() {
        let to = "a614f803b6fd780986a42c78ec9c7f77e6ded13c"; // 20 bytes hex
        let result = TronSigner::encode_trc20_transfer(to, 1_000_000);
        assert!(result.is_ok(), "{:?}", result.err());
        let data = result.unwrap();
        assert_eq!(data.len(), 136, "68 bytes = 136 hex chars");
        assert!(
            data.starts_with("a9059cbb"),
            "must start with transfer() selector"
        );
    }
}
