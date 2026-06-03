// src/signer/evm_signer.rs
//
// EvmSigner: EVM transaction signing helper built on top of ACE-GF.
//
// Supports:
// - Legacy Transaction (Type 0) signing
// - EIP-1559 Transaction (Type 2) signing
// - EIP-191 Personal Message signing
// - EIP-712 Typed Data signing (for permit/approve)
// - Multi-chain support via chainId parameter
//
// Compatible with: Ethereum, BSC, Polygon, Arbitrum, Optimism, Base, Avalanche, etc.

use crate::acegf_core::ACEGFCore;
use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use std::error::Error;

/// EVM Signer for all EVM-compatible chains
pub struct EvmSigner;

impl EvmSigner {
    // ==============================
    // Key Derivation
    // ==============================

    /// Derive SECP256K1 keypair from mnemonic + passphrase using ACE-GF
    ///
    /// Returns (signing_key, ethereum_address)
    /// The same keypair works for all EVM chains (ETH, BSC, Polygon, etc.)
    ///
    pub fn derive_keypair(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<(SigningKey, [u8; 20]), Box<dyn Error>> {
        let mut seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, secondary_passphrase)
            .map_err(|e| format!("Unseal failed: {:?}", e))?;

        // Use SECP256K1 seed for EVM
        let signing_key = SigningKey::from_bytes((&*seeds.secp256k1_evm).into())
            .map_err(|e| format!("Invalid SECP256K1 key: {:?}", e))?;

        // Derive Ethereum address from public key
        let address = Self::pubkey_to_address(&signing_key)?;

        ACEGFCore::clear_scheme_seeds(&mut seeds);

        Ok((signing_key, address))
    }

    /// Derive SECP256K1 keypair using a pre-derived base_key (PRF path, skips Argon2)
    pub fn derive_keypair_with_base_key(
        mnemonic: &str,
        base_key: &[u8; 32],
    ) -> Result<(SigningKey, [u8; 20]), Box<dyn Error>> {
        let mut seeds = ACEGFCore::unseal_to_seeds_with_base_key(mnemonic, base_key)?;

        let signing_key = SigningKey::from_bytes((&*seeds.secp256k1_evm).into())
            .map_err(|e| format!("Invalid SECP256K1 key: {:?}", e))?;

        let address = Self::pubkey_to_address(&signing_key)?;

        ACEGFCore::clear_scheme_seeds(&mut seeds);

        Ok((signing_key, address))
    }

    // ==============================
    // Context-Aware Key Derivation (REV32 only)
    // ==============================

    /// Derive SECP256K1 keypair with vault context isolation.
    ///
    /// Uses the REV32 derivation path with HKDF context extension.
    /// Empty context produces the same keys as `derive_keypair()` for REV32 wallets.
    /// Returns error for non-REV32 mnemonic formats.
    pub fn derive_keypair_with_context(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        context_info: &str,
    ) -> Result<(SigningKey, [u8; 20]), Box<dyn Error>> {
        let sealed_bytes = ACEGFCore::decode_mnemonic_to_sealed(mnemonic)
            .map_err(|e| format!("Decode mnemonic failed: {:?}", e))?;

        // If context is empty, delegate to the standard path.
        if context_info.is_empty() {
            return Self::derive_keypair(mnemonic, passphrase, secondary_passphrase);
        }

        let full_passphrase =
            PassphraseSealingUtil::combine_passphrase(passphrase, secondary_passphrase);
        let kmaster = PassphraseSealingUtil::derive_kmaster_from_rev32(
            full_passphrase.as_bytes(),
            &sealed_bytes,
        )
        .map_err(|e| format!("Derive Kmaster failed: {:?}", e))?;

        let identity_root = PassphraseSealingUtil::derive_identity_root(&kmaster)
            .map_err(|e| format!("Derive identity root failed: {:?}", e))?;

        let mut seeds =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, context_info.as_bytes())
                .map_err(|e| format!("Derive seeds with context failed: {:?}", e))?;

        let signing_key = SigningKey::from_bytes((&*seeds.secp256k1_evm).into())
            .map_err(|e| format!("Invalid SECP256K1 key: {:?}", e))?;
        let address = Self::pubkey_to_address(&signing_key)?;
        ACEGFCore::clear_scheme_seeds(&mut seeds);

        Ok((signing_key, address))
    }

    /// Derive SECP256K1 keypair with context using PRF base_key (skips Argon2).
    ///
    /// In the PRF path, `base_key` replaces the Argon2-derived Kmaster.
    /// For REV32 context mode: derive identity_root from base_key, then apply context.
    pub fn derive_keypair_with_context_base_key(
        mnemonic: &str,
        base_key: &[u8; 32],
        context_info: &str,
    ) -> Result<(SigningKey, [u8; 20]), Box<dyn Error>> {
        // If context is empty, use the standard PRF path
        if context_info.is_empty() {
            return Self::derive_keypair_with_base_key(mnemonic, base_key);
        }

        // Context + PRF: base_key acts as Kmaster equivalent.
        // Derive identity_root from it, then apply context to get chain seeds.
        let identity_root = PassphraseSealingUtil::derive_identity_root(base_key)
            .map_err(|e| format!("Derive identity root failed: {:?}", e))?;

        let mut seeds =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, context_info.as_bytes())
                .map_err(|e| format!("Derive seeds with context failed: {:?}", e))?;

        let signing_key = SigningKey::from_bytes((&*seeds.secp256k1_evm).into())
            .map_err(|e| format!("Invalid SECP256K1 key: {:?}", e))?;
        let address = Self::pubkey_to_address(&signing_key)?;
        ACEGFCore::clear_scheme_seeds(&mut seeds);

        Ok((signing_key, address))
    }

    // ==============================
    // Context-Aware Transaction Signing
    // ==============================

    /// Sign EIP-1559 transaction with vault context.
    pub fn sign_eip1559_transaction_with_context(
        mnemonic: &str,
        passphrase: &str,
        context_info: &str,
        chain_id: u64,
        nonce: &str,
        max_priority_fee_per_gas: &str,
        max_fee_per_gas: &str,
        gas_limit: &str,
        to: &str,
        value: &str,
        data: &str,
    ) -> Result<String, Box<dyn Error>> {
        let (signing_key, _address) =
            Self::derive_keypair_with_context(mnemonic, passphrase, None, context_info)?;
        Self::sign_eip1559_transaction_with_key(
            &signing_key,
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
        )
    }

    /// Sign personal message with vault context.
    pub fn sign_personal_message_with_context(
        mnemonic: &str,
        passphrase: &str,
        context_info: &str,
        message: &[u8],
    ) -> Result<String, Box<dyn Error>> {
        let (signing_key, _address) =
            Self::derive_keypair_with_context(mnemonic, passphrase, None, context_info)?;
        Self::sign_personal_message_with_key(&signing_key, message)
    }

    /// Get EVM address for a vault context.
    pub fn get_address_with_context(
        mnemonic: &str,
        passphrase: &str,
        context_info: &str,
    ) -> Result<String, Box<dyn Error>> {
        let (_signing_key, address) =
            Self::derive_keypair_with_context(mnemonic, passphrase, None, context_info)?;
        Ok(format!("0x{}", hex::encode(address)))
    }

    /// Convert SECP256K1 public key to Ethereum address
    ///
    /// Address = Keccak256(uncompressed_pubkey[1..65])[12..32]
    fn pubkey_to_address(signing_key: &SigningKey) -> Result<[u8; 20], Box<dyn Error>> {
        let verifying_key = signing_key.verifying_key();
        let pubkey_point = verifying_key.to_encoded_point(false);
        let pubkey_bytes = pubkey_point.as_bytes();

        // Skip the 0x04 prefix, hash the 64-byte uncompressed public key
        if pubkey_bytes.len() != 65 {
            return Err("Invalid public key length".into());
        }

        let mut hasher = Keccak256::new();
        hasher.update(&pubkey_bytes[1..65]);
        let hash = hasher.finalize();

        // Take last 20 bytes as address
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..32]);

        Ok(address)
    }

    // ==============================
    // RLP Encoding Helpers
    // ==============================

    /// Encode a single item using RLP
    ///
    /// RLP encoding rules:
    /// - Single byte [0x00, 0x7f]: as-is
    /// - String 0-55 bytes: 0x80 + len, then data
    /// - String 56+ bytes: 0xb7 + len_of_len, then len (big endian), then data
    fn rlp_encode_item(data: &[u8]) -> Vec<u8> {
        if data.len() == 1 && data[0] < 0x80 {
            // Single byte in range [0x00, 0x7f]
            return data.to_vec();
        }

        if data.is_empty() {
            // Empty string
            return vec![0x80];
        }

        if data.len() <= 55 {
            // Short string: 0x80 + len prefix
            let mut result = vec![0x80 + data.len() as u8];
            result.extend_from_slice(data);
            result
        } else {
            // Long string: 0xb7 + len_of_len prefix
            let len_bytes = Self::encode_length(data.len());
            let mut result = vec![0xb7 + len_bytes.len() as u8];
            result.extend_from_slice(&len_bytes);
            result.extend_from_slice(data);
            result
        }
    }

    /// Encode a list using RLP
    ///
    /// List encoding rules:
    /// - List 0-55 bytes total: 0xc0 + total_len, then concatenated items
    /// - List 56+ bytes: 0xf7 + len_of_len, then len (big endian), then items
    fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = Vec::new();
        for item in items {
            payload.extend_from_slice(item);
        }

        if payload.len() <= 55 {
            let mut result = vec![0xc0 + payload.len() as u8];
            result.extend_from_slice(&payload);
            result
        } else {
            let len_bytes = Self::encode_length(payload.len());
            let mut result = vec![0xf7 + len_bytes.len() as u8];
            result.extend_from_slice(&len_bytes);
            result.extend_from_slice(&payload);
            result
        }
    }

    /// Encode length as big-endian bytes (without leading zeros)
    fn encode_length(len: usize) -> Vec<u8> {
        if len == 0 {
            return vec![];
        }
        let bytes = (len as u64).to_be_bytes();
        let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        bytes[first_nonzero..].to_vec()
    }

    /// Encode u64 value as RLP (big-endian, no leading zeros)
    fn rlp_encode_u64(value: u64) -> Vec<u8> {
        if value == 0 {
            return Self::rlp_encode_item(&[]);
        }
        let bytes = value.to_be_bytes();
        let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        Self::rlp_encode_item(&bytes[first_nonzero..])
    }

    /// Encode U256 value (32 bytes) as RLP (big-endian, no leading zeros)
    fn rlp_encode_u256(value: &[u8; 32]) -> Vec<u8> {
        let first_nonzero = value.iter().position(|&b| b != 0);
        match first_nonzero {
            Some(idx) => Self::rlp_encode_item(&value[idx..]),
            None => Self::rlp_encode_item(&[]), // All zeros = empty
        }
    }

    /// Parse hex string to bytes (with or without 0x prefix).
    /// Pads odd-length hex with a leading zero so "0x0" and "0x1" decode correctly (EVM hex must be even length).
    fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex).trim();
        if hex.is_empty() {
            return Ok(vec![]);
        }
        let hex = if hex.len() % 2 != 0 {
            format!("0{}", hex)
        } else {
            hex.to_string()
        };
        hex::decode(hex.as_str()).map_err(|e| format!("Invalid hex: {}", e).into())
    }

    /// Parse hex string to U256 (32 bytes, big-endian)
    fn hex_to_u256(hex: &str) -> Result<[u8; 32], Box<dyn Error>> {
        let bytes = Self::hex_to_bytes(hex)?;
        let mut result = [0u8; 32];
        if bytes.len() > 32 {
            return Err("Value too large for U256".into());
        }
        result[32 - bytes.len()..].copy_from_slice(&bytes);
        Ok(result)
    }

    /// Parse hex string to u64
    fn hex_to_u64(hex: &str) -> Result<u64, Box<dyn Error>> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        if hex.is_empty() {
            return Ok(0);
        }
        u64::from_str_radix(hex, 16).map_err(|e| format!("Invalid hex number: {}", e).into())
    }

    /// Convert address hex to bytes
    fn address_to_bytes(address: &str) -> Result<[u8; 20], Box<dyn Error>> {
        let bytes = Self::hex_to_bytes(address)?;
        if bytes.len() != 20 {
            return Err(format!("Invalid address length: expected 20, got {}", bytes.len()).into());
        }
        let mut result = [0u8; 20];
        result.copy_from_slice(&bytes);
        Ok(result)
    }

    // ==============================
    // Type-0 Transaction
    // ==============================

    /// Sign a Type-0 Transaction
    ///
    /// This is the original Ethereum transaction format, still widely supported.
    /// Uses EIP-155 replay protection with chainId.
    ///
    /// Parameters:
    /// - mnemonic: ACE-GF mnemonic
    /// - passphrase: wallet passphrase
    /// - chain_id: EVM chain ID (1=Ethereum, 56=BSC, 137=Polygon, etc.)
    /// - nonce: transaction nonce (hex string)
    /// - gas_price: gas price in wei (hex string)
    /// - gas_limit: gas limit (hex string)
    /// - to: recipient address (hex string with 0x prefix)
    /// - value: amount in wei (hex string)
    /// - data: transaction data (hex string, can be empty)
    ///
    /// Returns: signed transaction as hex string (ready for eth_sendRawTransaction)
    pub fn sign_type0_transaction(
        mnemonic: &str,
        passphrase: &str,
        chain_id: u64,
        nonce: &str,
        gas_price: &str,
        gas_limit: &str,
        to: &str,
        value: &str,
        data: &str,
    ) -> Result<String, Box<dyn Error>> {
        let (signing_key, _address) = Self::derive_keypair(mnemonic, passphrase, None)?;
        Self::sign_type0_transaction_with_key(
            &signing_key,
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
        )
    }

    /// Sign a Type-0 Transaction with a pre-derived signing key
    pub fn sign_type0_transaction_with_key(
        signing_key: &SigningKey,
        chain_id: u64,
        nonce: &str,
        gas_price: &str,
        gas_limit: &str,
        to: &str,
        value: &str,
        data: &str,
    ) -> Result<String, Box<dyn Error>> {
        // 2. Parse parameters
        let nonce_val = Self::hex_to_u64(nonce)?;
        let gas_price_bytes = Self::hex_to_u256(gas_price)?;
        let gas_limit_val = Self::hex_to_u64(gas_limit)?;
        let to_bytes = Self::address_to_bytes(to)?;
        let value_bytes = Self::hex_to_u256(value)?;
        let data_bytes = Self::hex_to_bytes(data)?;

        // 3. Build unsigned transaction for signing (EIP-155)
        // [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
        let unsigned_items = vec![
            Self::rlp_encode_u64(nonce_val),
            Self::rlp_encode_u256(&gas_price_bytes),
            Self::rlp_encode_u64(gas_limit_val),
            Self::rlp_encode_item(&to_bytes),
            Self::rlp_encode_u256(&value_bytes),
            Self::rlp_encode_item(&data_bytes),
            Self::rlp_encode_u64(chain_id),
            Self::rlp_encode_item(&[]), // empty for EIP-155
            Self::rlp_encode_item(&[]), // empty for EIP-155
        ];
        let unsigned_rlp = Self::rlp_encode_list(&unsigned_items);

        // 4. Hash and sign
        let mut hasher = Keccak256::new();
        hasher.update(&unsigned_rlp);
        let hash = hasher.finalize();

        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&hash)
            .map_err(|e| format!("Signing failed: {:?}", e))?;

        let sig_bytes = signature.to_bytes();
        let r = &sig_bytes[0..32];
        let s = &sig_bytes[32..64];

        // 5. Calculate v value (EIP-155: v = chainId * 2 + 35 + recoveryId)
        let v = chain_id * 2 + 35 + recovery_id.to_byte() as u64;

        // 6. Build signed transaction
        // [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
        let mut r_arr = [0u8; 32];
        let mut s_arr = [0u8; 32];
        r_arr.copy_from_slice(r);
        s_arr.copy_from_slice(s);

        let signed_items = vec![
            Self::rlp_encode_u64(nonce_val),
            Self::rlp_encode_u256(&gas_price_bytes),
            Self::rlp_encode_u64(gas_limit_val),
            Self::rlp_encode_item(&to_bytes),
            Self::rlp_encode_u256(&value_bytes),
            Self::rlp_encode_item(&data_bytes),
            Self::rlp_encode_u64(v),
            Self::rlp_encode_u256(&r_arr),
            Self::rlp_encode_u256(&s_arr),
        ];
        let signed_rlp = Self::rlp_encode_list(&signed_items);

        Ok(format!("0x{}", hex::encode(signed_rlp)))
    }

    /// Backward-compatible alias for Type-0 transaction signing.
    pub fn sign_legacy_transaction(
        mnemonic: &str,
        passphrase: &str,
        chain_id: u64,
        nonce: &str,
        gas_price: &str,
        gas_limit: &str,
        to: &str,
        value: &str,
        data: &str,
    ) -> Result<String, Box<dyn Error>> {
        Self::sign_type0_transaction(
            mnemonic, passphrase, chain_id, nonce, gas_price, gas_limit, to, value, data,
        )
    }

    /// Backward-compatible alias for Type-0 transaction signing with key.
    pub fn sign_legacy_transaction_with_key(
        signing_key: &SigningKey,
        chain_id: u64,
        nonce: &str,
        gas_price: &str,
        gas_limit: &str,
        to: &str,
        value: &str,
        data: &str,
    ) -> Result<String, Box<dyn Error>> {
        Self::sign_type0_transaction_with_key(
            signing_key,
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
        )
    }

    // ==============================
    // EIP-1559 Transaction (Type 2)
    // ==============================

    /// Sign an EIP-1559 Transaction (Type 2)
    ///
    /// This is the modern transaction format with dynamic fee market.
    /// Preferred for Ethereum mainnet and most L2s.
    ///
    /// Parameters:
    /// - mnemonic: ACE-GF mnemonic
    /// - passphrase: wallet passphrase
    /// - chain_id: EVM chain ID
    /// - nonce: transaction nonce (hex string)
    /// - max_priority_fee_per_gas: tip to miner in wei (hex string)
    /// - max_fee_per_gas: maximum total fee in wei (hex string)
    /// - gas_limit: gas limit (hex string)
    /// - to: recipient address (hex string with 0x prefix)
    /// - value: amount in wei (hex string)
    /// - data: transaction data (hex string)
    /// - access_list: EIP-2930 access list (empty for most cases)
    ///
    /// Returns: signed transaction as hex string (with 0x02 prefix)
    pub fn sign_eip1559_transaction(
        mnemonic: &str,
        passphrase: &str,
        chain_id: u64,
        nonce: &str,
        max_priority_fee_per_gas: &str,
        max_fee_per_gas: &str,
        gas_limit: &str,
        to: &str,
        value: &str,
        data: &str,
    ) -> Result<String, Box<dyn Error>> {
        let (signing_key, _address) = Self::derive_keypair(mnemonic, passphrase, None)?;
        Self::sign_eip1559_transaction_with_key(
            &signing_key,
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
        )
    }

    /// Sign an EIP-1559 Transaction with secondary passphrase (e.g. admin factor).
    /// The secondary passphrase is combined with the primary passphrase to derive the signing key.
    pub fn sign_eip1559_transaction_with_secondary(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        chain_id: u64,
        nonce: &str,
        max_priority_fee_per_gas: &str,
        max_fee_per_gas: &str,
        gas_limit: &str,
        to: &str,
        value: &str,
        data: &str,
    ) -> Result<String, Box<dyn Error>> {
        let (signing_key, _address) =
            Self::derive_keypair(mnemonic, passphrase, secondary_passphrase)?;
        Self::sign_eip1559_transaction_with_key(
            &signing_key,
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
        )
    }

    /// Sign an EIP-1559 Transaction with a pre-derived signing key
    pub fn sign_eip1559_transaction_with_key(
        signing_key: &SigningKey,
        chain_id: u64,
        nonce: &str,
        max_priority_fee_per_gas: &str,
        max_fee_per_gas: &str,
        gas_limit: &str,
        to: &str,
        value: &str,
        data: &str,
    ) -> Result<String, Box<dyn Error>> {
        // 2. Parse parameters
        let nonce_val = Self::hex_to_u64(nonce)?;
        let max_priority_fee = Self::hex_to_u256(max_priority_fee_per_gas)?;
        let max_fee = Self::hex_to_u256(max_fee_per_gas)?;
        let gas_limit_val = Self::hex_to_u64(gas_limit)?;
        let to_bytes = Self::address_to_bytes(to)?;
        let value_bytes = Self::hex_to_u256(value)?;
        let data_bytes = Self::hex_to_bytes(data)?;

        // 3. Build unsigned transaction payload
        // [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList]
        let unsigned_items = vec![
            Self::rlp_encode_u64(chain_id),
            Self::rlp_encode_u64(nonce_val),
            Self::rlp_encode_u256(&max_priority_fee),
            Self::rlp_encode_u256(&max_fee),
            Self::rlp_encode_u64(gas_limit_val),
            Self::rlp_encode_item(&to_bytes),
            Self::rlp_encode_u256(&value_bytes),
            Self::rlp_encode_item(&data_bytes),
            Self::rlp_encode_list(&[]), // Empty access list
        ];
        let unsigned_payload = Self::rlp_encode_list(&unsigned_items);

        // 4. Hash: keccak256(0x02 || rlp([...]))
        let mut to_hash = vec![0x02u8];
        to_hash.extend_from_slice(&unsigned_payload);

        let mut hasher = Keccak256::new();
        hasher.update(&to_hash);
        let hash = hasher.finalize();

        // 5. Sign
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&hash)
            .map_err(|e| format!("Signing failed: {:?}", e))?;

        let sig_bytes = signature.to_bytes();
        let r = &sig_bytes[0..32];
        let s = &sig_bytes[32..64];

        // 6. Build signed transaction
        // 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, yParity, r, s])
        let mut r_arr = [0u8; 32];
        let mut s_arr = [0u8; 32];
        r_arr.copy_from_slice(r);
        s_arr.copy_from_slice(s);

        let signed_items = vec![
            Self::rlp_encode_u64(chain_id),
            Self::rlp_encode_u64(nonce_val),
            Self::rlp_encode_u256(&max_priority_fee),
            Self::rlp_encode_u256(&max_fee),
            Self::rlp_encode_u64(gas_limit_val),
            Self::rlp_encode_item(&to_bytes),
            Self::rlp_encode_u256(&value_bytes),
            Self::rlp_encode_item(&data_bytes),
            Self::rlp_encode_list(&[]), // Empty access list
            Self::rlp_encode_u64(recovery_id.to_byte() as u64), // yParity (0 or 1)
            Self::rlp_encode_u256(&r_arr),
            Self::rlp_encode_u256(&s_arr),
        ];
        let signed_payload = Self::rlp_encode_list(&signed_items);

        // Prepend type byte
        let mut signed_tx = vec![0x02u8];
        signed_tx.extend_from_slice(&signed_payload);

        Ok(format!("0x{}", hex::encode(signed_tx)))
    }

    // ==============================
    // Message Signing (EIP-191)
    // ==============================

    /// Sign a personal message (EIP-191)
    ///
    /// This is used for "Sign Message" functionality in wallets.
    /// The message is prefixed with "\x19Ethereum Signed Message:\n{length}"
    ///
    /// Parameters:
    /// - mnemonic: ACE-GF mnemonic
    /// - passphrase: wallet passphrase
    /// - message: raw message bytes
    ///
    /// Returns: signature as hex string (65 bytes: r[32] + s[32] + v[1])
    pub fn sign_personal_message(
        mnemonic: &str,
        passphrase: &str,
        message: &[u8],
    ) -> Result<String, Box<dyn Error>> {
        let (signing_key, _address) = Self::derive_keypair(mnemonic, passphrase, None)?;
        Self::sign_personal_message_with_key(&signing_key, message)
    }

    /// Sign a personal message with a pre-derived signing key
    pub fn sign_personal_message_with_key(
        signing_key: &SigningKey,
        message: &[u8],
    ) -> Result<String, Box<dyn Error>> {
        // Build EIP-191 prefixed message
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut prefixed = prefix.into_bytes();
        prefixed.extend_from_slice(message);

        // Hash
        let mut hasher = Keccak256::new();
        hasher.update(&prefixed);
        let hash = hasher.finalize();

        // Sign
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&hash)
            .map_err(|e| format!("Signing failed: {:?}", e))?;

        let sig_bytes = signature.to_bytes();

        // Return r + s + v (v = 27 + recoveryId for personal_sign)
        let v = 27 + recovery_id.to_byte();
        let mut result = sig_bytes.to_vec();
        result.push(v);

        Ok(format!("0x{}", hex::encode(result)))
    }

    // ==============================
    // Typed Data Signing (EIP-712)
    // ==============================

    /// Sign typed structured data (EIP-712)
    ///
    /// Used for permit signatures, NFT marketplace approvals, etc.
    /// The hash is provided pre-computed (domainSeparator + structHash)
    ///
    /// Parameters:
    /// - mnemonic: ACE-GF mnemonic
    /// - passphrase: wallet passphrase
    /// - typed_data_hash: pre-computed EIP-712 hash (32 bytes hex)
    ///
    /// Returns: signature as hex string (65 bytes: r[32] + s[32] + v[1])
    pub fn sign_typed_data(
        mnemonic: &str,
        passphrase: &str,
        typed_data_hash: &str,
    ) -> Result<String, Box<dyn Error>> {
        let (signing_key, _address) = Self::derive_keypair(mnemonic, passphrase, None)?;
        Self::sign_typed_data_with_key(&signing_key, typed_data_hash)
    }

    /// Sign typed data with a pre-derived signing key
    pub fn sign_typed_data_with_key(
        signing_key: &SigningKey,
        typed_data_hash: &str,
    ) -> Result<String, Box<dyn Error>> {
        let hash_bytes = Self::hex_to_bytes(typed_data_hash)?;
        if hash_bytes.len() != 32 {
            return Err("Invalid typed data hash length".into());
        }

        // Sign the hash directly
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&hash_bytes)
            .map_err(|e| format!("Signing failed: {:?}", e))?;

        let sig_bytes = signature.to_bytes();

        // Return r + s + v (v = 27 + recoveryId)
        let v = 27 + recovery_id.to_byte();
        let mut result = sig_bytes.to_vec();
        result.push(v);

        Ok(format!("0x{}", hex::encode(result)))
    }

    // ==============================
    // Utility Functions
    // ==============================

    /// Get Ethereum address from mnemonic
    ///
    /// Returns: address as checksummed hex string (EIP-55)
    pub fn get_address(mnemonic: &str, passphrase: &str) -> Result<String, Box<dyn Error>> {
        let (_signing_key, address) = Self::derive_keypair(mnemonic, passphrase, None)?;
        Ok(Self::to_checksum_address(&address))
    }

    /// Convert raw address bytes to EIP-55 checksummed hex string
    fn to_checksum_address(address: &[u8; 20]) -> String {
        let addr_hex = hex::encode(address);

        // Hash the lowercase address
        let mut hasher = Keccak256::new();
        hasher.update(addr_hex.as_bytes());
        let hash = hasher.finalize();

        // Apply checksum
        let mut result = String::with_capacity(42);
        result.push_str("0x");

        for (i, c) in addr_hex.chars().enumerate() {
            let hash_byte = hash[i / 2];
            let hash_nibble = if i % 2 == 0 {
                hash_byte >> 4
            } else {
                hash_byte & 0x0f
            };

            if c.is_ascii_alphabetic() && hash_nibble >= 8 {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c);
            }
        }

        result
    }

    /// Compute transaction hash from signed transaction
    ///
    /// Parameters:
    /// - signed_tx: signed transaction hex string
    ///
    /// Returns: transaction hash as hex string
    pub fn compute_tx_hash(signed_tx: &str) -> Result<String, Box<dyn Error>> {
        let tx_bytes = Self::hex_to_bytes(signed_tx)?;

        let mut hasher = Keccak256::new();
        hasher.update(&tx_bytes);
        let hash = hasher.finalize();

        Ok(format!("0x{}", hex::encode(hash)))
    }

    /// Encode ERC20 transfer function call
    ///
    /// Parameters:
    /// - to: recipient address
    /// - amount: amount to transfer (hex string, in token decimals)
    ///
    /// Returns: encoded function call data as hex string
    pub fn encode_erc20_transfer(to: &str, amount: &str) -> Result<String, Box<dyn Error>> {
        // Function selector: transfer(address,uint256) = 0xa9059cbb
        let selector = "a9059cbb";

        let to_bytes = Self::address_to_bytes(to)?;
        let amount_bytes = Self::hex_to_u256(amount)?;

        // Encode: selector + to (padded to 32 bytes) + amount (32 bytes)
        let mut data = hex::decode(selector)?;
        data.extend_from_slice(&[0u8; 12]); // Pad address to 32 bytes
        data.extend_from_slice(&to_bytes);
        data.extend_from_slice(&amount_bytes);

        Ok(format!("0x{}", hex::encode(data)))
    }

    /// Encode ERC20 approve function call
    ///
    /// Parameters:
    /// - spender: spender address (DEX router, etc.)
    /// - amount: amount to approve (hex string, use max uint256 for unlimited)
    ///
    /// Returns: encoded function call data as hex string
    pub fn encode_erc20_approve(spender: &str, amount: &str) -> Result<String, Box<dyn Error>> {
        // Function selector: approve(address,uint256) = 0x095ea7b3
        let selector = "095ea7b3";

        let spender_bytes = Self::address_to_bytes(spender)?;
        let amount_bytes = Self::hex_to_u256(amount)?;

        let mut data = hex::decode(selector)?;
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&spender_bytes);
        data.extend_from_slice(&amount_bytes);

        Ok(format!("0x{}", hex::encode(data)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rlp_encode_item() {
        // Empty string
        assert_eq!(EvmSigner::rlp_encode_item(&[]), vec![0x80]);

        // Single byte < 0x80
        assert_eq!(EvmSigner::rlp_encode_item(&[0x00]), vec![0x00]);
        assert_eq!(EvmSigner::rlp_encode_item(&[0x7f]), vec![0x7f]);

        // Single byte >= 0x80
        assert_eq!(EvmSigner::rlp_encode_item(&[0x80]), vec![0x81, 0x80]);

        // Short string
        assert_eq!(
            EvmSigner::rlp_encode_item(b"dog"),
            vec![0x83, b'd', b'o', b'g']
        );
    }

    #[test]
    fn test_rlp_encode_list() {
        // Empty list
        assert_eq!(EvmSigner::rlp_encode_list(&[]), vec![0xc0]);

        // List with items
        let items = vec![
            EvmSigner::rlp_encode_item(b"cat"),
            EvmSigner::rlp_encode_item(b"dog"),
        ];
        let encoded = EvmSigner::rlp_encode_list(&items);
        assert_eq!(
            encoded,
            vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );
    }

    #[test]
    fn test_rlp_encode_u64() {
        assert_eq!(EvmSigner::rlp_encode_u64(0), vec![0x80]);
        assert_eq!(EvmSigner::rlp_encode_u64(1), vec![0x01]);
        assert_eq!(EvmSigner::rlp_encode_u64(127), vec![0x7f]);
        assert_eq!(EvmSigner::rlp_encode_u64(128), vec![0x81, 0x80]);
        assert_eq!(EvmSigner::rlp_encode_u64(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_hex_to_bytes() {
        let empty: Vec<u8> = vec![];
        assert_eq!(EvmSigner::hex_to_bytes("0x").unwrap(), empty);
        assert_eq!(EvmSigner::hex_to_bytes("").unwrap(), empty);
        assert_eq!(
            EvmSigner::hex_to_bytes("0x1234").unwrap(),
            vec![0x12u8, 0x34]
        );
        assert_eq!(EvmSigner::hex_to_bytes("1234").unwrap(), vec![0x12u8, 0x34]);
    }

    #[test]
    fn test_checksum_address() {
        // Known checksummed addresses
        let addr1 = [
            0x5a, 0xAe, 0xb6, 0x05, 0x3F, 0x3E, 0x94, 0xC9, 0xb9, 0xA0, 0x9f, 0x33, 0x66, 0x9a,
            0x0b, 0x65, 0x43, 0x3F, 0x6f, 0x3c,
        ];
        let checksum = EvmSigner::to_checksum_address(&addr1);
        assert!(checksum.starts_with("0x"));
        assert_eq!(checksum.len(), 42);
    }

    #[test]
    fn test_encode_erc20_transfer() {
        let to = "0x1234567890123456789012345678901234567890";
        let amount = "0x0de0b6b3a7640000"; // 1 ETH in wei

        let data = EvmSigner::encode_erc20_transfer(to, amount).unwrap();

        // Should start with transfer selector
        assert!(data.starts_with("0xa9059cbb"));
        // Should be 4 + 32 + 32 = 68 bytes = 136 hex chars + "0x"
        assert_eq!(data.len(), 138);
    }

    #[test]
    fn test_encode_erc20_approve() {
        let spender = "0x1234567890123456789012345678901234567890";
        let amount = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; // max uint256

        let data = EvmSigner::encode_erc20_approve(spender, amount).unwrap();

        // Should start with approve selector
        assert!(data.starts_with("0x095ea7b3"));
        assert_eq!(data.len(), 138);
    }
}
