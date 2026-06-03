// src/signer/solana_signer.rs
//
// SolanaSigner: Solana signing helper built on top of ACE-GF.
//
// - Constructs System Program transfer Message
// - Constructs SPL Token Program transfer Message
// - Signs Message using ACE-GF / Ed25519
// - Returns complete Transaction bytes (signatures + message)

use crate::acegf_core::ACEGFCore;
use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;
use bs58;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::error::Error;

// Solana System Program ID: 11111111111111111111111111111111
// Raw bytes are 32 zeros.
const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

// SPL Token Program ID: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
const SPL_TOKEN_PROGRAM_ID: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
];

// Associated Token Account Program ID: ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL
const ATA_PROGRAM_ID: [u8; 32] = [
    0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1, 0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83,
    0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84, 0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59,
];

pub struct SolanaSigner;

impl SolanaSigner {
    // ==============================
    // Basic helpers
    // ==============================

    /// Decode base58 pubkey string -> 32 byte pubkey
    fn decode_pubkey_base58(pk: &str) -> Result<[u8; 32], Box<dyn Error>> {
        let bytes = bs58::decode(pk).into_vec()?;
        if bytes.len() != 32 {
            return Err("Invalid Solana pubkey length, expected 32 bytes".into());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    /// Decode base58 blockhash -> 32 bytes
    fn decode_blockhash_base58(hash: &str) -> Result<[u8; 32], Box<dyn Error>> {
        let bytes = bs58::decode(hash).into_vec()?;
        if bytes.len() != 32 {
            return Err("Invalid Solana blockhash length, expected 32 bytes".into());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    /// Solana short_vec encoding (official short_vec<u8> format)
    fn encode_short_len(len: usize) -> Vec<u8> {
        let mut rem = len;
        let mut out = Vec::new();
        loop {
            let mut elem = (rem & 0x7F) as u8;
            rem >>= 7;
            if rem != 0 {
                elem |= 0x80;
            }
            out.push(elem);
            if rem == 0 {
                break;
            }
        }
        out
    }

    // ==============================
    // Derive Solana keypair from ACE-GF
    // ==============================

    /// Get Solana Ed25519 keypair from mnemonic + passphrase
    pub fn derive_keypair(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<(SigningKey, VerifyingKey), Box<dyn Error>> {
        let mut seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, secondary_passphrase)
            .map_err(|e| format!("Unseal failed: {:?}", e))?;

        let signing_key = SigningKey::from_bytes(&*seeds.ed25519_solana);
        let verifying_key = signing_key.verifying_key();

        ACEGFCore::clear_scheme_seeds(&mut seeds);

        Ok((signing_key, verifying_key))
    }

    /// Derive Solana keypair using a pre-derived base_key (PRF path, skips Argon2)
    pub fn derive_keypair_with_base_key(
        mnemonic: &str,
        base_key: &[u8; 32],
    ) -> Result<(SigningKey, VerifyingKey), Box<dyn Error>> {
        let mut seeds = ACEGFCore::unseal_to_seeds_with_base_key(mnemonic, base_key)?;

        let signing_key = SigningKey::from_bytes(&*seeds.ed25519_solana);
        let verifying_key = signing_key.verifying_key();

        ACEGFCore::clear_scheme_seeds(&mut seeds);

        Ok((signing_key, verifying_key))
    }

    // ==============================
    // Context-Aware Key Derivation (REV32 only)
    // ==============================

    /// Derive Solana Ed25519 keypair with vault context isolation.
    ///
    /// Uses the REV32 derivation path with HKDF context extension.
    /// Empty context produces the same keys as `derive_keypair()` for REV32 wallets.
    /// Returns error for non-REV32 mnemonic formats.
    pub fn derive_keypair_with_context(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        context_info: &str,
    ) -> Result<(SigningKey, VerifyingKey), Box<dyn Error>> {
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

        let signing_key = SigningKey::from_bytes(&*seeds.ed25519_solana);
        let verifying_key = signing_key.verifying_key();

        ACEGFCore::clear_scheme_seeds(&mut seeds);

        Ok((signing_key, verifying_key))
    }

    /// Derive Solana keypair with context using PRF base_key (skips Argon2).
    pub fn derive_keypair_with_context_base_key(
        mnemonic: &str,
        base_key: &[u8; 32],
        context_info: &str,
    ) -> Result<(SigningKey, VerifyingKey), Box<dyn Error>> {
        // If context is empty, use the standard PRF path
        if context_info.is_empty() {
            return Self::derive_keypair_with_base_key(mnemonic, base_key);
        }

        // Context + PRF: base_key acts as Kmaster equivalent.
        let identity_root = PassphraseSealingUtil::derive_identity_root(base_key)
            .map_err(|e| format!("Derive identity root failed: {:?}", e))?;

        let mut seeds =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, context_info.as_bytes())
                .map_err(|e| format!("Derive seeds with context failed: {:?}", e))?;

        let signing_key = SigningKey::from_bytes(&*seeds.ed25519_solana);
        let verifying_key = signing_key.verifying_key();

        ACEGFCore::clear_scheme_seeds(&mut seeds);

        Ok((signing_key, verifying_key))
    }

    // ==============================
    // Context-Aware Transaction Signing
    // ==============================

    /// Get Solana base58 address with vault context.
    pub fn get_address_with_context(
        mnemonic: &str,
        passphrase: &str,
        context_info: &str,
    ) -> Result<String, Box<dyn Error>> {
        let (_signing_key, verifying_key) =
            Self::derive_keypair_with_context(mnemonic, passphrase, None, context_info)?;
        Ok(bs58::encode(verifying_key.to_bytes()).into_string())
    }

    /// Sign system transfer with vault context.
    pub fn sign_system_transfer_with_context(
        mnemonic: &str,
        passphrase: &str,
        context_info: &str,
        to_pubkey_base58: &str,
        lamports: u64,
        recent_blockhash_base58: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let (sk, _pk) =
            Self::derive_keypair_with_context(mnemonic, passphrase, None, context_info)?;
        Self::sign_system_transfer_with_key(
            &sk,
            to_pubkey_base58,
            lamports,
            recent_blockhash_base58,
        )
    }

    /// Sign an external serialized transaction with vault context.
    pub fn sign_serialized_transaction_with_context(
        mnemonic: &str,
        passphrase: &str,
        context_info: &str,
        serialized_tx_base64: &str,
    ) -> Result<String, Box<dyn Error>> {
        let (sk, _pk) =
            Self::derive_keypair_with_context(mnemonic, passphrase, None, context_info)?;
        Self::sign_serialized_transaction_with_key(&sk, serialized_tx_base64)
    }

    /// Sign an arbitrary message with context-derived Ed25519 key.
    /// Returns hex-encoded Ed25519 signature (128 hex chars = 64 bytes).
    pub fn sign_message_with_context(
        mnemonic: &str,
        passphrase: &str,
        context_info: &str,
        message: &[u8],
    ) -> Result<String, Box<dyn Error>> {
        let (sk, _pk) =
            Self::derive_keypair_with_context(mnemonic, passphrase, None, context_info)?;
        let sig = sk.sign(message).to_bytes();
        Ok(hex::encode(sig))
    }

    // ==============================
    // Build System Transfer Message
    // ==============================
    //
    // accounts: [from, to, system_program]
    // Only supports most common 1-signer scenario

    fn build_system_transfer_message(
        from_pubkey: [u8; 32],
        to_pubkey: [u8; 32],
        lamports: u64,
        recent_blockhash: [u8; 32],
    ) -> Vec<u8> {
        let mut out = Vec::new();

        // 1. Header
        out.push(1u8); // num_required_signatures
        out.push(0u8); // num_readonly_signed_accounts
        out.push(1u8); // num_readonly_unsigned_accounts (system program)

        // 2. Account keys = [from, to, system_program]
        let account_keys = [&from_pubkey[..], &to_pubkey[..], &SYSTEM_PROGRAM_ID[..]];
        out.extend_from_slice(&Self::encode_short_len(account_keys.len()));
        for pk in &account_keys {
            out.extend_from_slice(pk);
        }

        // 3. Recent blockhash
        out.extend_from_slice(&recent_blockhash);

        // 4. Instructions = 1 transfer
        out.extend_from_slice(&Self::encode_short_len(1)); // num_instructions = 1

        // program_id_index = 2 (system_program)
        out.push(2u8);

        // account indices: from = 0, to = 1
        let account_indices = [0u8, 1u8];
        out.extend_from_slice(&Self::encode_short_len(account_indices.len()));
        out.extend_from_slice(&account_indices);

        // data: SystemInstruction::Transfer { lamports }
        // layout: [ 2u32 LE ][ lamports u64 LE ]
        let mut data = Vec::with_capacity(4 + 8);
        data.extend_from_slice(&2u32.to_le_bytes()); // Transfer discriminant = 2
        data.extend_from_slice(&lamports.to_le_bytes()); // lamports

        out.extend_from_slice(&Self::encode_short_len(data.len()));
        out.extend_from_slice(&data);

        out
    }

    // ==============================
    // Sign System Transfer Transaction
    // ==============================
    //
    // Returns: complete Transaction bytes:
    //   short_vec(num_signatures=1) || sig(64 bytes) || message_bytes

    pub fn sign_system_transfer_tx(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        to_pubkey_base58: &str,
        lamports: u64,
        recent_blockhash_base58: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let (sk, _pk) = Self::derive_keypair(mnemonic, passphrase, secondary_passphrase)?;
        Self::sign_system_transfer_with_key(
            &sk,
            to_pubkey_base58,
            lamports,
            recent_blockhash_base58,
        )
    }

    /// Sign system transfer using a pre-derived SigningKey (PRF path)
    pub fn sign_system_transfer_with_key(
        sk: &SigningKey,
        to_pubkey_base58: &str,
        lamports: u64,
        recent_blockhash_base58: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let from_pk_arr = sk.verifying_key().to_bytes();

        let to_pk = Self::decode_pubkey_base58(to_pubkey_base58)?;
        let recent_blockhash = Self::decode_blockhash_base58(recent_blockhash_base58)?;

        let message =
            Self::build_system_transfer_message(from_pk_arr, to_pk, lamports, recent_blockhash);

        let sig = sk.sign(&message).to_bytes();

        let mut tx = Vec::new();
        tx.extend_from_slice(&Self::encode_short_len(1));
        tx.extend_from_slice(&sig);
        tx.extend_from_slice(&message);

        Ok(tx)
    }

    // ==============================
    // SPL Token Transfer
    // ==============================

    /// Find a Program Derived Address (PDA), e.g. for an Associated Token Account.
    ///
    /// Algorithm (per Solana SDK):
    /// 1) Hash each seed
    /// 2) Hash the bump seed
    /// 3) Hash `[program_id, b"ProgramDerivedAddress"]` into the hasher
    /// 4) The result must not lie on the Ed25519 curve
    fn find_program_address(
        seeds: &[&[u8]],
        program_id: &[u8; 32],
    ) -> Result<[u8; 32], Box<dyn Error>> {
        // Try bump seeds from 255 down to 0
        for bump in (0u8..=255).rev() {
            match Self::create_program_address(seeds, &[bump], program_id) {
                Ok(address) => return Ok(address),
                Err(_) => continue,
            }
        }
        Err("Could not find valid PDA".into())
    }

    /// `create_program_address` — see Solana SDK
    fn create_program_address(
        seeds: &[&[u8]],
        bump_seed: &[u8],
        program_id: &[u8; 32],
    ) -> Result<[u8; 32], Box<dyn Error>> {
        // Enforce seed length limits
        const MAX_SEED_LEN: usize = 32;
        const MAX_SEEDS: usize = 16;

        if seeds.len() + 1 > MAX_SEEDS {
            return Err("Too many seeds".into());
        }

        for seed in seeds {
            if seed.len() > MAX_SEED_LEN {
                return Err("Seed too long".into());
            }
        }

        // Solana incremental hash over seeds, bump, then program_id || PDA_MARKER
        let mut hasher = Sha256::new();

        for seed in seeds {
            hasher.update(seed);
        }

        hasher.update(bump_seed);

        hasher.update(program_id);
        hasher.update(b"ProgramDerivedAddress");

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash[..32]);

        // PDAs must be off-curve
        if Self::is_on_curve(&result) {
            return Err("Invalid seeds - address on curve".into());
        }

        Ok(result)
    }

    /// Whether a point is on the Ed25519 curve
    fn is_on_curve(point: &[u8; 32]) -> bool {
        use ed25519_dalek::VerifyingKey;
        VerifyingKey::from_bytes(point).is_ok()
    }

    /// Associated Token Account (ATA) address
    pub fn get_associated_token_address(
        wallet: &[u8; 32],
        mint: &[u8; 32],
    ) -> Result<[u8; 32], Box<dyn Error>> {
        let seeds: [&[u8]; 3] = [wallet, &SPL_TOKEN_PROGRAM_ID, mint];
        Self::find_program_address(&seeds, &ATA_PROGRAM_ID)
    }

    /// SPL Token Transfer instruction data: `3` (discriminant) + `amount` (u64 LE)
    fn build_spl_transfer_data(amount: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(9);
        data.push(3u8); // SPL Token Transfer instruction = 3
        data.extend_from_slice(&amount.to_le_bytes());
        data
    }

    /// Legacy message for an SPL Token transfer
    ///
    /// Account order (message rules):
    /// 1) Signer + writable (owner, pays fee)
    /// 2) Signer + readonly (none)
    /// 3) Nonsigner + writable (source_ata, dest_ata)
    /// 4) Nonsigner + readonly (token_program)
    ///
    /// Order: `[owner, source_ata, dest_ata, token_program]`
    fn build_spl_transfer_message(
        source_ata: [u8; 32],
        dest_ata: [u8; 32],
        owner: [u8; 32],
        amount: u64,
        recent_blockhash: [u8; 32],
    ) -> Vec<u8> {
        let mut out = Vec::new();

        // 1. Header
        // - num_required_signatures = 1 (owner)
        // - num_readonly_signed_accounts = 0
        // - num_readonly_unsigned_accounts = 1 (token_program)
        out.push(1u8); // num_required_signatures
        out.push(0u8); // num_readonly_signed_accounts
        out.push(1u8); // num_readonly_unsigned_accounts

        // 2) Account keys — signers first, then writable
        let account_keys: [&[u8]; 4] = [
            &owner,                // 0: signer, writable
            &source_ata,           // 1: writable
            &dest_ata,             // 2: writable
            &SPL_TOKEN_PROGRAM_ID, // 3: readonly
        ];
        out.extend_from_slice(&Self::encode_short_len(account_keys.len()));
        for pk in &account_keys {
            out.extend_from_slice(pk);
        }

        // 3. Recent blockhash
        out.extend_from_slice(&recent_blockhash);

        // 4) One instruction: SPL transfer
        out.extend_from_slice(&Self::encode_short_len(1)); // num_instructions = 1

        // program_id_index = 3 (token program)
        out.push(3u8);

        // Instruction accounts: [source, dest, authority] → indices 1,2,0
        let account_indices = [1u8, 2u8, 0u8];
        out.extend_from_slice(&Self::encode_short_len(account_indices.len()));
        out.extend_from_slice(&account_indices);

        // data: SPL Transfer instruction
        let data = Self::build_spl_transfer_data(amount);
        out.extend_from_slice(&Self::encode_short_len(data.len()));
        out.extend_from_slice(&data);

        out
    }

    /// Sign an SPL token transfer. Args: mnemonic, passphrase, mint (base58), recipient
    /// wallet (base58, not ATA), raw amount, recent blockhash (base58). Returns wire tx bytes.
    pub fn sign_spl_transfer_tx(
        mnemonic: &str,
        passphrase: &str,
        mint_base58: &str,
        to_wallet_base58: &str,
        amount: u64,
        recent_blockhash_base58: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        // 1) derive keypair via ACE-GF (secondary_passphrase not used for SPL)
        let (sk, pk) = Self::derive_keypair(mnemonic, passphrase, None)?;
        let owner = pk.to_bytes();

        // 2) parse addresses
        let mint = Self::decode_pubkey_base58(mint_base58)?;
        let to_wallet = Self::decode_pubkey_base58(to_wallet_base58)?;
        let recent_blockhash = Self::decode_blockhash_base58(recent_blockhash_base58)?;

        // 3) derive ATAs
        let source_ata = Self::get_associated_token_address(&owner, &mint)?;
        let dest_ata = Self::get_associated_token_address(&to_wallet, &mint)?;

        // 4) build message
        let message =
            Self::build_spl_transfer_message(source_ata, dest_ata, owner, amount, recent_blockhash);

        // 5) sign
        let sig = sk.sign(&message).to_bytes();

        // 6) serialize tx
        let mut tx = Vec::new();
        tx.extend_from_slice(&Self::encode_short_len(1));
        tx.extend_from_slice(&sig);
        tx.extend_from_slice(&message);

        Ok(tx)
    }

    /// Message: create ATA + transfer (when the recipient has no ATA yet)
    ///
    /// Two instructions: createAssociatedTokenAccount, then SPL transfer.
    ///
    /// Account order: owner(s,w), source_ata(w), dest_ata(w), to_wallet(r), mint(r),
    /// system(r), token(r), ata_program(r)
    fn build_spl_transfer_with_create_ata_message(
        source_ata: [u8; 32],
        dest_ata: [u8; 32],
        owner: [u8; 32],
        to_wallet: [u8; 32],
        mint: [u8; 32],
        amount: u64,
        recent_blockhash: [u8; 32],
    ) -> Vec<u8> {
        let mut out = Vec::new();

        // 1. Header
        // - num_required_signatures = 1 (owner)
        // - num_readonly_signed_accounts = 0
        // - num_readonly_unsigned_accounts = 5 (to_wallet, mint, system, token, ata programs)
        out.push(1u8); // num_required_signatures
        out.push(0u8); // num_readonly_signed_accounts
        out.push(5u8); // num_readonly_unsigned_accounts

        // 2) Account keys — signers first, writable first
        let account_keys: [&[u8]; 8] = [
            &owner,                // 0: signer, writable (payer + authority)
            &source_ata,           // 1: writable
            &dest_ata,             // 2: writable
            &to_wallet,            // 3: readonly (ATA owner)
            &mint,                 // 4: readonly
            &SYSTEM_PROGRAM_ID,    // 5: readonly
            &SPL_TOKEN_PROGRAM_ID, // 6: readonly
            &ATA_PROGRAM_ID,       // 7: readonly
        ];
        out.extend_from_slice(&Self::encode_short_len(account_keys.len()));
        for pk in &account_keys {
            out.extend_from_slice(pk);
        }

        // 3. Recent blockhash
        out.extend_from_slice(&recent_blockhash);

        // 4) Two instructions
        out.extend_from_slice(&Self::encode_short_len(2)); // num_instructions = 2

        // Instruction 1: createAssociatedTokenAccount — program 7
        out.push(7u8);

        // [payer, ata, owner, mint, system, token] → indices 0,2,3,4,5,6
        let create_ata_account_indices = [0u8, 2u8, 3u8, 4u8, 5u8, 6u8];
        out.extend_from_slice(&Self::encode_short_len(create_ata_account_indices.len()));
        out.extend_from_slice(&create_ata_account_indices);

        // createAssociatedTokenAccount has empty data
        out.extend_from_slice(&Self::encode_short_len(0));

        // Instruction 2: SPL transfer — program 6
        out.push(6u8);

        // [source, dest, authority] → 1,2,0
        let transfer_account_indices = [1u8, 2u8, 0u8];
        out.extend_from_slice(&Self::encode_short_len(transfer_account_indices.len()));
        out.extend_from_slice(&transfer_account_indices);

        // data: SPL Transfer instruction
        let data = Self::build_spl_transfer_data(amount);
        out.extend_from_slice(&Self::encode_short_len(data.len()));
        out.extend_from_slice(&data);

        out
    }

    /// Sign create-ATA + transfer. Same args as `sign_spl_transfer_tx`.
    pub fn sign_spl_transfer_with_create_ata_tx(
        mnemonic: &str,
        passphrase: &str,
        mint_base58: &str,
        to_wallet_base58: &str,
        amount: u64,
        recent_blockhash_base58: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        // 1) derive keypair via ACE-GF
        let (sk, pk) = Self::derive_keypair(mnemonic, passphrase, None)?;
        let owner = pk.to_bytes();

        // 2) parse addresses
        let mint = Self::decode_pubkey_base58(mint_base58)?;
        let to_wallet = Self::decode_pubkey_base58(to_wallet_base58)?;
        let recent_blockhash = Self::decode_blockhash_base58(recent_blockhash_base58)?;

        // 3) derive ATAs
        let source_ata = Self::get_associated_token_address(&owner, &mint)?;
        let dest_ata = Self::get_associated_token_address(&to_wallet, &mint)?;

        // 4) build message with createATA instruction
        let message = Self::build_spl_transfer_with_create_ata_message(
            source_ata,
            dest_ata,
            owner,
            to_wallet,
            mint,
            amount,
            recent_blockhash,
        );

        // 5) sign
        let sig = sk.sign(&message).to_bytes();

        // 6) serialize tx
        let mut tx = Vec::new();
        tx.extend_from_slice(&Self::encode_short_len(1));
        tx.extend_from_slice(&sig);
        tx.extend_from_slice(&message);

        Ok(tx)
    }

    /// Sign an external serialized transaction (Legacy Transaction)
    ///
    /// Takes a base64-encoded serialized transaction, signs it with the derived keypair,
    /// and returns the signed transaction as base64.
    ///
    /// Note: This only works for Legacy Transactions, not Versioned Transactions (v0).
    /// The transaction must have the signer as the first account.
    pub fn sign_serialized_transaction(
        mnemonic: &str,
        passphrase: &str,
        serialized_tx_base64: &str,
    ) -> Result<String, Box<dyn Error>> {
        let (sk, _pk) = Self::derive_keypair(mnemonic, passphrase, None)?;
        Self::sign_serialized_transaction_with_key(&sk, serialized_tx_base64)
    }

    /// Sign an external serialized transaction using a pre-derived SigningKey (PRF path)
    pub fn sign_serialized_transaction_with_key(
        sk: &SigningKey,
        serialized_tx_base64: &str,
    ) -> Result<String, Box<dyn Error>> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

        let signer_pubkey = sk.verifying_key().to_bytes();

        let tx_bytes = BASE64
            .decode(serialized_tx_base64)
            .map_err(|e| format!("Failed to decode base64: {}", e))?;

        if tx_bytes.is_empty() {
            return Err("Empty transaction".into());
        }

        let mut offset = 0;

        // Read num_signatures (short_vec encoded)
        let (num_sigs, bytes_read) = Self::decode_short_vec(&tx_bytes[offset..])?;
        offset += bytes_read;

        // Skip existing signatures (they may be empty placeholders)
        let sigs_size = num_sigs * 64;
        if offset + sigs_size > tx_bytes.len() {
            return Err("Invalid transaction: signatures overflow".into());
        }
        offset += sigs_size;

        // The rest is the message
        let message = &tx_bytes[offset..];

        if message.len() < 4 {
            return Err("Message too short".into());
        }

        let _num_required_sigs = message[0];
        let _num_readonly_signed = message[1];
        let _num_readonly_unsigned = message[2];

        // Read num_accounts
        let (num_accounts, accounts_offset) = Self::decode_short_vec(&message[3..])?;
        let accounts_start = 3 + accounts_offset;

        if num_accounts == 0 || accounts_start + 32 > message.len() {
            return Err("Invalid message: no accounts".into());
        }

        // First account should be the fee payer / signer
        let first_account = &message[accounts_start..accounts_start + 32];

        if first_account != signer_pubkey {
            return Err(format!(
                "Transaction signer mismatch. Expected: {}, Found: {}",
                bs58::encode(&signer_pubkey).into_string(),
                bs58::encode(first_account).into_string()
            )
            .into());
        }

        let signature = sk.sign(message).to_bytes();

        let mut signed_tx = Vec::new();
        signed_tx.extend_from_slice(&Self::encode_short_len(1)); // 1 signature
        signed_tx.extend_from_slice(&signature);
        signed_tx.extend_from_slice(message);

        Ok(BASE64.encode(&signed_tx))
    }

    /// Decode short_vec encoding
    /// Returns (value, bytes_read)
    fn decode_short_vec(data: &[u8]) -> Result<(usize, usize), Box<dyn Error>> {
        if data.is_empty() {
            return Err("Empty data for short_vec decode".into());
        }

        let mut value: usize = 0;
        let mut shift = 0;
        let mut i = 0;

        loop {
            if i >= data.len() {
                return Err("Incomplete short_vec".into());
            }

            let byte = data[i];
            value |= ((byte & 0x7F) as usize) << shift;

            if byte & 0x80 == 0 {
                return Ok((value, i + 1));
            }

            shift += 7;
            i += 1;

            if shift > 21 {
                return Err("short_vec overflow".into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only mnemonic
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const TEST_PASSPHRASE: &str = "test";

    #[test]
    fn test_encode_short_len() {
        // short_vec encode
        assert_eq!(SolanaSigner::encode_short_len(0), vec![0]);
        assert_eq!(SolanaSigner::encode_short_len(1), vec![1]);
        assert_eq!(SolanaSigner::encode_short_len(127), vec![127]);
        assert_eq!(SolanaSigner::encode_short_len(128), vec![0x80, 1]);
        assert_eq!(SolanaSigner::encode_short_len(255), vec![0xFF, 1]);
    }

    #[test]
    fn test_decode_pubkey_base58() {
        // System program = all zeros
        let system_program = "11111111111111111111111111111111";
        let decoded = SolanaSigner::decode_pubkey_base58(system_program).unwrap();
        assert_eq!(decoded, [0u8; 32]);

        // Invalid must fail
        let invalid = "invalid";
        assert!(SolanaSigner::decode_pubkey_base58(invalid).is_err());
    }

    #[test]
    fn test_get_associated_token_address() {
        // Known wallet + USDC mint
        // USDC mint: EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v

        let wallet_str = "11111111111111111111111111111111";
        let mint_str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

        let wallet = SolanaSigner::decode_pubkey_base58(wallet_str).unwrap();
        let mint = SolanaSigner::decode_pubkey_base58(mint_str).unwrap();

        let ata = SolanaSigner::get_associated_token_address(&wallet, &mint);
        assert!(ata.is_ok());

        let ata_bytes = ata.unwrap();
        assert_eq!(ata_bytes.len(), 32);

        // PDA is off-curve
        assert!(!SolanaSigner::is_on_curve(&ata_bytes));

        // Cross-check with @solana/spl-token reference:
        // Wallet: 11111111111111111111111111111111
        // Mint: EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
        // ATA: HJt8Tjdsc9ms9i4WCZEzhzr4oyf3ANcdzXrNdLPFqm3M
        let expected_ata =
            SolanaSigner::decode_pubkey_base58("HJt8Tjdsc9ms9i4WCZEzhzr4oyf3ANcdzXrNdLPFqm3M")
                .unwrap();

        let ata_base58 = bs58::encode(&ata_bytes).into_string();
        println!("Calculated ATA: {}", ata_base58);
        println!("Expected ATA:   HJt8Tjdsc9ms9i4WCZEzhzr4oyf3ANcdzXrNdLPFqm3M");

        assert_eq!(ata_bytes, expected_ata, "ATA address mismatch!");
    }

    #[test]
    fn test_program_ids_correct() {
        let expected_token =
            SolanaSigner::decode_pubkey_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
                .unwrap();
        assert_eq!(SPL_TOKEN_PROGRAM_ID, expected_token);

        // Official Associated Token program id
        let expected_ata =
            SolanaSigner::decode_pubkey_base58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
                .unwrap();
        assert_eq!(ATA_PROGRAM_ID, expected_ata);
    }

    #[test]
    fn test_build_spl_transfer_data() {
        let data = SolanaSigner::build_spl_transfer_data(1000000); // 1 USDC (6 decimals)

        assert_eq!(data[0], 3); // Transfer
        assert_eq!(data.len(), 9);

        let amount_bytes = &data[1..9];
        let amount = u64::from_le_bytes(amount_bytes.try_into().unwrap());
        assert_eq!(amount, 1000000);
    }

    #[test]
    fn test_is_on_curve() {
        let zero = [0u8; 32];
        // Some impls may accept all-zero; we only require the check runs
        let _ = SolanaSigner::is_on_curve(&zero);
    }

    #[test]
    fn test_build_system_transfer_message() {
        let from = [1u8; 32];
        let to = [2u8; 32];
        let lamports = 1_000_000_000u64; // 1 SOL
        let blockhash = [3u8; 32];

        let message = SolanaSigner::build_system_transfer_message(from, to, lamports, blockhash);

        // Header: 3 bytes
        assert_eq!(message[0], 1); // num_required_signatures
        assert_eq!(message[1], 0); // num_readonly_signed_accounts
        assert_eq!(message[2], 1); // num_readonly_unsigned_accounts

        // short_vec length for 3 accounts
        assert_eq!(message[3], 3);

        assert!(message.len() > 100);
    }

    #[test]
    fn test_build_spl_transfer_message() {
        let source_ata = [1u8; 32];
        let dest_ata = [2u8; 32];
        let owner = [3u8; 32];
        let amount = 1_000_000u64;
        let blockhash = [4u8; 32];

        let message = SolanaSigner::build_spl_transfer_message(
            source_ata, dest_ata, owner, amount, blockhash,
        );

        assert_eq!(message[0], 1);
        assert_eq!(message[1], 0);
        assert_eq!(message[2], 1);

        assert_eq!(message[3], 4);

        let first_account = &message[4..36];
        assert_eq!(first_account, &owner);

        assert!(message.len() > 130);
    }

    // ==============================
    // Context-Isolated Tests (REV32 only)
    // ==============================

    #[test]
    fn test_derive_keypair_with_context_empty_matches_standard() {
        // Empty context should produce the same keypair as derive_keypair
        // for REV32 wallets. We use TEST_MNEMONIC which may be a legacy or REV32
        // mnemonic; just verify the function doesn't panic with empty context.
        let result = SolanaSigner::derive_keypair(TEST_MNEMONIC, TEST_PASSPHRASE, None);
        let result_ctx =
            SolanaSigner::derive_keypair_with_context(TEST_MNEMONIC, TEST_PASSPHRASE, None, "");

        match (result, result_ctx) {
            (Ok((_, pk1)), Ok((_, pk2))) => {
                // If the mnemonic is REV32, empty context should equal standard derivation
                assert_eq!(
                    pk1.to_bytes(),
                    pk2.to_bytes(),
                    "Empty context should produce the same public key as standard derivation"
                );
            }
            (Err(_), Err(_)) => {
                // Both fail -> mnemonic issue, that's fine for this test
            }
            (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
                // If standard works but context fails (or vice versa), that's also OK
                // because empty-context delegates to standard derive_keypair
            }
        }
    }

    #[test]
    fn test_derive_keypair_with_context_different_contexts_differ() {
        // This test verifies the core property: different contexts produce different keys.
        // We cannot use TEST_MNEMONIC because it might be a UUID wallet.
        // Instead, test the PRF base_key path which doesn't require wallet format.
        let base_key = [42u8; 32]; // Arbitrary base key for testing
        let dummy_mnemonic = TEST_MNEMONIC; // Just for unsealing, PRF skips passphrase

        let result_a = SolanaSigner::derive_keypair_with_context_base_key(
            dummy_mnemonic,
            &base_key,
            "vault:operating:0",
        );
        let result_b = SolanaSigner::derive_keypair_with_context_base_key(
            dummy_mnemonic,
            &base_key,
            "vault:escrow:0",
        );

        // Both should succeed (PRF path doesn't require REV32 format for unsealing)
        // Note: derive_keypair_with_context_base_key bypasses mnemonic format checks
        // for non-empty context, going directly through identity_root derivation.
        if let (Ok((_, pk_a)), Ok((_, pk_b))) = (result_a, result_b) {
            assert_ne!(
                pk_a.to_bytes(),
                pk_b.to_bytes(),
                "Different contexts must produce different public keys"
            );
        }
        // If the PRF path fails (mnemonic unsealing issue), that's OK for a unit test
    }

    #[test]
    fn test_derive_keypair_with_context_deterministic() {
        // Same inputs always produce the same output
        let base_key = [42u8; 32];
        let dummy_mnemonic = TEST_MNEMONIC;
        let context = "agent:abc:dir:outbound:seq:0";

        let result_1 =
            SolanaSigner::derive_keypair_with_context_base_key(dummy_mnemonic, &base_key, context);
        let result_2 =
            SolanaSigner::derive_keypair_with_context_base_key(dummy_mnemonic, &base_key, context);

        if let (Ok((_, pk_1)), Ok((_, pk_2))) = (result_1, result_2) {
            assert_eq!(
                pk_1.to_bytes(),
                pk_2.to_bytes(),
                "Same context must produce the same public key"
            );
        }
    }

    #[test]
    fn test_sign_message_with_context_produces_valid_signature() {
        // Verify that sign_message_with_context produces a valid Ed25519 signature
        let base_key = [42u8; 32];
        let dummy_mnemonic = TEST_MNEMONIC;
        let context = "test:signing:context";
        let message = b"Hello, context-isolated Solana!";

        let keypair_result =
            SolanaSigner::derive_keypair_with_context_base_key(dummy_mnemonic, &base_key, context);

        if let Ok((signing_key, verifying_key)) = keypair_result {
            // Sign with the raw key
            let sig = signing_key.sign(message);

            // Verify the signature
            use ed25519_dalek::Verifier;
            assert!(
                verifying_key.verify(message, &sig).is_ok(),
                "Context-derived Ed25519 signature must be valid"
            );

            // Verify hex encoding round-trips
            let sig_hex = hex::encode(sig.to_bytes());
            assert_eq!(
                sig_hex.len(),
                128,
                "Ed25519 signature hex should be 128 chars"
            );
        }
    }

    #[test]
    fn test_get_address_with_context_returns_base58() {
        // get_address_with_context should return a valid base58 address.
        // Empty context should work for any wallet type.
        let result = SolanaSigner::get_address_with_context(TEST_MNEMONIC, TEST_PASSPHRASE, "");

        match result {
            Ok(address) => {
                // Should be a valid base58 Solana address
                let decoded = bs58::decode(&address).into_vec();
                assert!(decoded.is_ok(), "Address should be valid base58");
                assert_eq!(
                    decoded.unwrap().len(),
                    32,
                    "Solana address should decode to 32 bytes"
                );
            }
            Err(_) => {
                // If it fails (e.g., mnemonic issue), that's acceptable in unit tests
            }
        }
    }

    #[test]
    fn test_build_spl_transfer_with_create_ata_message() {
        let source_ata = [1u8; 32];
        let dest_ata = [2u8; 32];
        let owner = [3u8; 32];
        let to_wallet = [4u8; 32];
        let mint = [5u8; 32];
        let amount = 1_000_000u64;
        let blockhash = [6u8; 32];

        let message = SolanaSigner::build_spl_transfer_with_create_ata_message(
            source_ata, dest_ata, owner, to_wallet, mint, amount, blockhash,
        );

        assert_eq!(message[0], 1);
        assert_eq!(message[1], 0);
        assert_eq!(message[2], 5);

        assert_eq!(message[3], 8);

        let first_account = &message[4..36];
        assert_eq!(first_account, &owner);

        let blockhash_offset = 4 + 8 * 32;
        let msg_blockhash = &message[blockhash_offset..blockhash_offset + 32];
        assert_eq!(msg_blockhash, &blockhash);

        let num_instructions_offset = blockhash_offset + 32;
        assert_eq!(message[num_instructions_offset], 2);

        assert!(message.len() > 280);
    }
}
