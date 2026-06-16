// src/acegf_core.rs
//
// Core cryptographic operations for ACE-GF.
//
// Uses canonical REV-based sealed flow for wallet generation and recovery.

use crate::acegf::CryptoError;
use crate::acegf_structs::AcegfError;
use crate::acegf_structs::CryptoEntity;
use crate::pqclean_ffi::MlDsa44;
use crate::utils::acegf_rev_generator::AccountType;
use crate::utils::passphrase_sealing_util::MnemonicSealError;
use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;
use base64ct::Base64;
use base64ct::Encoding;
use bech32::ToBase32;
use bech32::Variant;
use bip39::Language;
use bip39::Mnemonic;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use sha2::Sha256;
use sha3::Digest;
use sha3::Keccak256;
use sha3::Sha3_256;
use std::error::Error;
use x25519_dalek::PublicKey as XPublic;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;
use zeroize::Zeroizing;

// For WASM: use k256 (pure Rust)
use k256::ecdsa::SigningKey as K256SigningKey;

// For native: use secp256k1 and bitcoin crates
#[cfg(not(target_arch = "wasm32"))]
use bitcoin::key::Keypair;
#[cfg(not(target_arch = "wasm32"))]
use bitcoin::Address;
#[cfg(not(target_arch = "wasm32"))]
use bitcoin::Network;
#[cfg(not(target_arch = "wasm32"))]
use bitcoin::XOnlyPublicKey;
#[cfg(not(target_arch = "wasm32"))]
use secp256k1::{Secp256k1, SecretKey};

use crate::acegf_structs::SchemeSeeds;

pub struct ACEGFCore;

impl ACEGFCore {
    const ED25519_SOLANA_INFO_SEALED: &'static [u8] = b"ACEGF-V1-ED25519-SOLANA";
    const ED25519_POLKADOT_INFO_SEALED: &'static [u8] = b"ACEGF-V1-ED25519-POLKADOT";
    const SECP256K1_EVM_INFO_SEALED: &'static [u8] = b"ACEGF-V1-SECP256K1-EVM";
    const SECP256K1_BTC_INFO_SEALED: &'static [u8] = b"ACEGF-V1-SECP256K1-BTC";
    const SECP256K1_COSMOS_INFO_SEALED: &'static [u8] = b"ACEGF-V1-SECP256K1-COSMOS";
    const SECP256K1_TRON_INFO_SEALED: &'static [u8] = b"ACEGF-V1-SECP256K1-TRON";
    const X25519_INFO_SEALED: &'static [u8] = b"ACEGF-V1-X25519-IDENTITY";
    const ML_DSA_INFO_SEALED: &'static [u8] = b"ACEGF-V1-ML-DSA-44-PQC-IDENTITY";
    const ML_KEM_INFO_SEALED: &'static [u8] = b"ACEGF-V1-ML-KEM-768-PQC-IDENTITY";

    fn new_identity_material16(_account_type: u8) -> Result<Zeroizing<[u8; 16]>, AcegfError> {
        let mut material = [0u8; 16];
        getrandom::getrandom(&mut material).map_err(|_| AcegfError::Internal)?;
        Ok(Zeroizing::new(material))
    }

    fn derive_seeds_from_sealed_passphrase(
        sealed: &[u8; 32],
        passphrase: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<SchemeSeeds, AcegfError> {
        let full_passphrase =
            PassphraseSealingUtil::combine_passphrase(passphrase, secondary_passphrase);
        let material =
            PassphraseSealingUtil::unseal_identity_material(sealed, full_passphrase.as_bytes())?;
        Self::derive_from_material16(&*material)
    }

    fn derive_seeds_from_sealed_base_key(
        sealed: &[u8; 32],
        base_key: &[u8; 32],
    ) -> Result<SchemeSeeds, AcegfError> {
        let material =
            PassphraseSealingUtil::unseal_identity_material_with_base_key(sealed, base_key)?;
        Self::derive_from_material16(&*material)
    }

    pub fn generate_ace_internal_with_type(
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        account_type: u8,
    ) -> Result<CryptoEntity, AcegfError> {
        let material = Self::new_identity_material16(account_type)?;
        let full_passphrase =
            PassphraseSealingUtil::combine_passphrase(passphrase, secondary_passphrase);
        let sealed =
            PassphraseSealingUtil::seal_identity_material(&*material, full_passphrase.as_bytes())?;
        let mnemonic_str = Mnemonic::from_entropy(&sealed)
            .map_err(|_| AcegfError::Internal)?
            .to_string();
        let mut seeds = Self::derive_from_material16(&*material)?;

        match Self::generate_crypto_entity(&mut seeds) {
            Ok(mut entity) => {
                entity.mnemonic = Zeroizing::new(mnemonic_str);
                Ok(entity)
            }
            Err(e) => Err(e),
        }
    }

    /// Compute xid: permanent wallet fingerprint from rev32 (sealed mnemonic entropy).
    /// xid = hex(SHA3-256(sealed || "acegf:xid"))
    pub fn compute_xid(sealed: &[u8; 32]) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(sealed);
        hasher.update(b"acegf:xid");
        hex::encode(hasher.finalize())
    }

    pub fn generate_ace_internal(
        passphrase: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<CryptoEntity, AcegfError> {
        let material = Self::new_identity_material16(AccountType::Standard as u8)?;
        let full_passphrase =
            PassphraseSealingUtil::combine_passphrase(passphrase, secondary_passphrase);
        let sealed =
            PassphraseSealingUtil::seal_identity_material(&*material, full_passphrase.as_bytes())?;
        let mnemonic_str = Mnemonic::from_entropy(&sealed)
            .map_err(|_| AcegfError::Internal)?
            .to_string();
        let xid = Self::compute_xid(&sealed);
        let mut seeds = Self::derive_from_material16(&*material)?;

        match Self::generate_crypto_entity(&mut seeds) {
            Ok(mut entity) => {
                entity.mnemonic = Zeroizing::new(mnemonic_str);
                entity.xid = xid;
                Ok(entity)
            }
            Err(e) => Err(e),
        }
    }

    pub fn generate_crypto_entity(seeds: &mut SchemeSeeds) -> Result<CryptoEntity, AcegfError> {
        // Derive all addresses with proper error propagation
        let evm_address = Self::derive_evm_address(&seeds.secp256k1_evm)
            .map_err(|_| AcegfError::AddressDerivationFailed)?;
        let bitcoin_address = Self::derive_btc_taproot_address(&seeds.secp256k1_btc)
            .map_err(|_| AcegfError::AddressDerivationFailed)?;
        let solana_address = Self::derive_solana_address(&seeds.ed25519_solana)
            .map_err(|_| AcegfError::AddressDerivationFailed)?;
        let cosmos_address = Self::derive_cosmos_address(&seeds.secp256k1_cosmos)
            .map_err(|_| AcegfError::AddressDerivationFailed)?;
        let tron_address = Self::derive_tron_address(&seeds.secp256k1_tron)
            .map_err(|_| AcegfError::AddressDerivationFailed)?;
        let polkadot_address = Self::derive_polkadot_address(&seeds.ed25519_polkadot)
            .map_err(|_| AcegfError::AddressDerivationFailed)?;
        let x25519 = Self::derive_x25519_public(&seeds.x25519)
            .map_err(|_| AcegfError::AddressDerivationFailed)?;
        // PQC address is allowed to fail gracefully (returns message for unsupported platforms)
        let xaddress = Self::derive_pqc_address(&seeds.ml_dsa_44);
        // ML-KEM-768 public key: fail gracefully, matching the xaddress path.
        let xkem = Self::derive_ml_kem_768_public(&seeds.ml_kem_768)
            .unwrap_or_else(|_| Self::PQC_NOT_AVAILABLE_MESSAGE.to_string());

        let entity = CryptoEntity {
            evm_address,
            bitcoin_address,
            solana_address,
            cosmos_address,
            tron_address,
            polkadot_address,
            xaddress,
            x25519,
            xkem,
            ..Default::default()
        };

        Self::clear_scheme_seeds(seeds);

        Ok(entity)
    }

    pub fn to_checksum_address(address: &str) -> String {
        let addr_lower = address.strip_prefix("0x").unwrap_or(address).to_lowercase();

        let mut hasher = Keccak256::new();
        hasher.update(addr_lower.as_bytes());
        let hash = hasher.finalize();
        let hash_hex = hex::encode(hash);

        let mut checksum_addr = String::with_capacity(42);
        checksum_addr.push_str("0x");

        for (i, c) in addr_lower.chars().enumerate() {
            if c.is_numeric() {
                checksum_addr.push(c);
            } else {
                let hash_char_val = u8::from_str_radix(&hash_hex[i..i + 1], 16).unwrap_or(0);
                if hash_char_val >= 8 {
                    checksum_addr.push(c.to_ascii_uppercase());
                } else {
                    checksum_addr.push(c);
                }
            }
        }
        checksum_addr
    }

    pub fn derive_x25519_public(
        seed: &Zeroizing<[u8; 32]>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        if seed.len() != 32 {
            return Err("Invalid X25519 seed length: expected 32 bytes".into());
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&**seed);

        let secret = StaticSecret::from(bytes);

        let public = XPublic::from(&secret);

        let pub_base64 = Base64::encode_string(public.as_bytes());

        Ok(pub_base64)
    }

    /// Derive the Base64-encoded ML-KEM-768 encapsulation (public) key
    /// from a 64-byte seed (`d || z`, per FIPS 203).
    ///
    /// This is the post-quantum analogue of `derive_x25519_public`: it returns
    /// a Base64 string that callers publish as the wallet's KEM identity
    /// (`xkem`). Interface shape mirrors `derive_x25519_public` exactly —
    /// same error type, same encoding, same ownership semantics — so KEM
    /// can be used interchangeably alongside X25519 at every layer.
    pub fn derive_ml_kem_768_public(
        seed: &Zeroizing<[u8; 64]>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        use crate::pqclean_ffi::MlKem768;

        if seed.len() != 64 {
            return Err("Invalid ML-KEM-768 seed length: expected 64 bytes".into());
        }

        let (ek_bytes, _dk) = MlKem768::keypair_from_seed(&**seed)
            .map_err(|e| format!("ML-KEM-768 keygen failed: {}", e))?;

        Ok(Base64::encode_string(&ek_bytes))
    }

    /// Shown when PQC is unavailable
    pub const PQC_NOT_AVAILABLE_MESSAGE: &'static str =
        "Please install Yallet app on your mobile device to support PQC, see https://yallet.xyz.";

    pub fn derive_pqc_address(pqc_seed: &Zeroizing<[u8; 32]>) -> String {
        // Try to derive a PQC address
        // - Native: PQClean C
        // - WASM: return hint (pure-Rust PQC API still unstable)
        match MlDsa44::keypair_from_seed(&pqc_seed) {
            Ok((pk, _sk)) => {
                let mut hasher = Keccak256::new();
                hasher.update(&pk);
                let hash_result = hasher.finalize();

                let fingerprint = &hash_result[12..32];

                bech32::encode("acegf", fingerprint.to_base32(), Variant::Bech32m)
                    .unwrap_or_else(|_| Self::PQC_NOT_AVAILABLE_MESSAGE.to_string())
            }
            Err(_) => {
                // PQC keygen failed (e.g. WASM) — return hint
                Self::PQC_NOT_AVAILABLE_MESSAGE.to_string()
            }
        }
    }
    pub fn derive_polkadot_address(seed: &Zeroizing<[u8; 32]>) -> Result<String, Box<dyn Error>> {
        let signing_key = SigningKey::from_bytes(&**seed);
        let public_bytes = signing_key.verifying_key().to_bytes();

        let mut payload = Vec::with_capacity(35);
        payload.push(0x00);
        payload.extend_from_slice(&public_bytes);

        use blake2::{Blake2b512, Digest as BlakeDigest};
        let mut hasher = Blake2b512::new();
        hasher.update(b"SS58PRE");
        hasher.update(&payload);
        let hash = hasher.finalize();

        payload.extend_from_slice(&hash[0..2]);

        Ok(bs58::encode(payload).into_string())
    }

    // Cosmos address derivation - use k256 for WASM compatibility
    pub fn derive_cosmos_address(seed: &Zeroizing<[u8; 32]>) -> Result<String, Box<dyn Error>> {
        let signing_key = K256SigningKey::from_bytes((&**seed).into())
            .map_err(|e| format!("Invalid secp256k1 key: {}", e))?;
        let verifying_key = signing_key.verifying_key();
        let public_key_point = verifying_key.to_encoded_point(true); // compressed
        let serialized_pk = public_key_point.as_bytes();

        let sha_hash = sha2::Sha256::digest(serialized_pk);
        let mut ripemd = ripemd::Ripemd160::new();
        ripemd.update(sha_hash);
        let fingerprint = ripemd.finalize();

        Ok(bech32::encode(
            "cosmos",
            fingerprint.to_base32(),
            bech32::Variant::Bech32,
        )?)
    }

    /// Derive a Tron address from a secp256k1 seed.
    ///
    /// Algorithm:
    ///   1. Derive uncompressed public key (65 bytes: 0x04 || 64B)
    ///   2. Keccak256(pubkey[1..]) → take last 20 bytes  (identical to ETH)
    ///   3. Prepend 0x41 → 21-byte raw address
    ///   4. checksum = SHA256(SHA256(raw))[..4]
    ///   5. Base58(raw || checksum) → starts with "T"
    pub fn derive_tron_address(
        seed: &Zeroizing<[u8; 32]>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        use sha2::{Digest as _, Sha256};

        let signing_key = K256SigningKey::from_bytes((&**seed).into())
            .map_err(|e| format!("Invalid secp256k1 key: {}", e))?;
        let verifying_key = signing_key.verifying_key();
        let public_key_point = verifying_key.to_encoded_point(false); // uncompressed
        let serialized_pk = public_key_point.as_bytes();

        // Same Keccak step as ETH
        let hash = Keccak256::digest(&serialized_pk[1..]);
        let addr20 = &hash[12..]; // last 20 bytes

        // 21-byte raw address: Tron mainnet prefix 0x41
        let mut raw = [0u8; 21];
        raw[0] = 0x41;
        raw[1..].copy_from_slice(addr20);

        // Double-SHA256 checksum (first 4 bytes)
        let first = Sha256::digest(&raw);
        let second = Sha256::digest(&first);
        let checksum = &second[..4];

        // Base58Check: raw(21) || checksum(4)
        let mut payload = [0u8; 25];
        payload[..21].copy_from_slice(&raw);
        payload[21..].copy_from_slice(checksum);

        Ok(bs58::encode(&payload).into_string())
    }

    // EVM address derivation - use k256 for WASM compatibility
    pub fn derive_evm_address(
        seed: &Zeroizing<[u8; 32]>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        if seed.len() != 32 {
            return Err("Invalid EVM seed length".into());
        }

        let signing_key = K256SigningKey::from_bytes((&**seed).into())
            .map_err(|e| format!("Invalid secp256k1 key: {}", e))?;
        let verifying_key = signing_key.verifying_key();
        let public_key_point = verifying_key.to_encoded_point(false); // uncompressed
        let serialized_pk = public_key_point.as_bytes();

        // Skip the 0x04 prefix byte for Keccak hash
        let hash = Keccak256::digest(&serialized_pk[1..]);
        let address_bytes = &hash[12..];
        let raw_address = hex::encode(address_bytes);

        Ok(Self::to_checksum_address(&raw_address))
    }

    // Bitcoin Taproot address - mainnet
    pub fn derive_btc_taproot_address(
        corrected_sk_bytes: &Zeroizing<[u8; 32]>,
    ) -> Result<String, Box<dyn Error>> {
        Self::derive_btc_taproot_address_for_network(corrected_sk_bytes, false)
    }

    // Bitcoin Taproot address with network selection - native only (uses bitcoin crate)
    #[cfg(not(target_arch = "wasm32"))]
    pub fn derive_btc_taproot_address_for_network(
        corrected_sk_bytes: &Zeroizing<[u8; 32]>,
        testnet: bool,
    ) -> Result<String, Box<dyn Error>> {
        let secp = Secp256k1::new();

        let sk = SecretKey::from_slice(&**corrected_sk_bytes)?;

        let keypair = Keypair::from_secret_key(&secp, &sk);

        let (internal_key, _) = XOnlyPublicKey::from_keypair(&keypair);

        let network = if testnet {
            Network::Testnet
        } else {
            Network::Bitcoin
        };
        let address = Address::p2tr(&secp, internal_key, None, network);

        Ok(address.to_string())
    }

    // Bitcoin Taproot address with network selection - WASM fallback (simplified bech32m encoding)
    #[cfg(target_arch = "wasm32")]
    pub fn derive_btc_taproot_address_for_network(
        corrected_sk_bytes: &Zeroizing<[u8; 32]>,
        testnet: bool,
    ) -> Result<String, Box<dyn Error>> {
        use k256::ecdsa::SigningKey as EcdsaSigningKey;
        use k256::elliptic_curve::ops::Reduce;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
        use sha2::{Digest as Sha2Digest, Sha256};

        // Derive internal public key using k256
        let ecdsa_key = EcdsaSigningKey::from_bytes((&**corrected_sk_bytes).into())
            .map_err(|e| format!("Invalid secp256k1 key: {}", e))?;
        let pubkey_point = ecdsa_key.verifying_key().to_encoded_point(false);

        // Get internal x-only pubkey (32 bytes)
        let internal_x: [u8; 32] = pubkey_point.as_bytes()[1..33]
            .try_into()
            .map_err(|_| "Invalid public key length")?;

        // Apply BIP341 Taproot tweak: output_key = internal_key + tagged_hash("TapTweak", internal_x) * G
        // tagged_hash(tag, data) = SHA256(SHA256(tag) || SHA256(tag) || data)
        let tag_hash = Sha256::digest(b"TapTweak");
        let tweak_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&tag_hash);
            hasher.update(&tag_hash);
            hasher.update(&internal_x);
            let result = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&result);
            out
        };

        // tweak as scalar
        let tweak_scalar =
            <Scalar as Reduce<U256>>::reduce_bytes(&k256::FieldBytes::from_slice(&tweak_hash));

        // internal public key as a projective point
        let internal_pubkey = k256::PublicKey::from(ecdsa_key.verifying_key());
        let internal_affine = AffinePoint::from(&internal_pubkey);
        let internal_proj = ProjectivePoint::from(internal_affine);

        // output_point = internal_point + tweak * G
        let tweak_point = ProjectivePoint::GENERATOR * tweak_scalar;
        let output_point = internal_proj + tweak_point;

        // Convert to affine and extract x-coordinate
        let output_affine = output_point.to_affine();
        let output_encoded = output_affine.to_encoded_point(false);
        let x_only_bytes: [u8; 32] = output_encoded.as_bytes()[1..33]
            .try_into()
            .map_err(|_| "Invalid tweaked public key")?;

        let hrp = if testnet { "tb" } else { "bc" };

        // Encode as bech32m with witness version 1 (Taproot)
        let witness_program_5bit = Self::convert_bits_internal(&x_only_bytes, 8, 5, true)?;
        let mut data5 = vec![1u8]; // witness version 1 as raw 5-bit value
        data5.extend(witness_program_5bit);

        // Calculate bech32m checksum
        let checksum = Self::bech32m_create_checksum(hrp, &data5);
        data5.extend(checksum);

        // Encode to string
        const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let mut result = format!("{}1", hrp);
        for &d in &data5 {
            result.push(BECH32_CHARSET.chars().nth(d as usize).unwrap());
        }

        Ok(result)
    }

    #[cfg(target_arch = "wasm32")]
    fn convert_bits_internal(
        data: &[u8],
        from_bits: u32,
        to_bits: u32,
        pad: bool,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut ret: Vec<u8> = Vec::new();
        let maxv: u32 = (1 << to_bits) - 1;

        for &value in data {
            let value = value as u32;
            acc = (acc << from_bits) | value;
            bits += from_bits;
            while bits >= to_bits {
                bits -= to_bits;
                ret.push(((acc >> bits) & maxv) as u8);
            }
        }

        if pad && bits > 0 {
            ret.push(((acc << (to_bits - bits)) & maxv) as u8);
        }

        Ok(ret)
    }

    #[cfg(target_arch = "wasm32")]
    fn bech32m_create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
        let mut values = Self::bech32_hrp_expand_internal(hrp);
        values.extend(data);
        values.extend(vec![0u8; 6]);

        // bech32m uses constant 0x2bc830a3 instead of bech32's 1
        let polymod = Self::bech32_polymod_internal(&values) ^ 0x2bc830a3;

        (0..6)
            .map(|i| ((polymod >> (5 * (5 - i))) & 31) as u8)
            .collect()
    }

    #[cfg(target_arch = "wasm32")]
    fn bech32_hrp_expand_internal(hrp: &str) -> Vec<u8> {
        let mut ret: Vec<u8> = hrp.chars().map(|c| (c as u8) >> 5).collect();
        ret.push(0);
        ret.extend(hrp.chars().map(|c| (c as u8) & 31));
        ret
    }

    #[cfg(target_arch = "wasm32")]
    fn bech32_polymod_internal(values: &[u8]) -> u32 {
        let generator: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        let mut chk: u32 = 1;

        for &v in values {
            let top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
            for (i, &gen) in generator.iter().enumerate() {
                if (top >> i) & 1 == 1 {
                    chk ^= gen;
                }
            }
        }

        chk
    }

    pub fn derive_solana_address(
        seed: &Zeroizing<[u8; 32]>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        if seed.len() != 32 {
            return Err("Invalid Solana seed length: expected 32 bytes".into());
        }

        let signing_key = SigningKey::from_bytes(&**seed);

        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let address = bs58::encode(verifying_key.to_bytes()).into_string();

        Ok(address)
    }

    pub fn change_passphrase_internal(
        mnemonic_str: &str,
        old_passphrase: &str,
        new_passphrase: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<String, Box<dyn Error>> {
        let sealed = Self::decode_mnemonic_to_sealed(mnemonic_str).map_err(|e| {
            Box::new(CryptoError::InternalError(format!("{:?}", e))) as Box<dyn Error>
        })?;
        let old_full =
            PassphraseSealingUtil::combine_passphrase(old_passphrase, secondary_passphrase);
        let material =
            PassphraseSealingUtil::unseal_identity_material(&sealed, old_full.as_bytes()).map_err(
                |e| Box::new(CryptoError::InternalError(format!("{:?}", e))) as Box<dyn Error>,
            )?;

        let new_full =
            PassphraseSealingUtil::combine_passphrase(new_passphrase, secondary_passphrase);
        let resealed =
            PassphraseSealingUtil::seal_identity_material(&*material, new_full.as_bytes())
                .map_err(|e| {
                    Box::new(CryptoError::InternalError(format!("{:?}", e))) as Box<dyn Error>
                })?;
        Ok(Mnemonic::from_entropy(&resealed)?.to_string())
    }

    /// Change passphrase for wallets created WITHOUT secondary (e.g. extension via generate_wasm).
    /// Unseals with (existing_passphrase, None), seals with (new_passphrase, Some(admin_factor)).
    ///
    /// **Invariant: same root or fail.** The root secret is only decrypted and re-encrypted;
    /// no new randomness. So (newMnemonic, newPassphrase, admin_factor) must unseal to the **same**
    /// root → same addresses as wallet-1. Wrong (newPassphrase, admin_factor) → unseal fails.
    /// There is no code path that produces a different address set from the new mnemonic.
    pub fn change_passphrase_add_admin_internal(
        mnemonic_str: &str,
        existing_passphrase: &str,
        new_passphrase: &str,
        admin_factor: &str,
    ) -> Result<String, Box<dyn Error>> {
        let old_secondary: Option<&str> = None;
        let new_secondary: Option<&str> = if admin_factor.is_empty() {
            None
        } else {
            Some(admin_factor)
        };
        Self::change_passphrase_internal_mixed(
            mnemonic_str,
            existing_passphrase,
            new_passphrase,
            old_secondary,
            new_secondary,
        )
    }

    /// Unseal with (old_passphrase, old_secondary), re-seal same root with (new_passphrase, new_secondary).
    /// Returns new mnemonic encoding the same root; recovery must use (new_passphrase, new_secondary).
    fn change_passphrase_internal_mixed(
        mnemonic_str: &str,
        old_passphrase: &str,
        new_passphrase: &str,
        old_secondary: Option<&str>,
        new_secondary: Option<&str>,
    ) -> Result<String, Box<dyn Error>> {
        let sealed = Self::decode_mnemonic_to_sealed(mnemonic_str).map_err(|e| {
            Box::new(CryptoError::InternalError(format!("{:?}", e))) as Box<dyn Error>
        })?;
        let old_full = PassphraseSealingUtil::combine_passphrase(old_passphrase, old_secondary);
        let material =
            PassphraseSealingUtil::unseal_identity_material(&sealed, old_full.as_bytes()).map_err(
                |e| Box::new(CryptoError::InternalError(format!("{:?}", e))) as Box<dyn Error>,
            )?;
        let new_full = PassphraseSealingUtil::combine_passphrase(new_passphrase, new_secondary);
        let resealed =
            PassphraseSealingUtil::seal_identity_material(&*material, new_full.as_bytes())
                .map_err(|e| {
                    Box::new(CryptoError::InternalError(format!("{:?}", e))) as Box<dyn Error>
                })?;
        Ok(Mnemonic::from_entropy(&resealed)?.to_string())
    }

    /// Unseal mnemonic with a pre-derived base_key and return SchemeSeeds.
    /// This avoids running Argon2 again — the caller already has the base_key.
    /// Used by PRF-backed signing path where JS passes PRF key → WASM runs Argon2 once → reuses base_key.
    pub fn unseal_to_seeds(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<SchemeSeeds, AcegfError> {
        let sealed =
            Self::decode_mnemonic_to_sealed(mnemonic).map_err(|_| AcegfError::InvalidFormat)?;
        Self::derive_seeds_from_sealed_passphrase(&sealed, passphrase, secondary_passphrase)
    }

    pub fn unseal_to_seeds_with_base_key(
        mnemonic: &str,
        base_key: &[u8; 32],
    ) -> Result<SchemeSeeds, Box<dyn Error>> {
        let sealed = Self::decode_mnemonic_to_sealed(mnemonic)
            .map_err(|e| format!("Decode mnemonic failed: {:?}", e))?;
        let seeds = Self::derive_seeds_from_sealed_base_key(&sealed, base_key)?;
        Ok(seeds)
    }

    pub fn view_wallet_internal(
        mnemonic_input: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<CryptoEntity, AcegfError> {
        let sealed = Self::decode_mnemonic_to_sealed(mnemonic_input)
            .map_err(|_| AcegfError::InvalidFormat)?;
        let xid = Self::compute_xid(&sealed);
        let mut seeds =
            Self::derive_seeds_from_sealed_passphrase(&sealed, passphrase, secondary_passphrase)?;

        match Self::generate_crypto_entity(&mut seeds) {
            Ok(mut entity) => {
                entity.mnemonic = Zeroizing::new(mnemonic_input.to_string());
                entity.xid = xid;
                Ok(entity)
            }
            Err(e) => Err(e),
        }
    }

    /// View wallet using a pre-derived base_key (PRF path, skips Argon2)
    pub fn view_wallet_with_base_key(
        mnemonic_input: &str,
        base_key: &[u8; 32],
    ) -> Result<CryptoEntity, Box<dyn Error>> {
        let sealed = Self::decode_mnemonic_to_sealed(mnemonic_input)
            .map_err(|e| Box::new(e) as Box<dyn Error>)?;
        let xid = Self::compute_xid(&sealed);
        let mut seeds = Self::unseal_to_seeds_with_base_key(mnemonic_input, base_key)?;

        match Self::generate_crypto_entity(&mut seeds) {
            Ok(mut entity) => {
                entity.mnemonic = Zeroizing::new(mnemonic_input.to_string());
                entity.xid = xid;
                Ok(entity)
            }
            Err(e) => Err(Box::new(e) as Box<dyn Error>),
        }
    }

    fn derive_from_material16(material: &[u8; 16]) -> Result<SchemeSeeds, AcegfError> {
        let root_bytes = material;
        Ok(SchemeSeeds {
            ed25519_solana: Self::derive_ed25519_solana_seed_from_material16(root_bytes)?,
            ed25519_polkadot: Self::derive_ed25519_polkadot_seed_from_material16(root_bytes)?,
            secp256k1_evm: Self::derive_secp256k1_evm_seed_from_material16(root_bytes)?,
            secp256k1_btc: Self::derive_secp256k1_btc_seed_from_material16(root_bytes)?,
            secp256k1_cosmos: Self::derive_secp256k1_cosmos_seed_from_material16(root_bytes)?,
            secp256k1_tron: Self::derive_secp256k1_tron_seed_from_material16(root_bytes)?,
            x25519: Self::derive_x25519_seed_from_material16(root_bytes)?,
            ml_dsa_44: Self::derive_ml_dsa_seed_from_material16(root_bytes)?,
            ml_kem_768: Self::derive_ml_kem_seed_from_material16(root_bytes)?,
        })
    }

    // =========================================================================
    // REV32 / Context Derivation Helpers
    // =========================================================================

    /// Private helper: HKDF-SHA256 expand with optional context appended to info.
    ///
    /// When `context` is empty, output is identical to using `base_info` alone.
    /// When non-empty, context bytes are appended to
    /// the info label, producing a cryptographically independent output.
    fn hkdf_expand_with_context(
        ikm: &[u8],
        base_info: &[u8],
        context: &[u8],
        output: &mut [u8; 32],
    ) -> Result<(), AcegfError> {
        if context.is_empty() {
            Hkdf::<Sha256>::new(None, ikm)
                .expand(base_info, output)
                .map_err(|_| AcegfError::KdfError)
        } else {
            let mut info = base_info.to_vec();
            info.push(b':');
            info.extend_from_slice(context);
            Hkdf::<Sha256>::new(None, ikm)
                .expand(&info, output)
                .map_err(|_| AcegfError::KdfError)
        }
    }

    /// Build a canonical vault context string from an array of segments.
    ///
    /// Segments are sorted lexicographically and joined with `:`, ensuring
    /// deterministic output regardless of caller-supplied order.
    ///
    /// Returns an empty string when the input is empty
    /// (personal wallet — no context).
    ///
    /// # Examples
    /// ```
    /// use acegf::acegf_core::ACEGFCore;
    /// // Order doesn't matter — same segments always produce the same context
    /// let ctx1 = ACEGFCore::build_vault_context(&["OperatingFund", "corp-abc", "0"]);
    /// let ctx2 = ACEGFCore::build_vault_context(&["0", "corp-abc", "OperatingFund"]);
    /// assert_eq!(ctx1, ctx2); // "0:OperatingFund:corp-abc"
    /// ```
    pub fn build_vault_context(segments: &[&str]) -> String {
        if segments.is_empty() {
            return String::new();
        }
        let mut sorted: Vec<&str> = segments.to_vec();
        sorted.sort();
        sorted.join(":")
    }

    /// REV32 info strings for domain-separated derivation
    const ED25519_SOLANA_INFO_REV32: &'static [u8] = b"ACEGF-REV32-V1-ED25519-SOLANA";
    const ED25519_POLKADOT_INFO_REV32: &'static [u8] = b"ACEGF-REV32-V1-ED25519-POLKADOT";
    const SECP256K1_EVM_INFO_REV32: &'static [u8] = b"ACEGF-REV32-V1-SECP256K1-EVM";
    const SECP256K1_BTC_INFO_REV32: &'static [u8] = b"ACEGF-REV32-V1-SECP256K1-BTC";
    const SECP256K1_COSMOS_INFO_REV32: &'static [u8] = b"ACEGF-REV32-V1-SECP256K1-COSMOS";
    const SECP256K1_TRON_INFO_REV32: &'static [u8] = b"ACEGF-REV32-V1-SECP256K1-TRON";
    const X25519_INFO_REV32: &'static [u8] = b"ACEGF-REV32-V1-X25519-IDENTITY";
    const ML_DSA_INFO_REV32: &'static [u8] = b"ACEGF-REV32-V1-ML-DSA-44-PQC-IDENTITY";
    const ML_KEM_INFO_REV32: &'static [u8] = b"ACEGF-REV32-V1-ML-KEM-768-PQC-IDENTITY";
    /// AR-ACE Profile A: Ed25519 mempool relay attestation key (paper 11 §3.2).
    ///
    /// MUST stay in sync with `ace_runtime::crypto::contexts::HKDF_INFO_REV32_RELAY_ED25519`.
    const ED25519_RELAY_INFO_REV32: &'static [u8] = b"ACEGF-REV32-V1-ED25519-MEMPOOL-ATTEST";

    /// Derive scheme seeds from REV32 (32-byte root entropy) with optional vault context.
    ///
    /// This uses the identity root derived from (REV32 + password) for key derivation.
    /// The identity_root is computed as: HKDF(Kmaster, "acegf:identity:root")
    /// where Kmaster = Argon2id(password, salt_from_rev32)
    ///
    /// When `context` is empty, behavior is identical to the original `derive_from_rev32`.
    /// When non-empty, each chain's HKDF info label is extended with the context,
    /// producing cryptographically isolated keys per vault.
    pub fn derive_from_rev32_with_context(
        identity_root: &[u8; 32],
        context: &[u8],
    ) -> Result<SchemeSeeds, AcegfError> {
        Ok(SchemeSeeds {
            ed25519_solana: Self::derive_ed25519_solana_seed_from_rev32_with_context(
                identity_root,
                context,
            )?,
            ed25519_polkadot: Self::derive_ed25519_polkadot_seed_from_rev32_with_context(
                identity_root,
                context,
            )?,
            secp256k1_evm: Self::derive_secp256k1_evm_seed_from_rev32_with_context(
                identity_root,
                context,
            )?,
            secp256k1_btc: Self::derive_secp256k1_btc_seed_from_rev32_with_context(
                identity_root,
                context,
            )?,
            secp256k1_cosmos: Self::derive_secp256k1_cosmos_seed_from_rev32_with_context(
                identity_root,
                context,
            )?,
            secp256k1_tron: Self::derive_secp256k1_tron_seed_from_rev32_with_context(
                identity_root,
                context,
            )?,
            x25519: Self::derive_x25519_seed_from_rev32_with_context(identity_root, context)?,
            ml_dsa_44: Self::derive_ml_dsa_seed_from_rev32_with_context(identity_root, context)?,
            ml_kem_768: Self::derive_ml_kem_seed_from_rev32_with_context(identity_root, context)?,
        })
    }

    /// Original: now delegates to _with_context with empty context.
    pub fn derive_from_rev32(identity_root: &[u8; 32]) -> Result<SchemeSeeds, AcegfError> {
        Self::derive_from_rev32_with_context(identity_root, b"")
    }

    /// Unified view wallet entrypoint.
    ///
    /// Empty context → sealed/material16 path (standard wallet addresses).
    /// Non-empty context → REV32 path: sealed bytes used as per-wallet salt for Argon2,
    /// then identity_root → context-isolated seeds. Mirrors the signing path in evm_signer
    /// and solana_signer so view and sign always produce consistent addresses.
    pub fn view_wallet_unified_with_context(
        mnemonic_input: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        context_info: &str,
    ) -> Result<CryptoEntity, AcegfError> {
        if context_info.is_empty() {
            return Self::view_wallet_internal(mnemonic_input, passphrase, secondary_passphrase);
        }

        let sealed = Self::decode_mnemonic_to_sealed(mnemonic_input)
            .map_err(|_| AcegfError::InvalidFormat)?;
        let xid = Self::compute_xid(&sealed);
        let full_passphrase =
            PassphraseSealingUtil::combine_passphrase(passphrase, secondary_passphrase);
        let kmaster =
            PassphraseSealingUtil::derive_kmaster_from_rev32(full_passphrase.as_bytes(), &sealed)?;
        let identity_root = PassphraseSealingUtil::derive_identity_root(&kmaster)?;
        let mut seeds =
            Self::derive_from_rev32_with_context(&identity_root, context_info.as_bytes())?;

        match Self::generate_crypto_entity(&mut seeds) {
            Ok(mut entity) => {
                entity.mnemonic = Zeroizing::new(mnemonic_input.to_string());
                entity.xid = xid;
                Ok(entity)
            }
            Err(e) => Err(e),
        }
    }

    pub fn view_wallet_unified(
        mnemonic_input: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<CryptoEntity, AcegfError> {
        Self::view_wallet_internal(mnemonic_input, passphrase, secondary_passphrase)
    }

    // =========================================================================
    // REV32 Seed Derivation Functions
    // =========================================================================

    // --- Ed25519 Solana ---

    pub fn derive_ed25519_solana_seed_from_rev32_with_context(
        identity_root: &[u8; 32],
        context: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut ed = [0u8; 32];
        Self::hkdf_expand_with_context(
            identity_root,
            Self::ED25519_SOLANA_INFO_REV32,
            context,
            &mut ed,
        )?;
        Ok(Zeroizing::new(ed))
    }

    pub fn derive_ed25519_solana_seed_from_rev32(
        identity_root: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        Self::derive_ed25519_solana_seed_from_rev32_with_context(identity_root, b"")
    }

    // --- Ed25519 Polkadot ---

    pub fn derive_ed25519_polkadot_seed_from_rev32_with_context(
        identity_root: &[u8; 32],
        context: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut ed = [0u8; 32];
        Self::hkdf_expand_with_context(
            identity_root,
            Self::ED25519_POLKADOT_INFO_REV32,
            context,
            &mut ed,
        )?;
        Ok(Zeroizing::new(ed))
    }

    pub fn derive_ed25519_polkadot_seed_from_rev32(
        identity_root: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        Self::derive_ed25519_polkadot_seed_from_rev32_with_context(identity_root, b"")
    }

    // --- AR-ACE Profile A: Ed25519 mempool relay key (Ctx_relay) ---

    /// Derive the Ed25519 mempool relay attestation seed from REV32 identity root.
    ///
    /// AR-ACE Profile A (paper 11 §3.2): the relay key is cryptographically
    /// isolated from the on-chain authorization key (`derive_ml_dsa_seed_from_rev32`)
    /// via the distinct HKDF info string [`Self::ED25519_RELAY_INFO_REV32`].
    ///
    /// Compromise of this relay key allows mempool spam (subject to per-idcom
    /// rate-limits enforced in PR2) but cannot forge inclusion-eligible txs:
    /// the builder still verifies the auth credential at block inclusion time.
    pub fn derive_ed25519_relay_seed_from_rev32_with_context(
        identity_root: &[u8; 32],
        context: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut ed = [0u8; 32];
        Self::hkdf_expand_with_context(
            identity_root,
            Self::ED25519_RELAY_INFO_REV32,
            context,
            &mut ed,
        )?;
        Ok(Zeroizing::new(ed))
    }

    /// Convenience wrapper: derive relay seed with empty context (personal wallet).
    pub fn derive_ed25519_relay_seed_from_rev32(
        identity_root: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        Self::derive_ed25519_relay_seed_from_rev32_with_context(identity_root, b"")
    }

    // --- Secp256k1 EVM ---

    pub fn derive_secp256k1_evm_seed_from_rev32_with_context(
        identity_root: &[u8; 32],
        context: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut secp_raw = [0u8; 32];
        Self::hkdf_expand_with_context(
            identity_root,
            Self::SECP256K1_EVM_INFO_REV32,
            context,
            &mut secp_raw,
        )?;
        let secp = Self::normalize_secp256k1_key(&secp_raw);
        Ok(Zeroizing::new(secp))
    }

    pub fn derive_secp256k1_evm_seed_from_rev32(
        identity_root: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        Self::derive_secp256k1_evm_seed_from_rev32_with_context(identity_root, b"")
    }

    // --- Secp256k1 BTC ---

    pub fn derive_secp256k1_btc_seed_from_rev32_with_context(
        identity_root: &[u8; 32],
        context: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut secp_raw = [0u8; 32];
        Self::hkdf_expand_with_context(
            identity_root,
            Self::SECP256K1_BTC_INFO_REV32,
            context,
            &mut secp_raw,
        )?;
        let secp = Self::normalize_secp256k1_key(&secp_raw);
        Ok(Zeroizing::new(secp))
    }

    pub fn derive_secp256k1_btc_seed_from_rev32(
        identity_root: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        Self::derive_secp256k1_btc_seed_from_rev32_with_context(identity_root, b"")
    }

    // --- Secp256k1 Cosmos ---

    pub fn derive_secp256k1_cosmos_seed_from_rev32_with_context(
        identity_root: &[u8; 32],
        context: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut secp_raw = [0u8; 32];
        Self::hkdf_expand_with_context(
            identity_root,
            Self::SECP256K1_COSMOS_INFO_REV32,
            context,
            &mut secp_raw,
        )?;
        let secp = Self::normalize_secp256k1_key(&secp_raw);
        Ok(Zeroizing::new(secp))
    }

    pub fn derive_secp256k1_cosmos_seed_from_rev32(
        identity_root: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        Self::derive_secp256k1_cosmos_seed_from_rev32_with_context(identity_root, b"")
    }

    // --- Secp256k1 Tron ---

    pub fn derive_secp256k1_tron_seed_from_rev32_with_context(
        identity_root: &[u8; 32],
        context: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut secp_raw = [0u8; 32];
        Self::hkdf_expand_with_context(
            identity_root,
            Self::SECP256K1_TRON_INFO_REV32,
            context,
            &mut secp_raw,
        )?;
        let secp = Self::normalize_secp256k1_key(&secp_raw);
        Ok(Zeroizing::new(secp))
    }

    pub fn derive_secp256k1_tron_seed_from_rev32(
        identity_root: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        Self::derive_secp256k1_tron_seed_from_rev32_with_context(identity_root, b"")
    }

    // --- X25519 ---

    pub fn derive_x25519_seed_from_rev32_with_context(
        identity_root: &[u8; 32],
        context: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut x = [0u8; 32];
        Self::hkdf_expand_with_context(identity_root, Self::X25519_INFO_REV32, context, &mut x)?;
        // X25519 key clamping (RFC 7748)
        x[0] &= 248;
        x[31] &= 127;
        x[31] |= 64;
        Ok(Zeroizing::new(x))
    }

    pub fn derive_x25519_seed_from_rev32(
        identity_root: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        Self::derive_x25519_seed_from_rev32_with_context(identity_root, b"")
    }

    // --- ML-DSA-44 (PQC) ---

    pub fn derive_ml_dsa_seed_from_rev32_with_context(
        identity_root: &[u8; 32],
        context: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut ml_dsa = [0u8; 32];
        Self::hkdf_expand_with_context(
            identity_root,
            Self::ML_DSA_INFO_REV32,
            context,
            &mut ml_dsa,
        )?;
        Ok(Zeroizing::new(ml_dsa))
    }

    pub fn derive_ml_dsa_seed_from_rev32(
        identity_root: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        Self::derive_ml_dsa_seed_from_rev32_with_context(identity_root, b"")
    }

    // --- ML-KEM-768 (PQC KEM — quantum-resistant key exchange) ---
    //
    // ML-KEM-768 consumes a 64-byte seed (`d || z`, per FIPS 203 §7.1).
    // We expand 64 bytes of HKDF output in one shot using a 64-byte buffer
    // so `d` and `z` come from a single cryptographically independent
    // stream bound to the ML-KEM domain label.

    pub fn derive_ml_kem_seed_from_rev32_with_context(
        identity_root: &[u8; 32],
        context: &[u8],
    ) -> Result<Zeroizing<[u8; 64]>, AcegfError> {
        let mut out = [0u8; 64];
        if context.is_empty() {
            Hkdf::<Sha256>::new(None, identity_root)
                .expand(Self::ML_KEM_INFO_REV32, &mut out)
                .map_err(|_| AcegfError::KdfError)?;
        } else {
            let mut info = Self::ML_KEM_INFO_REV32.to_vec();
            info.push(b':');
            info.extend_from_slice(context);
            Hkdf::<Sha256>::new(None, identity_root)
                .expand(&info, &mut out)
                .map_err(|_| AcegfError::KdfError)?;
        }
        Ok(Zeroizing::new(out))
    }

    pub fn derive_ml_kem_seed_from_rev32(
        identity_root: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 64]>, AcegfError> {
        Self::derive_ml_kem_seed_from_rev32_with_context(identity_root, b"")
    }

    // =========================================================================
    // Sealed Artifact Derivation (credential-bound unseal -> 16-byte identity material)
    // =========================================================================

    fn derive_ed25519_solana_seed_from_material16(
        material: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut ed = [0u8; 32];
        Hkdf::<Sha256>::new(None, material)
            .expand(Self::ED25519_SOLANA_INFO_SEALED, &mut ed)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(ed))
    }

    fn derive_secp256k1_btc_seed_from_material16(
        material: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut secp_raw = [0u8; 32];
        Hkdf::<Sha256>::new(None, material)
            .expand(Self::SECP256K1_BTC_INFO_SEALED, &mut secp_raw)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(Self::normalize_secp256k1_key(&secp_raw)))
    }

    fn derive_ed25519_polkadot_seed_from_material16(
        material: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut ed = [0u8; 32];
        Hkdf::<Sha256>::new(None, material)
            .expand(Self::ED25519_POLKADOT_INFO_SEALED, &mut ed)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(ed))
    }

    fn derive_secp256k1_evm_seed_from_material16(
        material: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut secp_raw = [0u8; 32];
        Hkdf::<Sha256>::new(None, material)
            .expand(Self::SECP256K1_EVM_INFO_SEALED, &mut secp_raw)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(Self::normalize_secp256k1_key(&secp_raw)))
    }

    fn derive_secp256k1_cosmos_seed_from_material16(
        material: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut secp_raw = [0u8; 32];
        Hkdf::<Sha256>::new(None, material)
            .expand(Self::SECP256K1_COSMOS_INFO_SEALED, &mut secp_raw)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(Self::normalize_secp256k1_key(&secp_raw)))
    }

    fn derive_secp256k1_tron_seed_from_material16(
        material: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut secp_raw = [0u8; 32];
        Hkdf::<Sha256>::new(None, material)
            .expand(Self::SECP256K1_TRON_INFO_SEALED, &mut secp_raw)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(Self::normalize_secp256k1_key(&secp_raw)))
    }

    fn derive_x25519_seed_from_material16(
        material: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut x = [0u8; 32];
        Hkdf::<Sha256>::new(None, material)
            .expand(Self::X25519_INFO_SEALED, &mut x)
            .map_err(|_| AcegfError::KdfError)?;
        x[0] &= 248;
        x[31] &= 127;
        x[31] |= 64;
        Ok(Zeroizing::new(x))
    }

    fn derive_ml_dsa_seed_from_material16(
        material: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut ml_dsa = [0u8; 32];
        Hkdf::<Sha256>::new(None, material)
            .expand(Self::ML_DSA_INFO_SEALED, &mut ml_dsa)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(ml_dsa))
    }

    fn derive_ml_kem_seed_from_material16(
        material: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 64]>, AcegfError> {
        let mut ml_kem = [0u8; 64];
        Hkdf::<Sha256>::new(None, material)
            .expand(Self::ML_KEM_INFO_SEALED, &mut ml_kem)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(ml_kem))
    }

    pub fn clear_scheme_seeds(seeds: &mut SchemeSeeds) {
        seeds.ed25519_solana.zeroize();
        seeds.secp256k1_evm.zeroize();
        seeds.secp256k1_btc.zeroize();
        seeds.secp256k1_cosmos.zeroize();
        seeds.secp256k1_tron.zeroize();
        seeds.ed25519_polkadot.zeroize();
        seeds.x25519.zeroize();
        seeds.ml_dsa_44.zeroize();
        seeds.ml_kem_768.zeroize();
    }

    pub fn decode_mnemonic_to_sealed(mnemonic_str: &str) -> Result<[u8; 32], MnemonicSealError> {
        let mnemonic = bip39::Mnemonic::parse_in(Language::English, mnemonic_str.trim())
            .map_err(|_| MnemonicSealError::InvalidFormat)?;

        let entropy = mnemonic.to_entropy();

        let sealed_bytes: [u8; 32] = entropy
            .try_into()
            .map_err(|_| MnemonicSealError::InvalidEntropy)?;

        Ok(sealed_bytes)
    }

    // Normalize secp256k1 key to be within valid range
    pub fn normalize_secp256k1_key(raw: &[u8; 32]) -> [u8; 32] {
        // Try to create a k256 SigningKey to validate the scalar
        match K256SigningKey::from_bytes(raw.into()) {
            Ok(_) => *raw,
            Err(_) => {
                // If invalid, hash it to get a valid scalar
                use sha2::Digest;
                let hash = sha2::Sha256::digest(raw);
                let mut out = [0u8; 32];
                out.copy_from_slice(&hash);
                out
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_checksum_address() {
        // Test EIP-55 checksum address conversion
        let addr = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        let checksum = ACEGFCore::to_checksum_address(addr);
        assert!(checksum.starts_with("0x"));
        assert_eq!(checksum.len(), 42);

        // Verify mixed case in output
        let has_upper = checksum.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = checksum[2..].chars().any(|c| c.is_ascii_lowercase());
        assert!(has_upper || has_lower); // Checksum should have mixed case

        // Without 0x prefix should also work
        let addr_no_prefix = "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        let checksum2 = ACEGFCore::to_checksum_address(addr_no_prefix);
        assert!(checksum2.starts_with("0x"));
    }

    #[test]
    fn test_derive_x25519_public() {
        let seed = Zeroizing::new([42u8; 32]);
        let result = ACEGFCore::derive_x25519_public(&seed);
        assert!(result.is_ok());

        let pubkey_b64 = result.unwrap();
        // X25519 public key should be 32 bytes, base64 encoded (~44 chars)
        assert!(!pubkey_b64.is_empty());
        assert!(pubkey_b64.len() > 40);
    }

    #[test]
    fn test_derive_solana_address() {
        let seed = Zeroizing::new([1u8; 32]);
        let result = ACEGFCore::derive_solana_address(&seed);
        assert!(result.is_ok());

        let address = result.unwrap();
        // Solana address is base58 encoded 32-byte public key
        assert!(!address.is_empty());
        // Should be around 32-44 characters in base58
        assert!(address.len() >= 32 && address.len() <= 50);
    }

    #[test]
    fn test_derive_evm_address() {
        let seed = Zeroizing::new([1u8; 32]);
        let result = ACEGFCore::derive_evm_address(&seed);
        assert!(result.is_ok());

        let address = result.unwrap();
        // EVM address should be checksummed hex with 0x prefix
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_derive_cosmos_address() {
        let seed = Zeroizing::new([1u8; 32]);
        let result = ACEGFCore::derive_cosmos_address(&seed);
        assert!(result.is_ok());

        let address = result.unwrap();
        // Cosmos address should start with "cosmos1"
        assert!(address.starts_with("cosmos1"));
    }

    #[test]
    fn test_derive_polkadot_address() {
        let seed = Zeroizing::new([1u8; 32]);
        let result = ACEGFCore::derive_polkadot_address(&seed);
        assert!(result.is_ok());

        let address = result.unwrap();
        // Polkadot address is SS58 encoded, typically starts with 1
        assert!(!address.is_empty());
        assert!(address.len() > 40);
    }

    #[test]
    fn test_derive_btc_taproot_address() {
        let seed = Zeroizing::new([1u8; 32]);
        let result = ACEGFCore::derive_btc_taproot_address(&seed);
        assert!(result.is_ok());

        let address = result.unwrap();
        // Taproot address should start with "bc1p"
        assert!(address.starts_with("bc1p") || address.starts_with("bc1"));
    }

    #[test]
    fn test_derive_btc_taproot_address_testnet() {
        let seed = Zeroizing::new([1u8; 32]);

        // Mainnet
        let mainnet = ACEGFCore::derive_btc_taproot_address_for_network(&seed, false).unwrap();
        assert!(mainnet.starts_with("bc1p"));

        // Testnet
        let testnet = ACEGFCore::derive_btc_taproot_address_for_network(&seed, true).unwrap();
        assert!(testnet.starts_with("tb1p"));

        // Same key, different prefix, same witness program
        assert_ne!(mainnet, testnet);
    }

    #[test]
    fn test_derive_from_rev32() {
        let identity_root = [0x11u8; 32];
        let result = ACEGFCore::derive_from_rev32(&identity_root);
        assert!(result.is_ok());

        let seeds = result.unwrap();
        // All classical seeds are 32 bytes; ML-KEM-768 uses a 64-byte seed
        // (d || z per FIPS 203).
        assert_eq!(seeds.ed25519_solana.len(), 32);
        assert_eq!(seeds.secp256k1_evm.len(), 32);
        assert_eq!(seeds.secp256k1_btc.len(), 32);
        assert_eq!(seeds.secp256k1_cosmos.len(), 32);
        assert_eq!(seeds.ed25519_polkadot.len(), 32);
        assert_eq!(seeds.x25519.len(), 32);
        assert_eq!(seeds.ml_dsa_44.len(), 32);
        assert_eq!(seeds.ml_kem_768.len(), 64);
    }

    #[test]
    fn test_derive_from_rev32_deterministic() {
        let identity_root: [u8; 32] = [0x55; 32];

        let seeds1 = ACEGFCore::derive_from_rev32(&identity_root).unwrap();
        let seeds2 = ACEGFCore::derive_from_rev32(&identity_root).unwrap();

        // Same root should produce same seeds
        assert_eq!(*seeds1.ed25519_solana, *seeds2.ed25519_solana);
        assert_eq!(*seeds1.secp256k1_evm, *seeds2.secp256k1_evm);
    }

    #[test]
    fn test_normalize_secp256k1_key_valid() {
        // Valid key should be unchanged
        let valid_key = [1u8; 32];
        let normalized = ACEGFCore::normalize_secp256k1_key(&valid_key);
        assert_eq!(normalized, valid_key);
    }

    #[test]
    fn test_normalize_secp256k1_key_invalid() {
        // All zeros is invalid for secp256k1
        let invalid_key = [0u8; 32];
        let normalized = ACEGFCore::normalize_secp256k1_key(&invalid_key);
        // Should be hashed to get a valid key
        assert_ne!(normalized, invalid_key);
        // The result should be a valid scalar
        assert!(K256SigningKey::from_bytes((&normalized).into()).is_ok());
    }

    #[test]
    fn test_decode_mnemonic_to_sealed_valid() {
        let result = ACEGFCore::decode_mnemonic_to_sealed(crate::test_vectors::BIP39_ZERO_ENTROPY_MNEMONIC);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_decode_mnemonic_to_sealed_invalid() {
        let invalid = "not a valid mnemonic phrase";
        let result = ACEGFCore::decode_mnemonic_to_sealed(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_clear_scheme_seeds() {
        let identity_root = [0x22u8; 32];
        let mut seeds = ACEGFCore::derive_from_rev32(&identity_root).unwrap();

        // Store original values
        let original_sol = *seeds.ed25519_solana;

        // Clear seeds
        ACEGFCore::clear_scheme_seeds(&mut seeds);

        // After clearing, seeds should be zeroed
        assert_eq!(*seeds.ed25519_solana, [0u8; 32]);
        assert_eq!(*seeds.secp256k1_evm, [0u8; 32]);
        assert_ne!(original_sol, [0u8; 32]); // Original was not zero
    }

    #[test]
    fn test_pqc_not_available_message() {
        // Verify the constant is defined
        assert!(!ACEGFCore::PQC_NOT_AVAILABLE_MESSAGE.is_empty());
        assert!(ACEGFCore::PQC_NOT_AVAILABLE_MESSAGE.contains("Yallet"));
    }

    #[test]
    fn test_ml_kem_seed_is_isolated_from_ml_dsa() {
        // Even though both PQC streams are derived from the same identity_root,
        // their HKDF info labels differ so their seeds must not collide with
        // each other nor with any classical-curve seed.
        let identity_root = [0x77u8; 32];
        let seeds = ACEGFCore::derive_from_rev32(&identity_root).unwrap();

        let kem_prefix = &seeds.ml_kem_768[0..32];
        assert_ne!(kem_prefix, &*seeds.ml_dsa_44);
        assert_ne!(kem_prefix, &*seeds.ed25519_solana);
        assert_ne!(kem_prefix, &*seeds.x25519);

        // The second 32-byte half (z) must also differ from the first (d).
        assert_ne!(&seeds.ml_kem_768[0..32], &seeds.ml_kem_768[32..64]);
    }

    #[test]
    fn test_ml_kem_end_to_end_from_identity_root() {
        // Round-trip: derive KEM seed → keygen → encaps/decaps → same secret.
        use crate::pqclean_ffi::MlKem768;

        let identity_root = [0xC3u8; 32];
        let seeds = ACEGFCore::derive_from_rev32(&identity_root).unwrap();
        let (ek, dk) = MlKem768::keypair_from_seed(&seeds.ml_kem_768).unwrap();

        let (ss_sender, ct) = MlKem768::encapsulate(&ek).unwrap();
        let ss_receiver = MlKem768::decapsulate(&dk, &ct).unwrap();
        assert_eq!(&*ss_sender, &*ss_receiver);
    }

    #[test]
    fn test_ml_kem_seed_context_isolation() {
        // Different vault contexts must yield different ML-KEM seeds
        // (i.e. the context label flows into the HKDF info for ML-KEM too).
        let identity_root = [0x42u8; 32];

        let seed_personal =
            ACEGFCore::derive_ml_kem_seed_from_rev32_with_context(&identity_root, b"").unwrap();
        let seed_vault =
            ACEGFCore::derive_ml_kem_seed_from_rev32_with_context(&identity_root, b"vault-a:0")
                .unwrap();
        assert_ne!(*seed_personal, *seed_vault);
    }

    // =========================================================================
    // Context Isolation Tests
    // =========================================================================

    #[test]
    fn test_hkdf_expand_with_context_empty_matches_original() {
        let identity_root = [42u8; 32];

        // With empty context should match original
        let with_empty =
            ACEGFCore::derive_ed25519_solana_seed_from_rev32_with_context(&identity_root, b"")
                .unwrap();
        let original = ACEGFCore::derive_ed25519_solana_seed_from_rev32(&identity_root).unwrap();
        assert_eq!(*with_empty, *original);
    }

    #[test]
    fn test_hkdf_expand_with_context_all_chains_empty_matches_original() {
        let identity_root = [42u8; 32];

        let seeds_ctx = ACEGFCore::derive_from_rev32_with_context(&identity_root, b"").unwrap();
        let seeds_orig = ACEGFCore::derive_from_rev32(&identity_root).unwrap();

        assert_eq!(*seeds_ctx.ed25519_solana, *seeds_orig.ed25519_solana);
        assert_eq!(*seeds_ctx.ed25519_polkadot, *seeds_orig.ed25519_polkadot);
        assert_eq!(*seeds_ctx.secp256k1_evm, *seeds_orig.secp256k1_evm);
        assert_eq!(*seeds_ctx.secp256k1_btc, *seeds_orig.secp256k1_btc);
        assert_eq!(*seeds_ctx.secp256k1_cosmos, *seeds_orig.secp256k1_cosmos);
        assert_eq!(*seeds_ctx.x25519, *seeds_orig.x25519);
        assert_eq!(*seeds_ctx.ml_dsa_44, *seeds_orig.ml_dsa_44);
        assert_eq!(*seeds_ctx.ml_kem_768, *seeds_orig.ml_kem_768);
    }

    #[test]
    fn test_context_produces_different_seeds() {
        let identity_root = [42u8; 32];

        let seeds_personal =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, b"").unwrap();
        let seeds_vault0 =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, b"corp-abc:OperatingFund:0")
                .unwrap();

        // Every chain must differ
        assert_ne!(*seeds_personal.ed25519_solana, *seeds_vault0.ed25519_solana);
        assert_ne!(*seeds_personal.secp256k1_evm, *seeds_vault0.secp256k1_evm);
        assert_ne!(*seeds_personal.secp256k1_btc, *seeds_vault0.secp256k1_btc);
        assert_ne!(
            *seeds_personal.secp256k1_cosmos,
            *seeds_vault0.secp256k1_cosmos
        );
        assert_ne!(
            *seeds_personal.ed25519_polkadot,
            *seeds_vault0.ed25519_polkadot
        );
        assert_ne!(*seeds_personal.x25519, *seeds_vault0.x25519);
        assert_ne!(*seeds_personal.ml_dsa_44, *seeds_vault0.ml_dsa_44);
        assert_ne!(*seeds_personal.ml_kem_768, *seeds_vault0.ml_kem_768);
    }

    #[test]
    fn test_different_contexts_produce_different_seeds() {
        let identity_root = [42u8; 32];

        let seeds_vault0 =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, b"corp-abc:OperatingFund:0")
                .unwrap();
        let seeds_vault1 =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, b"corp-abc:MnAEscrow:0")
                .unwrap();
        let seeds_vault2 =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, b"corp-xyz:OperatingFund:0")
                .unwrap();

        // All three must differ from each other
        assert_ne!(*seeds_vault0.ed25519_solana, *seeds_vault1.ed25519_solana);
        assert_ne!(*seeds_vault0.ed25519_solana, *seeds_vault2.ed25519_solana);
        assert_ne!(*seeds_vault1.ed25519_solana, *seeds_vault2.ed25519_solana);

        assert_ne!(*seeds_vault0.secp256k1_evm, *seeds_vault1.secp256k1_evm);
        assert_ne!(*seeds_vault0.secp256k1_btc, *seeds_vault1.secp256k1_btc);
    }

    #[test]
    fn test_context_is_deterministic() {
        let identity_root = [42u8; 32];
        let ctx = b"corp-abc:OperatingFund:0";

        let seeds1 = ACEGFCore::derive_from_rev32_with_context(&identity_root, ctx).unwrap();
        let seeds2 = ACEGFCore::derive_from_rev32_with_context(&identity_root, ctx).unwrap();

        assert_eq!(*seeds1.ed25519_solana, *seeds2.ed25519_solana);
        assert_eq!(*seeds1.secp256k1_evm, *seeds2.secp256k1_evm);
        assert_eq!(*seeds1.secp256k1_btc, *seeds2.secp256k1_btc);
        assert_eq!(*seeds1.x25519, *seeds2.x25519);
    }

    #[test]
    fn test_context_secp256k1_keys_are_valid() {
        let identity_root = [42u8; 32];
        let ctx = b"corp-abc:OperatingFund:0";

        let seeds = ACEGFCore::derive_from_rev32_with_context(&identity_root, ctx).unwrap();

        // secp256k1 seeds must be valid scalars (normalize_secp256k1_key ensures this)
        assert!(K256SigningKey::from_bytes((&*seeds.secp256k1_evm).into()).is_ok());
        assert!(K256SigningKey::from_bytes((&*seeds.secp256k1_btc).into()).is_ok());
        assert!(K256SigningKey::from_bytes((&*seeds.secp256k1_cosmos).into()).is_ok());
    }

    #[test]
    fn test_context_x25519_key_is_clamped() {
        let identity_root = [42u8; 32];
        let ctx = b"corp-abc:OperatingFund:0";

        let seeds = ACEGFCore::derive_from_rev32_with_context(&identity_root, ctx).unwrap();

        // X25519 clamping: low 3 bits of byte 0 cleared, high bit of byte 31 cleared, bit 6 set
        assert_eq!(seeds.x25519[0] & 0x07, 0, "low 3 bits must be 0");
        assert_eq!(seeds.x25519[31] & 0x80, 0, "high bit must be 0");
        assert_eq!(seeds.x25519[31] & 0x40, 0x40, "bit 6 must be set");
    }

    #[test]
    fn test_context_addresses_differ() {
        let identity_root = [42u8; 32];

        let mut seeds_personal =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, b"").unwrap();
        let mut seeds_vault =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, b"corp-abc:OperatingFund:0")
                .unwrap();

        let entity_personal = ACEGFCore::generate_crypto_entity(&mut seeds_personal).unwrap();
        let entity_vault = ACEGFCore::generate_crypto_entity(&mut seeds_vault).unwrap();

        // All addresses must differ
        assert_ne!(entity_personal.solana_address, entity_vault.solana_address);
        assert_ne!(entity_personal.evm_address, entity_vault.evm_address);
        assert_ne!(
            entity_personal.bitcoin_address,
            entity_vault.bitcoin_address
        );
        assert_ne!(entity_personal.cosmos_address, entity_vault.cosmos_address);
        assert_ne!(
            entity_personal.polkadot_address,
            entity_vault.polkadot_address
        );
        assert_ne!(entity_personal.x25519, entity_vault.x25519);
    }

    // --- view_wallet tests (require full wallet generation) ---

    #[test]
    fn test_view_wallet_unified_with_context_rejects_non_empty() {
        let passphrase = "test_password_ctx";
        let entity_orig = ACEGFCore::generate_ace_internal(passphrase, None).unwrap();
        let mnemonic = &entity_orig.mnemonic;

        let ok =
            ACEGFCore::view_wallet_unified_with_context(mnemonic, passphrase, None, "").unwrap();
        assert!(!ok.solana_address.is_empty());

        // Non-empty context should succeed and return context-isolated addresses
        // that differ from the default (empty-context) addresses.
        let ctx_entity = ACEGFCore::view_wallet_unified_with_context(
            mnemonic,
            passphrase,
            None,
            "corp-abc:OperatingFund:0",
        )
        .unwrap();
        assert!(!ctx_entity.solana_address.is_empty());
        assert_ne!(ok.solana_address, ctx_entity.solana_address);
        assert_ne!(ok.evm_address, ctx_entity.evm_address);
    }

    #[test]
    fn test_view_wallet_unified_roundtrip() {
        let passphrase = "test_password_unified";
        let entity_orig = ACEGFCore::generate_ace_internal(passphrase, None).unwrap();
        let mnemonic = &entity_orig.mnemonic;

        let restored = ACEGFCore::view_wallet_unified(mnemonic, passphrase, None).unwrap();
        assert_eq!(entity_orig.solana_address, restored.solana_address);
        assert_eq!(entity_orig.evm_address, restored.evm_address);
        assert_eq!(entity_orig.bitcoin_address, restored.bitcoin_address);
    }

    // =========================================================================
    // build_vault_context Tests
    // =========================================================================

    #[test]
    fn test_build_vault_context_empty() {
        let ctx = ACEGFCore::build_vault_context(&[]);
        assert_eq!(ctx, "");
    }

    #[test]
    fn test_build_vault_context_single_segment() {
        let ctx = ACEGFCore::build_vault_context(&["corp-abc"]);
        assert_eq!(ctx, "corp-abc");
    }

    #[test]
    fn test_build_vault_context_sorted_output() {
        let ctx = ACEGFCore::build_vault_context(&["OperatingFund", "corp-abc", "0"]);
        assert_eq!(ctx, "0:OperatingFund:corp-abc");
    }

    #[test]
    fn test_build_vault_context_order_independent() {
        let ctx1 = ACEGFCore::build_vault_context(&["OperatingFund", "corp-abc", "0"]);
        let ctx2 = ACEGFCore::build_vault_context(&["0", "corp-abc", "OperatingFund"]);
        let ctx3 = ACEGFCore::build_vault_context(&["corp-abc", "0", "OperatingFund"]);
        assert_eq!(ctx1, ctx2);
        assert_eq!(ctx2, ctx3);
    }

    #[test]
    fn test_build_vault_context_produces_deterministic_keys() {
        let identity_root = [42u8; 32];

        // Same segments, different order → same context → same keys
        let ctx1 = ACEGFCore::build_vault_context(&["OperatingFund", "corp-abc", "0"]);
        let ctx2 = ACEGFCore::build_vault_context(&["0", "corp-abc", "OperatingFund"]);

        let seeds1 =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, ctx1.as_bytes()).unwrap();
        let seeds2 =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, ctx2.as_bytes()).unwrap();

        assert_eq!(*seeds1.ed25519_solana, *seeds2.ed25519_solana);
        assert_eq!(*seeds1.secp256k1_evm, *seeds2.secp256k1_evm);
    }

    #[test]
    fn test_build_vault_context_different_segments_differ() {
        let identity_root = [42u8; 32];

        let ctx_ops = ACEGFCore::build_vault_context(&["corp-abc", "OperatingFund", "0"]);
        let ctx_escrow = ACEGFCore::build_vault_context(&["corp-abc", "MnAEscrow", "0"]);

        let seeds_ops =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, ctx_ops.as_bytes()).unwrap();
        let seeds_escrow =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, ctx_escrow.as_bytes())
                .unwrap();

        assert_ne!(*seeds_ops.ed25519_solana, *seeds_escrow.ed25519_solana);
        assert_ne!(*seeds_ops.secp256k1_evm, *seeds_escrow.secp256k1_evm);
    }

    #[test]
    fn test_build_vault_context_extensible_dimensions() {
        // Can freely add more dimensions without breaking anything
        let ctx_3d = ACEGFCore::build_vault_context(&["corp-abc", "OperatingFund", "0"]);
        let ctx_5d = ACEGFCore::build_vault_context(&[
            "corp-abc",
            "OperatingFund",
            "0",
            "co-signer-1",
            "2025Q1",
        ]);

        // More dimensions → different context → different keys
        assert_ne!(ctx_3d, ctx_5d);

        let identity_root = [42u8; 32];
        let seeds_3d =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, ctx_3d.as_bytes()).unwrap();
        let seeds_5d =
            ACEGFCore::derive_from_rev32_with_context(&identity_root, ctx_5d.as_bytes()).unwrap();

        assert_ne!(*seeds_3d.ed25519_solana, *seeds_5d.ed25519_solana);
    }
}

    #[test]
    fn test_view_specific_wallet() {
        use crate::test_vectors::{BITCOIN_ADDRESS, EVM_ADDRESS, MNEMONIC, PASSPHRASE, SOLANA_ADDRESS, XID};
        match ACEGFCore::view_wallet_internal(MNEMONIC, PASSPHRASE, None) {
            Ok(entity) => {
                assert_eq!(entity.xid, XID);
                assert_eq!(entity.evm_address, EVM_ADDRESS);
                assert_eq!(entity.solana_address, SOLANA_ADDRESS);
                assert_eq!(entity.bitcoin_address, BITCOIN_ADDRESS);
            }
            Err(e) => panic!("canonical wallet must open: {:?}", e),
        }
    }

    #[test]
    fn test_xid_vs_idcom() {
        use sha3::{Digest, Sha3_256};
        use crate::test_vectors::{MNEMONIC, PASSPHRASE};

        let sealed = ACEGFCore::decode_mnemonic_to_sealed(MNEMONIC).unwrap();
        println!("sealed hex: {}", hex::encode(sealed));
        
        // Current: XID from sealed
        let xid_from_sealed = ACEGFCore::compute_xid(&sealed);
        println!("XID from sealed: {}", xid_from_sealed);

        // Alternative: XID from unsealed material
        use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;
        let material = PassphraseSealingUtil::unseal_identity_material(&sealed, PASSPHRASE.as_bytes()).unwrap();
        let mut hasher = Sha3_256::new();
        hasher.update(&*material);
        hasher.update(b"acegf:xid");
        let xid_from_material = hex::encode(hasher.finalize());
        println!("XID from material: {}", xid_from_material);

        // Also: SHA3-256 of sealed without suffix
        let mut hasher2 = Sha3_256::new();
        hasher2.update(sealed);
        println!("SHA3-256(sealed): {}", hex::encode(hasher2.finalize()));

        // SHA3-256 of material without suffix  
        let mut hasher3 = Sha3_256::new();
        hasher3.update(&*material);
        println!("SHA3-256(material): {}", hex::encode(hasher3.finalize()));
    }

    #[cfg(feature = "zk")]
    #[test]
    fn test_identity_commitment() {
        use crate::test_vectors::{MNEMONIC, PASSPHRASE};
        match crate::hfi_pay::derive_binding_metadata(MNEMONIC, PASSPHRASE, 0) {
            Ok(meta) => {
                println!("identity_commitment: {}", meta.identity_commitment_hex);
                println!("claim_binding_handle: {}", meta.claim_binding_handle_hex);
            }
            Err(e) => println!("Error: {}", e),
        }
    }

    #[test]
    fn test_xid_empty_passphrase() {
        use crate::test_vectors::{MNEMONIC, PASSPHRASE, XID};
        let sealed = ACEGFCore::decode_mnemonic_to_sealed(MNEMONIC).unwrap();
        let xid = ACEGFCore::compute_xid(&sealed);
        assert_eq!(xid, XID);

        // Try view with empty passphrase to see EVM
        match ACEGFCore::view_wallet_internal(MNEMONIC, "", None) {
            Ok(e) => println!("EVM (empty pass): {}", e.evm_address),
            Err(e) => println!("Error empty pass: {:?}", e),
        }
        // Try with secondary passphrase
        match ACEGFCore::view_wallet_internal(MNEMONIC, PASSPHRASE, Some("")) {
            Ok(e) => println!("EVM (with secondary empty): {}", e.evm_address),
            Err(e) => println!("Error: {:?}", e),
        }
    }

    #[test]
    fn test_xid_variants() {
        use sha3::{Digest, Sha3_256};
        use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;
        use crate::test_vectors::{MNEMONIC, PASSPHRASE};
        let sealed = ACEGFCore::decode_mnemonic_to_sealed(MNEMONIC).unwrap();
        let material = PassphraseSealingUtil::unseal_identity_material(&sealed, PASSPHRASE.as_bytes()).unwrap();

        let target = "380802043b3ff7126054883edd31dc12ca7c497da876808d87255879fa83b45c";

        for (label, input) in [
            ("SHA3(material||acegf:xid:v1)", {
                let mut h = Sha3_256::new(); h.update(&*material); h.update(b"acegf:xid:v1"); hex::encode(h.finalize())
            }),
            ("SHA3(sealed||acegf:xid:v0)", {
                let mut h = Sha3_256::new(); h.update(sealed); h.update(b"acegf:xid:v0"); hex::encode(h.finalize())
            }),
            ("SHA3(material)", {
                let mut h = Sha3_256::new(); h.update(&*material); hex::encode(h.finalize())
            }),
            ("SHA3(material||acegf:rev)", {
                let mut h = Sha3_256::new(); h.update(&*material); h.update(b"acegf:rev"); hex::encode(h.finalize())
            }),
            ("SHA3(sealed[:16]||acegf:xid)", {
                let mut h = Sha3_256::new(); h.update(&sealed[..16]); h.update(b"acegf:xid"); hex::encode(h.finalize())
            }),
        ] {
            let matches = if input == target { " <-- MATCH" } else { "" };
            println!("{}: {}{}", label, input, matches);
        }
    }

    #[test]
    fn test_xid_variants2() {
        use sha2::{Digest as _, Sha256};
        use sha3::{Digest, Sha3_256};
        use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;
        use crate::pqclean_ffi::MlDsa44;
        use crate::test_vectors::{MNEMONIC, PASSPHRASE};
        let sealed = ACEGFCore::decode_mnemonic_to_sealed(MNEMONIC).unwrap();
        let material = PassphraseSealingUtil::unseal_identity_material(&sealed, PASSPHRASE.as_bytes()).unwrap();
        let seeds = ACEGFCore::derive_seeds_from_sealed_passphrase(&sealed, PASSPHRASE, None).unwrap();
        let target = "380802043b3ff7126054883edd31dc12ca7c497da876808d87255879fa83b45c";

        let sha256_sealed = hex::encode(Sha256::digest(sealed));
        let sha256_material = hex::encode(Sha256::digest(&*material));
        let sha256_mldsa_seed = hex::encode(Sha256::digest(&seeds.ml_dsa_44));
        let sha3_mldsa_seed = hex::encode(Sha3_256::digest(&seeds.ml_dsa_44));
        let (mldsa_pk, _) = MlDsa44::keypair_from_seed(&seeds.ml_dsa_44).unwrap();
        let sha3_mldsa_pk = hex::encode(Sha3_256::digest(&mldsa_pk));
        let sha3_mldsa_pk_truncated = hex::encode(&Sha3_256::digest(&mldsa_pk)[..]);
        
        for (label, val) in [
            ("SHA256(sealed)", &sha256_sealed),
            ("SHA256(material)", &sha256_material),
            ("SHA256(ml_dsa_44 seed)", &sha256_mldsa_seed),
            ("SHA3-256(ml_dsa_44 seed)", &sha3_mldsa_seed),
            ("SHA3-256(ml_dsa_44 pubkey)", &sha3_mldsa_pk),
        ] {
            let m = if val == target { " <-- MATCH" } else { "" };
            println!("{}: {}{}", label, val, m);
        }
    }
