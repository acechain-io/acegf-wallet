// src/acegf_structs.rs
use serde::{ser::SerializeStruct, Serialize, Serializer};
use thiserror::Error;
use zeroize::Zeroizing;

pub struct SchemeSeeds {
    pub ed25519_solana: Zeroizing<[u8; 32]>,
    pub secp256k1_evm: Zeroizing<[u8; 32]>,
    pub secp256k1_btc: Zeroizing<[u8; 32]>,
    pub secp256k1_cosmos: Zeroizing<[u8; 32]>,
    pub secp256k1_tron: Zeroizing<[u8; 32]>,
    pub ed25519_polkadot: Zeroizing<[u8; 32]>,
    pub x25519: Zeroizing<[u8; 32]>,
    pub ml_dsa_44: Zeroizing<[u8; 32]>,
    /// ML-KEM-768 (FIPS 203) seed — 64 bytes (`d || z`), consumed by
    /// `MlKem768::keypair_from_seed` to deterministically derive the
    /// post-quantum KEM encapsulation/decapsulation key pair.
    pub ml_kem_768: Zeroizing<[u8; 64]>,
}

impl std::fmt::Debug for SchemeSeeds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemeSeeds")
            .field("ed25519_solana", &"[REDACTED]")
            .field("secp256k1_evm", &"[REDACTED]")
            .field("secp256k1_btc", &"[REDACTED]")
            .field("secp256k1_cosmos", &"[REDACTED]")
            .field("secp256k1_tron", &"[REDACTED]")
            .field("ed25519_polkadot", &"[REDACTED]")
            .field("x25519", &"[REDACTED]")
            .field("ml_dsa_44", &"[REDACTED]")
            .field("ml_kem_768", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct CryptoEntity {
    pub mnemonic: Zeroizing<String>,
    pub solana_address: String,
    pub evm_address: String,
    pub bitcoin_address: String,
    pub cosmos_address: String,
    pub polkadot_address: String,
    pub xaddress: String,
    pub x25519: String,
    /// Base64-encoded ML-KEM-768 encapsulation key (1184 bytes).
    ///
    /// This is the wallet's **post-quantum key-exchange identity** — the
    /// analogue of `x25519` (X25519) but built on the NIST-standardized
    /// lattice KEM (FIPS 203). It is safe to publish; any party can run
    /// `ACEGF::encapsulate_for_xkem` against it to derive a shared secret,
    /// and only the wallet owner can recover the same secret via
    /// `ACEGF::decapsulate_for_xkem`.
    pub xkem: String,
    pub xid: String,
    pub tron_address: String,
}

impl Serialize for CryptoEntity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CryptoEntity", 11)?;
        state.serialize_field("mnemonic", &self.mnemonic.as_str())?;
        state.serialize_field("solana_address", &self.solana_address)?;
        state.serialize_field("evm_address", &self.evm_address)?;
        state.serialize_field("bitcoin_address", &self.bitcoin_address)?;
        state.serialize_field("cosmos_address", &self.cosmos_address)?;
        state.serialize_field("polkadot_address", &self.polkadot_address)?;
        state.serialize_field("xaddress", &self.xaddress)?;
        state.serialize_field("x25519", &self.x25519)?;
        state.serialize_field("xkem", &self.xkem)?;
        state.serialize_field("xid", &self.xid)?;
        state.serialize_field("tron_address", &self.tron_address)?;
        state.end()
    }
}

impl std::fmt::Debug for CryptoEntity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoEntity")
            .field("mnemonic", &"[REDACTED]")
            .field("solana_address", &self.solana_address)
            .field("evm_address", &self.evm_address)
            .field("bitcoin_address", &self.bitcoin_address)
            .field("cosmos_address", &self.cosmos_address)
            .field("polkadot_address", &self.polkadot_address)
            .field("xaddress", &self.xaddress)
            .field("x25519", &self.x25519)
            .field("xkem", &self.xkem)
            .field("xid", &self.xid)
            .field("tron_address", &self.tron_address)
            .finish()
    }
}

impl Default for CryptoEntity {
    fn default() -> Self {
        CryptoEntity {
            mnemonic: Zeroizing::new(String::new()),
            solana_address: String::new(),
            evm_address: String::new(),
            bitcoin_address: String::new(),
            cosmos_address: String::new(),
            polkadot_address: String::new(),
            xaddress: String::new(),
            x25519: String::new(),
            xkem: String::new(),
            xid: String::new(),
            tron_address: String::new(),
        }
    }
}

// ---------------- Error Types ----------------

#[derive(Debug, Error, Serialize, Clone)]
pub enum AcegfError {
    #[error("KDF (Argon2) failed")]
    KdfError,

    #[error("Decryption failed or incorrect passphrase")]
    InvalidPassphrase,

    #[error("Ambiguous mnemonic: collision detected in passphrase-sealed encoding. Please try a different passphrase.")]
    AmbiguousMnemonic,

    #[error("Only 12-word mnemonics are supported")]
    UnsupportedMnemonicLength,

    #[error("Invalid format")]
    InvalidFormat,

    #[error("Internal error")]
    Internal,

    #[error("Address derivation failed")]
    AddressDerivationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SignFlavor {
    Ed25519Raw,           // Solana / Polkadot
    Secp256k1Evm,         // Ethereum / BSC
    Secp256k1Bitcoin,     // Bitcoin Signed Message
    Secp256k1CosmosAmino, // Cosmos legacy
    Secp256k1Eip712,      // Cosmos (EIP-712)
    MlDsa44Raw,           // PQC
}

#[derive(Debug, Serialize)]
pub enum PqcAlg {
    MlDsa44,
    MlKem768,
}

#[derive(Debug)]
pub struct SignRequest<'a> {
    pub alg: PqcAlg,
    pub flavor: SignFlavor,
    pub payload: &'a [u8],
    pub chain_id_u64: Option<u64>,    // EVM chain id
    pub hrp: Option<&'a str>,         // Bech32 HRP
    pub btc_prefix: Option<&'a [u8]>, // Bitcoin message prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_entity_default() {
        let entity = CryptoEntity::default();
        assert!(entity.mnemonic.is_empty());
        assert!(entity.solana_address.is_empty());
        assert!(entity.evm_address.is_empty());
        assert!(entity.bitcoin_address.is_empty());
        assert!(entity.cosmos_address.is_empty());
        assert!(entity.polkadot_address.is_empty());
        assert!(entity.xaddress.is_empty());
        assert!(entity.x25519.is_empty());
    }

    #[test]
    fn test_crypto_entity_clone() {
        let entity = CryptoEntity {
            mnemonic: Zeroizing::new("test".to_string()),
            solana_address: "sol123".to_string(),
            evm_address: "0x123".to_string(),
            bitcoin_address: "bc1...".to_string(),
            cosmos_address: "cosmos1...".to_string(),
            polkadot_address: "1...".to_string(),
            xaddress: "acegf1...".to_string(),
            x25519: "base64...".to_string(),
            xkem: "base64-xkem...".to_string(),
            xid: String::new(),
            tron_address: String::new(),
        };

        let cloned = entity.clone();
        assert_eq!(*entity.mnemonic, *cloned.mnemonic);
        assert_eq!(entity.solana_address, cloned.solana_address);
    }

    #[test]
    fn test_acegf_error_display() {
        let err = AcegfError::KdfError;
        assert!(err.to_string().contains("KDF"));

        let err = AcegfError::InvalidPassphrase;
        assert!(err.to_string().contains("passphrase") || err.to_string().contains("Decryption"));

        let err = AcegfError::AmbiguousMnemonic;
        assert!(err.to_string().contains("Ambiguous"));

        let err = AcegfError::UnsupportedMnemonicLength;
        assert!(err.to_string().contains("12-word"));

        let err = AcegfError::InvalidFormat;
        assert!(err.to_string().contains("format"));

        let err = AcegfError::Internal;
        assert!(err.to_string().contains("Internal"));

        let err = AcegfError::AddressDerivationFailed;
        assert!(err.to_string().contains("derivation"));
    }

    #[test]
    fn test_acegf_error_clone() {
        let err = AcegfError::KdfError;
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    #[test]
    fn test_sign_flavor_equality() {
        assert_eq!(SignFlavor::Ed25519Raw, SignFlavor::Ed25519Raw);
        assert_ne!(SignFlavor::Ed25519Raw, SignFlavor::Secp256k1Evm);
        assert_ne!(
            SignFlavor::Secp256k1Bitcoin,
            SignFlavor::Secp256k1CosmosAmino
        );
    }

    #[test]
    fn test_sign_flavor_copy() {
        let flavor = SignFlavor::MlDsa44Raw;
        let copied = flavor; // Copy, not move
        assert_eq!(flavor, copied);
    }

    #[test]
    fn test_sign_request_creation() {
        let payload = b"test message";
        let request = SignRequest {
            alg: PqcAlg::MlDsa44,
            flavor: SignFlavor::Ed25519Raw,
            payload,
            chain_id_u64: Some(1),
            hrp: Some("cosmos"),
            btc_prefix: None,
        };

        assert_eq!(request.payload, b"test message");
        assert_eq!(request.chain_id_u64, Some(1));
        assert_eq!(request.hrp, Some("cosmos"));
        assert!(request.btc_prefix.is_none());
    }

    #[test]
    fn test_scheme_seeds_debug() {
        let seeds = SchemeSeeds {
            ed25519_solana: Zeroizing::new([1u8; 32]),
            secp256k1_evm: Zeroizing::new([2u8; 32]),
            secp256k1_btc: Zeroizing::new([3u8; 32]),
            secp256k1_cosmos: Zeroizing::new([4u8; 32]),
            secp256k1_tron: Zeroizing::new([5u8; 32]),
            ed25519_polkadot: Zeroizing::new([5u8; 32]),
            x25519: Zeroizing::new([6u8; 32]),
            ml_dsa_44: Zeroizing::new([7u8; 32]),
            ml_kem_768: Zeroizing::new([8u8; 64]),
        };

        // Debug should work without panicking
        let debug_str = format!("{:?}", seeds);
        assert!(!debug_str.is_empty());
    }

    #[test]
    fn test_scheme_seeds_debug_redacted() {
        let seeds = SchemeSeeds {
            ed25519_solana: Zeroizing::new([1u8; 32]),
            secp256k1_evm: Zeroizing::new([2u8; 32]),
            secp256k1_btc: Zeroizing::new([3u8; 32]),
            secp256k1_cosmos: Zeroizing::new([4u8; 32]),
            secp256k1_tron: Zeroizing::new([5u8; 32]),
            ed25519_polkadot: Zeroizing::new([5u8; 32]),
            x25519: Zeroizing::new([6u8; 32]),
            ml_dsa_44: Zeroizing::new([7u8; 32]),
            ml_kem_768: Zeroizing::new([8u8; 64]),
        };
        let debug_str = format!("{:?}", seeds);
        // Ensure no raw key bytes leak in debug output
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("[1, 1, 1"));
    }

    #[test]
    fn test_crypto_entity_serialization() {
        let entity = CryptoEntity {
            mnemonic: Zeroizing::new("test".to_string()),
            solana_address: "sol".to_string(),
            evm_address: "0x".to_string(),
            bitcoin_address: "bc1".to_string(),
            cosmos_address: "cosmos1".to_string(),
            polkadot_address: "1abc".to_string(),
            xaddress: "acegf1".to_string(),
            x25519: "base64".to_string(),
            xkem: "base64-xkem".to_string(),
            xid: String::new(),
            tron_address: String::new(),
        };

        let json = serde_json::to_string(&entity).unwrap();
        assert!(json.contains("mnemonic"));
        assert!(json.contains("solana_address"));
        assert!(json.contains("evm_address"));
    }
}
