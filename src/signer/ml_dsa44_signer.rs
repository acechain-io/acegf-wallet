// src/signer/ml_dsa44_signer.rs
//
// MlDsa44Signer: context-isolated ML-DSA-44 signing built on ACE-GF.
//
// Mirrors the EVM/Solana `*_with_context` pattern: callers supply an opaque
// context byte string; ACE-GF derives a dedicated ML-DSA-44 seed without
// exporting identity_root or secret key material across the wallet boundary.

use crate::acegf_core::ACEGFCore;
use crate::pqclean_ffi::MlDsa44;
use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;
use std::error::Error;
use zeroize::Zeroizing;

/// ML-DSA-44 signer with REV32 context isolation.
pub struct MlDsa44Signer;

impl MlDsa44Signer {
    // ==============================
    // Key Derivation
    // ==============================

    /// Derive an ML-DSA-44 keypair from mnemonic + passphrase.
    ///
    /// Empty `context` uses the standard unseal path (same ML-DSA-44 identity
    /// key as `ACEGFCore::unseal_to_seeds`). Non-empty `context` uses the REV32
    /// HKDF context extension and produces a cryptographically isolated key.
    pub fn derive_keypair_with_context(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        context: &[u8],
    ) -> Result<
        (
            [u8; MlDsa44::PK_BYTES],
            Zeroizing<[u8; MlDsa44::SK_BYTES]>,
        ),
        Box<dyn Error>,
    > {
        if context.is_empty() {
            let mut seeds =
                ACEGFCore::unseal_to_seeds(mnemonic, passphrase, secondary_passphrase)
                    .map_err(|e| format!("Unseal failed: {:?}", e))?;
            let (pk, sk) = MlDsa44::keypair_from_seed(&*seeds.ml_dsa_44)
                .map_err(|e| format!("ML-DSA-44 keygen failed: {e}"))?;
            ACEGFCore::clear_scheme_seeds(&mut seeds);
            return Ok((pk, sk));
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

        let identity_root = PassphraseSealingUtil::derive_identity_root(&kmaster)
            .map_err(|e| format!("Derive identity root failed: {:?}", e))?;

        let seed = ACEGFCore::derive_ml_dsa_seed_from_rev32_with_context(&identity_root, context)
            .map_err(|e| format!("Derive ML-DSA seed with context failed: {:?}", e))?;

        let (pk, sk) = MlDsa44::keypair_from_seed(&*seed)
            .map_err(|e| format!("ML-DSA-44 keygen failed: {e}"))?;
        Ok((pk, sk))
    }

    /// Derive an ML-DSA-44 keypair with context using a PRF-derived base key
    /// (skips Argon2). `base_key` acts as the Kmaster equivalent on the REV32
    /// context path.
    pub fn derive_keypair_with_context_base_key(
        mnemonic: &str,
        base_key: &[u8; 32],
        context: &[u8],
    ) -> Result<
        (
            [u8; MlDsa44::PK_BYTES],
            Zeroizing<[u8; MlDsa44::SK_BYTES]>,
        ),
        Box<dyn Error>,
    > {
        if context.is_empty() {
            let mut seeds = ACEGFCore::unseal_to_seeds_with_base_key(mnemonic, base_key)?;
            let (pk, sk) = MlDsa44::keypair_from_seed(&*seeds.ml_dsa_44)
                .map_err(|e| format!("ML-DSA-44 keygen failed: {e}"))?;
            ACEGFCore::clear_scheme_seeds(&mut seeds);
            return Ok((pk, sk));
        }

        let identity_root = PassphraseSealingUtil::derive_identity_root(base_key)
            .map_err(|e| format!("Derive identity root failed: {:?}", e))?;

        let seed = ACEGFCore::derive_ml_dsa_seed_from_rev32_with_context(&identity_root, context)
            .map_err(|e| format!("Derive ML-DSA seed with context failed: {:?}", e))?;

        let (pk, sk) = MlDsa44::keypair_from_seed(&*seed)
            .map_err(|e| format!("ML-DSA-44 keygen failed: {e}"))?;
        Ok((pk, sk))
    }

    // ==============================
    // Context-Aware Signing
    // ==============================

    /// Return the ML-DSA-44 public key bytes for `context`.
    pub fn pubkey_with_context(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        context: &[u8],
    ) -> Result<[u8; MlDsa44::PK_BYTES], Box<dyn Error>> {
        let (pk, _sk) = Self::derive_keypair_with_context(
            mnemonic,
            passphrase,
            secondary_passphrase,
            context,
        )?;
        Ok(pk)
    }

    /// Sign `message` with the ML-DSA-44 key isolated under `context`.
    pub fn sign_with_context(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        context: &[u8],
        message: &[u8],
    ) -> Result<[u8; MlDsa44::SIG_BYTES], Box<dyn Error>> {
        let (_pk, sk) = Self::derive_keypair_with_context(
            mnemonic,
            passphrase,
            secondary_passphrase,
            context,
        )?;
        MlDsa44::sign(&sk, message).map_err(|e| e.into())
    }

    /// Sign with PRF base key + context (passkey path).
    pub fn sign_with_context_base_key(
        mnemonic: &str,
        base_key: &[u8; 32],
        context: &[u8],
        message: &[u8],
    ) -> Result<[u8; MlDsa44::SIG_BYTES], Box<dyn Error>> {
        let (_pk, sk) =
            Self::derive_keypair_with_context_base_key(mnemonic, base_key, context)?;
        MlDsa44::sign(&sk, message).map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acegf_core::ACEGFCore;
    use crate::pqclean_ffi::MlDsa44;

    const TEST_PASSPHRASE: &str = "test-pass";

    fn test_mnemonic() -> String {
        ACEGFCore::generate_ace_internal(TEST_PASSPHRASE, None)
            .expect("wallet generation must succeed")
            .mnemonic
            .to_string()
    }

    #[test]
    fn derive_keypair_empty_context_matches_unseal_ml_dsa() {
        let mnemonic = test_mnemonic();
        let mut seeds = ACEGFCore::unseal_to_seeds(&mnemonic, TEST_PASSPHRASE, None).unwrap();
        let (expected_pk, _) = MlDsa44::keypair_from_seed(&*seeds.ml_dsa_44).unwrap();
        ACEGFCore::clear_scheme_seeds(&mut seeds);

        let (context_pk, _) = MlDsa44Signer::derive_keypair_with_context(
            &mnemonic,
            TEST_PASSPHRASE,
            None,
            b"",
        )
        .unwrap();

        assert_eq!(context_pk, expected_pk);
    }

    #[test]
    fn derive_keypair_with_context_base_key_is_deterministic() {
        let base_key = [0x42u8; 32];
        let context = b"test:ml-dsa:context";
        let dummy_mnemonic = test_mnemonic();

        let (pk_a, _) = MlDsa44Signer::derive_keypair_with_context_base_key(
            &dummy_mnemonic,
            &base_key,
            context,
        )
        .unwrap();
        let (pk_b, _) = MlDsa44Signer::derive_keypair_with_context_base_key(
            &dummy_mnemonic,
            &base_key,
            context,
        )
        .unwrap();
        assert_eq!(pk_a, pk_b);
    }

    #[test]
    fn different_contexts_yield_different_pubkeys() {
        let base_key = [0x55u8; 32];
        let dummy_mnemonic = test_mnemonic();

        let (pk_a, _) = MlDsa44Signer::derive_keypair_with_context_base_key(
            &dummy_mnemonic,
            &base_key,
            b"context-a",
        )
        .unwrap();
        let (pk_b, _) = MlDsa44Signer::derive_keypair_with_context_base_key(
            &dummy_mnemonic,
            &base_key,
            b"context-b",
        )
        .unwrap();
        assert_ne!(pk_a, pk_b);
    }

    #[test]
    fn sign_with_context_produces_valid_signature() {
        let base_key = [0x77u8; 32];
        let context = b"test:signing:context";
        let dummy_mnemonic = test_mnemonic();
        let message = b"mev-ace commit signing input";

        let (pk, _) = MlDsa44Signer::derive_keypair_with_context_base_key(
            &dummy_mnemonic,
            &base_key,
            context,
        )
        .unwrap();
        let sig = MlDsa44Signer::sign_with_context_base_key(
            &dummy_mnemonic,
            &base_key,
            context,
            message,
        )
        .unwrap();

        assert!(MlDsa44::verify(&pk, message, &sig).unwrap());
    }

    #[test]
    fn sign_with_context_end_to_end_rev32_mnemonic() {
        let mnemonic = test_mnemonic();
        let context = b"mev-ace/auth";
        let message = b"protocol message";

        let pk = MlDsa44Signer::pubkey_with_context(
            &mnemonic,
            TEST_PASSPHRASE,
            None,
            context,
        )
        .unwrap();
        let sig =
            MlDsa44Signer::sign_with_context(&mnemonic, TEST_PASSPHRASE, None, context, message)
                .unwrap();

        assert!(MlDsa44::verify(&pk, message, &sig).unwrap());
    }

    #[test]
    fn context_isolated_key_differs_from_default_ml_dsa_identity() {
        let mnemonic = test_mnemonic();
        let default_pk = MlDsa44Signer::pubkey_with_context(
            &mnemonic,
            TEST_PASSPHRASE,
            None,
            b"",
        )
        .unwrap();
        let isolated_pk = MlDsa44Signer::pubkey_with_context(
            &mnemonic,
            TEST_PASSPHRASE,
            None,
            b"mev-ace/auth",
        )
        .unwrap();
        assert_ne!(default_pk, isolated_pk);
    }
}
