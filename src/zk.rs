// src/zk.rs
//
// ZK-ACE integration module for ACE-GF.
//
// This module is a thin bridge between ACE-GF's identity types (Rev32, AcegfError)
// and the zk-ace crate, which is the canonical source of truth for Poseidon2 hash,
// derivation, and zero-knowledge proof implementation.
//
// Re-exports from zk-ace:
//   - poseidon2_hash    (native Poseidon2 hash over M31 field)
//   - DerivationContext (aliased as ZkDerivationContext for backward compatibility)
//
// ACE-GF specific wrappers (use ACE-GF types: Rev32, AcegfError):
//   - rev32_to_m31      (Rev32 -> [M31; 9] lossless encoding)
//   - mnemonic_to_rev_m31 (BIP39 mnemonic -> [M31; 9], with AcegfError)
//   - bytes_to_m31      (raw bytes -> [M31; 9], with AcegfError)
//   - derive_poseidon   (delegates to zk-ace's derive_native)
//
// Compiled only when the `zk` feature is enabled:
//   cargo build --features zk
//   cargo test --features zk

use stwo::core::fields::m31::M31;
use bip39::Mnemonic;
use zeroize::Zeroize;

use crate::acegf_structs::AcegfError;
use crate::utils::acegf_rev_generator::Rev32;

// ============================================================================
//  Re-exports from zk-ace (canonical source of truth)
// ============================================================================

/// Native Poseidon2 hash over M31 field.
/// Canonical implementation lives in zk-ace.
pub use zk_ace::native::hash::poseidon2_hash;

/// Derivation context for ZK-ACE: (AlgID, Domain, Index).
/// Type alias for backward compatibility with existing ACE-GF code.
pub type ZkDerivationContext = zk_ace::stwo::types::DerivationContext;

// ============================================================================
//  Poseidon2-based derivation (delegates to zk-ace)
// ============================================================================

/// Poseidon2-based key derivation: `Derive(REV, Ctx) = Poseidon2(REV[0..9], AlgID, Domain, Index)`.
///
/// Delegates to zk-ace's canonical derive function.
///
/// **This is NOT the same as ACE-GF's HKDF-based derivation.**
/// - HKDF: used to generate actual signing keys (Ed25519, Secp256k1, etc.)
/// - Poseidon2 Derive: used for ZK-ACE identity commitment and target binding
///
/// The two derivation paths serve different purposes and coexist:
/// ```text
///   REV --+-- HKDF(REV, "ACEGF-V1-ED25519-SOLANA") --> Solana signing key
///         |-- HKDF(REV, "ACEGF-V1-SECP256K1-EVM")  --> EVM signing key
///         +-- Poseidon2(REV[0..9], AlgID, Domain, Index) --> ZK-ACE target commitment
/// ```
pub fn derive_poseidon(rev: &[M31; 9], ctx: &ZkDerivationContext) -> [M31; 8] {
    zk_ace::native::derive::derive_native(rev, ctx)
}

// ============================================================================
//  REV -> M31 conversion (ACE-GF specific, wraps AcegfError)
// ============================================================================

/// Expected byte length for a REV used in ZK-ACE (256-bit).
pub const ZK_REV_BYTES: usize = 32;

/// Convert a REV32 byte array to 9 M31 field elements (lossless).
///
/// The 256-bit REV is encoded losslessly: each 4-byte chunk maps to a 31-bit
/// M31 element (lower bits), with the high bits collected in a 9th element.
pub fn rev32_to_m31(rev: &Rev32) -> [M31; 9] {
    zk_ace::stwo::types::bytes_to_elements(rev)
}

/// Parse a BIP39 mnemonic and convert its entropy to M31 field elements.
///
/// Only 24-word mnemonics (256-bit entropy) are accepted to ensure sufficient
/// security for ZK-ACE's 128-bit target. 12-word mnemonics (128-bit) are
/// rejected because the entropy would be too small.
///
/// Note: M31 does not implement Zeroize; callers are responsible for clearing
/// the returned value from memory after use.
pub fn mnemonic_to_rev_m31(mnemonic: &str) -> Result<[M31; 9], AcegfError> {
    let parsed = Mnemonic::parse_normalized(mnemonic).map_err(|_| AcegfError::AmbiguousMnemonic)?;
    let mut entropy = parsed.to_entropy();
    if entropy.len() != ZK_REV_BYTES {
        entropy.zeroize();
        return Err(AcegfError::UnsupportedMnemonicLength);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&entropy);
    let result = zk_ace::stwo::types::bytes_to_elements(&arr);
    arr.zeroize();
    entropy.zeroize();
    Ok(result)
}

/// Convert arbitrary bytes to M31 field elements (lossless, 9 elements).
///
/// Accepts exactly 32 bytes. For typed `Rev32` values, prefer `rev32_to_m31`.
pub fn bytes_to_m31(bytes: &[u8]) -> Result<[M31; 9], AcegfError> {
    if bytes.len() != ZK_REV_BYTES {
        return Err(AcegfError::InvalidFormat);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(zk_ace::stwo::types::bytes_to_elements(&arr))
}

// ============================================================================
//  Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Re-exported Poseidon2 (verify delegation works) ----

    #[test]
    fn poseidon2_hash_via_reexport() {
        let a = M31(42);
        let b = M31(123);
        assert_eq!(poseidon2_hash(&[a, b]), poseidon2_hash(&[a, b]));
    }

    // ---- Poseidon2 derive (delegates to zk-ace) ----

    #[test]
    fn derive_is_deterministic() {
        let rev = [M31(12345); 9];
        let ctx = ZkDerivationContext {
            alg_id: M31(0),
            domain: M31(1),
            index: M31(0),
        };
        assert_eq!(derive_poseidon(&rev, &ctx), derive_poseidon(&rev, &ctx));
    }

    #[test]
    fn derive_context_isolation() {
        let rev = [M31(12345); 9];
        let ctx_ed = ZkDerivationContext {
            alg_id: M31(0),
            domain: M31(1),
            index: M31(0),
        };
        let ctx_secp = ZkDerivationContext {
            alg_id: M31(1),
            domain: M31(1),
            index: M31(0),
        };
        assert_ne!(
            derive_poseidon(&rev, &ctx_ed),
            derive_poseidon(&rev, &ctx_secp)
        );
    }

    // ---- REV -> M31 conversion ----

    #[test]
    fn rev32_to_m31_is_deterministic() {
        let rev: Rev32 = core::array::from_fn(|i| (i + 1) as u8);
        assert_eq!(rev32_to_m31(&rev), rev32_to_m31(&rev));
    }

    #[test]
    fn rev32_to_m31_nonzero_input_gives_nonzero_output() {
        let rev: Rev32 = core::array::from_fn(|i| (i + 1) as u8);
        assert_ne!(rev32_to_m31(&rev), [M31(0); 9]);
    }

    #[test]
    fn different_revs_produce_different_m31() {
        assert_ne!(rev32_to_m31(&[1u8; 32]), rev32_to_m31(&[2u8; 32]));
    }

    #[test]
    fn mnemonic_24_word_accepted() {
        let entropy: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap().to_string();
        let m31 = mnemonic_to_rev_m31(&mnemonic).unwrap();
        assert_eq!(m31, rev32_to_m31(&entropy));
    }

    #[test]
    fn mnemonic_12_word_rejected() {
        let mnemonic = Mnemonic::from_entropy(&[0u8; 16]).unwrap().to_string();
        assert!(mnemonic_to_rev_m31(&mnemonic).is_err());
    }

    #[test]
    fn bytes_to_m31_rejects_wrong_length() {
        assert!(bytes_to_m31(&[0u8; 16]).is_err());
        assert!(bytes_to_m31(&[0u8; 31]).is_err());
    }

    #[test]
    fn bytes_to_m31_accepts_32_bytes() {
        let bytes = [42u8; 32];
        assert_eq!(bytes_to_m31(&bytes).unwrap(), rev32_to_m31(&bytes));
    }
}
