// src/hfi_pay.rs
//
// HFI Pay helpers for registration, claim authorization, and verified-quote
// binding metadata.

use base64ct::{Base64, Encoding};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::acegf_core::ACEGFCore;
use crate::utils::acegf_rev_generator::AceRevGenerator;
use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;

#[cfg(feature = "zk")]
use stwo::core::fields::m31::M31;
#[cfg(feature = "zk")]
use zk_ace::native::commitment::{compute_id_com, compute_target};
#[cfg(feature = "zk")]
use zk_ace::native::hash::poseidon2_hash;
#[cfg(feature = "zk")]
use zk_ace::stwo::types::{
    bytes_to_elements, u64_to_domain_elements, DerivationContext, ELEMENTS_PER_HASH,
};

const REGISTER_DOMAIN: &[u8] = b"hfipay:register";
const REFUND_DOMAIN: &[u8] = b"hfipay:refund";
const DEPLOYMENT_DOMAIN: &[u8] = b"ace-hfi-pay:v1";

#[cfg(feature = "zk")]
const HFIPAY_ID_SALT_LABEL: &[u8] = b"hfipay:id-salt:v1";
#[cfg(feature = "zk")]
const HFIPAY_ID_DOMAIN_LABEL: &[u8] = b"hfipay:id-domain:v1";
#[cfg(feature = "zk")]
const HFIPAY_BIND_ALG_LABEL: &[u8] = b"hfipay:claim-bind:alg:v1";
#[cfg(feature = "zk")]
const HFIPAY_BIND_DOMAIN_LABEL: &[u8] = b"hfipay:claim-bind:domain:v1";

/// Compute the HFI Pay registration message hash.
///
/// Returns the hex-encoded SHA-256 hash, or an error string prefixed with "error:".
pub fn registration_message(xid_hex: &str, identifier: &str) -> String {
    let xid_bytes = match hex::decode(xid_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return "error:invalid xid hex (expected 64 hex chars)".to_string(),
    };
    let mut hasher = Sha256::new();
    hasher.update(REGISTER_DOMAIN);
    hasher.update(&xid_bytes);
    hasher.update(identifier.as_bytes());
    hex::encode(hasher.finalize())
}

/// Derive the Ed25519 public key used by HFI Pay claim signatures.
pub fn claim_pubkey_hex(mnemonic: &str, passphrase: &str) -> Result<String, String> {
    let seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, None)
        .map_err(|e| format!("unseal failed: {:?}", e))?;
    let signing_key = SigningKey::from_bytes(&seeds.ed25519_solana);
    Ok(hex::encode(signing_key.verifying_key().to_bytes()))
}

/// Result of signing a registration message.
#[derive(Debug)]
pub struct RegistrationSignature {
    /// Base64-encoded public key (Ed25519 32B or ML-DSA-44 1312B).
    pub pubkey: String,
    /// Base64-encoded signature (Ed25519 64B or ML-DSA-44 2420B).
    pub signature: String,
    /// Hex-encoded 32-byte message hash that was signed.
    pub message: String,
    /// Hex-encoded public key (for on-chain registration).
    pub pubkey_hex: String,
    /// Signature algorithm identifier (0=Ed25519, 2=ML-DSA-44).
    pub algorithm: u8,
}

/// Compute and sign the HFI Pay registration message using ML-DSA-44 (post-quantum).
///
/// Returns a `RegistrationSignature` on success, or an error string.
pub fn sign_registration(
    mnemonic: &str,
    passphrase: &str,
    xid_hex: &str,
    identifier: &str,
) -> Result<RegistrationSignature, String> {
    use crate::pqclean_ffi::MlDsa44;

    let xid_bytes = match hex::decode(xid_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return Err("invalid xid hex (expected 64 hex chars)".to_string()),
    };

    // Compute registration message
    let mut hasher = Sha256::new();
    hasher.update(REGISTER_DOMAIN);
    hasher.update(&xid_bytes);
    hasher.update(identifier.as_bytes());
    let msg_hash: [u8; 32] = hasher.finalize().into();

    // Get ML-DSA-44 keypair from seed
    let seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, None)
        .map_err(|e| format!("unseal failed: {:?}", e))?;
    let (pk, sk) = MlDsa44::keypair_from_seed(&seeds.ml_dsa_44)
        .map_err(|e| format!("ML-DSA-44 keygen failed: {}", e))?;

    // Sign with ML-DSA-44
    let sig = MlDsa44::sign(&sk, &msg_hash).map_err(|e| format!("ML-DSA-44 sign failed: {}", e))?;

    Ok(RegistrationSignature {
        pubkey: Base64::encode_string(&pk),
        signature: Base64::encode_string(&sig),
        message: hex::encode(msg_hash),
        pubkey_hex: hex::encode(pk),
        algorithm: 2, // ML-DSA-44
    })
}

/// Pre-sign a refund authorization so the server can auto-submit a refund tx when the intent expires.
///
/// Message: SHA256(REFUND_DOMAIN || DEPLOYMENT_DOMAIN || chain_tag(1) || asset_presence(1)[|| mint(32)] ||
///                 intent_id(32) || blinded_binding(32) || amount_le(8) || refund_authorizer(32) ||
///                 refund_dest(32) || expiry_le(8) || nonce_le(8))
///
/// `mint_hex` is None for the native ACE token; for ERC-20/SPL pass the 32-byte padded mint address.
pub fn sign_refund_auth(
    mnemonic: &str,
    passphrase: &str,
    chain_tag: u8,
    mint_hex: Option<&str>,
    intent_id_hex: &str,
    blinded_binding_hex: &str,
    amount: u64,
    refund_authorizer_hex: &str,
    refund_dest_hex: &str,
    expiry: u64,
    nonce: u64,
) -> Result<RegistrationSignature, String> {
    use crate::pqclean_ffi::MlDsa44;

    let decode32 = |s: &str, label: &str| -> Result<[u8; 32], String> {
        let b = hex::decode(s).map_err(|_| format!("invalid hex for {label}"))?;
        b.try_into().map_err(|_| format!("{label} must be 32 bytes"))
    };

    let intent_id = decode32(intent_id_hex, "intent_id")?;
    let blinded_binding = decode32(blinded_binding_hex, "blinded_binding")?;
    let refund_authorizer = decode32(refund_authorizer_hex, "refund_authorizer")?;
    let refund_dest = decode32(refund_dest_hex, "refund_dest")?;

    let mut hasher = Sha256::new();
    hasher.update(REFUND_DOMAIN);
    hasher.update(DEPLOYMENT_DOMAIN);
    hasher.update([chain_tag]);
    if let Some(mint) = mint_hex {
        let mint_bytes = decode32(mint, "mint")?;
        hasher.update([1u8]);
        hasher.update(mint_bytes);
    } else {
        hasher.update([0u8]);
    }
    hasher.update(intent_id);
    hasher.update(blinded_binding);
    hasher.update(amount.to_le_bytes());
    hasher.update(refund_authorizer);
    hasher.update(refund_dest);
    hasher.update(expiry.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    let msg_hash: [u8; 32] = hasher.finalize().into();

    let seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, None)
        .map_err(|e| format!("unseal failed: {:?}", e))?;
    let (pk, sk) = MlDsa44::keypair_from_seed(&seeds.ml_dsa_44)
        .map_err(|e| format!("ML-DSA-44 keygen failed: {}", e))?;
    let sig = MlDsa44::sign(&sk, &msg_hash)
        .map_err(|e| format!("ML-DSA-44 sign failed: {}", e))?;

    Ok(RegistrationSignature {
        pubkey: Base64::encode_string(&pk),
        signature: Base64::encode_string(&sig),
        message: hex::encode(msg_hash),
        pubkey_hex: hex::encode(pk),
        algorithm: 2,
    })
}

/// Binding metadata required by sender-verifiable HFI Pay quotes.
pub struct BindingMetadata {
    pub identity_commitment_hex: String,
    pub claim_binding_handle_hex: String,
    pub binding_epoch: u64,
}

/// Derive the verified-quote binding tuple for HFI Pay.
///
/// The resulting values are re-derivable from the recipient's mnemonic, which
/// keeps the portal flow stateless while still aligning with the paper's
/// `IDcom_B` / `u_{B,e}` story:
///
/// - `identity_commitment = Poseidon2(REV, salt(REV), domain_id)`
/// - `claim_binding_handle = Poseidon2(Derive(REV, Ctx_bind(e)))`
pub fn derive_binding_metadata(
    mnemonic: &str,
    _passphrase: &str,
    binding_epoch: u64,
) -> Result<BindingMetadata, String> {
    #[cfg(feature = "zk")]
    {
        let rev_m31 = crate::zk::mnemonic_to_rev_m31(mnemonic)
            .map_err(|e| format!("failed to derive REV from mnemonic: {e}"))?;

        // salt = Poseidon2(REV, label_to_m31_elem(HFIPAY_ID_SALT_LABEL))
        let salt_hash: [M31; ELEMENTS_PER_HASH] = {
            let label_elem = label_to_m31_elem(HFIPAY_ID_SALT_LABEL);
            let mut inputs = Vec::with_capacity(9 + 1);
            inputs.extend_from_slice(&rev_m31);
            inputs.push(label_elem);
            poseidon2_hash(&inputs)
        };
        // Extend salt from 8 hash elements to 9 bytes32 elements (pad with zero overflow)
        let mut salt_m31 = [M31(0u32); 9];
        salt_m31[..ELEMENTS_PER_HASH].copy_from_slice(&salt_hash);

        // domain = u64_to_domain_elements from label hash
        let id_domain_m31 = {
            let label_elem = label_to_m31_elem(HFIPAY_ID_DOMAIN_LABEL);
            u64_to_domain_elements(label_elem.0 as u64)
        };

        let identity_commitment = compute_id_com(&rev_m31, &salt_m31, &id_domain_m31);

        if binding_epoch >= 0x7FFF_FFFF {
            return Err(format!(
                "binding_epoch {} exceeds M31 field bound (must be < 0x7FFF_FFFF)",
                binding_epoch
            ));
        }
        let bind_ctx = DerivationContext {
            alg_id: label_to_m31_elem(HFIPAY_BIND_ALG_LABEL),
            domain: label_to_m31_elem(HFIPAY_BIND_DOMAIN_LABEL),
            index: M31(binding_epoch as u32),
        };
        let claim_binding_handle = compute_target(&rev_m31, &bind_ctx);

        return Ok(BindingMetadata {
            identity_commitment_hex: hash8_to_hex(&identity_commitment),
            claim_binding_handle_hex: hash8_to_hex(&claim_binding_handle),
            binding_epoch,
        });
    }

    #[cfg(not(feature = "zk"))]
    {
        let _ = mnemonic;
        let _ = binding_epoch;
        Err("HFI Pay binding derivation requires ace-gf built with the zk feature".to_string())
    }
}

pub fn default_binding_epoch() -> u64 {
    0
}

fn decode_rev32_mnemonic(mnemonic: &str) -> Result<[u8; 32], String> {
    let sealed = ACEGFCore::decode_mnemonic_to_sealed(mnemonic.trim())
        .map_err(|_| "invalid mnemonic format".to_string())?;
    if !AceRevGenerator::is_rev32(&sealed) {
        return Err("expected canonical REV32 mnemonic".to_string());
    }
    Ok(sealed)
}

pub fn identity_root_hex(mnemonic: &str, passphrase: &str) -> Result<String, String> {
    let rev = decode_rev32_mnemonic(mnemonic)?;
    let full_passphrase = PassphraseSealingUtil::combine_passphrase(passphrase, None);
    let kmaster =
        PassphraseSealingUtil::derive_kmaster_from_rev32(full_passphrase.as_bytes(), &rev)
            .map_err(|e| format!("kmaster derivation failed: {:?}", e))?;
    let identity_root = PassphraseSealingUtil::derive_identity_root(&kmaster)
        .map_err(|e| format!("identity root derivation failed: {:?}", e))?;
    Ok(hex::encode(&*identity_root))
}

/// Hash a label with SHA-256 and take the lower 31 bits as a single M31 element.
///
/// **Collision bound**: Only 31 bits of entropy — birthday threshold ~2^15.5 (~46K).
/// Safe for the small fixed set of internal HFI Pay labels. Do NOT use with
/// user-controlled or unbounded label inputs.
#[cfg(feature = "zk")]
fn label_to_m31_elem(label: &[u8]) -> M31 {
    let digest = Sha256::digest(label);
    let val = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]) & 0x7FFF_FFFF;
    M31(val)
}

/// Convert an 8-element M31 hash to a hex string (little-endian u32s).
#[cfg(feature = "zk")]
fn hash8_to_hex(elems: &[M31; ELEMENTS_PER_HASH]) -> String {
    let mut bytes = [0u8; 32];
    for (i, e) in elems.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&e.0.to_le_bytes());
    }
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acegf_core::ACEGFCore;
    use crate::pqclean_ffi::MlDsa44;

    const PASSPHRASE: &str = "test-pass";

    /// Generate a fresh ACE wallet and return its mnemonic.
    fn test_mnemonic() -> String {
        ACEGFCore::generate_ace_internal(PASSPHRASE, None)
            .expect("wallet generation must succeed")
            .mnemonic
            .to_string()
    }

    // Fixed 32-byte test values (all-zeros and all-ones for variety)
    const INTENT_ID: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const BLINDED: &str   = "0202020202020202020202020202020202020202020202020202020202020202";
    const AUTHORIZER: &str = "0303030303030303030303030303030303030303030303030303030303030303";
    const DEST: &str       = "0404040404040404040404040404040404040404040404040404040404040404";
    const MINT: &str       = "0505050505050505050505050505050505050505050505050505050505050505";

    // ── happy path: native token (no mint) ──────────────────────────────────────
    #[test]
    fn sign_refund_auth_native_happy_path() {
        let mnemonic = test_mnemonic();
        let result = sign_refund_auth(
            &mnemonic, PASSPHRASE,
            1,          // chain_tag: ACE mainnet
            None,       // native token
            INTENT_ID, BLINDED,
            1_000_000,  // amount
            AUTHORIZER, DEST,
            99_999,     // expiry slot
            0,          // nonce
        );
        let sig = result.expect("sign_refund_auth should succeed for native token");

        // message is a valid 32-byte SHA-256 hex
        assert_eq!(sig.message.len(), 64, "message should be 64 hex chars");
        assert!(sig.message.chars().all(|c| c.is_ascii_hexdigit()));

        // pubkey is ML-DSA-44 size
        let pk_bytes = base64ct::Base64::decode_vec(&sig.pubkey).expect("pubkey base64 decode");
        assert_eq!(pk_bytes.len(), MlDsa44::PK_BYTES, "pubkey must be ML-DSA-44 size");

        // signature is ML-DSA-44 size
        let sig_bytes = base64ct::Base64::decode_vec(&sig.signature).expect("sig base64 decode");
        assert_eq!(sig_bytes.len(), MlDsa44::SIG_BYTES, "signature must be ML-DSA-44 size");

        assert_eq!(sig.algorithm, 2);
    }

    // ── happy path: ERC-20/SPL token (with mint) ────────────────────────────────
    #[test]
    fn sign_refund_auth_with_mint_happy_path() {
        let mnemonic = test_mnemonic();
        let result = sign_refund_auth(
            &mnemonic, PASSPHRASE,
            1, Some(MINT),
            INTENT_ID, BLINDED,
            500,
            AUTHORIZER, DEST,
            200_000, 1,
        );
        let sig = result.expect("sign_refund_auth should succeed for token with mint");
        assert_eq!(sig.algorithm, 2);

        // Message must differ from native-token message (mint bytes affect the hash)
        let native = sign_refund_auth(
            &mnemonic, PASSPHRASE,
            1, None,
            INTENT_ID, BLINDED,
            500,
            AUTHORIZER, DEST,
            200_000, 1,
        ).unwrap();
        assert_ne!(sig.message, native.message, "mint vs no-mint messages must differ");
    }

    // ── determinism: same inputs → same output ───────────────────────────────────
    #[test]
    fn sign_refund_auth_is_deterministic() {
        let mnemonic = test_mnemonic();
        let a = sign_refund_auth(&mnemonic, PASSPHRASE, 1, None, INTENT_ID, BLINDED, 42, AUTHORIZER, DEST, 1000, 0).unwrap();
        let b = sign_refund_auth(&mnemonic, PASSPHRASE, 1, None, INTENT_ID, BLINDED, 42, AUTHORIZER, DEST, 1000, 0).unwrap();
        // message hash and pubkey are deterministic; ML-DSA-44 signing is randomized so
        // signatures may differ between calls — that is expected and correct per FIPS 204.
        assert_eq!(a.message, b.message);
        assert_eq!(a.pubkey, b.pubkey);
    }

    // ── domain separation: different inputs → different messages ─────────────────
    #[test]
    fn sign_refund_auth_message_varies_with_inputs() {
        let mnemonic = test_mnemonic();
        let base = sign_refund_auth(&mnemonic, PASSPHRASE, 1, None, INTENT_ID, BLINDED, 100, AUTHORIZER, DEST, 1000, 0).unwrap();

        let diff_amount = sign_refund_auth(&mnemonic, PASSPHRASE, 1, None, INTENT_ID, BLINDED, 999, AUTHORIZER, DEST, 1000, 0).unwrap();
        assert_ne!(base.message, diff_amount.message);

        let diff_nonce = sign_refund_auth(&mnemonic, PASSPHRASE, 1, None, INTENT_ID, BLINDED, 100, AUTHORIZER, DEST, 1000, 7).unwrap();
        assert_ne!(base.message, diff_nonce.message);

        let diff_chain = sign_refund_auth(&mnemonic, PASSPHRASE, 2, None, INTENT_ID, BLINDED, 100, AUTHORIZER, DEST, 1000, 0).unwrap();
        assert_ne!(base.message, diff_chain.message);
    }

    // ── unhappy path: invalid hex inputs ─────────────────────────────────────────
    // These don't require a valid mnemonic: the hex parse happens before unseal.
    #[test]
    fn sign_refund_auth_bad_intent_id() {
        let mnemonic = test_mnemonic();
        let err = sign_refund_auth(&mnemonic, PASSPHRASE, 1, None, "not_hex", BLINDED, 0, AUTHORIZER, DEST, 0, 0).unwrap_err();
        assert!(err.contains("intent_id"), "error should mention field name, got: {err}");
    }

    #[test]
    fn sign_refund_auth_bad_blinded_binding() {
        let mnemonic = test_mnemonic();
        let err = sign_refund_auth(&mnemonic, PASSPHRASE, 1, None, INTENT_ID, "deadbeef", 0, AUTHORIZER, DEST, 0, 0).unwrap_err();
        assert!(err.contains("blinded_binding"), "error should mention field name, got: {err}");
    }

    #[test]
    fn sign_refund_auth_bad_authorizer() {
        let mnemonic = test_mnemonic();
        let err = sign_refund_auth(&mnemonic, PASSPHRASE, 1, None, INTENT_ID, BLINDED, 0, "nothex!", DEST, 0, 0).unwrap_err();
        assert!(err.contains("refund_authorizer"), "error should mention field name, got: {err}");
    }

    #[test]
    fn sign_refund_auth_bad_dest() {
        let mnemonic = test_mnemonic();
        let err = sign_refund_auth(&mnemonic, PASSPHRASE, 1, None, INTENT_ID, BLINDED, 0, AUTHORIZER, "zz", 0, 0).unwrap_err();
        assert!(err.contains("refund_dest"), "error should mention field name, got: {err}");
    }

    #[test]
    fn sign_refund_auth_bad_mint_hex() {
        let mnemonic = test_mnemonic();
        let err = sign_refund_auth(&mnemonic, PASSPHRASE, 1, Some("not_hex"), INTENT_ID, BLINDED, 0, AUTHORIZER, DEST, 0, 0).unwrap_err();
        assert!(err.contains("mint"), "error should mention field name, got: {err}");
    }

    // ── unhappy path: wrong passphrase ────────────────────────────────────────────
    #[test]
    fn sign_refund_auth_wrong_passphrase() {
        let mnemonic = test_mnemonic();
        // Wrong passphrase must either fail to unseal or produce a different keypair.
        let result_bad = sign_refund_auth(&mnemonic, "definitely-wrong", 1, None, INTENT_ID, BLINDED, 0, AUTHORIZER, DEST, 0, 0);
        match result_bad {
            Err(_) => {} // unseal rejected — correct
            Ok(bad) => {
                let good = sign_refund_auth(&mnemonic, PASSPHRASE, 1, None, INTENT_ID, BLINDED, 0, AUTHORIZER, DEST, 0, 0).unwrap();
                assert_ne!(bad.pubkey, good.pubkey, "different passphrase must yield different keypair");
            }
        }
    }
}
