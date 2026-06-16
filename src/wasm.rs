// src/wasm.rs
//
// WASM bindings for ACE-GF Chrome extension wallet.
// Exposes wallet generation, viewing, Solana signing, and VA-DAR functions to JavaScript.

use bs58;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::acegf::ACEGF;
use crate::acegf_core::ACEGFCore;
use crate::signer::bitcoin_signer::{TxInput, TxOutput, UnsignedTx};
use crate::signer::BitcoinSigner;
use crate::signer::EvmSigner;
use crate::signer::SolanaSigner;
use crate::signer::TronSigner;
use crate::vadar::VADAR;
use ed25519_dalek::Signer as Ed25519Signer;
use zeroize::{Zeroize, Zeroizing};

// =====================================================
// Error response struct for JS interop
// =====================================================

#[derive(Serialize)]
struct WasmError {
    error: bool,
    message: String,
}

// Install a panic hook so panics print to the browser console
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

// =====================================================
// WasmWallet struct for JS interop
// =====================================================

#[derive(Serialize)]
pub struct WasmWallet {
    pub mnemonic: String,
    pub solana_address: String,
    pub evm_address: String,
    pub tron_address: String,
    pub bitcoin_address: String,
    pub cosmos_address: String,
    pub polkadot_address: String,
    pub xaddress: String,
    pub x25519: String,
    /// Base64-encoded ML-KEM-768 encapsulation key (post-quantum KEM identity).
    pub xkem: String,
    pub xid: String,
}

// =====================================================
// Wallet Generation
// =====================================================

#[wasm_bindgen]
pub fn generate_wasm(passphrase: &str) -> JsValue {
    generate_with_secondary_wasm(passphrase, None)
}

#[wasm_bindgen]
pub fn generate_with_secondary_wasm(
    passphrase: &str,
    secondary_passphrase: Option<String>,
) -> JsValue {
    let sec_pass = secondary_passphrase.as_deref();

    match ACEGFCore::generate_ace_internal(passphrase, sec_pass) {
        Ok(entity) => {
            let js_wallet = WasmWallet {
                mnemonic: entity.mnemonic.to_string(),
                solana_address: entity.solana_address,
                evm_address: entity.evm_address,
                tron_address: entity.tron_address,
                bitcoin_address: entity.bitcoin_address,
                cosmos_address: entity.cosmos_address,
                polkadot_address: entity.polkadot_address,
                xaddress: entity.xaddress,
                x25519: entity.x25519,
                xkem: entity.xkem,
                xid: entity.xid,
            };
            #[allow(deprecated)]
            match JsValue::from_serde(&js_wallet) {
                Ok(val) => val,
                Err(e) => {
                    let err = WasmError {
                        error: true,
                        message: format!("Serialization failed: {}", e),
                    };
                    #[allow(deprecated)]
                    JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
                }
            }
        }
        Err(e) => {
            let err = WasmError {
                error: true,
                message: format!("Wallet generation failed: {}", e),
            };
            #[allow(deprecated)]
            JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
        }
    }
}

// =====================================================
// View Wallet (restore from mnemonic)
// =====================================================

#[wasm_bindgen]
pub fn view_wallet_wasm(mnemonic: &str, passphrase: &str) -> JsValue {
    view_wallet_with_secondary_wasm(mnemonic, passphrase, None)
}

#[wasm_bindgen]
pub fn view_wallet_with_secondary_wasm(
    mnemonic: &str,
    passphrase: &str,
    secondary_passphrase: Option<String>,
) -> JsValue {
    let sec_pass = secondary_passphrase.as_deref();

    match ACEGFCore::view_wallet_internal(mnemonic, passphrase, sec_pass) {
        Ok(entity) => {
            let js_wallet = WasmWallet {
                mnemonic: entity.mnemonic.to_string(),
                solana_address: entity.solana_address,
                evm_address: entity.evm_address,
                tron_address: entity.tron_address,
                bitcoin_address: entity.bitcoin_address,
                cosmos_address: entity.cosmos_address,
                polkadot_address: entity.polkadot_address,
                xaddress: entity.xaddress,
                x25519: entity.x25519,
                xkem: entity.xkem,
                xid: entity.xid,
            };
            #[allow(deprecated)]
            match JsValue::from_serde(&js_wallet) {
                Ok(val) => val,
                Err(e) => {
                    let err = WasmError {
                        error: true,
                        message: format!("Serialization failed: {}", e),
                    };
                    #[allow(deprecated)]
                    JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
                }
            }
        }
        Err(e) => {
            let err = WasmError {
                error: true,
                message: format!("View wallet failed: {}", e),
            };
            #[allow(deprecated)]
            JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
        }
    }
}

// =====================================================
// Signing
// =====================================================

/// Sign message - returns base64 signature on success, or "error:..." on failure
#[wasm_bindgen]
pub fn acegf_sign_message_wasm(
    mnemonic: &str,
    passphrase: &str,
    message: &[u8],
    curve: u32,
) -> String {
    acegf_sign_message_with_secondary_wasm(mnemonic, passphrase, None, message, curve)
}

/// Sign message - returns signature bytes on success, or error string prefixed with "error:" on failure
#[wasm_bindgen]
pub fn acegf_sign_message_with_secondary_wasm(
    mnemonic: &str,
    passphrase: &str,
    secondary_passphrase: Option<String>,
    message: &[u8],
    curve: u32,
) -> String {
    let sec_pass = secondary_passphrase.as_deref();

    match ACEGF::sign_message_internal(mnemonic, passphrase, sec_pass, message, curve) {
        Ok(sig) => {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(&sig)
        }
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// X25519 Sign/Verify
// =====================================================

/// X25519 sign - returns base64 signature on success, or "error:..." on failure
#[wasm_bindgen]
pub fn acegf_x25519_sign_wasm(mnemonic: &str, passphrase: &str, message: &[u8]) -> String {
    match ACEGF::sign_message_internal(mnemonic, passphrase, None, message, 0) {
        Ok(sig) => {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(&sig)
        }
        Err(e) => format!("error:{}", e),
    }
}

/// X25519 verify - returns "true", "false", or "error:..." on failure
#[wasm_bindgen]
pub fn acegf_x25519_verify_wasm(
    x25519_b64: &str,
    message: &[u8],
    signature: &[u8],
) -> String {
    match ACEGF::x25519_verify_internal(x25519_b64, message, signature) {
        Ok(valid) => {
            if valid {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// DH Shared Key
// =====================================================

/// Compute DH shared key - returns base64-encoded key on success, or "error:..." on failure
#[wasm_bindgen]
pub fn acegf_compute_dh_key_wasm(mnemonic: &str, passphrase: &str, peer_pub_b64: &str) -> String {
    match ACEGF::compute_dh_key_internal(mnemonic, passphrase, peer_pub_b64, None) {
        Ok(key) => {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(&key)
        }
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// Passphrase Rotation
// =====================================================

#[wasm_bindgen]
pub fn acegf_change_passphrase_wasm(
    mnemonic: &str,
    old_passphrase: &str,
    new_passphrase: &str,
) -> Option<String> {
    ACEGFCore::change_passphrase_internal(mnemonic, old_passphrase, new_passphrase, None).ok()
}

/// Same as change_passphrase but with AdminFactor as secondary_passphrase (for path credential generation).
/// Use for wallets that were CREATED with secondary. Returns new mnemonic on success, None on failure.
#[wasm_bindgen]
pub fn acegf_change_passphrase_with_admin_wasm(
    existing_mnemonic: &str,
    existing_passphrase: &str,
    new_passphrase: &str,
    admin_factor: &str,
) -> Option<String> {
    let secondary = if admin_factor.is_empty() {
        None
    } else {
        Some(admin_factor)
    };
    ACEGFCore::change_passphrase_internal(
        existing_mnemonic,
        existing_passphrase,
        new_passphrase,
        secondary,
    )
    .ok()
}

/// Change passphrase for wallets created WITHOUT secondary (e.g. extension via generate_wasm).
/// Unseals with (existing_passphrase, None), seals with (new_passphrase, Some(admin_factor)).
/// Use this for extension wallets. Returns new mnemonic on success, None on failure.
#[wasm_bindgen]
pub fn acegf_change_passphrase_add_admin_wasm(
    existing_mnemonic: &str,
    existing_passphrase: &str,
    new_passphrase: &str,
    admin_factor: &str,
) -> Option<String> {
    ACEGFCore::change_passphrase_add_admin_internal(
        existing_mnemonic,
        existing_passphrase,
        new_passphrase,
        admin_factor,
    )
    .ok()
}

// =====================================================
// AES Encrypt (for x25519 recipient)
// =====================================================

#[derive(serde::Serialize)]
struct EncryptedPayload {
    ephemeral_pub: String,
    encrypted_aes_key: String,
    iv: String,
    encrypted_data: String, // base64 encoded
}

/// Encrypt data for a recipient's x25519 public key
/// Returns JSON: { ephemeral_pub, encrypted_aes_key, iv, encrypted_data }
/// or "error:..." on failure
#[wasm_bindgen]
pub fn acegf_encrypt_for_x25519(recipient_x25519_b64: &str, plaintext: &[u8]) -> String {
    match ACEGF::encrypt_for_x25519(recipient_x25519_b64, plaintext) {
        Ok((ephemeral_pub, encrypted_aes_key, iv, encrypted_data)) => {
            use base64ct::{Base64, Encoding};
            let payload = EncryptedPayload {
                ephemeral_pub,
                encrypted_aes_key,
                iv,
                encrypted_data: Base64::encode_string(&encrypted_data),
            };
            serde_json::to_string(&payload)
                .unwrap_or_else(|e| format!("error:serialization failed: {}", e))
        }
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// AES Decrypt
// =====================================================

/// Decrypt with mnemonic - returns base64-encoded plaintext on success, or "error:..." on failure
#[wasm_bindgen]
pub fn acegf_decrypt_with_mnemonic_wasm(
    mnemonic: &str,
    passphrase: &str,
    ephemeral_pub_b64: &str,
    encrypted_aes_key_b64: &str,
    iv_b64: &str,
    encrypted_data: &[u8],
) -> String {
    match ACEGF::decrypt_internal(
        mnemonic,
        passphrase,
        ephemeral_pub_b64,
        encrypted_aes_key_b64,
        iv_b64,
        encrypted_data,
        None,
    ) {
        Ok(plaintext) => {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(&plaintext)
        }
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// Hybrid X25519 + ML-KEM-768 Encrypt / Decrypt — THE NEW DEFAULT
//
// These functions fully replace `acegf_encrypt_for_x25519` /
// `acegf_decrypt_with_mnemonic_wasm` for any new code path that needs to be
// post-quantum safe (i.e., all of them). The legacy pair is retained
// unchanged only so existing ciphertexts remain readable.
//
// Wire format: `HybridEncryptedPayload` serialized as a JSON object:
//   {
//     "v": "acegf-hybrid-kem-v1",
//     "ephemeral_x25519_pub_b64": "...",   // 32B X25519 ephemeral pub
//     "kem_ciphertext_b64": "...",          // 1088B ML-KEM-768 ciphertext
//     "iv_b64": "...",                       // 12B AES-GCM IV
//     "ciphertext": [ ... ]                  // AES-256-GCM encrypted bytes
//   }
// =====================================================

/// Encrypt `plaintext` for a recipient using hybrid X25519 + ML-KEM-768.
///
/// Both `recipient_x25519_b64` and `recipient_xkem_b64` are required —
/// there is no silent fallback. This is the **default** encryption path
/// going forward.
///
/// On success returns a JSON string encoding a `HybridEncryptedPayload`.
/// On failure returns `"error:..."`.
#[wasm_bindgen]
pub fn acegf_encrypt_for_recipient_pq_wasm(
    recipient_x25519_b64: &str,
    recipient_xkem_b64: &str,
    plaintext: &[u8],
) -> String {
    match ACEGF::encrypt_for_recipient_pq(recipient_x25519_b64, recipient_xkem_b64, plaintext) {
        Ok(payload) => serde_json::to_string(&payload)
            .unwrap_or_else(|e| format!("error:serialization failed: {}", e)),
        Err(e) => format!("error:{}", e),
    }
}

/// Decrypt a hybrid encrypted payload (provided as its JSON string form)
/// using `mnemonic + passphrase`.
///
/// The version field of the payload is checked with strict equality; any
/// deviation fails hard (no downgrade to the legacy X25519 path).
///
/// On success returns the plaintext as a Base64 string. On failure returns
/// `"error:..."`.
#[wasm_bindgen]
pub fn acegf_decrypt_for_recipient_pq_wasm(
    mnemonic: &str,
    passphrase: &str,
    payload_json: &str,
) -> String {
    use crate::acegf::HybridEncryptedPayload;

    let payload: HybridEncryptedPayload = match serde_json::from_str(payload_json) {
        Ok(p) => p,
        Err(e) => return format!("error:failed to parse HybridEncryptedPayload JSON: {}", e),
    };

    match ACEGF::decrypt_for_recipient_pq(mnemonic, passphrase, &payload, None) {
        Ok(plaintext) => {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(&plaintext)
        }
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// Hybrid Envelope v2 (Deterministic Wrap) — WASM exports
// =====================================================
// See `src/acegf.rs` for the full protocol description. These are the
// surfaces consumed by the Yallet chrome extension and rwa-sdk after
// the 2026-04-10 architecture redesign.

/// Encrypt `plaintext` using the v2 deterministic hybrid-KEM envelope.
///
/// Parameters:
/// * `mnemonic` / `passphrase` — sender's wallet (required: v2 derives
///   `wrap_master` from the sender's keys).
/// * `recipient_x25519_b64` — recipient's X25519 public key.
/// * `recipient_xkem_b64` — recipient's ML-KEM-768 encaps key.
/// * `nonce_b64` — 16-byte Base64 nonce. Pass an empty string to have
///   the WASM generate a fresh random 16-byte nonce; pass a stored
///   nonce to reproduce an existing wrap deterministically.
/// * `plaintext` — bytes to seal.
///
/// Returns a JSON string of [`HybridEncryptedV2Payload`] on success, or
/// `"error:..."` on failure.
#[wasm_bindgen]
pub fn acegf_encrypt_for_recipient_pq_v2_wasm(
    mnemonic: &str,
    passphrase: &str,
    recipient_x25519_b64: &str,
    recipient_xkem_b64: &str,
    nonce_b64: &str,
    plaintext: &[u8],
) -> String {
    use base64ct::{Base64, Encoding};

    // Optional caller-supplied nonce. Empty string ⇒ fresh random.
    let nonce_arr_opt: Option<[u8; 16]> = if nonce_b64.is_empty() {
        None
    } else {
        match Base64::decode_vec(nonce_b64) {
            Ok(v) if v.len() == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&v);
                Some(a)
            }
            Ok(v) => {
                return format!(
                    "error:nonce must be 16 bytes after base64 decode, got {}",
                    v.len()
                );
            }
            Err(e) => return format!("error:failed to decode nonce base64: {}", e),
        }
    };

    let result = ACEGF::encrypt_for_recipient_pq_v2(
        mnemonic,
        passphrase,
        recipient_x25519_b64,
        recipient_xkem_b64,
        nonce_arr_opt.as_ref(),
        plaintext,
    );

    match result {
        Ok(payload) => serde_json::to_string(&payload)
            .unwrap_or_else(|e| format!("error:serialization failed: {}", e)),
        Err(e) => format!("error:{}", e),
    }
}

/// Decrypt a v2 hybrid envelope using `mnemonic + passphrase`.
///
/// `payload_json` must be the JSON-serialized form of a
/// [`HybridEncryptedV2Payload`]. On success returns the plaintext as a
/// Base64 string; on failure returns `"error:..."`.
#[wasm_bindgen]
pub fn acegf_decrypt_for_recipient_pq_v2_wasm(
    mnemonic: &str,
    passphrase: &str,
    payload_json: &str,
) -> String {
    use crate::acegf::HybridEncryptedV2Payload;

    let payload: HybridEncryptedV2Payload = match serde_json::from_str(payload_json) {
        Ok(p) => p,
        Err(e) => return format!("error:failed to parse HybridEncryptedV2Payload JSON: {}", e),
    };

    match ACEGF::decrypt_for_recipient_pq_v2(mnemonic, passphrase, &payload, None) {
        Ok(plaintext) => {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(&plaintext)
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Decrypt a v2 hybrid envelope using a pre-derived PRF `base_key`
/// (passkey / WebAuthn PRF path). Mirrors
/// `acegf_decrypt_for_recipient_pq_v2_wasm` but skips the Argon2id step.
#[wasm_bindgen]
pub fn acegf_decrypt_for_recipient_pq_v2_with_prf_wasm(
    mnemonic: &str,
    prf_key: &[u8],
    payload_json: &str,
) -> String {
    use crate::acegf::HybridEncryptedV2Payload;

    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    let payload: HybridEncryptedV2Payload = match serde_json::from_str(payload_json) {
        Ok(p) => p,
        Err(e) => return format!("error:failed to parse HybridEncryptedV2Payload JSON: {}", e),
    };

    match ACEGF::decrypt_for_recipient_pq_v2_with_base_key(mnemonic, &base_key, &payload) {
        Ok(plaintext) => {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(&plaintext)
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Regenerate the deterministic `wrap` portion of a v2 envelope.
///
/// Disaster-recovery helper. The sender can rebuild a byte-identical
/// `wrap` object given the original nonce and the recipient's keys
/// (see architecture §5.4 / §15.3). This does NOT regenerate the
/// `blob`, which is non-deterministic.
///
/// Parameters:
/// * `mnemonic` / `passphrase` — sender's wallet.
/// * `recipient_x25519_b64` — recipient's X25519 public key.
/// * `recipient_xkem_b64` — recipient's ML-KEM-768 encaps key.
/// * `nonce_b64` — the original 16-byte Base64 nonce (required).
///
/// Returns a JSON string of [`HybridEncryptedV2Wrap`] on success, or
/// `"error:..."` on failure.
#[wasm_bindgen]
pub fn acegf_regenerate_wrap_v2_wasm(
    mnemonic: &str,
    passphrase: &str,
    recipient_x25519_b64: &str,
    recipient_xkem_b64: &str,
    nonce_b64: &str,
) -> String {
    let result = ACEGF::regenerate_wrap_v2(
        mnemonic,
        passphrase,
        recipient_x25519_b64,
        recipient_xkem_b64,
        nonce_b64,
    );

    match result {
        Ok(wrap) => serde_json::to_string(&wrap)
            .unwrap_or_else(|e| format!("error:serialization failed: {}", e)),
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// PRF-backed functions (Passkey Secure Enclave path)
// =====================================================
// These functions accept a 32-byte PRF key from WebAuthn instead of a passphrase string.
// The PRF key is fed through Argon2 to derive the base_key, same as passphrase path.
// Benefit: passphrase never appears as plaintext in JavaScript memory.

/// Derive base_key from PRF key (runs Argon2 once)
/// This is the shared helper — all _with_prf functions below use this.
fn derive_base_key_from_prf(prf_key: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;
    PassphraseSealingUtil::derive_base_key(prf_key)
        .map_err(|e| format!("PRF key derivation failed: {:?}", e))
}

/// View wallet using PRF key (skips passphrase decryption in JS)
#[wasm_bindgen]
pub fn view_wallet_with_prf_wasm(mnemonic: &str, prf_key: &[u8]) -> JsValue {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => {
            let err = WasmError {
                error: true,
                message: e,
            };
            #[allow(deprecated)]
            return JsValue::from_serde(&err).unwrap_or(JsValue::NULL);
        }
    };

    match ACEGFCore::view_wallet_with_base_key(mnemonic, &base_key) {
        Ok(entity) => {
            let js_wallet = WasmWallet {
                mnemonic: entity.mnemonic.to_string(),
                solana_address: entity.solana_address,
                evm_address: entity.evm_address,
                tron_address: entity.tron_address,
                bitcoin_address: entity.bitcoin_address,
                cosmos_address: entity.cosmos_address,
                polkadot_address: entity.polkadot_address,
                xaddress: entity.xaddress,
                x25519: entity.x25519,
                xkem: entity.xkem,
                xid: entity.xid,
            };
            #[allow(deprecated)]
            match JsValue::from_serde(&js_wallet) {
                Ok(val) => val,
                Err(e) => {
                    let err = WasmError {
                        error: true,
                        message: format!("Serialization failed: {}", e),
                    };
                    #[allow(deprecated)]
                    JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
                }
            }
        }
        Err(e) => {
            let err = WasmError {
                error: true,
                message: format!("View wallet failed: {}", e),
            };
            #[allow(deprecated)]
            JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
        }
    }
}

/// Sign message using PRF key
#[wasm_bindgen]
pub fn acegf_sign_message_with_prf_wasm(
    mnemonic: &str,
    prf_key: &[u8],
    message: &[u8],
    curve: u32,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match ACEGF::sign_message_with_base_key(mnemonic, &base_key, message, curve) {
        Ok(sig) => {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(&sig)
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Compute DH shared key using PRF key
#[wasm_bindgen]
pub fn acegf_compute_dh_key_with_prf_wasm(
    mnemonic: &str,
    prf_key: &[u8],
    peer_pub_b64: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match ACEGF::compute_dh_key_with_base_key_and_peer(mnemonic, &base_key, peer_pub_b64) {
        Ok(key) => {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(&key)
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Decrypt with PRF key (no passphrase in JS)
#[wasm_bindgen]
pub fn acegf_decrypt_with_prf_wasm(
    mnemonic: &str,
    prf_key: &[u8],
    ephemeral_pub_b64: &str,
    encrypted_aes_key_b64: &str,
    iv_b64: &str,
    encrypted_data: &[u8],
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match ACEGF::decrypt_with_base_key(
        mnemonic,
        &base_key,
        ephemeral_pub_b64,
        encrypted_aes_key_b64,
        iv_b64,
        encrypted_data,
    ) {
        Ok(plaintext) => {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(&plaintext)
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Sign EVM Type-0 Transaction using PRF key
#[wasm_bindgen]
pub fn evm_sign_type0_transaction_with_prf(
    mnemonic: &str,
    prf_key: &[u8],
    chain_id: u64,
    nonce: &str,
    gas_price: &str,
    gas_limit: &str,
    to: &str,
    value: &str,
    data: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match EvmSigner::derive_keypair_with_base_key(mnemonic, &base_key) {
        Ok((signing_key, _addr)) => {
            match EvmSigner::sign_type0_transaction_with_key(
                &signing_key,
                chain_id,
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
            ) {
                Ok(signed_tx) => signed_tx,
                Err(e) => format!("error:{}", e),
            }
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Backward-compatible alias for `evm_sign_type0_transaction_with_prf`.
#[wasm_bindgen]
pub fn evm_sign_legacy_transaction_with_prf(
    mnemonic: &str,
    prf_key: &[u8],
    chain_id: u64,
    nonce: &str,
    gas_price: &str,
    gas_limit: &str,
    to: &str,
    value: &str,
    data: &str,
) -> String {
    evm_sign_type0_transaction_with_prf(
        mnemonic, prf_key, chain_id, nonce, gas_price, gas_limit, to, value, data,
    )
}

/// Sign EVM EIP-1559 Transaction using PRF key
#[wasm_bindgen]
pub fn evm_sign_eip1559_transaction_with_prf(
    mnemonic: &str,
    prf_key: &[u8],
    chain_id: u64,
    nonce: &str,
    max_priority_fee_per_gas: &str,
    max_fee_per_gas: &str,
    gas_limit: &str,
    to: &str,
    value: &str,
    data: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match EvmSigner::derive_keypair_with_base_key(mnemonic, &base_key) {
        Ok((signing_key, _addr)) => {
            match EvmSigner::sign_eip1559_transaction_with_key(
                &signing_key,
                chain_id,
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
                to,
                value,
                data,
            ) {
                Ok(signed_tx) => signed_tx,
                Err(e) => format!("error:{}", e),
            }
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Sign EVM personal message using PRF key
#[wasm_bindgen]
pub fn evm_sign_personal_message_with_prf(mnemonic: &str, prf_key: &[u8], message: &str) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match EvmSigner::derive_keypair_with_base_key(mnemonic, &base_key) {
        Ok((signing_key, _addr)) => {
            match EvmSigner::sign_personal_message_with_key(&signing_key, message.as_bytes()) {
                Ok(signature) => signature,
                Err(e) => format!("error:{}", e),
            }
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Sign EVM typed data using PRF key
#[wasm_bindgen]
pub fn evm_sign_typed_data_with_prf(
    mnemonic: &str,
    prf_key: &[u8],
    typed_data_hash: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match EvmSigner::derive_keypair_with_base_key(mnemonic, &base_key) {
        Ok((signing_key, _addr)) => {
            match EvmSigner::sign_typed_data_with_key(&signing_key, typed_data_hash) {
                Ok(signature) => signature,
                Err(e) => format!("error:{}", e),
            }
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Get EVM address using PRF key
#[wasm_bindgen]
pub fn evm_get_address_with_prf(mnemonic: &str, prf_key: &[u8]) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match EvmSigner::derive_keypair_with_base_key(mnemonic, &base_key) {
        Ok((_signing_key, addr)) => {
            // Format as checksummed hex address
            format!("0x{}", hex::encode(addr))
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Sign Solana system transfer using PRF key
#[wasm_bindgen]
pub fn solana_sign_system_transfer_with_prf(
    mnemonic: &str,
    prf_key: &[u8],
    to_pubkey: &str,
    lamports: u64,
    recent_blockhash: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match SolanaSigner::derive_keypair_with_base_key(mnemonic, &base_key) {
        Ok((signing_key, _verifying_key)) => {
            match SolanaSigner::sign_system_transfer_with_key(
                &signing_key,
                to_pubkey,
                lamports,
                recent_blockhash,
            ) {
                Ok(tx_bytes) => {
                    use base64ct::{Base64, Encoding};
                    Base64::encode_string(&tx_bytes)
                }
                Err(e) => format!("error:{}", e),
            }
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Sign Solana external transaction using PRF key
#[wasm_bindgen]
pub fn solana_sign_transaction_with_prf(
    mnemonic: &str,
    prf_key: &[u8],
    serialized_tx_base64: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match SolanaSigner::derive_keypair_with_base_key(mnemonic, &base_key) {
        Ok((signing_key, _verifying_key)) => {
            match SolanaSigner::sign_serialized_transaction_with_key(
                &signing_key,
                serialized_tx_base64,
            ) {
                Ok(signed_tx) => signed_tx,
                Err(e) => format!("error:{}", e),
            }
        }
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// Solana System Transfer
// =====================================================

#[wasm_bindgen]
pub fn solana_sign_system_transfer(
    mnemonic: &str,
    passphrase: &str,
    to_pubkey: &str,
    lamports: u64,
    recent_blockhash: &str,
) -> String {
    solana_sign_system_transfer_with_secondary(
        mnemonic,
        passphrase,
        None,
        to_pubkey,
        lamports,
        recent_blockhash,
    )
}

#[wasm_bindgen]
pub fn solana_sign_system_transfer_with_secondary(
    mnemonic: &str,
    passphrase: &str,
    secondary_passphrase: Option<String>,
    to_pubkey: &str,
    lamports: u64,
    recent_blockhash: &str,
) -> String {
    let sec_pass = secondary_passphrase.as_deref();

    match SolanaSigner::sign_system_transfer_tx(
        mnemonic,
        passphrase,
        sec_pass,
        to_pubkey,
        lamports,
        recent_blockhash,
    ) {
        Ok(tx_bytes) => {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(&tx_bytes)
        }
        Err(e) => {
            format!("error:{}", e)
        }
    }
}

/// Sign an SPL Token transfer
///
/// Args:
/// - mnemonic
/// - passphrase
/// - mint: SPL Token mint (base58)
/// - to_wallet: recipient wallet (base58, not ATA; ATA is derived here)
/// - amount: raw amount (already scaled by 10^decimals)
/// - recent_blockhash: latest blockhash
///
/// Returns: base64-encoded signed transaction
#[wasm_bindgen]
pub fn solana_sign_spl_transfer(
    mnemonic: &str,
    passphrase: &str,
    mint: &str,
    to_wallet: &str,
    amount: u64,
    recent_blockhash: &str,
) -> String {
    match SolanaSigner::sign_spl_transfer_tx(
        mnemonic,
        passphrase,
        mint,
        to_wallet,
        amount,
        recent_blockhash,
    ) {
        Ok(tx_bytes) => {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(&tx_bytes)
        }
        Err(e) => {
            format!("error:{}", e)
        }
    }
}

/// Get the Associated Token Account (ATA) address
///
/// Args:
/// - wallet: wallet pubkey (base58)
/// - mint: token mint (base58)
///
/// Returns: ATA address (base58)
#[wasm_bindgen]
pub fn solana_get_ata_address(wallet: &str, mint: &str) -> String {
    let wallet_bytes = match bs58::decode(wallet).into_vec() {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return "error:invalid wallet address".to_string(),
    };

    let mint_bytes = match bs58::decode(mint).into_vec() {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return "error:invalid mint address".to_string(),
    };

    match SolanaSigner::get_associated_token_address(&wallet_bytes, &mint_bytes) {
        Ok(ata) => bs58::encode(ata).into_string(),
        Err(e) => format!("error:{}", e),
    }
}

/// Sign an SPL Token transfer, creating the destination ATA if needed
///
/// Use when the recipient has no ATA yet. The tx has two instructions:
/// createAssociatedTokenAccount + Transfer.
///
/// Args: same as `solana_sign_spl_transfer`.
///
/// Returns: base64-encoded signed transaction
#[wasm_bindgen]
pub fn solana_sign_spl_transfer_with_create_ata(
    mnemonic: &str,
    passphrase: &str,
    mint: &str,
    to_wallet: &str,
    amount: u64,
    recent_blockhash: &str,
) -> String {
    match SolanaSigner::sign_spl_transfer_with_create_ata_tx(
        mnemonic,
        passphrase,
        mint,
        to_wallet,
        amount,
        recent_blockhash,
    ) {
        Ok(tx_bytes) => {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(&tx_bytes)
        }
        Err(e) => {
            format!("error:{}", e)
        }
    }
}

// =====================================================
// Sign External Transaction (for Jupiter Swap, etc.)
// =====================================================

/// Sign an externally built serialized transaction (legacy format)
///
/// Args:
/// - mnemonic, passphrase, serialized_tx_base64 (base64)
///
/// Returns: base64 signed tx, or `"error:..."` on failure
#[wasm_bindgen]
pub fn solana_sign_transaction(
    mnemonic: &str,
    passphrase: &str,
    serialized_tx_base64: &str,
) -> String {
    match SolanaSigner::sign_serialized_transaction(mnemonic, passphrase, serialized_tx_base64) {
        Ok(signed_tx) => signed_tx,
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// VA-DAR (Vendor-Agnostic Deterministic Artifact Resolution)
// =====================================================

/// Normalize email for VA-DAR
/// - Lowercase
/// - Trim whitespace
/// - Remove dots from local part
/// - Remove +suffix from local part
#[wasm_bindgen]
pub fn vadar_normalize_email(email: &str) -> String {
    VADAR::normalize_email(email)
}

/// Compute Discovery ID from password and normalized email
/// Returns hex-encoded 32-byte discovery ID, or "error:..." on failure
#[wasm_bindgen]
pub fn vadar_compute_discovery_id(password: &str, normalized_email: &str) -> String {
    match VADAR::compute_discovery_id(password, normalized_email) {
        Ok(id) => id,
        Err(e) => format!("error:{}", e),
    }
}

/// Seal mnemonic into SA2 artifact
/// Returns base64-encoded SA2, or "error:..." on failure
#[wasm_bindgen]
pub fn vadar_seal_sa2(mnemonic: &str, password: &str, normalized_email: &str) -> String {
    match VADAR::seal_sa2(mnemonic, password, normalized_email) {
        Ok(sa2) => sa2,
        Err(e) => format!("error:{}", e),
    }
}

/// Unseal SA2 artifact to recover mnemonic
/// Returns mnemonic string, or "error:..." on failure
#[wasm_bindgen]
pub fn vadar_unseal_sa2(sa2_base64: &str, password: &str, normalized_email: &str) -> String {
    match VADAR::unseal_sa2(sa2_base64, password, normalized_email) {
        Ok(mnemonic) => mnemonic,
        Err(e) => format!("error:{}", e),
    }
}

/// Get owner public key for registry authorization
/// Returns base64-encoded Ed25519 public key, or "error:..." on failure
#[wasm_bindgen]
pub fn vadar_get_owner_pubkey(password: &str, normalized_email: &str) -> String {
    match VADAR::get_owner_pubkey(password, normalized_email) {
        Ok(pubkey) => pubkey,
        Err(e) => format!("error:{}", e),
    }
}

/// Sign registry update for create/update operations
/// Returns base64-encoded Ed25519 signature, or "error:..." on failure
#[wasm_bindgen]
pub fn vadar_sign_registry_update(
    password: &str,
    normalized_email: &str,
    discovery_id: &str,
    cid: &str,
    version: u64,
    commit: &str,
) -> String {
    match VADAR::sign_registry_update(
        password,
        normalized_email,
        discovery_id,
        cid,
        version,
        commit,
    ) {
        Ok(sig) => sig,
        Err(e) => format!("error:{}", e),
    }
}

/// Compute commit hash of SA2 artifact
/// Returns hex-encoded SHA256 hash, or "error:..." on failure
#[wasm_bindgen]
pub fn vadar_compute_commit(sa2_base64: &str) -> String {
    match VADAR::compute_commit(sa2_base64) {
        Ok(commit) => commit,
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// HFI Pay Registration
// =====================================================

/// Compute the HFI Pay registration message hash.
///
/// `SHA-256("hfipay:register" || xid_bytes || identifier_bytes)`
///
/// Returns hex-encoded 32-byte message hash, or "error:..." on failure.
#[wasm_bindgen]
pub fn hfi_pay_registration_message(xid_hex: &str, identifier: &str) -> String {
    crate::hfi_pay::registration_message(xid_hex, identifier)
}

/// Sign the HFI Pay registration message with the wallet's Ed25519 key.
///
/// Returns a JSON string: `{"pubkey":"<base64>","signature":"<base64>","message":"<hex>"}`,
/// or "error:..." on failure.
#[wasm_bindgen]
pub fn hfi_pay_sign_registration(
    mnemonic: &str,
    passphrase: &str,
    xid_hex: &str,
    identifier: &str,
) -> String {
    match crate::hfi_pay::sign_registration(mnemonic, passphrase, xid_hex, identifier) {
        Ok(reg) => format!(
            "{{\"pubkey\":\"{}\",\"signature\":\"{}\",\"message\":\"{}\",\"pubkey_hex\":\"{}\",\"algorithm\":{}}}",
            reg.pubkey, reg.signature, reg.message, reg.pubkey_hex, reg.algorithm,
        ),
        Err(e) => format!("error:{}", e),
    }
}

/// Pre-sign a refund authorization for an HFI Pay intent.
///
/// Returns a JSON string: `{"pubkey":"<base64>","signature":"<base64>","message":"<hex>","pubkey_hex":"<hex>","algorithm":2}`,
/// or "error:..." on failure.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn hfi_pay_sign_refund_auth(
    mnemonic: &str,
    passphrase: &str,
    chain_tag: u8,
    mint_hex: &str,         // "" for native token
    intent_id_hex: &str,
    blinded_binding_hex: &str,
    amount: u64,
    refund_authorizer_hex: &str,
    refund_dest_hex: &str,
    expiry: u64,
    nonce: u64,
) -> String {
    let mint = if mint_hex.is_empty() { None } else { Some(mint_hex) };
    match crate::hfi_pay::sign_refund_auth(
        mnemonic, passphrase, chain_tag, mint,
        intent_id_hex, blinded_binding_hex,
        amount, refund_authorizer_hex, refund_dest_hex, expiry, nonce,
    ) {
        Ok(r) => format!(
            "{{\"pubkey\":\"{}\",\"signature\":\"{}\",\"message\":\"{}\",\"pubkey_hex\":\"{}\",\"algorithm\":{}}}",
            r.pubkey, r.signature, r.message, r.pubkey_hex, r.algorithm,
        ),
        Err(e) => format!("error:{}", e),
    }
}

/// Get the Ed25519 public key used for HFI Pay claim authorization.
///
/// Returns hex-encoded 32-byte public key, or "error:..." on failure.
#[wasm_bindgen]
pub fn hfi_pay_claim_pubkey_hex(mnemonic: &str, passphrase: &str) -> String {
    match crate::hfi_pay::claim_pubkey_hex(mnemonic, passphrase) {
        Ok(pubkey_hex) => pubkey_hex,
        Err(e) => format!("error:{}", e),
    }
}

/// Derive the verified-quote binding metadata used by HFI Pay registration.
///
/// Returns a JSON string:
/// `{"identity_commitment_hex":"<hex>","claim_binding_handle_hex":"<hex>","binding_epoch":0}`
/// or "error:..." on failure.
#[wasm_bindgen]
pub fn hfi_pay_derive_binding_wasm(mnemonic: &str, passphrase: &str, binding_epoch: u64) -> String {
    match crate::hfi_pay::derive_binding_metadata(mnemonic, passphrase, binding_epoch) {
        Ok(binding) => format!(
            "{{\"identity_commitment_hex\":\"{}\",\"claim_binding_handle_hex\":\"{}\",\"binding_epoch\":{}}}",
            binding.identity_commitment_hex, binding.claim_binding_handle_hex, binding.binding_epoch,
        ),
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// EVM Transaction Signing
// =====================================================
// All functions below work for any EVM-compatible chain:
// Ethereum, BSC, Polygon, Arbitrum, Optimism, Base, Avalanche, etc.
// The chain is specified by the chainId parameter.

/// Sign a Type-0 Transaction
///
/// This is the original Ethereum transaction format with EIP-155 replay protection.
/// Compatible with all EVM chains.
///
/// Parameters:
/// - mnemonic: ACE-GF mnemonic
/// - passphrase: wallet passphrase
/// - chain_id: EVM chain ID (1=Ethereum, 56=BSC, 137=Polygon, etc.)
/// - nonce: transaction nonce (hex string, e.g., "0x0")
/// - gas_price: gas price in wei (hex string, e.g., "0x3b9aca00" for 1 gwei)
/// - gas_limit: gas limit (hex string, e.g., "0x5208" for 21000)
/// - to: recipient address (hex string with 0x prefix)
/// - value: amount in wei (hex string)
/// - data: transaction data (hex string, use "0x" for empty)
///
/// Returns: signed transaction as hex string (ready for eth_sendRawTransaction),
///          or "error:..." on failure
#[wasm_bindgen]
pub fn evm_sign_type0_transaction(
    mnemonic: &str,
    passphrase: &str,
    chain_id: u64,
    nonce: &str,
    gas_price: &str,
    gas_limit: &str,
    to: &str,
    value: &str,
    data: &str,
) -> String {
    match EvmSigner::sign_type0_transaction(
        mnemonic, passphrase, chain_id, nonce, gas_price, gas_limit, to, value, data,
    ) {
        Ok(signed_tx) => signed_tx,
        Err(e) => format!("error:{}", e),
    }
}

/// Backward-compatible alias for `evm_sign_type0_transaction`.
#[wasm_bindgen]
pub fn evm_sign_legacy_transaction(
    mnemonic: &str,
    passphrase: &str,
    chain_id: u64,
    nonce: &str,
    gas_price: &str,
    gas_limit: &str,
    to: &str,
    value: &str,
    data: &str,
) -> String {
    evm_sign_type0_transaction(
        mnemonic, passphrase, chain_id, nonce, gas_price, gas_limit, to, value, data,
    )
}

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
///
/// Returns: signed transaction as hex string (with 0x02 type prefix),
///          or "error:..." on failure
#[wasm_bindgen]
pub fn evm_sign_eip1559_transaction(
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
) -> String {
    match EvmSigner::sign_eip1559_transaction(
        mnemonic,
        passphrase,
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        value,
        data,
    ) {
        Ok(signed_tx) => signed_tx,
        Err(e) => format!("error:{}", e),
    }
}

/// Sign an EIP-1559 Transaction with secondary passphrase (e.g. admin factor)
///
/// Same as evm_sign_eip1559_transaction but combines passphrase with secondary_passphrase
/// for key derivation. This allows recipients holding 3-factor credentials
/// (mnemonic + passphrase + admin_factor) to sign as the wallet owner.
#[wasm_bindgen]
pub fn evm_sign_eip1559_transaction_with_secondary(
    mnemonic: &str,
    passphrase: &str,
    secondary_passphrase: Option<String>,
    chain_id: u64,
    nonce: &str,
    max_priority_fee_per_gas: &str,
    max_fee_per_gas: &str,
    gas_limit: &str,
    to: &str,
    value: &str,
    data: &str,
) -> String {
    let sec_pass = secondary_passphrase.as_deref();
    match EvmSigner::sign_eip1559_transaction_with_secondary(
        mnemonic,
        passphrase,
        sec_pass,
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        value,
        data,
    ) {
        Ok(signed_tx) => signed_tx,
        Err(e) => format!("error:{}", e),
    }
}

/// Sign a personal message (EIP-191)
///
/// Used for "Sign Message" functionality in wallets.
/// The message is prefixed with "\x19Ethereum Signed Message:\n{length}"
///
/// Parameters:
/// - mnemonic: ACE-GF mnemonic
/// - passphrase: wallet passphrase
/// - message: raw message as UTF-8 string
///
/// Returns: signature as hex string (65 bytes: r[32] + s[32] + v[1]),
///          or "error:..." on failure
#[wasm_bindgen]
pub fn evm_sign_personal_message(mnemonic: &str, passphrase: &str, message: &str) -> String {
    match EvmSigner::sign_personal_message(mnemonic, passphrase, message.as_bytes()) {
        Ok(signature) => signature,
        Err(e) => format!("error:{}", e),
    }
}

/// Sign typed structured data (EIP-712)
///
/// Used for permit signatures, NFT marketplace approvals, etc.
/// The typed data hash should be pre-computed by the frontend.
///
/// Parameters:
/// - mnemonic: ACE-GF mnemonic
/// - passphrase: wallet passphrase
/// - typed_data_hash: pre-computed EIP-712 hash (32 bytes as hex string)
///
/// Returns: signature as hex string (65 bytes: r[32] + s[32] + v[1]),
///          or "error:..." on failure
#[wasm_bindgen]
pub fn evm_sign_typed_data(mnemonic: &str, passphrase: &str, typed_data_hash: &str) -> String {
    match EvmSigner::sign_typed_data(mnemonic, passphrase, typed_data_hash) {
        Ok(signature) => signature,
        Err(e) => format!("error:{}", e),
    }
}

/// Get EVM address from mnemonic
///
/// Returns the same address for all EVM chains (Ethereum, BSC, Polygon, etc.)
/// since they all use the same address derivation.
///
/// Parameters:
/// - mnemonic: ACE-GF mnemonic
/// - passphrase: wallet passphrase
///
/// Returns: checksummed address (EIP-55 format, e.g., "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
///          or "error:..." on failure
#[wasm_bindgen]
pub fn evm_get_address(mnemonic: &str, passphrase: &str) -> String {
    match EvmSigner::get_address(mnemonic, passphrase) {
        Ok(address) => address,
        Err(e) => format!("error:{}", e),
    }
}

/// Compute transaction hash from signed transaction
///
/// Parameters:
/// - signed_tx: signed transaction hex string
///
/// Returns: transaction hash as hex string (e.g., "0x..."),
///          or "error:..." on failure
#[wasm_bindgen]
pub fn evm_compute_tx_hash(signed_tx: &str) -> String {
    match EvmSigner::compute_tx_hash(signed_tx) {
        Ok(hash) => hash,
        Err(e) => format!("error:{}", e),
    }
}

/// Encode ERC20 transfer function call data
///
/// Use this to build the `data` field for ERC20 token transfers.
///
/// Parameters:
/// - to: recipient address (hex string)
/// - amount: amount to transfer in token's smallest unit (hex string)
///
/// Returns: encoded function call data as hex string,
///          or "error:..." on failure
#[wasm_bindgen]
pub fn evm_encode_erc20_transfer(to: &str, amount: &str) -> String {
    match EvmSigner::encode_erc20_transfer(to, amount) {
        Ok(data) => data,
        Err(e) => format!("error:{}", e),
    }
}

/// Encode ERC20 approve function call data
///
/// Use this to approve a spender (DEX router) to spend tokens.
/// For unlimited approval, use max uint256: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
///
/// Parameters:
/// - spender: spender address (DEX router, etc.)
/// - amount: amount to approve in token's smallest unit (hex string)
///
/// Returns: encoded function call data as hex string,
///          or "error:..." on failure
#[wasm_bindgen]
pub fn evm_encode_erc20_approve(spender: &str, amount: &str) -> String {
    match EvmSigner::encode_erc20_approve(spender, amount) {
        Ok(data) => data,
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// Bitcoin Transaction Signing
// =====================================================
// Functions for Native SegWit (P2WPKH) Bitcoin transactions

/// Get Bitcoin address from mnemonic
///
/// Returns Native SegWit address (bc1q...) for mainnet
///
/// Parameters:
/// - mnemonic: ACE-GF mnemonic
/// - passphrase: wallet passphrase
/// - testnet: true for testnet (tb1q...), false for mainnet (bc1q...)
///
/// Returns: Bitcoin address or "error:..." on failure
#[wasm_bindgen]
pub fn bitcoin_get_address(mnemonic: &str, passphrase: &str, testnet: bool) -> String {
    match BitcoinSigner::derive_keypair(mnemonic, passphrase, None) {
        Ok((_, compressed_pubkey)) => {
            match BitcoinSigner::pubkey_to_p2wpkh_address(&compressed_pubkey, testnet) {
                Ok(address) => address,
                Err(e) => format!("error:{}", e),
            }
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Get Bitcoin Taproot address from mnemonic
///
/// Returns Taproot address (bc1p... for mainnet, tb1p... for testnet)
///
/// Parameters:
/// - mnemonic: ACE-GF mnemonic
/// - passphrase: wallet passphrase
/// - testnet: true for testnet (tb1p...), false for mainnet (bc1p...)
///
/// Returns: Bitcoin Taproot address or "error:..." on failure
#[wasm_bindgen]
pub fn bitcoin_get_taproot_address(mnemonic: &str, passphrase: &str, testnet: bool) -> String {
    let mut seeds = match ACEGFCore::unseal_to_seeds(mnemonic, passphrase, None) {
        Ok(s) => s,
        Err(e) => return format!("error:{:?}", e),
    };

    let result =
        match ACEGFCore::derive_btc_taproot_address_for_network(&seeds.secp256k1_btc, testnet) {
            Ok(address) => address,
            Err(e) => format!("error:{}", e),
        };
    ACEGFCore::clear_scheme_seeds(&mut seeds);
    result
}

/// Sign a Bitcoin SegWit transaction
///
/// Parameters:
/// - mnemonic: ACE-GF mnemonic
/// - passphrase: wallet passphrase
/// - tx_json: JSON string containing unsigned transaction data
///   Format: {
///     "version": 2,
///     "inputs": [{"txid": "hex", "vout": 0, "value": 10000, "sequence": 4294967293}],
///     "outputs": [{"value": 9000, "script_pubkey": "hex"}],
///     "locktime": 0
///   }
///
/// Returns: signed transaction as hex string, or "error:..." on failure
#[wasm_bindgen]
pub fn bitcoin_sign_transaction(mnemonic: &str, passphrase: &str, tx_json: &str) -> String {
    let unsigned_tx = match parse_bitcoin_tx_json(tx_json) {
        Ok(tx) => tx,
        Err(e) => return e,
    };

    // Auto-detect address type from first input's script_pubkey
    let is_taproot = unsigned_tx
        .inputs
        .first()
        .map(|inp| BitcoinSigner::is_p2tr_script(&inp.script_pubkey))
        .unwrap_or(false);

    if is_taproot {
        // Taproot (P2TR) signing — derive keypair and use Schnorr
        match BitcoinSigner::derive_keypair(mnemonic, passphrase, None) {
            Ok((signing_key, _compressed_pubkey)) => {
                let result = BitcoinSigner::sign_taproot_tx_with_key(&signing_key, &unsigned_tx);
                drop(signing_key);
                match result {
                    Ok(signed_hex) => signed_hex,
                    Err(e) => format!("error:{}", e),
                }
            }
            Err(e) => format!("error:{}", e),
        }
    } else {
        // SegWit (P2WPKH) signing
        match BitcoinSigner::sign_segwit_tx(mnemonic, passphrase, &unsigned_tx) {
            Ok(signed_hex) => signed_hex,
            Err(e) => format!("error:{}", e),
        }
    }
}

/// Sign a Bitcoin SegWit transaction using PRF key (no passphrase in JS)
///
/// Parameters same as bitcoin_sign_transaction, but uses prf_key instead of passphrase.
///
/// Returns: signed transaction as hex string, or "error:..." on failure
#[wasm_bindgen]
pub fn bitcoin_sign_transaction_prf(mnemonic: &str, prf_key: &[u8], tx_json: &str) -> String {
    let mut base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    let unsigned_tx = match parse_bitcoin_tx_json(tx_json) {
        Ok(tx) => tx,
        Err(e) => {
            base_key.zeroize();
            return e;
        }
    };

    // Auto-detect address type from first input's script_pubkey
    let is_taproot = unsigned_tx
        .inputs
        .first()
        .map(|inp| BitcoinSigner::is_p2tr_script(&inp.script_pubkey))
        .unwrap_or(false);

    let result = match BitcoinSigner::derive_keypair_with_base_key(mnemonic, &base_key) {
        Ok((signing_key, compressed_pubkey)) => {
            let r = if is_taproot {
                BitcoinSigner::sign_taproot_tx_with_key(&signing_key, &unsigned_tx)
            } else {
                BitcoinSigner::sign_segwit_tx_with_key(
                    &signing_key,
                    &compressed_pubkey,
                    &unsigned_tx,
                )
            };
            // Ensure signing_key is zeroized before returning (ZeroizeOnDrop)
            drop(signing_key);
            match r {
                Ok(signed_hex) => signed_hex,
                Err(e) => format!("error:{}", e),
            }
        }
        Err(e) => format!("error:{}", e),
    };

    // Zeroize base_key (plain [u8; 32] does not implement ZeroizeOnDrop)
    base_key.zeroize();

    result
}

/// Parse Bitcoin transaction JSON into UnsignedTx.
/// Returns Err(String) with "error:..." prefix on parse failure.
fn parse_bitcoin_tx_json(tx_json: &str) -> Result<UnsignedTx, String> {
    let tx_data: serde_json::Value =
        serde_json::from_str(tx_json).map_err(|e| format!("error:Invalid JSON: {}", e))?;

    // Parse inputs
    let inputs_arr = tx_data["inputs"]
        .as_array()
        .ok_or_else(|| "error:Missing inputs array".to_string())?;

    let mut inputs: Vec<TxInput> = Vec::new();
    for input in inputs_arr {
        let txid_hex = input["txid"]
            .as_str()
            .ok_or_else(|| "error:Missing txid".to_string())?;
        let txid_bytes = match hex::decode(txid_hex) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                // Reverse for little-endian (API returns big-endian hex)
                for (i, byte) in b.iter().enumerate() {
                    arr[31 - i] = *byte;
                }
                arr
            }
            _ => return Err("error:Invalid txid".to_string()),
        };

        let vout = input["vout"]
            .as_u64()
            .ok_or_else(|| "error:Missing vout".to_string())? as u32;

        let value = input["value"]
            .as_u64()
            .ok_or_else(|| "error:Missing value".to_string())?;

        let sequence = input["sequence"].as_u64().unwrap_or(0xfffffffd) as u32;

        // Parse optional script_pubkey (required for Taproot, optional for P2WPKH)
        let script_pubkey = if let Some(sp_hex) = input["script_pubkey"].as_str() {
            hex::decode(sp_hex).map_err(|_| "error:Invalid input script_pubkey hex".to_string())?
        } else {
            Vec::new()
        };

        inputs.push(TxInput {
            txid: txid_bytes,
            vout,
            value,
            sequence,
            script_pubkey,
        });
    }

    // Parse outputs
    let outputs_arr = tx_data["outputs"]
        .as_array()
        .ok_or_else(|| "error:Missing outputs array".to_string())?;

    let mut outputs: Vec<TxOutput> = Vec::new();
    for output in outputs_arr {
        let value = output["value"]
            .as_u64()
            .ok_or_else(|| "error:Missing output value".to_string())?;

        let script_hex = output["script_pubkey"]
            .as_str()
            .ok_or_else(|| "error:Missing script_pubkey".to_string())?;
        let script_pubkey =
            hex::decode(script_hex).map_err(|_| "error:Invalid script_pubkey hex".to_string())?;

        outputs.push(TxOutput {
            value,
            script_pubkey,
        });
    }

    let version = tx_data["version"].as_u64().unwrap_or(2) as u32;
    let locktime = tx_data["locktime"].as_u64().unwrap_or(0) as u32;

    Ok(UnsignedTx {
        version,
        inputs,
        outputs,
        locktime,
    })
}

/// Convert a Bitcoin bech32/bech32m address between mainnet and testnet
///
/// Examples:
///   bc1p... → tb1p... (mainnet to testnet)
///   tb1p... → bc1p... (testnet to mainnet)
///   bc1q... → tb1q... (mainnet to testnet)
///
/// Parameters:
/// - address: Bitcoin bech32/bech32m address
/// - testnet: true to convert to testnet (tb1...), false for mainnet (bc1...)
///
/// Returns: converted address, or "error:..." on failure
#[wasm_bindgen]
pub fn bitcoin_convert_address_network(address: &str, testnet: bool) -> String {
    // Decode the address to get witness version and program
    let (witness_version, program) = match BitcoinSigner::decode_bech32_address(address) {
        Ok(r) => r,
        Err(e) => return format!("error:{}", e),
    };

    // Re-encode with the target HRP
    let hrp = if testnet { "tb" } else { "bc" };
    match BitcoinSigner::encode_bech32_public(hrp, witness_version, &program) {
        Ok(addr) => addr,
        Err(e) => format!("error:{}", e),
    }
}

/// Generate scriptPubKey for any Bitcoin address
///
/// Supports all address types:
/// - Bech32/Bech32m: bc1q... (P2WPKH), bc1p... (P2TR), tb1q..., tb1p...
/// - Legacy Base58Check: 1... (P2PKH), 3... (P2SH), m.../n... (testnet P2PKH), 2... (testnet P2SH)
///
/// Returns: scriptPubKey as hex string, or "error:..." on failure
#[wasm_bindgen]
pub fn bitcoin_address_to_script_pubkey(address: &str) -> String {
    match BitcoinSigner::address_to_script_pubkey(address) {
        Ok(script) => hex::encode(script),
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// REV32 Wallet Generation (New 32-byte Root Entropy)
// =====================================================
// These functions use the new REV32 format with 224-bit entropy
// and metadata fields. They generate 24-word mnemonics that
// directly encode the REV32 (no encryption layer).

/// Generate a new REV32 wallet with passphrase
/// Returns JSON: { mnemonic, solana_address, evm_address, bitcoin_address, cosmos_address, polkadot_address, xaddress, x25519 }
/// or JSON: { error: true, message: "..." }
#[wasm_bindgen]
pub fn generate_rev32_wasm(passphrase: &str) -> JsValue {
    generate_rev32_with_secondary_wasm(passphrase, None)
}

/// Generate a new REV32 wallet with passphrase and optional secondary passphrase
#[wasm_bindgen]
pub fn generate_rev32_with_secondary_wasm(
    passphrase: &str,
    secondary_passphrase: Option<String>,
) -> JsValue {
    let sec_pass = secondary_passphrase.as_deref();

    match ACEGFCore::generate_ace_internal(passphrase, sec_pass) {
        Ok(entity) => {
            let js_wallet = WasmWallet {
                mnemonic: entity.mnemonic.to_string(),
                solana_address: entity.solana_address,
                evm_address: entity.evm_address,
                tron_address: entity.tron_address,
                bitcoin_address: entity.bitcoin_address,
                cosmos_address: entity.cosmos_address,
                polkadot_address: entity.polkadot_address,
                xaddress: entity.xaddress,
                x25519: entity.x25519,
                xkem: entity.xkem,
                xid: entity.xid,
            };
            #[allow(deprecated)]
            match JsValue::from_serde(&js_wallet) {
                Ok(val) => val,
                Err(e) => {
                    let err = WasmError {
                        error: true,
                        message: format!("Serialization failed: {}", e),
                    };
                    #[allow(deprecated)]
                    JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
                }
            }
        }
        Err(e) => {
            let err = WasmError {
                error: true,
                message: format!("REV32 wallet generation failed: {}", e),
            };
            #[allow(deprecated)]
            JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
        }
    }
}

/// View REV32 wallet (restore from 24-word mnemonic)
/// Automatically detects REV32 format and uses the new derivation path
#[wasm_bindgen]
pub fn view_wallet_rev32_wasm(mnemonic: &str, passphrase: &str) -> JsValue {
    view_wallet_rev32_with_secondary_wasm(mnemonic, passphrase, None)
}

#[wasm_bindgen]
pub fn view_wallet_rev32_with_secondary_wasm(
    mnemonic: &str,
    passphrase: &str,
    secondary_passphrase: Option<String>,
) -> JsValue {
    let sec_pass = secondary_passphrase.as_deref();

    match ACEGFCore::view_wallet_internal(mnemonic, passphrase, sec_pass) {
        Ok(entity) => {
            let js_wallet = WasmWallet {
                mnemonic: entity.mnemonic.to_string(),
                solana_address: entity.solana_address,
                evm_address: entity.evm_address,
                tron_address: entity.tron_address,
                bitcoin_address: entity.bitcoin_address,
                cosmos_address: entity.cosmos_address,
                polkadot_address: entity.polkadot_address,
                xaddress: entity.xaddress,
                x25519: entity.x25519,
                xkem: entity.xkem,
                xid: entity.xid,
            };
            #[allow(deprecated)]
            match JsValue::from_serde(&js_wallet) {
                Ok(val) => val,
                Err(e) => {
                    let err = WasmError {
                        error: true,
                        message: format!("Serialization failed: {}", e),
                    };
                    #[allow(deprecated)]
                    JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
                }
            }
        }
        Err(e) => {
            let err = WasmError {
                error: true,
                message: format!("REV32 view wallet failed: {}", e),
            };
            #[allow(deprecated)]
            JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
        }
    }
}

/// Unified wallet view for canonical REV32 mnemonics.
#[wasm_bindgen]
pub fn view_wallet_unified_wasm(mnemonic: &str, passphrase: &str) -> JsValue {
    view_wallet_unified_with_secondary_wasm(mnemonic, passphrase, None)
}

#[wasm_bindgen]
pub fn view_wallet_unified_with_secondary_wasm(
    mnemonic: &str,
    passphrase: &str,
    secondary_passphrase: Option<String>,
) -> JsValue {
    let sec_pass = secondary_passphrase.as_deref();

    match ACEGFCore::view_wallet_unified(mnemonic, passphrase, sec_pass) {
        Ok(entity) => {
            let js_wallet = WasmWallet {
                mnemonic: entity.mnemonic.to_string(),
                solana_address: entity.solana_address,
                evm_address: entity.evm_address,
                tron_address: entity.tron_address,
                bitcoin_address: entity.bitcoin_address,
                cosmos_address: entity.cosmos_address,
                polkadot_address: entity.polkadot_address,
                xaddress: entity.xaddress,
                x25519: entity.x25519,
                xkem: entity.xkem,
                xid: entity.xid,
            };
            #[allow(deprecated)]
            match JsValue::from_serde(&js_wallet) {
                Ok(val) => val,
                Err(e) => {
                    let err = WasmError {
                        error: true,
                        message: format!("Serialization failed: {}", e),
                    };
                    #[allow(deprecated)]
                    JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
                }
            }
        }
        Err(e) => {
            let err = WasmError {
                error: true,
                message: format!("Unified view wallet failed: {}", e),
            };
            #[allow(deprecated)]
            JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
        }
    }
}

// =====================================================
// Context-Isolated (Deniable Account) WASM Exports
// =====================================================
// These functions derive keys using HKDF context isolation.
// A non-empty context produces completely independent addresses/keys.
// Empty context falls back to the standard (personal) derivation path.
// Context isolation only works with canonical REV32 mnemonics.

/// View wallet with context isolation (passphrase path)
/// Returns 7 chain addresses for the given context, or error for non-REV32 formats.
#[wasm_bindgen]
pub fn view_wallet_unified_with_context_wasm(
    mnemonic: &str,
    passphrase: &str,
    context: &str,
) -> JsValue {
    match ACEGFCore::view_wallet_unified_with_context(mnemonic, passphrase, None, context) {
        Ok(entity) => {
            let js_wallet = WasmWallet {
                mnemonic: entity.mnemonic.to_string(),
                solana_address: entity.solana_address,
                evm_address: entity.evm_address,
                tron_address: entity.tron_address,
                bitcoin_address: entity.bitcoin_address,
                cosmos_address: entity.cosmos_address,
                polkadot_address: entity.polkadot_address,
                xaddress: entity.xaddress,
                x25519: entity.x25519,
                xkem: entity.xkem,
                xid: entity.xid,
            };
            #[allow(deprecated)]
            match JsValue::from_serde(&js_wallet) {
                Ok(val) => val,
                Err(e) => {
                    let err = WasmError {
                        error: true,
                        message: format!("Serialization failed: {}", e),
                    };
                    #[allow(deprecated)]
                    JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
                }
            }
        }
        Err(e) => {
            let err = WasmError {
                error: true,
                message: format!("Context wallet view failed: {:?}", e),
            };
            #[allow(deprecated)]
            JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
        }
    }
}

/// Get the ML-DSA-44 public key (1312 bytes) as hex string from mnemonic+passphrase.
/// Returns hex string on success, or "error:..." on failure.
#[wasm_bindgen]
pub fn ml_dsa_44_pubkey_hex(mnemonic: &str, passphrase: &str) -> String {
    use crate::pqclean_ffi::MlDsa44;

    let seeds = match ACEGFCore::unseal_to_seeds(mnemonic, passphrase, None) {
        Ok(s) => s,
        Err(e) => return format!("error:{:?}", e),
    };

    match MlDsa44::keypair_from_seed(&seeds.ml_dsa_44) {
        Ok((pk, _)) => hex::encode(pk),
        Err(e) => format!("error:{}", e),
    }
}

/// Sign a message with ML-DSA-44 (FIPS 204, post-quantum).
/// Returns base64 signature (2420 bytes) on success, or "error:..." on failure.
#[wasm_bindgen]
pub fn ml_dsa_44_sign_wasm(mnemonic: &str, passphrase: &str, message: &[u8]) -> String {
    use crate::pqclean_ffi::MlDsa44;

    let seeds = match ACEGFCore::unseal_to_seeds(mnemonic, passphrase, None) {
        Ok(s) => s,
        Err(e) => return format!("error:{:?}", e),
    };

    match MlDsa44::keypair_from_seed(&seeds.ml_dsa_44) {
        Ok((_, sk)) => match MlDsa44::sign(&sk, message) {
            Ok(sig) => {
                use base64ct::{Base64, Encoding};
                Base64::encode_string(&sig)
            }
            Err(e) => format!("error:{}", e),
        },
        Err(e) => format!("error:{}", e),
    }
}

/// Get the wallet's ML-DSA-44 public key hex using a PRF key (passkey path).
#[wasm_bindgen]
pub fn ml_dsa_44_pubkey_hex_with_prf_wasm(mnemonic: &str, prf_key: &[u8]) -> String {
    use crate::pqclean_ffi::MlDsa44;
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };
    let seeds = match ACEGFCore::unseal_to_seeds_with_base_key(mnemonic, &base_key) {
        Ok(s) => s,
        Err(e) => return format!("error:{:?}", e),
    };
    match MlDsa44::keypair_from_seed(&seeds.ml_dsa_44) {
        Ok((pk, _)) => hex::encode(pk),
        Err(e) => format!("error:{}", e),
    }
}

/// Sign a message with ML-DSA-44 using a PRF key (passkey path).
/// Returns base64 signature (2420 bytes) on success, or "error:..." on failure.
#[wasm_bindgen]
pub fn ml_dsa_44_sign_with_prf_wasm(mnemonic: &str, prf_key: &[u8], message: &[u8]) -> String {
    use crate::pqclean_ffi::MlDsa44;
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };
    let seeds = match ACEGFCore::unseal_to_seeds_with_base_key(mnemonic, &base_key) {
        Ok(s) => s,
        Err(e) => return format!("error:{:?}", e),
    };
    match MlDsa44::keypair_from_seed(&seeds.ml_dsa_44) {
        Ok((_, sk)) => match MlDsa44::sign(&sk, message) {
            Ok(sig) => {
                use base64ct::{Base64, Encoding};
                Base64::encode_string(&sig)
            }
            Err(e) => format!("error:{}", e),
        },
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// XKEM (ML-KEM-768 / FIPS 203) — post-quantum key encapsulation
//
// Interface shape mirrors X25519 (X25519) exactly:
//   * all public-key / ciphertext / shared-secret values are Base64 strings,
//   * success returns a plain string (for single-value APIs) or JSON (for
//     tuple APIs, matching `acegf_encrypt_for_x25519`),
//   * failure returns "error:..." (single-value) or
//     `{ "error": true, "message": "..." }` (JSON).
// =====================================================

/// Get the wallet's ML-KEM-768 encapsulation (public) key — the `xkem`
/// identity — as a Base64 string, derived from `mnemonic + passphrase`.
///
/// Parallel to the x25519 field returned from `generate_wasm` /
/// `view_wallet_with_passphrase_wasm`.
///
/// Returns a Base64 string (1184 raw bytes) on success, or `"error:..."`
/// on failure.
#[wasm_bindgen]
pub fn acegf_xkem_pubkey_wasm(mnemonic: &str, passphrase: &str) -> String {
    use base64ct::{Base64, Encoding};

    use crate::pqclean_ffi::MlKem768;

    let seeds = match ACEGFCore::unseal_to_seeds(mnemonic, passphrase, None) {
        Ok(s) => s,
        Err(e) => return format!("error:{:?}", e),
    };

    match MlKem768::keypair_from_seed(&seeds.ml_kem_768) {
        Ok((ek, _)) => Base64::encode_string(&ek),
        Err(e) => format!("error:{}", e),
    }
}

/// Encapsulate a shared secret against a recipient's published xkem.
///
/// Parallel to `acegf_encrypt_for_x25519`: no mnemonic is required —
/// any party that has the recipient's xkem can run this. On success returns
/// a JSON string `{ "shared_secret": "<b64>", "ciphertext": "<b64>" }`.
/// Transmit `ciphertext` to the recipient; they recover the same
/// `shared_secret` via `acegf_decapsulate_for_xkem_wasm`.
///
/// Returns `"error:..."` on failure.
#[wasm_bindgen]
pub fn acegf_encapsulate_for_xkem_wasm(recipient_xkem_b64: &str) -> String {
    match ACEGF::encapsulate_for_xkem(recipient_xkem_b64) {
        Ok((shared_secret, ciphertext)) => {
            #[derive(Serialize)]
            struct XKemEncapsPayload {
                shared_secret: String,
                ciphertext: String,
            }
            let payload = XKemEncapsPayload {
                shared_secret,
                ciphertext,
            };
            serde_json::to_string(&payload)
                .unwrap_or_else(|e| format!("error:serialization failed: {}", e))
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Recover the 32-byte shared secret from an xkem ciphertext using the
/// wallet's own decapsulation key.
///
/// Parallel to `acegf_decrypt_with_mnemonic_wasm`: requires mnemonic +
/// passphrase to re-derive the decapsulation key. Returns the shared secret
/// as a Base64 string on success, or `"error:..."` on failure.
#[wasm_bindgen]
pub fn acegf_decapsulate_for_xkem_wasm(
    mnemonic: &str,
    passphrase: &str,
    ciphertext_b64: &str,
) -> String {
    match ACEGF::decapsulate_for_xkem(mnemonic, passphrase, ciphertext_b64, None) {
        Ok(shared_secret_b64) => shared_secret_b64,
        Err(e) => format!("error:{}", e),
    }
}

/// View wallet with context isolation (PRF path)
/// Uses PRF key → base_key → identity_root → context-isolated seeds
#[wasm_bindgen]
pub fn view_wallet_with_context_prf_wasm(mnemonic: &str, prf_key: &[u8], context: &str) -> JsValue {
    use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;

    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => {
            let err = WasmError {
                error: true,
                message: e,
            };
            #[allow(deprecated)]
            return JsValue::from_serde(&err).unwrap_or(JsValue::NULL);
        }
    };

    // Empty context: fall back to standard PRF view
    if context.is_empty() {
        return view_wallet_with_prf_wasm(mnemonic, prf_key);
    }

    // Context path: base_key IS the Kmaster equivalent → derive identity_root → context seeds
    let identity_root = match PassphraseSealingUtil::derive_identity_root(&base_key) {
        Ok(root) => root,
        Err(e) => {
            let err = WasmError {
                error: true,
                message: format!("Derive identity root failed: {:?}", e),
            };
            #[allow(deprecated)]
            return JsValue::from_serde(&err).unwrap_or(JsValue::NULL);
        }
    };

    let mut seeds =
        match ACEGFCore::derive_from_rev32_with_context(&identity_root, context.as_bytes()) {
            Ok(s) => s,
            Err(e) => {
                let err = WasmError {
                    error: true,
                    message: format!("Context derivation failed: {:?}", e),
                };
                #[allow(deprecated)]
                return JsValue::from_serde(&err).unwrap_or(JsValue::NULL);
            }
        };

    match ACEGFCore::generate_crypto_entity(&mut seeds) {
        Ok(mut entity) => {
            entity.mnemonic = Zeroizing::new(mnemonic.to_string());
            ACEGFCore::clear_scheme_seeds(&mut seeds);
            let js_wallet = WasmWallet {
                mnemonic: entity.mnemonic.to_string(),
                solana_address: entity.solana_address,
                evm_address: entity.evm_address,
                tron_address: entity.tron_address,
                bitcoin_address: entity.bitcoin_address,
                cosmos_address: entity.cosmos_address,
                polkadot_address: entity.polkadot_address,
                xaddress: entity.xaddress,
                x25519: entity.x25519,
                xkem: entity.xkem,
                xid: entity.xid,
            };
            #[allow(deprecated)]
            match JsValue::from_serde(&js_wallet) {
                Ok(val) => val,
                Err(e) => {
                    let err = WasmError {
                        error: true,
                        message: format!("Serialization failed: {}", e),
                    };
                    #[allow(deprecated)]
                    JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
                }
            }
        }
        Err(e) => {
            ACEGFCore::clear_scheme_seeds(&mut seeds);
            let err = WasmError {
                error: true,
                message: format!("Generate entity failed: {:?}", e),
            };
            #[allow(deprecated)]
            JsValue::from_serde(&err).unwrap_or(JsValue::NULL)
        }
    }
}

/// Get EVM address with context isolation (passphrase path)
#[wasm_bindgen]
pub fn evm_get_address_with_context(mnemonic: &str, passphrase: &str, context: &str) -> String {
    match EvmSigner::get_address_with_context(mnemonic, passphrase, context) {
        Ok(address) => address,
        Err(e) => format!("error:{}", e),
    }
}

/// Get EVM address with context isolation (PRF path)
#[wasm_bindgen]
pub fn evm_get_address_with_context_prf(mnemonic: &str, prf_key: &[u8], context: &str) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match EvmSigner::derive_keypair_with_context_base_key(mnemonic, &base_key, context) {
        Ok((_signing_key, addr)) => {
            format!("0x{}", hex::encode(addr))
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Sign EVM personal message with context isolation (passphrase path)
#[wasm_bindgen]
pub fn evm_sign_personal_message_with_context(
    mnemonic: &str,
    passphrase: &str,
    context: &str,
    message: &str,
) -> String {
    match EvmSigner::sign_personal_message_with_context(
        mnemonic,
        passphrase,
        context,
        message.as_bytes(),
    ) {
        Ok(signature) => signature,
        Err(e) => format!("error:{}", e),
    }
}

/// Sign EVM personal message with context isolation (PRF path)
#[wasm_bindgen]
pub fn evm_sign_personal_message_with_context_prf(
    mnemonic: &str,
    prf_key: &[u8],
    context: &str,
    message: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match EvmSigner::derive_keypair_with_context_base_key(mnemonic, &base_key, context) {
        Ok((signing_key, _addr)) => {
            match EvmSigner::sign_personal_message_with_key(&signing_key, message.as_bytes()) {
                Ok(signature) => signature,
                Err(e) => format!("error:{}", e),
            }
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Sign EVM EIP-1559 transaction with context isolation (passphrase path)
#[wasm_bindgen]
pub fn evm_sign_eip1559_transaction_with_context(
    mnemonic: &str,
    passphrase: &str,
    context: &str,
    chain_id: u64,
    nonce: &str,
    max_priority_fee_per_gas: &str,
    max_fee_per_gas: &str,
    gas_limit: &str,
    to: &str,
    value: &str,
    data: &str,
) -> String {
    match EvmSigner::sign_eip1559_transaction_with_context(
        mnemonic,
        passphrase,
        context,
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        value,
        data,
    ) {
        Ok(signed_tx) => signed_tx,
        Err(e) => format!("error:{}", e),
    }
}

/// Sign EVM EIP-1559 transaction with context isolation (PRF path)
#[wasm_bindgen]
pub fn evm_sign_eip1559_transaction_with_context_prf(
    mnemonic: &str,
    prf_key: &[u8],
    context: &str,
    chain_id: u64,
    nonce: &str,
    max_priority_fee_per_gas: &str,
    max_fee_per_gas: &str,
    gas_limit: &str,
    to: &str,
    value: &str,
    data: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match EvmSigner::derive_keypair_with_context_base_key(mnemonic, &base_key, context) {
        Ok((signing_key, _addr)) => {
            match EvmSigner::sign_eip1559_transaction_with_key(
                &signing_key,
                chain_id,
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
                to,
                value,
                data,
            ) {
                Ok(signed_tx) => signed_tx,
                Err(e) => format!("error:{}", e),
            }
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Sign EVM typed data with context isolation (passphrase path)
#[wasm_bindgen]
pub fn evm_sign_typed_data_with_context(
    mnemonic: &str,
    passphrase: &str,
    context: &str,
    typed_data_hash: &str,
) -> String {
    match EvmSigner::derive_keypair_with_context(mnemonic, passphrase, None, context) {
        Ok((signing_key, _addr)) => {
            match EvmSigner::sign_typed_data_with_key(&signing_key, typed_data_hash) {
                Ok(signature) => signature,
                Err(e) => format!("error:{}", e),
            }
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Sign EVM typed data with context isolation (PRF path)
#[wasm_bindgen]
pub fn evm_sign_typed_data_with_context_prf(
    mnemonic: &str,
    prf_key: &[u8],
    context: &str,
    typed_data_hash: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match EvmSigner::derive_keypair_with_context_base_key(mnemonic, &base_key, context) {
        Ok((signing_key, _addr)) => {
            match EvmSigner::sign_typed_data_with_key(&signing_key, typed_data_hash) {
                Ok(signature) => signature,
                Err(e) => format!("error:{}", e),
            }
        }
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// Solana Context-Isolated Operations (REV32 only)
// =====================================================

/// Get Solana address with context isolation (passphrase path)
#[wasm_bindgen]
pub fn solana_get_address_with_context(mnemonic: &str, passphrase: &str, context: &str) -> String {
    match SolanaSigner::get_address_with_context(mnemonic, passphrase, context) {
        Ok(address) => address,
        Err(e) => format!("error:{}", e),
    }
}

/// Get Solana address with context isolation (PRF path)
#[wasm_bindgen]
pub fn solana_get_address_with_context_prf(
    mnemonic: &str,
    prf_key: &[u8],
    context: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match SolanaSigner::derive_keypair_with_context_base_key(mnemonic, &base_key, context) {
        Ok((_signing_key, verifying_key)) => bs58::encode(verifying_key.to_bytes()).into_string(),
        Err(e) => format!("error:{}", e),
    }
}

/// Sign a Solana serialized transaction with context isolation (passphrase path)
#[wasm_bindgen]
pub fn solana_sign_transaction_with_context(
    mnemonic: &str,
    passphrase: &str,
    context: &str,
    serialized_tx_base64: &str,
) -> String {
    match SolanaSigner::sign_serialized_transaction_with_context(
        mnemonic,
        passphrase,
        context,
        serialized_tx_base64,
    ) {
        Ok(signed_tx) => signed_tx,
        Err(e) => format!("error:{}", e),
    }
}

/// Sign a Solana serialized transaction with context isolation (PRF path)
#[wasm_bindgen]
pub fn solana_sign_transaction_with_context_prf(
    mnemonic: &str,
    prf_key: &[u8],
    context: &str,
    serialized_tx_base64: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match SolanaSigner::derive_keypair_with_context_base_key(mnemonic, &base_key, context) {
        Ok((signing_key, _verifying_key)) => {
            match SolanaSigner::sign_serialized_transaction_with_key(
                &signing_key,
                serialized_tx_base64,
            ) {
                Ok(signed_tx) => signed_tx,
                Err(e) => format!("error:{}", e),
            }
        }
        Err(e) => format!("error:{}", e),
    }
}

/// Sign an arbitrary message with Solana context-derived Ed25519 key (passphrase path)
#[wasm_bindgen]
pub fn solana_sign_message_with_context(
    mnemonic: &str,
    passphrase: &str,
    context: &str,
    message: &str,
) -> String {
    match SolanaSigner::sign_message_with_context(mnemonic, passphrase, context, message.as_bytes())
    {
        Ok(signature) => signature,
        Err(e) => format!("error:{}", e),
    }
}

/// Sign an arbitrary message with Solana context-derived Ed25519 key (PRF path)
#[wasm_bindgen]
pub fn solana_sign_message_with_context_prf(
    mnemonic: &str,
    prf_key: &[u8],
    context: &str,
    message: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match SolanaSigner::derive_keypair_with_context_base_key(mnemonic, &base_key, context) {
        Ok((signing_key, _verifying_key)) => {
            let sig = signing_key.sign(message.as_bytes()).to_bytes();
            hex::encode(sig)
        }
        Err(e) => format!("error:{}", e),
    }
}

// =====================================================
// Tron (secp256k1, Base58 T-address) — aligned with EVM/Solana WASM surfaces
// =====================================================

/// Tron Base58Check address (`T...`), or `"error:..."` on failure.
#[wasm_bindgen]
pub fn tron_get_address(mnemonic: &str, passphrase: &str) -> String {
    match TronSigner::get_address(mnemonic, passphrase, None) {
        Ok(address) => address,
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_get_address_with_prf(mnemonic: &str, prf_key: &[u8]) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match TronSigner::derive_keypair_with_base_key(mnemonic, &base_key) {
        Ok((_signing_key, address)) => address,
        Err(e) => format!("error:{}", e),
    }
}

/// Context isolation — passphrase path (same `None` secondary convention as Solana context WASM).
#[wasm_bindgen]
pub fn tron_get_address_with_context(mnemonic: &str, passphrase: &str, context: &str) -> String {
    match TronSigner::derive_keypair_with_context(mnemonic, passphrase, None, context) {
        Ok((_signing_key, address)) => address,
        Err(e) => format!("error:{}", e),
    }
}

/// Context isolation — PRF path (matches EVM/Solana `*_with_context_prf`).
#[wasm_bindgen]
pub fn tron_get_address_with_context_prf(mnemonic: &str, prf_key: &[u8], context: &str) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match TronSigner::derive_keypair_with_context_base_key(mnemonic, &base_key, context) {
        Ok((_signing_key, address)) => address,
        Err(e) => format!("error:{}", e),
    }
}

/// Sign Tron txID (64 hex chars = 32 bytes). Signature: 65-byte hex (`r||s||v`, `v` = recovery id only).
#[wasm_bindgen]
pub fn tron_sign_transaction(mnemonic: &str, passphrase: &str, tx_id_hex: &str) -> String {
    match TronSigner::sign_transaction(mnemonic, passphrase, None, tx_id_hex) {
        Ok(sig) => sig,
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_transaction_with_secondary(
    mnemonic: &str,
    passphrase: &str,
    secondary_passphrase: Option<String>,
    tx_id_hex: &str,
) -> String {
    let sec = secondary_passphrase.as_deref();
    match TronSigner::sign_transaction(mnemonic, passphrase, sec, tx_id_hex) {
        Ok(sig) => sig,
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_transaction_with_prf(mnemonic: &str, prf_key: &[u8], tx_id_hex: &str) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match TronSigner::derive_keypair_with_base_key(mnemonic, &base_key) {
        Ok((signing_key, _addr)) => {
            match TronSigner::sign_transaction_with_key(&signing_key, tx_id_hex) {
                Ok(sig) => sig,
                Err(e) => format!("error:{}", e),
            }
        }
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_transaction_with_context(mnemonic: &str, passphrase: &str, context: &str, tx_id_hex: &str) -> String {
    match TronSigner::derive_keypair_with_context(mnemonic, passphrase, None, context) {
        Ok((signing_key, _addr)) => match TronSigner::sign_transaction_with_key(&signing_key, tx_id_hex) {
            Ok(sig) => sig,
            Err(e) => format!("error:{}", e),
        },
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_transaction_with_context_prf(
    mnemonic: &str,
    prf_key: &[u8],
    context: &str,
    tx_id_hex: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match TronSigner::derive_keypair_with_context_base_key(mnemonic, &base_key, context) {
        Ok((signing_key, _addr)) => match TronSigner::sign_transaction_with_key(&signing_key, tx_id_hex) {
            Ok(sig) => sig,
            Err(e) => format!("error:{}", e),
        },
        Err(e) => format!("error:{}", e),
    }
}

/// Sign raw protobuf tx hex (`SHA256(raw)` = txID). Same signature format as `tron_sign_transaction`.
#[wasm_bindgen]
pub fn tron_sign_raw_transaction(mnemonic: &str, passphrase: &str, raw_tx_hex: &str) -> String {
    match TronSigner::sign_raw_transaction(mnemonic, passphrase, None, raw_tx_hex) {
        Ok(sig) => sig,
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_raw_transaction_with_secondary(
    mnemonic: &str,
    passphrase: &str,
    secondary_passphrase: Option<String>,
    raw_tx_hex: &str,
) -> String {
    let sec = secondary_passphrase.as_deref();
    match TronSigner::sign_raw_transaction(mnemonic, passphrase, sec, raw_tx_hex) {
        Ok(sig) => sig,
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_raw_transaction_with_prf(mnemonic: &str, prf_key: &[u8], raw_tx_hex: &str) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match TronSigner::derive_keypair_with_base_key(mnemonic, &base_key) {
        Ok((signing_key, _addr)) => match TronSigner::sign_raw_transaction_with_key(&signing_key, raw_tx_hex) {
            Ok(sig) => sig,
            Err(e) => format!("error:{}", e),
        },
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_raw_transaction_with_context(mnemonic: &str, passphrase: &str, context: &str, raw_tx_hex: &str) -> String {
    match TronSigner::derive_keypair_with_context(mnemonic, passphrase, None, context) {
        Ok((signing_key, _addr)) => match TronSigner::sign_raw_transaction_with_key(&signing_key, raw_tx_hex) {
            Ok(sig) => sig,
            Err(e) => format!("error:{}", e),
        },
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_raw_transaction_with_context_prf(
    mnemonic: &str,
    prf_key: &[u8],
    context: &str,
    raw_tx_hex: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match TronSigner::derive_keypair_with_context_base_key(mnemonic, &base_key, context) {
        Ok((signing_key, _addr)) => match TronSigner::sign_raw_transaction_with_key(&signing_key, raw_tx_hex) {
            Ok(sig) => sig,
            Err(e) => format!("error:{}", e),
        },
        Err(e) => format!("error:{}", e),
    }
}

/// Tron personal-sign (`v` = 27 + recovery id). `message` is UTF-8.
#[wasm_bindgen]
pub fn tron_sign_personal_message(mnemonic: &str, passphrase: &str, message: &str) -> String {
    match TronSigner::sign_message(mnemonic, passphrase, None, message.as_bytes()) {
        Ok(sig) => sig,
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_personal_message_with_secondary(
    mnemonic: &str,
    passphrase: &str,
    secondary_passphrase: Option<String>,
    message: &str,
) -> String {
    let sec = secondary_passphrase.as_deref();
    match TronSigner::sign_message(mnemonic, passphrase, sec, message.as_bytes()) {
        Ok(sig) => sig,
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_personal_message_with_prf(mnemonic: &str, prf_key: &[u8], message: &str) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match TronSigner::derive_keypair_with_base_key(mnemonic, &base_key) {
        Ok((signing_key, _addr)) => match TronSigner::sign_message_with_key(&signing_key, message.as_bytes()) {
            Ok(sig) => sig,
            Err(e) => format!("error:{}", e),
        },
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_personal_message_with_context(mnemonic: &str, passphrase: &str, context: &str, message: &str) -> String {
    match TronSigner::derive_keypair_with_context(mnemonic, passphrase, None, context) {
        Ok((signing_key, _addr)) => match TronSigner::sign_message_with_key(&signing_key, message.as_bytes()) {
            Ok(sig) => sig,
            Err(e) => format!("error:{}", e),
        },
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_personal_message_with_context_prf(
    mnemonic: &str,
    prf_key: &[u8],
    context: &str,
    message: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    match TronSigner::derive_keypair_with_context_base_key(mnemonic, &base_key, context) {
        Ok((signing_key, _addr)) => match TronSigner::sign_message_with_key(&signing_key, message.as_bytes()) {
            Ok(sig) => sig,
            Err(e) => format!("error:{}", e),
        },
        Err(e) => format!("error:{}", e),
    }
}

/// Pre-hashed personal payload: 64 hex chars (32 bytes), Tron convention — same `v` as `tron_sign_personal_message`.
#[wasm_bindgen]
pub fn tron_sign_message_hash(mnemonic: &str, passphrase: &str, hash_hex: &str) -> String {
    match TronSigner::sign_message_hash(mnemonic, passphrase, None, hash_hex) {
        Ok(sig) => sig,
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_message_hash_with_secondary(
    mnemonic: &str,
    passphrase: &str,
    secondary_passphrase: Option<String>,
    hash_hex: &str,
) -> String {
    let sec = secondary_passphrase.as_deref();
    match TronSigner::sign_message_hash(mnemonic, passphrase, sec, hash_hex) {
        Ok(sig) => sig,
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_message_hash_with_prf(mnemonic: &str, prf_key: &[u8], hash_hex: &str) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    let hash_bytes = match hex::decode(hash_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return "error:message hash must be 32 bytes".to_string(),
    };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_bytes);

    match TronSigner::derive_keypair_with_base_key(mnemonic, &base_key) {
        Ok((signing_key, _addr)) => match TronSigner::sign_message_hash_with_key(&signing_key, &hash) {
            Ok(sig) => sig,
            Err(e) => format!("error:{}", e),
        },
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_message_hash_with_context(mnemonic: &str, passphrase: &str, context: &str, hash_hex: &str) -> String {
    let hash_bytes = match hex::decode(hash_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return "error:message hash must be 32 bytes".to_string(),
    };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_bytes);

    match TronSigner::derive_keypair_with_context(mnemonic, passphrase, None, context) {
        Ok((signing_key, _addr)) => match TronSigner::sign_message_hash_with_key(&signing_key, &hash) {
            Ok(sig) => sig,
            Err(e) => format!("error:{}", e),
        },
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_sign_message_hash_with_context_prf(
    mnemonic: &str,
    prf_key: &[u8],
    context: &str,
    hash_hex: &str,
) -> String {
    let base_key = match derive_base_key_from_prf(prf_key) {
        Ok(k) => k,
        Err(e) => return format!("error:{}", e),
    };

    let hash_bytes = match hex::decode(hash_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return "error:message hash must be 32 bytes".to_string(),
    };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_bytes);

    match TronSigner::derive_keypair_with_context_base_key(mnemonic, &base_key, context) {
        Ok((signing_key, _addr)) => match TronSigner::sign_message_hash_with_key(&signing_key, &hash) {
            Ok(sig) => sig,
            Err(e) => format!("error:{}", e),
        },
        Err(e) => format!("error:{}", e),
    }
}

/// TRC-20 `transfer(address,uint256)` call data hex (matches `TronSigner::encode_trc20_transfer`).
#[wasm_bindgen]
pub fn tron_encode_trc20_transfer(to_address_hex: &str, amount_low128: &str) -> String {
    let amount = match amount_low128.parse::<u128>() {
        Ok(a) => a,
        Err(_) => return "error:invalid amount (expect decimal u128)".to_string(),
    };
    match TronSigner::encode_trc20_transfer(to_address_hex, amount) {
        Ok(data) => data,
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_address_to_hex(tron_address: &str) -> String {
    match TronSigner::address_to_hex(tron_address) {
        Ok(h) => h,
        Err(e) => format!("error:{}", e),
    }
}

#[wasm_bindgen]
pub fn tron_hex_to_address(hex_addr: &str) -> String {
    match TronSigner::hex_to_address(hex_addr) {
        Ok(a) => a,
        Err(e) => format!("error:{}", e),
    }
}
