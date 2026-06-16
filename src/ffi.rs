// src/ffi.rs
//
// FFI bindings for ACE-GF native library (iOS/Android).
// Exposes the same functions as wasm.rs but for C/Swift/Kotlin interop.

use base64ct::{Base64, Encoding};
use libc::size_t;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::acegf::ACEGF;
use crate::acegf_core::ACEGFCore;
use crate::signer::bitcoin_signer::{TxInput, TxOutput, UnsignedTx};
use crate::signer::BitcoinSigner;
use crate::signer::EvmSigner;
use crate::signer::SolanaSigner;
use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;
use crate::vadar::VADAR;

// =====================================================
// Helper functions
// =====================================================

fn to_cstring(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => CString::new("")
            .expect("Empty string should never fail")
            .into_raw(),
    }
}

unsafe fn from_cstr(ptr: *const c_char) -> Option<&'static str> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok()
}

/// For optional C strings (e.g. secondary_passphrase): treat null or empty string as None.
/// Flutter/Dart often passes a pointer to "" instead of null for "no value"; that would make
/// combine_passphrase(primary, Some("")) add an extra NUL byte and change Argon2 input (address mismatch).
unsafe fn from_cstr_optional(ptr: *const c_char) -> Option<&'static str> {
    let s = from_cstr(ptr)?;
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

unsafe fn from_cstr_or_empty(ptr: *const c_char) -> &'static str {
    from_cstr(ptr).unwrap_or("")
}

/// Free a string returned by any acegf_* function
#[no_mangle]
pub unsafe extern "C" fn acegf_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

// =====================================================
// Version
// =====================================================

#[no_mangle]
pub extern "C" fn acegf_version() -> *mut c_char {
    to_cstring(ACEGF::VERSION.to_string())
}

// =====================================================
// Wallet Generation
// =====================================================

/// Generate a new wallet with passphrase
/// Returns JSON: { mnemonic, solana_address, evm_address, bitcoin_address, cosmos_address, polkadot_address, xaddress, x25519 }
/// or JSON: { error: true, message: "..." }
#[no_mangle]
pub unsafe extern "C" fn acegf_generate(passphrase: *const c_char) -> *mut c_char {
    acegf_generate_with_secondary(passphrase, std::ptr::null())
}

/// Generate a new wallet with passphrase and optional secondary passphrase
#[no_mangle]
pub unsafe extern "C" fn acegf_generate_with_secondary(
    passphrase: *const c_char,
    secondary_passphrase: *const c_char,
) -> *mut c_char {
    let pass = from_cstr_or_empty(passphrase);
    let sec_pass = from_cstr_optional(secondary_passphrase);

    match ACEGFCore::generate_ace_internal(pass, sec_pass) {
        Ok(entity) => {
            let json = serde_json::json!({
                "mnemonic": &*entity.mnemonic,
                "solana_address": entity.solana_address,
                "evm_address": entity.evm_address,
                "bitcoin_address": entity.bitcoin_address,
                "cosmos_address": entity.cosmos_address,
                "polkadot_address": entity.polkadot_address,
                "xaddress": entity.xaddress,
                "x25519": entity.x25519,
                "xkem": entity.xkem,
            });
            to_cstring(json.to_string())
        }
        Err(e) => {
            let json = serde_json::json!({ "error": true, "message": format!("{}", e) });
            to_cstring(json.to_string())
        }
    }
}

// =====================================================
// View Wallet (restore from mnemonic)
// =====================================================

/// Restore wallet from mnemonic
/// Returns JSON with wallet addresses or error
#[no_mangle]
pub unsafe extern "C" fn acegf_view_wallet(
    mnemonic: *const c_char,
    passphrase: *const c_char,
) -> *mut c_char {
    acegf_view_wallet_with_secondary(mnemonic, passphrase, std::ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn acegf_view_wallet_with_secondary(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    secondary_passphrase: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let sec_pass = from_cstr_optional(secondary_passphrase);

    match ACEGFCore::view_wallet_internal(mnemonic_str, pass, sec_pass) {
        Ok(entity) => {
            let json = serde_json::json!({
                "mnemonic": &*entity.mnemonic,
                "solana_address": entity.solana_address,
                "evm_address": entity.evm_address,
                "bitcoin_address": entity.bitcoin_address,
                "cosmos_address": entity.cosmos_address,
                "polkadot_address": entity.polkadot_address,
                "xaddress": entity.xaddress,
                "x25519": entity.x25519,
                "xkem": entity.xkem,
            });
            to_cstring(json.to_string())
        }
        Err(e) => {
            let json = serde_json::json!({ "error": true, "message": format!("{}", e) });
            to_cstring(json.to_string())
        }
    }
}

// =====================================================
// Signing
// =====================================================

/// Sign message - returns base64 signature on success, or "error:..." on failure
/// curve: 0 = Ed25519, 1 = Secp256k1
#[no_mangle]
pub unsafe extern "C" fn acegf_sign_message(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    message: *const u8,
    message_len: size_t,
    curve: u32,
) -> *mut c_char {
    acegf_sign_message_with_secondary(
        mnemonic,
        passphrase,
        std::ptr::null(),
        message,
        message_len,
        curve,
    )
}

#[no_mangle]
pub unsafe extern "C" fn acegf_sign_message_with_secondary(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    secondary_passphrase: *const c_char,
    message: *const u8,
    message_len: size_t,
    curve: u32,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let sec_pass = from_cstr_optional(secondary_passphrase);

    if message.is_null() || message_len == 0 {
        return to_cstring("error:empty message".to_string());
    }
    let message_slice = std::slice::from_raw_parts(message, message_len);

    match ACEGF::sign_message_internal(mnemonic_str, pass, sec_pass, message_slice, curve) {
        Ok(sig) => to_cstring(Base64::encode_string(&sig)),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

// =====================================================
// X25519 Sign/Verify
// =====================================================

#[no_mangle]
pub unsafe extern "C" fn acegf_x25519_sign(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    message: *const u8,
    message_len: size_t,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);

    if message.is_null() || message_len == 0 {
        return to_cstring("error:empty message".to_string());
    }
    let message_slice = std::slice::from_raw_parts(message, message_len);

    match ACEGF::sign_message_internal(mnemonic_str, pass, None, message_slice, 0) {
        Ok(sig) => to_cstring(Base64::encode_string(&sig)),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn acegf_x25519_verify(
    x25519_b64: *const c_char,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
) -> *mut c_char {
    let x25519_str = from_cstr_or_empty(x25519_b64);

    if message.is_null() || signature.is_null() {
        return to_cstring("error:null pointer".to_string());
    }
    let message_slice = std::slice::from_raw_parts(message, message_len);
    let signature_slice = std::slice::from_raw_parts(signature, signature_len);

    match ACEGF::x25519_verify_internal(x25519_str, message_slice, signature_slice) {
        Ok(valid) => to_cstring(if valid {
            "true".to_string()
        } else {
            "false".to_string()
        }),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

// =====================================================
// DH Shared Key
// =====================================================

#[no_mangle]
pub unsafe extern "C" fn acegf_compute_dh_key(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    peer_pub_b64: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let peer_pub = from_cstr_or_empty(peer_pub_b64);

    match ACEGF::compute_dh_key_internal(mnemonic_str, pass, peer_pub, None) {
        Ok(key) => to_cstring(Base64::encode_string(&key)),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

// =====================================================
// Passphrase Rotation
// =====================================================

#[no_mangle]
pub unsafe extern "C" fn acegf_change_passphrase(
    mnemonic: *const c_char,
    old_passphrase: *const c_char,
    new_passphrase: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let old_pass = from_cstr_or_empty(old_passphrase);
    let new_pass = from_cstr_or_empty(new_passphrase);

    match ACEGFCore::change_passphrase_internal(mnemonic_str, old_pass, new_pass, None) {
        Ok(new_mnemonic) => to_cstring(new_mnemonic),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

// =====================================================
// Encryption/Decryption
// =====================================================

/// Encrypt data for a recipient's x25519 public key
/// Returns JSON: { ephemeral_pub, encrypted_aes_key, iv, encrypted_data }
#[no_mangle]
pub unsafe extern "C" fn acegf_encrypt_for_x25519(
    recipient_x25519_b64: *const c_char,
    plaintext: *const u8,
    plaintext_len: size_t,
) -> *mut c_char {
    if recipient_x25519_b64.is_null() || plaintext.is_null() {
        return to_cstring("error:null pointer".to_string());
    }

    let x25519_str = from_cstr_or_empty(recipient_x25519_b64);
    let plaintext_slice = std::slice::from_raw_parts(plaintext, plaintext_len);

    match ACEGF::encrypt_for_x25519(x25519_str, plaintext_slice) {
        Ok((ephemeral_pub, encrypted_aes_key, iv, encrypted_data)) => {
            let json = serde_json::json!({
                "ephemeral_pub": ephemeral_pub,
                "encrypted_aes_key": encrypted_aes_key,
                "iv": iv,
                "encrypted_data": Base64::encode_string(&encrypted_data)
            });
            to_cstring(json.to_string())
        }
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

// =====================================================
// XKEM (ML-KEM-768 / FIPS 203) — post-quantum key encapsulation
//
// Interface shape is deliberately aligned with the x25519 (X25519) FFI
// surface above: Base64 strings in, Base64 strings out, error handling via
// "error:..." C-string conventions. Callers can drop KEM into the same code
// paths that currently publish / consume `x25519`.
// =====================================================

/// Get the wallet's xkem (ML-KEM-768 encapsulation key) as a Base64
/// C string, derived from `mnemonic + passphrase`.
///
/// Parallel to `acegf_x25519_sign` in that the wallet-side key is
/// re-derived from the mnemonic; the returned string is the public
/// encapsulation key that the wallet publishes as its post-quantum
/// key-exchange identity.
///
/// Returns a C string ("<base64>" on success, "error:..." on failure).
#[no_mangle]
pub unsafe extern "C" fn acegf_xkem_pubkey(
    mnemonic: *const c_char,
    passphrase: *const c_char,
) -> *mut c_char {
    use crate::pqclean_ffi::MlKem768;

    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);

    let seeds = match ACEGFCore::unseal_to_seeds(mnemonic_str, pass, None) {
        Ok(s) => s,
        Err(e) => return to_cstring(format!("error:{:?}", e)),
    };

    match MlKem768::keypair_from_seed(&seeds.ml_kem_768) {
        Ok((ek, _)) => to_cstring(Base64::encode_string(&ek)),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Encapsulate a shared secret against a recipient's published xkem.
///
/// Parallel to `acegf_encrypt_for_x25519`: no mnemonic required; the
/// recipient's Base64 xkem is the only input beyond the returned JSON
/// transport shape.
///
/// Returns JSON C string on success:
///   `{ "shared_secret": "<b64>", "ciphertext": "<b64>" }`
/// Returns `"error:..."` on failure.
#[no_mangle]
pub unsafe extern "C" fn acegf_encapsulate_for_xkem(
    recipient_xkem_b64: *const c_char,
) -> *mut c_char {
    if recipient_xkem_b64.is_null() {
        return to_cstring("error:null pointer".to_string());
    }
    let xkem_str = from_cstr_or_empty(recipient_xkem_b64);

    match ACEGF::encapsulate_for_xkem(xkem_str) {
        Ok((shared_secret, ciphertext)) => {
            let json = serde_json::json!({
                "shared_secret": shared_secret,
                "ciphertext": ciphertext,
            });
            to_cstring(json.to_string())
        }
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Recover the 32-byte shared secret from an xkem ciphertext using the
/// wallet's own decapsulation key.
///
/// Parallel to `acegf_decrypt_with_mnemonic`: mnemonic + passphrase unlock
/// the wallet's ML-KEM-768 secret key, which is then applied to the Base64
/// ciphertext produced by `acegf_encapsulate_for_xkem`.
///
/// Returns a C string containing the Base64 shared secret on success, or
/// `"error:..."` on failure.
#[no_mangle]
pub unsafe extern "C" fn acegf_decapsulate_for_xkem(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    ciphertext_b64: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let ct_str = from_cstr_or_empty(ciphertext_b64);

    match ACEGF::decapsulate_for_xkem(mnemonic_str, pass, ct_str, None) {
        Ok(shared_secret_b64) => to_cstring(shared_secret_b64),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Decrypt with mnemonic (buffer-based version for Flutter FFI)
///
/// Two-pass usage:
/// 1. First call: pass dummy out_plaintext buffer, out_len = 1
///    - Returns false (0), but out_len is set to required buffer size
/// 2. Second call: allocate buffer of size out_len, pass it
///    - Returns true (1) on success, plaintext written to out_plaintext
///
/// Returns: 1 (true) on success, 0 (false) on failure or when returning required size
#[no_mangle]
pub unsafe extern "C" fn acegf_decrypt_with_mnemonic(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    ephemeral_pub_b64: *const c_char,
    encrypted_aes_key_b64: *const c_char,
    iv_b64: *const c_char,
    encrypted_data: *const u8,
    data_len: size_t,
    out_plaintext: *mut u8,
    out_len: *mut size_t,
    secondary_passphrase: *const c_char,
) -> u8 {
    // Validate required pointers
    if mnemonic.is_null()
        || encrypted_data.is_null()
        || data_len == 0
        || out_plaintext.is_null()
        || out_len.is_null()
    {
        return 0;
    }

    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let sec_pass = from_cstr_optional(secondary_passphrase);
    let ephemeral_pub = from_cstr_or_empty(ephemeral_pub_b64);
    let encrypted_key = from_cstr_or_empty(encrypted_aes_key_b64);
    let iv = from_cstr_or_empty(iv_b64);
    let ciphertext = std::slice::from_raw_parts(encrypted_data, data_len);

    match ACEGF::decrypt_internal(
        mnemonic_str,
        pass,
        ephemeral_pub,
        encrypted_key,
        iv,
        ciphertext,
        sec_pass,
    ) {
        Ok(plaintext) => {
            let available = *out_len;
            let needed = plaintext.len();

            // Set the required/actual length
            *out_len = needed;

            // If buffer is too small, return 0 but with out_len set
            // This allows caller to allocate correct size and call again
            if available < needed {
                return 0;
            }

            // Copy plaintext to output buffer
            std::ptr::copy_nonoverlapping(plaintext.as_ptr(), out_plaintext, needed);
            1 // success
        }
        Err(_) => {
            *out_len = 0;
            0 // failure
        }
    }
}

/// Decrypt with mnemonic (string return version - legacy)
/// Returns base64-encoded plaintext on success, or "error:..." on failure
#[no_mangle]
pub unsafe extern "C" fn acegf_decrypt_with_mnemonic_str(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    ephemeral_pub_b64: *const c_char,
    encrypted_aes_key_b64: *const c_char,
    iv_b64: *const c_char,
    encrypted_data: *const u8,
    data_len: size_t,
) -> *mut c_char {
    if mnemonic.is_null() || encrypted_data.is_null() || data_len == 0 {
        return to_cstring("error:invalid parameters".to_string());
    }

    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let ephemeral_pub = from_cstr_or_empty(ephemeral_pub_b64);
    let encrypted_key = from_cstr_or_empty(encrypted_aes_key_b64);
    let iv = from_cstr_or_empty(iv_b64);
    let ciphertext = std::slice::from_raw_parts(encrypted_data, data_len);

    match ACEGF::decrypt_internal(
        mnemonic_str,
        pass,
        ephemeral_pub,
        encrypted_key,
        iv,
        ciphertext,
        None,
    ) {
        Ok(plaintext) => to_cstring(Base64::encode_string(&plaintext)),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

// =====================================================
// Hybrid X25519 + ML-KEM-768 Encrypt / Decrypt — THE NEW DEFAULT
//
// These functions fully replace `acegf_encrypt_for_x25519` /
// `acegf_decrypt_with_mnemonic*` for any new code path that needs to be
// post-quantum safe. The legacy pair is retained unchanged only so existing
// ciphertexts remain readable.
//
// Wire format: a `HybridEncryptedPayload` serialized as JSON — same shape
// as the WASM side, see `acegf_encrypt_for_recipient_pq_wasm`.
// =====================================================

/// Encrypt `plaintext` for a recipient using hybrid X25519 + ML-KEM-768.
///
/// Both `recipient_x25519_b64` and `recipient_xkem_b64` are required —
/// there is NO silent fallback to legacy X25519-only encryption. If either
/// is missing or malformed the call returns `"error:..."`.
///
/// On success returns a C string containing a JSON-encoded
/// `HybridEncryptedPayload`. On failure returns a C string prefixed with
/// `"error:"`. The caller must free the returned pointer via
/// [`acegf_free_string`].
#[no_mangle]
pub unsafe extern "C" fn acegf_encrypt_for_recipient_pq(
    recipient_x25519_b64: *const c_char,
    recipient_xkem_b64: *const c_char,
    plaintext: *const u8,
    plaintext_len: size_t,
) -> *mut c_char {
    if recipient_x25519_b64.is_null() || recipient_xkem_b64.is_null() || plaintext.is_null() {
        return to_cstring("error:null pointer".to_string());
    }

    let x25519_str = from_cstr_or_empty(recipient_x25519_b64);
    let xkem_str = from_cstr_or_empty(recipient_xkem_b64);
    let plaintext_slice = std::slice::from_raw_parts(plaintext, plaintext_len);

    match ACEGF::encrypt_for_recipient_pq(x25519_str, xkem_str, plaintext_slice) {
        Ok(payload) => match serde_json::to_string(&payload) {
            Ok(json) => to_cstring(json),
            Err(e) => to_cstring(format!("error:serialization failed: {}", e)),
        },
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Decrypt a hybrid encrypted payload (provided as its JSON string form)
/// using `mnemonic + passphrase`.
///
/// The version field of the payload is checked with strict equality; any
/// deviation fails hard (no downgrade to the legacy X25519 path).
///
/// On success returns a C string containing the Base64-encoded plaintext.
/// On failure returns `"error:..."`. The caller must free the returned
/// pointer via [`acegf_free_string`].
#[no_mangle]
pub unsafe extern "C" fn acegf_decrypt_for_recipient_pq(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    payload_json: *const c_char,
) -> *mut c_char {
    use crate::acegf::HybridEncryptedPayload;

    if mnemonic.is_null() || payload_json.is_null() {
        return to_cstring("error:null pointer".to_string());
    }

    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let payload_json_str = from_cstr_or_empty(payload_json);

    let payload: HybridEncryptedPayload = match serde_json::from_str(payload_json_str) {
        Ok(p) => p,
        Err(e) => {
            return to_cstring(format!(
                "error:failed to parse HybridEncryptedPayload JSON: {}",
                e
            ))
        }
    };

    match ACEGF::decrypt_for_recipient_pq(mnemonic_str, pass, &payload, None) {
        Ok(plaintext) => to_cstring(Base64::encode_string(&plaintext)),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Decrypt with passkey PRF key (buffer-based version for Flutter FFI)
///
/// Uses PRF key from WebAuthn Secure Enclave instead of a passphrase.
/// The PRF key is fed through Argon2 to derive base_key, then used
/// to unseal the mnemonic and perform ECDH decryption.
///
/// Two-pass usage (same as acegf_decrypt_with_mnemonic):
/// 1. First call: pass dummy out_plaintext buffer, out_len = 1
///    - Returns 0, but out_len is set to required buffer size
/// 2. Second call: allocate buffer of size out_len, pass it
///    - Returns 1 on success, plaintext written to out_plaintext
///
/// Parameters:
/// - mnemonic: ACE-GF mnemonic (C string)
/// - prf_key_ptr: PRF output from WebAuthn (raw bytes)
/// - prf_key_len: length of PRF key (typically 32 bytes)
/// - ephemeral_pub_b64: base64-encoded ephemeral public key
/// - encrypted_aes_key_b64: base64-encoded encrypted AES key
/// - iv_b64: base64-encoded IV
/// - encrypted_data: ciphertext bytes
/// - data_len: length of ciphertext
/// - out_plaintext: output buffer for plaintext
/// - out_len: in/out size parameter
///
/// Returns: 1 on success, 0 on failure
#[no_mangle]
pub unsafe extern "C" fn acegf_decrypt_with_passkey(
    mnemonic: *const c_char,
    prf_key_ptr: *const u8,
    prf_key_len: size_t,
    ephemeral_pub_b64: *const c_char,
    encrypted_aes_key_b64: *const c_char,
    iv_b64: *const c_char,
    encrypted_data: *const u8,
    data_len: size_t,
    out_plaintext: *mut u8,
    out_len: *mut size_t,
) -> u8 {
    // Validate required pointers
    if mnemonic.is_null()
        || prf_key_ptr.is_null()
        || prf_key_len == 0
        || encrypted_data.is_null()
        || data_len == 0
        || out_plaintext.is_null()
        || out_len.is_null()
    {
        return 0;
    }

    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let prf_key = std::slice::from_raw_parts(prf_key_ptr, prf_key_len);
    let ephemeral_pub = from_cstr_or_empty(ephemeral_pub_b64);
    let encrypted_key = from_cstr_or_empty(encrypted_aes_key_b64);
    let iv = from_cstr_or_empty(iv_b64);
    let ciphertext = std::slice::from_raw_parts(encrypted_data, data_len);

    // Derive base_key from PRF key via Argon2
    use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;
    let base_key = match PassphraseSealingUtil::derive_base_key(prf_key) {
        Ok(k) => k,
        Err(_) => {
            *out_len = 0;
            return 0;
        }
    };

    match ACEGF::decrypt_with_base_key(
        mnemonic_str,
        &base_key,
        ephemeral_pub,
        encrypted_key,
        iv,
        ciphertext,
    ) {
        Ok(plaintext) => {
            let available = *out_len;
            let needed = plaintext.len();

            *out_len = needed;

            if available < needed {
                return 0;
            }

            std::ptr::copy_nonoverlapping(plaintext.as_ptr(), out_plaintext, needed);
            1 // success
        }
        Err(_) => {
            *out_len = 0;
            0
        }
    }
}

/// Free a C string allocated by acegf (alias for acegf_free_string)
#[no_mangle]
pub unsafe extern "C" fn acegf_free_cstring(ptr: *mut c_char) {
    acegf_free_string(ptr);
}

// =====================================================
// Solana Transactions
// =====================================================

#[no_mangle]
pub unsafe extern "C" fn solana_sign_system_transfer(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    to_pubkey: *const c_char,
    lamports: u64,
    recent_blockhash: *const c_char,
) -> *mut c_char {
    solana_sign_system_transfer_with_secondary(
        mnemonic,
        passphrase,
        std::ptr::null(),
        to_pubkey,
        lamports,
        recent_blockhash,
    )
}

#[no_mangle]
pub unsafe extern "C" fn solana_sign_system_transfer_with_secondary(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    secondary_passphrase: *const c_char,
    to_pubkey: *const c_char,
    lamports: u64,
    recent_blockhash: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let sec_pass = from_cstr_optional(secondary_passphrase);
    let to_str = from_cstr_or_empty(to_pubkey);
    let blockhash = from_cstr_or_empty(recent_blockhash);

    match SolanaSigner::sign_system_transfer_tx(
        mnemonic_str,
        pass,
        sec_pass,
        to_str,
        lamports,
        blockhash,
    ) {
        Ok(tx_bytes) => to_cstring(Base64::encode_string(&tx_bytes)),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn solana_sign_spl_transfer(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    mint: *const c_char,
    to_wallet: *const c_char,
    amount: u64,
    recent_blockhash: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let mint_str = from_cstr_or_empty(mint);
    let to_str = from_cstr_or_empty(to_wallet);
    let blockhash = from_cstr_or_empty(recent_blockhash);

    match SolanaSigner::sign_spl_transfer_tx(
        mnemonic_str,
        pass,
        mint_str,
        to_str,
        amount,
        blockhash,
    ) {
        Ok(tx_bytes) => to_cstring(Base64::encode_string(&tx_bytes)),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn solana_get_ata_address(
    wallet: *const c_char,
    mint: *const c_char,
) -> *mut c_char {
    let wallet_str = from_cstr_or_empty(wallet);
    let mint_str = from_cstr_or_empty(mint);

    let wallet_bytes = match bs58::decode(wallet_str).into_vec() {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return to_cstring("error:invalid wallet address".to_string()),
    };

    let mint_bytes = match bs58::decode(mint_str).into_vec() {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return to_cstring("error:invalid mint address".to_string()),
    };

    match SolanaSigner::get_associated_token_address(&wallet_bytes, &mint_bytes) {
        Ok(ata) => to_cstring(bs58::encode(ata).into_string()),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn solana_sign_spl_transfer_with_create_ata(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    mint: *const c_char,
    to_wallet: *const c_char,
    amount: u64,
    recent_blockhash: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let mint_str = from_cstr_or_empty(mint);
    let to_str = from_cstr_or_empty(to_wallet);
    let blockhash = from_cstr_or_empty(recent_blockhash);

    match SolanaSigner::sign_spl_transfer_with_create_ata_tx(
        mnemonic_str,
        pass,
        mint_str,
        to_str,
        amount,
        blockhash,
    ) {
        Ok(tx_bytes) => to_cstring(Base64::encode_string(&tx_bytes)),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn solana_sign_transaction(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    serialized_tx_base64: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let tx_b64 = from_cstr_or_empty(serialized_tx_base64);

    match SolanaSigner::sign_serialized_transaction(mnemonic_str, pass, tx_b64) {
        Ok(signed_tx) => to_cstring(signed_tx),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

// =====================================================
// VA-DAR (Vendor-Agnostic Deterministic Artifact Resolution)
// =====================================================

#[no_mangle]
pub unsafe extern "C" fn vadar_normalize_email(email: *const c_char) -> *mut c_char {
    let email_str = from_cstr_or_empty(email);
    to_cstring(VADAR::normalize_email(email_str))
}

#[no_mangle]
pub unsafe extern "C" fn vadar_compute_discovery_id(
    password: *const c_char,
    normalized_email: *const c_char,
) -> *mut c_char {
    let pass = from_cstr_or_empty(password);
    let email = from_cstr_or_empty(normalized_email);

    match VADAR::compute_discovery_id(pass, email) {
        Ok(id) => to_cstring(id),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn vadar_seal_sa2(
    mnemonic: *const c_char,
    password: *const c_char,
    normalized_email: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(password);
    let email = from_cstr_or_empty(normalized_email);

    match VADAR::seal_sa2(mnemonic_str, pass, email) {
        Ok(sa2) => to_cstring(sa2),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn vadar_unseal_sa2(
    sa2_base64: *const c_char,
    password: *const c_char,
    normalized_email: *const c_char,
) -> *mut c_char {
    let sa2 = from_cstr_or_empty(sa2_base64);
    let pass = from_cstr_or_empty(password);
    let email = from_cstr_or_empty(normalized_email);

    match VADAR::unseal_sa2(sa2, pass, email) {
        Ok(mnemonic) => to_cstring(mnemonic),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn vadar_get_owner_pubkey(
    password: *const c_char,
    normalized_email: *const c_char,
) -> *mut c_char {
    let pass = from_cstr_or_empty(password);
    let email = from_cstr_or_empty(normalized_email);

    match VADAR::get_owner_pubkey(pass, email) {
        Ok(pubkey) => to_cstring(pubkey),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn vadar_sign_registry_update(
    password: *const c_char,
    normalized_email: *const c_char,
    discovery_id: *const c_char,
    cid: *const c_char,
    version: u64,
    commit: *const c_char,
) -> *mut c_char {
    let pass = from_cstr_or_empty(password);
    let email = from_cstr_or_empty(normalized_email);
    let did = from_cstr_or_empty(discovery_id);
    let cid_str = from_cstr_or_empty(cid);
    let commit_str = from_cstr_or_empty(commit);

    match VADAR::sign_registry_update(pass, email, did, cid_str, version, commit_str) {
        Ok(sig) => to_cstring(sig),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn vadar_compute_commit(sa2_base64: *const c_char) -> *mut c_char {
    let sa2 = from_cstr_or_empty(sa2_base64);

    match VADAR::compute_commit(sa2) {
        Ok(commit) => to_cstring(commit),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

// =====================================================
// EVM Transaction Signing
// =====================================================

#[no_mangle]
pub unsafe extern "C" fn evm_sign_type0_transaction(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    chain_id: u64,
    nonce: *const c_char,
    gas_price: *const c_char,
    gas_limit: *const c_char,
    to: *const c_char,
    value: *const c_char,
    data: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let nonce_str = from_cstr_or_empty(nonce);
    let gas_price_str = from_cstr_or_empty(gas_price);
    let gas_limit_str = from_cstr_or_empty(gas_limit);
    let to_str = from_cstr_or_empty(to);
    let value_str = from_cstr_or_empty(value);
    let data_str = from_cstr_or_empty(data);

    match EvmSigner::sign_type0_transaction(
        mnemonic_str,
        pass,
        chain_id,
        nonce_str,
        gas_price_str,
        gas_limit_str,
        to_str,
        value_str,
        data_str,
    ) {
        Ok(signed_tx) => to_cstring(signed_tx),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn evm_sign_legacy_transaction(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    chain_id: u64,
    nonce: *const c_char,
    gas_price: *const c_char,
    gas_limit: *const c_char,
    to: *const c_char,
    value: *const c_char,
    data: *const c_char,
) -> *mut c_char {
    evm_sign_type0_transaction(
        mnemonic, passphrase, chain_id, nonce, gas_price, gas_limit, to, value, data,
    )
}

#[no_mangle]
pub unsafe extern "C" fn evm_sign_eip1559_transaction(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    chain_id: u64,
    nonce: *const c_char,
    max_priority_fee_per_gas: *const c_char,
    max_fee_per_gas: *const c_char,
    gas_limit: *const c_char,
    to: *const c_char,
    value: *const c_char,
    data: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let nonce_str = from_cstr_or_empty(nonce);
    let max_priority_str = from_cstr_or_empty(max_priority_fee_per_gas);
    let max_fee_str = from_cstr_or_empty(max_fee_per_gas);
    let gas_limit_str = from_cstr_or_empty(gas_limit);
    let to_str = from_cstr_or_empty(to);
    let value_str = from_cstr_or_empty(value);
    let data_str = from_cstr_or_empty(data);

    match EvmSigner::sign_eip1559_transaction(
        mnemonic_str,
        pass,
        chain_id,
        nonce_str,
        max_priority_str,
        max_fee_str,
        gas_limit_str,
        to_str,
        value_str,
        data_str,
    ) {
        Ok(signed_tx) => to_cstring(signed_tx),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn evm_sign_personal_message(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    message: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let msg = from_cstr_or_empty(message);

    match EvmSigner::sign_personal_message(mnemonic_str, pass, msg.as_bytes()) {
        Ok(signature) => to_cstring(signature),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn evm_sign_typed_data(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    typed_data_hash: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let hash = from_cstr_or_empty(typed_data_hash);

    match EvmSigner::sign_typed_data(mnemonic_str, pass, hash) {
        Ok(signature) => to_cstring(signature),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn evm_get_address(
    mnemonic: *const c_char,
    passphrase: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);

    match EvmSigner::get_address(mnemonic_str, pass) {
        Ok(address) => to_cstring(address),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn evm_compute_tx_hash(signed_tx: *const c_char) -> *mut c_char {
    let tx = from_cstr_or_empty(signed_tx);

    match EvmSigner::compute_tx_hash(tx) {
        Ok(hash) => to_cstring(hash),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn evm_encode_erc20_transfer(
    to: *const c_char,
    amount: *const c_char,
) -> *mut c_char {
    let to_str = from_cstr_or_empty(to);
    let amount_str = from_cstr_or_empty(amount);

    match EvmSigner::encode_erc20_transfer(to_str, amount_str) {
        Ok(data) => to_cstring(data),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn evm_encode_erc20_approve(
    spender: *const c_char,
    amount: *const c_char,
) -> *mut c_char {
    let spender_str = from_cstr_or_empty(spender);
    let amount_str = from_cstr_or_empty(amount);

    match EvmSigner::encode_erc20_approve(spender_str, amount_str) {
        Ok(data) => to_cstring(data),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

// =====================================================
// Bitcoin Transaction Signing
// =====================================================

/// Get Bitcoin P2WPKH address from mnemonic
/// Returns bc1q... (mainnet) or tb1q... (testnet), or "error:..." on failure
#[no_mangle]
pub unsafe extern "C" fn bitcoin_get_address(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    testnet: u8,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let is_testnet = testnet != 0;

    match BitcoinSigner::derive_keypair(mnemonic_str, pass, None) {
        Ok((_, compressed_pubkey)) => {
            match BitcoinSigner::pubkey_to_p2wpkh_address(&compressed_pubkey, is_testnet) {
                Ok(address) => to_cstring(address),
                Err(e) => to_cstring(format!("error:{}", e)),
            }
        }
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Get Bitcoin Taproot address from mnemonic
/// Returns bc1p... (mainnet) or tb1p... (testnet), or "error:..." on failure
#[no_mangle]
pub unsafe extern "C" fn bitcoin_get_taproot_address(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    testnet: u8,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let is_testnet = testnet != 0;

    let mut seeds = match ACEGFCore::unseal_to_seeds(mnemonic_str, pass, None) {
        Ok(s) => s,
        Err(e) => return to_cstring(format!("error:{:?}", e)),
    };

    let result =
        match ACEGFCore::derive_btc_taproot_address_for_network(&seeds.secp256k1_btc, is_testnet) {
            Ok(address) => to_cstring(address),
            Err(e) => to_cstring(format!("error:{}", e)),
        };

    ACEGFCore::clear_scheme_seeds(&mut seeds);
    result
}

/// Sign a Bitcoin transaction (auto-detects P2WPKH vs P2TR from inputs)
/// tx_json: JSON string with { version, inputs: [{txid, vout, value, sequence, script_pubkey}], outputs: [{value, script_pubkey}], locktime }
/// Returns signed transaction as hex string, or "error:..." on failure
#[no_mangle]
pub unsafe extern "C" fn bitcoin_sign_transaction(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    tx_json: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let tx_json_str = from_cstr_or_empty(tx_json);

    let unsigned_tx = match parse_bitcoin_tx_json(tx_json_str) {
        Ok(tx) => tx,
        Err(e) => return to_cstring(e),
    };

    let is_taproot = unsigned_tx
        .inputs
        .first()
        .map(|inp| BitcoinSigner::is_p2tr_script(&inp.script_pubkey))
        .unwrap_or(false);

    if is_taproot {
        match BitcoinSigner::derive_keypair(mnemonic_str, pass, None) {
            Ok((signing_key, _compressed_pubkey)) => {
                let result = BitcoinSigner::sign_taproot_tx_with_key(&signing_key, &unsigned_tx);
                drop(signing_key);
                match result {
                    Ok(signed_hex) => to_cstring(signed_hex),
                    Err(e) => to_cstring(format!("error:{}", e)),
                }
            }
            Err(e) => to_cstring(format!("error:{}", e)),
        }
    } else {
        match BitcoinSigner::sign_segwit_tx(mnemonic_str, pass, &unsigned_tx) {
            Ok(signed_hex) => to_cstring(signed_hex),
            Err(e) => to_cstring(format!("error:{}", e)),
        }
    }
}

/// Convert a Bitcoin bech32/bech32m address between mainnet and testnet
/// Returns converted address, or "error:..." on failure
#[no_mangle]
pub unsafe extern "C" fn bitcoin_convert_address_network(
    address: *const c_char,
    testnet: u8,
) -> *mut c_char {
    let addr = from_cstr_or_empty(address);
    let is_testnet = testnet != 0;

    let (witness_version, program) = match BitcoinSigner::decode_bech32_address(addr) {
        Ok(r) => r,
        Err(e) => return to_cstring(format!("error:{}", e)),
    };

    let hrp = if is_testnet { "tb" } else { "bc" };
    match BitcoinSigner::encode_bech32_public(hrp, witness_version, &program) {
        Ok(addr) => to_cstring(addr),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Generate scriptPubKey for any Bitcoin address
/// Returns scriptPubKey as hex string, or "error:..." on failure
#[no_mangle]
pub unsafe extern "C" fn bitcoin_address_to_script_pubkey(address: *const c_char) -> *mut c_char {
    let addr = from_cstr_or_empty(address);

    match BitcoinSigner::address_to_script_pubkey(addr) {
        Ok(script) => to_cstring(hex::encode(script)),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

// =====================================================
// REV32 Wallet Generation
// =====================================================

/// Generate a new REV32 wallet with passphrase
/// Returns JSON: { mnemonic, solana_address, evm_address, bitcoin_address, cosmos_address, polkadot_address, xaddress, x25519 }
/// or JSON: { error: true, message: "..." }
#[no_mangle]
pub unsafe extern "C" fn acegf_generate_rev32(passphrase: *const c_char) -> *mut c_char {
    acegf_generate_rev32_with_secondary(passphrase, std::ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn acegf_generate_rev32_with_secondary(
    passphrase: *const c_char,
    secondary_passphrase: *const c_char,
) -> *mut c_char {
    let pass = from_cstr_or_empty(passphrase);
    let sec_pass = from_cstr_optional(secondary_passphrase);

    match ACEGFCore::generate_ace_internal(pass, sec_pass) {
        Ok(entity) => {
            let json = serde_json::json!({
                "mnemonic": &*entity.mnemonic,
                "solana_address": entity.solana_address,
                "evm_address": entity.evm_address,
                "bitcoin_address": entity.bitcoin_address,
                "cosmos_address": entity.cosmos_address,
                "polkadot_address": entity.polkadot_address,
                "xaddress": entity.xaddress,
                "x25519": entity.x25519,
                "xkem": entity.xkem,
            });
            to_cstring(json.to_string())
        }
        Err(e) => {
            let json = serde_json::json!({ "error": true, "message": format!("{}", e) });
            to_cstring(json.to_string())
        }
    }
}

/// View REV32 wallet (restore from 24-word mnemonic)
#[no_mangle]
pub unsafe extern "C" fn acegf_view_wallet_rev32(
    mnemonic: *const c_char,
    passphrase: *const c_char,
) -> *mut c_char {
    acegf_view_wallet_rev32_with_secondary(mnemonic, passphrase, std::ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn acegf_view_wallet_rev32_with_secondary(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    secondary_passphrase: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let sec_pass = from_cstr_optional(secondary_passphrase);

    match ACEGFCore::view_wallet_internal(mnemonic_str, pass, sec_pass) {
        Ok(entity) => {
            let json = serde_json::json!({
                "mnemonic": &*entity.mnemonic,
                "solana_address": entity.solana_address,
                "evm_address": entity.evm_address,
                "bitcoin_address": entity.bitcoin_address,
                "cosmos_address": entity.cosmos_address,
                "polkadot_address": entity.polkadot_address,
                "xaddress": entity.xaddress,
                "x25519": entity.x25519,
                "xkem": entity.xkem,
            });
            to_cstring(json.to_string())
        }
        Err(e) => {
            let json = serde_json::json!({ "error": true, "message": format!("{}", e) });
            to_cstring(json.to_string())
        }
    }
}

/// Unified wallet view for canonical REV32 mnemonics.
#[no_mangle]
pub unsafe extern "C" fn acegf_view_wallet_unified(
    mnemonic: *const c_char,
    passphrase: *const c_char,
) -> *mut c_char {
    acegf_view_wallet_unified_with_secondary(mnemonic, passphrase, std::ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn acegf_view_wallet_unified_with_secondary(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    secondary_passphrase: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let pass = from_cstr_or_empty(passphrase);
    let sec_pass = from_cstr_optional(secondary_passphrase);

    match ACEGFCore::view_wallet_unified(mnemonic_str, pass, sec_pass) {
        Ok(entity) => {
            let json = serde_json::json!({
                "mnemonic": &*entity.mnemonic,
                "solana_address": entity.solana_address,
                "evm_address": entity.evm_address,
                "bitcoin_address": entity.bitcoin_address,
                "cosmos_address": entity.cosmos_address,
                "polkadot_address": entity.polkadot_address,
                "xaddress": entity.xaddress,
                "x25519": entity.x25519,
                "xkem": entity.xkem,
            });
            to_cstring(json.to_string())
        }
        Err(e) => {
            let json = serde_json::json!({ "error": true, "message": format!("{}", e) });
            to_cstring(json.to_string())
        }
    }
}

// =====================================================
// PRF-backed functions (Passkey Secure Enclave path)
// =====================================================
// These functions accept a raw PRF key from WebAuthn instead of a passphrase.
// The PRF key is fed through Argon2 to derive the base_key.

/// View wallet using PRF key
#[no_mangle]
pub unsafe extern "C" fn acegf_view_wallet_with_prf(
    mnemonic: *const c_char,
    prf_key_ptr: *const u8,
    prf_key_len: size_t,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);

    if prf_key_ptr.is_null() || prf_key_len == 0 {
        let json = serde_json::json!({ "error": true, "message": "null PRF key" });
        return to_cstring(json.to_string());
    }
    let prf_key = std::slice::from_raw_parts(prf_key_ptr, prf_key_len);

    let base_key = match PassphraseSealingUtil::derive_base_key(prf_key) {
        Ok(k) => k,
        Err(e) => {
            let json = serde_json::json!({ "error": true, "message": format!("PRF key derivation failed: {:?}", e) });
            return to_cstring(json.to_string());
        }
    };

    match ACEGFCore::view_wallet_with_base_key(mnemonic_str, &base_key) {
        Ok(entity) => {
            let json = serde_json::json!({
                "mnemonic": &*entity.mnemonic,
                "solana_address": entity.solana_address,
                "evm_address": entity.evm_address,
                "bitcoin_address": entity.bitcoin_address,
                "cosmos_address": entity.cosmos_address,
                "polkadot_address": entity.polkadot_address,
                "xaddress": entity.xaddress,
                "x25519": entity.x25519,
                "xkem": entity.xkem,
            });
            to_cstring(json.to_string())
        }
        Err(e) => {
            let json = serde_json::json!({ "error": true, "message": format!("{}", e) });
            to_cstring(json.to_string())
        }
    }
}

/// Sign message using PRF key
/// Returns base64 signature on success, or "error:..." on failure
#[no_mangle]
pub unsafe extern "C" fn acegf_sign_message_with_prf(
    mnemonic: *const c_char,
    prf_key_ptr: *const u8,
    prf_key_len: size_t,
    message: *const u8,
    message_len: size_t,
    curve: u32,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);

    if prf_key_ptr.is_null() || prf_key_len == 0 {
        return to_cstring("error:null PRF key".to_string());
    }
    if message.is_null() || message_len == 0 {
        return to_cstring("error:empty message".to_string());
    }

    let prf_key = std::slice::from_raw_parts(prf_key_ptr, prf_key_len);
    let message_slice = std::slice::from_raw_parts(message, message_len);

    let base_key = match PassphraseSealingUtil::derive_base_key(prf_key) {
        Ok(k) => k,
        Err(_) => return to_cstring("error:PRF key derivation failed".to_string()),
    };

    match ACEGF::sign_message_with_base_key(mnemonic_str, &base_key, message_slice, curve) {
        Ok(sig) => to_cstring(Base64::encode_string(&sig)),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Compute DH shared key using PRF key
/// Returns base64-encoded key on success, or "error:..." on failure
#[no_mangle]
pub unsafe extern "C" fn acegf_compute_dh_key_with_prf(
    mnemonic: *const c_char,
    prf_key_ptr: *const u8,
    prf_key_len: size_t,
    peer_pub_b64: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let peer_pub = from_cstr_or_empty(peer_pub_b64);

    if prf_key_ptr.is_null() || prf_key_len == 0 {
        return to_cstring("error:null PRF key".to_string());
    }
    let prf_key = std::slice::from_raw_parts(prf_key_ptr, prf_key_len);

    let base_key = match PassphraseSealingUtil::derive_base_key(prf_key) {
        Ok(k) => k,
        Err(_) => return to_cstring("error:PRF key derivation failed".to_string()),
    };

    match ACEGF::compute_dh_key_with_base_key_and_peer(mnemonic_str, &base_key, peer_pub) {
        Ok(key) => to_cstring(Base64::encode_string(&key)),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Decrypt with PRF key (string return version)
/// Returns base64-encoded plaintext on success, or "error:..." on failure
#[no_mangle]
pub unsafe extern "C" fn acegf_decrypt_with_prf(
    mnemonic: *const c_char,
    prf_key_ptr: *const u8,
    prf_key_len: size_t,
    ephemeral_pub_b64: *const c_char,
    encrypted_aes_key_b64: *const c_char,
    iv_b64: *const c_char,
    encrypted_data: *const u8,
    data_len: size_t,
) -> *mut c_char {
    if mnemonic.is_null()
        || prf_key_ptr.is_null()
        || prf_key_len == 0
        || encrypted_data.is_null()
        || data_len == 0
    {
        return to_cstring("error:invalid parameters".to_string());
    }

    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let prf_key = std::slice::from_raw_parts(prf_key_ptr, prf_key_len);
    let ephemeral_pub = from_cstr_or_empty(ephemeral_pub_b64);
    let encrypted_key = from_cstr_or_empty(encrypted_aes_key_b64);
    let iv = from_cstr_or_empty(iv_b64);
    let ciphertext = std::slice::from_raw_parts(encrypted_data, data_len);

    let base_key = match PassphraseSealingUtil::derive_base_key(prf_key) {
        Ok(k) => k,
        Err(_) => return to_cstring("error:PRF key derivation failed".to_string()),
    };

    match ACEGF::decrypt_with_base_key(
        mnemonic_str,
        &base_key,
        ephemeral_pub,
        encrypted_key,
        iv,
        ciphertext,
    ) {
        Ok(plaintext) => to_cstring(Base64::encode_string(&plaintext)),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Sign EVM Type-0 Transaction using PRF key
#[no_mangle]
pub unsafe extern "C" fn evm_sign_type0_transaction_with_prf(
    mnemonic: *const c_char,
    prf_key_ptr: *const u8,
    prf_key_len: size_t,
    chain_id: u64,
    nonce: *const c_char,
    gas_price: *const c_char,
    gas_limit: *const c_char,
    to: *const c_char,
    value: *const c_char,
    data: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);

    if prf_key_ptr.is_null() || prf_key_len == 0 {
        return to_cstring("error:null PRF key".to_string());
    }
    let prf_key = std::slice::from_raw_parts(prf_key_ptr, prf_key_len);

    let base_key = match PassphraseSealingUtil::derive_base_key(prf_key) {
        Ok(k) => k,
        Err(_) => return to_cstring("error:PRF key derivation failed".to_string()),
    };

    let nonce_str = from_cstr_or_empty(nonce);
    let gas_price_str = from_cstr_or_empty(gas_price);
    let gas_limit_str = from_cstr_or_empty(gas_limit);
    let to_str = from_cstr_or_empty(to);
    let value_str = from_cstr_or_empty(value);
    let data_str = from_cstr_or_empty(data);

    match EvmSigner::derive_keypair_with_base_key(mnemonic_str, &base_key) {
        Ok((signing_key, _addr)) => {
            match EvmSigner::sign_type0_transaction_with_key(
                &signing_key,
                chain_id,
                nonce_str,
                gas_price_str,
                gas_limit_str,
                to_str,
                value_str,
                data_str,
            ) {
                Ok(signed_tx) => to_cstring(signed_tx),
                Err(e) => to_cstring(format!("error:{}", e)),
            }
        }
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn evm_sign_legacy_transaction_with_prf(
    mnemonic: *const c_char,
    prf_key_ptr: *const u8,
    prf_key_len: size_t,
    chain_id: u64,
    nonce: *const c_char,
    gas_price: *const c_char,
    gas_limit: *const c_char,
    to: *const c_char,
    value: *const c_char,
    data: *const c_char,
) -> *mut c_char {
    evm_sign_type0_transaction_with_prf(
        mnemonic,
        prf_key_ptr,
        prf_key_len,
        chain_id,
        nonce,
        gas_price,
        gas_limit,
        to,
        value,
        data,
    )
}

/// Sign EVM EIP-1559 Transaction using PRF key
#[no_mangle]
pub unsafe extern "C" fn evm_sign_eip1559_transaction_with_prf(
    mnemonic: *const c_char,
    prf_key_ptr: *const u8,
    prf_key_len: size_t,
    chain_id: u64,
    nonce: *const c_char,
    max_priority_fee_per_gas: *const c_char,
    max_fee_per_gas: *const c_char,
    gas_limit: *const c_char,
    to: *const c_char,
    value: *const c_char,
    data: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);

    if prf_key_ptr.is_null() || prf_key_len == 0 {
        return to_cstring("error:null PRF key".to_string());
    }
    let prf_key = std::slice::from_raw_parts(prf_key_ptr, prf_key_len);

    let base_key = match PassphraseSealingUtil::derive_base_key(prf_key) {
        Ok(k) => k,
        Err(_) => return to_cstring("error:PRF key derivation failed".to_string()),
    };

    let nonce_str = from_cstr_or_empty(nonce);
    let max_priority_str = from_cstr_or_empty(max_priority_fee_per_gas);
    let max_fee_str = from_cstr_or_empty(max_fee_per_gas);
    let gas_limit_str = from_cstr_or_empty(gas_limit);
    let to_str = from_cstr_or_empty(to);
    let value_str = from_cstr_or_empty(value);
    let data_str = from_cstr_or_empty(data);

    match EvmSigner::derive_keypair_with_base_key(mnemonic_str, &base_key) {
        Ok((signing_key, _addr)) => {
            match EvmSigner::sign_eip1559_transaction_with_key(
                &signing_key,
                chain_id,
                nonce_str,
                max_priority_str,
                max_fee_str,
                gas_limit_str,
                to_str,
                value_str,
                data_str,
            ) {
                Ok(signed_tx) => to_cstring(signed_tx),
                Err(e) => to_cstring(format!("error:{}", e)),
            }
        }
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Sign EVM personal message using PRF key
#[no_mangle]
pub unsafe extern "C" fn evm_sign_personal_message_with_prf(
    mnemonic: *const c_char,
    prf_key_ptr: *const u8,
    prf_key_len: size_t,
    message: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let msg = from_cstr_or_empty(message);

    if prf_key_ptr.is_null() || prf_key_len == 0 {
        return to_cstring("error:null PRF key".to_string());
    }
    let prf_key = std::slice::from_raw_parts(prf_key_ptr, prf_key_len);

    let base_key = match PassphraseSealingUtil::derive_base_key(prf_key) {
        Ok(k) => k,
        Err(_) => return to_cstring("error:PRF key derivation failed".to_string()),
    };

    match EvmSigner::derive_keypair_with_base_key(mnemonic_str, &base_key) {
        Ok((signing_key, _addr)) => {
            match EvmSigner::sign_personal_message_with_key(&signing_key, msg.as_bytes()) {
                Ok(signature) => to_cstring(signature),
                Err(e) => to_cstring(format!("error:{}", e)),
            }
        }
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Sign EVM typed data using PRF key
#[no_mangle]
pub unsafe extern "C" fn evm_sign_typed_data_with_prf(
    mnemonic: *const c_char,
    prf_key_ptr: *const u8,
    prf_key_len: size_t,
    typed_data_hash: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let hash = from_cstr_or_empty(typed_data_hash);

    if prf_key_ptr.is_null() || prf_key_len == 0 {
        return to_cstring("error:null PRF key".to_string());
    }
    let prf_key = std::slice::from_raw_parts(prf_key_ptr, prf_key_len);

    let base_key = match PassphraseSealingUtil::derive_base_key(prf_key) {
        Ok(k) => k,
        Err(_) => return to_cstring("error:PRF key derivation failed".to_string()),
    };

    match EvmSigner::derive_keypair_with_base_key(mnemonic_str, &base_key) {
        Ok((signing_key, _addr)) => match EvmSigner::sign_typed_data_with_key(&signing_key, hash) {
            Ok(signature) => to_cstring(signature),
            Err(e) => to_cstring(format!("error:{}", e)),
        },
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Get EVM address using PRF key
#[no_mangle]
pub unsafe extern "C" fn evm_get_address_with_prf(
    mnemonic: *const c_char,
    prf_key_ptr: *const u8,
    prf_key_len: size_t,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);

    if prf_key_ptr.is_null() || prf_key_len == 0 {
        return to_cstring("error:null PRF key".to_string());
    }
    let prf_key = std::slice::from_raw_parts(prf_key_ptr, prf_key_len);

    let base_key = match PassphraseSealingUtil::derive_base_key(prf_key) {
        Ok(k) => k,
        Err(_) => return to_cstring("error:PRF key derivation failed".to_string()),
    };

    match EvmSigner::derive_keypair_with_base_key(mnemonic_str, &base_key) {
        Ok((_signing_key, addr)) => to_cstring(format!("0x{}", hex::encode(addr))),
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Sign Solana system transfer using PRF key
#[no_mangle]
pub unsafe extern "C" fn solana_sign_system_transfer_with_prf(
    mnemonic: *const c_char,
    prf_key_ptr: *const u8,
    prf_key_len: size_t,
    to_pubkey: *const c_char,
    lamports: u64,
    recent_blockhash: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let to_str = from_cstr_or_empty(to_pubkey);
    let blockhash = from_cstr_or_empty(recent_blockhash);

    if prf_key_ptr.is_null() || prf_key_len == 0 {
        return to_cstring("error:null PRF key".to_string());
    }
    let prf_key = std::slice::from_raw_parts(prf_key_ptr, prf_key_len);

    let base_key = match PassphraseSealingUtil::derive_base_key(prf_key) {
        Ok(k) => k,
        Err(_) => return to_cstring("error:PRF key derivation failed".to_string()),
    };

    match SolanaSigner::derive_keypair_with_base_key(mnemonic_str, &base_key) {
        Ok((signing_key, _verifying_key)) => {
            match SolanaSigner::sign_system_transfer_with_key(
                &signing_key,
                to_str,
                lamports,
                blockhash,
            ) {
                Ok(tx_bytes) => to_cstring(Base64::encode_string(&tx_bytes)),
                Err(e) => to_cstring(format!("error:{}", e)),
            }
        }
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Sign Solana external transaction using PRF key
#[no_mangle]
pub unsafe extern "C" fn solana_sign_transaction_with_prf(
    mnemonic: *const c_char,
    prf_key_ptr: *const u8,
    prf_key_len: size_t,
    serialized_tx_base64: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let tx_b64 = from_cstr_or_empty(serialized_tx_base64);

    if prf_key_ptr.is_null() || prf_key_len == 0 {
        return to_cstring("error:null PRF key".to_string());
    }
    let prf_key = std::slice::from_raw_parts(prf_key_ptr, prf_key_len);

    let base_key = match PassphraseSealingUtil::derive_base_key(prf_key) {
        Ok(k) => k,
        Err(_) => return to_cstring("error:PRF key derivation failed".to_string()),
    };

    match SolanaSigner::derive_keypair_with_base_key(mnemonic_str, &base_key) {
        Ok((signing_key, _verifying_key)) => {
            match SolanaSigner::sign_serialized_transaction_with_key(&signing_key, tx_b64) {
                Ok(signed_tx) => to_cstring(signed_tx),
                Err(e) => to_cstring(format!("error:{}", e)),
            }
        }
        Err(e) => to_cstring(format!("error:{}", e)),
    }
}

/// Sign Bitcoin transaction using PRF key
#[no_mangle]
pub unsafe extern "C" fn bitcoin_sign_transaction_prf(
    mnemonic: *const c_char,
    prf_key_ptr: *const u8,
    prf_key_len: size_t,
    tx_json: *const c_char,
) -> *mut c_char {
    let mnemonic_str = from_cstr_or_empty(mnemonic);
    let tx_json_str = from_cstr_or_empty(tx_json);

    if prf_key_ptr.is_null() || prf_key_len == 0 {
        return to_cstring("error:null PRF key".to_string());
    }
    let prf_key = std::slice::from_raw_parts(prf_key_ptr, prf_key_len);

    use zeroize::Zeroize;

    let mut base_key = match PassphraseSealingUtil::derive_base_key(prf_key) {
        Ok(k) => k,
        Err(_) => return to_cstring("error:PRF key derivation failed".to_string()),
    };

    let unsigned_tx = match parse_bitcoin_tx_json(tx_json_str) {
        Ok(tx) => tx,
        Err(e) => {
            base_key.zeroize();
            return to_cstring(e);
        }
    };

    let is_taproot = unsigned_tx
        .inputs
        .first()
        .map(|inp| BitcoinSigner::is_p2tr_script(&inp.script_pubkey))
        .unwrap_or(false);

    let result = match BitcoinSigner::derive_keypair_with_base_key(mnemonic_str, &base_key) {
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
            drop(signing_key);
            match r {
                Ok(signed_hex) => to_cstring(signed_hex),
                Err(e) => to_cstring(format!("error:{}", e)),
            }
        }
        Err(e) => to_cstring(format!("error:{}", e)),
    };

    base_key.zeroize();
    result
}

// =====================================================
// Legacy ACEGF_Call interface (for backward compatibility)
// =====================================================

pub const ACEGF_METHOD_GENERATE: i32 = 1;
pub const ACEGF_METHOD_REKEY: i32 = 3;
pub const ACEGF_METHOD_VIEW: i32 = 4;

#[repr(C)]
pub struct ACEGF_Call {
    pub method: i32,
    pub input_1: *const c_char,
    pub input_2: *const c_char,
    pub input_3: *const c_char,
}

#[repr(C)]
pub struct ACEGF_Result {
    pub code: i32,
    pub data: *const c_char,
    pub data_len: u64,
    pub reserved: [u8; 8],
}

#[no_mangle]
pub unsafe extern "C" fn acegf_call(call: *const ACEGF_Call, out: *mut ACEGF_Result) -> i32 {
    if call.is_null() || out.is_null() {
        return -1;
    }

    let call = &*call;
    let mut result = ACEGF_Result {
        code: 0,
        data: std::ptr::null(),
        data_len: 0,
        reserved: [0; 8],
    };

    let res: Result<serde_json::Value, String> = match call.method {
        ACEGF_METHOD_GENERATE => {
            let pass = from_cstr_or_empty(call.input_1);
            let sec_pass = from_cstr_optional(call.input_2);

            ACEGFCore::generate_ace_internal(pass, sec_pass)
                .map_err(|e| e.to_string())
                .and_then(|entity| {
                    serde_json::to_value(entity).map_err(|e| format!("Serialization failed: {}", e))
                })
        }

        ACEGF_METHOD_REKEY => {
            let mnemonic = from_cstr_or_empty(call.input_1);
            let old_pass = from_cstr_or_empty(call.input_2);
            let new_pass = from_cstr_or_empty(call.input_3);

            ACEGFCore::change_passphrase_internal(mnemonic, old_pass, new_pass, None)
                .map(|new_mnemonic| serde_json::json!({ "mnemonic": new_mnemonic }))
                .map_err(|e| e.to_string())
        }

        ACEGF_METHOD_VIEW => {
            let mnemonic = from_cstr_or_empty(call.input_1);
            let pass = from_cstr_or_empty(call.input_2);
            let sec_pass = from_cstr_optional(call.input_3);

            ACEGFCore::view_wallet_internal(mnemonic, pass, sec_pass)
                .map_err(|e| e.to_string())
                .and_then(|entity| {
                    serde_json::to_value(entity).map_err(|e| format!("Serialization failed: {}", e))
                })
        }

        _ => Err("Unknown method".to_string()),
    };

    match res {
        Ok(json_val) => match serde_json::to_string(&json_val) {
            Ok(json_string) => match CString::new(json_string) {
                Ok(cstr) => {
                    result.data_len = cstr.as_bytes().len() as u64;
                    result.data = cstr.into_raw();
                    result.code = 0;
                }
                Err(_) => result.code = -3,
            },
            Err(_) => result.code = -4,
        },
        Err(err_msg) => {
            let json = serde_json::json!({ "error": err_msg });
            let s = json.to_string();
            match CString::new(s) {
                Ok(cstr) => {
                    result.data_len = cstr.as_bytes().len() as u64;
                    result.data = cstr.into_raw();
                    result.code = -2;
                }
                Err(_) => {
                    let fallback =
                        CString::new(r#"{"error":"Error message contained invalid characters"}"#)
                            .expect("Fallback should never fail");
                    result.data_len = fallback.as_bytes().len() as u64;
                    result.data = fallback.into_raw();
                    result.code = -5;
                }
            }
        }
    }

    let final_code = result.code;
    *out = result;
    final_code
}

#[no_mangle]
pub unsafe extern "C" fn acegf_free_result(result: *mut ACEGF_Result) {
    if result.is_null() {
        return;
    }
    let res = &mut *result;
    if !res.data.is_null() {
        let _ = CString::from_raw(res.data as *mut c_char);
        res.data = std::ptr::null();
        res.data_len = 0;
    }
}

// =====================================================
// Bitcoin TX JSON Parser (shared by bitcoin_sign_transaction and bitcoin_sign_transaction_prf)
// =====================================================

fn parse_bitcoin_tx_json(tx_json: &str) -> Result<UnsignedTx, String> {
    let tx_data: serde_json::Value =
        serde_json::from_str(tx_json).map_err(|e| format!("error:Invalid JSON: {}", e))?;

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
