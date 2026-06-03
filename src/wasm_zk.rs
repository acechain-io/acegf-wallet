// src/wasm_zk.rs
//
// ZK-ACE WASM bindings for zero-knowledge proof generation and verification.
//
// Only compiled when: target_arch = "wasm32" && feature = "zk"
//
// Exports 3 functions to JavaScript:
//   1. zkace_prove_wasm    — generate ZK proof (REV never leaves WASM)
//   2. zkace_verify_wasm   — verify ZK proof (optional, mainly done on-chain)
//
// Security invariant:
//   The REV (Root Entropy Value) is extracted from the mnemonic inside WASM,
//   used for proof generation, then zeroized. It NEVER appears in any return value.

use serde::{Deserialize, Serialize};
use stwo::core::fields::m31::M31;
use wasm_bindgen::prelude::*;

use crate::zk::mnemonic_to_rev_m31;
use zk_ace::native::commitment::compute_public_inputs;
use zk_ace::prover::prove;
use zk_ace::serde_utils::{deserialize_public_inputs, public_inputs_to_hex, serialize_proof};
use zk_ace::stwo::types::{
    bytes_to_elements, u64_to_domain_elements, try_u64_to_element, DerivationContext,
    ReplayMode, ZkAceWitness,
};
use zk_ace::verifier::verify;

// ============================================================================
//  Helper types
// ============================================================================

#[derive(Serialize)]
struct ZkProveResult {
    proof: String,
    #[serde(rename = "publicInputs")]
    public_inputs: Vec<String>,
}

#[derive(Deserialize)]
struct ZkVerifyInput {
    proof: String,
    #[serde(rename = "publicInputs")]
    public_inputs: Vec<String>,
}

// ============================================================================
//  Helper parsers
// ============================================================================

/// Parse "nonce" | "nullifier" to ReplayMode.
fn parse_replay_mode(s: &str) -> Result<ReplayMode, JsError> {
    match s.trim().to_lowercase().as_str() {
        "nonce" => Ok(ReplayMode::NonceRegistry),
        "nullifier" => Ok(ReplayMode::NullifierSet),
        _ => Err(JsError::new(&format!(
            "Invalid replay_mode: '{}'. Expected 'nonce' or 'nullifier'.",
            s
        ))),
    }
}

/// Parse a string as a u64 scalar value.
fn parse_u64_str(s: &str, label: &str) -> Result<u64, JsError> {
    s.trim()
        .parse::<u64>()
        .map_err(|e| JsError::new(&format!("Invalid {label}: {e}")))
}

/// Parse a string as a canonical M31 element (u32 < 2^31 - 1).
///
/// Accepts decimal or "0x"-prefixed hex.
fn parse_m31_str(s: &str, label: &str) -> Result<M31, JsError> {
    let s = s.trim();
    let raw: u32 = if s.starts_with("0x") || s.starts_with("0X") {
        u32::from_str_radix(&s[2..], 16)
            .map_err(|e| JsError::new(&format!("Invalid {label} (hex u32): {e}")))?
    } else {
        s.parse::<u32>()
            .map_err(|e| JsError::new(&format!("Invalid {label} (decimal u32): {e}")))?
    };
    if raw >= 0x7FFF_FFFF {
        return Err(JsError::new(&format!(
            "{label} value {raw} is not a canonical M31 element (must be < 2^31-1)"
        )));
    }
    Ok(M31(raw))
}

/// Parse a 32-byte hex string into a `[M31; 9]` lossless encoding.
///
/// Accepts an optional "0x" prefix.
fn parse_bytes32_to_m31(s: &str, label: &str) -> Result<[M31; 9], JsError> {
    let normalized = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    let bytes = hex::decode(normalized)
        .map_err(|e| JsError::new(&format!("Invalid {label} hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "{label} must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(bytes_to_elements(&arr))
}

/// Encode a byte slice as a 0x-prefixed hex string.
fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn zeroize_m31_slice(values: &mut [M31]) {
    for value in values.iter_mut() {
        // Use volatile writes so the compiler cannot elide secret wiping.
        unsafe {
            core::ptr::write_volatile(value, M31(0));
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn zeroize_derivation_context(ctx: &mut DerivationContext) {
    zeroize_m31_slice(core::slice::from_mut(&mut ctx.alg_id));
    zeroize_m31_slice(core::slice::from_mut(&mut ctx.domain));
    zeroize_m31_slice(core::slice::from_mut(&mut ctx.index));
}

fn zeroize_witness(witness: &mut ZkAceWitness) {
    zeroize_m31_slice(&mut witness.rev);
    zeroize_m31_slice(&mut witness.salt);
    zeroize_derivation_context(&mut witness.ctx);
    zeroize_m31_slice(&mut witness.nonce);
}

// ============================================================================
//  WASM exports
// ============================================================================

/// Generate a ZK-ACE authorization proof.
///
/// The REV (identity root) is extracted from the mnemonic INSIDE WASM,
/// used to construct the witness and generate the proof, then securely zeroized.
/// The REV never appears in the return value — only the proof and public inputs
/// are returned.
///
/// **WARNING**: The `passphrase` parameter is currently unused and does NOT
/// influence proof generation. The proof is derived solely from the mnemonic
/// entropy (REV). Do not rely on the passphrase for ZK proof security.
///
/// # Arguments
/// * `mnemonic`    - 24-word BIP39 mnemonic (256-bit entropy = REV)
/// * `passphrase`  - Reserved for future auth; currently unused
/// * `salt`        - Identity commitment salt as 64-char hex string (32 bytes)
/// * `alg_id`      - Target algorithm ID as decimal or hex u32 (M31 element)
/// * `domain`      - Chain/application domain tag as u64 (decimal)
/// * `index_val`   - Derivation index as decimal or hex u32 (M31 element)
/// * `nonce`       - Replay-prevention nonce as u64 (decimal)
/// * `tx_hash`     - Transaction hash to authorize as 64-char hex string (32 bytes)
/// * `replay_mode` - "nonce" (NonceRegistry) or "nullifier" (NullifierSet)
///
/// # Returns
/// JSON string: `{ "proof": "0x...", "publicInputs": ["0x...", ...] }`
///
/// Public inputs are 36 M31 elements encoded as hex strings.
#[wasm_bindgen]
pub fn zkace_prove_wasm(
    mnemonic: &str,
    passphrase: &str,
    salt: &str,
    alg_id: &str,
    domain: &str,
    index_val: &str,
    nonce: &str,
    tx_hash: &str,
    replay_mode: &str,
) -> Result<String, JsError> {
    // Suppress unused variable warning — passphrase reserved for future use.
    let _ = passphrase;

    // 1. Extract REV from mnemonic (24 words -> 256-bit entropy -> [M31; 9])
    let mut rev_m31 = mnemonic_to_rev_m31(mnemonic)
        .map_err(|e| JsError::new(&format!("Failed to extract REV from mnemonic: {}", e)))?;

    // 2. Parse witness parameters
    let mut salt_m31 = parse_bytes32_to_m31(salt, "salt")?;
    let alg_id_m31 = parse_m31_str(alg_id, "alg_id")?;
    let domain_u64 = parse_u64_str(domain, "domain")?;
    let domain_m31 = try_u64_to_element(domain_u64)
        .ok_or_else(|| JsError::new("domain value does not fit in a canonical M31 element"))?;
    let index_m31 = parse_m31_str(index_val, "index")?;
    let nonce_u64 = parse_u64_str(nonce, "nonce")?;
    let mut nonce_m31 = u64_to_domain_elements(nonce_u64);
    let tx_hash_m31 = parse_bytes32_to_m31(tx_hash, "tx_hash")?;
    let domain_elems = u64_to_domain_elements(domain_u64);
    let mode = parse_replay_mode(replay_mode)?;

    // 3. Build witness
    let mut witness = ZkAceWitness {
        rev: rev_m31,
        salt: salt_m31,
        ctx: DerivationContext {
            alg_id: alg_id_m31,
            domain: domain_m31,
            index: index_m31,
        },
        nonce: nonce_m31,
    };

    // 4. Compute public inputs
    let public_inputs = compute_public_inputs(&witness, &tx_hash_m31, &domain_elems, mode);

    // 5. Generate proof
    let proof_result = prove(&witness, &public_inputs, mode);
    zeroize_witness(&mut witness);
    zeroize_m31_slice(&mut rev_m31);
    zeroize_m31_slice(&mut salt_m31);
    zeroize_m31_slice(&mut nonce_m31);
    let proof_bytes = proof_result
        .map_err(|e| JsError::new(&format!("ZK-ACE proving failed: {}", e)))?;

    // 6. Format result
    let result = ZkProveResult {
        proof: to_hex(&serialize_proof(&proof_bytes)),
        public_inputs: public_inputs_to_hex(&public_inputs),
    };

    serde_json::to_string(&result)
        .map_err(|e| JsError::new(&format!("JSON serialization failed: {}", e)))
}

/// Verify a ZK-ACE authorization proof.
///
/// This is primarily for off-chain verification (e.g., relayer pre-check).
/// On-chain verification is done by the Solidity verifier contract.
///
/// # Arguments
/// * `proof_json` - JSON from `zkace_prove_wasm` output:
///                  `{ "proof": "0x...", "publicInputs": ["0x...", ...] }`
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise.
#[wasm_bindgen]
pub fn zkace_verify_wasm(proof_json: &str) -> Result<bool, JsError> {
    // 1. Parse JSON input
    let input: ZkVerifyInput = serde_json::from_str(proof_json)
        .map_err(|e| JsError::new(&format!("Invalid proof JSON: {}", e)))?;

    // 2. Decode proof bytes from hex
    let proof_hex = input.proof.strip_prefix("0x").unwrap_or(&input.proof);
    let proof_bytes =
        hex::decode(proof_hex).map_err(|e| JsError::new(&format!("Invalid proof hex: {}", e)))?;

    // 3. Parse public inputs: 36 hex-encoded M31 elements
    if input.public_inputs.len() != 36 {
        return Err(JsError::new(&format!(
            "Expected 36 public input elements (M31), got {}",
            input.public_inputs.len()
        )));
    }

    // Re-encode the hex strings into 36 * 4 = 144 bytes for deserialization
    let mut pi_bytes = Vec::with_capacity(36 * 4);
    for s in &input.public_inputs {
        let hex_str = s.strip_prefix("0x").unwrap_or(s);
        let val = u32::from_str_radix(hex_str, 16)
            .map_err(|e| JsError::new(&format!("Invalid public input hex '{}': {}", s, e)))?;
        pi_bytes.extend_from_slice(&val.to_le_bytes());
    }

    let public_inputs = deserialize_public_inputs(&pi_bytes)
        .map_err(|e| JsError::new(&format!("Failed to parse public inputs: {}", e)))?;

    // 4. Verify — try NonceRegistry first, then NullifierSet as fallback.
    match verify(&proof_bytes, &public_inputs, ReplayMode::NonceRegistry) {
        Ok(true) => return Ok(true),
        _ => {}
    }
    verify(&proof_bytes, &public_inputs, ReplayMode::NullifierSet)
        .map_err(|e| JsError::new(&format!("ZK-ACE verification failed: {}", e)))
}

/// Verify a ZK-ACE authorization proof with an explicit replay mode.
///
/// # Arguments
/// * `proof_json`   - JSON from `zkace_prove_wasm`
/// * `replay_mode`  - "nonce" or "nullifier"
#[wasm_bindgen]
pub fn zkace_verify_wasm_with_mode(
    proof_json: &str,
    replay_mode: &str,
) -> Result<bool, JsError> {
    let input: ZkVerifyInput = serde_json::from_str(proof_json)
        .map_err(|e| JsError::new(&format!("Invalid proof JSON: {}", e)))?;

    let proof_hex = input.proof.strip_prefix("0x").unwrap_or(&input.proof);
    let proof_bytes =
        hex::decode(proof_hex).map_err(|e| JsError::new(&format!("Invalid proof hex: {}", e)))?;

    if input.public_inputs.len() != 36 {
        return Err(JsError::new(&format!(
            "Expected 36 public input elements (M31), got {}",
            input.public_inputs.len()
        )));
    }

    let mut pi_bytes = Vec::with_capacity(36 * 4);
    for s in &input.public_inputs {
        let hex_str = s.strip_prefix("0x").unwrap_or(s);
        let val = u32::from_str_radix(hex_str, 16)
            .map_err(|e| JsError::new(&format!("Invalid public input hex '{}': {}", s, e)))?;
        pi_bytes.extend_from_slice(&val.to_le_bytes());
    }

    let public_inputs = deserialize_public_inputs(&pi_bytes)
        .map_err(|e| JsError::new(&format!("Failed to parse public inputs: {}", e)))?;

    let mode = parse_replay_mode(replay_mode)?;
    verify(&proof_bytes, &public_inputs, mode)
        .map_err(|e| JsError::new(&format!("ZK-ACE verification failed: {}", e)))
}
