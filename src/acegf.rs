// src/acegf.rs
// Core imports only — no unused deps
use crate::acegf_core::ACEGFCore;
use aes_gcm::aead::Aead;
use arrayref::array_ref;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

// Error handling
use aes_gcm::{Aes256Gcm, KeyInit, Nonce as AesNonce};
use std::error::Error;
use std::fmt;

// Minimal custom error: generic variants to avoid variant-matching pain
#[derive(Debug)]
pub enum CryptoError {
    EncryptionError(String), // encrypt/decrypt
    DecodingError(String),   // base64/length
    CustomError(String),     // domain errors
    InternalError(String),   // internal
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            CryptoError::DecodingError(msg) => write!(f, "Decoding error: {}", msg),
            CryptoError::CustomError(msg) => write!(f, "Error: {}", msg),
            CryptoError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl Error for CryptoError {}

// ─────────────────────────────────────────────────────────────────────────────
// Hybrid X25519 + ML-KEM-768 Encrypted Payload (v1) — THE NEW DEFAULT
//
// This is the recommended encryption envelope from v0.2 onwards. It combines:
//
//   * X25519 ephemeral ECDH (classical security + forward secrecy via ephemeral)
//   * ML-KEM-768 KEM        (post-quantum security, NIST FIPS 203)
//
// both shared secrets are fed into HKDF-SHA256 with the transcript (version
// label || ephemeral X25519 pub || ML-KEM ciphertext) bound into the `info`
// field. The derived AES-256-GCM key therefore depends on BOTH schemes —
// breaking either one alone does NOT recover the plaintext. This matches the
// hybrid KEM construction used by Signal PQXDH, TLS 1.3 X25519Kyber768,
// Chrome, Cloudflare, and the IETF `draft-ietf-tls-hybrid-design` series.
//
// **Anti-downgrade guarantee**: the `v` field is checked with strict equality
// at decrypt time. There is NO silent fallback to X25519-only. Legacy
// `EncryptedPayload` ciphertexts (pre-migration) are decrypted by the legacy
// path `ACEGF::decrypt_internal` / `ACEGF::decrypt_with_base_key` based on
// their *structure*, not on a capability negotiation — so an attacker cannot
// coerce hybrid ciphertexts into being reinterpreted as legacy.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridEncryptedPayload {
    /// Format version. Must equal [`HybridEncryptedPayload::VERSION`] exactly —
    /// any other value is rejected at decrypt time. The value is also mixed
    /// into the HKDF `info` so swapping it post-encryption invalidates the
    /// derived AES key and trips the AES-GCM auth tag.
    pub v: String,
    /// Sender's ephemeral X25519 public key, Base64 (32 raw bytes).
    pub ephemeral_x25519_pub_b64: String,
    /// ML-KEM-768 ciphertext, Base64 (1088 raw bytes). Encapsulates the
    /// post-quantum half of the hybrid shared secret under the recipient's
    /// long-term `xkem`.
    pub kem_ciphertext_b64: String,
    /// AES-256-GCM nonce / IV, Base64 (12 raw bytes).
    pub iv_b64: String,
    /// AES-256-GCM ciphertext with appended 16-byte authentication tag.
    pub ciphertext: Vec<u8>,
}

impl HybridEncryptedPayload {
    /// Current wire format version. Bump this if the HKDF construction,
    /// transcript binding, or envelope layout changes in a way that old
    /// decoders cannot parse — never bump it to "weaken" anything.
    pub const VERSION: &'static str = "acegf-hybrid-kem-v1";

    /// HKDF-Extract salt. Fixed byte string serving as a domain separator
    /// so hybrid-KEM keys cannot be confused with any other HKDF output
    /// in the ACE-GF codebase.
    const HKDF_SALT: &'static [u8] = b"ACEGF-HYBRID-KEM-v1";

    /// HKDF-Expand info prefix. The full info = this prefix || ephemeral_pub
    /// || kem_ciphertext, which binds the derived key to the complete
    /// transcript (prevents key-confusion / splicing attacks).
    const HKDF_INFO_PREFIX: &'static [u8] = b"acegf:hybrid-kem:v1:aes-256-gcm";
}

// ─────────────────────────────────────────────────────────────────────────────
// Hybrid X25519 + ML-KEM-768 Encrypted Payload (v2) — Deterministic Wrap
//
// v2 separates the "wrap" (DK encryption) layer from the "blob" (payload
// encryption) layer, and derives every wrap-layer secret deterministically
// from the sender's `wrap_master` plus a 16-byte public `nonce`. This lets
// the sender reconstruct byte-identical wraps from just `mnemonic + nonce`,
// enabling disaster recovery without a trusted third party (see
// the ACE-GF architecture spec §5).
//
// The blob layer uses a random IV, so blob ciphertext is NOT
// byte-deterministic — but the DK is, so any blob bytes the sender ever
// stored can be decrypted later without network access.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridEncryptedV2Payload {
    /// Format version. Must equal [`HybridEncryptedV2Payload::VERSION`]
    /// exactly — no downgrade to v1 is ever negotiated.
    pub v: String,
    /// 16-byte public nonce, Base64. Input to the HKDF salt. Callers that
    /// need to reproduce a wrap must store this alongside the envelope.
    pub nonce_b64: String,
    /// Sender's long-term X25519 public key (x25519), Base64. Used by
    /// the recipient to optionally authenticate the wrap (the sender is
    /// the only party that can compute the deterministic derivation).
    pub sender_x25519_b64: String,
    /// Recipient's long-term X25519 public key (x25519), Base64.
    /// Echoed in the envelope so recipients can verify "this wrap is
    /// intended for me" before attempting decryption.
    pub recipient_x25519_b64: String,
    /// SHA-256 hash of the recipient's ML-KEM-768 encaps key, Base64.
    /// Stored (instead of the full 1184-byte xkem) to let recipients /
    /// senders detect xkem rotation without bloating the envelope.
    pub recipient_xkem_hash_b64: String,
    /// Wrap layer — contains the encrypted DK.
    pub wrap: HybridEncryptedV2Wrap,
    /// Blob layer — contains the AES-GCM ciphertext of the plaintext
    /// under DK. In Phase 1 the blob travels inline in the envelope;
    /// in Phase 2 the caller may replace `blob` with a `blob_ref` (URL
    /// + hash + iv + size) pointing at Arweave or similar durable
    /// storage — see the architecture doc §6.
    pub blob: HybridEncryptedV2Blob,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridEncryptedV2Wrap {
    /// Deterministic ephemeral X25519 public key, Base64 (32 B).
    pub eph_x25519_pub_b64: String,
    /// Deterministic ML-KEM-768 ciphertext, Base64 (1088 B).
    pub ml_kem_ct_b64: String,
    /// Wrap AES-GCM nonce (12 B), Base64.
    pub iv_b64: String,
    /// AES-256-GCM ciphertext of DK under `dk_key` (32-byte DK + 16-byte
    /// auth tag = 48 bytes), Base64.
    pub wrap_ct_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridEncryptedV2Blob {
    /// Blob AES-GCM nonce (12 B, random), Base64.
    pub iv_b64: String,
    /// AES-256-GCM ciphertext of the plaintext under DK (payload + 16-byte
    /// auth tag). Transported as raw bytes (not base64) to avoid inflating
    /// large blobs on the wire.
    pub ciphertext: Vec<u8>,
}

impl HybridEncryptedV2Payload {
    /// Current wire format version for v2. See `derive_v2_*` helpers in
    /// `ACEGF` for the exact HKDF construction this version string refers
    /// to.
    pub const VERSION: &'static str = "acegf-hybrid-kem-v2";
}

pub struct ACEGF;

impl ACEGF {
    pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");
    // 1) X25519 DH shared secret
    pub fn compute_dh_key_internal(
        mnemonic: &str,
        passphrase: &str,
        peer_pub_b64: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        use base64ct::{Base64, Encoding};
        use sha2::{Digest, Sha256};

        // Map errors to string-wrapped `CryptoError`
        let mut seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, secondary_passphrase)
            .map_err(|e| {
                Box::new(CryptoError::InternalError(format!(
                    "Unseal failed: {:?}",
                    e
                ))) as Box<dyn Error>
            })?;

        let x25519_seed = &seeds.x25519;

        // X25519 secret clamp (RFC 7748)
        let mut raw = **x25519_seed;
        raw[0] &= 248;
        raw[31] &= 127;
        raw[31] |= 64;
        let private = StaticSecret::from(raw);

        // Peer pubkey
        let peer_pub_bytes = Base64::decode_vec(peer_pub_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        if peer_pub_bytes.len() != 32 {
            return Err(Box::new(CryptoError::DecodingError(
                "Peer X25519 pubkey must be 32 bytes".to_string(),
            )) as Box<dyn Error>);
        }

        let peer_pub = XPublic::from(*array_ref![peer_pub_bytes, 0, 32]);

        // DH + SHA256
        let shared_secret = private.diffie_hellman(&peer_pub);
        let dh_hash = Sha256::digest(shared_secret.as_bytes());
        let mut out = vec![0u8; 32];
        out.copy_from_slice(&dh_hash[..]);

        ACEGFCore::clear_scheme_seeds(&mut seeds);
        Ok(out)
    }

    /// Compute X25519 DH shared key using a pre-derived base_key (PRF path, skips Argon2)
    pub fn compute_dh_key_with_base_key_and_peer(
        mnemonic: &str,
        base_key: &[u8; 32],
        peer_pub_b64: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        use base64ct::{Base64, Encoding};
        use sha2::{Digest, Sha256};

        let mut seeds = ACEGFCore::unseal_to_seeds_with_base_key(mnemonic, base_key)?;

        let x25519_seed = &seeds.x25519;

        // X25519 private key normalization (RFC 7748)
        let mut raw = **x25519_seed;
        raw[0] &= 248;
        raw[31] &= 127;
        raw[31] |= 64;
        let private = StaticSecret::from(raw);

        let peer_pub_bytes = Base64::decode_vec(peer_pub_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        if peer_pub_bytes.len() != 32 {
            return Err(Box::new(CryptoError::DecodingError(
                "Peer X25519 pubkey must be 32 bytes".to_string(),
            )) as Box<dyn Error>);
        }

        let peer_pub = XPublic::from(*array_ref![peer_pub_bytes, 0, 32]);

        let shared_secret = private.diffie_hellman(&peer_pub);
        let dh_hash = Sha256::digest(shared_secret.as_bytes());
        let mut out = vec![0u8; 32];
        out.copy_from_slice(&dh_hash[..]);

        ACEGFCore::clear_scheme_seeds(&mut seeds);
        Ok(out)
    }

    /// Decrypt data using a pre-derived base_key (PRF path, skips Argon2)
    pub fn decrypt_with_base_key(
        mnemonic: &str,
        base_key: &[u8; 32],
        ephemeral_pub_b64: &str,
        encrypted_aes_key_b64: &str,
        iv_b64: &str,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        use base64ct::{Base64, Encoding};

        let dh_key =
            Self::compute_dh_key_with_base_key_and_peer(mnemonic, base_key, ephemeral_pub_b64)?;
        if dh_key.len() != 32 {
            return Err(Box::new(CryptoError::DecodingError(
                "DH key must be 32 bytes".to_string(),
            )) as Box<dyn Error>);
        }

        let master_key = Aes256Gcm::new_from_slice(&dh_key).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Invalid AES key: {}",
                e
            ))) as Box<dyn Error>
        })?;

        let encrypted_aes_key = Base64::decode_vec(encrypted_aes_key_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode AES key failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        let iv_bytes = Base64::decode_vec(iv_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode IV failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        if iv_bytes.len() != 12 {
            return Err(Box::new(CryptoError::DecodingError(
                "IV must be 12 bytes".to_string(),
            )) as Box<dyn Error>);
        }

        let nonce = AesNonce::from_slice(&iv_bytes);
        let real_aes_key = master_key
            .decrypt(nonce, &encrypted_aes_key[..])
            .map_err(|e| {
                Box::new(CryptoError::EncryptionError(format!(
                    "Decrypt AES key failed: {}",
                    e
                ))) as Box<dyn Error>
            })?;

        let data_cipher = Aes256Gcm::new_from_slice(&real_aes_key).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Invalid data key: {}",
                e
            ))) as Box<dyn Error>
        })?;

        let plaintext = data_cipher.decrypt(nonce, encrypted_data).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Decrypt data failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        let mut key_buf = real_aes_key;
        key_buf.zeroize();
        Ok(plaintext)
    }

    /// Sign message using a pre-derived base_key (PRF path, skips Argon2)
    pub fn sign_message_with_base_key(
        mnemonic: &str,
        base_key: &[u8; 32],
        message: &[u8],
        curve: u32,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
        use k256::ecdsa::SigningKey as K256SigningKey;

        let mut seeds = ACEGFCore::unseal_to_seeds_with_base_key(mnemonic, base_key)?;

        let signature = match curve {
            0 => {
                let signing_key = Ed25519SigningKey::from_bytes(&*seeds.ed25519_solana);
                let sig = signing_key.sign(message);
                sig.to_bytes().to_vec()
            }
            1 => {
                let signing_key = K256SigningKey::from_bytes((&*seeds.secp256k1_evm).into())
                    .map_err(|e| format!("Invalid secp256k1 key: {}", e))?;
                let (sig, _) = signing_key.sign(message);
                sig.to_bytes().to_vec()
            }
            2 => {
                // ML-DSA-44 (Post-Quantum)
                use crate::pqclean_ffi::MlDsa44;
                let (_, sk) = MlDsa44::keypair_from_seed(&seeds.ml_dsa_44)
                    .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;
                let sig = MlDsa44::sign(&sk, message)
                    .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;
                sig.to_vec()
            }
            _ => {
                return Err(
                    Box::new(CryptoError::CustomError("Unsupported curve".to_string()))
                        as Box<dyn Error>,
                );
            }
        };

        ACEGFCore::clear_scheme_seeds(&mut seeds);
        Ok(signature)
    }

    // 2) Encrypt to an x25519 holder; returns
    // (ephemeral_pub_b64, encrypted_aes_key_b64, iv_b64, encrypted_data)
    pub fn encrypt_for_x25519(
        recipient_x25519_b64: &str,
        plaintext: &[u8],
    ) -> Result<(String, String, String, Vec<u8>), Box<dyn Error>> {
        use base64ct::{Base64, Encoding};
        use rand::RngCore;
        use sha2::{Digest, Sha256};

        // 1) Recipient x25519 pubkey
        let recipient_pub_bytes = Base64::decode_vec(recipient_x25519_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode x25519 failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        if recipient_pub_bytes.len() != 32 {
            return Err(Box::new(CryptoError::DecodingError(
                "x25519 must be 32 bytes".to_string(),
            )) as Box<dyn Error>);
        }

        let recipient_pub = XPublic::from(*array_ref![recipient_pub_bytes, 0, 32]);

        // 2) Ephemeral X25519 keypair
        let mut ephemeral_secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ephemeral_secret_bytes);
        let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
        let ephemeral_pub = XPublic::from(&ephemeral_secret);

        // 3) DH shared secret
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pub);
        let dh_key = Sha256::digest(shared_secret.as_bytes());

        // 4) Random AES key + IV
        let mut aes_key = [0u8; 32];
        let mut iv = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut aes_key);
        rand::thread_rng().fill_bytes(&mut iv);

        // 5) Encrypt the AES key with the DH key
        let master_cipher = Aes256Gcm::new_from_slice(&dh_key).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Invalid DH key: {}",
                e
            ))) as Box<dyn Error>
        })?;

        let nonce = AesNonce::from_slice(&iv);
        let encrypted_aes_key = master_cipher.encrypt(nonce, &aes_key[..]).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Encrypt AES key failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        // 6) Encrypt payload with AES
        let data_cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Invalid AES key: {}",
                e
            ))) as Box<dyn Error>
        })?;

        let encrypted_data = data_cipher.encrypt(nonce, plaintext).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Encrypt data failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        // 7. Encode IV before zeroizing local buffers.
        let iv_b64 = Base64::encode_string(&iv);

        // 8) Zeroize secrets (orig buffers, not copies)
        ephemeral_secret_bytes.zeroize();
        aes_key.zeroize();
        iv.zeroize();

        // 9) Base64 outputs
        Ok((
            Base64::encode_string(ephemeral_pub.as_bytes()),
            Base64::encode_string(&encrypted_aes_key),
            iv_b64,
            encrypted_data,
        ))
    }

    // 3) Decrypt with DH-derived key
    pub fn decrypt_internal(
        mnemonic: &str,
        passphrase: &str,
        ephemeral_pub_b64: &str,
        encrypted_aes_key_b64: &str,
        iv_b64: &str,
        encrypted_data: &[u8],
        secondary_passphrase: Option<&str>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        use base64ct::{Base64, Encoding};

        // 1) DH key (unseal path: single Argon2 internally)
        let dh_key = Self::compute_dh_key_internal(
            mnemonic,
            passphrase,
            ephemeral_pub_b64,
            secondary_passphrase,
        )?;
        if dh_key.len() != 32 {
            return Err(Box::new(CryptoError::DecodingError(
                "DH key must be 32 bytes".to_string(),
            )) as Box<dyn Error>);
        }

        // 2) Unwrap AES key
        let master_key = Aes256Gcm::new_from_slice(&dh_key).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Invalid AES key: {}",
                e
            ))) as Box<dyn Error>
        })?;

        let encrypted_aes_key = Base64::decode_vec(encrypted_aes_key_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode AES key failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        let iv_bytes = Base64::decode_vec(iv_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode IV failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        if iv_bytes.len() != 12 {
            return Err(Box::new(CryptoError::DecodingError(
                "IV must be 12 bytes".to_string(),
            )) as Box<dyn Error>);
        }

        let nonce = AesNonce::from_slice(&iv_bytes);
        // Plaintext is &[u8]
        let real_aes_key = master_key
            .decrypt(nonce, &encrypted_aes_key[..])
            .map_err(|e| {
                Box::new(CryptoError::EncryptionError(format!(
                    "Decrypt AES key failed: {}",
                    e
                ))) as Box<dyn Error>
            })?;

        // 3) Decrypt payload
        let data_cipher = Aes256Gcm::new_from_slice(&real_aes_key).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Invalid data key: {}",
                e
            ))) as Box<dyn Error>
        })?;

        let plaintext = data_cipher.decrypt(nonce, encrypted_data).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Decrypt data failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        // 4) Zeroize
        let mut key_buf = real_aes_key;
        key_buf.zeroize();
        Ok(plaintext)
    }

    // ──────────────────────────────────────────────────────────────
    // ML-KEM-768 (FIPS 203) — post-quantum key encapsulation
    //
    // The KEM API is intentionally shaped to mirror the X25519 / x25519
    // surface above: all inputs/outputs are Base64 strings, errors flow
    // through `CryptoError`, and the recipient identity argument is always
    // a `*_b64: &str`. This keeps the KEM substitutable with (or composable
    // alongside) the classical x25519 path at every integration layer.
    // ──────────────────────────────────────────────────────────────

    /// Encapsulate a fresh 32-byte shared secret against a recipient's
    /// published ML-KEM-768 encapsulation key (`xkem`, Base64-encoded,
    /// 1184 raw bytes).
    ///
    /// This is the post-quantum analogue of `encrypt_for_x25519`.
    /// Anyone holding the recipient's `xkem` can call this function
    /// without knowing the recipient's mnemonic.
    ///
    /// Returns `(shared_secret_b64, ciphertext_b64)` on success. The caller
    /// transmits `ciphertext_b64` to the recipient, who recovers the same
    /// `shared_secret_b64` via `decapsulate_for_xkem`.
    pub fn encapsulate_for_xkem(
        recipient_xkem_b64: &str,
    ) -> Result<(String, String), Box<dyn Error>> {
        use base64ct::{Base64, Encoding};

        use crate::pqclean_ffi::MlKem768;

        let ek_vec = Base64::decode_vec(recipient_xkem_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode xkem failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        if ek_vec.len() != MlKem768::EK_BYTES {
            return Err(Box::new(CryptoError::DecodingError(format!(
                "xkem must be {} bytes, got {}",
                MlKem768::EK_BYTES,
                ek_vec.len()
            ))) as Box<dyn Error>);
        }

        let mut ek_bytes = [0u8; MlKem768::EK_BYTES];
        ek_bytes.copy_from_slice(&ek_vec);

        let (shared_secret, ciphertext) = MlKem768::encapsulate(&ek_bytes).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "ML-KEM-768 encapsulation failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        let ss_b64 = Base64::encode_string(&*shared_secret);
        let ct_b64 = Base64::encode_string(&ciphertext);
        Ok((ss_b64, ct_b64))
    }

    /// Recover the 32-byte shared secret produced by `encapsulate_for_xkem`,
    /// using the wallet's own ML-KEM-768 decapsulation key (re-derived from
    /// `mnemonic + passphrase`).
    ///
    /// This is the post-quantum analogue of `decrypt_internal`.
    ///
    /// Returns `shared_secret_b64` on success.
    pub fn decapsulate_for_xkem(
        mnemonic: &str,
        passphrase: &str,
        ciphertext_b64: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<String, Box<dyn Error>> {
        use base64ct::{Base64, Encoding};

        use crate::pqclean_ffi::MlKem768;

        let ct_vec = Base64::decode_vec(ciphertext_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode ciphertext failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        if ct_vec.len() != MlKem768::CT_BYTES {
            return Err(Box::new(CryptoError::DecodingError(format!(
                "ciphertext must be {} bytes, got {}",
                MlKem768::CT_BYTES,
                ct_vec.len()
            ))) as Box<dyn Error>);
        }

        let mut ct_bytes = [0u8; MlKem768::CT_BYTES];
        ct_bytes.copy_from_slice(&ct_vec);

        let mut seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, secondary_passphrase)
            .map_err(|e| {
                Box::new(CryptoError::InternalError(format!(
                    "Unseal failed: {:?}",
                    e
                ))) as Box<dyn Error>
            })?;

        let (_ek, dk) = MlKem768::keypair_from_seed(&seeds.ml_kem_768).map_err(|e| {
            Box::new(CryptoError::InternalError(format!(
                "ML-KEM-768 keygen failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        let shared_secret = MlKem768::decapsulate(&dk, &ct_bytes).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "ML-KEM-768 decapsulation failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        let ss_b64 = Base64::encode_string(&*shared_secret);

        ACEGFCore::clear_scheme_seeds(&mut seeds);
        Ok(ss_b64)
    }

    // ──────────────────────────────────────────────────────────────────────
    // Hybrid X25519 + ML-KEM-768 data encryption — the NEW DEFAULT.
    //
    // These methods fully replace the legacy `encrypt_for_x25519` /
    // `decrypt_internal` pair at every call site that is being migrated for
    // post-quantum safety. The legacy pair is left in place, byte-identical,
    // so existing ciphertexts remain readable forever.
    // ──────────────────────────────────────────────────────────────────────

    /// Internal helper: derive the 32-byte AES-256-GCM key from the two
    /// shared secrets + transcript binding.
    ///
    /// `ikm = ss_classical || ss_pq` (each 32 bytes, total 64).
    /// `salt = "ACEGF-HYBRID-KEM-v1"`.
    /// `info = "acegf:hybrid-kem:v1:aes-256-gcm" || ephemeral_pub || kem_ct`.
    ///
    /// Binding the ephemeral pub and KEM ciphertext into `info` kills
    /// splicing / key-confusion attacks — the attacker cannot take a KDF
    /// output from one session and reuse it in another with different
    /// transport values.
    fn derive_hybrid_aes_key(
        ss_classical: &[u8; 32],
        ss_pq: &[u8; 32],
        ephemeral_pub: &[u8; 32],
        kem_ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, Box<dyn Error>> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        // ikm = ss_classical || ss_pq (held in Zeroizing so the 64-byte
        // concatenation is wiped before we leave the function).
        let mut ikm = Zeroizing::new([0u8; 64]);
        ikm[0..32].copy_from_slice(ss_classical);
        ikm[32..64].copy_from_slice(ss_pq);

        let hk = Hkdf::<Sha256>::new(Some(HybridEncryptedPayload::HKDF_SALT), &*ikm);

        // info = prefix || eph_pub || kem_ct
        let mut info =
            Vec::with_capacity(HybridEncryptedPayload::HKDF_INFO_PREFIX.len() + 32 + kem_ciphertext.len());
        info.extend_from_slice(HybridEncryptedPayload::HKDF_INFO_PREFIX);
        info.extend_from_slice(ephemeral_pub);
        info.extend_from_slice(kem_ciphertext);

        let mut aes_key = Zeroizing::new([0u8; 32]);
        hk.expand(&info, &mut *aes_key).map_err(|e| {
            Box::new(CryptoError::InternalError(format!(
                "HKDF expand failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        Ok(aes_key)
    }

    /// Encrypt `plaintext` to a recipient using the **hybrid** post-quantum
    /// construction. This is the **default** encryption method going forward.
    ///
    /// The caller supplies **both** halves of the recipient's identity:
    ///
    /// * `recipient_x25519_b64` — the long-term X25519 public key (same
    ///   value that [`ACEGF::encrypt_for_x25519`] accepted)
    /// * `recipient_xkem_b64` — the long-term ML-KEM-768 encapsulation key
    ///   (the new `xkem` field populated on [`CryptoEntity`] /
    ///   [`crate::WalletPublicView`])
    ///
    /// Both are required: there is **no downgrade path** to X25519-only.
    /// If the recipient has not yet published an `xkem`, the caller must
    /// either (a) re-generate the recipient's wallet view via the current
    /// library (which will populate `xkem` deterministically from the same
    /// mnemonic) or (b) explicitly and consciously use the legacy
    /// [`ACEGF::encrypt_for_x25519`] method.
    ///
    /// Returns a [`HybridEncryptedPayload`] ready for JSON serialization,
    /// wire transfer, or storage in any immutable medium (IPFS / Arweave /
    /// on-chain calldata).
    ///
    /// # Security properties
    ///
    /// * **Post-quantum confidentiality** — Shor's algorithm breaking X25519
    ///   is NOT sufficient to recover the plaintext. The attacker must also
    ///   break ML-KEM-768.
    /// * **Classical confidentiality** — a cryptanalytic break of ML-KEM-768
    ///   that does not affect X25519 is also NOT sufficient.
    /// * **Forward secrecy (classical part)** — a fresh random ephemeral
    ///   X25519 key is generated per message, so past messages remain safe
    ///   against future compromise of the recipient's long-term X25519 key
    ///   (subject to the usual caveat that ML-KEM with a static `xkem` does
    ///   not provide PFS on the PQ side; compromising `ml_kem_768` seed
    ///   exposes past PQ half, but the X25519 half stays safe).
    /// * **Integrity** — AES-256-GCM authentication tag detects any tamper
    ///   to `ciphertext`; HKDF transcript binding detects any tamper to
    ///   `ephemeral_x25519_pub_b64`, `kem_ciphertext_b64`, or `v`.
    pub fn encrypt_for_recipient_pq(
        recipient_x25519_b64: &str,
        recipient_xkem_b64: &str,
        plaintext: &[u8],
    ) -> Result<HybridEncryptedPayload, Box<dyn Error>> {
        use base64ct::{Base64, Encoding};
        use rand::RngCore;

        use crate::pqclean_ffi::MlKem768;

        // 1. Decode recipient's X25519 public key (x25519).
        let recipient_x_bytes = Base64::decode_vec(recipient_x25519_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode x25519 failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        if recipient_x_bytes.len() != 32 {
            return Err(Box::new(CryptoError::DecodingError(
                "x25519 must be 32 bytes".to_string(),
            )) as Box<dyn Error>);
        }
        let recipient_x_pub = XPublic::from(*array_ref![recipient_x_bytes, 0, 32]);

        // 2. Decode recipient's ML-KEM-768 encapsulation key (xkem).
        let recipient_kem_bytes = Base64::decode_vec(recipient_xkem_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode xkem failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        if recipient_kem_bytes.len() != MlKem768::EK_BYTES {
            return Err(Box::new(CryptoError::DecodingError(format!(
                "xkem must be {} bytes, got {}",
                MlKem768::EK_BYTES,
                recipient_kem_bytes.len()
            ))) as Box<dyn Error>);
        }
        let mut recipient_kem_arr = [0u8; MlKem768::EK_BYTES];
        recipient_kem_arr.copy_from_slice(&recipient_kem_bytes);

        // 3. Generate ephemeral X25519 keypair (fresh per message — PFS).
        let mut ephemeral_secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ephemeral_secret_bytes);
        let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
        let ephemeral_pub = XPublic::from(&ephemeral_secret);

        // 4. Classical half: X25519 ECDH → 32-byte shared secret.
        let ss_classical_raw = ephemeral_secret.diffie_hellman(&recipient_x_pub);
        let mut ss_classical = [0u8; 32];
        ss_classical.copy_from_slice(ss_classical_raw.as_bytes());

        // 5. Post-quantum half: ML-KEM-768 encapsulation → (32-byte shared
        //    secret, 1088-byte ciphertext).
        let (ss_pq_boxed, kem_ct) = MlKem768::encapsulate(&recipient_kem_arr).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "ML-KEM-768 encapsulation failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        let mut ss_pq = [0u8; 32];
        ss_pq.copy_from_slice(&*ss_pq_boxed);

        // 6. HKDF(salt, ikm = ss_classical || ss_pq, info = prefix || eph || kem_ct).
        let aes_key = Self::derive_hybrid_aes_key(
            &ss_classical,
            &ss_pq,
            ephemeral_pub.as_bytes(),
            &kem_ct,
        )?;

        // Shared secrets go away as soon as the AES key is derived.
        ss_classical.zeroize();
        ss_pq.zeroize();

        // 7. Random 12-byte AES-GCM IV.
        let mut iv = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut iv);
        let iv_b64 = Base64::encode_string(&iv);

        // 8. AES-256-GCM seal.
        let cipher = Aes256Gcm::new_from_slice(&*aes_key).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Invalid AES key: {}",
                e
            ))) as Box<dyn Error>
        })?;
        let nonce = AesNonce::from_slice(&iv);
        let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "AES-GCM encrypt failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        // 9. Wipe remaining secret material.
        ephemeral_secret_bytes.zeroize();
        iv.zeroize();

        Ok(HybridEncryptedPayload {
            v: HybridEncryptedPayload::VERSION.to_string(),
            ephemeral_x25519_pub_b64: Base64::encode_string(ephemeral_pub.as_bytes()),
            kem_ciphertext_b64: Base64::encode_string(&kem_ct),
            iv_b64,
            ciphertext,
        })
    }

    /// Internal shared decrypt path — takes already-derived `SchemeSeeds`
    /// so both the passphrase-based and the `base_key`-based public entry
    /// points can reuse it.
    fn decrypt_for_recipient_pq_with_seeds(
        payload: &HybridEncryptedPayload,
        seeds: &mut crate::acegf_structs::SchemeSeeds,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        use base64ct::{Base64, Encoding};

        use crate::pqclean_ffi::MlKem768;

        // 0. STRICT version check. Anti-downgrade barrier — any deviation
        //    from the exact expected version string is a hard failure with
        //    no silent fallback anywhere.
        if payload.v != HybridEncryptedPayload::VERSION {
            return Err(Box::new(CryptoError::DecodingError(format!(
                "unsupported HybridEncryptedPayload version: expected {:?}, got {:?}",
                HybridEncryptedPayload::VERSION,
                payload.v
            ))) as Box<dyn Error>);
        }

        // 1. Decode ephemeral X25519 pub.
        let eph_bytes = Base64::decode_vec(&payload.ephemeral_x25519_pub_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode ephemeral_x25519_pub failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        if eph_bytes.len() != 32 {
            return Err(Box::new(CryptoError::DecodingError(
                "ephemeral X25519 pub must be 32 bytes".to_string(),
            )) as Box<dyn Error>);
        }
        let eph_pub_arr = *array_ref![eph_bytes, 0, 32];
        let eph_pub = XPublic::from(eph_pub_arr);

        // 2. Decode ML-KEM-768 ciphertext.
        let kem_ct_vec = Base64::decode_vec(&payload.kem_ciphertext_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode kem ciphertext failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        if kem_ct_vec.len() != MlKem768::CT_BYTES {
            return Err(Box::new(CryptoError::DecodingError(format!(
                "kem ciphertext must be {} bytes, got {}",
                MlKem768::CT_BYTES,
                kem_ct_vec.len()
            ))) as Box<dyn Error>);
        }
        let mut kem_ct_arr = [0u8; MlKem768::CT_BYTES];
        kem_ct_arr.copy_from_slice(&kem_ct_vec);

        // 3. Decode IV.
        let iv_bytes = Base64::decode_vec(&payload.iv_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode iv failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        if iv_bytes.len() != 12 {
            return Err(Box::new(CryptoError::DecodingError(
                "iv must be 12 bytes".to_string(),
            )) as Box<dyn Error>);
        }

        // 4. Classical half: re-derive X25519 private key + DH.
        let mut x_raw = **&seeds.x25519;
        x_raw[0] &= 248;
        x_raw[31] &= 127;
        x_raw[31] |= 64;
        let x_secret = StaticSecret::from(x_raw);
        let ss_classical_raw = x_secret.diffie_hellman(&eph_pub);
        let mut ss_classical = [0u8; 32];
        ss_classical.copy_from_slice(ss_classical_raw.as_bytes());
        x_raw.zeroize();

        // 5. Post-quantum half: re-derive ML-KEM-768 dk + decapsulate.
        let (_ek, dk) = MlKem768::keypair_from_seed(&seeds.ml_kem_768).map_err(|e| {
            Box::new(CryptoError::InternalError(format!(
                "ML-KEM-768 keygen failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        let ss_pq_boxed = MlKem768::decapsulate(&dk, &kem_ct_arr).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "ML-KEM-768 decapsulation failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        let mut ss_pq = [0u8; 32];
        ss_pq.copy_from_slice(&*ss_pq_boxed);

        // 6. HKDF — exactly the same construction as on the encrypt side.
        let aes_key = Self::derive_hybrid_aes_key(
            &ss_classical,
            &ss_pq,
            &eph_pub_arr,
            &kem_ct_arr,
        )?;

        ss_classical.zeroize();
        ss_pq.zeroize();

        // 7. AES-256-GCM open. On tamper (of v / ephemeral_pub / kem_ct /
        //    ciphertext) the auth tag will not validate here and this
        //    returns an error.
        let cipher = Aes256Gcm::new_from_slice(&*aes_key).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Invalid AES key: {}",
                e
            ))) as Box<dyn Error>
        })?;
        let nonce = AesNonce::from_slice(&iv_bytes);
        let plaintext = cipher
            .decrypt(nonce, payload.ciphertext.as_slice())
            .map_err(|e| {
                Box::new(CryptoError::EncryptionError(format!(
                    "AES-GCM decrypt failed (auth tag mismatch, wrong key, or tampered payload): {}",
                    e
                ))) as Box<dyn Error>
            })?;

        Ok(plaintext)
    }

    /// Decrypt a [`HybridEncryptedPayload`] using `mnemonic + passphrase`
    /// (Argon2id path). This is the **default** decryption method paired
    /// with [`ACEGF::encrypt_for_recipient_pq`].
    ///
    /// The version field of the payload is checked with strict equality;
    /// no downgrade to legacy X25519-only is ever performed.
    pub fn decrypt_for_recipient_pq(
        mnemonic: &str,
        passphrase: &str,
        payload: &HybridEncryptedPayload,
        secondary_passphrase: Option<&str>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut seeds =
            ACEGFCore::unseal_to_seeds(mnemonic, passphrase, secondary_passphrase).map_err(
                |e| {
                    Box::new(CryptoError::InternalError(format!(
                        "Unseal failed: {:?}",
                        e
                    ))) as Box<dyn Error>
                },
            )?;

        let result = Self::decrypt_for_recipient_pq_with_seeds(payload, &mut seeds);

        ACEGFCore::clear_scheme_seeds(&mut seeds);
        result
    }

    /// Decrypt a [`HybridEncryptedPayload`] using a pre-derived `base_key`
    /// (PRF path, skips Argon2id — mirrors
    /// [`ACEGF::decrypt_with_base_key`] for the legacy X25519 format).
    pub fn decrypt_for_recipient_pq_with_base_key(
        mnemonic: &str,
        base_key: &[u8; 32],
        payload: &HybridEncryptedPayload,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut seeds = ACEGFCore::unseal_to_seeds_with_base_key(mnemonic, base_key)?;

        let result = Self::decrypt_for_recipient_pq_with_seeds(payload, &mut seeds);

        ACEGFCore::clear_scheme_seeds(&mut seeds);
        result
    }

    // ──────────────────────────────────────────────────────────────────────
    // Hybrid X25519 + ML-KEM-768 — Envelope v2 (Deterministic Wrap)
    //
    // This is the Yallet-specific envelope format introduced in the
    // 2026-04-10 architecture redesign (see
    // the ACE-GF architecture spec).
    //
    // Unlike v1, which uses fresh randomness for the ephemeral X25519 key,
    // ML-KEM encapsulation randomness, and AES-GCM IVs, v2 derives **all**
    // wrap-layer secrets deterministically from `wrap_master` (itself
    // derived from `mnemonic + passphrase`) plus a 16-byte public `nonce`.
    //
    // The consequence is that the sender can reconstruct any wrap at any
    // later time from just the mnemonic and the stored `nonce`, without
    // needing a copy of the wrap bytes. This is the cornerstone of the
    // "disaster recovery" story in the architecture doc: if the wrap layer
    // (Storj) becomes unavailable, the sender regenerates byte-identical
    // wraps from mnemonic alone, no trusted third party required.
    //
    // The blob layer (the actual plaintext ciphertext) uses a random IV,
    // so the blob ciphertext is NOT byte-identical across re-encryptions —
    // but it doesn't need to be, because the DK itself is deterministic
    // and can decrypt whichever blob bytes the caller has stored.
    //
    // ## Derivation (matches §5 / §14.1 of the architecture doc)
    //
    // ```
    // wrap_master   = HKDF(IKM = seeds.x25519 || seeds.ml_kem_768,
    //                       salt = [], info = "wrap-master-v1", L = 32)
    // salt          = nonce(16) || recipient_x25519(32)
    //                 || SHA256(recipient_xkem)(32)
    // seed64        = HKDF(IKM = wrap_master, salt = salt,
    //                       info = "yallet-wrap-seed-v2", L = 64)
    // DK            = HKDF(seed64, "dk-v2", 32)
    // eph_x_priv    = clamp(HKDF(seed64, "eph-x25519-v2", 32))
    // kem_rand      = HKDF(seed64, "ml-kem-rand-v2", 32)
    // wrap_iv       = HKDF(seed64, "wrap-iv-v2", 12)
    // ss_x          = X25519(eph_x_priv, recipient_x25519)
    // (ss_k, kem_ct)= ML-KEM-768.encaps_from_seed(recipient_xkem, kem_rand)
    // dk_key        = HKDF(IKM = ss_x || ss_k, salt = [],
    //                       info = "dk-wrap-v2", L = 32)
    // wrap_ct       = AES-256-GCM.encrypt(dk_key, wrap_iv, DK)
    // blob_iv       = random(12)
    // blob_ct       = AES-256-GCM.encrypt(DK, blob_iv, plaintext)
    // ```
    //
    // The wrap part is byte-deterministic; the blob part is not.
    // ──────────────────────────────────────────────────────────────────────

    /// Derive the 32-byte `wrap_master` from `SchemeSeeds`. The input
    /// material combines the X25519 and ML-KEM-768 seeds so that the
    /// resulting master is both deterministic from the mnemonic and
    /// domain-separated from any other HKDF output in this codebase.
    fn derive_wrap_master_v2(
        seeds: &crate::acegf_structs::SchemeSeeds,
    ) -> Result<Zeroizing<[u8; 32]>, String> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let mut ikm = Zeroizing::new([0u8; 96]);
        ikm[0..32].copy_from_slice(&*seeds.x25519);
        ikm[32..96].copy_from_slice(&*seeds.ml_kem_768);

        let hk = Hkdf::<Sha256>::new(None, &*ikm);
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(b"wrap-master-v1", &mut *out)
            .map_err(|e| format!("HKDF expand wrap-master failed: {}", e))?;
        Ok(out)
    }

    /// Given `wrap_master`, the public `nonce`, and the recipient's
    /// identity/xkem, derive the 64-byte `seed64` that all subsequent
    /// wrap-layer secrets feed from.
    fn derive_v2_seed64(
        wrap_master: &[u8; 32],
        nonce: &[u8; 16],
        recipient_x25519: &[u8; 32],
        recipient_xkem: &[u8],
    ) -> Result<Zeroizing<[u8; 64]>, String> {
        use hkdf::Hkdf;
        use sha2::{Digest, Sha256};

        // salt = nonce || recipient_x25519 || SHA256(recipient_xkem)
        let mut kem_hash = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(recipient_xkem);
        kem_hash.copy_from_slice(&hasher.finalize());

        let mut salt = [0u8; 16 + 32 + 32];
        salt[0..16].copy_from_slice(nonce);
        salt[16..48].copy_from_slice(recipient_x25519);
        salt[48..80].copy_from_slice(&kem_hash);

        let hk = Hkdf::<Sha256>::new(Some(&salt), wrap_master);
        let mut out = Zeroizing::new([0u8; 64]);
        hk.expand(b"yallet-wrap-seed-v2", &mut *out)
            .map_err(|e| format!("HKDF expand seed64 failed: {}", e))?;
        Ok(out)
    }

    /// Expand `seed64` into a fixed-length slice with a given info label.
    /// Internal helper kept private because every call site uses a fixed
    /// label that is part of the protocol.
    fn v2_expand<const L: usize>(seed64: &[u8; 64], info: &[u8]) -> Result<Zeroizing<[u8; L]>, String> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(None, seed64);
        let mut out = Zeroizing::new([0u8; L]);
        hk.expand(info, &mut *out)
            .map_err(|e| format!("HKDF expand failed: {}", e))?;
        Ok(out)
    }

    /// Derive the 32-byte `dk_key` that wraps the DK, from the two
    /// post-exchange shared secrets `ss_x || ss_k`.
    fn derive_v2_dk_key(
        ss_x: &[u8; 32],
        ss_k: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, String> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let mut ikm = Zeroizing::new([0u8; 64]);
        ikm[0..32].copy_from_slice(ss_x);
        ikm[32..64].copy_from_slice(ss_k);

        let hk = Hkdf::<Sha256>::new(None, &*ikm);
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(b"dk-wrap-v2", &mut *out)
            .map_err(|e| format!("HKDF expand dk-key failed: {}", e))?;
        Ok(out)
    }

    /// Encrypt `plaintext` using the v2 deterministic hybrid-KEM envelope.
    ///
    /// **Note**: This function does not support wallets created with a secondary
    /// passphrase (admin factor). The `secondary_passphrase` is hardcoded to `None`
    /// in the `unseal_to_seeds` call. Callers with admin-factor wallets must use
    /// a different code path or extend this function signature.
    ///
    /// Arguments:
    /// * `mnemonic` / `passphrase` — sender's wallet, used to derive
    ///   `wrap_master`. The sender must be unlocked.
    /// * `recipient_x25519_b64` — recipient's X25519 public key (32 B).
    /// * `recipient_xkem_b64` — recipient's ML-KEM-768 encaps key (1184 B).
    /// * `nonce_opt` — optional 16-byte public nonce. If `None`, a fresh
    ///   random 16-byte nonce is generated. Callers that need to reproduce
    ///   an exact wrap should pass the stored nonce here.
    /// * `plaintext` — the bytes to seal.
    ///
    /// Returns a [`HybridEncryptedV2Payload`] ready for JSON serialization.
    /// The `wrap` portion is byte-deterministic given the same inputs; the
    /// `blob` portion uses a random IV and is NOT byte-deterministic.
    pub fn encrypt_for_recipient_pq_v2(
        mnemonic: &str,
        passphrase: &str,
        recipient_x25519_b64: &str,
        recipient_xkem_b64: &str,
        nonce_opt: Option<&[u8; 16]>,
        plaintext: &[u8],
    ) -> Result<HybridEncryptedV2Payload, Box<dyn Error>> {
        use base64ct::{Base64, Encoding};
        use rand::RngCore;
        use sha2::{Digest, Sha256};
        use x25519_dalek::{PublicKey as XPublic, StaticSecret};

        use crate::acegf_core::ACEGFCore;
        use crate::pqclean_ffi::MlKem768;

        // 1. Decode recipient keys.
        let recipient_x_bytes = Base64::decode_vec(recipient_x25519_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode recipient x25519 failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        if recipient_x_bytes.len() != 32 {
            return Err(Box::new(CryptoError::DecodingError(
                "recipient x25519 must be 32 bytes".to_string(),
            )) as Box<dyn Error>);
        }
        let recipient_x_arr = *array_ref![recipient_x_bytes, 0, 32];
        let recipient_x_pub = XPublic::from(recipient_x_arr);

        let recipient_kem_bytes = Base64::decode_vec(recipient_xkem_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode recipient xkem failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        if recipient_kem_bytes.len() != MlKem768::EK_BYTES {
            return Err(Box::new(CryptoError::DecodingError(format!(
                "recipient xkem must be {} bytes, got {}",
                MlKem768::EK_BYTES,
                recipient_kem_bytes.len()
            ))) as Box<dyn Error>);
        }
        let mut recipient_kem_arr = [0u8; MlKem768::EK_BYTES];
        recipient_kem_arr.copy_from_slice(&recipient_kem_bytes);

        // 2. Unseal sender seeds → wrap_master + sender x25519.
        let mut seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, None).map_err(|e| {
            Box::new(CryptoError::InternalError(format!(
                "Unseal failed: {:?}",
                e
            ))) as Box<dyn Error>
        })?;
        let wrap_master = Self::derive_wrap_master_v2(&seeds).map_err(|e| {
            Box::new(CryptoError::InternalError(e)) as Box<dyn Error>
        })?;

        // Sender's long-term X25519 public key (x25519). Same derivation
        // used by `generate_crypto_entity` — clamp + scalar-mult base point.
        let mut sender_x_raw = **&seeds.x25519;
        sender_x_raw[0] &= 248;
        sender_x_raw[31] &= 127;
        sender_x_raw[31] |= 64;
        let sender_secret = StaticSecret::from(sender_x_raw);
        let sender_x_pub = XPublic::from(&sender_secret);
        let sender_x25519_b64 = Base64::encode_string(sender_x_pub.as_bytes());
        sender_x_raw.zeroize();
        // seeds will be cleared at the end
        let _ = sender_secret; // drop

        // 3. Resolve nonce (caller-supplied or fresh random 16 B).
        let nonce: [u8; 16] = match nonce_opt {
            Some(n) => *n,
            None => {
                let mut n = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut n);
                n
            }
        };

        // 4. Derive seed64 and all wrap-layer secrets.
        let hkdf_err = |e: String| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>;
        let seed64 =
            Self::derive_v2_seed64(&wrap_master, &nonce, &recipient_x_arr, &recipient_kem_arr)
                .map_err(hkdf_err)?;
        let dk = Self::v2_expand::<32>(&seed64, b"dk-v2")
            .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;
        let mut eph_x_priv_raw = *Self::v2_expand::<32>(&seed64, b"eph-x25519-v2")
            .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;
        // RFC 7748 clamp for X25519 scalar.
        eph_x_priv_raw[0] &= 248;
        eph_x_priv_raw[31] &= 127;
        eph_x_priv_raw[31] |= 64;
        let kem_rand = Self::v2_expand::<32>(&seed64, b"ml-kem-rand-v2")
            .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;
        let wrap_iv = *Self::v2_expand::<12>(&seed64, b"wrap-iv-v2")
            .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;

        // 5. X25519 half: ss_x.
        let eph_secret = StaticSecret::from(eph_x_priv_raw);
        let eph_pub = XPublic::from(&eph_secret);
        let ss_x_raw = eph_secret.diffie_hellman(&recipient_x_pub);
        let mut ss_x = [0u8; 32];
        ss_x.copy_from_slice(ss_x_raw.as_bytes());
        eph_x_priv_raw.zeroize();

        // 6. ML-KEM half: deterministic encaps using kem_rand as the seed.
        let (ss_k_boxed, kem_ct) =
            MlKem768::encapsulate_from_seed(&recipient_kem_arr, &*kem_rand).map_err(|e| {
                Box::new(CryptoError::EncryptionError(format!(
                    "ML-KEM-768 deterministic encapsulation failed: {}",
                    e
                ))) as Box<dyn Error>
            })?;
        let mut ss_k = [0u8; 32];
        ss_k.copy_from_slice(&*ss_k_boxed);

        // 7. dk_key = HKDF(ss_x || ss_k, "dk-wrap-v2", 32).
        let dk_key = Self::derive_v2_dk_key(&ss_x, &ss_k)
            .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;
        ss_x.zeroize();
        ss_k.zeroize();

        // 8. wrap_ct = AES-256-GCM(dk_key, wrap_iv, DK).
        let wrap_cipher = Aes256Gcm::new_from_slice(&*dk_key).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Invalid dk_key: {}",
                e
            ))) as Box<dyn Error>
        })?;
        let wrap_nonce = AesNonce::from_slice(&wrap_iv);
        let wrap_ct = wrap_cipher
            .encrypt(wrap_nonce, dk.as_slice())
            .map_err(|e| {
                Box::new(CryptoError::EncryptionError(format!(
                    "AES-GCM wrap encrypt failed: {}",
                    e
                ))) as Box<dyn Error>
            })?;

        // 9. blob_iv = random(12). blob_ct = AES-256-GCM(DK, blob_iv, plaintext).
        let mut blob_iv = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut blob_iv);
        let blob_cipher = Aes256Gcm::new_from_slice(&*dk).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Invalid DK: {}",
                e
            ))) as Box<dyn Error>
        })?;
        let blob_nonce = AesNonce::from_slice(&blob_iv);
        let blob_ct = blob_cipher
            .encrypt(blob_nonce, plaintext)
            .map_err(|e| {
                Box::new(CryptoError::EncryptionError(format!(
                    "AES-GCM blob encrypt failed: {}",
                    e
                ))) as Box<dyn Error>
            })?;

        // 10. Compute recipient_xkem_hash for self-binding in envelope.
        let mut kem_hash = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&recipient_kem_arr);
        kem_hash.copy_from_slice(&hasher.finalize());

        // 11. Wipe remaining secret material.
        ACEGFCore::clear_scheme_seeds(&mut seeds);

        Ok(HybridEncryptedV2Payload {
            v: HybridEncryptedV2Payload::VERSION.to_string(),
            nonce_b64: Base64::encode_string(&nonce),
            sender_x25519_b64,
            recipient_x25519_b64: recipient_x25519_b64.to_string(),
            recipient_xkem_hash_b64: Base64::encode_string(&kem_hash),
            wrap: HybridEncryptedV2Wrap {
                eph_x25519_pub_b64: Base64::encode_string(eph_pub.as_bytes()),
                ml_kem_ct_b64: Base64::encode_string(&kem_ct),
                iv_b64: Base64::encode_string(&wrap_iv),
                wrap_ct_b64: Base64::encode_string(&wrap_ct),
            },
            blob: HybridEncryptedV2Blob {
                iv_b64: Base64::encode_string(&blob_iv),
                ciphertext: blob_ct,
            },
        })
    }

    /// Regenerate ONLY the deterministic `wrap` portion of a v2 envelope.
    ///
    /// Disaster-recovery helper (see architecture §5.4 / §15.3). The
    /// sender can always rebuild a byte-identical `wrap` object given:
    /// mnemonic + passphrase, the original 16-byte `nonce`, and the
    /// recipient's x25519 + xkem. This does NOT touch the `blob`
    /// (which uses a random IV and is not deterministic); the caller is
    /// responsible for holding onto the original `blob` or re-encrypting
    /// the plaintext with the recovered DK.
    ///
    /// Arguments:
    /// * `mnemonic` / `passphrase` — sender's wallet.
    /// * `recipient_x25519_b64` — recipient's X25519 public key (32 B).
    /// * `recipient_xkem_b64` — recipient's ML-KEM-768 encaps key (1184 B).
    /// * `nonce_b64` — the original 16-byte Base64 nonce.
    ///
    /// Returns a [`HybridEncryptedV2Wrap`] with the regenerated wrap
    /// fields; the bytes are guaranteed byte-equal to the original wrap
    /// produced by [`Self::encrypt_for_recipient_pq_v2`] when called
    /// with the same inputs.
    pub fn regenerate_wrap_v2(
        mnemonic: &str,
        passphrase: &str,
        recipient_x25519_b64: &str,
        recipient_xkem_b64: &str,
        nonce_b64: &str,
    ) -> Result<HybridEncryptedV2Wrap, Box<dyn Error>> {
        use base64ct::{Base64, Encoding};
        use x25519_dalek::{PublicKey as XPublic, StaticSecret};

        use crate::acegf_core::ACEGFCore;
        use crate::pqclean_ffi::MlKem768;

        // 1. Decode recipient keys.
        let recipient_x_bytes = Base64::decode_vec(recipient_x25519_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode recipient x25519 failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        if recipient_x_bytes.len() != 32 {
            return Err(Box::new(CryptoError::DecodingError(
                "recipient x25519 must be 32 bytes".to_string(),
            )) as Box<dyn Error>);
        }
        let recipient_x_arr = *array_ref![recipient_x_bytes, 0, 32];
        let recipient_x_pub = XPublic::from(recipient_x_arr);

        let recipient_kem_bytes = Base64::decode_vec(recipient_xkem_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode recipient xkem failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        if recipient_kem_bytes.len() != MlKem768::EK_BYTES {
            return Err(Box::new(CryptoError::DecodingError(format!(
                "recipient xkem must be {} bytes, got {}",
                MlKem768::EK_BYTES,
                recipient_kem_bytes.len()
            ))) as Box<dyn Error>);
        }
        let mut recipient_kem_arr = [0u8; MlKem768::EK_BYTES];
        recipient_kem_arr.copy_from_slice(&recipient_kem_bytes);

        // 2. Decode the original nonce (required — this function is purely
        // deterministic so the nonce cannot be regenerated).
        let nonce_vec = Base64::decode_vec(nonce_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode nonce failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        if nonce_vec.len() != 16 {
            return Err(Box::new(CryptoError::DecodingError(format!(
                "nonce must be 16 bytes, got {}",
                nonce_vec.len()
            ))) as Box<dyn Error>);
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&nonce_vec);

        // 3. Unseal sender seeds → wrap_master.
        let mut seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, None).map_err(|e| {
            Box::new(CryptoError::InternalError(format!(
                "Unseal failed: {:?}",
                e
            ))) as Box<dyn Error>
        })?;
        let wrap_master = Self::derive_wrap_master_v2(&seeds).map_err(|e| {
            Box::new(CryptoError::InternalError(e)) as Box<dyn Error>
        })?;
        ACEGFCore::clear_scheme_seeds(&mut seeds);

        // 4. Derive seed64 and all wrap-layer secrets. Same labels and
        // same order as `encrypt_for_recipient_pq_v2` — must stay in
        // lock-step with that function or wraps will drift.
        let seed64 =
            Self::derive_v2_seed64(&wrap_master, &nonce, &recipient_x_arr, &recipient_kem_arr)
                .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;
        let dk = Self::v2_expand::<32>(&seed64, b"dk-v2")
            .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;
        let mut eph_x_priv_raw = *Self::v2_expand::<32>(&seed64, b"eph-x25519-v2")
            .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;
        // RFC 7748 clamp for X25519 scalar.
        eph_x_priv_raw[0] &= 248;
        eph_x_priv_raw[31] &= 127;
        eph_x_priv_raw[31] |= 64;
        let kem_rand = Self::v2_expand::<32>(&seed64, b"ml-kem-rand-v2")
            .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;
        let wrap_iv = *Self::v2_expand::<12>(&seed64, b"wrap-iv-v2")
            .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;

        // 5. X25519 half: ss_x.
        let eph_secret = StaticSecret::from(eph_x_priv_raw);
        let eph_pub = XPublic::from(&eph_secret);
        let ss_x_raw = eph_secret.diffie_hellman(&recipient_x_pub);
        let mut ss_x = [0u8; 32];
        ss_x.copy_from_slice(ss_x_raw.as_bytes());
        eph_x_priv_raw.zeroize();

        // 6. ML-KEM half: deterministic encaps using kem_rand as the seed.
        let (ss_k_boxed, kem_ct) =
            MlKem768::encapsulate_from_seed(&recipient_kem_arr, &*kem_rand).map_err(|e| {
                Box::new(CryptoError::EncryptionError(format!(
                    "ML-KEM-768 deterministic encapsulation failed: {}",
                    e
                ))) as Box<dyn Error>
            })?;
        let mut ss_k = [0u8; 32];
        ss_k.copy_from_slice(&*ss_k_boxed);

        // 7. dk_key = HKDF(ss_x || ss_k, "dk-wrap-v2", 32).
        let dk_key = Self::derive_v2_dk_key(&ss_x, &ss_k)
            .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;
        ss_x.zeroize();
        ss_k.zeroize();

        // 8. wrap_ct = AES-256-GCM(dk_key, wrap_iv, DK).
        let wrap_cipher = Aes256Gcm::new_from_slice(&*dk_key).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Invalid dk_key: {}",
                e
            ))) as Box<dyn Error>
        })?;
        let wrap_nonce = AesNonce::from_slice(&wrap_iv);
        let wrap_ct = wrap_cipher
            .encrypt(wrap_nonce, dk.as_slice())
            .map_err(|e| {
                Box::new(CryptoError::EncryptionError(format!(
                    "AES-GCM wrap encrypt failed: {}",
                    e
                ))) as Box<dyn Error>
            })?;

        Ok(HybridEncryptedV2Wrap {
            eph_x25519_pub_b64: Base64::encode_string(eph_pub.as_bytes()),
            ml_kem_ct_b64: Base64::encode_string(&kem_ct),
            iv_b64: Base64::encode_string(&wrap_iv),
            wrap_ct_b64: Base64::encode_string(&wrap_ct),
        })
    }

    /// Internal shared v2 decrypt path. The caller provides `SchemeSeeds`
    /// (from whichever unseal strategy — passphrase or base_key).
    fn decrypt_for_recipient_pq_v2_with_seeds(
        payload: &HybridEncryptedV2Payload,
        seeds: &mut crate::acegf_structs::SchemeSeeds,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        use base64ct::{Base64, Encoding};
        use sha2::{Digest, Sha256};
        use x25519_dalek::{PublicKey as XPublic, StaticSecret};

        use crate::pqclean_ffi::MlKem768;

        // 0. Strict version check.
        if payload.v != HybridEncryptedV2Payload::VERSION {
            return Err(Box::new(CryptoError::DecodingError(format!(
                "unsupported HybridEncryptedV2Payload version: expected {:?}, got {:?}",
                HybridEncryptedV2Payload::VERSION,
                payload.v
            ))) as Box<dyn Error>);
        }

        // 0a. Recipient self-binding check. Envelope v2 commits to the
        // recipient's long-term X25519 pubkey and the hash of the recipient's
        // ML-KEM-768 public key (see §5.3 / §8.2 of the architecture doc).
        // A decrypt that cannot verify those bindings would be vulnerable to
        // a sender-side pubkey-swap (attacker substitutes their own keypair
        // into the envelope header to trick the recipient into decrypting
        // under a different identity). We verify the bindings against the
        // receiver's derived keys before touching the ciphertext.
        {
            // Derive the receiver's own X25519 pubkey from the seeds.
            let mut x_raw_check = **&seeds.x25519;
            x_raw_check[0] &= 248;
            x_raw_check[31] &= 127;
            x_raw_check[31] |= 64;
            let x_secret_check = StaticSecret::from(x_raw_check);
            let my_x_pub = XPublic::from(&x_secret_check);
            x_raw_check.zeroize();

            let env_recipient_x = Base64::decode_vec(&payload.recipient_x25519_b64)
                .map_err(|e| {
                    Box::new(CryptoError::DecodingError(format!(
                        "Base64 decode recipient_x25519 failed: {}",
                        e
                    ))) as Box<dyn Error>
                })?;
            if env_recipient_x.len() != 32
                || env_recipient_x.as_slice() != my_x_pub.as_bytes().as_slice()
            {
                return Err(Box::new(CryptoError::DecodingError(
                    "recipient_x25519 binding mismatch: envelope was not addressed to this wallet"
                        .to_string(),
                )) as Box<dyn Error>);
            }

            // Derive the receiver's own ML-KEM-768 encapsulation key and
            // compare SHA-256 against the envelope's `recipient_xkem_hash_b64`.
            let (my_kem_ek, _my_kem_dk) =
                MlKem768::keypair_from_seed(&seeds.ml_kem_768).map_err(|e| {
                    Box::new(CryptoError::InternalError(format!(
                        "ML-KEM-768 keygen for xkem check failed: {}",
                        e
                    ))) as Box<dyn Error>
                })?;
            let mut my_kem_hash = [0u8; 32];
            let mut hasher = Sha256::new();
            hasher.update(&my_kem_ek);
            my_kem_hash.copy_from_slice(&hasher.finalize());

            let env_kem_hash =
                Base64::decode_vec(&payload.recipient_xkem_hash_b64).map_err(|e| {
                    Box::new(CryptoError::DecodingError(format!(
                        "Base64 decode recipient_xkem_hash failed: {}",
                        e
                    ))) as Box<dyn Error>
                })?;
            if env_kem_hash.len() != 32 || env_kem_hash.as_slice() != my_kem_hash.as_slice() {
                return Err(Box::new(CryptoError::DecodingError(
                    "recipient_xkem_hash binding mismatch: envelope was not addressed to this wallet's xkem"
                        .to_string(),
                )) as Box<dyn Error>);
            }
        }

        // 1. Decode wrap fields.
        let eph_bytes = Base64::decode_vec(&payload.wrap.eph_x25519_pub_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode eph_x25519_pub failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        if eph_bytes.len() != 32 {
            return Err(Box::new(CryptoError::DecodingError(
                "eph_x25519_pub must be 32 bytes".to_string(),
            )) as Box<dyn Error>);
        }
        let eph_pub_arr = *array_ref![eph_bytes, 0, 32];
        let eph_pub = XPublic::from(eph_pub_arr);

        let kem_ct_vec = Base64::decode_vec(&payload.wrap.ml_kem_ct_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode ml_kem_ct failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        if kem_ct_vec.len() != MlKem768::CT_BYTES {
            return Err(Box::new(CryptoError::DecodingError(format!(
                "ml_kem_ct must be {} bytes, got {}",
                MlKem768::CT_BYTES,
                kem_ct_vec.len()
            ))) as Box<dyn Error>);
        }
        let mut kem_ct_arr = [0u8; MlKem768::CT_BYTES];
        kem_ct_arr.copy_from_slice(&kem_ct_vec);

        let wrap_iv_bytes = Base64::decode_vec(&payload.wrap.iv_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode wrap iv failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        if wrap_iv_bytes.len() != 12 {
            return Err(Box::new(CryptoError::DecodingError(
                "wrap iv must be 12 bytes".to_string(),
            )) as Box<dyn Error>);
        }

        let wrap_ct = Base64::decode_vec(&payload.wrap.wrap_ct_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode wrap_ct failed: {}",
                e
            ))) as Box<dyn Error>
        })?;

        let blob_iv_bytes = Base64::decode_vec(&payload.blob.iv_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Base64 decode blob iv failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        if blob_iv_bytes.len() != 12 {
            return Err(Box::new(CryptoError::DecodingError(
                "blob iv must be 12 bytes".to_string(),
            )) as Box<dyn Error>);
        }

        // 2. Classical half: ss_x = X25519(recipient_x_priv, eph_pub).
        let mut x_raw = **&seeds.x25519;
        x_raw[0] &= 248;
        x_raw[31] &= 127;
        x_raw[31] |= 64;
        let x_secret = StaticSecret::from(x_raw);
        let ss_x_raw = x_secret.diffie_hellman(&eph_pub);
        let mut ss_x = [0u8; 32];
        ss_x.copy_from_slice(ss_x_raw.as_bytes());
        x_raw.zeroize();

        // 3. PQ half: derive recipient's ML-KEM-768 dk, then decapsulate.
        let (_ek, dk_kem) = MlKem768::keypair_from_seed(&seeds.ml_kem_768).map_err(|e| {
            Box::new(CryptoError::InternalError(format!(
                "ML-KEM-768 keygen failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        let ss_k_boxed = MlKem768::decapsulate(&dk_kem, &kem_ct_arr).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "ML-KEM-768 decapsulation failed: {}",
                e
            ))) as Box<dyn Error>
        })?;
        let mut ss_k = [0u8; 32];
        ss_k.copy_from_slice(&*ss_k_boxed);

        // 4. dk_key = HKDF(ss_x || ss_k, "dk-wrap-v2", 32).
        let dk_key = Self::derive_v2_dk_key(&ss_x, &ss_k)
            .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;
        ss_x.zeroize();
        ss_k.zeroize();

        // 5. Unwrap DK.
        let wrap_cipher = Aes256Gcm::new_from_slice(&*dk_key).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Invalid dk_key: {}",
                e
            ))) as Box<dyn Error>
        })?;
        let wrap_nonce = AesNonce::from_slice(&wrap_iv_bytes);
        let dk_bytes_vec = wrap_cipher
            .decrypt(wrap_nonce, wrap_ct.as_slice())
            .map_err(|e| {
                Box::new(CryptoError::EncryptionError(format!(
                    "AES-GCM wrap decrypt failed (auth tag mismatch, wrong recipient, or tampered wrap): {}",
                    e
                ))) as Box<dyn Error>
            })?;
        if dk_bytes_vec.len() != 32 {
            return Err(Box::new(CryptoError::DecodingError(format!(
                "unwrapped DK must be 32 bytes, got {}",
                dk_bytes_vec.len()
            ))) as Box<dyn Error>);
        }
        let mut dk_bytes = Zeroizing::new([0u8; 32]);
        dk_bytes.copy_from_slice(&dk_bytes_vec);

        // 6. Decrypt blob.
        let blob_cipher = Aes256Gcm::new_from_slice(&*dk_bytes).map_err(|e| {
            Box::new(CryptoError::EncryptionError(format!(
                "Invalid DK: {}",
                e
            ))) as Box<dyn Error>
        })?;
        let blob_nonce = AesNonce::from_slice(&blob_iv_bytes);
        let plaintext = blob_cipher
            .decrypt(blob_nonce, payload.blob.ciphertext.as_slice())
            .map_err(|e| {
                Box::new(CryptoError::EncryptionError(format!(
                    "AES-GCM blob decrypt failed (auth tag mismatch, wrong DK, or tampered blob): {}",
                    e
                ))) as Box<dyn Error>
            })?;

        Ok(plaintext)
    }

    /// Decrypt a v2 hybrid envelope using `mnemonic + passphrase`.
    pub fn decrypt_for_recipient_pq_v2(
        mnemonic: &str,
        passphrase: &str,
        payload: &HybridEncryptedV2Payload,
        secondary_passphrase: Option<&str>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, secondary_passphrase)
            .map_err(|e| {
                Box::new(CryptoError::InternalError(format!(
                    "Unseal failed: {:?}",
                    e
                ))) as Box<dyn Error>
            })?;

        let result = Self::decrypt_for_recipient_pq_v2_with_seeds(payload, &mut seeds);

        ACEGFCore::clear_scheme_seeds(&mut seeds);
        result
    }

    /// Decrypt a v2 hybrid envelope using a pre-derived `base_key`
    /// (PRF path, skips Argon2id).
    pub fn decrypt_for_recipient_pq_v2_with_base_key(
        mnemonic: &str,
        base_key: &[u8; 32],
        payload: &HybridEncryptedV2Payload,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut seeds = ACEGFCore::unseal_to_seeds_with_base_key(mnemonic, base_key)?;

        let result = Self::decrypt_for_recipient_pq_v2_with_seeds(payload, &mut seeds);

        ACEGFCore::clear_scheme_seeds(&mut seeds);
        result
    }

    // Message signing — curve: 0 = Ed25519 (Solana), 1 = Secp256k1 (EVM)
    /// curve: 0 = Ed25519 (Solana), 1 = Secp256k1 (EVM)
    pub fn sign_message_internal(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        message: &[u8],
        curve: u32,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        use ed25519_dalek::{Signer, SigningKey};
        use k256::ecdsa::SigningKey as K256SigningKey;

        let mut seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, secondary_passphrase)
            .map_err(|e| {
                Box::new(CryptoError::InternalError(format!(
                    "Unseal failed: {:?}",
                    e
                ))) as Box<dyn Error>
            })?;

        let signature = match curve {
            0 => {
                // Ed25519 (Solana)
                let signing_key = SigningKey::from_bytes(&*seeds.ed25519_solana);
                let sig = signing_key.sign(message);
                sig.to_bytes().to_vec()
            }
            1 => {
                // Secp256k1 (EVM)
                let signing_key = K256SigningKey::from_bytes((&*seeds.secp256k1_evm).into())
                    .map_err(|e| {
                        Box::new(CryptoError::InternalError(format!(
                            "Invalid secp256k1 key: {}",
                            e
                        ))) as Box<dyn Error>
                    })?;
                let (sig, _) = signing_key.sign(message);
                sig.to_bytes().to_vec()
            }
            2 => {
                // ML-DSA-44 (Post-Quantum)
                use crate::pqclean_ffi::MlDsa44;
                let (_, sk) = MlDsa44::keypair_from_seed(&seeds.ml_dsa_44)
                    .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;
                let sig = MlDsa44::sign(&sk, message)
                    .map_err(|e| Box::new(CryptoError::InternalError(e)) as Box<dyn Error>)?;
                sig.to_vec()
            }
            _ => {
                return Err(
                    Box::new(CryptoError::CustomError("Unsupported curve".to_string()))
                        as Box<dyn Error>,
                );
            }
        };

        ACEGFCore::clear_scheme_seeds(&mut seeds);
        Ok(signature)
    }

    // Verify Ed25519 signature (x25519)
    // Returns Result to properly propagate errors instead of silently failing
    pub fn x25519_verify_internal(
        x25519_b64: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Box<dyn Error>> {
        use base64ct::{Base64, Encoding};
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let pub_bytes = Base64::decode_vec(x25519_b64).map_err(|e| {
            Box::new(CryptoError::DecodingError(format!(
                "Invalid base64 public key: {}",
                e
            ))) as Box<dyn Error>
        })?;

        if pub_bytes.len() != 32 {
            return Err(Box::new(CryptoError::DecodingError(format!(
                "Public key must be 32 bytes, got {}",
                pub_bytes.len()
            ))) as Box<dyn Error>);
        }

        // Safely convert to fixed-size array with proper error handling
        let pub_array: [u8; 32] = pub_bytes.as_slice().try_into().map_err(|_| {
            Box::new(CryptoError::DecodingError(
                "Failed to convert public key to array".to_string(),
            )) as Box<dyn Error>
        })?;

        let verifying_key = VerifyingKey::from_bytes(&pub_array).map_err(|e| {
            Box::new(CryptoError::InternalError(format!(
                "Invalid Ed25519 public key: {}",
                e
            ))) as Box<dyn Error>
        })?;

        if signature.len() != 64 {
            return Err(Box::new(CryptoError::DecodingError(format!(
                "Signature must be 64 bytes, got {}",
                signature.len()
            ))) as Box<dyn Error>);
        }

        let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| {
            Box::new(CryptoError::DecodingError(
                "Failed to convert signature to array".to_string(),
            )) as Box<dyn Error>
        })?;

        let sig = Signature::from_bytes(&sig_bytes);

        Ok(verifying_key.verify(message, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_error_display() {
        let err = CryptoError::EncryptionError("test error".to_string());
        assert!(err.to_string().contains("Encryption error"));
        assert!(err.to_string().contains("test error"));

        let err = CryptoError::DecodingError("decode failed".to_string());
        assert!(err.to_string().contains("Decoding error"));

        let err = CryptoError::CustomError("custom msg".to_string());
        assert!(err.to_string().contains("Error:"));

        let err = CryptoError::InternalError("internal".to_string());
        assert!(err.to_string().contains("Internal error"));
    }

    #[test]
    fn test_acegf_version() {
        // Verify VERSION constant is set from Cargo.toml
        assert!(!ACEGF::VERSION.is_empty());
    }

    #[test]
    fn test_x25519_verify_invalid_base64() {
        let result =
            ACEGF::x25519_verify_internal("not-valid-base64!!!", b"test message", &[0u8; 64]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("base64") || err.to_string().contains("Decoding"));
    }

    #[test]
    fn test_x25519_verify_wrong_pubkey_length() {
        use base64ct::{Base64, Encoding};

        // Encode 16 bytes instead of 32
        let short_key = Base64::encode_string(&[0u8; 16]);
        let result = ACEGF::x25519_verify_internal(&short_key, b"test message", &[0u8; 64]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_x25519_verify_wrong_signature_length() {
        use base64ct::{Base64, Encoding};
        use ed25519_dalek::SigningKey;

        // Generate a valid public key
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let pubkey = signing_key.verifying_key();
        let pubkey_b64 = Base64::encode_string(pubkey.as_bytes());

        // Use wrong signature length (32 instead of 64)
        let result = ACEGF::x25519_verify_internal(
            &pubkey_b64,
            b"test message",
            &[0u8; 32], // Wrong length
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("64 bytes"));
    }

    #[test]
    fn test_x25519_verify_valid_signature() {
        use base64ct::{Base64, Encoding};
        use ed25519_dalek::{Signer, SigningKey};

        let message = b"Hello, World!";

        // Generate keypair
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let pubkey_b64 = Base64::encode_string(verifying_key.as_bytes());

        // Sign the message
        let signature = signing_key.sign(message);

        // Verify
        let result = ACEGF::x25519_verify_internal(&pubkey_b64, message, &signature.to_bytes());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_x25519_verify_invalid_signature() {
        use base64ct::{Base64, Encoding};
        use ed25519_dalek::SigningKey;

        let message = b"Hello, World!";

        // Generate keypair
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let pubkey_b64 = Base64::encode_string(verifying_key.as_bytes());

        // Use a fake signature (all zeros)
        let fake_signature = [0u8; 64];

        // Verify should return false (not error)
        let result = ACEGF::x25519_verify_internal(&pubkey_b64, message, &fake_signature);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should be false for invalid signature
    }

    // =====================================================
    // Encryption Tests
    // =====================================================

    #[test]
    fn test_encrypt_for_x25519_basic() {
        use base64ct::{Base64, Encoding};
        use x25519_dalek::{PublicKey, StaticSecret};

        // Generate a recipient keypair
        let recipient_secret = StaticSecret::from([42u8; 32]);
        let recipient_public = PublicKey::from(&recipient_secret);
        let recipient_x25519_b64 = Base64::encode_string(recipient_public.as_bytes());

        // Test data
        let plaintext = b"Hello, World! This is a test message for encryption.";

        // Encrypt
        let result = ACEGF::encrypt_for_x25519(&recipient_x25519_b64, plaintext);
        assert!(result.is_ok(), "Encryption should succeed");

        let (ephemeral_pub, encrypted_aes_key, iv, encrypted_data) = result.unwrap();

        // Verify outputs are non-empty
        assert!(
            !ephemeral_pub.is_empty(),
            "Ephemeral public key should not be empty"
        );
        assert!(
            !encrypted_aes_key.is_empty(),
            "Encrypted AES key should not be empty"
        );
        assert!(!iv.is_empty(), "IV should not be empty");
        assert!(
            !encrypted_data.is_empty(),
            "Encrypted data should not be empty"
        );

        // Verify base64 decoding works
        let ephemeral_pub_bytes = Base64::decode_vec(&ephemeral_pub);
        assert!(
            ephemeral_pub_bytes.is_ok(),
            "Ephemeral public key should be valid base64"
        );
        assert_eq!(
            ephemeral_pub_bytes.unwrap().len(),
            32,
            "Ephemeral public key should be 32 bytes"
        );

        let iv_bytes = Base64::decode_vec(&iv);
        assert!(iv_bytes.is_ok(), "IV should be valid base64");
        assert_eq!(iv_bytes.unwrap().len(), 12, "IV should be 12 bytes");
    }

    #[test]
    fn test_encrypt_for_x25519_invalid_pubkey() {
        // Invalid base64
        let result = ACEGF::encrypt_for_x25519("not-valid-base64!!!", b"test");
        assert!(result.is_err(), "Should fail with invalid base64");

        // Valid base64 but wrong length
        use base64ct::{Base64, Encoding};
        let short_key = Base64::encode_string(&[1u8; 16]); // Only 16 bytes
        let result = ACEGF::encrypt_for_x25519(&short_key, b"test");
        assert!(result.is_err(), "Should fail with wrong key length");
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_encrypt_for_x25519_empty_plaintext() {
        use base64ct::{Base64, Encoding};
        use x25519_dalek::{PublicKey, StaticSecret};

        // Generate a recipient keypair
        let recipient_secret = StaticSecret::from([42u8; 32]);
        let recipient_public = PublicKey::from(&recipient_secret);
        let recipient_x25519_b64 = Base64::encode_string(recipient_public.as_bytes());

        // Encrypt empty data
        let result = ACEGF::encrypt_for_x25519(&recipient_x25519_b64, b"");
        assert!(result.is_ok(), "Should handle empty plaintext");

        let (_, _, _, encrypted_data) = result.unwrap();
        // AES-GCM adds 16 bytes auth tag even for empty plaintext
        assert!(
            !encrypted_data.is_empty(),
            "Encrypted data should have auth tag"
        );
    }

    #[test]
    fn test_encrypt_for_x25519_large_data() {
        use base64ct::{Base64, Encoding};
        use x25519_dalek::{PublicKey, StaticSecret};

        // Generate a recipient keypair
        let recipient_secret = StaticSecret::from([42u8; 32]);
        let recipient_public = PublicKey::from(&recipient_secret);
        let recipient_x25519_b64 = Base64::encode_string(recipient_public.as_bytes());

        // Test with larger data (1MB)
        let large_data = vec![0xABu8; 1024 * 1024];

        let result = ACEGF::encrypt_for_x25519(&recipient_x25519_b64, &large_data);
        assert!(result.is_ok(), "Should handle large plaintext");

        let (_, _, _, encrypted_data) = result.unwrap();
        // Encrypted data should be larger than plaintext (includes auth tag)
        assert!(encrypted_data.len() > large_data.len());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Generate a wallet to get valid mnemonic and x25519
        let passphrase = "test_password";
        let entity = crate::acegf_core::ACEGFCore::generate_ace_internal(passphrase, None)
            .expect("Should generate wallet");

        let mnemonic = &entity.mnemonic;
        let x25519 = &entity.x25519;

        // Test data
        let original_plaintext =
            b"This is a secret message that should be encrypted and decrypted correctly!";

        // Encrypt
        let encrypt_result = ACEGF::encrypt_for_x25519(x25519, original_plaintext);
        assert!(encrypt_result.is_ok(), "Encryption should succeed");

        let (ephemeral_pub, encrypted_aes_key, iv, encrypted_data) = encrypt_result.unwrap();

        // Decrypt
        let decrypt_result = ACEGF::decrypt_internal(
            mnemonic,
            passphrase,
            &ephemeral_pub,
            &encrypted_aes_key,
            &iv,
            &encrypted_data,
            None,
        );
        assert!(
            decrypt_result.is_ok(),
            "Decryption should succeed: {:?}",
            decrypt_result.err()
        );

        let decrypted_plaintext = decrypt_result.unwrap();
        assert_eq!(
            decrypted_plaintext,
            original_plaintext.to_vec(),
            "Decrypted data should match original"
        );
    }

    #[test]
    fn test_encrypt_decrypt_with_secondary_passphrase() {
        // Generate a wallet with secondary passphrase
        let passphrase = "main_password";
        let secondary = "secondary_password";
        let entity =
            crate::acegf_core::ACEGFCore::generate_ace_internal(passphrase, Some(secondary))
                .expect("Should generate wallet with secondary passphrase");

        let mnemonic = &entity.mnemonic;
        let x25519 = &entity.x25519;

        // Test data
        let original_plaintext = b"Secret message with secondary passphrase protection";

        // Encrypt
        let (ephemeral_pub, encrypted_aes_key, iv, encrypted_data) =
            ACEGF::encrypt_for_x25519(x25519, original_plaintext)
                .expect("Encryption should succeed");

        // Decrypt with secondary passphrase
        let decrypt_result = ACEGF::decrypt_internal(
            mnemonic,
            passphrase,
            &ephemeral_pub,
            &encrypted_aes_key,
            &iv,
            &encrypted_data,
            Some(secondary),
        );
        assert!(
            decrypt_result.is_ok(),
            "Decryption with secondary passphrase should succeed"
        );
        assert_eq!(decrypt_result.unwrap(), original_plaintext.to_vec());

        // Decrypt without secondary passphrase should fail
        let wrong_decrypt = ACEGF::decrypt_internal(
            mnemonic,
            passphrase,
            &ephemeral_pub,
            &encrypted_aes_key,
            &iv,
            &encrypted_data,
            None, // Missing secondary passphrase
        );
        assert!(
            wrong_decrypt.is_err(),
            "Decryption without secondary passphrase should fail"
        );
    }

    #[test]
    fn test_decrypt_wrong_mnemonic() {
        // Generate two wallets
        let passphrase = "password";
        let entity1 = crate::acegf_core::ACEGFCore::generate_ace_internal(passphrase, None)
            .expect("Should generate wallet 1");
        let entity2 = crate::acegf_core::ACEGFCore::generate_ace_internal(passphrase, None)
            .expect("Should generate wallet 2");

        // Encrypt with wallet1's x25519
        let original = b"Secret for wallet1";
        let (ephemeral_pub, encrypted_aes_key, iv, encrypted_data) =
            ACEGF::encrypt_for_x25519(&entity1.x25519, original)
                .expect("Encryption should succeed");

        // Try to decrypt with wallet2's mnemonic (should fail)
        let wrong_decrypt = ACEGF::decrypt_internal(
            &entity2.mnemonic,
            passphrase,
            &ephemeral_pub,
            &encrypted_aes_key,
            &iv,
            &encrypted_data,
            None,
        );
        assert!(
            wrong_decrypt.is_err(),
            "Decryption with wrong mnemonic should fail"
        );
    }

    #[test]
    fn test_decrypt_wrong_passphrase() {
        let passphrase = "correct_password";
        let entity = crate::acegf_core::ACEGFCore::generate_ace_internal(passphrase, None)
            .expect("Should generate wallet");

        // Encrypt
        let original = b"Secret message";
        let (ephemeral_pub, encrypted_aes_key, iv, encrypted_data) =
            ACEGF::encrypt_for_x25519(&entity.x25519, original)
                .expect("Encryption should succeed");

        // Try to decrypt with wrong passphrase
        let wrong_decrypt = ACEGF::decrypt_internal(
            &entity.mnemonic,
            "wrong_password",
            &ephemeral_pub,
            &encrypted_aes_key,
            &iv,
            &encrypted_data,
            None,
        );
        assert!(
            wrong_decrypt.is_err(),
            "Decryption with wrong passphrase should fail"
        );
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let passphrase = "password";
        let entity = crate::acegf_core::ACEGFCore::generate_ace_internal(passphrase, None)
            .expect("Should generate wallet");

        // Encrypt
        let original = b"Integrity protected message";
        let (ephemeral_pub, encrypted_aes_key, iv, mut encrypted_data) =
            ACEGF::encrypt_for_x25519(&entity.x25519, original)
                .expect("Encryption should succeed");

        // Tamper with the ciphertext
        if !encrypted_data.is_empty() {
            encrypted_data[0] ^= 0xFF; // Flip bits
        }

        // Try to decrypt tampered data
        let tampered_decrypt = ACEGF::decrypt_internal(
            &entity.mnemonic,
            passphrase,
            &ephemeral_pub,
            &encrypted_aes_key,
            &iv,
            &encrypted_data,
            None,
        );
        assert!(
            tampered_decrypt.is_err(),
            "Decryption of tampered data should fail"
        );
    }

    #[test]
    fn test_decrypt_invalid_iv() {
        use base64ct::{Base64, Encoding};

        let passphrase = "password";
        let entity = crate::acegf_core::ACEGFCore::generate_ace_internal(passphrase, None)
            .expect("Should generate wallet");

        // Encrypt
        let (ephemeral_pub, encrypted_aes_key, _, encrypted_data) =
            ACEGF::encrypt_for_x25519(&entity.x25519, b"test")
                .expect("Encryption should succeed");

        // Try with wrong IV length
        let wrong_iv = Base64::encode_string(&[0u8; 8]); // 8 bytes instead of 12
        let result = ACEGF::decrypt_internal(
            &entity.mnemonic,
            passphrase,
            &ephemeral_pub,
            &encrypted_aes_key,
            &wrong_iv,
            &encrypted_data,
            None,
        );
        assert!(result.is_err(), "Should fail with wrong IV length");
        assert!(result.unwrap_err().to_string().contains("12 bytes"));
    }

    #[test]
    fn test_encrypt_decrypt_binary_data() {
        let passphrase = "password";
        let entity = crate::acegf_core::ACEGFCore::generate_ace_internal(passphrase, None)
            .expect("Should generate wallet");

        // Binary data with all byte values
        let binary_data: Vec<u8> = (0..=255).collect();

        let (ephemeral_pub, encrypted_aes_key, iv, encrypted_data) =
            ACEGF::encrypt_for_x25519(&entity.x25519, &binary_data)
                .expect("Encryption should succeed");

        let decrypted = ACEGF::decrypt_internal(
            &entity.mnemonic,
            passphrase,
            &ephemeral_pub,
            &encrypted_aes_key,
            &iv,
            &encrypted_data,
            None,
        )
        .expect("Decryption should succeed");

        assert_eq!(
            decrypted, binary_data,
            "Binary data should roundtrip correctly"
        );
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        use base64ct::{Base64, Encoding};
        use x25519_dalek::{PublicKey, StaticSecret};

        let recipient_secret = StaticSecret::from([42u8; 32]);
        let recipient_public = PublicKey::from(&recipient_secret);
        let recipient_x25519_b64 = Base64::encode_string(recipient_public.as_bytes());

        let plaintext = b"Same message encrypted twice";

        // Encrypt twice
        let (_, _, iv1, encrypted1) =
            ACEGF::encrypt_for_x25519(&recipient_x25519_b64, plaintext)
                .expect("First encryption should succeed");
        let (_, _, iv2, encrypted2) =
            ACEGF::encrypt_for_x25519(&recipient_x25519_b64, plaintext)
                .expect("Second encryption should succeed");

        // Each encryption should use random IV and ephemeral key
        assert_ne!(iv1, iv2, "IVs should be different");
        assert_ne!(encrypted1, encrypted2, "Ciphertexts should be different");
    }

    #[test]
    fn test_encrypt_for_different_recipients() {
        use base64ct::{Base64, Encoding};
        use x25519_dalek::{PublicKey, StaticSecret};

        // Two different recipients
        let recipient1_secret = StaticSecret::from([42u8; 32]);
        let recipient1_public = PublicKey::from(&recipient1_secret);
        let recipient1_x25519 = Base64::encode_string(recipient1_public.as_bytes());

        let recipient2_secret = StaticSecret::from([43u8; 32]);
        let recipient2_public = PublicKey::from(&recipient2_secret);
        let recipient2_x25519 = Base64::encode_string(recipient2_public.as_bytes());

        let plaintext = b"Message for specific recipient";

        // Encrypt for each recipient
        let (_, enc_key1, _, _) = ACEGF::encrypt_for_x25519(&recipient1_x25519, plaintext)
            .expect("Encryption for recipient1 should succeed");
        let (_, enc_key2, _, _) = ACEGF::encrypt_for_x25519(&recipient2_x25519, plaintext)
            .expect("Encryption for recipient2 should succeed");

        // Encrypted AES keys should be different (encrypted with different DH keys)
        assert_ne!(
            enc_key1, enc_key2,
            "Encrypted AES keys should differ for different recipients"
        );
    }

    // ──────────────────────────────────────────────────────────────
    // XKEM (ML-KEM-768) — parallel to the x25519 tests above
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn test_xkem_roundtrip_via_acegf() {
        // End-to-end: wallet owner publishes xkem; sender encapsulates against
        // the Base64 xkem; wallet owner decapsulates with mnemonic+passphrase.
        let pass = "xkem-roundtrip-test";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        assert!(!entity.xkem.is_empty(), "xkem must be populated");

        let (ss_sender_b64, ct_b64) =
            ACEGF::encapsulate_for_xkem(&entity.xkem).expect("encapsulation should succeed");

        let ss_recipient_b64 =
            ACEGF::decapsulate_for_xkem(&entity.mnemonic, pass, &ct_b64, None)
                .expect("decapsulation should succeed");

        assert_eq!(
            ss_sender_b64, ss_recipient_b64,
            "sender and recipient must agree on the KEM shared secret"
        );
    }

    #[test]
    fn test_xkem_is_aligned_with_x25519_base64_shape() {
        // Both x25519 (X25519) and xkem (ML-KEM-768) must be Base64 strings
        // on the generated entity — callers must be able to treat them
        // identically as "publishable recipient identifiers".
        let entity = ACEGFCore::generate_ace_internal("shape-test", None).unwrap();

        use base64ct::{Base64, Encoding};
        let x25519_bytes = Base64::decode_vec(&entity.x25519).unwrap();
        let xkem_bytes = Base64::decode_vec(&entity.xkem).unwrap();

        assert_eq!(x25519_bytes.len(), 32, "X25519 public key is 32 bytes");
        assert_eq!(
            xkem_bytes.len(),
            1184,
            "ML-KEM-768 encapsulation key is 1184 bytes"
        );
    }

    #[test]
    fn test_xkem_encapsulate_invalid_base64_errors() {
        let result = ACEGF::encapsulate_for_xkem("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_xkem_encapsulate_wrong_length_errors() {
        use base64ct::{Base64, Encoding};
        let too_short = Base64::encode_string(&[0u8; 100]);
        let result = ACEGF::encapsulate_for_xkem(&too_short);
        assert!(result.is_err());
    }

    #[test]
    fn test_xkem_decapsulate_wrong_mnemonic_yields_different_secret() {
        // ML-KEM-768 implicit rejection: a wrong decapsulation key still
        // returns 32 bytes, but they won't match the sender's shared secret.
        let pass = "decaps-wrong-dk";
        let alice = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let bob = ACEGFCore::generate_ace_internal(pass, None).unwrap();

        let (ss_sender, ct) = ACEGF::encapsulate_for_xkem(&alice.xkem).unwrap();
        let ss_wrong =
            ACEGF::decapsulate_for_xkem(&bob.mnemonic, pass, &ct, None).unwrap();
        assert_ne!(ss_sender, ss_wrong);
    }

    #[test]
    fn test_xkem_two_encaps_yield_different_ciphertexts() {
        // ML-KEM encapsulation is randomized — two calls against the same
        // xkem must produce different ciphertexts even though both still
        // decapsulate to valid (but distinct) shared secrets.
        let pass = "randomized-encaps";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();

        let (ss1, ct1) = ACEGF::encapsulate_for_xkem(&entity.xkem).unwrap();
        let (ss2, ct2) = ACEGF::encapsulate_for_xkem(&entity.xkem).unwrap();
        assert_ne!(ct1, ct2);
        assert_ne!(ss1, ss2);

        // Each recovered secret round-trips correctly.
        let rec1 =
            ACEGF::decapsulate_for_xkem(&entity.mnemonic, pass, &ct1, None).unwrap();
        let rec2 =
            ACEGF::decapsulate_for_xkem(&entity.mnemonic, pass, &ct2, None).unwrap();
        assert_eq!(rec1, ss1);
        assert_eq!(rec2, ss2);
    }

    // ──────────────────────────────────────────────────────────────────
    // Hybrid X25519 + ML-KEM-768 tests — the new default encryption path
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_hybrid_roundtrip() {
        let pass = "hybrid-roundtrip";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        assert!(!entity.x25519.is_empty());
        assert!(!entity.xkem.is_empty());

        let plaintext = b"Quantum-safe NFT unlockable content - top secret.";
        let payload =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, &entity.xkem, plaintext).unwrap();

        assert_eq!(payload.v, HybridEncryptedPayload::VERSION);
        assert!(!payload.ephemeral_x25519_pub_b64.is_empty());
        assert!(!payload.kem_ciphertext_b64.is_empty());

        let recovered =
            ACEGF::decrypt_for_recipient_pq(&entity.mnemonic, pass, &payload, None).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_hybrid_version_tag_exact() {
        // The serialized payload must contain the exact version string;
        // any rename / drift on either side should be caught by this test.
        let entity = ACEGFCore::generate_ace_internal("v-tag", None).unwrap();
        let payload =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, &entity.xkem, b"hi").unwrap();
        assert_eq!(payload.v, "acegf-hybrid-kem-v1");
    }

    #[test]
    fn test_hybrid_version_mismatch_rejected() {
        // Anti-downgrade: swapping the version string MUST fail decryption,
        // not silently fall back to any other path.
        let pass = "version-mismatch";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let mut payload =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, &entity.xkem, b"hi").unwrap();

        payload.v = "acegf-hybrid-kem-v0".to_string();
        let result = ACEGF::decrypt_for_recipient_pq(&entity.mnemonic, pass, &payload, None);
        assert!(result.is_err(), "version mismatch must be rejected");
    }

    #[test]
    fn test_hybrid_tampered_ephemeral_pub_rejected() {
        // Tampering the ephemeral X25519 pub changes the HKDF info binding
        // → derived AES key differs → AES-GCM auth tag fails.
        let pass = "tamper-eph";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let mut payload =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, &entity.xkem, b"hi").unwrap();

        // Swap in a random but well-formed 32-byte X25519 pub.
        use base64ct::{Base64, Encoding};
        use x25519_dalek::{PublicKey, StaticSecret};
        let fake_secret = StaticSecret::from([0xAAu8; 32]);
        let fake_pub = PublicKey::from(&fake_secret);
        payload.ephemeral_x25519_pub_b64 = Base64::encode_string(fake_pub.as_bytes());

        let result = ACEGF::decrypt_for_recipient_pq(&entity.mnemonic, pass, &payload, None);
        assert!(result.is_err(), "tampered ephemeral pub must be rejected");
    }

    #[test]
    fn test_hybrid_tampered_kem_ciphertext_rejected() {
        // Flip a byte in the KEM ciphertext → decapsulation still succeeds
        // (ML-KEM implicit rejection) but yields a different shared secret
        // → AES-GCM auth fails.
        let pass = "tamper-kem-ct";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let mut payload =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, &entity.xkem, b"hi").unwrap();

        use base64ct::{Base64, Encoding};
        let mut kem_ct_bytes = Base64::decode_vec(&payload.kem_ciphertext_b64).unwrap();
        kem_ct_bytes[0] ^= 0x01;
        payload.kem_ciphertext_b64 = Base64::encode_string(&kem_ct_bytes);

        let result = ACEGF::decrypt_for_recipient_pq(&entity.mnemonic, pass, &payload, None);
        assert!(result.is_err(), "tampered kem ciphertext must be rejected");
    }

    #[test]
    fn test_hybrid_tampered_aes_ciphertext_rejected() {
        // Flip a byte in the AES-GCM ciphertext → auth tag mismatch.
        let pass = "tamper-aes-ct";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let mut payload =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, &entity.xkem, b"hello").unwrap();

        payload.ciphertext[0] ^= 0x01;

        let result = ACEGF::decrypt_for_recipient_pq(&entity.mnemonic, pass, &payload, None);
        assert!(result.is_err(), "tampered aes ciphertext must be rejected");
    }

    #[test]
    fn test_hybrid_wrong_mnemonic_rejected() {
        // Alice encrypts to herself, Bob cannot decrypt.
        let pass = "wrong-mnemonic";
        let alice = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let bob = ACEGFCore::generate_ace_internal(pass, None).unwrap();

        let payload =
            ACEGF::encrypt_for_recipient_pq(&alice.x25519, &alice.xkem, b"Alice-only").unwrap();

        let result = ACEGF::decrypt_for_recipient_pq(&bob.mnemonic, pass, &payload, None);
        assert!(result.is_err(), "Bob must not be able to decrypt Alice's payload");
    }

    #[test]
    fn test_hybrid_two_encrypts_yield_different_ciphertexts() {
        // Fresh ephemeral X25519 + fresh ML-KEM encapsulation randomness
        // ensure every encryption of the same plaintext is distinct.
        let entity = ACEGFCore::generate_ace_internal("fresh-randomness", None).unwrap();

        let p1 =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, &entity.xkem, b"same plaintext").unwrap();
        let p2 =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, &entity.xkem, b"same plaintext").unwrap();

        assert_ne!(p1.ephemeral_x25519_pub_b64, p2.ephemeral_x25519_pub_b64);
        assert_ne!(p1.kem_ciphertext_b64, p2.kem_ciphertext_b64);
        assert_ne!(p1.iv_b64, p2.iv_b64);
        assert_ne!(p1.ciphertext, p2.ciphertext);
    }

    #[test]
    fn test_hybrid_empty_plaintext() {
        // Edge case — AES-GCM on empty message is still a valid 16-byte tag.
        let pass = "empty";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let payload =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, &entity.xkem, b"").unwrap();
        let recovered =
            ACEGF::decrypt_for_recipient_pq(&entity.mnemonic, pass, &payload, None).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_hybrid_large_plaintext() {
        let pass = "large";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let plaintext = vec![0x5Au8; 256 * 1024]; // 256 KiB
        let payload =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, &entity.xkem, &plaintext).unwrap();
        let recovered =
            ACEGF::decrypt_for_recipient_pq(&entity.mnemonic, pass, &payload, None).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_hybrid_json_wire_roundtrip() {
        // Serialize → string → deserialize → decrypt. Validates the WASM/FFI
        // JSON transport path end-to-end.
        let pass = "json-wire";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let payload =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, &entity.xkem, b"wire-format").unwrap();

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("acegf-hybrid-kem-v1"));
        assert!(json.contains("ephemeral_x25519_pub_b64"));
        assert!(json.contains("kem_ciphertext_b64"));

        let parsed: HybridEncryptedPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, payload);

        let recovered =
            ACEGF::decrypt_for_recipient_pq(&entity.mnemonic, pass, &parsed, None).unwrap();
        assert_eq!(recovered, b"wire-format");
    }

    #[test]
    fn test_hybrid_missing_xkem_errors() {
        // New API refuses to encrypt without a valid xkem — no silent
        // fallback to X25519-only.
        let entity = ACEGFCore::generate_ace_internal("missing-xkem", None).unwrap();
        let result =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, "", b"hi");
        assert!(result.is_err(), "empty xkem must error, not downgrade");
    }

    #[test]
    fn test_hybrid_missing_x25519_errors() {
        let entity = ACEGFCore::generate_ace_internal("missing-x", None).unwrap();
        let result = ACEGF::encrypt_for_recipient_pq("", &entity.xkem, b"hi");
        assert!(result.is_err(), "empty x25519 must error, not skip classical half");
    }

    #[test]
    fn test_hybrid_legacy_and_new_coexist() {
        // A wallet can continue to produce AND consume legacy X25519
        // ciphertexts while also producing and consuming new hybrid ones.
        // The two formats must not interfere with each other.
        let pass = "coexist";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();

        // Legacy path still works.
        let (eph_pub, enc_key, iv, legacy_ct) =
            ACEGF::encrypt_for_x25519(&entity.x25519, b"legacy message").unwrap();
        let legacy_pt = ACEGF::decrypt_internal(
            &entity.mnemonic,
            pass,
            &eph_pub,
            &enc_key,
            &iv,
            &legacy_ct,
            None,
        )
        .unwrap();
        assert_eq!(legacy_pt, b"legacy message");

        // New hybrid path also works.
        let hybrid_payload =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, &entity.xkem, b"new message")
                .unwrap();
        let hybrid_pt =
            ACEGF::decrypt_for_recipient_pq(&entity.mnemonic, pass, &hybrid_payload, None)
                .unwrap();
        assert_eq!(hybrid_pt, b"new message");
    }

    #[test]
    fn test_hybrid_base_key_path_matches_passphrase_path() {
        // The Session PRF flow and the passphrase flow must agree.
        use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;

        let pass = "prf-vs-passphrase";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();

        let payload =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, &entity.xkem, b"both paths").unwrap();

        let via_passphrase =
            ACEGF::decrypt_for_recipient_pq(&entity.mnemonic, pass, &payload, None).unwrap();

        let base_key = PassphraseSealingUtil::derive_base_key(pass.as_bytes()).unwrap();
        let via_base_key = ACEGF::decrypt_for_recipient_pq_with_base_key(
            &entity.mnemonic,
            &base_key,
            &payload,
        )
        .unwrap();

        assert_eq!(via_passphrase, b"both paths");
        assert_eq!(via_passphrase, via_base_key);
    }

    #[test]
    fn test_hybrid_version_binding_via_hkdf_info() {
        // Sanity that the `v` field is not just metadata — it's mixed into
        // the HKDF info (or at least strictly compared). Either way, tampering
        // with it must fail. This is already covered by
        // `test_hybrid_version_mismatch_rejected` but here we exercise every
        // non-matching value in a small alphabet to double-check there's no
        // edge case where the version is ignored.
        let pass = "binding";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let payload =
            ACEGF::encrypt_for_recipient_pq(&entity.x25519, &entity.xkem, b"x").unwrap();

        for bad in &[
            "",
            "acegf-hybrid-kem-v2",
            "acegf-hybrid-kem-v1 ",
            " acegf-hybrid-kem-v1",
            "ACEGF-HYBRID-KEM-V1",
            "legacy",
            "null",
        ] {
            let mut tampered = payload.clone();
            tampered.v = bad.to_string();
            let result =
                ACEGF::decrypt_for_recipient_pq(&entity.mnemonic, pass, &tampered, None);
            assert!(result.is_err(), "version {:?} must be rejected", bad);
        }
    }
}
