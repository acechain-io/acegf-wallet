// src/vadar.rs
//
// VA-DAR (Vendor-Agnostic Deterministic Artifact Resolution)
// Implements the cryptographic operations for the discovery-and-recovery layer
//
// Reference: VA-DAR specification (07_VA_DAR.pdf)
//
// Key derivation hierarchy:
//   Primary Passphrase P
//       |
//       v
//   Kmaster = Argon2id(P, SALT_GLOBAL)
//       |
//       +---> Ksa  = HKDF(Kmaster, "acegf:sa2:seal")      -- for sealing SA2
//       +---> Kidx = HKDF(Kmaster, "va-dar:discovery:index") -- for DiscoveryID
//       +---> Kreg = HKDF(Kmaster, "va-dar:registry:auth")   -- for registry auth (owner key)

use crate::acegf_structs::AcegfError;
use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;
use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256GcmSiv, Nonce,
};
use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{digest::KeyInit as HmacKeyInit, Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// VA-DAR core implementation
pub struct VADAR;

impl VADAR {
    // Domain separation constants (per VA-DAR spec Section 5.2)
    const INFO_SA2_SEAL: &'static [u8] = b"acegf:sa2:seal";
    const INFO_DISCOVERY_INDEX: &'static [u8] = b"va-dar:discovery:index";
    const INFO_REGISTRY_AUTH: &'static [u8] = b"va-dar:registry:auth";

    // SA2 artifact constants
    const SA2_VERSION: u8 = 0x01;
    const SA2_AEAD_ALG: u8 = 0x01; // AES-256-GCM-SIV

    // =========================================================================
    // Email Normalization (Section 6.2)
    // =========================================================================

    /// Normalize an email identifier according to VA-DAR spec
    /// - Lowercase
    /// - Trim whitespace
    /// - Remove +suffix from local part (RFC 5233 sub-addressing, universally supported)
    ///
    /// NOTE: We intentionally do NOT remove dots from the local part.
    /// Only Gmail treats dots as insignificant; for all other providers
    /// (Outlook, ProtonMail, etc.) "john.doe" and "johndoe" are different
    /// mailboxes. Removing dots would create a cross-user collision risk
    /// where two distinct users could derive the same Discovery ID.
    pub fn normalize_email(email: &str) -> String {
        let email = email.trim().to_lowercase();

        // Split into local and domain parts
        if let Some((local, domain)) = email.split_once('@') {
            // Remove +suffix (plus addressing / sub-addressing)
            // RFC 5233: user+tag@domain routes to user@domain on all providers
            let local = if let Some((base, _suffix)) = local.split_once('+') {
                base.to_string()
            } else {
                local.to_string()
            };

            format!("{}@{}", local, domain)
        } else {
            // Not a valid email format, just return trimmed lowercase
            email
        }
    }

    // =========================================================================
    // Key Derivation (Section 5)
    // =========================================================================

    /// VA-DAR salt prefix for domain separation from the global ACEGF salt.
    const VADAR_SALT_PREFIX: &'static [u8] = b"ACEGF-VADAR-V1:";

    /// Derive base key using per-identity salt instead of global salt.
    ///
    /// salt = "ACEGF-VADAR-V1:" || normalized_email
    ///
    /// This ensures:
    /// - Two users with the same password produce different base keys
    /// - Rainbow tables built against the global salt don't apply
    /// - Domain separation from the non-VA-DAR derivation path
    // pub(crate) for test access; not exposed outside the crate
    pub(crate) fn derive_vadar_base_key(
        password: &str,
        normalized_email: &str,
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut salt = Vec::with_capacity(Self::VADAR_SALT_PREFIX.len() + normalized_email.len());
        salt.extend_from_slice(Self::VADAR_SALT_PREFIX);
        salt.extend_from_slice(normalized_email.as_bytes());

        PassphraseSealingUtil::derive_base_key_with_salt(password.as_bytes(), &salt)
    }

    /// Derive Ksa (sealing key) from base key
    fn derive_ksa(base_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut ksa = [0u8; 32];
        let hkdf = Hkdf::<Sha256>::new(None, base_key);
        hkdf.expand(Self::INFO_SA2_SEAL, &mut ksa)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(ksa))
    }

    /// Derive Kidx (discovery index key) from base key
    fn derive_kidx(base_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut kidx = [0u8; 32];
        let hkdf = Hkdf::<Sha256>::new(None, base_key);
        hkdf.expand(Self::INFO_DISCOVERY_INDEX, &mut kidx)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(kidx))
    }

    /// Derive Kreg (registry auth key) from base key
    /// This is used as seed for Ed25519 signing key
    fn derive_kreg(base_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut kreg = [0u8; 32];
        let hkdf = Hkdf::<Sha256>::new(None, base_key);
        hkdf.expand(Self::INFO_REGISTRY_AUTH, &mut kreg)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(kreg))
    }

    // =========================================================================
    // Discovery ID (Section 6)
    // =========================================================================

    /// Compute DiscoveryID = HMAC(Kidx, Norm(I))
    /// Returns hex-encoded 32-byte discovery ID
    pub fn compute_discovery_id(
        password: &str,
        normalized_email: &str,
    ) -> Result<String, AcegfError> {
        // Derive base key from password with per-identity salt
        let base_key = Self::derive_vadar_base_key(password, normalized_email)?;

        // Derive Kidx
        let kidx = Self::derive_kidx(&base_key)?;

        // Compute HMAC(Kidx, normalized_email)
        let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(&*kidx)
            .map_err(|_| AcegfError::Internal)?;
        mac.update(normalized_email.as_bytes());
        let result = mac.finalize();

        Ok(hex::encode(result.into_bytes()))
    }

    // =========================================================================
    // SA2 Sealing/Unsealing (Section 7.1)
    // =========================================================================

    /// Seal mnemonic into SA2 artifact
    ///
    /// SA2 Format:
    /// - version (1 byte)
    /// - aead_alg (1 byte)
    /// - nonce (12 bytes)
    /// - ciphertext (variable, includes 16-byte auth tag)
    ///
    /// AAD = version || aead_alg || normalized_email
    pub fn seal_sa2(
        mnemonic: &str,
        password: &str,
        normalized_email: &str,
    ) -> Result<String, AcegfError> {
        // Derive keys with per-identity salt
        let base_key = Self::derive_vadar_base_key(password, normalized_email)?;
        let ksa = Self::derive_ksa(&base_key)?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).map_err(|_| AcegfError::Internal)?;

        // Build AAD: version || aead_alg || normalized_email
        let mut aad = Vec::with_capacity(2 + normalized_email.len());
        aad.push(Self::SA2_VERSION);
        aad.push(Self::SA2_AEAD_ALG);
        aad.extend_from_slice(normalized_email.as_bytes());

        // Encrypt mnemonic
        let cipher = Aes256GcmSiv::new_from_slice(&*ksa).map_err(|_| AcegfError::Internal)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: mnemonic.as_bytes(),
            aad: &aad,
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| AcegfError::Internal)?;

        // Build SA2: version || aead_alg || nonce || ciphertext
        let mut sa2 = Vec::with_capacity(2 + 12 + ciphertext.len());
        sa2.push(Self::SA2_VERSION);
        sa2.push(Self::SA2_AEAD_ALG);
        sa2.extend_from_slice(&nonce_bytes);
        sa2.extend_from_slice(&ciphertext);

        Ok(Base64::encode_string(&sa2))
    }

    /// Unseal SA2 artifact to recover mnemonic
    pub fn unseal_sa2(
        sa2_base64: &str,
        password: &str,
        normalized_email: &str,
    ) -> Result<String, AcegfError> {
        // Decode base64
        let sa2 = Base64::decode_vec(sa2_base64).map_err(|_| AcegfError::InvalidFormat)?;

        // Parse SA2 header
        if sa2.len() < 14 {
            return Err(AcegfError::InvalidFormat);
        }

        let version = sa2[0];
        let aead_alg = sa2[1];

        if version != Self::SA2_VERSION || aead_alg != Self::SA2_AEAD_ALG {
            return Err(AcegfError::InvalidFormat);
        }

        let nonce_bytes = &sa2[2..14];
        let ciphertext = &sa2[14..];

        // Derive keys with per-identity salt
        let base_key = Self::derive_vadar_base_key(password, normalized_email)?;
        let ksa = Self::derive_ksa(&base_key)?;

        // Build AAD
        let mut aad = Vec::with_capacity(2 + normalized_email.len());
        aad.push(version);
        aad.push(aead_alg);
        aad.extend_from_slice(normalized_email.as_bytes());

        // Decrypt
        let cipher = Aes256GcmSiv::new_from_slice(&*ksa).map_err(|_| AcegfError::Internal)?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };
        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| AcegfError::InvalidPassphrase)?;

        String::from_utf8(plaintext).map_err(|_| AcegfError::Internal)
    }

    // =========================================================================
    // Registry Authorization (Section 8.2 - Option B)
    // =========================================================================

    /// Get owner public key for registry (Ed25519)
    /// Returns base64-encoded public key
    pub fn get_owner_pubkey(password: &str, normalized_email: &str) -> Result<String, AcegfError> {
        let base_key = Self::derive_vadar_base_key(password, normalized_email)?;
        let kreg = Self::derive_kreg(&base_key)?;

        // Use HKDF output as Ed25519 seed (with email as additional context)
        let mut seed = Zeroizing::new([0u8; 32]);
        let hkdf = Hkdf::<Sha256>::new(Some(normalized_email.as_bytes()), &*kreg);
        hkdf.expand(b"va-dar:owner:keypair", &mut *seed)
            .map_err(|_| AcegfError::KdfError)?;

        let signing_key = SigningKey::from_bytes(&*seed);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        Ok(Base64::encode_string(verifying_key.as_bytes()))
    }

    /// Sign registry update (for create/update operations)
    /// Message format: "vadar-update:{discoveryId}:{cid}:{version}:{commit}"
    /// This format matches the relayer's buildUpdateMessage() function
    /// Returns base64-encoded signature
    pub fn sign_registry_update(
        password: &str,
        normalized_email: &str,
        discovery_id: &str,
        cid: &str,
        version: u64,
        commit: &str,
    ) -> Result<String, AcegfError> {
        // Derive signing key with per-identity salt
        let base_key = Self::derive_vadar_base_key(password, normalized_email)?;
        let kreg = Self::derive_kreg(&base_key)?;

        let mut seed = Zeroizing::new([0u8; 32]);
        let hkdf = Hkdf::<Sha256>::new(Some(normalized_email.as_bytes()), &*kreg);
        hkdf.expand(b"va-dar:owner:keypair", &mut *seed)
            .map_err(|_| AcegfError::KdfError)?;

        let signing_key = SigningKey::from_bytes(&*seed);

        // Build message to sign - matches relayer's buildUpdateMessage()
        // Format: "vadar-update:{discoveryId}:{cid}:{version}:{commit}"
        let message = format!(
            "vadar-update:{}:{}:{}:{}",
            discovery_id, cid, version, commit
        );

        // Sign
        let signature = signing_key.sign(message.as_bytes());

        Ok(Base64::encode_string(&signature.to_bytes()))
    }

    // =========================================================================
    // Commit Hash (Section 8.1)
    // =========================================================================

    /// Compute commit hash of SA2 artifact
    /// commit = SHA256(SA2)
    /// Returns hex-encoded hash
    pub fn compute_commit(sa2_base64: &str) -> Result<String, AcegfError> {
        let sa2 = Base64::decode_vec(sa2_base64).map_err(|_| AcegfError::InvalidFormat)?;

        let hash = Sha256::digest(&sa2);

        Ok(hex::encode(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_email() {
        // Basic normalization: lowercase + trim
        assert_eq!(
            VADAR::normalize_email("  Test@Example.COM  "),
            "test@example.com"
        );

        // Dots are preserved (only Gmail ignores dots; other providers treat them as significant)
        assert_eq!(
            VADAR::normalize_email("john.doe@gmail.com"),
            "john.doe@gmail.com"
        );
        assert_eq!(
            VADAR::normalize_email("john.doe@outlook.com"),
            "john.doe@outlook.com"
        );

        // Plus addressing removal (RFC 5233 — universally supported)
        assert_eq!(
            VADAR::normalize_email("user+tag@domain.com"),
            "user@domain.com"
        );

        // Combined: lowercase + trim + plus removal, but dots preserved
        assert_eq!(
            VADAR::normalize_email("J.Smith+newsletter@Gmail.COM"),
            "j.smith@gmail.com"
        );
    }

    #[test]
    fn test_discovery_id_deterministic() {
        let id1 = VADAR::compute_discovery_id("password123", "test@example.com").unwrap();
        let id2 = VADAR::compute_discovery_id("password123", "test@example.com").unwrap();
        assert_eq!(id1, id2);

        // Different password = different ID
        let id3 = VADAR::compute_discovery_id("different", "test@example.com").unwrap();
        assert_ne!(id1, id3);

        // Different email = different ID
        let id4 = VADAR::compute_discovery_id("password123", "other@example.com").unwrap();
        assert_ne!(id1, id4);
    }

    #[test]
    fn test_seal_unseal_roundtrip() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = "test-password";
        let email = "test@example.com";

        let sealed = VADAR::seal_sa2(mnemonic, password, email).unwrap();
        let unsealed = VADAR::unseal_sa2(&sealed, password, email).unwrap();

        assert_eq!(mnemonic, unsealed);
    }

    #[test]
    fn test_unseal_wrong_password_fails() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = "correct-password";
        let email = "test@example.com";

        let sealed = VADAR::seal_sa2(mnemonic, password, email).unwrap();
        let result = VADAR::unseal_sa2(&sealed, "wrong-password", email);

        assert!(result.is_err());
    }

    #[test]
    fn test_owner_pubkey_deterministic() {
        let pk1 = VADAR::get_owner_pubkey("password", "test@example.com").unwrap();
        let pk2 = VADAR::get_owner_pubkey("password", "test@example.com").unwrap();
        assert_eq!(pk1, pk2);

        // Different inputs = different keys
        let pk3 = VADAR::get_owner_pubkey("other", "test@example.com").unwrap();
        assert_ne!(pk1, pk3);
    }

    #[test]
    fn test_commit_deterministic() {
        let sa2 = "AQEAAAAAAAAAAAAAAAAAAAAAAAAA"; // dummy base64
        let commit1 = VADAR::compute_commit(sa2).unwrap();
        let commit2 = VADAR::compute_commit(sa2).unwrap();
        assert_eq!(commit1, commit2);
    }

    #[test]
    fn test_per_identity_salt_isolation() {
        // Same password, different emails → different discovery IDs, keys, etc.
        let password = "same-password";
        let email_a = "alice@example.com";
        let email_b = "bob@example.com";

        // Discovery IDs must differ (base_key differs due to per-identity salt)
        let id_a = VADAR::compute_discovery_id(password, email_a).unwrap();
        let id_b = VADAR::compute_discovery_id(password, email_b).unwrap();
        assert_ne!(
            id_a, id_b,
            "Same password with different emails must produce different discovery IDs"
        );

        // Owner pubkeys must differ
        let pk_a = VADAR::get_owner_pubkey(password, email_a).unwrap();
        let pk_b = VADAR::get_owner_pubkey(password, email_b).unwrap();
        assert_ne!(
            pk_a, pk_b,
            "Same password with different emails must produce different owner pubkeys"
        );

        // SA2 sealed under email_a cannot be unsealed under email_b
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let sealed_a = VADAR::seal_sa2(mnemonic, password, email_a).unwrap();
        let result = VADAR::unseal_sa2(&sealed_a, password, email_b);
        assert!(
            result.is_err(),
            "SA2 sealed under email_a must not unseal under email_b"
        );
    }

    #[test]
    fn test_vadar_salt_domain_separation() {
        // Ensure VA-DAR derivation path is separate from global ACEGF path.
        // derive_vadar_base_key uses "ACEGF-VADAR-V1:{email}" as salt,
        // while derive_base_key uses "ACEGF-KDF-GLOBAL-V1".
        // Even with the same password, the base keys must differ.
        let password = "test-password";
        let email = "test@example.com";

        let global_base_key = PassphraseSealingUtil::derive_base_key(password.as_bytes()).unwrap();
        let vadar_base_key = VADAR::derive_vadar_base_key(password, email).unwrap();

        assert_ne!(
            global_base_key.as_slice(),
            vadar_base_key.as_slice(),
            "VA-DAR base key must differ from global base key"
        );
    }
}
