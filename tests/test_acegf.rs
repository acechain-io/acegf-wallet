use acegf::acegf_core::ACEGFCore;
use acegf::ACEGF;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce as AesNonce};
use arrayref::array_ref;
use base64ct::{Base64, Encoding};
use crypto_common::rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

#[derive(Debug)]
enum CryptoTestError {
    AesGcmError(String),
    InvalidLengthError(String),
    InternalError(String),
}

impl fmt::Display for CryptoTestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoTestError::AesGcmError(msg) => write!(f, "AES-GCM error: {}", msg),
            CryptoTestError::InvalidLengthError(msg) => write!(f, "Invalid length error: {}", msg),
            CryptoTestError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl Error for CryptoTestError {}

impl From<crypto_common::InvalidLength> for CryptoTestError {
    fn from(e: crypto_common::InvalidLength) -> Self {
        CryptoTestError::InvalidLengthError(format!("{}", e))
    }
}

impl From<aes_gcm::Error> for CryptoTestError {
    fn from(e: aes_gcm::Error) -> Self {
        CryptoTestError::AesGcmError(format!("{}", e))
    }
}

fn get_recipient_x25519_pubkey(
    mnemonic: &str,
    passphrase: &str,
    secondary_passphrase: Option<&str>,
) -> Result<String, Box<dyn Error>> {
    let mut seeds = ACEGFCore::unseal_to_seeds(mnemonic, passphrase, secondary_passphrase)
        .map_err(|e| {
            Box::new(CryptoTestError::InternalError(format!(
                "Derive seeds failed: {:?}",
                e
            ))) as Box<dyn Error>
        })?;
    let x25519_seed = &seeds.x25519;

    let mut raw = **x25519_seed;
    raw[0] &= 248;
    raw[31] &= 127;
    raw[31] |= 64;
    let private = StaticSecret::from(raw);

    let public = XPublic::from(&private);
    let pub_b64 = Base64::encode_string(public.as_bytes());

    ACEGFCore::clear_scheme_seeds(&mut seeds);
    Ok(pub_b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ace_internal_basic() {
        let passphrase = "correct-horse-battery-staple";
        let secondary = Some("optional-salt");

        let result = ACEGFCore::generate_ace_internal(passphrase, secondary);

        assert!(result.is_ok(), "Entity generation should succeed");
        let entity = result.unwrap();

        assert!(!entity.mnemonic.is_empty());
        assert!(entity.evm_address.starts_with("0x"));
        assert!(entity.bitcoin_address.starts_with("bc1p"));
        assert!(!entity.solana_address.is_empty());
        assert!(entity.xaddress.starts_with("acegf"));
    }
}

#[cfg(test)]
mod acegf_view_wallet_tests {
    use super::*;

    #[test]
    fn test_view_wallet_native_mode() {
        let pass = "test-pass";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let mnemonic = &entity.mnemonic;

        let restored = ACEGFCore::view_wallet_internal(mnemonic, pass, None).unwrap();
        assert_eq!(restored.evm_address, entity.evm_address);
        assert_eq!(restored.bitcoin_address, entity.bitcoin_address);
        assert_eq!(restored.solana_address, entity.solana_address);
    }

    #[test]
    fn test_view_wallet_wrong_passphrase() {
        let pass = "correct-pass";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();

        let result = ACEGFCore::view_wallet_internal(&entity.mnemonic, "wrong-pass", None);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod acegf_crypto_tests {
    use super::*;

    #[test]
    fn test_compute_dh_key_internal() {
        let pass = "test-dh-key";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let mnemonic = &entity.mnemonic;

        let mut csprng = OsRng;
        let peer_secret = StaticSecret::random_from_rng(&mut csprng);
        let peer_pub = XPublic::from(&peer_secret);
        let peer_pub_b64 = Base64::encode_string(peer_pub.as_bytes());

        let dh_key = ACEGF::compute_dh_key_internal(mnemonic, pass, &peer_pub_b64, None)
            .expect("DH key computation failed");

        assert_eq!(dh_key.len(), 32, "DH key must be 32 bytes");
    }

    #[test]
    fn test_decrypt_internal_end_to_end() {
        let pass = "test-decrypt-123";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let mnemonic = &entity.mnemonic;
        let plaintext = b"test secret message 123456";

        let mut csprng = OsRng;
        let ephemeral_secret = StaticSecret::random_from_rng(&mut csprng);
        let ephemeral_pub = XPublic::from(&ephemeral_secret);
        let ephemeral_pub_b64 = Base64::encode_string(ephemeral_pub.as_bytes());

        let recipient_pub_b64 = get_recipient_x25519_pubkey(mnemonic, pass, None).unwrap();
        let recipient_pub_bytes = Base64::decode_vec(&recipient_pub_b64).unwrap();
        let recipient_pub = XPublic::from(*array_ref![recipient_pub_bytes, 0, 32]);

        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pub);
        let dh_hash = Sha256::digest(shared_secret.as_bytes());
        let mut dh_key = vec![0u8; 32];
        dh_key.copy_from_slice(&dh_hash[..]);

        let mut aes_key = [0u8; 32];
        OsRng.fill_bytes(&mut aes_key);
        let mut iv = [0u8; 12];
        OsRng.fill_bytes(&mut iv);
        let nonce = AesNonce::from_slice(&iv);

        let master_key = Aes256Gcm::new_from_slice(&dh_key).unwrap();
        let encrypted_aes_key = master_key.encrypt(nonce, aes_key.as_slice()).unwrap();
        let encrypted_aes_key_b64 = Base64::encode_string(&encrypted_aes_key);
        let iv_b64 = Base64::encode_string(&iv);

        let data_cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let encrypted_data = data_cipher.encrypt(nonce, plaintext.as_slice()).unwrap();

        let decrypted = ACEGF::decrypt_internal(
            mnemonic,
            pass,
            &ephemeral_pub_b64,
            &encrypted_aes_key_b64,
            &iv_b64,
            &encrypted_data,
            None,
        )
        .expect("Decryption failed");

        assert_eq!(
            decrypted, plaintext,
            "Decrypted result must match plaintext"
        );
    }

    // ─── HFI Pay Registration ───

    #[test]
    fn test_hfi_pay_registration_message() {
        let pass = "test-passphrase";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let mnemonic = entity.mnemonic.to_string();
        let xid_hex = &entity.xid;

        let identifier = "alice@example.com";

        // Compute registration message hash manually
        let mut hasher = Sha256::new();
        hasher.update(b"hfipay:register");
        hasher.update(&hex::decode(xid_hex).unwrap());
        hasher.update(identifier.as_bytes());
        let expected_hash = hex::encode(hasher.finalize());

        // Use the library function
        let msg_hash = acegf::hfi_pay::registration_message(xid_hex, identifier);
        assert!(
            !msg_hash.starts_with("error:"),
            "registration_message should not error: {}",
            msg_hash
        );
        assert_eq!(
            msg_hash, expected_hash,
            "Message hash should match manual computation"
        );

        // Sign registration with ML-DSA-44
        let reg = acegf::hfi_pay::sign_registration(&mnemonic, pass, xid_hex, identifier)
            .expect("sign_registration should succeed");

        assert_eq!(reg.algorithm, 2, "Expected ML-DSA-44 algorithm tag");

        // Verify the signature with the wallet's ML-DSA-44 wrapper
        use acegf::pqclean_ffi::MlDsa44;
        let pubkey_bytes = Base64::decode_vec(&reg.pubkey).unwrap();
        let sig_bytes = Base64::decode_vec(&reg.signature).unwrap();
        let msg_bytes = hex::decode(&reg.message).unwrap();

        assert_eq!(pubkey_bytes.len(), MlDsa44::PK_BYTES);
        assert_eq!(sig_bytes.len(), MlDsa44::SIG_BYTES);

        let pk: [u8; MlDsa44::PK_BYTES] = pubkey_bytes.try_into().unwrap();
        let sig: [u8; MlDsa44::SIG_BYTES] = sig_bytes.try_into().unwrap();

        assert!(
            MlDsa44::verify(&pk, &msg_bytes, &sig).unwrap_or(false),
            "ML-DSA-44 signature should be valid"
        );

        // Message in result should match independently computed hash
        assert_eq!(
            reg.message, expected_hash,
            "Signed message should match expected hash"
        );
    }

    #[test]
    fn test_hfi_pay_registration_deterministic() {
        let pass = "deterministic-test";
        let entity = ACEGFCore::generate_ace_internal(pass, None).unwrap();
        let mnemonic = entity.mnemonic.to_string();
        let xid_hex = &entity.xid;
        let identifier = "+1234567890";

        let msg1 = acegf::hfi_pay::registration_message(xid_hex, identifier);
        let msg2 = acegf::hfi_pay::registration_message(xid_hex, identifier);
        assert_eq!(msg1, msg2, "Registration message should be deterministic");

        // Different identifier → different message
        let msg3 = acegf::hfi_pay::registration_message(xid_hex, "other@example.com");
        assert_ne!(
            msg1, msg3,
            "Different identifier should produce different message"
        );

        // Sign twice → ML-DSA-44 in hedged mode produces fresh signatures, but
        // the keypair (and therefore the public key) is deterministic from the
        // mnemonic-derived seed, and both signatures must verify against the
        // same key.
        let r1 = acegf::hfi_pay::sign_registration(&mnemonic, pass, xid_hex, identifier).unwrap();
        let r2 = acegf::hfi_pay::sign_registration(&mnemonic, pass, xid_hex, identifier).unwrap();
        assert_eq!(r1.pubkey, r2.pubkey, "ML-DSA-44 public key should be deterministic");
        assert_eq!(r1.message, r2.message, "Registration message should be deterministic");
        assert_eq!(r1.algorithm, 2);
        assert_eq!(r2.algorithm, 2);

        use acegf::pqclean_ffi::MlDsa44;
        let pk_bytes = Base64::decode_vec(&r1.pubkey).unwrap();
        let pk: [u8; MlDsa44::PK_BYTES] = pk_bytes.try_into().unwrap();
        let msg = hex::decode(&r1.message).unwrap();
        for r in [&r1, &r2] {
            let sig_vec = Base64::decode_vec(&r.signature).unwrap();
            let sig: [u8; MlDsa44::SIG_BYTES] = sig_vec.try_into().unwrap();
            assert!(
                MlDsa44::verify(&pk, &msg, &sig).unwrap_or(false),
                "Each ML-DSA-44 signature should verify against the deterministic public key"
            );
        }
    }

    #[test]
    fn test_hfi_pay_registration_invalid_xid() {
        let result = acegf::hfi_pay::registration_message("not-hex", "test@example.com");
        assert!(
            result.starts_with("error:"),
            "Should error on invalid xid: {}",
            result
        );

        let result = acegf::hfi_pay::registration_message("aabb", "test@example.com");
        assert!(
            result.starts_with("error:"),
            "Should error on short xid: {}",
            result
        );
    }
}
