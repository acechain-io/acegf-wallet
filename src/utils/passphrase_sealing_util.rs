// src/utils/passphrase_sealing_util.rs
//
// Passphrase utilities for canonical REV32-only ACE-GF flow.

use crate::acegf_structs::AcegfError;
use crate::utils::acegf_rev_generator::{AceRevGenerator, Rev32};
use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256GcmSiv, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum MnemonicSealError {
    #[error("Invalid word in mnemonic: {0}")]
    InvalidWord(String),
    #[error("Invalid mnemonic format or length")]
    InvalidFormat,
    #[error("Invalid entropy length")]
    InvalidEntropy,
    #[error("Mnemonic parse error: {0}")]
    Bip39(#[from] bip39::Error),
    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

pub struct PassphraseSealingUtil;

impl PassphraseSealingUtil {
    pub const SALT_GLOBAL: &'static [u8] = b"ACEGF-KDF-GLOBAL-V1";
    pub const SALT_REV32: &'static [u8] = b"ACEGF-KDF-REV32-V1";
    pub const SALT_SEALED: &'static [u8] = b"ACEGF-KDF-NATIVE-V1";

    const INFO_IDENTITY_ROOT: &'static [u8] = b"acegf:identity:root";
    const INFO_KMASTER_FROM_BASE_KEY: &'static [u8] = b"acegf:rev32:kmaster";
    const PROTOCOL_VERSION_AD: &'static [u8] = &[0x01];

    fn argon2_config() -> Result<Argon2<'static>, AcegfError> {
        let params = Params::new(4096, 3, 1, Some(32)).map_err(|_| AcegfError::KdfError)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    pub fn derive_base_key(passphrase: &[u8]) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        Self::derive_base_key_with_salt(passphrase, Self::SALT_GLOBAL)
    }

    pub fn derive_base_key_with_salt(
        passphrase: &[u8],
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut base_key = [0u8; 32];
        Self::argon2_config()?
            .hash_password_into(passphrase, salt, &mut base_key)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(base_key))
    }

    fn expand_key(base_key: &[u8; 32], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut okm = [0u8; 32];
        let h = Hkdf::<Sha256>::new(None, base_key);
        h.expand(info, &mut okm).map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(okm))
    }

    fn encrypt_internal(data: &[u8; 16], key: &[u8; 32]) -> Result<[u8; 32], AcegfError> {
        let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| AcegfError::Internal)?;
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let payload = Payload {
            msg: data,
            aad: Self::PROTOCOL_VERSION_AD,
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| AcegfError::Internal)?;
        ciphertext.try_into().map_err(|_| AcegfError::Internal)
    }

    fn decrypt_internal(
        sealed: &[u8; 32],
        key: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 16]>, AcegfError> {
        let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| AcegfError::Internal)?;
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let payload = Payload {
            msg: sealed,
            aad: Self::PROTOCOL_VERSION_AD,
        };
        let mut plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| AcegfError::InvalidPassphrase)?;
        if plaintext.len() != 16 {
            plaintext.zeroize();
            return Err(AcegfError::Internal);
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(Zeroizing::new(out))
    }

    pub fn seal_identity_material(
        material: &[u8; 16],
        passphrase: &[u8],
    ) -> Result<[u8; 32], AcegfError> {
        let base_key = Self::derive_base_key(passphrase)?;
        let key = Self::expand_key(&base_key, Self::SALT_SEALED)?;
        Self::encrypt_internal(material, &key)
    }

    pub fn unseal_identity_material(
        sealed: &[u8; 32],
        passphrase: &[u8],
    ) -> Result<Zeroizing<[u8; 16]>, AcegfError> {
        let base_key = Self::derive_base_key(passphrase)?;
        Self::unseal_identity_material_with_base_key(sealed, &base_key)
    }

    pub fn unseal_identity_material_with_base_key(
        sealed: &[u8; 32],
        base_key: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 16]>, AcegfError> {
        let key = Self::expand_key(base_key, Self::SALT_SEALED)?;
        Self::decrypt_internal(sealed, &key)
    }

    pub fn combine_passphrase(primary: &str, secondary: Option<&str>) -> String {
        match secondary {
            None => primary.to_string(),
            Some(s) => format!("{primary}\0{s}"),
        }
    }

    pub fn derive_kmaster_from_rev32(
        passphrase: &[u8],
        rev: &Rev32,
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let salt = AceRevGenerator::derive_salt(rev)?;
        let mut kmaster = [0u8; 32];
        Self::argon2_config()?
            .hash_password_into(passphrase, &salt, &mut kmaster)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(kmaster))
    }

    pub fn derive_kmaster_from_base_key_and_rev32(
        base_key: &[u8; 32],
        rev: &Rev32,
    ) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut kmaster = [0u8; 32];
        let hkdf = Hkdf::<Sha256>::new(Some(rev), base_key);
        hkdf.expand(Self::INFO_KMASTER_FROM_BASE_KEY, &mut kmaster)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(kmaster))
    }

    pub fn derive_identity_root(kmaster: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
        let mut root = [0u8; 32];
        let hkdf = Hkdf::<Sha256>::new(None, kmaster);
        hkdf.expand(Self::INFO_IDENTITY_ROOT, &mut root)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(Zeroizing::new(root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rev32() -> Rev32 {
        let mut rev = [0u8; 32];
        rev[28] = 0xA0;
        rev
    }

    #[test]
    fn test_base_key_deterministic() {
        let k1 = PassphraseSealingUtil::derive_base_key(b"test_password").unwrap();
        let k2 = PassphraseSealingUtil::derive_base_key(b"test_password").unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn test_combine_passphrase() {
        assert_eq!(PassphraseSealingUtil::combine_passphrase("a", None), "a");
        assert_eq!(
            PassphraseSealingUtil::combine_passphrase("a", Some("b")),
            "a\0b"
        );
    }

    #[test]
    fn test_kmaster_from_rev32_depends_on_passphrase() {
        let rev = sample_rev32();
        let k1 = PassphraseSealingUtil::derive_kmaster_from_rev32(b"pass1", &rev).unwrap();
        let k2 = PassphraseSealingUtil::derive_kmaster_from_rev32(b"pass2", &rev).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn test_kmaster_from_base_key_depends_on_rev32() {
        let base_key = PassphraseSealingUtil::derive_base_key(b"base").unwrap();
        let rev1 = sample_rev32();
        let mut rev2 = rev1;
        rev2[0] ^= 0x01;

        let k1 = PassphraseSealingUtil::derive_kmaster_from_base_key_and_rev32(&base_key, &rev1)
            .unwrap();
        let k2 = PassphraseSealingUtil::derive_kmaster_from_base_key_and_rev32(&base_key, &rev2)
            .unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn test_identity_root_deterministic() {
        let kmaster = [7u8; 32];
        let r1 = PassphraseSealingUtil::derive_identity_root(&kmaster).unwrap();
        let r2 = PassphraseSealingUtil::derive_identity_root(&kmaster).unwrap();
        assert_eq!(*r1, *r2);
    }
}
