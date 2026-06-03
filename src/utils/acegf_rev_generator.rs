// src/utils/acegf_rev_generator.rs
//
// Minimal REV32 helpers for canonical ACE-GF flow.

use crate::acegf_structs::AcegfError;
use hkdf::Hkdf;
use sha2::Sha256;

/// 32-byte Root Entropy Value.
pub type Rev32 = [u8; 32];

/// REV format recognition result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevMode {
    /// Canonical REV32 format.
    Rev32,
    /// Unsupported/non-canonical bytes.
    Invalid,
}

/// Account type metadata (low 4 bits of byte 28).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AccountType {
    Standard = 0x00,
    MpcShard = 0x01,
    SocialRecovery = 0x02,
    HardwareBacked = 0x03,
    Reserved = 0x0F,
}

impl From<u8> for AccountType {
    fn from(v: u8) -> Self {
        match v & 0x0F {
            0x00 => AccountType::Standard,
            0x01 => AccountType::MpcShard,
            0x02 => AccountType::SocialRecovery,
            0x03 => AccountType::HardwareBacked,
            _ => AccountType::Reserved,
        }
    }
}

pub struct AceRevGenerator;

impl AceRevGenerator {
    // byte[28] high nibble must be 0xA for canonical REV32.
    const REV32_VERSION_NIBBLE: u8 = 0xA;
    const POS_VERSION_TYPE: usize = 28;
    const POS_RESERVED: usize = 31;

    const INFO_SALT: &'static [u8] = b"acegf:rev32:salt";
    const INFO_NONCE: &'static [u8] = b"acegf:rev32:nonce";

    /// Identify whether bytes match canonical REV32 format.
    pub fn identify(data: &Rev32) -> RevMode {
        let version_nibble = (data[Self::POS_VERSION_TYPE] >> 4) & 0x0F;
        if version_nibble == Self::REV32_VERSION_NIBBLE && data[Self::POS_RESERVED] == 0 {
            RevMode::Rev32
        } else {
            RevMode::Invalid
        }
    }

    #[inline]
    pub fn is_rev32(data: &Rev32) -> bool {
        matches!(Self::identify(data), RevMode::Rev32)
    }

    /// Derive Argon2 salt from REV32 by HKDF.
    pub fn derive_salt(rev: &Rev32) -> Result<[u8; 16], AcegfError> {
        let mut salt = [0u8; 16];
        let hkdf = Hkdf::<Sha256>::new(None, rev);
        hkdf.expand(Self::INFO_SALT, &mut salt)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(salt)
    }

    /// Derive nonce from Kmaster by HKDF.
    pub fn derive_nonce(kmaster: &[u8; 32]) -> Result<[u8; 12], AcegfError> {
        let mut nonce = [0u8; 12];
        let hkdf = Hkdf::<Sha256>::new(None, kmaster);
        hkdf.expand(Self::INFO_NONCE, &mut nonce)
            .map_err(|_| AcegfError::KdfError)?;
        Ok(nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_rev32_valid() {
        let mut rev = [0u8; 32];
        rev[28] = 0xA0;
        rev[31] = 0x00;
        assert_eq!(AceRevGenerator::identify(&rev), RevMode::Rev32);
        assert!(AceRevGenerator::is_rev32(&rev));
    }

    #[test]
    fn test_identify_rev32_invalid() {
        let rev = [0u8; 32];
        assert_eq!(AceRevGenerator::identify(&rev), RevMode::Invalid);
    }

    #[test]
    fn test_derive_salt_deterministic() {
        let mut rev = [0u8; 32];
        rev[28] = 0xA0;
        let s1 = AceRevGenerator::derive_salt(&rev).unwrap();
        let s2 = AceRevGenerator::derive_salt(&rev).unwrap();
        assert_eq!(s1, s2);
    }
}
