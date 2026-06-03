use acegf::acegf_core::ACEGFCore;
use base64ct::Encoding;
use sha3::Digest;

#[cfg(test)]
mod acegf_change_passphrase_tests {
    use super::*;

    #[test]
    fn test_change_passphrase_success() {
        let pass1 = "old-pass-123";
        let entity = ACEGFCore::generate_ace_internal(pass1, None).unwrap();
        let mnemonic = &entity.mnemonic;

        let pass2 = "new-pass-456";
        let new_mnemonic = ACEGFCore::change_passphrase_internal(mnemonic, pass1, pass2, None)
            .expect("Change passphrase failed");

        let restored_with_new =
            ACEGFCore::view_wallet_internal(&new_mnemonic, pass2, None).unwrap();
        assert_eq!(restored_with_new.evm_address, entity.evm_address);

        let restored_with_old = ACEGFCore::view_wallet_internal(&new_mnemonic, pass1, None);
        assert!(restored_with_old.is_err());
    }

    #[test]
    fn test_change_passphrase_invalid_old_pass() {
        let pass1 = "correct-pass";
        let entity = ACEGFCore::generate_ace_internal(pass1, None).unwrap();
        let mnemonic = &entity.mnemonic;

        let result =
            ACEGFCore::change_passphrase_internal(mnemonic, "wrong-pass", "new-pass", None);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod zeroize_tests {
    use acegf::acegf_core::ACEGFCore;
    use acegf::acegf_structs::SchemeSeeds;
    use zeroize::Zeroizing;

    #[test]
    fn test_clear_scheme_seeds() {
        let mut seeds = SchemeSeeds {
            ed25519_solana: Zeroizing::new([1u8; 32]),
            secp256k1_evm: Zeroizing::new([2u8; 32]),
            secp256k1_btc: Zeroizing::new([3u8; 32]),
            secp256k1_cosmos: Zeroizing::new([4u8; 32]),
            secp256k1_tron: Zeroizing::new([5u8; 32]),
            ed25519_polkadot: Zeroizing::new([5u8; 32]),
            x25519: Zeroizing::new([6u8; 32]),
            ml_dsa_44: Zeroizing::new([7u8; 32]),
            ml_kem_768: Zeroizing::new([8u8; 64]),
        };

        ACEGFCore::clear_scheme_seeds(&mut seeds);
        assert_eq!(*seeds.ed25519_solana, [0u8; 32]);
        assert_eq!(*seeds.secp256k1_evm, [0u8; 32]);
        assert_eq!(*seeds.x25519, [0u8; 32]);
        assert_eq!(*seeds.ml_kem_768, [0u8; 64]);
    }
}

#[cfg(test)]
mod acegf_core_derive_tests {
    use super::*;
    use acegf::acegf_core::ACEGFCore;
    use hex::encode;
    use sha3::Keccak256;
    use zeroize::Zeroizing;

    #[test]
    fn test_derive_evm_address() {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[0] = 1;
        let seed = Zeroizing::new(seed_bytes);

        let address = ACEGFCore::derive_evm_address(&seed).unwrap();

        assert!(address.starts_with("0x"), "EVM address must start with 0x");
        assert_eq!(address.len(), 42, "EVM address must be 42 chars (with 0x)");

        let raw_address = address.strip_prefix("0x").unwrap();
        let mut hasher = Keccak256::new();
        hasher.update(raw_address.to_lowercase().as_bytes());
        let hash = hasher.finalize();
        let hash_hex = encode(hash);

        for (i, c) in raw_address.chars().enumerate() {
            if c.is_numeric() {
                continue;
            }
            let hash_char = hash_hex.chars().nth(i).unwrap();
            let hash_val = u8::from_str_radix(&hash_char.to_string(), 16).unwrap();
            if hash_val >= 8 {
                assert!(
                    c.is_uppercase(),
                    "Char {} at position {} should be uppercase",
                    c,
                    i
                );
            } else {
                assert!(
                    c.is_lowercase(),
                    "Char {} at position {} should be lowercase",
                    c,
                    i
                );
            }
        }
    }

    #[test]
    fn test_derive_btc_taproot_address() {
        let seed_bytes = [1u8; 32];
        let seed = Zeroizing::new(seed_bytes);

        let address = ACEGFCore::derive_btc_taproot_address(&seed).unwrap();

        assert!(
            address.starts_with("bc1p"),
            "BTC Taproot address must start with bc1p"
        );
        assert!(
            address.len() >= 42 && address.len() <= 62,
            "Taproot address length abnormal"
        );
    }

    #[test]
    fn test_derive_x25519_public() {
        let mut seed_bytes = [2u8; 32];
        seed_bytes[0] &= 248;
        seed_bytes[31] &= 127;
        seed_bytes[31] |= 64;
        let seed = Zeroizing::new(seed_bytes);

        let pub_b64 = ACEGFCore::derive_x25519_public(&seed).unwrap();

        let pub_bytes = base64ct::Base64::decode_vec(&pub_b64).unwrap();
        assert_eq!(pub_bytes.len(), 32, "X25519 public key must be 32 bytes");
    }

    #[test]
    fn test_normalize_secp256k1_key() {
        let invalid_key = [0xFFu8; 32];
        let normalized = ACEGFCore::normalize_secp256k1_key(&invalid_key);
        assert_ne!(normalized, invalid_key);

        let valid_key = [1u8; 32];
        let normalized_valid = ACEGFCore::normalize_secp256k1_key(&valid_key);
        assert_eq!(normalized_valid, valid_key);
    }
}
