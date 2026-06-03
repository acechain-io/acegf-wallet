use acegf::utils::passphrase_sealing_util::PassphraseSealingUtil;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rev32() -> [u8; 32] {
        let mut rev = [0u8; 32];
        rev[28] = 0xA0;
        rev
    }

    #[test]
    fn test_kmaster_roundtrip_properties() {
        let rev = sample_rev32();
        let k1 =
            PassphraseSealingUtil::derive_kmaster_from_rev32(b"correct horse battery staple", &rev)
                .unwrap();
        let k2 =
            PassphraseSealingUtil::derive_kmaster_from_rev32(b"correct horse battery staple", &rev)
                .unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn test_kmaster_changes_with_wrong_passphrase() {
        let rev = sample_rev32();
        let k1 = PassphraseSealingUtil::derive_kmaster_from_rev32(b"pass-a", &rev).unwrap();
        let k2 = PassphraseSealingUtil::derive_kmaster_from_rev32(b"pass-b", &rev).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn test_kmaster_from_base_key_is_rev_bound() {
        let base_key = PassphraseSealingUtil::derive_base_key(b"prf-secret").unwrap();
        let rev1 = sample_rev32();
        let mut rev2 = rev1;
        rev2[0] = 1;

        let k1 = PassphraseSealingUtil::derive_kmaster_from_base_key_and_rev32(&base_key, &rev1)
            .unwrap();
        let k2 = PassphraseSealingUtil::derive_kmaster_from_base_key_and_rev32(&base_key, &rev2)
            .unwrap();
        assert_ne!(*k1, *k2);
    }
}
