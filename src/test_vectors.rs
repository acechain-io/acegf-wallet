//! Canonical ACE-GF test wallet (mnemonic + passphrase pair with published outputs).
//!
//! Unlike BIP39's `abandon...art` (entropy-only, no passphrase), ACE-GF mnemonics
//! encode sealed identity material and require both fields to recover keys.

#![allow(dead_code)]

/// BIP39 official 24-word test vector (256-bit all-zero entropy + checksum).
/// Use only for mnemonic **decode/format** checks — not a sealed ACE-GF wallet.
pub const BIP39_ZERO_ENTROPY_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/// 24-word mnemonic encoding the sealed REV32 blob (not BIP39 HD seed entropy).
pub const MNEMONIC: &str = "express number monitor cigar clown fat ethics emotion claw busy alien begin hotel scare avocado action alley lucky tunnel grape token aim usual increase";

/// Passphrase that seals/unseals [`MNEMONIC`].
pub const PASSPHRASE: &str = "1qazxsw2";

/// Permanent wallet fingerprint: `hex(SHA3-256(sealed || "acegf:xid"))`.
pub const XID: &str = "c156156bad7a61af1e478f72b06b89d60106669661318e6d8572cd7b2c6f63f0";

pub const EVM_ADDRESS: &str = "0xC01eBEC23B1846bf4Ad6E1C115C723Aad78E7fbF";
pub const SOLANA_ADDRESS: &str = "5V31DCoTPC9M4qx4qedTJYCUfJNtfAdWWJx5wmQBC4TL";
pub const BITCOIN_ADDRESS: &str = "bc1pmxf4qt9qevxss9uavu6g4tw9w5m3z5kq2evl0y66z5jusd56nn6s3hmghk";
pub const COSMOS_ADDRESS: &str = "cosmos1fn59gkjjsfssk44mxnqhgyxcmxyjkhn77htt4x";
pub const TRON_ADDRESS: &str = "TRn3s2MQ1zcjq6okELbGvpkUxBnKL7vzDd";
pub const POLKADOT_ADDRESS: &str = "14R3d5CkvAqpGBwapBxQn715aHofSH5M9rTKSZsknynCSfqE";

/// Base64-encoded X25519 identity public key (`x25519` field).
pub const X25519_B64: &str = "gLf/SYoOb5WarU8n+c06igQDMavLP1W6mjKvdEuOq0M=";

/// Default (empty-context) ML-DSA-44 public key, hex-encoded (1312 bytes).
pub const ML_DSA44_PK_HEX: &str = "9c64421f696d4d30ea8f6993d05ab3e1b5dbf6f7d3ab7e19c549b005b99736ca175869e304d3d98aca17ca1746e2aa74bb971c4342ed71c8c2ed327ce0d4685b0e877689bc15f160f3426aa6a0779f7deeb77622b7d810bb0e4d19c2314b84b8d280840068e1dbb8ec1a595cdca9672ae311b9c509bf7851c4c5ab3cbcca07ec0ed7ab59d78e982ee1db21875fb6062a63eab02b5216c73f0f913d23dd42a0e3c26236aa47aaf03df032810706909d4b4a656b4231c6624fd803e7c0e97270d12113b0484af2b3e159a070d056047d6b590c897217cc2440686658ccd4638117048f37d464b88e11ae56f2847d7862ef43dd2a77e8ca13cec2073a875fb36b4f18362c8a126150648717465743544612026d33e9d7419f5f637845c03555052d76ef5f66d9fe1628c427b5b2027f9f45e805ae866ef131ab29b0ae687fbba4d0c04b8eb2ff6b08438ed355af62ebe8c8ca4f8d60cb5e4b20fd4befc60e52bf125025a9f0ca1ed42acc46526c3a46061fc6f6c03c23f5bf629384389f9c76c1f0d373d7dd4f88d8b8df4edd5f9a77d3f79ab7b4145fe4a778c864c99430cae9302ceef22ae5d175ee92f11b5fd1177d82e7b57783511c847a3e6ae35e64c8c700dab57b69c66213432ba40b08856f04fdd71c1b3f0c6dcdeef82e507b8f732491729ae50c330270bf75f7e2f8684acc4bcc1f523c36f02672461e6066de60045179210868732c2e6218eac4b931e8497efe486cc3323cbbb702a60d4166f89a74c3b6c07bdee6a4ba25a0caba488e646539041c6301ecfc81a1e4ad940873cb6f8ef52b4a2b24cbb8ef86e417c5e2e9b4d369fae6712c08db552a3e97b1852b22c35e456f68841e3066adfe8da185ce5d73df2fb3df404bd42d6501d02caa7697e0c43af59e9a01b7f9f53c87bc53f8e93706b00a3574fdcc68ecd33ba0c172185533af3946b12867e842cfeb90ff4ab3d28989608a652df30868bf13b03b6ccbf8ea66d66547869a8056293ac36d4103d5036a466ebdf61b182fb2d2ac51c0e8b1144fb6e4758440e349bb4bfbc35d0751f8c3732c00895bd8fccb7983ec6941e034c6190b04616f4ab12c6fb3665d7480ba96d5eed3ad98309f657e050fa3f21f12c641f17fb33b248196624b14ad318d4ca9155dff5c43c5e445dafd4be4551ac894af83349b055d3e818f0aa95964f1fa0b076b75469d6183f8a08c5762126df3a4726dad6f0554b90e95a8d1ec19896391e4fd7664116d6cc724621021d48bca1d3da08cb37be15a33411f2457634b7abc96492b1a807b59613dc3bd8f361cae55d19975078f21b991a74f8e5210ecf0962eddcf2667dd822f2f0615023c7565d40ae920af5eb4c2340be13489c25c4f234845a66632edabc2cb59a5694762709888437b43c99d6610d0816887a9c6bdf497266a8c3b9f480d19f645900bcdfac97604388bc85c615ae7421b0f98fd072eac9553989535b6e2c5f696da29e4839122375a954e9e8c3892e1ca35918d25aa329cd3f9fc514a02b340091cdcfcb83f131f564db06e041754eb1a5df395e55072c5be38f97237bda01659631be9bff4155280518f1f3aa4adc7ef580c996f9919e92c1dcfd3f08f3702db4c0dc0c0b449a815c1c421164000c6147304aa83dcf9fcc07a2052ef27ccad6866e49681d7bb64de789bd61b4a011bc124e4d7420e66c03c3ef10604f798e3ac5e8a6e39a061f1f8f1b1708dc4b360fe516c85f1ae276396ac60def6e16ec30bf7f8d452e03b98738df740fe6ea419bb1934993d6d10019a21b5066740f7f4535a4d02a19eef84d4fde193f6840a24a2b90bef0bda94819bd8f475d4375446a827b5";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acegf_core::ACEGFCore;
    use crate::pqclean_ffi::MlDsa44;

    #[test]
    fn canonical_vectors_match_golden() {
        let entity = ACEGFCore::view_wallet_internal(MNEMONIC, PASSPHRASE, None)
            .expect("canonical test wallet must open");

        assert_eq!(entity.xid, XID);
        assert_eq!(entity.evm_address, EVM_ADDRESS);
        assert_eq!(entity.solana_address, SOLANA_ADDRESS);
        assert_eq!(entity.bitcoin_address, BITCOIN_ADDRESS);
        assert_eq!(entity.cosmos_address, COSMOS_ADDRESS);
        assert_eq!(entity.tron_address, TRON_ADDRESS);
        assert_eq!(entity.polkadot_address, POLKADOT_ADDRESS);
        assert_eq!(entity.x25519, X25519_B64);

        let mut seeds = ACEGFCore::unseal_to_seeds(MNEMONIC, PASSPHRASE, None)
            .expect("unseal canonical wallet");
        let (pk, _) = MlDsa44::keypair_from_seed(&*seeds.ml_dsa_44)
            .expect("default ML-DSA-44 key");
        ACEGFCore::clear_scheme_seeds(&mut seeds);
        assert_eq!(hex::encode(pk), ML_DSA44_PK_HEX);
    }

    /// Run with `--ignored --nocapture` when refreshing golden values after sealing changes.
    #[test]
    #[ignore = "manual: print golden values for test vector maintenance"]
    fn print_canonical_golden_values() {
        let entity = ACEGFCore::view_wallet_internal(MNEMONIC, PASSPHRASE, None).unwrap();
        println!("XID: {}", entity.xid);
        println!("EVM: {}", entity.evm_address);
        println!("SOLANA: {}", entity.solana_address);
        println!("BTC: {}", entity.bitcoin_address);
        println!("COSMOS: {}", entity.cosmos_address);
        println!("TRON: {}", entity.tron_address);
        println!("POLKADOT: {}", entity.polkadot_address);
        println!("X25519: {}", entity.x25519);

        let mut seeds = ACEGFCore::unseal_to_seeds(MNEMONIC, PASSPHRASE, None).unwrap();
        let (pk, _) = MlDsa44::keypair_from_seed(&*seeds.ml_dsa_44).unwrap();
        ACEGFCore::clear_scheme_seeds(&mut seeds);
        println!("ML_DSA44_PK_HEX: {}", hex::encode(pk));
    }
}
