use std::error::Error;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::acegf::{HybridEncryptedPayload, ACEGF};
use crate::acegf_core::ACEGFCore;
use crate::acegf_structs::CryptoEntity;
use crate::utils::passphrase_sealing_util::PassphraseSealingUtil;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletPublicView {
    pub solana_address: String,
    pub evm_address: String,
    pub bitcoin_address: String,
    pub cosmos_address: String,
    pub polkadot_address: String,
    pub xaddress: String,
    pub x25519: String,
    /// Base64-encoded ML-KEM-768 encapsulation key (post-quantum KEM identity).
    pub xkem: String,
}

impl From<&CryptoEntity> for WalletPublicView {
    fn from(entity: &CryptoEntity) -> Self {
        Self {
            solana_address: entity.solana_address.clone(),
            evm_address: entity.evm_address.clone(),
            bitcoin_address: entity.bitcoin_address.clone(),
            cosmos_address: entity.cosmos_address.clone(),
            polkadot_address: entity.polkadot_address.clone(),
            xaddress: entity.xaddress.clone(),
            x25519: entity.x25519.clone(),
            xkem: entity.xkem.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeneratedWallet {
    pub mnemonic: String,
    pub wallet: WalletPublicView,
}

impl std::fmt::Debug for GeneratedWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedWallet")
            .field("mnemonic", &"<redacted>")
            .field("wallet", &self.wallet)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedPayload {
    pub ephemeral_pub_b64: String,
    pub encrypted_aes_key_b64: String,
    pub iv_b64: String,
    pub ciphertext: Vec<u8>,
}

pub struct Session {
    mnemonic: Zeroizing<String>,
    base_key: Zeroizing<[u8; 32]>,
    auth_signing_seed: Zeroizing<[u8; 32]>,
    auth_pubkey: [u8; 32],
    wallet: WalletPublicView,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("auth_pubkey", &hex::encode(self.auth_pubkey))
            .field("wallet", &self.wallet)
            .finish()
    }
}

impl Session {
    pub fn open(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<Self, Box<dyn Error>> {
        let full_passphrase = Zeroizing::new(PassphraseSealingUtil::combine_passphrase(
            passphrase,
            secondary_passphrase,
        ));
        let base_key = PassphraseSealingUtil::derive_base_key(full_passphrase.as_bytes())?;
        let wallet_entity = ACEGFCore::view_wallet_with_base_key(mnemonic, &base_key)?;
        let mut seeds = ACEGFCore::unseal_to_seeds_with_base_key(mnemonic, &base_key)?;

        let mut auth_signing_seed = [0u8; 32];
        auth_signing_seed.copy_from_slice(&*seeds.ed25519_solana);
        let auth_pubkey = SigningKey::from_bytes(&auth_signing_seed)
            .verifying_key()
            .to_bytes();

        ACEGFCore::clear_scheme_seeds(&mut seeds);

        Ok(Self {
            mnemonic: Zeroizing::new(mnemonic.to_owned()),
            base_key,
            auth_signing_seed: Zeroizing::new(auth_signing_seed),
            auth_pubkey,
            wallet: WalletPublicView::from(&wallet_entity),
        })
    }

    pub fn wallet(&self) -> &WalletPublicView {
        &self.wallet
    }

    pub fn x25519(&self) -> &str {
        &self.wallet.x25519
    }

    /// Base64-encoded ML-KEM-768 encapsulation key (post-quantum
    /// key-exchange identity). Parallel to `x25519()`.
    pub fn xkem(&self) -> &str {
        &self.wallet.xkem
    }

    pub fn auth_pubkey(&self) -> [u8; 32] {
        self.auth_pubkey
    }

    pub fn sign_message(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.auth_signing_seed)
            .sign(message)
            .to_bytes()
    }

    pub fn verify_message(auth_pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(auth_pubkey) else {
            return false;
        };
        let signature = Signature::from_bytes(signature);
        verifying_key.verify_strict(message, &signature).is_ok()
    }

    pub fn decrypt_payload(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, Box<dyn Error>> {
        ACEGF::decrypt_with_base_key(
            &self.mnemonic,
            &self.base_key,
            &payload.ephemeral_pub_b64,
            &payload.encrypted_aes_key_b64,
            &payload.iv_b64,
            &payload.ciphertext,
        )
    }

    pub fn encrypt_for_recipient(
        recipient_x25519_b64: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, Box<dyn Error>> {
        let (ephemeral_pub_b64, encrypted_aes_key_b64, iv_b64, ciphertext) =
            ACEGF::encrypt_for_x25519(recipient_x25519_b64, plaintext)?;
        Ok(EncryptedPayload {
            ephemeral_pub_b64,
            encrypted_aes_key_b64,
            iv_b64,
            ciphertext,
        })
    }

    /// Decrypt a [`HybridEncryptedPayload`] using the session's cached
    /// `base_key` (skips Argon2id). This is the **default** path going
    /// forward; [`Session::decrypt_payload`] remains available only for
    /// reading legacy X25519-only ciphertexts.
    pub fn decrypt_pq_payload(
        &self,
        payload: &HybridEncryptedPayload,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        ACEGF::decrypt_for_recipient_pq_with_base_key(&self.mnemonic, &self.base_key, payload)
    }

    /// Encapsulate + encrypt for a recipient identified by `(x25519, xkem)`
    /// using hybrid X25519 + ML-KEM-768. Static helper — no mnemonic needed
    /// on the sender side (randomness comes from the OS RNG). This is the
    /// **default** path for new code; [`Session::encrypt_for_recipient`]
    /// remains available only for interoperating with legacy peers.
    pub fn encrypt_for_recipient_pq(
        recipient_x25519_b64: &str,
        recipient_xkem_b64: &str,
        plaintext: &[u8],
    ) -> Result<HybridEncryptedPayload, Box<dyn Error>> {
        ACEGF::encrypt_for_recipient_pq(recipient_x25519_b64, recipient_xkem_b64, plaintext)
    }
}

impl ACEGF {
    pub fn generate_wallet(
        passphrase: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<GeneratedWallet, Box<dyn Error>> {
        let entity = ACEGFCore::generate_ace_internal(passphrase, secondary_passphrase)?;
        Ok(GeneratedWallet {
            mnemonic: entity.mnemonic.to_string(),
            wallet: WalletPublicView::from(&entity),
        })
    }

    pub fn view_wallet(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<WalletPublicView, Box<dyn Error>> {
        let entity = ACEGFCore::view_wallet_internal(mnemonic, passphrase, secondary_passphrase)?;
        Ok(WalletPublicView::from(&entity))
    }

    pub fn open_session(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
    ) -> Result<Session, Box<dyn Error>> {
        Session::open(mnemonic, passphrase, secondary_passphrase)
    }

    pub fn encrypt_payload_for_x25519(
        recipient_x25519_b64: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, Box<dyn Error>> {
        Session::encrypt_for_recipient(recipient_x25519_b64, plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_payload_roundtrip() {
        let wallet = ACEGF::generate_wallet("secret-passphrase", None).expect("wallet generation");
        let session = Session::open(&wallet.mnemonic, "secret-passphrase", None).unwrap();

        let envelope = Session::encrypt_for_recipient(session.x25519(), b"payload").unwrap();
        let plaintext = session.decrypt_payload(&envelope).unwrap();

        assert_eq!(plaintext, b"payload");
    }

    #[test]
    fn identity_signature_roundtrip() {
        let wallet = ACEGF::generate_wallet("signing-passphrase", None).expect("wallet generation");
        let session = Session::open(&wallet.mnemonic, "signing-passphrase", None).unwrap();
        let signature = session.sign_message(b"takeover");

        assert!(Session::verify_message(
            &session.auth_pubkey(),
            b"takeover",
            &signature
        ));
    }
}
