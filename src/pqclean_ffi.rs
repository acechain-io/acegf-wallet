// src/pqclean_ffi.rs
//
// Post-quantum primitives via pure-Rust FIPS crates:
//   * ML-DSA-44  (FIPS 204) — lattice-based digital signature
//   * ML-KEM-768 (FIPS 203) — lattice-based key encapsulation mechanism
//
// Works on ALL platforms: native (desktop/iOS/Android) and WASM (browser).
// No C compiler or PQClean build system required.

use zeroize::Zeroizing;

pub struct MlDsa44;

impl MlDsa44 {
    pub const PK_BYTES: usize = 1312;
    pub const SK_BYTES: usize = 2560; // fips204 expanded secret key size
    pub const SIG_BYTES: usize = 2420;
    pub const SEED_BYTES: usize = 32;

    /// Deterministic key generation from a 32-byte seed.
    /// Returns (public_key, secret_key) or an error.
    pub fn keypair_from_seed(
        seed: &[u8; 32],
    ) -> Result<([u8; Self::PK_BYTES], Zeroizing<[u8; Self::SK_BYTES]>), String> {
        use fips204::ml_dsa_44::KG;
        use fips204::traits::{KeyGen, SerDes};

        let (pk, sk) = KG::keygen_from_seed(seed);
        let pk_bytes = pk.into_bytes();
        let sk_bytes = Zeroizing::new(sk.into_bytes());
        Ok((pk_bytes, sk_bytes))
    }

    /// Sign a message with a secret key. Returns the signature bytes.
    pub fn sign(
        sk_bytes: &[u8; Self::SK_BYTES],
        message: &[u8],
    ) -> Result<[u8; Self::SIG_BYTES], String> {
        use fips204::ml_dsa_44;
        use fips204::traits::{SerDes, Signer};

        let sk = ml_dsa_44::PrivateKey::try_from_bytes(sk_bytes.clone())
            .map_err(|e| format!("Invalid ML-DSA-44 secret key: {e}"))?;
        sk.try_sign(message, &[])
            .map_err(|e| format!("ML-DSA-44 signing failed: {e}"))
    }

    /// Verify a signature against a public key and message.
    pub fn verify(
        pk_bytes: &[u8; Self::PK_BYTES],
        message: &[u8],
        sig_bytes: &[u8; Self::SIG_BYTES],
    ) -> Result<bool, String> {
        use fips204::ml_dsa_44;
        use fips204::traits::{SerDes, Verifier};

        let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_bytes.clone())
            .map_err(|e| format!("Invalid ML-DSA-44 public key: {e}"))?;
        Ok(pk.verify(message, sig_bytes, &[]))
    }
}

/// ML-KEM-768 (FIPS 203) — quantum-resistant Key Encapsulation Mechanism.
///
/// This is the NIST-standardized lattice-based KEM (formerly CRYSTALS-Kyber).
/// It is used for post-quantum key exchange: an originator derives a deterministic
/// (encaps, decaps) key pair from a 64-byte seed (`d || z`), publishes the
/// encapsulation key, and any party can encapsulate against it to obtain a
/// shared 32-byte secret + ciphertext. The originator recovers the same
/// shared secret by decapsulating the ciphertext with the decapsulation key.
pub struct MlKem768;

impl MlKem768 {
    /// Encapsulation key (public) size in bytes — FIPS 203, ML-KEM-768.
    pub const EK_BYTES: usize = 1184;
    /// Decapsulation key (secret) size in bytes — FIPS 203, ML-KEM-768.
    pub const DK_BYTES: usize = 2400;
    /// Ciphertext size in bytes — FIPS 203, ML-KEM-768.
    pub const CT_BYTES: usize = 1088;
    /// Shared-secret size in bytes.
    pub const SS_BYTES: usize = 32;
    /// Seed size in bytes. ML-KEM key generation consumes two 32-byte
    /// values (`d` and `z`) per FIPS 203; we concatenate them into a
    /// single 64-byte seed for deterministic derivation.
    pub const SEED_BYTES: usize = 64;

    /// Deterministic key generation from a 64-byte seed (`d || z`).
    /// Returns `(encaps_key_bytes, decaps_key_bytes)`.
    pub fn keypair_from_seed(
        seed: &[u8; Self::SEED_BYTES],
    ) -> Result<([u8; Self::EK_BYTES], Zeroizing<[u8; Self::DK_BYTES]>), String> {
        use fips203::ml_kem_768::KG;
        use fips203::traits::{KeyGen, SerDes};

        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&seed[0..32]);
        z.copy_from_slice(&seed[32..64]);

        let (ek, dk) = KG::keygen_from_seed(d, z);
        let ek_bytes = ek.into_bytes();
        let dk_bytes = Zeroizing::new(dk.into_bytes());
        Ok((ek_bytes, dk_bytes))
    }

    /// Encapsulate a shared secret against a remote encapsulation key.
    /// Uses the OS RNG; output is non-deterministic.
    /// Returns `(shared_secret, ciphertext)`.
    pub fn encapsulate(
        ek_bytes: &[u8; Self::EK_BYTES],
    ) -> Result<(Zeroizing<[u8; Self::SS_BYTES]>, [u8; Self::CT_BYTES]), String> {
        use fips203::ml_kem_768;
        use fips203::traits::{Encaps, SerDes};

        let ek = ml_kem_768::EncapsKey::try_from_bytes(*ek_bytes)
            .map_err(|e| format!("Invalid ML-KEM-768 encapsulation key: {e}"))?;
        let (ssk, ct) = ek
            .try_encaps()
            .map_err(|e| format!("ML-KEM-768 encapsulation failed: {e}"))?;
        Ok((Zeroizing::new(ssk.into_bytes()), ct.into_bytes()))
    }

    /// Deterministic encapsulation against a remote encapsulation key using a
    /// caller-supplied 32-byte seed. Given the same `(ek, seed)` pair, this
    /// always yields the same `(shared_secret, ciphertext)` — useful for
    /// reproducible KATs and session-level determinism.
    pub fn encapsulate_from_seed(
        ek_bytes: &[u8; Self::EK_BYTES],
        seed: &[u8; 32],
    ) -> Result<(Zeroizing<[u8; Self::SS_BYTES]>, [u8; Self::CT_BYTES]), String> {
        use fips203::ml_kem_768;
        use fips203::traits::{Encaps, SerDes};

        let ek = ml_kem_768::EncapsKey::try_from_bytes(*ek_bytes)
            .map_err(|e| format!("Invalid ML-KEM-768 encapsulation key: {e}"))?;
        let (ssk, ct) = ek.encaps_from_seed(seed);
        Ok((Zeroizing::new(ssk.into_bytes()), ct.into_bytes()))
    }

    /// Decapsulate a ciphertext using the local decapsulation key and recover
    /// the 32-byte shared secret.
    pub fn decapsulate(
        dk_bytes: &[u8; Self::DK_BYTES],
        ct_bytes: &[u8; Self::CT_BYTES],
    ) -> Result<Zeroizing<[u8; Self::SS_BYTES]>, String> {
        use fips203::ml_kem_768;
        use fips203::traits::{Decaps, SerDes};

        let dk = ml_kem_768::DecapsKey::try_from_bytes(*dk_bytes)
            .map_err(|e| format!("Invalid ML-KEM-768 decapsulation key: {e}"))?;
        let ct = ml_kem_768::CipherText::try_from_bytes(*ct_bytes)
            .map_err(|e| format!("Invalid ML-KEM-768 ciphertext: {e}"))?;
        let ssk = dk
            .try_decaps(&ct)
            .map_err(|e| format!("ML-KEM-768 decapsulation failed: {e}"))?;
        Ok(Zeroizing::new(ssk.into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_768_roundtrip_from_seed() {
        // Deterministic keygen from a fixed 64-byte seed must always
        // produce the same (ek, dk); encaps/decaps must agree on the
        // shared secret.
        let seed = [0xA5u8; 64];
        let (ek1, dk1) =
            MlKem768::keypair_from_seed(&seed).expect("keygen from seed should succeed");
        let (ek2, dk2) =
            MlKem768::keypair_from_seed(&seed).expect("keygen from seed should succeed");
        assert_eq!(ek1, ek2, "deterministic keygen: ek must match");
        assert_eq!(&*dk1, &*dk2, "deterministic keygen: dk must match");
        assert_eq!(ek1.len(), MlKem768::EK_BYTES);
        assert_eq!(dk1.len(), MlKem768::DK_BYTES);

        let (ss_enc, ct) =
            MlKem768::encapsulate(&ek1).expect("encapsulation should succeed");
        assert_eq!(ct.len(), MlKem768::CT_BYTES);
        assert_eq!(ss_enc.len(), MlKem768::SS_BYTES);

        let ss_dec =
            MlKem768::decapsulate(&dk1, &ct).expect("decapsulation should succeed");
        assert_eq!(
            &*ss_enc, &*ss_dec,
            "sender and recipient must agree on shared secret"
        );
    }

    #[test]
    fn ml_kem_768_different_seeds_yield_different_keys() {
        let seed_a = [0x11u8; 64];
        let seed_b = [0x22u8; 64];
        let (ek_a, _) = MlKem768::keypair_from_seed(&seed_a).unwrap();
        let (ek_b, _) = MlKem768::keypair_from_seed(&seed_b).unwrap();
        assert_ne!(ek_a, ek_b);
    }

    #[test]
    fn ml_kem_768_encaps_from_seed_is_deterministic() {
        // Given a fixed encapsulation key and a fixed 32-byte encaps seed,
        // encaps_from_seed must always yield the same (ss, ct).
        let kem_seed = [0x33u8; 64];
        let (ek, dk) = MlKem768::keypair_from_seed(&kem_seed).unwrap();
        let encaps_seed = [0x77u8; 32];

        let (ss1, ct1) = MlKem768::encapsulate_from_seed(&ek, &encaps_seed).unwrap();
        let (ss2, ct2) = MlKem768::encapsulate_from_seed(&ek, &encaps_seed).unwrap();
        assert_eq!(ct1, ct2);
        assert_eq!(&*ss1, &*ss2);

        // Decapsulation still recovers the same shared secret.
        let ss_dec = MlKem768::decapsulate(&dk, &ct1).unwrap();
        assert_eq!(&*ss_dec, &*ss1);
    }

    #[test]
    fn ml_kem_768_wrong_dk_yields_different_secret() {
        // ML-KEM has implicit rejection: decapsulating with the wrong dk
        // still returns 32 bytes, but they will not match the sender's
        // shared secret.
        let (ek_a, _dk_a) = MlKem768::keypair_from_seed(&[0x01u8; 64]).unwrap();
        let (_ek_b, dk_b) = MlKem768::keypair_from_seed(&[0x02u8; 64]).unwrap();
        let (ss_sender, ct) = MlKem768::encapsulate(&ek_a).unwrap();
        let ss_wrong = MlKem768::decapsulate(&dk_b, &ct).unwrap();
        assert_ne!(&*ss_sender, &*ss_wrong);
    }
}
