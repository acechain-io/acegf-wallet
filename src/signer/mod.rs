// src/signer/mod.rs
//
// Signing modules for different blockchain networks.
// Each signer uses ACE-GF for key derivation and provides chain-specific transaction signing.

pub mod bitcoin_signer;
pub mod evm_signer;
pub mod ml_dsa44_signer;
pub mod solana_signer;
pub mod tron_signer;

pub use bitcoin_signer::BitcoinSigner;
pub use evm_signer::EvmSigner;
pub use ml_dsa44_signer::MlDsa44Signer;
pub use solana_signer::SolanaSigner;
pub use tron_signer::TronSigner;
