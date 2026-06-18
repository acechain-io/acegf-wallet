// src/lib.rs
pub mod acegf;
pub mod acegf_core;
pub mod acegf_structs;
pub mod hfi_pay;
pub mod pqclean_ffi;
pub mod session;
pub mod signer;
pub mod utils;
pub mod vadar;

/// Canonical mnemonic + passphrase test wallet and golden outputs.
pub mod test_vectors;

#[cfg(feature = "zk")]
pub mod zk;


#[cfg(not(target_arch = "wasm32"))]
pub mod ffi;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[cfg(all(target_arch = "wasm32", feature = "zk"))]
pub mod wasm_zk;

pub use acegf::{HybridEncryptedPayload, ACEGF};
pub use session::{EncryptedPayload, GeneratedWallet, Session, WalletPublicView};
pub use signer::MlDsa44Signer;
pub use vadar::VADAR;
