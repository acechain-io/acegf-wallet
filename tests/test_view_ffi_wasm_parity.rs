//! Tests that the same mnemonic + passphrase produce identical addresses
//! whether called from Rust (core), FFI, or WASM.
//!
//! Run with: cargo test view_ffi_wasm_parity
//!
//! For WASM parity: build with wasm-pack, then run scripts/test_wasm_view.mjs
//! and compare addresses with this test's expected values.

use acegf::acegf_core::ACEGFCore;
use acegf::test_vectors::{EVM_ADDRESS, MNEMONIC, PASSPHRASE, SOLANA_ADDRESS};

#[test]
fn test_view_unified_24_word_matches_wasm_addresses() {
    let entity = ACEGFCore::view_wallet_unified(MNEMONIC, PASSPHRASE, None)
        .expect("view_wallet_unified should succeed for canonical test wallet");
    assert_eq!(
        entity.evm_address, EVM_ADDRESS,
        "EVM address should match canonical golden vector"
    );
    assert_eq!(
        entity.solana_address, SOLANA_ADDRESS,
        "Solana address should match canonical golden vector"
    );
}

#[test]
fn test_view_unified_deterministic() {
    let a = ACEGFCore::view_wallet_unified(MNEMONIC, PASSPHRASE, None).expect("first view");
    let b = ACEGFCore::view_wallet_unified(MNEMONIC, PASSPHRASE, None).expect("second view");
    assert_eq!(a.evm_address, b.evm_address);
    assert_eq!(a.solana_address, b.solana_address);
    assert_eq!(a.bitcoin_address, b.bitcoin_address);
    assert_eq!(a.cosmos_address, b.cosmos_address);
    assert_eq!(a.polkadot_address, b.polkadot_address);
}
