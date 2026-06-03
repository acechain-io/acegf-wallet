//! Tests that the same mnemonic + passphrase produce identical addresses
//! whether called from Rust (core), FFI, or WASM.
//!
//! Run with: cargo test view_ffi_wasm_parity
//!
//! For WASM parity: build with wasm-pack, then run scripts/test_wasm_view.mjs
//! and compare addresses with this test's expected values.

use acegf::acegf_core::ACEGFCore;

/// Fixed 24-word mnemonic + passphrase used in App and Extension.
/// Expected addresses (REV32 path) must match WASM/Extension output.
const MNEMONIC: &str = "awkward shift carpet hazard peasant embark total into whisper minimum knife coach cousin treat pledge company help oval thought exit play cheese rocket spatial";
const PASSPHRASE: &str = "1qazxsw2";

/// EVM address from Extension (WASM) for the above mnemonic+passphrase.
const EXPECTED_EVM: &str = "0x00e1304043f99B88F89e7f7a742dc0D66a1de17a";
/// Solana address from Extension (WASM).
const EXPECTED_SOLANA: &str = "CF92xnWNi6oAtTacEwPpxvoRGyCceK8NPmrjUaMTcoTe";

#[test]
fn test_view_unified_24_word_matches_wasm_addresses() {
    let entity = ACEGFCore::view_wallet_unified(MNEMONIC, PASSPHRASE, None)
        .expect("view_wallet_unified should succeed for 24-word + passphrase");
    assert_eq!(
        entity.evm_address, EXPECTED_EVM,
        "EVM address should match WASM (17a)"
    );
    assert_eq!(
        entity.solana_address, EXPECTED_SOLANA,
        "Solana address should match WASM"
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
