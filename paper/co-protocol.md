# Co-Protocol: Bridging the On-Chain and Off-Chain Halves of Account Abstraction through ACE-GF and EIP-8141 Integration

**Authors:** Hayekw
**Date:** February 2026
**Version:** 1.0

---

## Abstract

Account abstraction has been a central pursuit in Ethereum's roadmap since its inception, yet existing proposals address only one half of the problem. On-chain protocols such as ERC-4337 and the enshrined EIP-8141 (Frame Transactions) provide programmable validation and gas abstraction at the protocol layer but remain agnostic to how keys are generated, managed, and migrated on the client side. Conversely, client-side key management frameworks like ACE-GF (Atomic Cryptographic Entity Generative Framework) provide deterministic multi-chain key derivation, zero-plaintext memory security, and post-quantum readiness but cannot leverage protocol-level account abstraction capabilities through standard EOA transactions alone.

This paper introduces the **Co-Protocol architecture**, a design pattern in which ACE-GF and EIP-8141 operate as peer protocols sharing a common identity root. We demonstrate that their integration produces **four emergent capabilities** that neither system can achieve independently: (1) seamless post-quantum signature migration, (2) unlinkable institutional paymaster networks, (3) zero-knowledge cross-chain identity attestation, and (4) end-to-end private transactions with client-side zero-plaintext guarantees. We formalize each capability, provide construction details grounded in ACE-GF's implemented cryptographic primitives, and analyze the security properties of the combined system. We further generalize the co-protocol as a pattern *(OffChainKM, OnChainAA, SharedRoot, Interface)* and evaluate its instantiation across Solana, Bitcoin, Cosmos, and Polkadot, demonstrating that Ethereum + EIP-8141 provides the most complete capability coverage (4/4) while other chains achieve partial but valuable instantiations.

**Keywords:** account abstraction, multi-chain key derivation, post-quantum cryptography, frame transactions, HKDF, ML-DSA-44, zero-knowledge proofs, paymaster, privacy, co-protocol pattern, cross-chain identity

---

## 1. Introduction

### 1.1 The Two Halves of Account Abstraction

Account abstraction, broadly construed, encompasses the transformation of blockchain accounts from rigid cryptographic endpoints into programmable entities. The Ethereum community has pursued this goal through multiple proposals: EIP-86 [1], EIP-2938 [2], ERC-4337 [3], RIP-7560 [4], and most recently EIP-8141 (Frame Transactions) [5]. These proposals focus on the **on-chain half**---enabling smart contracts to define custom validation logic, abstracting gas payment, and supporting diverse signature schemes at the protocol level.

However, the **off-chain half**---the question of how cryptographic keys are generated, derived, stored, protected in memory, and migrated across signature schemes---has received comparatively little attention in the formal account abstraction literature. This asymmetry creates a significant gap: even with perfect on-chain account abstraction, a wallet that stores keys insecurely, cannot derive addresses deterministically across chains, or has no migration path to post-quantum signatures remains fundamentally limited.

ACE-GF (Atomic Cryptographic Entity Generative Framework) addresses the off-chain half. Its core is a deterministic, multi-scheme, chain-isolated key derivation architecture that produces seven independent cryptographic key streams from a single mnemonic, supports context-isolated institutional vaults, provides zero-plaintext memory security through Argon2id key stretching and `Zeroizing` memory wrappers, and includes ML-DSA-44 post-quantum key derivation.

### 1.2 The Co-Protocol Thesis

We argue that the optimal integration of ACE-GF and EIP-8141 is neither hierarchical (one as "base layer" for the other) nor loosely coupled (independent tools that happen to coexist). Instead, we propose a **co-protocol** relationship: two protocols that share a common cryptographic identity root and operate in complementary domains---ACE-GF governs the off-chain lifecycle (key generation, derivation, storage, migration), while EIP-8141 governs the on-chain lifecycle (validation, gas abstraction, execution). The shared identity root ensures cryptographic coherence between the two domains.

### 1.3 Contributions

This paper makes the following contributions:

1. **Formalization of the Co-Protocol architecture** connecting ACE-GF's HKDF-based key derivation hierarchy with EIP-8141's frame transaction model.

2. **Four emergent capability constructions:**
   - **Dual-Track Validation**: A phased post-quantum migration path where the same mnemonic supports ECDSA, hybrid, and pure ML-DSA-44 modes, with EIP-8141 validation frames verifying the appropriate scheme at each phase.
   - **Unlinkable Institutional Paymaster Networks**: Context-isolated vaults derived from ACE-GF serving as paymaster relationships within EIP-8141 frame transactions, achieving organizational gas management without on-chain address linkability.
   - **Zero-Knowledge Cross-Chain Identity Attestation**: Leveraging ACE-GF's deterministic multi-chain derivation as a ZK-SNARK witness to prove same-origin ownership across multiple chains without revealing the identity root. A two-chain reference instantiation (Ethereum + Solana, ~700K constraints) is fully specified; extensions to Bitcoin and Cosmos are sketched with marginal cost estimates.
   - **End-to-End Private Transactions**: Combining EIP-8141's ZK-SNARK paymaster capability with ACE-GF's zero-plaintext memory model and X25519 end-to-end encryption for full-stack transaction privacy.

3. **Security analysis** of the combined system against an adversary model spanning on-chain analysis, mempool observation, client-side memory attacks, and quantum key recovery.

4. **Generalization** of the co-protocol as a formal pattern *(OffChainKM, OnChainAA, SharedRoot, Interface)*, with capability coverage analysis across five blockchain ecosystems (Ethereum, Solana, Bitcoin, Cosmos, Polkadot), identifying a fundamental asymmetry: the off-chain half is chain-invariant while the on-chain half varies per chain.

---

## 2. Background

### 2.1 EIP-8141: Frame Transactions

EIP-8141, proposed by Vitalik Buterin et al., introduces **frame transactions** as an enshrined account abstraction mechanism. Unlike ERC-4337's off-protocol approach using UserOperations and a shared EntryPoint contract, EIP-8141 operates at the protocol level with first-class support in the execution layer.

**Core Concepts:**

A frame transaction (EIP-2718 type `0x06`) consists of an ordered sequence of **frames**, each a tuple `[mode, target, gas_limit, data]` representing an independent step within a single atomic transaction. The key innovation is the **APPROVE opcode**, which allows a frame's code to explicitly signal authorization---for sending, gas payment, or both---after executing arbitrary verification logic.

The transaction payload is the RLP serialization of:
```
[chain_id, nonce, sender, frames, max_priority_fee_per_gas, max_fee_per_gas,
 max_fee_per_blob_gas, blob_versioned_hashes]
```

Frames operate in two modes:

- **VERIFY mode**: Read-only execution (equivalent to `STATICCALL` semantics). Must call `APPROVE` to signal success. Frame data in VERIFY mode is elided from the signature hash and from introspection by other frames, preventing validation secret leakage.
- **ENTRY_POINT mode**: Standard execution for the transaction's actual operations.

The `APPROVE` opcode accepts an argument specifying what is being approved:
- `APPROVE(0x0)`: Sets `sender_approved = true` (sender authorization only).
- `APPROVE(0x1)`: Sets `payer_approved = true` (gas payment authorization only).
- `APPROVE(0x2)`: Sets both `sender_approved` and `payer_approved` (self-paying sender).

A typical multi-frame flow:
- **Frame 0 (VERIFY)**: Sender's smart contract verifies the signature and calls `APPROVE(0x2)` or `APPROVE(0x0)`.
- **Frame 1 (VERIFY, optional)**: Paymaster verifies fee conditions and calls `APPROVE(0x1)`.
- **Frame 2+ (ENTRY_POINT)**: Execution calls (token transfers, swaps, fee settlement, etc.).

**Key Properties:**

1. **No intermediaries**: Unlike ERC-4337, which requires bundlers to package UserOperations, frame transactions are self-contained and can be submitted directly to the mempool. As Buterin stated: "'First-class citizen' means that operations sent from that account can be included directly onchain as transactions, with no wrappers."
2. **Programmable validation**: Any signature scheme (ECDSA, Ed25519, Schnorr, BLS, ML-DSA, passkeys) can be verified in the validation frame's smart contract code.
3. **Gas abstraction**: Paymasters can pay gas in any token, and the settlement occurs within the same atomic transaction.
4. **Privacy potential**: ZK-SNARK paymasters can prove authorization without revealing the sender's identity, and 2D nonces (key, sequence pairs) enable concurrent transactions from the same account, critical for privacy protocol multi-tenant models.
5. **FOCIL synergy**: Fork-Choice Enforced Inclusion Lists (FOCIL, EIP-7805) guarantee that any of 17 randomly selected actors per slot (1 proposer + 16 IL committee members) can force transaction inclusion, even under adversarial conditions.

**Mempool Safety:**

EIP-8141 inherits mempool safety rules from ERC-7562, defining storage access restrictions for VERIFY-mode frames to prevent denial-of-service attacks. Validation code may only access storage "associated" with the sender address (calculated as `keccak(address || x) + n` where n is in range 0..128). Environment-dependent opcodes (`BLOCKHASH`, `TIMESTAMP`, `NUMBER`, etc.) are banned during validation to prevent off-chain-valid/on-chain-invalid divergences. Additional new opcodes---`TXPARAMLOAD` (0xb0), `TXPARAMSIZE` (0xb1), `TXPARAMCOPY` (0xb2)---enable validation frames to inspect transaction parameters efficiently.

**Timeline:** EIP-8141 is positioned as the execution-layer headliner for Ethereum's Hegota hard fork (H2 2026), alongside FOCIL (EIP-7805) as the consensus-layer headliner.

### 2.2 ACE-GF: Atomic Cryptographic Entity Generative Framework

ACE-GF is a client-side cryptographic framework implemented in Rust that provides deterministic multi-chain key derivation, zero-plaintext memory security, and post-quantum readiness. Its core technical components are:

#### 2.2.1 Key Derivation Architecture

ACE-GF's key derivation is built on HKDF-SHA256 [RFC 5869] with domain-separated info strings. From a single root entropy value, seven independent key streams are derived:

```
Root Entropy (UUID-16B or REV32-32B)
    │
    ├─→ HKDF(root, "ACEGF-V1-ED25519-SOLANA")      → Ed25519 seed → Solana address
    ├─→ HKDF(root, "ACEGF-V1-SECP256K1-EVM")        → secp256k1 seed → EVM address
    ├─→ HKDF(root, "ACEGF-V1-SECP256K1-BTC")        → secp256k1 seed → Bitcoin P2TR address
    ├─→ HKDF(root, "ACEGF-V1-SECP256K1-COSMOS")     → secp256k1 seed → Cosmos address
    ├─→ HKDF(root, "ACEGF-V1-ED25519-POLKADOT")     → Ed25519 seed → Polkadot SS58 address
    ├─→ HKDF(root, "ACEGF-V1-X25519-IDENTITY")      → X25519 static secret → identity key
    └─→ HKDF(root, "ACEGF-V1-ML-DSA-44-PQC-IDENTITY") → ML-DSA-44 seed → PQC keypair
```

The domain separation in the HKDF info strings ensures that compromise of one key stream does not affect others (chain isolation property).

#### 2.2.2 REV32 Format and Account Types

The REV32 (Root Entropy Value, 32 bytes) format extends the original UUID-based approach with higher entropy (224 bits vs. UUID's ~122 bits) and structured metadata:

```
rev[0..28]  = 224 bits of entropy
rev[28]     = VERSION (high nibble, 0xA = V1) | TYPE (low nibble)
rev[29]     = PROFILE (Default, EvmOnly, BitcoinOnly, SolanaOnly, Custom)
rev[30]     = FLAGS (IMPORTED_LEGACY, VADAR_ENABLED, TESTNET, BIP39_PASSPHRASE)
rev[31]     = RESERVED
```

Account types include: `Standard` (0x00), `MpcShard` (0x01), `SocialRecovery` (0x02), `HardwareBacked` (0x03), and `LegacyImport` (0x0F).

**Notation convention.** ACE-GF supports two IKM modes: legacy UUID (16 bytes, info strings prefixed `ACEGF-V1-`) and REV32 (32-byte `identity_root`, info strings prefixed `ACEGF-REV32-V1-`). Context-isolated derivation is available in REV32 mode only. All constructions in Sections 3--7 of this paper use REV32 mode and `ACEGF-REV32-V1-*` info strings; the legacy `ACEGF-V1-*` strings are retained in Section 2.2.1 and Appendix A for completeness.

#### 2.2.3 Context-Isolated Key Derivation

For institutional use cases, ACE-GF supports **context isolation**: appending an arbitrary context string to each HKDF info label produces a cryptographically independent set of addresses from the same root:

```
HKDF(identity_root, "ACEGF-REV32-V1-SECP256K1-EVM")                    → default EVM address
HKDF(identity_root, "ACEGF-REV32-V1-SECP256K1-EVM:corp:Treasury:0")    → Treasury vault address
HKDF(identity_root, "ACEGF-REV32-V1-SECP256K1-EVM:corp:Operations:0")  → Operations vault address
```

When the context is empty, the output is identical to the default derivation (backward compatibility). When non-empty, the context bytes are appended after a `:` separator, producing independent output per the HKDF security model.

#### 2.2.4 Zero-Plaintext Memory Security

ACE-GF's passphrase sealing uses a two-layer encryption model:

1. **Argon2id KDF** (m=4MB, t=3, p=1) derives a 32-byte base key from the user's passphrase.
2. **HKDF expansion** with domain-separated salts (`ACEGF-KDF-NATIVE-V1`, `ACEGF-KDF-LEGACY-V1`) produces encryption keys.
3. **AES-256-GCM-SIV** encrypts the root entropy with protocol version as associated authenticated data (AAD).
4. The encrypted root is encoded as a BIP39 mnemonic (the mnemonic itself is ciphertext, not plaintext entropy).
5. All sensitive buffers use Rust's `Zeroizing<[u8; 32]>` wrapper for deterministic memory clearing.

For REV32 mode, the passphrase participates in key derivation rather than sealing:

```
salt = HKDF(REV32, "acegf:rev32:salt")
Kmaster = Argon2id(passphrase, salt)
identity_root = HKDF(Kmaster, "acegf:identity:root")
```

This ensures that a wrong passphrase produces a completely different (but valid-looking) wallet, providing plausible deniability.

#### 2.2.5 VA-DAR: Vendor-Agnostic Deterministic Artifact Resolution

VA-DAR provides a discovery-and-recovery layer with per-identity key isolation:

```
Kmaster = Argon2id(password, "ACEGF-VADAR-V1:" || normalized_email)
    ├─→ Ksa  = HKDF(Kmaster, "acegf:sa2:seal")          → SA2 artifact sealing
    ├─→ Kidx = HKDF(Kmaster, "va-dar:discovery:index")   → DiscoveryID computation
    └─→ Kreg = HKDF(Kmaster, "va-dar:registry:auth")     → Registry authorization (Ed25519)
```

#### 2.2.6 Transaction Signing

ACE-GF implements native transaction signing for multiple chains:

- **EVM**: Legacy (Type 0, EIP-155) and EIP-1559 (Type 2) transactions, EIP-191 personal messages, EIP-712 typed data
- **Solana**: Ed25519 raw signature
- **Bitcoin**: secp256k1 signed messages
- **Cosmos**: Amino and EIP-712 Cosmos signing
- **Post-Quantum**: ML-DSA-44 raw signature (via PQClean FFI on native, placeholder on WASM)

### 2.3 Why Neither Alone Suffices

**EIP-8141 alone** can verify any signature scheme in its validation frame, but:
- It does not specify how keys are generated, stored, or migrated
- It cannot ensure cross-chain address derivation consistency
- It provides no client-side memory protection
- It has no mechanism for deterministic multi-chain recovery from a single seed

**ACE-GF alone** can derive keys for any chain, but:
- On Ethereum, it can only produce standard EOA transactions (ECDSA-only)
- It cannot leverage programmable validation (e.g., ML-DSA-44 verification on-chain)
- It cannot abstract gas payment
- It cannot participate in privacy-preserving paymaster schemes

The co-protocol architecture fills both gaps simultaneously.

---

## 3. Co-Protocol Architecture

### 3.1 Design Principles

1. **Shared Identity Root**: Both protocols reference the same `identity_root` derived from ACE-GF's mnemonic. This creates cryptographic coherence---the key that ACE-GF uses to sign is the key that EIP-8141's validation frame expects to verify.

2. **Domain Sovereignty**: Each protocol governs its own domain exclusively. ACE-GF never makes on-chain assertions; EIP-8141 never manages client-side key material. The interface is a well-defined set of signatures and public keys.

3. **Graceful Independence**: Each protocol can operate without the other. ACE-GF produces valid EOA transactions when EIP-8141 is unavailable. EIP-8141 accepts signatures from any key management system. The co-protocol capabilities are additive.

4. **No New Trusted Parties**: The co-protocol introduces no bundlers, relayers, or other intermediaries beyond what each protocol requires independently.

### 3.2 Architectural Overview

```
                        ┌──────────────────────────┐
                        │     User (Single Seed)    │
                        └────────────┬─────────────┘
                                     │
                        ┌────────────▼─────────────┐
                        │    ACE-GF Identity Root    │
                        │  HKDF(Kmaster, "acegf:    │
                        │   identity:root")          │
                        └────────────┬─────────────┘
                                     │
            ┌────────────────────────┼────────────────────────┐
            │                        │                        │
  ┌─────────▼──────────┐  ┌─────────▼──────────┐  ┌─────────▼──────────┐
  │  Classical Keys     │  │  Identity Keys     │  │  Post-Quantum Keys │
  │  secp256k1 (EVM)   │  │  X25519            │  │  ML-DSA-44         │
  │  secp256k1 (BTC)   │  │  (cross-chain      │  │  (future-proof     │
  │  Ed25519 (Solana)  │  │   anchor)           │  │   signature)       │
  │  Ed25519 (DOT)     │  │                     │  │                    │
  │  secp256k1 (ATOM)  │  │                     │  │                    │
  └─────────┬──────────┘  └─────────┬──────────┘  └─────────┬──────────┘
            │                        │                        │
            │        OFF-CHAIN (ACE-GF domain)               │
  ══════════╪════════════════════════╪════════════════════════╪══════════
            │        ON-CHAIN (EIP-8141 domain)              │
            │                        │                        │
  ┌─────────▼────────────────────────▼────────────────────────▼─────────┐
  │                    EIP-8141 Frame Transaction                       │
  │  ┌────────────┐  ┌────────────┐  ┌────────────────────────────┐   │
  │  │ Validation  │  │ Paymaster  │  │ Execution Frames           │   │
  │  │ Frame       │  │ Frame      │  │ (transfers, swaps, etc.)   │   │
  │  │             │  │            │  │                            │   │
  │  │ verify(sig) │  │ check fee  │  │                            │   │
  │  │ → APPROVE   │  │ → APPROVE  │  │                            │   │
  │  └────────────┘  └────────────┘  └────────────────────────────┘   │
  └────────────────────────────────────────────────────────────────────┘
```

### 3.3 Interface Specification

The interface between the two protocols consists of exactly three data types:

1. **Public Key**: ACE-GF derives and exports public keys; EIP-8141 validation frames store and verify against them.
2. **Signature**: ACE-GF produces signatures over transaction data; EIP-8141 validation frames consume and verify them.
3. **Address**: ACE-GF derives addresses deterministically; EIP-8141 uses them as account identifiers.

No other data crosses the boundary. In particular, private keys, mnemonics, passphrases, and derivation paths never leave ACE-GF's domain.

---

## 4. Emergent Capability 1: Dual-Track Post-Quantum Migration

### 4.1 Problem Statement

The transition from classical (ECDSA/secp256k1) to post-quantum (ML-DSA-44) signatures cannot happen atomically. During the transition period:
- Users need both classical and PQC signatures available
- Wallet infrastructure varies in PQC support (native vs. WASM vs. hardware)
- On-chain verifiers must support both schemes without security degradation
- The migration must not require users to manage multiple seed phrases

### 4.2 Why Neither System Alone Suffices

**EIP-8141 alone**: The validation frame can verify ML-DSA-44 signatures (it can run arbitrary verification code), but how does the user generate and manage ML-DSA-44 keys? Each user would need a separate key management process for PQC keys, with no guaranteed relationship to their existing classical keys.

**ACE-GF alone**: It derives ML-DSA-44 keys from the same root (`HKDF(root, "ACEGF-REV32-V1-ML-DSA-44-PQC-IDENTITY")`), but current Ethereum only accepts ECDSA signatures for EOA transactions. The PQC key exists but cannot be used for on-chain authorization.

### 4.3 Construction

The co-protocol enables a three-phase migration where the user's mnemonic remains constant throughout:

**Phase 1 --- Classical (Current State):**

```
Client (ACE-GF):
  identity_root → HKDF("ACEGF-REV32-V1-SECP256K1-EVM") → secp256k1 key → ECDSA signature

On-chain (EIP-8141 Validation Frame):
  function validate(bytes calldata sig) {
      require(ecrecover(txHash, sig) == owner);
      APPROVE(0x2);  // sender + gas
  }
```

**Phase 2 --- Hybrid (Transition Period):**

```
Client (ACE-GF):
  identity_root → HKDF("ACEGF-REV32-V1-SECP256K1-EVM")        → ECDSA signature
  identity_root → HKDF("ACEGF-REV32-V1-ML-DSA-44-PQC-IDENTITY") → ML-DSA-44 signature
  Combined signature = ecdsa_sig || mldsa_sig

On-chain (EIP-8141 Validation Frame):
  function validate(bytes calldata combinedSig) {
      (bytes memory ecdsaSig, bytes memory mldsaSig) = split(combinedSig);
      require(ecrecover(txHash, ecdsaSig) == classicalOwner);
      require(mlDsa44Verify(txHash, mldsaSig, pqcOwner));
      APPROVE(0x2);  // sender + gas
  }
```

Both signatures must be valid. This provides "belt and suspenders" security: even if ECDSA is broken by a quantum computer, the ML-DSA-44 signature remains secure. Even if ML-DSA-44 has an undiscovered flaw, the ECDSA signature provides classical security.

**Phase 3 --- Pure PQC (Post-Migration):**

```
Client (ACE-GF):
  identity_root → HKDF("ACEGF-REV32-V1-ML-DSA-44-PQC-IDENTITY") → ML-DSA-44 signature only

On-chain (EIP-8141 Validation Frame):
  function validate(bytes calldata sig) {
      require(mlDsa44Verify(txHash, sig, pqcOwner));
      APPROVE(0x2);  // sender + gas
  }
```

The classical key is decommissioned. The account address remains the same (it's the contract address, not derived from the signing key).

### 4.4 Migration Protocol

The phase transition is executed via a governance transaction within the validation frame:

```
// Phase transition: Classical → Hybrid
Frame 0 (VERIFY): Sign with current ECDSA key → APPROVE(0x2)
Frame 1 (ENTRY_POINT): Call account.setValidationMode(HYBRID, mlDsaPubkey)

// Phase transition: Hybrid → PQC-Only
Frame 0 (VERIFY): Sign with both ECDSA + ML-DSA-44 → APPROVE(0x2)
Frame 1 (ENTRY_POINT): Call account.setValidationMode(PQC_ONLY)
Frame 2 (ENTRY_POINT): Call account.decommissionClassicalKey()
```

### 4.5 ACE-GF Properties Enabling This Construction

1. **Same mnemonic throughout**: The user never needs a new seed phrase. Both `secp256k1` and `ML-DSA-44` keys derive from the same `identity_root`.
2. **Deterministic re-derivation**: If the user loses their device, they can re-derive both key types from their mnemonic + passphrase on any ACE-GF compatible client.
3. **Platform-adaptive PQC**: ACE-GF's `pqclean_ffi.rs` uses PQClean C library on native platforms and provides a stub on WASM. During Phase 2, the user can sign the ML-DSA-44 component on their mobile device (native) while the ECDSA component comes from a browser extension (WASM). The EIP-8141 validation frame accepts both in a single transaction.
4. **Zero-plaintext during signing**: Both key derivations occur within ACE-GF's `Zeroizing<[u8; 32]>` wrappers. The `clear_scheme_seeds()` function zeroes all seven key streams immediately after signing.

### 4.6 Security Analysis

**Claim 1 (Phase-2 Security).** During the hybrid phase, the adversary must break *both* secp256k1 ECDSA and ML-DSA-44 to forge a valid signature. The combined security level is min(128, 128) = 128 bits under the assumption that both schemes have independent security foundations (discrete log vs. Module-LWE).

**Argument.** The validation frame performs an AND check: both `ecrecover` and `mlDsa44Verify` must succeed. An adversary who can forge ECDSA (via quantum computer) still cannot forge ML-DSA-44 (assumed quantum-resistant). An adversary who finds a flaw in ML-DSA-44 still cannot forge ECDSA (assumed classically secure). This argument assumes the two schemes do not share a common algebraic weakness; a formal reduction to the independent hardness of ECDLP and Module-LWE is left to future work. ∎

**Rollback resistance.** The phase transitions are on-chain state changes protected by the current validation mode. An adversary cannot force a rollback from Hybrid to Classical without a valid hybrid signature.

---

## 5. Emergent Capability 2: Unlinkable Institutional Paymaster Networks

### 5.1 Problem Statement

Institutions (exchanges, asset managers, DAOs) operate multiple purpose-specific wallets: treasury, operations, escrow, petty cash. These wallets need:
- **Unified gas management**: A master treasury pays gas for all operational wallets
- **On-chain unlinkability**: External observers should not be able to determine that these wallets belong to the same entity
- **Policy enforcement**: Per-vault gas budgets, transaction limits, and approval workflows
- **Single-seed recovery**: Disaster recovery should require only one mnemonic

### 5.2 Why Neither System Alone Suffices

**EIP-8141 alone**: Paymaster frames provide gas abstraction, but if all vaults are derived from the same key manager using a standard HD wallet (BIP-44), the sequential index structure (`m/44'/60'/0'/0/i`) creates a linkability risk. While an on-chain observer cannot directly recover HD paths from addresses alone, common wallet behaviors---such as sequential account activation, correlated funding patterns, and timing---enable heuristic clustering attacks that can identify sibling addresses with high probability [see Harrigan and Fretter, "The Unreasonable Effectiveness of Address Clustering," 2016].

**ACE-GF alone**: Context-isolated derivation produces unlinkable addresses, but without EIP-8141, there is no mechanism for one vault to pay gas for another within a single atomic transaction.

### 5.3 Construction

**Step 1: Vault Derivation via ACE-GF Context Isolation**

```
identity_root = HKDF(Kmaster, "acegf:identity:root")

Treasury vault:
  HKDF(identity_root, "ACEGF-REV32-V1-SECP256K1-EVM:corp:Treasury:0")
  → secp256k1 seed → EVM address 0xAAAA...

Operations vault:
  HKDF(identity_root, "ACEGF-REV32-V1-SECP256K1-EVM:corp:Operations:0")
  → secp256k1 seed → EVM address 0xBBBB...

M&A Escrow vault:
  HKDF(identity_root, "ACEGF-REV32-V1-SECP256K1-EVM:corp:MnA-Escrow:0")
  → secp256k1 seed → EVM address 0xCCCC...
```

By the HKDF security model, these three addresses are computationally unlinkable without knowledge of `identity_root`. There is no derivation index or path structure (unlike BIP-44's `m/44'/60'/0'/0/i`) that an observer could iterate.

**Step 2: EIP-8141 Paymaster Frame Transaction**

When the Operations vault needs to execute a transaction with the Treasury paying gas:

```
Frame 0 (Validation - Operations vault 0xBBBB):
  ACE-GF signs with context "corp:Operations:0" derived key
  Validation contract at 0xBBBB:
    verify(ECDSA, operations_pubkey, sig)
    APPROVE(0x0)  // sender only, no gas  // I authorize as sender but don't pay gas

Frame 1 (Paymaster - Treasury vault 0xAAAA):
  ACE-GF signs paymaster authorization with context "corp:Treasury:0" derived key
  Paymaster contract at 0xAAAA:
    // Check policy: is 0xBBBB an authorized sub-vault?
    require(isAuthorizedVault[msg.sender])
    // Check budget: has 0xBBBB exceeded monthly gas allocation?
    require(monthlyGasUsed[msg.sender] + getTxParam(2) <= monthlyGasLimit[msg.sender])  // TXPARAMLOAD: gas_limit
    // Check Frame 2: does it transfer fee tokens to us?
    require(decodeFrame(2).to == address(this))
    APPROVE(0x1)  // gas payment only  // I pay the gas

Frame 2 (Fee Settlement):
  Operations vault transfers fee tokens to Treasury vault
  (This frame is verified by the paymaster in Frame 1)

Frame 3 (Execution):
  Operations vault's actual business transaction (swap, transfer, etc.)
```

### 5.4 Unlinkability Analysis

**Claim 2 (Vault Unlinkability).** Given addresses `A₁ = Addr(HKDF(root, info₁))` and `A₂ = Addr(HKDF(root, info₂))` where `info₁ ≠ info₂`, no polynomial-time adversary can determine whether `A₁` and `A₂` share the same `root` with advantage greater than negligible, assuming HKDF-SHA256 is a secure PRF.

**Argument.** HKDF-SHA256 with distinct info strings is a secure PRF [RFC 5869, Theorem 1]. The outputs for different info strings are computationally indistinguishable from independent random values. Since Ethereum addresses are derived from the HKDF output via a one-way function (public key derivation + Keccak256), the addresses inherit this indistinguishability. The formal security game (Cross-Context Linkability) and tight reduction are given in Appendix E.2. ∎

**Paymaster linkability caveat.** The paymaster frame transaction itself reveals that 0xAAAA pays gas for 0xBBBB, creating a one-time link. However:
1. The treasury can act as paymaster for many unrelated parties, providing plausible deniability.
2. Time-delayed settlement (paying gas from a common pool with batched repayment) can further obscure the relationship.
3. Multiple treasury proxies can be used for different sub-vaults, breaking the single-point linkage.

### 5.5 Policy Enforcement

The paymaster contract at the Treasury vault can enforce arbitrarily complex policies:

```solidity
// Simplified paymaster policy contract
//
// Note: VERIFY-mode frames ban environment-dependent opcodes (TIMESTAMP,
// BLOCKHASH, NUMBER, etc.) per ERC-7562 mempool safety rules. Therefore
// this contract uses an on-chain epoch counter instead of block.timestamp,
// and reads the transaction gas limit via TXPARAMLOAD (opcode 0xb0)
// introduced by EIP-8141, rather than the non-existent tx.gasLimit field.

mapping(address => uint256) public monthlyGasLimit;
mapping(address => uint256) public monthlyGasUsed;
mapping(address => bool) public isAuthorizedVault;
mapping(address => uint256) public perTxGasLimit;
uint256 public currentEpoch;  // incremented by an external keeper or governance call

function validate(bytes calldata paymasterSig) external {
    address sender = getFrameSender(0);  // Read Frame 0's sender
    uint256 frameGasLimit = getTxParam(2);  // TXPARAMLOAD: read gas_limit from tx params

    require(isAuthorizedVault[sender], "Unauthorized vault");
    require(monthlyGasUsed[sender] + frameGasLimit <= monthlyGasLimit[sender],
            "Monthly gas budget exceeded");
    require(frameGasLimit <= perTxGasLimit[sender],
            "Per-transaction gas limit exceeded");

    // Verify Treasury admin signature over (sender, gasLimit, epoch)
    // currentEpoch is storage-based, not environment-dependent, so it is
    // permitted in VERIFY mode (associated storage per ERC-7562).
    require(ecrecover(keccak256(abi.encode(sender, frameGasLimit, currentEpoch)),
                      paymasterSig) == treasuryAdmin);

    monthlyGasUsed[sender] += frameGasLimit;
    APPROVE(0x1);  // gas payment only
}
```

---

## 6. Emergent Capability 3: Zero-Knowledge Cross-Chain Identity Attestation

### 6.1 Problem Statement

A user holds assets on Ethereum (via EVM address) and Solana (via Ed25519 address). A DeFi protocol wants to verify "these two addresses belong to the same entity" without learning *which* entity or *which* other addresses they control. The same pattern extends to additional chains (Bitcoin, Cosmos); we present the two-chain case as the reference instantiation and discuss extensions in Section 6.6.

Use cases include: cross-chain credit scoring, unified governance voting, cross-chain airdrop eligibility, and reputation portability.

### 6.2 Why Neither System Alone Suffices

**EIP-8141 alone**: Can verify a ZK proof on Ethereum, but the proof needs a *witness*---some secret that binds all addresses together. Without a deterministic multi-chain derivation system, there is no mathematical relationship between addresses on different chains. Users could create ad-hoc links (e.g., signed attestations), but these are not zero-knowledge.

**ACE-GF alone**: Provides the mathematical relationship---all addresses derive from the same `identity_root` via HKDF. But on the current Ethereum (EOA-only), there is no way to submit a ZK proof as part of a transaction. The user would need an off-chain verifier, introducing trust assumptions.

### 6.3 Construction

**Witness**: The user's ACE-GF `identity_root` (32 bytes).

**Public Inputs**:
- Ethereum address `A_eth`
- Solana address `A_sol`
- A Merkle root `R` of a set of registered X25519 identity public keys

**ZK Circuit (expressed as constraints)**:

```
// Private witness
identity_root: [u8; 32]

// Public inputs
target_eth_address: [u8; 20]
target_sol_address: [u8; 32]
identity_set_root: [u8; 32]  // Merkle root of registered identities

// Constraints

// 1. Ethereum (secp256k1 → Keccak256 → address)
evm_seed = HKDF_SHA256(identity_root, "ACEGF-REV32-V1-SECP256K1-EVM")
evm_pubkey = secp256k1_point_mul(G, evm_seed)
evm_addr = keccak256(evm_pubkey)[12..32]
ASSERT: evm_addr == target_eth_address

// 2. Solana (Ed25519 → pubkey is address)
sol_seed = HKDF_SHA256(identity_root, "ACEGF-REV32-V1-ED25519-SOLANA")
sol_pubkey = ed25519_base_mul(sol_seed)
ASSERT: sol_pubkey == target_sol_address

// 3. Identity set membership (X25519 → Merkle proof)
x25519_seed = HKDF_SHA256(identity_root, "ACEGF-REV32-V1-X25519-IDENTITY")
x25519_pubkey = x25519_base_mul(x25519_seed)
merkle_proof = compute_merkle_proof(x25519_pubkey, identity_set_root)
ASSERT: verify_merkle_proof(merkle_proof, identity_set_root)
```

**Protocol Flow:**

1. **Registration (one-time)**: The user's X25519 identity public key is added to a Merkle tree maintained by a smart contract on Ethereum.

2. **Attestation**: When a protocol requests cross-chain identity proof:
   - ACE-GF derives the identity_root on the client side (never leaves the device)
   - A ZK-SNARK prover generates a proof `π` for the circuit above
   - The proof is submitted via an EIP-8141 frame transaction

3. **Verification**: The EIP-8141 validation frame's smart contract verifies the ZK-SNARK proof:

```
Frame 0 (Validation):
  ACE-GF signs with standard ECDSA (to authorize the transaction)
  APPROVE(0x2)  // sender + gas

Frame 1 (ENTRY_POINT - Identity Attestation):
  identityRegistry.verifyAttestation(
    proof=π,
    ethAddress=0xAAAA,
    solAddress=<base58>,
    identitySetRoot=R
  )
```

### 6.4 Security Properties

1. **Zero-knowledge**: The proof reveals nothing about `identity_root`. The verifier learns only that the claimed addresses share a common root in the registered identity set.

2. **Soundness**: A dishonest prover cannot claim ownership of addresses they don't control, because they would need to find an `identity_root` that simultaneously produces the correct EVM address, Solana address, and a valid X25519 key in the Merkle tree. This holds under the combined assumptions: (i) HKDF-SHA256 is a PRF under each domain separator, (ii) secp256k1 and Ed25519 discrete-log hardness (group operations are correct), (iii) Keccak256 preimage resistance for EVM address binding, (iv) collision resistance of the Poseidon hash used in the Merkle tree, and (v) the knowledge soundness of the underlying ZK-SNARK proving system.

3. **Non-transferability**: The proof is bound to specific addresses. It cannot be replayed for different addresses.

### 6.5 Practicality Considerations

The two-chain reference circuit requires HKDF-SHA256, secp256k1 scalar multiplication, Ed25519 base-point multiplication, Keccak256, and Merkle proof verification as in-circuit operations. Modern ZK-SNARK systems (Groth16, PLONK, Halo2) can handle these, though with non-trivial proving costs. The following estimates are derived from published constraint counts for comparable circuit components in the literature and should be treated as analytical projections, not empirical benchmarks:

- HKDF-SHA256 (×3 derivations: EVM, Solana, X25519): ~60K constraints (two rounds of HMAC-SHA256 each; based on SHA-256 circuit estimates from circomlib)
- secp256k1 point multiplication (×1: EVM): ~200K constraints (based on non-native field arithmetic estimates from Halo2 and circom-ecdsa)
- Ed25519 base multiplication (×1: Solana): ~150K constraints (comparable to secp256k1 with smaller field)
- X25519 base multiplication (×1: identity): ~100K constraints
- Keccak256 (EVM address derivation): ~150K constraints (based on keccak256 circuit implementations in circomlib)
- Merkle proof verification (depth 20): ~40K constraints (20 Poseidon hashes at ~2K constraints each)

Total: ~700K constraints for the two-chain reference circuit. This is well within the range of circuits proven in production ZK systems (e.g., Zcash Sapling's circuit is ~100K constraints; zkSync Era's circuits exceed 1M). Proving time will depend heavily on the proving system, hardware, and optimization level; we estimate single-digit seconds on modern desktop/server hardware and under 30 seconds on mobile devices. For extension to additional chains, see Section 6.6.

### 6.6 Extension to Additional Chains

The two-chain reference instantiation above covers EVM and Solana. ACE-GF's deterministic derivation architecture supports additional chains via the same HKDF pattern; each chain introduces one additional constraint module into the ZK circuit. We outline two concrete extensions below. **These modules are not included in the current benchmark estimates** (Section 6.5) and are presented as design sketches for future instantiation.

#### 6.6.1 Bitcoin (BIP-340 / Taproot)

ACE-GF derives a Bitcoin key via:

```
btc_seed = HKDF_SHA256(identity_root, "ACEGF-REV32-V1-SECP256K1-BTC")
btc_pubkey = secp256k1_point_mul(G, btc_seed)
btc_xonly = btc_pubkey.x  // BIP-340 x-only representation
```

**Additional circuit constraints:**
- secp256k1 point multiplication: ~200K constraints (same curve as EVM, independent derivation)
- BIP-340 x-only extraction: negligible (single field element selection)

**Estimated marginal cost:** ~200K constraints. The BIP-340 x-only public key serves as the public input; the verifier checks `btc_xonly == target_btc_xonly`.

#### 6.6.2 Cosmos (secp256k1 + SHA-256 + RIPEMD-160)

ACE-GF derives a Cosmos address via:

```
cosmos_seed = HKDF_SHA256(identity_root, "ACEGF-REV32-V1-SECP256K1-COSMOS")
cosmos_pubkey = secp256k1_point_mul(G, cosmos_seed)
cosmos_addr = RIPEMD160(SHA256(cosmos_pubkey))  // Bech32-encoded
```

**Additional circuit constraints:**
- secp256k1 point multiplication: ~200K constraints
- SHA-256 hash: ~25K constraints (based on circomlib)
- RIPEMD-160 hash: ~5K constraints

**Estimated marginal cost:** ~230K constraints.

#### 6.6.3 Full Four-Chain Circuit Projection

A circuit covering all four chains (EVM, Solana, Bitcoin, Cosmos) plus X25519 identity membership would total approximately **1.13M constraints** (700K reference + 200K Bitcoin + 230K Cosmos). This remains within the range of production ZK systems (zkSync Era exceeds 1M constraints), but proving time on mobile devices may be impractical without delegated or recursive proving strategies.

---

## 7. Emergent Capability 4: End-to-End Private Transactions

### 7.1 Problem Statement

A user wants to execute a transaction on Ethereum without revealing:
- Which address is the sender (on-chain privacy)
- The transaction contents during broadcast (mempool privacy)
- The signing key, even to a compromised memory inspector (client-side privacy)

### 7.2 The Privacy Stack

The co-protocol creates a full-stack privacy architecture where each layer addresses a distinct threat:

```
┌─────────────────────────────────────────────────────┐
│ Layer 4: Communication Privacy                       │
│ ACE-GF X25519 end-to-end encryption                │
│ Threat: network eavesdropping on tx notification    │
├─────────────────────────────────────────────────────┤
│ Layer 3: Client-Side Privacy                         │
│ ACE-GF zero-plaintext model                          │
│ Threat: cold-boot attack, memory forensics          │
├─────────────────────────────────────────────────────┤
│ Layer 2: Mempool Privacy                             │
│ EIP-8141 private submission + FOCIL inclusion       │
│ Threat: mempool front-running, censorship           │
├─────────────────────────────────────────────────────┤
│ Layer 1: On-Chain Privacy                            │
│ EIP-8141 ZK-SNARK paymaster                          │
│ Threat: on-chain transaction graph analysis         │
└─────────────────────────────────────────────────────┘
```

### 7.3 Construction

**Step 1: Client-Side Key Derivation (ACE-GF, Layer 3)**

```
// REV32 mode: passphrase participates in derivation, not sealing
salt = HKDF(REV32, "acegf:rev32:salt")
Kmaster = Argon2id(passphrase, salt)              // Zeroizing<[u8; 32]>; passphrase consumed
identity_root = HKDF(Kmaster, "acegf:identity:root")  // Zeroizing<[u8; 32]>
// Kmaster is dropped (zeroized) here — only identity_root remains
seeds = HKDF(identity_root, per-chain info strings)    // SchemeSeeds with Zeroizing fields
signature = sign(seeds.secp256k1_evm, tx_hash)
clear_scheme_seeds(&mut seeds)                    // All 7 seeds zeroed
```

At no point do `passphrase`, `Kmaster`, and `identity_root` coexist in plaintext memory: `passphrase` is consumed by Argon2id, and `Kmaster` is dropped before chain seeds are derived. The ACE-GF implementation ensures this via Rust's ownership model and `Zeroizing` drop behavior.

**Step 2: ZK Proof Generation (ACE-GF + ZK Prover, Layers 3+1)**

The user generates a ZK-SNARK proof that they are authorized to spend from a privacy pool, without revealing which address in the pool is theirs:

```
// Witness (private)
identity_root, merkle_path, nullifier_secret

// Public inputs
privacy_pool_root, nullifier_hash, amount, recipient

// Circuit
seed = HKDF(identity_root, "ACEGF-REV32-V1-SECP256K1-EVM")
address = derive_address(seed)
ASSERT: merkle_verify(address, privacy_pool_root, merkle_path)
ASSERT: nullifier_hash == hash(nullifier_secret, address)
```

**Step 3: EIP-8141 Frame Transaction with ZK Paymaster (Layer 1+2)**

```
Frame 0 (Validation - ZK-SNARK Paymaster):
  The paymaster is a privacy-preserving contract that:
  1. Verifies the ZK proof π
  2. Checks the nullifier hasn't been used (prevents double-spend)
  3. Records the nullifier
  4. APPROVE(0x2)  // Acts as both sender-authorizer and gas-payer

Frame 1 (Execution):
  Transfer from privacy pool to recipient
```

The transaction is submitted to a private mempool or directly to a FOCIL-enabled proposer, preventing mempool observation.

**Step 4: Notification (ACE-GF X25519, Layer 4)**

After the transaction is confirmed, the sender notifies the recipient via encrypted communication:

```
// Sender has recipient's X25519 public key (their x25519)
(ephemeral_pub, encrypted_aes_key, iv, encrypted_data) =
    ACEGF::encrypt_for_x25519(recipient_x25519, tx_receipt)

// Recipient decrypts with their ACE-GF derived X25519 private key
tx_receipt = ACEGF::decrypt_internal(
    mnemonic, passphrase,
    ephemeral_pub, encrypted_aes_key, iv, encrypted_data
)
```

### 7.4 Threat Model and Mitigations

| Threat | Layer | Mitigation | Protocol |
|--------|-------|------------|----------|
| On-chain tx graph analysis | 1 | ZK-SNARK proof hides sender identity in privacy pool | EIP-8141 |
| Mempool front-running | 2 | Private submission to FOCIL-enabled proposers | EIP-8141 |
| Cold-boot / memory forensics | 3 | `Zeroizing` wrappers, Argon2id KDF, no plaintext in memory | ACE-GF |
| Passphrase brute-force | 3 | Argon2id (4MB, 3 iter), also requires mnemonic | ACE-GF |
| Cross-address correlation | 1+3 | Context isolation + ZK proofs | Both |
| Communication eavesdropping | 4 | X25519 DH + AES-256-GCM | ACE-GF |
| Quantum key recovery | 3 | ML-DSA-44 key stream, dual-track migration | Both |

---

## 8. Security Analysis of the Combined System

### 8.1 Adversary Model

We consider a **composite adversary** `A` with the following capabilities:

- **On-chain**: Can observe all transactions, state changes, and contract interactions
- **Mempool**: Can observe public mempool contents (but not private submission channels)
- **Client-side**: Can perform cold-boot attacks (but not real-time memory access during signing)
- **Network**: Can observe encrypted communications (but cannot break X25519 DH)
- **Future quantum**: May gain access to a cryptographically relevant quantum computer (CRQC) at some future time

### 8.2 Security Properties

**Property 1: Key Isolation.** Compromise of one chain's signing key does not reveal any other chain's key.

*Argument.* Each chain's seed is derived via `HKDF(identity_root, info_i)` where `info_i` is distinct per chain. By the PRF security of HKDF-SHA256, the outputs for distinct info strings are computationally independent. Compromise of `seed_i` reveals nothing about `seed_j` for `j ≠ i` without knowledge of `identity_root`. ∎

**Property 2: Validation-Signing Coherence.** If ACE-GF produces a signature `σ` for a transaction `tx`, the EIP-8141 validation frame that was deployed with the corresponding public key will accept `σ`.

*Argument.* This follows from the determinism of ACE-GF's derivation. Given the same mnemonic, passphrase, and context, ACE-GF always produces the same key pair. The validation frame stores the public key at deployment time. As long as the signing key has not been rotated (which requires an on-chain transaction authorized by the current key), the signature produced by ACE-GF's key will verify against the stored public key. ∎

**Property 3: Zero-Plaintext Memory Discipline.** Under the assumptions stated below, at no point during a signing operation do `passphrase`, `Kmaster`, and `identity_root` simultaneously exist as plaintext in unprotected application memory.

**Assumptions.** This property holds at the application layer under the following boundary conditions: (1) the operating system does not swap the process's memory pages to disk (e.g., `mlock` is in effect or swap is disabled); (2) no core dump or crash dump is generated during the signing window; (3) the compiler does not reorder or elide the zeroization operations (Rust's `Zeroizing<T>` uses `volatile` semantics via the `zeroize` crate to mitigate this); and (4) speculative execution side channels (e.g., Spectre-class attacks) are out of scope. In deployment environments where these conditions cannot be guaranteed (e.g., shared hosting, mobile devices with aggressive memory management), additional OS-level hardening is recommended.

*Argument.* In ACE-GF's REV32 signing flow:
1. A static salt is derived: `salt = HKDF(REV32, "acegf:rev32:salt")`.
2. The passphrase is processed through Argon2id to produce `Kmaster` (wrapped in `Zeroizing`; the passphrase is consumed).
3. `identity_root = HKDF(Kmaster, "acegf:identity:root")` (wrapped in `Zeroizing`); `Kmaster` is dropped.
4. Chain seeds are derived from `identity_root` via HKDF with domain-separated info strings (each in `Zeroizing`).
5. The signing key is constructed from the chain seed.
6. `clear_scheme_seeds()` zeroes all seven seeds.

At step 3, the passphrase has already been consumed by Argon2id and `Kmaster` is dropped after producing `identity_root`. At step 6, the seeds are zeroed. The `Zeroizing` wrapper ensures deterministic cleanup even on panic paths (Rust's `Drop` trait). ∎

**Property 4: Post-Quantum Forward Secrecy.** Assets protected by the dual-track validation (Section 4) remain secure even if a CRQC becomes available after the migration to Phase 3 (pure PQC).

*Argument.* In Phase 3, the validation frame accepts only ML-DSA-44 signatures. ML-DSA-44 is based on Module-LWE, which is not known to be vulnerable to quantum attacks (FIPS 204). The ECDSA key, which would be vulnerable, has been decommissioned on-chain (the validation frame no longer checks it). Even if the adversary recovers the secp256k1 private key via quantum factoring, they cannot produce a valid ML-DSA-44 signature to pass the validation frame. ∎

**Proposition 1 (BIP-44 Separation).** In a derivation model where (i) child keys are derived via a deterministic, sequentially-indexed path `m/purpose'/coin'/account'/change/index`, and (ii) the adversary can observe account activation order and correlate timing and funding patterns across addresses, no scheme satisfying (i) can achieve Cross-Context Unlinkability as defined in Appendix E.2.

*Argument.* In BIP-44, the derivation path structure is deterministic and monotonically increasing: the *k*-th account uses index *k*. An adversary who observes *n* addresses appearing on-chain in temporal order can hypothesize they correspond to indices 0, 1, ..., n−1 under a common master key. While the on-chain addresses alone do not reveal their HD path (the mapping from index to address is one-way), the sequential activation pattern provides a side channel: the adversary constructs candidate sets {(a_i, i)} and tests whether the activation timestamps are consistent with sequential derivation. This auxiliary information breaks the indistinguishability required by Game CL (Appendix E.2), where the adversary must distinguish same-root from independent-root address pairs. Concretely, in the same-root case the activation order correlates with the index order, while in the independent-root case it does not—giving the adversary non-negligible advantage.

In contrast, ACE-GF's context-isolated derivation uses arbitrary, non-sequential info strings (e.g., `"corp:Treasury:0"`, `"corp:Operations:0"`). There is no index structure to correlate with activation order, and the HKDF PRF security ensures that the mapping from info string to address is indistinguishable from random (see Appendix E.2 reduction). ∎

*Remark.* This is a separation in the *model*, not a claim that ACE-GF is "globally superior" to BIP-44. BIP-44 provides interoperability, ecosystem compatibility, and hardware wallet support that are outside the scope of this comparison. The proposition establishes that under the specific property of Cross-Context Unlinkability, the structural difference in derivation path design creates a formal capability gap.

### 8.3 Assumptions and Scope

The security arguments in this paper rest on the following assumptions. We state them explicitly so that readers can evaluate the boundaries of each claim.

1. **Cryptographic hardness assumptions.** Key isolation (Property 1) and vault unlinkability (Claim 2) rely on HKDF-SHA256 being a secure PRF as analyzed in [10]. Hybrid-phase security (Claim 1) assumes that ECDLP and Module-LWE are independently hard; a shared algebraic weakness affecting both would invalidate the AND-composition argument. Post-quantum forward secrecy (Property 4) assumes ML-DSA-44 remains secure against quantum adversaries per FIPS 204 [11].

2. **EIP-8141 specification stability.** The constructions in Sections 4--7 are grounded in the EIP-8141 specification as formalized. Should the specification undergo material changes (e.g., removal of APPROVE semantics or VERIFY-mode data elision), the on-chain half of the co-protocol would require corresponding adaptation.

3. **Client-side environment.** The zero-plaintext memory discipline (Property 3) holds at the application layer only. It does not defend against OS-level memory exposure (swap, core dumps), hardware side channels (Spectre, Rowhammer), or compromised compilers. See Property 3's assumptions block for details.

4. **ZK circuit and gas estimates.** The constraint counts in Section 6.5 and gas costs in Section 9.3 are analytical projections based on known circuit component sizes and EVM opcode pricing, not empirical measurements from a deployed prototype. Actual costs may vary with proving system choice, compiler optimizations, and future EVM gas schedule changes.

5. **Scope of formal analysis.** Appendix E provides game-based definitions for three properties (Context Isolation, Cross-Context Unlinkability, Rotation Independence) with tight reductions to HKDF-SHA256 PRF security. Proposition 1 establishes a separation between ACE-GF and BIP-44 under the specific property of Cross-Context Unlinkability. These results are *property-specific*: they demonstrate that ACE-GF satisfies a well-defined set of security games, not that it is "globally superior" to alternative derivation schemes. Full simulation-based or UC-framework proofs covering the end-to-end co-protocol (including on-chain interactions) are left to future work.

---

## 9. Implementation Considerations

### 9.1 EIP-8141 Account Contract

The validation frame's smart contract must be designed to work with ACE-GF's key management. A reference design:

```solidity
contract AceGfAccount {
    enum ValidationMode { CLASSICAL, HYBRID, PQC_ONLY }

    ValidationMode public mode;
    address public classicalOwner;      // secp256k1 derived address
    bytes public pqcOwnerPubkey;        // ML-DSA-44 public key (1312 bytes)
    mapping(address => bool) public authorizedVaults;

    function validate(bytes calldata sig) external {
        if (mode == ValidationMode.CLASSICAL) {
            require(ecrecover(txHash(), sig) == classicalOwner);
        } else if (mode == ValidationMode.HYBRID) {
            (bytes memory ecdsaSig, bytes memory mldsaSig) = splitSignature(sig);
            require(ecrecover(txHash(), ecdsaSig) == classicalOwner);
            require(mlDsa44Verify(txHash(), mldsaSig, pqcOwnerPubkey));
        } else {
            require(mlDsa44Verify(txHash(), sig, pqcOwnerPubkey));
        }
        APPROVE(0x2);  // sender + gas
    }
}
```

### 9.2 ACE-GF Client Integration

The ACE-GF client must be extended to:

1. **Detect account type**: Query whether the user's EVM address is an EOA or an EIP-8141 account.
2. **Construct frame transactions**: When the address is an EIP-8141 account, construct frame transaction payloads instead of standard transactions.
3. **Multi-signature support**: In hybrid mode, produce both ECDSA and ML-DSA-44 signatures and concatenate them for the validation frame.
4. **Paymaster coordination**: When operating as a sub-vault, include the paymaster authorization in the frame transaction construction.

### 9.3 Gas Cost Estimates

The following gas costs are analytical projections. The `ecrecover` cost is specified by the EVM yellow paper. Groth16 verification cost is based on deployed verifier contracts (e.g., Tornado Cash, Semaphore). ML-DSA-44 verification cost assumes a future precompile; without a precompile, pure-Solidity verification would be prohibitively expensive. Actual costs will depend on the final EIP-8141 gas schedule and any PQC precompile specifications.

| Operation | Approximate Gas Cost | Basis |
|-----------|---------------------|-------|
| ECDSA validation (ecrecover) | 3,000 | EVM specification |
| ML-DSA-44 verification (precompile) | ~50,000--100,000 | Projected; no precompile exists yet |
| Hybrid validation (both) | ~53,000--103,000 | Sum of above |
| ZK-SNARK verification (Groth16) | ~200,000--300,000 | Based on deployed Groth16 verifiers |
| Paymaster frame overhead | ~21,000 | Base CALL cost |

These projected costs are within practical bounds for mainnet Ethereum and significantly cheaper on L2s.

---

## 10. Related Work

**ERC-4337** [3] pioneered account abstraction without protocol changes using UserOperations and a shared EntryPoint contract. However, it requires bundlers as intermediaries and cannot provide the same level of enshrined support as EIP-8141. The co-protocol architecture could be adapted to work with ERC-4337, though with reduced efficiency due to the bundler intermediary.

**BIP-44/BIP-32** [6, 7] provide hierarchical deterministic key derivation for multi-chain wallets. While on-chain addresses alone do not reveal their HD derivation paths, the sequential index structure of BIP-44 (`m/44'/60'/0'/0/i`) combined with observable wallet behaviors (sequential activation, correlated funding, timing) enables heuristic clustering that can identify sibling addresses. ACE-GF's HKDF-based derivation with arbitrary, non-sequential context strings eliminates this structural linkability risk: there is no index to iterate and no predictable activation order.

**EIP-7702** [8] allows EOAs to temporarily delegate to contract code, providing some account abstraction benefits. However, it does not support custom signature verification or paymaster patterns natively, limiting its applicability for the co-protocol capabilities described here.

**Safe/Gnosis Smart Accounts** [9] provide multi-signature and modular account functionality. They could serve as a deployment target for the co-protocol's validation logic, but they lack ACE-GF's deterministic cross-chain derivation and zero-plaintext guarantees.

---

## 11. Generalization: The Multi-Chain Co-Protocol Pattern

The Ethereum-focused construction in Sections 4--7 demonstrates the co-protocol architecture at its fullest. However, the underlying pattern---pairing a unified off-chain key management protocol with a chain-native on-chain programmable validation mechanism---is not Ethereum-specific. This section formalizes the general pattern, maps it onto four additional blockchain ecosystems, and identifies the structural reasons why Ethereum + EIP-8141 provides the most complete instantiation.

### 11.1 Abstract Pattern Definition

**Definition (Co-Protocol).** A co-protocol is a tuple *(OffChainKM, OnChainAA, SharedRoot, Interface)* where:

- **OffChainKM** is a client-side key management system satisfying four properties:
  1. *Deterministic multi-chain derivation*: A single seed produces keys for N chains
  2. *Chain isolation*: Compromise of chain_i key reveals nothing about chain_j key
  3. *Zero-plaintext memory security*: No sensitive material exists in unprotected memory during signing
  4. *PQC readiness*: At least one post-quantum key stream is derivable from the same seed

- **OnChainAA** is a chain-native account abstraction mechanism satisfying two properties:
  1. *Programmable validation*: The account can define arbitrary signature verification logic
  2. *Gas abstraction*: A third party can pay transaction fees on behalf of the sender

- **SharedRoot** is a cryptographic value (e.g., identity_root) from which both the OffChainKM-derived signing key and the OnChainAA-registered verification key are deterministically produced.

- **Interface** is the set {public_key, signature, address} that crosses the off-chain/on-chain boundary.

**Claim 3 (Emergent Capability Conditions).** Given a co-protocol *(OffChainKM, OnChainAA, SharedRoot, Interface)*:

- *Capability 1 (PQC Migration)* requires: OffChainKM has PQC readiness AND OnChainAA has programmable validation supporting PQC signature verification.
- *Capability 2 (Unlinkable Paymaster)* requires: OffChainKM has context-isolated derivation AND OnChainAA has gas abstraction with paymaster support.
- *Capability 3 (ZK Cross-Chain Identity)* requires: OffChainKM has deterministic multi-chain derivation AND OnChainAA has programmable validation supporting ZK-SNARK verification.
- *Capability 4 (E2E Privacy)* requires: OffChainKM has zero-plaintext security + E2E encryption AND OnChainAA has programmable validation supporting ZK-SNARK paymasters.

### 11.2 Instantiation Spectrum

We evaluate four blockchain ecosystems against the co-protocol requirements, using ACE-GF as the fixed OffChainKM:

#### 11.2.1 Solana: Program Accounts + Ed25519 SigVerify

Solana's account model is inherently program-owned---there are no EOAs in the Ethereum sense. Every account is owned by a program, and programs define their own validation logic. This makes Solana a **natural candidate** for co-protocol instantiation.

**OnChainAA mapping:**

| EIP-8141 Concept | Solana Equivalent | Notes |
|-----------------|-------------------|-------|
| VERIFY frame + APPROVE | Program instruction + Ed25519 SigVerify precompile | Native Ed25519 verification at ~3,500 compute units |
| ENTRY_POINT frame | Standard instruction | CPI (Cross-Program Invocation) enables atomic multi-step |
| Paymaster frame | Fee delegation via CPI | Not standardized; requires custom program logic |
| 2D nonces | Durable nonces (off-chain signing) | Different mechanism, similar effect |
| FOCIL inclusion | Leader schedule + priority fees | Weaker censorship resistance guarantees |

**ACE-GF integration points:**

```
ACE-GF identity_root
    │
    ├─→ HKDF("ACEGF-REV32-V1-ED25519-SOLANA") → Ed25519 keypair
    │   └─→ Direct use: Solana natively uses Ed25519
    │       No smart contract wrapper needed for basic validation
    │
    └─→ HKDF("ACEGF-REV32-V1-ML-DSA-44-PQC-IDENTITY") → ML-DSA-44 keypair
        └─→ Solana program verifies ML-DSA-44 via custom instruction
            (Ed25519 SigVerify precompile doesn't support ML-DSA)
```

**Capability coverage:**

| Capability | Feasibility | Mechanism |
|-----------|:-----------:|-----------|
| PQC Migration | Partial | Solana uses Ed25519 natively; ML-DSA-44 requires a custom verifier program. No enshrined support, but the permissionless program model allows it. |
| Unlinkable Paymaster | Feasible | ACE-GF context isolation + custom fee delegation program. Less elegant than EIP-8141's APPROVE(0x1) but functionally equivalent. |
| ZK Cross-Chain Identity | Feasible | Solana has multiple ZK verifier programs (Groth16, PLONK). The Ed25519 SigVerify precompile also enables direct signature-based identity proofs without ZK for same-curve attestations. |
| E2E Privacy | Partial | ZK compression programs exist (Light Protocol, Elusiv) but lack the atomic paymaster pattern of EIP-8141. Privacy requires application-layer design. |

**Unique advantage:** Solana's native Ed25519 support means ACE-GF's Solana key stream can be used **without any smart contract wrapper** for basic transactions. The co-protocol overhead is zero for the common case, with the programmable validation path available for advanced capabilities.

#### 11.2.2 Bitcoin: Taproot Script Paths

Bitcoin's programmability is intentionally minimal, but Taproot (activated November 2021) introduced script-path spending that enables limited co-protocol patterns.

**OnChainAA mapping:**

| EIP-8141 Concept | Bitcoin Equivalent | Notes |
|-----------------|-------------------|-------|
| VERIFY frame | Taproot script-path spending | Limited: only Schnorr signature verification + basic opcodes |
| ENTRY_POINT frame | Standard spending | No atomic multi-step within a single transaction |
| Paymaster | SIGHASH_ANYONECANPAY | Primitive: anyone can add inputs (= add gas/fees) |
| Programmable validation | Tapscript opcodes | Very limited compared to EVM; no loops, no state access |

**ACE-GF integration points:**

```
ACE-GF identity_root
    │
    └─→ HKDF("ACEGF-REV32-V1-SECP256K1-BTC") → secp256k1 keypair
        │
        ├─→ Key-path spend: Standard P2TR (Taproot) transaction
        │   Internal key = x-only public key derived from seed
        │
        └─→ Script-path spend: Taproot script tree with multiple paths
            ├── Leaf 0: <classical_pubkey> OP_CHECKSIG
            └── Leaf 1: (reserved for future PQC opcode)
```

**Capability coverage:**

| Capability | Feasibility | Mechanism |
|-----------|:-----------:|-----------|
| PQC Migration | Future | Bitcoin lacks PQC opcodes today. Proposals exist (OP_CHECKCONTRACTVERIFY, OP_CAT enabling Lamport signatures) but are years from activation. The Taproot script tree **can** reserve a leaf for future PQC verification. ACE-GF's dual derivation prepares the client side now. |
| Unlinkable Paymaster | Primitive | SIGHASH_ANYONECANPAY allows a Treasury UTXO to add inputs to an Operations transaction, paying the miner fee. Combined with ACE-GF context isolation, the funding UTXO and spending UTXO are unlinkable. However, unlike EIP-8141, there is no policy enforcement layer---Bitcoin Script cannot check "monthly gas budget." |
| ZK Cross-Chain Identity | Not feasible | Bitcoin Script cannot verify ZK-SNARKs. Would require off-chain verification or a BitVM-style challenge-response protocol, adding trust assumptions. |
| E2E Privacy | Limited | CoinJoin + Taproot provides transaction-level privacy. ACE-GF's zero-plaintext model protects the client side. But there is no on-chain ZK paymaster equivalent---privacy is at the UTXO mixing level, not the account abstraction level. |

**Honest assessment:** Bitcoin provides the weakest on-chain half. The co-protocol with Bitcoin is primarily valuable for (a) preparing client-side PQC keys for future Bitcoin soft forks and (b) SIGHASH_ANYONECANPAY-based fee delegation with ACE-GF's unlinkable vault derivation.

#### 11.2.3 Cosmos: x/authz + x/feegrant (Native Gas Abstraction)

Cosmos is unique in that **two of the four capabilities already exist natively** without needing a co-protocol construction:

**OnChainAA mapping:**

| EIP-8141 Concept | Cosmos Equivalent | Notes |
|-----------------|-------------------|-------|
| VERIFY frame | x/authz generic authorization | Programmable spend authorization |
| ENTRY_POINT frame | Standard Msg execution | MsgExec wraps authorized messages |
| Paymaster | **x/feegrant** | **Native gas abstraction since Cosmos SDK v0.43** |
| Programmable validation | CosmWasm smart contracts | Full Turing-complete validation on CosmWasm chains |

**Key observation:** Cosmos's `x/feegrant` module is a **first-class paymaster** at the SDK level. A granter address can pay fees for a grantee address with configurable allowances (basic, periodic, or per-message). This means Capability 2 (Paymaster Networks) is partially achieved by Cosmos natively.

**What the co-protocol adds:**

```
Without ACE-GF:
  x/feegrant granter = 0xAAAA, grantee = 0xBBBB
  Problem: How are 0xAAAA and 0xBBBB related? If both are HD-derived (BIP-44),
           sequential activation, correlated funding, and timing patterns enable
           heuristic clustering that can identify sibling addresses.

With ACE-GF:
  0xAAAA = derive(identity_root, "ACEGF-REV32-V1-SECP256K1-COSMOS:corp:Treasury:0")
  0xBBBB = derive(identity_root, "ACEGF-REV32-V1-SECP256K1-COSMOS:corp:Operations:0")
  → Unlinkable by HKDF security, even though x/feegrant links them on-chain
  → Single-seed recovery for both vaults
```

**Capability coverage:**

| Capability | Feasibility | Mechanism |
|-----------|:-----------:|-----------|
| PQC Migration | Feasible | CosmWasm contracts can implement ML-DSA-44 verification. Cosmos SDK's x/auth module already supports custom account types. The co-protocol construction from Section 4 maps directly to a CosmWasm-based validation contract. |
| Unlinkable Paymaster | **Native + Enhanced** | x/feegrant provides the paymaster; ACE-GF provides the unlinkability. This is the cleanest instantiation outside Ethereum---no custom smart contract needed for basic gas abstraction. |
| ZK Cross-Chain Identity | Feasible | CosmWasm supports ZK verifier contracts. Additionally, IBC (Inter-Blockchain Communication) enables cross-chain proof relay, potentially allowing identity proofs to propagate across Cosmos zones. |
| E2E Privacy | Partial | No native ZK paymaster equivalent. Privacy chains (Secret Network, Penumbra) within Cosmos ecosystem provide alternatives but with different trust models. |

#### 11.2.4 Polkadot: Substrate Pallets

Polkadot's Substrate framework offers pallet-level customization of account validation:

| Capability | Feasibility | Mechanism |
|-----------|:-----------:|-----------|
| PQC Migration | Feasible | Custom pallet with `SignedExtension` trait |
| Unlinkable Paymaster | Feasible | `pallet-transaction-payment` + custom signed extension |
| ZK Cross-Chain Identity | Feasible | XCM (Cross-Consensus Messaging) + ZK verifier pallet |
| E2E Privacy | Partial | Ink! smart contracts with ZK primitives |

### 11.3 Comparative Analysis

```
On-chain capability coverage by chain:

                  PQC       Paymaster   ZK Identity   E2E Privacy
                Migration   Network     Attestation   Transactions
Ethereum        ████████    ████████    ████████      ████████     4/4 Full
(EIP-8141)

Solana          ██████░░    ██████░░    ████████      ████░░░░     3/4
(Programs)

Cosmos          ██████░░    ████████    ██████░░      ████░░░░     2.5/4
(x/feegrant)

Polkadot        ██████░░    ██████░░    ██████░░      ████░░░░     2.5/4
(Substrate)

Bitcoin         ██░░░░░░    ████░░░░    ░░░░░░░░      ██░░░░░░     1/4
(Taproot)
```

**Why Ethereum ranks highest:**

1. **APPROVE opcode granularity**: EIP-8141's `APPROVE(0x0)` / `APPROVE(0x1)` / `APPROVE(0x2)` distinction enables fine-grained separation of sender authorization and gas payment within a single atomic transaction. No other chain has this level of in-transaction role separation.

2. **VERIFY mode data elision**: Validation secrets (signatures) in VERIFY-mode frames are elided from the signature hash and from introspection by other frames. This prevents information leakage between validation and execution---a property critical for Capability 4 (privacy).

3. **Enshrined ZK-SNARK support**: Ethereum's precompiled contracts for elliptic curve operations (EIP-196, EIP-197) and the upcoming Verkle tree transition provide efficient building blocks for ZK-SNARK verification. Other chains can verify ZK proofs but at higher computational cost.

4. **FOCIL censorship resistance**: Capability 4 requires that privacy transactions cannot be censored. EIP-8141's synergy with FOCIL (EIP-7805) provides the strongest inclusion guarantee among the evaluated chains.

### 11.4 The Asymmetry Insight: One Off-Chain Half, Many On-Chain Halves

The most significant structural observation is the **fundamental asymmetry** between the off-chain and on-chain halves:

```
┌─────────────────────────────────────────────────┐
│              ACE-GF (Off-Chain Half)              │
│                                                   │
│  ● Unified across ALL chains                      │
│  ● One mnemonic → 7 key streams                  │
│  ● One identity_root → unlimited contexts          │
│  ● One zero-plaintext model → all signing ops     │
│  ● One X25519 identity → all E2E communication    │
│                                                   │
│  The off-chain half is INVARIANT across chains.   │
└─────────────────────────┬─────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
    ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐
    │ Ethereum  │  │  Solana   │  │  Bitcoin  │  ...
    │ EIP-8141  │  │ Programs  │  │ Taproot   │
    │ APPROVE   │  │ CPI+      │  │ Script    │
    │ frames    │  │ SigVerify │  │ paths     │
    └───────────┘  └───────────┘  └───────────┘

    Each chain provides its OWN on-chain half,
    with DIFFERENT capability coverage.
```

This asymmetry has a practical consequence: **a user who adopts ACE-GF gets the off-chain benefits on ALL chains simultaneously**, even chains where the on-chain half is weak. The zero-plaintext memory model, deterministic recovery, and PQC key readiness apply to Bitcoin transactions just as they do to Ethereum transactions, regardless of Bitcoin's limited on-chain programmability.

The co-protocol capabilities emerge at the *intersection* of what each chain's on-chain half can support with what the unified off-chain half provides. Ethereum + EIP-8141 maximizes this intersection; other chains provide partial intersections that are still valuable.

### 11.5 Cross-Chain Co-Protocol Composition

When a user instantiates the co-protocol on multiple chains simultaneously, additional emergent properties arise from the **shared identity root**:

**Cross-chain disaster recovery:** A single mnemonic + passphrase recovers all accounts on all chains, including all context-isolated vaults, all chain-specific signing keys, the X25519 identity key, and the ML-DSA-44 PQC key. This is not merely a convenience---it is a security property, as it eliminates the key management complexity that leads to human errors (forgotten seeds, mismatched backups, lost hardware wallets).

**Lightweight cross-chain identity:** Even on chains where ZK-SNARK verification is infeasible (Bitcoin), the X25519 identity key provides a **non-ZK but still useful** identity anchor. Two parties can verify same-origin ownership by exchanging X25519-signed attestations off-chain, using the on-chain transactions as anchoring evidence. This weaker form of cross-chain identity is still stronger than what any single-chain wallet provides.

**Heterogeneous PQC migration:** Different chains will adopt PQC support at different times. ACE-GF's dual key derivation ensures the PQC key is ready on the client side *before* any chain's on-chain half supports it. When Ethereum activates ML-DSA-44 support via EIP-8141, the user migrates on Ethereum. When Solana adds a PQC verifier program, the same ML-DSA-44 key (derived from the same root) is used. When Bitcoin eventually adds PQC opcodes, the Taproot script-path leaf reserved for PQC becomes active. **The migration is per-chain but the key is cross-chain.**

---

## 12. Conclusion

The co-protocol architecture demonstrates that the combination of ACE-GF and EIP-8141 is more than the sum of its parts. By sharing a cryptographic identity root while maintaining domain sovereignty, the two protocols produce four capabilities that neither can achieve independently:

1. **Seamless post-quantum migration** from ECDSA through hybrid to pure ML-DSA-44, with the same mnemonic throughout.
2. **Unlinkable institutional paymaster networks** with context-isolated vaults and on-chain gas management.
3. **Zero-knowledge cross-chain identity attestation** leveraging ACE-GF's deterministic multi-chain derivation as a ZK witness.
4. **End-to-end private transactions** combining on-chain ZK paymasters, mempool privacy, client-side zero-plaintext, and X25519 encrypted notifications.

The generalization analysis (Section 11) reveals a fundamental asymmetry: the off-chain half (ACE-GF) is invariant across all chains, while each chain provides a different on-chain half with varying capability coverage. Ethereum + EIP-8141 achieves 4/4 capability coverage; Solana and Cosmos achieve approximately 3/4; Bitcoin achieves approximately 1/4. This asymmetry means that adopting ACE-GF provides immediate off-chain benefits on all chains, while on-chain capabilities activate incrementally as each chain's programmable validation matures.

The co-protocol pattern---*(OffChainKM, OnChainAA, SharedRoot, Interface)*---is a general design pattern applicable beyond the specific ACE-GF + EIP-8141 instantiation. We anticipate that as more chains adopt enshrined account abstraction (Solana's planned account abstraction improvements, Cosmos's evolving x/auth module, Bitcoin's covenant proposals), the capability coverage will converge upward, and the co-protocol pattern will become the standard architecture for cross-chain wallet security.

---

## References

[1] V. Buterin, "EIP-86: Abstraction of transaction origin and signature," Ethereum Improvement Proposals, 2017.

[2] A. Beregszaszi, V. Buterin, "EIP-2938: Account Abstraction," Ethereum Improvement Proposals, 2020.

[3] V. Buterin, Y. Weiss, K. Payal, D. Rham, "ERC-4337: Account Abstraction Using Alt Mempool," Ethereum Improvement Proposals, 2021.

[4] Y. Weiss, V. Buterin, A. Forshtat, "RIP-7560: Native Account Abstraction," Rollup Improvement Proposals, 2023.

[5] V. Buterin et al., "EIP-8141: Frame Transactions," Ethereum Improvement Proposals, 2025.

[6] M. Palatinus, P. Rusnak, "BIP-44: Multi-Account Hierarchy for Deterministic Wallets," Bitcoin Improvement Proposals, 2014.

[7] P. Wuille, "BIP-32: Hierarchical Deterministic Wallets," Bitcoin Improvement Proposals, 2012.

[8] V. Buterin, S. Kozin, "EIP-7702: Set EOA account code for one transaction," Ethereum Improvement Proposals, 2024.

[9] Gnosis Ltd., "Safe: Smart Account Infrastructure," https://safe.global, 2018--2025.

[10] H. Krawczyk, "Cryptographic Extraction and Key Derivation: The HKDF Scheme," CRYPTO 2010.

[11] NIST, "Module-Lattice-Based Digital Signature Standard (ML-DSA)," FIPS 204, 2024.

[12] D. J. Bernstein et al., "Ed25519: High-speed high-security signatures," Journal of Cryptographic Engineering, 2012.

[13] Solana Foundation, "Solana Program Library: Ed25519 SigVerify," https://spl.solana.com, 2020--2025.

[14] Cosmos SDK Contributors, "x/feegrant Module Specification," Cosmos SDK Documentation, 2021.

[15] Cosmos SDK Contributors, "x/authz Module Specification," Cosmos SDK Documentation, 2021.

[16] P. Wuille, J. Nick, A. Towns, "BIP-341: Taproot: SegWit version 1 spending rules," Bitcoin Improvement Proposals, 2020.

[17] Parity Technologies, "Substrate Developer Hub: Transaction Payment Pallet," https://docs.substrate.io, 2019--2025.

[18] F. Benhamouda et al., "Can Bitcoin Survive a Quantum Computer?," Proceedings of IEEE S&P, 2025.

---

## Appendix A: ACE-GF HKDF Info String Registry

**Legacy UUID Mode** (IKM = 16-byte UUID):

| Key Stream | Info String | Output | Usage |
|-----------|-------------|--------|-------|
| EVM | `ACEGF-V1-SECP256K1-EVM` | secp256k1 seed (32B) | Ethereum, BSC, Polygon, Arbitrum, etc. |
| Bitcoin | `ACEGF-V1-SECP256K1-BTC` | secp256k1 seed (32B) | Bitcoin P2TR (Taproot) |
| Cosmos | `ACEGF-V1-SECP256K1-COSMOS` | secp256k1 seed (32B) | Cosmos Hub, Osmosis, etc. |
| Solana | `ACEGF-V1-ED25519-SOLANA` | Ed25519 seed (32B) | Solana |
| Polkadot | `ACEGF-V1-ED25519-POLKADOT` | Ed25519 seed (32B) | Polkadot, Kusama |
| Identity | `ACEGF-V1-X25519-IDENTITY` | X25519 secret (32B) | E2E encryption, DH key agreement |
| PQC | `ACEGF-V1-ML-DSA-44-PQC-IDENTITY` | ML-DSA-44 seed (32B) | Post-quantum signatures |

**REV32 Mode** (IKM = 32-byte identity_root):

| Key Stream | Info String | Output | Usage |
|-----------|-------------|--------|-------|
| EVM | `ACEGF-REV32-V1-SECP256K1-EVM` | secp256k1 seed (32B) | Ethereum, BSC, Polygon, Arbitrum, etc. |
| Bitcoin | `ACEGF-REV32-V1-SECP256K1-BTC` | secp256k1 seed (32B) | Bitcoin P2TR (Taproot) |
| Cosmos | `ACEGF-REV32-V1-SECP256K1-COSMOS` | secp256k1 seed (32B) | Cosmos Hub, Osmosis, etc. |
| Solana | `ACEGF-REV32-V1-ED25519-SOLANA` | Ed25519 seed (32B) | Solana |
| Polkadot | `ACEGF-REV32-V1-ED25519-POLKADOT` | Ed25519 seed (32B) | Polkadot, Kusama |
| Identity | `ACEGF-REV32-V1-X25519-IDENTITY` | X25519 secret (32B) | E2E encryption, DH key agreement |
| PQC | `ACEGF-REV32-V1-ML-DSA-44-PQC-IDENTITY` | ML-DSA-44 seed (32B) | Post-quantum signatures |

Context-isolated derivation (REV32 mode only) appends `:<context>` to the info string:
`ACEGF-REV32-V1-SECP256K1-EVM:corp:Treasury:0`

## Appendix B: REV32 Byte Layout

```
Byte  0-27:  224 bits of entropy (random or legacy-anchored)
Byte    28:  VERSION (high nibble) | TYPE (low nibble)
             VERSION: 0xA = V1 Native, 0xB = BIP39 Import
             TYPE: 0x0 = Standard, 0x1 = MpcShard, 0x2 = SocialRecovery,
                   0x3 = HardwareBacked, 0xF = LegacyImport
Byte    29:  PROFILE
             0x00 = Default (multi-chain), 0x01 = EvmOnly,
             0x02 = BitcoinOnly, 0x03 = SolanaOnly, 0xFF = Custom
Byte    30:  FLAGS
             Bit 0: IMPORTED_LEGACY
             Bit 1: VADAR_ENABLED
             Bit 2: TESTNET
             Bit 3: BIP39_PASSPHRASE
Byte    31:  RESERVED (0x00)
```

## Appendix C: VA-DAR Key Derivation Hierarchy

```
User Input: (password, normalized_email)
    │
    ▼
salt = "ACEGF-VADAR-V1:" || normalized_email
    │
    ▼
Kmaster = Argon2id(password, salt, m=4MB, t=3, p=1)
    │
    ├─→ Ksa  = HKDF(Kmaster, "acegf:sa2:seal")           → SA2 sealing key
    ├─→ Kidx = HKDF(Kmaster, "va-dar:discovery:index")    → Discovery ID (HMAC)
    └─→ Kreg = HKDF(Kmaster, "va-dar:registry:auth")      → Registry Ed25519 keypair
                    │
                    └─→ HKDF(Kreg, salt=email, "va-dar:owner:keypair") → Signing key
```

## Appendix D: EIP-8141 Frame Transaction Structure (Simplified)

```
FrameTransaction (EIP-2718 type 0x06) {
    chain_id,
    nonce,
    sender,
    frames: [
        [mode=VERIFY, target=sender_account, gas_limit, data=signature],
            // Executes sender's validation logic (STATICCALL semantics)
            // Must call APPROVE(0x0) or APPROVE(0x2)
            // Data is elided from signature hash

        [mode=VERIFY, target=paymaster_account, gas_limit, data=paymaster_sig],
            // Optional: paymaster validation
            // Must call APPROVE(0x1)

        [mode=ENTRY_POINT, target=fee_token, gas_limit, data=transfer_call],
            // Fee settlement (ERC-20 transfer to paymaster)

        [mode=ENTRY_POINT, target=target_contract, gas_limit, data=function_call],
            // Actual execution
    ],
    max_priority_fee_per_gas,
    max_fee_per_gas,
    max_fee_per_blob_gas,
    blob_versioned_hashes
}
```

New opcodes introduced: `APPROVE` (validation signal), `TXPARAMLOAD` (0xb0), `TXPARAMSIZE` (0xb1), `TXPARAMCOPY` (0xb2).

## Appendix E: Security Game Definitions

This appendix formalizes the security properties claimed in Sections 5 and 8 as game-based definitions and provides reductions to the PRF security of HKDF-SHA256.

**Notation.** Let `F: {0,1}^λ × S → {0,1}^n` denote HKDF-SHA256 keyed by IKM ∈ {0,1}^λ with info string s ∈ S. Let `Addr(s) = AddrDerive(F(root, s))` denote the address derivation function (e.g., secp256k1 point multiplication + Keccak256 for EVM). We write `negl(λ)` for negligible functions in the security parameter.

### E.1 Game 1: Context Isolation (CI)

This game captures Property 1 (Key Isolation): compromise of one context's seed does not reveal another context's seed.

```
Game CI_F^A(λ):
  root ←$ {0,1}^λ
  s* ←$ S                                    // challenge info string
  k* = F(root, s*)                           // challenge seed
  b ←$ {0,1}

  // Oracle O_derive(s): on query s ≠ s*, return F(root, s)
  // (models adversary who has compromised other contexts)

  if b = 0:  give A the value k*
  if b = 1:  give A a value k' ←$ {0,1}^n    // uniform random

  b' ← A^{O_derive}(k* or k')
  return (b' == b)
```

**Definition.** A key derivation scheme satisfies **(t, q, ε)-Context Isolation** if for all adversaries A running in time t and making at most q oracle queries:

`Adv_CI(A) = |Pr[CI^A = 1] - 1/2| ≤ ε`

**Reduction.** If HKDF-SHA256 is a (t, q+1, ε_PRF)-secure PRF, then ACE-GF satisfies (t', q, ε_PRF)-Context Isolation where t' ≈ t. The reduction B receives a PRF-or-random challenge, embeds it as k*, and uses the PRF key to answer O_derive queries on distinct info strings. A's advantage in CI is bounded by B's advantage against the PRF, i.e., Adv_CI(A) ≤ Adv_PRF(B) ≤ ε_PRF. ∎

### E.2 Game 2: Cross-Context Linkability (CL)

This game captures Claim 2 (Vault Unlinkability): given two addresses, the adversary cannot determine whether they share a common root.

```
Game CL_F^A(λ):
  root₀, root₁ ←$ {0,1}^λ
  s₁, s₂ ← A(1^λ)                          // adversary chooses two info strings, s₁ ≠ s₂
  b ←$ {0,1}

  if b = 0:                                  // same root
    a₁ = Addr(F(root₀, s₁))
    a₂ = Addr(F(root₀, s₂))
  if b = 1:                                  // independent roots
    a₁ = Addr(F(root₀, s₁))
    a₂ = Addr(F(root₁, s₂))

  b' ← A(a₁, a₂)
  return (b' == b)
```

**Definition.** A key derivation scheme satisfies **(t, ε)-Cross-Context Unlinkability** if for all adversaries A running in time t:

`Adv_CL(A) = |Pr[CL^A = 1] - 1/2| ≤ ε`

**Reduction.** We reduce to PRF security in two steps. First, replace F(root₀, s₁) and F(root₀, s₂) (or F(root₁, s₂)) with independent PRF evaluations. Since s₁ ≠ s₂, in the b=0 case the two outputs are evaluations of the same PRF on distinct inputs, which are indistinguishable from independent random values by PRF security. In the b=1 case the two outputs use independent keys, which are also indistinguishable from random. Thus both worlds produce computationally indistinguishable address pairs: Adv_CL(A) ≤ 2 · Adv_PRF(B) + negl(λ), where the additive term accounts for collisions in AddrDerive. ∎

### E.3 Game 3: Rotation Independence (RI)

This game captures the property that rotating a context string (e.g., incrementing a vault index) produces an address independent of all prior addresses, without requiring a new root.

```
Game RI_F^A(λ):
  root ←$ {0,1}^λ
  b ←$ {0,1}

  // Phase 1: A adaptively queries O_derive(s) for info strings of its choice,
  // receiving a_s = Addr(F(root, s)) for each query. Let Q be the set of queried strings.

  // Phase 2: A submits a challenge info string s* ∉ Q
  if b = 0:  a* = Addr(F(root, s*))          // real derivation
  if b = 1:  a* = Addr(r), r ←$ {0,1}^n      // random address

  b' ← A^{O_derive}(a*)
  return (b' == b)
```

**Definition.** A key derivation scheme satisfies **(t, q, ε)-Rotation Independence** if for all adversaries A running in time t and making at most q queries in total (Phases 1 + 2):

`Adv_RI(A) = |Pr[RI^A = 1] - 1/2| ≤ ε`

**Reduction.** This is a direct consequence of PRF security: A queries the PRF on at most q distinct info strings; the challenge s* is fresh. The reduction B embeds the PRF-or-random challenge at s* and answers all other queries using the PRF oracle. Adv_RI(A) ≤ Adv_PRF(B) ≤ ε_PRF. ∎

### E.4 Relationship to Main Text Claims

| Security Game | Main Text Claim | Formal Bound |
|--------------|----------------|--------------|
| Context Isolation (E.1) | Property 1 (Key Isolation) | Adv_CI ≤ Adv_PRF |
| Cross-Context Linkability (E.2) | Claim 2 (Vault Unlinkability) | Adv_CL ≤ 2·Adv_PRF + negl |
| Rotation Independence (E.3) | Section 5.3 (vault rotation) | Adv_RI ≤ Adv_PRF |

All three reductions are tight (up to a constant factor of 2 in Game 2) and rely solely on the PRF security of HKDF-SHA256 plus the one-wayness of AddrDerive. No additional cryptographic assumptions are introduced beyond those already stated in Section 8.3.
