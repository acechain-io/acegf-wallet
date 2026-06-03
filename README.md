# ACE-GF — Atomic Cryptographic Entity Generative Framework

> **One Mnemonic. Zero Paths. N Isolated Curves.**
> *Source-available cryptographic primitive for Web3 infrastructure*

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue)](LICENSE)

---

## Licensing

> **Important Legal Notice**
> This is a **source-available reference implementation** under the **Business Source License 1.1 (BUSL-1.1)**.

---

## 1. Key Advantages — What ACE-GF Brings

ACE-GF provides a rethought deterministic-root architecture tailored for multi-chain, multi-curve, and post-quantum readiness. Its design centers on entropy separation, context isolation, and minimized runtime exposure of sensitive material.

| Dimension | Conventional Model | ACE-GF Advantage |
|-----------|--------------------|-------------------|
| **Seed Architecture** | Single mnemonic → single seed | Multi-stream entropy separation with context isolation |
| **Curve Dependence** | Seed tightly bound to one curve (e.g., secp256k1) | Dedicated derivation streams for Ed25519, secp256k1, X25519, and PQC-ready curves |
| **Derivation Paths** | BIP-32/44 hierarchical paths | Zero path exposure — no HD-path enumeration surface |
| **Passphrase Handling** | Plaintext or transient seed in RAM | Argon2id-sealed High-Entropy Anchor Identifier (HEAI) + enforced zeroization |
| **Quantum Transition** | Whole-wallet rekey required | Modular HKDF streams allow PQC extension without invalidating historic keys |

**Result:** a single root (or sealed anchor) can deterministically produce multiple isolated key families, reduce systemic correlation risks, and support smooth migration toward post-quantum algorithms.

---

## 2. Why ACE-GF — Problem Statement & Design Rationale

Modern deterministic wallets and key management systems carry structural coupling that creates persistent risk:

- **Mnemonic coupling:** one entropy source maps to many curves/protocols, enabling cross-curve correlation.
- **Path leakage:** derivation paths reveal structure and enable enumeration or correlation attacks.
- **Memory exposure:** passphrases or master seeds often appear in RAM or swap during lifecycle events.
- **Quantum migration friction:** introducing PQC typically forces key rotation or complex migration that can break continuity.

ACE-GF addresses these by introducing **context-isolated HKDF streams** and a **sealed High-Entropy Anchor Identifier (HEAI)**. The architecture decouples entropy domains (identity, encryption, signature), eliminates HD-path attack surfaces, and reserves a modular stream for PQC primitives so the system can adopt post-quantum algorithms by updating HKDF info/labels — without invalidating prior keys or forcing wholesale migration.

Our goal is to establish ACE-GF as a **transparent, auditable foundation for deterministic key management** that helps the industry adopt improved security architectures and enables a practical, low-friction transition toward post-quantum cryptography.

---

## 3. Open Review & Feedback Invitation

We invite **cryptographers, wallet teams, security researchers, and Web3 infrastructure engineers** to review the implementation and provide feedback.

This repository contains a **reference implementation** in Rust (~820 LOC). The implementation is organized to be readable and reproducible so researchers and implementers can validate the design, reproduce results, and suggest improvements.

**We welcome feedback on:**
- HKDF stream isolation and cross-curve entropy separation
- Memory safety and zeroization behavior in FFI and runtime contexts
- Argon2id + AES-GCM sealing parameter choices and lifecycle handling
- Formal verification models, threat modeling, and implementation hardening
- Integration experience for C / WASM / JS bindings or PQC extensions

We ask reviewers to **give us feedback**: bug reports, design critiques, proofs-of-concept, formal models, or implementation notes are all highly valuable. We are committed to constructive follow-up and further technical collaboration with teams or researchers who contribute substantive technical findings.

→ Submit feedback or reports to [contact@acegf.com](mailto:contact@acegf.com) or via [GitHub Security Advisory](.github/SECURITY.md). See the SECURITY.md for disclosure guidelines.

> **Together, we aim to build a clearer, more resilient deterministic root for the post-quantum era.**

---

## 4. Technical Overview

**Language**: Rust (with safe FFI bindings for C/WASM/JS)
**Core Size**: ~820 LOC (derivation + FFI + tests)

### Key Components

- `src/lib.rs` — Module entry point; exports core structs and utilities (`ACEGF`, `SealedUuid`, `PassphraseSealingUtil`)
- `src/acegf.rs` — Implements **multi-stream HKDF derivation** and **curve-isolated key generation** (ed25519, secp256k1, x25519)
- `src/passphrase_sealing_util.rs` — Implements **HEAI sealing**, **Argon2id + AES-GCM encryption**, **DoS resistance**, and **secure memory zeroization**

### Build
```bash
cargo build --release
```
