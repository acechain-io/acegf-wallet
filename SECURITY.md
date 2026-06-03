# ACE-GF Security Policy

## Overview
ACE-GF is designed as a **cryptographic primitive** for deterministic key management.
Its reference implementation in Rust is intended for open review, formal verification, and
security research under a noncommercial license.

We take potential vulnerabilities seriously and encourage responsible disclosure.

---

## Reporting a Vulnerability

If you discover a potential security issue, please contact us directly **before publicly disclosing** it.

### Contact
**Email:** contact@acegf.com
**Subject:** `[SECURITY] Vulnerability Report - ACE-GF`

Alternatively, we recommend submitting your report via Yallet, by sending an NFT Message (available on the Apple App Store and Google Play Store) for secure and verifiable delivery.
We will acknowledge receipt within 3 business days and work with you to verify and assess the issue.

---

## Responsible Disclosure Policy

- Do not publicly disclose or share exploit details until we have confirmed and remediated the issue.
- Do not attempt to exploit, attack, or misuse live deployments using this code.
- Coordinated disclosure ensures the safety of downstream users and the integrity of the open review process.

---

## Scope

Reports are welcome for:
- HKDF stream isolation and cross-domain entropy separation flaws;
- Argon2id or AES-GCM parameter weaknesses;
- Memory zeroization or unsafe FFI exposure vulnerabilities;
- Logical or cryptographic flaws in key derivation or sealing routines.

Out of scope:
- Non-security bugs, documentation issues, or build system errors (use GitHub Issues instead).

---

## Commitment

ACE-GF Labs commits to:
- Transparency in the security review and resolution process;
- Collaboration with security researchers and cryptographers;
- Maintaining the reference implementation as a reliable, auditable foundation for future standards.

Together, we aim to establish a stronger deterministic security root for the post-quantum era.
