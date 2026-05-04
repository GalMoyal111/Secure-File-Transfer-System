# Secure-File-Transfer-System

## Overview
Implementation of a secure file transfer protocol between two parties (Alice and Bob) over an untrusted network.

The system combines authentication, key exchange, encryption, and integrity verification into a complete end-to-end flow.

---

## Features
- User authentication with SHA-256 password hashing  
- Authenticated key exchange using ECDH (secp256k1)  
- Digital signatures using ElGamal (ffdhe2048)  
- **Custom implementation of ARIA-128 (CBC mode)**  
- Integrity protection via signed payload (IV + plaintext)  

---

## Flow
1. Login  
2. Signed ECDH key exchange  
3. Shared key derivation  
4. File encryption (ARIA-CBC)  
5. Signature verification and decryption  
