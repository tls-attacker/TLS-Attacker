# TLS-Attacker Acronyms and Abbreviations

This document provides a comprehensive list of acronyms and abbreviations used throughout the TLS-Attacker project.

## TLS Protocol Messages

### Handshake Messages

- **CH** - Client Hello
- **SH** - Server Hello
- **HRR** - Hello Retry Request (TLS 1.3)
- **EE** - Encrypted Extensions (TLS 1.3)
- **CT** - Certificate (sometimes used as abbreviation)
- **CV** - Certificate Verify
- **CKE** - Client Key Exchange
- **SKE** - Server Key Exchange
- **CR** - Certificate Request
- **SHD** - Server Hello Done
- **CC** - Certificate Chain
- **NST** - New Session Ticket
- **KU** - Key Update (TLS 1.3)
- **EOD** - End of Early Data (TLS 1.3)

### Record Layer

- **CCS** - Change Cipher Spec
- **HB** - Heartbeat
- **APP** - Application Data
- **ACK** - Acknowledgment (TLS 1.3)

## Cryptographic Algorithms

### Key Exchange

- **RSA** - Rivest-Shamir-Adleman
- **DH** - Diffie-Hellman
- **DHE** - Diffie-Hellman Ephemeral
- **ECDH** - Elliptic Curve Diffie-Hellman
- **ECDHE** - Elliptic Curve Diffie-Hellman Ephemeral
- **PSK** - Pre-Shared Key
- **SRP** - Secure Remote Password
- **GOST** - Russian cryptographic standards (Государственный стандарт)

### Signature Algorithms

- **DSA** - Digital Signature Algorithm
- **ECDSA** - Elliptic Curve Digital Signature Algorithm
- **EdDSA** - Edwards-curve Digital Signature Algorithm
- **RSA-PSS** - RSA Probabilistic Signature Scheme

### Hash Functions

- **MD5** - Message Digest 5
- **SHA** - Secure Hash Algorithm
- **SHA-1** - Secure Hash Algorithm 1
- **SHA-256/384/512** - SHA-2 family variants

### Symmetric Ciphers

- **AES** - Advanced Encryption Standard
- **DES** - Data Encryption Standard
- **3DES** - Triple DES
- **RC4** - Rivest Cipher 4
- **ChaCha20** - ChaCha stream cipher with 20 rounds

### Cipher Modes

- **CBC** - Cipher Block Chaining
- **GCM** - Galois/Counter Mode
- **CCM** - Counter with CBC-MAC
- **CTR** - Counter Mode
- **ECB** - Electronic Codebook (not used in TLS)

### MAC Algorithms

- **MAC** - Message Authentication Code
- **HMAC** - Hash-based Message Authentication Code
- **AEAD** - Authenticated Encryption with Associated Data
- **Poly1305** - Polynomial MAC

## TLS Extensions

- **SNI** - Server Name Indication
- **ALPN** - Application-Layer Protocol Negotiation
- **NPN** - Next Protocol Negotiation (deprecated)
- **OCSP** - Online Certificate Status Protocol
- **SCT** - Signed Certificate Timestamp
- **HPKP** - HTTP Public Key Pinning
- **HSTS** - HTTP Strict Transport Security
- **EMS** - Extended Master Secret
- **ETM** - Encrypt-then-MAC
- **0-RTT** - Zero Round Trip Time (TLS 1.3)

## Certificate and PKI

- **CA** - Certificate Authority
- **CSR** - Certificate Signing Request
- **CRL** - Certificate Revocation List
- **OID** - Object Identifier
- **DN** - Distinguished Name
- **CN** - Common Name
- **SAN** - Subject Alternative Name
- **EKU** - Extended Key Usage
- **AKI** - Authority Key Identifier
- **SKI** - Subject Key Identifier

## Encoding and Formats

- **ASN.1** - Abstract Syntax Notation One
- **DER** - Distinguished Encoding Rules
- **PEM** - Privacy-Enhanced Mail
- **PKCS** - Public Key Cryptography Standards
- **X.509** - Digital certificate standard

## Elliptic Curves

- **ECC** - Elliptic Curve Cryptography
- **EC** - Elliptic Curve
- **NIST** - National Institute of Standards and Technology
- **P-256/384/521** - NIST curve designations
- **secp256r1/384r1/521r1** - SECG curve names (same as NIST P-curves)
- **X25519/X448** - Montgomery curves for ECDH

## Protocol Versions

- **SSL** - Secure Sockets Layer
- **TLS** - Transport Layer Security
- **DTLS** - Datagram Transport Layer Security
- **QUIC** - Quick UDP Internet Connections

## Miscellaneous

- **PRF** - Pseudo-Random Function
- **KDF** - Key Derivation Function
- **PFS** - Perfect Forward Secrecy
- **MITM** - Man-in-the-Middle
- **GREASE** - Generate Random Extensions And Sustain Extensibility
- **CID** - Connection ID (DTLS)
- **ECH** - Encrypted Client Hello
- **PSS** - Probabilistic Signature Scheme
- **MGF** - Mask Generation Function
- **OAEP** - Optimal Asymmetric Encryption Padding

## TLS-Attacker Specific

- **MV** - ModifiableVariable
- **PA** - Protocol-Attacker
- **TA** - TLS-Attacker
- **WFT** - WorkflowTrace

## Attack Names

- **BEAST** - Browser Exploit Against SSL/TLS
- **CRIME** - Compression Ratio Info-leak Made Easy
- **BREACH** - Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext
- **POODLE** - Padding Oracle On Downgraded Legacy Encryption
- **DROWN** - Decrypting RSA with Obsolete and Weakened eNcryption
- **ROBOT** - Return Of Bleichenbacher's Oracle Threat
- **SLOTH** - Security Losses from Obsolete and Truncated Transcript Hashes

## Common Usage Examples in Code

When you encounter these acronyms in the codebase, they typically appear in:

1. **Message class names**: `ClientHelloMessage`, `ServerKeyExchangeMessage`
2. **Handler classes**: `CHHandler`, `SKEHandler`
3. **Serializer/Parser classes**: `CHSerializer`, `SKEParser`
4. **Test classes**: `CHTest`, `SKETest`
5. **Configuration parameters**: `defaultCHCipherSuites`, `includeSKE`

## Notes

- Some acronyms may have multiple meanings depending on context
- TLS 1.3 introduced new message types and removed some older ones
- This list focuses on acronyms commonly used in the TLS-Attacker codebase
- When in doubt, check the context or the full class/method name for clarification

