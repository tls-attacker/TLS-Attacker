# TLS-Attacker Acronyms and Abbreviations

Acronyms and abbreviations used in the TLS-Attacker codebase and in the surrounding TLS
literature you will run into while reading it.

## Message Short Names

The following short names are used for minimal CLI output.

### Handshake Messages

- **CH** - ClientHello
- **SH** - ServerHello
- **HRR** - HelloRetryRequest (a ServerHello carrying the TLS 1.3 HRR random)
- **HR** - HelloRequest
- **HVR** - HelloVerifyRequest (DTLS)
- **CERT** - Certificate
- **CERT_STAT** - CertificateStatus
- **CV** - CertificateVerify
- **CR** - CertificateRequest
- **CKE** - ClientKeyExchange
- **SKE** - ServerKeyExchange
- **SHD** - ServerHelloDone
- **FIN** - Finished
- **EEM** - EncryptedExtensions (TLS 1.3)
- **EOED** - EndOfEarlyData (TLS 1.3)
- **KU** - KeyUpdate (TLS 1.3)
- **ST** - NewSessionTicket
- **SDM** - SupplementalData
- **ECH** - EncryptedClientHello
- **NCID** - NewConnectionId (DTLS 1.3)
- **RCID** - RequestConnectionId (DTLS 1.3)
- **HS(?)** - UnknownHandshakeMessage

### Key-Exchange Variants

`CKE` and `SKE` are prefixed with the key-exchange algorithm:

- **RSA_CKE**, **DH_CKE**, **ECDH_CKE**, **SRP_CKE**, **GOST_CKE**, **PWD_CKE**, **E_CKE** (empty)
- **DH_SKE**, **ECDH_SKE**, **SRP_SKE**, **PWD_SKE**
- **PSK_CKE**, **PSK_RSA_CKE**, **PSK_DH_CKE**, **PSK_ECDH_CKE**
- **PSK_SKE**, **PSK_DHE_SKE**, **PSK_ECDHE_SKE**

### Record Layer

- **CCS** - ChangeCipherSpec
- **HB** - Heartbeat
- **APP** - ApplicationData
- **ACK** - Acknowledgment (DTLS 1.3, content type 26)
- Alerts print the `AlertDescription` name (e.g. `HANDSHAKE_FAILURE`), or `UNKNOWN ALERT`
  when the description byte is unrecognised
- **?** - UnknownMessage; **UnknownSSL2** - UnknownSSL2Message

### SSLv2

- **SSL2_CH** - SSL2 ClientHello
- **SSL2_SH** - SSL2 ServerHello
- **SSL2_CMKM** - SSL2 ClientMasterKey
- **SSL2_SV** - SSL2 ServerVerify

### QUIC Packets and Frames

Packets:

- **IN** - Initial
- **HS** - Handshake
- **RT** - Retry
- **VN** - Version Negotiation
- **0-RTT** / **1-RTT** - ZeroRTT / OneRTT packet
- **SR** - Stateless Reset

Frames:

- **CRY** - Crypto
- **STR** - Stream
- **ACK** - Ack
- **PAD** - Padding
- **PNG** - Ping
- **CC** - Connection Close
- **HD** - Handshake Done
- **NT** - New Token
- **DG** - Datagram
- **RS** - Reset Stream
- **SS** - Stop Sending
- **PC** / **PR** - Path Challenge / Path Response
- **MD** - Max Data
- **MSD** - Max Stream Data
- **MS** - Max Streams
- **DB** - Data Blocked
- **SDB** - Stream Data Blocked
- **SB** - Streams Blocked
- **NCID** / **RCID** - New / Retire Connection ID (QUIC frames; the same two abbreviations are
  used for the DTLS 1.3 NewConnectionId and RequestConnectionId messages)

## Cryptographic Algorithms

### Key Exchange

- **RSA** - Rivest-Shamir-Adleman
- **DH** / **DHE** - Diffie-Hellman / Diffie-Hellman Ephemeral
- **FFDHE** - Finite Field Diffie-Hellman Ephemeral
- **ECDH** / **ECDHE** - Elliptic Curve Diffie-Hellman / Ephemeral
- **PSK** - Pre-Shared Key
- **SRP** - Secure Remote Password
- **PWD** - Password-authenticated key exchange (TLS-PWD)
- **GOST** - Russian cryptographic standards (Государственный стандарт)
- **KEM** - Key Encapsulation Mechanism
- **ML-KEM** - Module-Lattice Key Encapsulation Mechanism (FIPS 203)

### Signature Algorithms

- **DSA** - Digital Signature Algorithm
- **ECDSA** - Elliptic Curve Digital Signature Algorithm
- **RSA-PSS** - RSA Probabilistic Signature Scheme

### Hash Functions

- **MD5** - Message Digest 5
- **SHA** - Secure Hash Algorithm
- **SHA-1**, **SHA-256/384/512** - SHA-1 and SHA-2 family variants

### Symmetric Ciphers

- **AES** - Advanced Encryption Standard
- **DES** / **3DES** - Data Encryption Standard / Triple DES
- **RC4** - Rivest Cipher 4
- **ChaCha20** - ChaCha stream cipher with 20 rounds

### Cipher Modes

- **CBC** - Cipher Block Chaining
- **GCM** - Galois/Counter Mode
- **CCM** - Counter with CBC-MAC
- **CTR** - Counter Mode

### MAC and AEAD

- **MAC** - Message Authentication Code
- **HMAC** - Hash-based Message Authentication Code
- **AEAD** - Authenticated Encryption with Associated Data
- **Poly1305** - Polynomial MAC

## TLS Extensions

- **SNI** - Server Name Indication
- **ESNI** - Encrypted Server Name Indication
- **ECH** - Encrypted Client Hello
- **ALPN** - Application-Layer Protocol Negotiation
- **SCT** - Signed Certificate Timestamp
- **EMS** - Extended Master Secret
- **ETM** - Encrypt-then-MAC
- **CID** - Connection ID (DTLS)
- **SRTP** - Secure Real-time Transport Protocol (`USE_SRTP`)
- **0-RTT** - Zero Round Trip Time; the TLS 1.3 early-data mode, carried by the `EARLY_DATA`
  extension (also a QUIC packet short name, see above)

## Certificate and PKI

- **CA** - Certificate Authority
- **CSR** - Certificate Signing Request
- **CRL** - Certificate Revocation List
- **OCSP** - Online Certificate Status Protocol
- **CT** - Certificate Transparency (note: the Certificate *message* is `CERT`, not `CT`)
- **SCT** - Signed Certificate Timestamp
- **OID** - Object Identifier
- **DN** - Distinguished Name (see `DistinguishedName` in the X.509 handling)
- **RDN** - Relative Distinguished Name
- **CN** - Common Name
- **SAN** - Subject Alternative Name
- **KU** / **EKU** - Key Usage / Extended Key Usage (certificate extensions; distinct from the
  `KU` KeyUpdate message short name above)
- **AKI** / **SKI** - Authority / Subject Key Identifier
- **PKI** - Public Key Infrastructure

## Encoding and Formats

- **ASN.1** - Abstract Syntax Notation One
- **DER** - Distinguished Encoding Rules
- **PEM** - Privacy-Enhanced Mail
- **PKCS** - Public Key Cryptography Standards
- **X.509** - Digital certificate standard

## Elliptic Curves

- **ECC** / **EC** - Elliptic Curve Cryptography / Elliptic Curve
- **SECP** - SECG prime curves (`SECP256R1`, `SECP384R1`, `SECP521R1`), equal to the NIST
  P-256/P-384/P-521 curves
- **X25519** / **X448** - Montgomery curves for ECDH

## Protocol Versions

- **SSL** - Secure Sockets Layer
- **TLS** - Transport Layer Security
- **DTLS** - Datagram Transport Layer Security
- **QUIC** - transport protocol over UDP (RFC 9000; not an acronym)

## Miscellaneous

- **PRF** - Pseudo-Random Function
- **KDF** - Key Derivation Function
- **HKDF** - HMAC-based Key Derivation Function
- **IV** - Initialization Vector
- **PMS** / **MS** - Premaster Secret / Master Secret
- **PFS** - Perfect Forward Secrecy
- **MITM** - Man-in-the-Middle (see the `TLS-Mitm` module)
- **GREASE** - Generate Random Extensions And Sustain Extensibility (RFC 8701)
- **PSS** - Probabilistic Signature Scheme
- **MGF** - Mask Generation Function
- **OAEP** - Optimal Asymmetric Encryption Padding

## Project Modules and Dependencies

Modules (see the root `pom.xml`):

- **TLS-Core** - protocol messages, handlers, parsers, serializers, workflow engine
- **TLS-Client** / **TLS-Server** - command-line client and server
- **TLS-Mitm** / **TLS-Proxy** - man-in-the-middle and proxy runners
- **TraceTool** - workflow-trace inspection tool
- **Transport** / **Utils** - transport handlers and shared utilities

Sibling libraries from the same project family:

- **modifiable-variable** - the `ModifiableVariable` types used to mutate message fields
- **protocol-attacker** - shared protocol-layer abstractions
- **x509-attacker** / **asn1-attacker** - certificate and ASN.1 handling
- **tls-docker-library** - server images used by the integration tests

## Attack Names

General TLS attack acronyms. Those with a footprint in this repository are marked.

- **BEAST** - Browser Exploit Against SSL/TLS
- **CRIME** - Compression Ratio Info-leak Made Easy
- **BREACH** - Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext
- **POODLE** - Padding Oracle On Downgraded Legacy Encryption
- **DROWN** - Decrypting RSA with Obsolete and Weakened eNcryption
- **ROBOT** - Return Of Bleichenbacher's Oracle Threat
- **SLOTH** - Security Losses from Obsolete and Truncated Transcript Hashes
- **FREAK** - Factoring RSA Export Keys
- **Logjam** - DH downgrade to export-grade parameters
- **Sweet32** - birthday attack on 64-bit block ciphers (3DES, Blowfish)
- **Lucky13** - CBC padding timing attack
- **Heartbleed** - OpenSSL heartbeat buffer over-read
- **Raccoon** - timing attack on DH premaster secrets

