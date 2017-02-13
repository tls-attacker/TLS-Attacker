/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.constants;

/**
 * Symmetric cipher algorithm and its mapping to Java names
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum CipherAlgorithm {

    NULL(0, 0, 0, ""),
    RC2_128(16, 0, 0, "RC2/CBC/NoPadding"),
    RC4_128(16, 0, 0, "RC4"),
    DES_CBC(8, 8, 0, "DES/CBC/NoPadding"),
    DES_EDE_CBC(24, 8, 0, "DESede/CBC/NoPadding"),
    AES_128_CBC(16, 16, 0, "AES/CBC/NoPadding"),
    AES_256_CBC(32, 16, 0, "AES/CBC/NoPadding"),
    AES_128_GCM(16, 4, 8, "AES/GCM/NoPadding"),
    AES_256_GCM(32, 4, 8, "AES/GCM/NoPadding"),
    CAMELLIA_128_CBC(16, 16, 0, "Camellia/CBC/NoPadding"),
    CAMELLIA_256_CBC(32, 16, 0, "Camellia/CBC/NoPadding"),
    IDEA_128(16, 16, 0, "IDEA/CBC/NoPadding"),
    SEED_CBC(16, 16, 0, "SEED/CBC/NoPadding"), // TODO this is not verified
    AES_128_CCM(16, 4, 8, "AES/CCM/NoPadding"),
    AES_256_CCM(32, 4, 8, "AES/CCM/NoPadding"),
    ChaCha20Poly1305(32, 12, 0, "ChaCha"),
    DES40_CBC(5, 5, 0, "DES/CBC/NoPadding"); // TODO THIS IS NOT VERIFIED

    CipherAlgorithm(int keySize, int nonceBytesFromHandshake, int nonceBytesFromRecord, String javaName) {
        this.keySize = keySize;
        this.javaName = javaName;
        this.nonceBytesFromHandshake = nonceBytesFromHandshake;
        this.nonceBytesFromRecord = nonceBytesFromRecord;
    }

    /**
     * Key size for the underlying cipher
     */
    private final int keySize;

    /**
     * Number of bytes taken from the handshake and used as an initialization
     * vector / nonce input into the cipher (i.e., number of bytes in
     * server_write_IV / client_write_IV)
     */
    private final int nonceBytesFromHandshake;

    /**
     * Number of bytes generated with each new record.
     */
    private final int nonceBytesFromRecord;

    /**
     * java name mapping
     */
    private final String javaName;

    public int getKeySize() {
        return keySize;
    }

    public String getJavaName() {
        return javaName;
    }

    public int getNonceBytesFromHandshake() {
        return nonceBytesFromHandshake;
    }

    public int getNonceBytesFromRecord() {
        return nonceBytesFromRecord;
    }
}
