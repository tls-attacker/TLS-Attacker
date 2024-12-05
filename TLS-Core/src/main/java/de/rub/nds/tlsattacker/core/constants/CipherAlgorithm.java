/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

/** Symmetric cipher algorithm and its mapping to Java names */
public enum CipherAlgorithm {
    NULL(0, 0, 0, 0),
    RC2_40(5, 8, 0, 8, "RC2/CBC/NoPadding", true), // TODO Not sure this is correct
    RC2_128(16, 8, 0, 8, "RC2/CBC/NoPadding", false),
    RC4_128(16, 0, 0, 0, "RC4", false),
    DES_CBC(8, 8, 0, 8, "DES/CBC/NoPadding", false),
    DES_EDE_CBC(24, 8, 0, 8, "DESede/CBC/NoPadding", false),
    AES_128_CBC(16, 16, 0, 16, "AES/CBC/NoPadding", false),
    AES_256_CBC(32, 16, 0, 16, "AES/CBC/NoPadding", false),
    AES_128_GCM(16, 4, 8, 16, "AES/GCM/NoPadding", false),
    AES_256_GCM(32, 4, 8, 16, "AES/GCM/NoPadding", false),
    CAMELLIA_128_CBC(16, 16, 0, 16, "Camellia/CBC/NoPadding", false),
    CAMELLIA_256_CBC(32, 16, 0, 16, "Camellia/CBC/NoPadding", false),
    CAMELLIA_128_GCM(16, 16, 8, 16, "Camellia/GCM/NoPadding", false),
    CAMELLIA_256_GCM(32, 16, 8, 16, "Camellia/GCM/NoPadding", false),
    IDEA_128(16, 8, 0, 8, "IDEA/CBC/NoPadding", false),
    SEED_CBC(16, 16, 0, 16, "SEED/CBC/NoPadding", false),
    AES_128_CCM(16, 4, 8, 16, "AES/CCM/NoPadding", false),
    AES_256_CCM(32, 4, 8, 16, "AES/CCM/NoPadding", false),
    CHACHA20_POLY1305(32, 12, 0, 0, "ChaCha20-Poly1305", false),
    UNOFFICIAL_CHACHA20_POLY1305(32, 12, 0, 0, "ChaCha20-Poly1305", false),
    DES40_CBC(8, 8, 0, 8, "DES/CBC/NoPadding", true),
    ARIA_128_CBC(16, 16, 0, 16, "ARIA/CBC/NoPadding", false),
    ARIA_256_CBC(32, 16, 0, 16, "ARIA/CBC/NoPadding", false),
    ARIA_128_GCM(16, 16, 8, 16, "ARIA/GCM/NoPadding", false),
    ARIA_256_GCM(32, 16, 8, 16, "ARIA/GCM/NoPadding", false),
    GOST_28147_CNT_IMIT(32, 8, 0, 8, "GOST28147/ECB/NoPadding", false),
    FORTEZZA_CBC(0, 0, 0, 0), // TODO
    AES_128_CTR(16, 16, 0, 0, "AES/CTR/NoPadding", false),
    AES_256_CTR(32, 16, 0, 0, "AES/CTR/NoPadding", false),
    RABBIT_CBC(16, 8, 0, 8), // TODO Not sure this is correct
    SM4_GCM(16, 4, 8, 16, "SM4/GCM/NoPadding", false),
    SM4_CCM(16, 4, 8, 16, "SM4/CCM/NoPadding", false),
    RC4_40(5, 0, 0, 0, "RC4", true), // TODO check
    RC4_56(7, 0, 0, 0, "RC4", true), // TODO check
    RC2_56(7, 8, 0, 8, "RC2/CBC/NoPadding", true), // TODO check
    AES_128_CCM_8(16, 4, 8, 16, "AES/CCM/NoPadding", false), // TODO check
    AES_256_CCM_8(32, 4, 8, 16, "AES/CCM/NoPadding", false); // TODO check

    CipherAlgorithm(
            int keySize,
            int nonceBytesFromHandshake,
            int nonceBytesFromRecord,
            int blocksize,
            String javaName,
            boolean export) {
        this.keySize = keySize;
        this.javaName = javaName;
        this.nonceBytesFromHandshake = nonceBytesFromHandshake;
        this.nonceBytesFromRecord = nonceBytesFromRecord;
        this.blocksize = blocksize;
        this.export = export;
    }

    CipherAlgorithm(
            int keySize, int nonceBytesFromHandshake, int nonceBytesFromRecord, int blocksize) {
        this.keySize = keySize;
        this.javaName = null;
        this.nonceBytesFromHandshake = nonceBytesFromHandshake;
        this.nonceBytesFromRecord = nonceBytesFromRecord;
        this.blocksize = blocksize;
        this.export = false;
    }

    /** Key size for the underlying cipher */
    private final int keySize;

    /**
     * Number of bytes taken from the handshake and used as an initialization vector / nonce input
     * into the cipher (i.e., number of bytes in server_write_IV / client_write_IV)
     */
    private final int nonceBytesFromHandshake;

    /** Number of bytes generated with each new record. */
    private final int nonceBytesFromRecord;

    private final int blocksize;

    /** java name mapping */
    private final String javaName;

    private final boolean export;

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

    public int getBlocksize() {
        return blocksize;
    }

    public boolean isExport()
    {
        return export;
    }
}
