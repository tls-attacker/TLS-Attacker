/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.constants.BulkCipherAlgorithm;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.crypto.Cipher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class RecordCipher {

    protected static final Logger LOGGER = LogManager.getLogger(RecordCipher.class.getName());
    /**
     * minimalRecordLength an encrypted record should have
     */
    private int minimalEncryptedRecordLength;
    /**
     * additional authenticated data
     */
    protected byte[] aad;
    /**
     * cipher for decryption
     */
    protected Cipher decryptCipher;
    /**
     * cipher for encryption
     */
    protected Cipher encryptCipher;
    /**
     * CipherAlgorithm algorithm (AES, ...)
     */
    protected BulkCipherAlgorithm bulkCipherAlg;
    /**
     * client encryption key
     */
    protected byte[] clientWriteKey;
    /**
     * server encryption key
     */
    protected byte[] serverWriteKey;
    /**
     * TLS context
     */
    protected TlsContext tlsContext;

    public RecordCipher(int minimalEncryptedRecordLength) {
        this.minimalEncryptedRecordLength = minimalEncryptedRecordLength;
    }

    public abstract byte[] encrypt(byte[] data);

    public abstract byte[] decrypt(byte[] data);

    public abstract boolean isUsingPadding();

    public abstract boolean isUsingMac();

    public byte[] calculateMac(byte[] data) {
        return new byte[0];
    }

    public int getMacLength() {
        return 0;
    }

    public byte[] calculatePadding(int paddingLength) {
        return new byte[0];
    }

    public int calculatePaddingLength(int dataLength) {
        return 0;
    }

    public int getMinimalEncryptedRecordLength() {
        return minimalEncryptedRecordLength;
    }

    public void setMinimalEncryptedRecordLength(int minimalEncryptedRecordLength) {
        this.minimalEncryptedRecordLength = minimalEncryptedRecordLength;
    }

    public void setAad(byte[] aad) {
        this.aad = aad;
    }

    public byte[] getAad() {
        return aad;
    }

    /**
     * This function computes the difference between the plaintext size and the
     * size of the encrypted payload. In case of AES-CBC cipher suites, it
     * returns a sum of the IV length and MAC length. In case of AEAD cipher
     * suites, it sums the IV length and tag length.
     * 
     * This functionality is needed when decrypting and verifying records. The
     * number used for MAC/GMAC computation is based on the plaintext length
     * (and not the ciphertext length).
     * 
     * @return
     */
    public int getPlainCipherLengthDifference() {
        return 0;
    }
}
