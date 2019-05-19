/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher.cryptohelper;

public class DecryptionResult {

    private final byte[] initialisationVector;

    private final byte[] decryptedCipherText;

    private final Boolean explicitIv;

    private final boolean isSuccessful;

    public DecryptionResult(byte[] initialisationVector, byte[] decryptedCipherText, Boolean explicitIv,
            boolean isSuccessful) {
        this.initialisationVector = initialisationVector;
        this.decryptedCipherText = decryptedCipherText;
        this.explicitIv = explicitIv;
        this.isSuccessful = isSuccessful;
    }

    public byte[] getInitialisationVector() {
        return initialisationVector;
    }

    public byte[] getDecryptedCipherText() {
        return decryptedCipherText;
    }

    public Boolean isExplicitIv() {
        return explicitIv;
    }

    /**
     * True if the decryption was successful, false otherwise.
     */
    public boolean isSuccessful() {
        return isSuccessful;
    }
}
