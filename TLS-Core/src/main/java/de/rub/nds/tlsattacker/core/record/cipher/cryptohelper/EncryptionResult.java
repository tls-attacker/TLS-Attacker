/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher.cryptohelper;

import de.rub.nds.modifiablevariable.util.ArrayConverter;

public class EncryptionResult {

    private final byte[] initialisationVector;

    private final byte[] encryptedCipherText;

    private final boolean explicitIv;

    public EncryptionResult(byte[] initialisationVector, byte[] encryptedCipherText, boolean explicitIv) {
        this.initialisationVector = initialisationVector;
        this.encryptedCipherText = encryptedCipherText;
        this.explicitIv = explicitIv;
    }

    public EncryptionResult(byte[] encryptedCipherText) {
        this.initialisationVector = null;
        this.encryptedCipherText = encryptedCipherText;
        this.explicitIv = false;
    }

    public byte[] getInitialisationVector() {
        return initialisationVector;
    }

    public byte[] getEncryptedCipherText() {
        return encryptedCipherText;
    }

    public boolean isExplicitIv() {
        return explicitIv;
    }

    public byte[] getCompleteEncryptedCipherText() {
        if (explicitIv) {
            return ArrayConverter.concatenate(initialisationVector, encryptedCipherText);
        } else {
            return encryptedCipherText;
        }
    }
}
