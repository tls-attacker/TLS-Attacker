/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher.cryptohelper;

public class EncryptionRequest {

    private final byte[] plainText;

    private final byte[] initialisationVector;

    public EncryptionRequest(byte[] plainText, byte[] initialisationVector) {
        this.plainText = plainText;
        this.initialisationVector = initialisationVector;
    }

    public EncryptionRequest(byte[] plainText) {
        this.plainText = plainText;
        this.initialisationVector = null;
    }

    public byte[] getPlainText() {
        return plainText;
    }

    public byte[] getInitialisationVector() {
        return initialisationVector;
    }
}
