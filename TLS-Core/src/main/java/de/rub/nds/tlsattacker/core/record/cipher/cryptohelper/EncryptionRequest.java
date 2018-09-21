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

    private final byte[] additionalAuthenticatedData;

    public EncryptionRequest(byte[] plainText, byte[] initialisationVector, byte[] additionalAuthenticatedData) {
        this.plainText = plainText;
        this.initialisationVector = initialisationVector;
        this.additionalAuthenticatedData = additionalAuthenticatedData;
    }

    public byte[] getPlainText() {
        return plainText;
    }

    public byte[] getInitialisationVector() {
        return initialisationVector;
    }

    public byte[] getAdditionalAuthenticatedData() {
        return additionalAuthenticatedData;
    }
}
