/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher.cryptohelper;

public class DecryptionRequest {

    private final byte[] additionalAuthenticatedData;

    private final byte[] cipherText;

    public DecryptionRequest(byte[] additionalAuthenticatedData, byte[] cipherText) {
        this.additionalAuthenticatedData = additionalAuthenticatedData;
        this.cipherText = cipherText;
    }

    public byte[] getAdditionalAuthenticatedData() {
        return additionalAuthenticatedData;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

}
