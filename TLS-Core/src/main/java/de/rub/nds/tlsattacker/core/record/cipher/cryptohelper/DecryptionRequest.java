/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher.cryptohelper;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class DecryptionRequest {

    private final byte[] additionalAuthenticatedData;

    private final byte[] cipherText;

    private final ConnectionEndType connectionEndType;

    public DecryptionRequest(byte[] additionalAuthenticatedData, byte[] cipherText, ConnectionEndType connectionEndType) {
        this.additionalAuthenticatedData = additionalAuthenticatedData;
        this.cipherText = cipherText;
        this.connectionEndType = connectionEndType;
    }

    public byte[] getAdditionalAuthenticatedData() {
        return additionalAuthenticatedData;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public ConnectionEndType getConnectionEndType() {
        return connectionEndType;
    }
}
