/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.crypto;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class TlsRecordCipher {

    /**
     * minimalRecordLength an encrypted record should have
     */
    int minimalEncryptedRecordLength;

    public abstract void init();

    public int getMinimalEncryptedRecordLength() {
	return minimalEncryptedRecordLength;
    }

    public void setMinimalEncryptedRecordLength(int minimalEncryptedRecordLength) {
	this.minimalEncryptedRecordLength = minimalEncryptedRecordLength;
    }

}
