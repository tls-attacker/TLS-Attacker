/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class TlsRecordCipher {

    /**
     * minimalRecordLength an encrypted record should have
     */
    int minimalEncryptedRecordLength;

    public abstract void init() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException ;

    public int getMinimalEncryptedRecordLength() {
	return minimalEncryptedRecordLength;
    }

    public void setMinimalEncryptedRecordLength(int minimalEncryptedRecordLength) {
	this.minimalEncryptedRecordLength = minimalEncryptedRecordLength;
    }

}
