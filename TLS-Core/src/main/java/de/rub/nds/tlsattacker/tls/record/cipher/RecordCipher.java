/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.cipher;

import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class RecordCipher {

    /**
     * minimalRecordLength an encrypted record should have
     */
    private int minimalEncryptedRecordLength;

    private boolean usePadding;

    private boolean useMac;

    public RecordCipher(int minimalEncryptedRecordLength, boolean usePadding, boolean useMac) {
        this.minimalEncryptedRecordLength = minimalEncryptedRecordLength;
        this.usePadding = usePadding;
        this.useMac = useMac;
    }

    public abstract byte[] encrypt(byte[] data);

    public abstract byte[] decrypt(byte[] data);

    public abstract byte[] calculateMac(byte[] data);

    public abstract byte[] calculatePadding(int paddingLength);

    public boolean isUsePadding() {
        return usePadding;
    }

    public boolean isUseMac() {
        return useMac;
    }

    public abstract int getMacLength();

    public abstract int getPaddingLength(int dataLength);

    public int getMinimalEncryptedRecordLength() {
        return minimalEncryptedRecordLength;
    }

    public void setMinimalEncryptedRecordLength(int minimalEncryptedRecordLength) {
        this.minimalEncryptedRecordLength = minimalEncryptedRecordLength;
    }

}
