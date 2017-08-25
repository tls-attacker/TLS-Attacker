/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class RecordNullCipher extends RecordCipher {

    public RecordNullCipher() {
        super(0);
    }

    /**
     * Null Cipher just passes the data through
     *
     * @param data
     * @return
     */
    @Override
    public byte[] encrypt(byte[] data) {
        return data;
    }

    /**
     * Null Cipher just passes the data through
     *
     * @param data
     * @return
     */
    @Override
    public byte[] decrypt(byte[] data) {
        return data;
    }

    @Override
    public boolean isUsingPadding() {
        return false;
    }

    @Override
    public boolean isUsingMac() {
        return false;
    }

}
