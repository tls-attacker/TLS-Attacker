/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.cipher;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class RecordNullCipher extends RecordCipher {

    public RecordNullCipher() {
        super(0, false, false);
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
    public byte[] calculateMac(byte[] data) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int getMacLength() {
        return 0;
    }

    @Override
    public byte[] calculatePadding(int paddingLength) {
        return new byte[0];
    }

    @Override
    public int getPaddingLength(int dataLength) {
        return 0;
    }

}
