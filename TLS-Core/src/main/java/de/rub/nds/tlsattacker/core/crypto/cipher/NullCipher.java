/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.cipher;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;

/** */
public class NullCipher extends BaseCipher {

    public NullCipher() {}

    @Override
    public int getBlocksize() {
        return 0;
    }

    @Override
    public byte[] encrypt(byte[] someBytes) throws CryptoException {
        return someBytes;
    }

    @Override
    public byte[] encrypt(byte[] iv, byte[] someBytes) throws CryptoException {
        return someBytes;
    }

    @Override
    public byte[] encrypt(byte[] iv, int tagLength, byte[] someBytes) throws CryptoException {
        return someBytes;
    }

    @Override
    public byte[] encrypt(
            byte[] iv, int tagLength, byte[] additionAuthenticatedData, byte[] someBytes)
            throws CryptoException {
        return someBytes;
    }

    @Override
    public byte[] getIv() {
        return new byte[0];
    }

    @Override
    public void setIv(byte[] iv) {}

    @Override
    public byte[] decrypt(byte[] someBytes) throws CryptoException {
        return someBytes;
    }

    @Override
    public byte[] decrypt(byte[] iv, byte[] someBytes) throws CryptoException {
        return someBytes;
    }

    @Override
    public byte[] decrypt(byte[] iv, int tagLength, byte[] someBytes) throws CryptoException {
        return someBytes;
    }

    @Override
    public byte[] decrypt(
            byte[] iv, int tagLength, byte[] additionAuthenticatedData, byte[] someBytes)
            throws CryptoException {
        return someBytes;
    }
}
