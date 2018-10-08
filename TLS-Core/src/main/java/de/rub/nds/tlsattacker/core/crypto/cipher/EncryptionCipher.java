/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.cipher;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;

/**
 *
 *
 */
public interface EncryptionCipher {

    public int getBlocksize();

    public byte[] encrypt(byte[] someBytes) throws CryptoException;

    public byte[] encrypt(byte[] iv, byte[] someBytes) throws CryptoException;

    public byte[] encrypt(byte[] iv, int tagLength, byte[] someBytes) throws CryptoException;

    public byte[] encrypt(byte[] iv, int tagLength, byte[] additionAuthenticatedData, byte[] someBytes)
            throws CryptoException;

    public byte[] getIv();

    public void setIv(byte[] iv);
}
