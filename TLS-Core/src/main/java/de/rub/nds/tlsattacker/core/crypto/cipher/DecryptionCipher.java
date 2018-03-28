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
 * @author robert
 */
public interface DecryptionCipher {

    public int getBlocksize();

    public byte[] decrypt(byte[] key, byte[] someBytes) throws CryptoException;

    public byte[] decrypt(byte[] key, byte[] iv, byte[] someBytes) throws CryptoException;

    public byte[] decrypt(byte[] key, byte[] iv, int tagLength, byte[] someBytes) throws CryptoException;

    public byte[] decrypt(byte[] key, byte[] iv, int tagLength, byte[] additionAuthenticatedData, byte[] someBytes)
            throws CryptoException;

    public byte[] getIv();

    public void setIv(byte[] iv);
}
