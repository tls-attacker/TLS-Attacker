/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.cipher;

import de.rub.nds.protocol.exception.CryptoException;

public abstract class BaseCipher implements EncryptionCipher, DecryptionCipher {

    @Override
    public EncryptionCipher getEncryptionCipher() {
        return this;
    }

    @Override
    public DecryptionCipher getDecryptionCipher() {
        return this;
    }

    public abstract byte[] getDtls13Mask(byte[] key, byte[] ciphertext) throws CryptoException;
}
