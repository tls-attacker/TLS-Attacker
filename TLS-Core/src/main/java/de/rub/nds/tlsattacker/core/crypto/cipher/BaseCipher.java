/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.crypto.cipher;

public abstract class BaseCipher implements EncryptionCipher, DecryptionCipher {

    @Override
    public EncryptionCipher getEncryptionCipher() {
        return this;
    }

    @Override
    public DecryptionCipher getDecryptionCipher() {
        return this;
    }

}