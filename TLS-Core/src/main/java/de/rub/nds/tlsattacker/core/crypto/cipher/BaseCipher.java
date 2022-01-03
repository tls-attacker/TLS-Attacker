/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
