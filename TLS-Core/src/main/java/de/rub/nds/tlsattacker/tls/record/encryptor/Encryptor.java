/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.encryptor;

import de.rub.nds.tlsattacker.tls.record.AbstractRecord;
import de.rub.nds.tlsattacker.tls.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.tls.record.decryptor.RecordCryptoUnit;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 * @param <T>
 */
public abstract class Encryptor<T extends AbstractRecord> extends RecordCryptoUnit {

    public Encryptor(RecordCipher cipher) {
        super(cipher);
    }

    public abstract void encrypt(T object);
}
